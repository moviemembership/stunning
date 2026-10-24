import os
import threading
os.environ["PLAYWRIGHT_BROWSERS_PATH"] = "0"
from playwright.sync_api import sync_playwright
from playwright.async_api import async_playwright
import asyncio
import re
from datetime import datetime, timedelta, timezone, UTC
from flask import Flask, request, render_template, redirect, session, jsonify, send_from_directory, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from email_validator import validate_email, EmailNotValidError
import smtplib, ssl, secrets, time
from email.message import EmailMessage
import imaplib, email, re as _re
import requests
from bs4 import BeautifulSoup
import pathlib
import hashlib
import os, imaplib, email, json
from flask import abort
import socket
from urllib.parse import quote
socket.setdefaulttimeout(12)  # global timeout for IMAP socket

EMAIL_PEEK_TOKEN = os.environ.get("EMAIL_PEEK_TOKEN")
REPLACEMENT_FILE = os.getenv("REPLACEMENTS_FILE", "/etc/secrets/replacements.txt")

XX39_ACCOUNTS_FILE = os.getenv("XX39_ACCOUNTS_FILE", "/etc/secrets/xx39_accounts.txt")

CLICK_COUNT_FILE = os.getenv("CLICK_COUNT_FILE", "/var/data/shopee_clicks.json")

SIGNIN_URL = "https://yzmen.4knaifei.cn"

signin_playwright = None
signin_browser = None
signin_lock = threading.Lock()
signin_request_count = 0

OUTLOOK_URL = "https://yz.naifei.store/#/login"

AUTO_SIGNIN_URL = "https://yzmen.4knaifei.cn"

#------------ PAYMENT GATEWAY-------------

TOYYIBPAY_SANDBOX_SECRET_KEY = os.environ.get("SANDBOX_SERCET_CODE")
TOYYIBPAY_SANDBOX_CATEGORY_CODE = os.environ.get("SANDBOX_CATEGORY_CODE")
TOYYIBPAY_SANDBOX_BASE = "https://dev.toyyibpay.com"

# ---------------- CONFIG ----------------

IMAP_HOST = "mail.mantapnet.com"
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL")
ADMIN_PASS = os.environ.get("ADMIN_PASS")

# ---------------- FLASK APP ----------------
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "devkey")  # required for session

# ---------------- HELPERS ----------------
def imap_connect():
    m = imaplib.IMAP4_SSL(IMAP_HOST)
    m.login(ADMIN_EMAIL, ADMIN_PASS)
    m.select("INBOX")
    return m

def imap_uid_safe(mail, *args, retries=2):
    """
    Run mail.uid(...) with auto-reconnect on EOF/abort.
    Returns (mail, (status, data)) so you always keep the newest connection.
    """
    last_err = None
    for attempt in range(retries + 1):
        try:
            return mail, mail.uid(*args)
        except (imaplib.IMAP4.abort, imaplib.IMAP4.error, OSError) as e:
            last_err = e
            if attempt >= retries:
                raise
            try:
                mail.logout()
            except Exception:
                pass
            mail = imap_connect()
    raise last_err

def imap_call(mail, fn, *args, retries=3):
    """
    fn: "uid" or "noop"
    returns (mail, result)
    """
    last = None
    for _ in range(retries):
        try:
            if fn == "uid":
                return mail, mail.uid(*args)
            if fn == "noop":
                return mail, mail.noop()
            raise ValueError("bad fn")
        except (imaplib.IMAP4.abort, imaplib.IMAP4.error, OSError) as e:
            last = e
            try:
                mail.logout()
            except Exception:
                pass
            mail = imap_connect()
    raise last

def _extract_email_body(msg):
    """Extracts readable content from email (text/plain or text/html)."""
    try:
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() in ("text/plain", "text/html"):
                    payload = part.get_payload(decode=True)
                    return payload.decode(errors="ignore") if isinstance(payload, (bytes, bytearray)) else str(payload)
        else:
            payload = msg.get_payload(decode=True)
            return payload.decode(errors="ignore") if isinstance(payload, (bytes, bytearray)) else str(payload)
    except Exception:
        return ""

def get_mantapnet_email_code(
    entered_email,
    subjects,
    digits,
    max_age_minutes=25
):
    """
    Search the Mantapnet inbox for the newest email matching:
    - one of the supplied subjects
    - the entered Mantapnet email inside the message
    - a code with the requested number of digits

    Returns:
        (code, error)
    """
    entered_email = (entered_email or "").strip().lower()

    if not entered_email.endswith("@mantapnet.com"):
        return None, "Please enter a valid @mantapnet.com email."

    mail = None

    try:
        mail = imap_connect()

        since_date = (
            datetime.now(UTC) - timedelta(days=1)
        ).strftime("%d-%b-%Y")

        all_uids = []

        # Search each possible English/Malay subject separately.
        for subject in subjects:
            criteria = (
                f'(SINCE {since_date} '
                f'TO "{entered_email}" '
                f'SUBJECT "{subject}")'
            )

            mail, (status, data) = imap_uid_safe(
                mail,
                "search",
                None,
                criteria
            )

            if (
                status == "OK"
                and data
                and data[0]
            ):
                all_uids.extend(data[0].split())

        # Remove duplicate UIDs while preserving order.
        unique_uids = list(dict.fromkeys(all_uids))

        if not unique_uids:
            return None, "No recent code email found."

        cutoff = (
            datetime.now(UTC)
            - timedelta(minutes=max_age_minutes)
        )

        code_pattern = re.compile(
            rf"\b\d{{{digits}}}\b"
        )

        # Search newest emails first.
        for index, uid in enumerate(
            reversed(unique_uids[-100:]),
            start=1
        ):
            # Keep IMAP connection alive.
            if index % 8 == 0:
                try:
                    mail.noop()
                except Exception:
                    mail = imap_connect()

            # Read Date and Subject first.
            mail, (header_status, header_data) = (
                imap_uid_safe(
                    mail,
                    "fetch",
                    uid,
                    (
                        "(BODY.PEEK[HEADER.FIELDS "
                        "(DATE SUBJECT TO FROM)])"
                    )
                )
            )

            if (
                header_status != "OK"
                or not header_data
                or not header_data[0]
            ):
                continue

            message_header = email.message_from_bytes(
                header_data[0][1]
            )

            date_tuple = email.utils.parsedate_tz(
                message_header.get("Date")
            )

            if date_tuple:
                sent_utc = datetime.fromtimestamp(
                    email.utils.mktime_tz(date_tuple),
                    tz=UTC
                )

                if sent_utc < cutoff:
                    continue

            # Read full email so HTML/plain messages both work.
            mail, (body_status, body_data) = (
                imap_uid_safe(
                    mail,
                    "fetch",
                    uid,
                    "(BODY.PEEK[])"
                )
            )

            if (
                body_status != "OK"
                or not body_data
                or not body_data[0]
            ):
                continue

            message = email.message_from_bytes(
                body_data[0][1]
            )
            
            body = _extract_email_body(message) or ""
            
            to_header = (
                message.get("To")
                or message_header.get("To")
                or ""
            ).lower()
            
            if entered_email not in to_header:
                continue
            
            readable_body = BeautifulSoup(
                body,
                "html.parser"
            ).get_text(" ")
            
            match = code_pattern.search(readable_body)
            
            if match:
                return match.group(0), None

        return (
            None,
            f"No recent {digits}-digit code found for this "
            f"email. Request a new code and try again within "
            f"{max_age_minutes} minutes."
        )

    except Exception as exc:
        app.logger.exception(
            "Mantapnet email code error: %s",
            exc
        )

        return None, (
            "Unable to check the mailbox right now. "
            "Please try again."
        )

    finally:
        if mail:
            try:
                mail.logout()
            except Exception:
                pass

def get_mantapnet_signin_code(entered_email):
    return get_mantapnet_email_code(
        entered_email=entered_email,
        subjects=[
            "Your sign-in code",
            "Kod daftar masuk anda"
        ],
        digits=4,
        max_age_minutes=25
    )


def get_mantapnet_verification_code(entered_email):
    return get_mantapnet_email_code(
        entered_email=entered_email,
        subjects=[
            "Your verification code",
            "Kod pengesahan anda"
        ],
        digits=6,
        max_age_minutes=25
    )

# ---------------- SIGN IN CODE BROWSERS ----------------#

# ---------------- HOME ----------------
@app.route("/")
def index():
    return render_template("home.html")

# ---------------- SIGN-IN CODE (4-digit) ----------------
@app.route("/sign-in-code", methods=["GET", "POST"])
def redeem():
    code = None
    error = None
    entered = ""

    if request.method == "POST":
        entered = (request.form.get("email") or "").strip().lower()

        try:
            mail = imap_connect()

            since_1day = (datetime.now(UTC) - timedelta(days=1)).strftime("%d-%b-%Y")
            crit = (
                f'(SINCE {since_1day} '
                f'(OR SUBJECT "Your sign-in code" SUBJECT "Kod daftar masuk anda"))'
            )

            mail, (status, data) = imap_uid_safe(mail, "search", None, crit)
            if status != "OK" or not data or not data[0]:
                error = "No recent sign-in email found."
            else:
                uids = data[0].split()
                cutoff = datetime.now(UTC) - timedelta(minutes=25)

                for idx, uid in enumerate(reversed(uids[-60:]), start=1):
                    # keep IMAP alive
                    if idx % 8 == 0:
                        try:
                            mail.noop()
                        except Exception:
                            mail = imap_connect()

                    # fetch header first
                    mail, (st_hdr, hdr) = imap_uid_safe(
                        mail,
                        "fetch",
                        uid,
                        "(BODY.PEEK[HEADER.FIELDS (DATE)])"
                    )
                    if st_hdr != "OK" or not hdr or not hdr[0]:
                        continue

                    msg_hdr = email.message_from_bytes(hdr[0][1])
                    dt_tuple = email.utils.parsedate_tz(msg_hdr.get("Date"))
                    if dt_tuple:
                        sent_utc = datetime.fromtimestamp(
                            email.utils.mktime_tz(dt_tuple), tz=UTC
                        )
                        if sent_utc < cutoff:
                            continue  # ❗ DO NOT break

                    # 🔥 fetch ONLY first 4KB of text (no EOF)
                    mail, (st_body, body_data) = imap_uid_safe(
                        mail,
                        "fetch",
                        uid,
                        "(BODY.PEEK[TEXT]<0.4096>)"
                    )
                    if st_body != "OK" or not body_data or not body_data[0]:
                        continue

                    snippet = body_data[0][1].decode(
                        "utf-8", errors="ignore"
                    )

                    if entered in snippet.lower():
                        m = _re.search(r"\b\d{4}\b", snippet)
                        if m:
                            code = m.group(0)
                            break

                if not code:
                    error = (
                        "No recent sign-in email found for this address. "
                        "Request a new code and try again within 25 minutes."
                    )

            try:
                mail.logout()
            except Exception:
                pass

        except Exception as e:
            error = f"Error: {e}"

    return render_template(
        "sign_in_code.html",
        email=entered if request.method == "POST" else "",
        code=code,
        error=error
    )

# =========================================================
# SHARED SIGN-IN / VERIFICATION HELPERS
# =========================================================

EXPIRED_CDK_ERROR = (
    "This email has expired and can no longer retrieve a code. "
    "Please contact customer service for a replacement account."
)

INCORRECT_ACCOUNT_ERROR = (
    "Email or Password incorrect. Please check and try again."
)


def resolve_account_password(account_email, account_password):
    """
    Resolve the real account password.

    When the submitted password is qwe222, read the matching password
    from password.txt.
    """
    account_email = (account_email or "").strip()
    real_password = (account_password or "").strip()

    if real_password != "qwe222":
        return real_password, None

    try:
        with open("password.txt", "r", encoding="utf-8") as file:
            for line in file:
                parts = re.split(r"\s+", line.strip())

                if (
                    len(parts) >= 2
                    and parts[0].lower() == account_email.lower()
                ):
                    return parts[1], None

        return None, "Email not updated. Please ask admin to update."

    except Exception as exc:
        return None, f"Unable to read password.txt: {str(exc)}"


def text_has_expired_cdk(text):
    normalized = " ".join((text or "").lower().split())

    expired_messages = (
        "cdk has expired",
        "cdk expired",
        "cdk已过期",
        "cdk 已过期",
    )

    return any(message in normalized for message in expired_messages)


def text_has_invalid_cdk(text):
    normalized = " ".join((text or "").lower().split())

    invalid_messages = (
        "cdk does not exist",
        "cdk not exist",
    )

    return any(message in normalized for message in invalid_messages)


async def safe_body_text(page):
    try:
        return await page.locator("body").inner_text()
    except Exception:
        return ""


GMT8 = timezone(timedelta(hours=8))


async def wait_until_account_page_ready(page, timeout_seconds=20):
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        body_text = await safe_body_text(page)
        body_lower = " ".join(body_text.lower().split())
        if text_has_invalid_cdk(body_text):
            return False, INCORRECT_ACCOUNT_ERROR
        if text_has_expired_cdk(body_text):
            return False, EXPIRED_CDK_ERROR
        if "click replace" in body_lower:
            try:
                replace_button = page.locator(
                    'button:visible:has-text("Click Replace")'
                )
                if await replace_button.count() > 0:
                    return True, None
            except Exception:
                pass
        await page.wait_for_timeout(250)
    return False, "Unable to verify account. Please try again."


async def open_cdk_account(
    page,
    account_email,
    account_password
):
    cdk_password = build_cdk_password(
        account_email,
        account_password
    )

    login_value = (
        f"{account_email}----"
        f"{cdk_password}"
    )

    app.logger.info(
        "Opening CDK account: %s "
        "XX39=%s",
        account_email,
        cdk_password != account_password
    )

    await page.goto(
        "https://yzmen.4knaifei.cn//#/login",
        wait_until="domcontentloaded",
        timeout=45000,
    )

    login_input = (
        page.locator(
            "input:visible"
        ).first
    )

    await login_input.wait_for(
        state="visible",
        timeout=20000
    )

    await login_input.fill(
        login_value
    )

    exchange_clicked = False

    for label in (
        "Exchange",
        "兑换",
        "Redeem",
        "Submit",
        "Login"
    ):
        try:
            button = page.get_by_role(
                "button",
                name=re.compile(
                    rf"^{re.escape(label)}$",
                    re.I
                ),
            ).first

            if (
                await button.count() > 0
                and await button.is_visible()
            ):
                await button.click(
                    timeout=10000,
                    force=True
                )

                exchange_clicked = True
                break

        except Exception:
            continue

    if not exchange_clicked:
        try:
            buttons = page.locator(
                "button:visible"
            )

            if await buttons.count() > 0:
                await buttons.last.click(
                    timeout=10000,
                    force=True
                )

                exchange_clicked = True

        except Exception:
            pass

    if not exchange_clicked:
        return False, (
            "Unable to click Exchange. "
            "Please try again."
        )

    return await wait_until_account_page_ready(
        page,
        timeout_seconds=20
    )


async def click_replace_and_hint_ok(page):
    """
    Click Replace and verify that the Hint modal actually opens.
    Then click its OK button.
    """

    max_replace_attempts = 3

    for attempt in range(1, max_replace_attempts + 1):
        try:
            replace_buttons = page.locator(
                'button:visible:has-text("Click Replace")'
            )

            count = await replace_buttons.count()

            if count == 0:
                return False, (
                    "Unable to find the Replace button. "
                    "Please try again."
                )

            # Usually the visible account modal has the last matching button.
            replace_button = replace_buttons.last

            await replace_button.scroll_into_view_if_needed()

            app.logger.info(
                "Clicking Replace, attempt %s",
                attempt,
            )

            # Normal click first
            try:
                await replace_button.click(
                    timeout=5000
                )
            except Exception:
                # Force click only as fallback
                await replace_button.click(
                    timeout=5000,
                    force=True,
                )

        except Exception as exc:
            app.logger.exception(
                "Replace click attempt %s failed: %s",
                attempt,
                exc,
            )

            if attempt < max_replace_attempts:
                await page.wait_for_timeout(600)
                continue

            return False, (
                "Unable to click Replace. Please try again."
            )

        # -------------------------------------------------
        # Confirm that the Hint modal really appeared
        # -------------------------------------------------
        hint_modal = page.locator(
            ".ant-modal-confirm"
        ).filter(
            has_text=re.compile(
                r"Hint|Please click to obtain",
                re.I,
            )
        ).last

        try:
            await hint_modal.wait_for(
                state="visible",
                timeout=5000,
            )

            app.logger.info(
                "Hint modal appeared after Replace attempt %s",
                attempt,
            )

        except Exception:
            app.logger.warning(
                "Replace attempt %s did not open Hint modal.",
                attempt,
            )

            if attempt < max_replace_attempts:
                await page.wait_for_timeout(700)
                continue

            try:
                timestamp = int(time.time())

                screenshot_path = (
                    f"/tmp/replace_no_hint_{timestamp}.png"
                )

                await page.screenshot(
                    path=screenshot_path,
                    full_page=True,
                )

                app.logger.error(
                    "Replace was clicked but Hint did not appear. "
                    "URL=%s Screenshot=%s",
                    page.url,
                    screenshot_path,
                )

            except Exception:
                pass

            return False, (
                "The confirmation window did not appear. "
                "Please try again."
            )

        # -------------------------------------------------
        # Click OK inside the confirmed Hint modal
        # -------------------------------------------------
        try:
            ok_button = hint_modal.locator(
                "button"
            ).filter(
                has_text=re.compile(r"^OK$", re.I)
            ).last

            await ok_button.wait_for(
                state="visible",
                timeout=5000,
            )

            await ok_button.click(
                timeout=5000,
            )

            app.logger.info(
                "Hint OK clicked successfully."
            )

            # Do not wait for the modal to become hidden.
            await page.wait_for_timeout(300)

            return True, None

        except Exception as exc:
            app.logger.exception(
                "Unable to click Hint OK: %s",
                exc,
            )

            try:
                # JavaScript fallback, limited to the Hint modal
                clicked = await hint_modal.evaluate("""
                    modal => {
                        const buttons = Array.from(
                            modal.querySelectorAll("button")
                        );

                        const okButton = buttons.find(button => {
                            const text = (
                                button.innerText ||
                                button.textContent ||
                                ""
                            ).trim();

                            return text === "OK";
                        });

                        if (!okButton) {
                            return false;
                        }

                        okButton.click();
                        return true;
                    }
                """)

                if clicked:
                    await page.wait_for_timeout(300)
                    return True, None

            except Exception as js_exc:
                app.logger.exception(
                    "JavaScript OK click failed: %s",
                    js_exc,
                )

            return False, (
                "Unable to confirm the request. "
                "Please try again."
            )

    return False, "Unable to click Replace. Please try again."

async def get_top_history_signature(page):
    """
    Return the newest History row as:
        (code, collection_time)
    """
    try:
        rows = page.locator("table tbody tr")

        if await rows.count() == 0:
            return None, None

        first_row = rows.first
        cells = first_row.locator("td")

        if await cells.count() < 2:
            return None, None

        code_text = (await cells.nth(0).inner_text()).strip()
        time_text = (await cells.nth(1).inner_text()).strip()

        return code_text, time_text

    except Exception as exc:
        app.logger.warning(
            "Unable to read top History row: %s",
            exc,
        )
        return None, None


async def wait_for_replace_result(
    page,
    previous_history=None,
    timeout_seconds=30,
):
    """
    Detect the result after Click Replace -> OK.

    Returns:
        success
        no_more
        expired
        invalid
        timeout
    """
    deadline = time.monotonic() + timeout_seconds

    previous_history = previous_history or (
        None,
        None,
    )

    while time.monotonic() < deadline:
        notification_texts = []

        selectors = [
            ".ant-message-notice-content",
            ".ant-message-notice",
            ".ant-notification-notice",
            ".ant-notification-notice-message",
            ".ant-notification-notice-description",
            "[role='alert']",
        ]

        for selector in selectors:
            try:
                elements = page.locator(selector)
                count = await elements.count()

                for index in range(count):
                    element = elements.nth(index)

                    try:
                        text = (
                            await element.inner_text()
                        ).strip()

                        if text:
                            notification_texts.append(text)

                    except Exception:
                        continue

            except Exception:
                continue

        body_text = await safe_body_text(page)

        combined_text = " ".join(
            notification_texts + [body_text]
        )

        normalized = " ".join(
            combined_text.lower().split()
        )

        # Expired account after Replace -> OK
        if text_has_expired_cdk(combined_text):
            return "expired"

        # Invalid login/CDK
        if text_has_invalid_cdk(combined_text):
            return "invalid"

        # No more verification codes remain
        if (
            "we have not received the latest verification code"
            in normalized
            or "not received the latest verification code"
            in normalized
            or "未收到最新验证码" in normalized
            or "没有收到最新验证码" in normalized
        ):
            return "no_more"

        # Successful retrieval
        if (
            "successfully obtained verification code"
            in normalized
            or "verification code obtained successfully"
            in normalized
            or "成功获取验证码" in normalized
            or "验证码获取成功" in normalized
        ):
            return "success"

        # Fallback: newest history row changed
        current_history = await get_top_history_signature(
            page
        )

        if (
            current_history != (None, None)
            and current_history != previous_history
        ):
            return "success"

        await page.wait_for_timeout(100)

    try:
        timestamp = int(time.time())
        screenshot_path = (
            f"/tmp/replace_result_timeout_{timestamp}.png"
        )

        await page.screenshot(
            path=screenshot_path,
            full_page=True,
        )

        app.logger.error(
            "Replace result timeout. Previous history=%r "
            "Current history=%r URL=%s Screenshot=%s",
            previous_history,
            await get_top_history_signature(page),
            page.url,
            screenshot_path,
        )
    except Exception:
        pass

    return "timeout"

async def retrieve_all_latest_codes(
    page,
    max_clicks=10,
):
    started_at = time.monotonic()

    for attempt in range(max_clicks):
        previous_history = await get_top_history_signature(page)

        attempt_started = time.monotonic()

        app.logger.info(
            "Replace attempt %s started. "
            "Total elapsed=%.2fs Previous history=%r",
            attempt + 1,
            attempt_started - started_at,
            previous_history,
        )

        clicked, click_error = await click_replace_and_hint_ok(page)

        click_finished = time.monotonic()

        app.logger.info(
            "Replace attempt %s click/confirm finished in %.2fs",
            attempt + 1,
            click_finished - attempt_started,
        )

        if not clicked:
            app.logger.info(
                "Replace attempt %s failed before result wait. "
                "Total elapsed=%.2fs Error=%s",
                attempt + 1,
                time.monotonic() - started_at,
                click_error,
            )

            return False, click_error

        wait_started = time.monotonic()

        result = await wait_for_replace_result(
            page,
            previous_history=previous_history,
            timeout_seconds=45,
        )

        wait_finished = time.monotonic()

        app.logger.info(
            "Replace attempt %s result=%s "
            "Result wait=%.2fs "
            "Attempt total=%.2fs "
            "Overall total=%.2fs",
            attempt + 1,
            result,
            wait_finished - wait_started,
            wait_finished - attempt_started,
            wait_finished - started_at,
        )

        if result == "expired":
            return False, EXPIRED_CDK_ERROR

        if result == "invalid":
            return False, INCORRECT_ACCOUNT_ERROR

        if result == "no_more":
            return True, None

        if result == "success":
            await page.wait_for_timeout(500)
            continue

        return False, (
            "Please request the code again and retry."
        )

    return False, (
        "Too many codes were received. Please try again."
    )


def parse_history_time(time_text):
    try:
        return datetime.strptime(
            (time_text or "").strip(),
            "%Y-%m-%d %H:%M:%S",
        ).replace(tzinfo=GMT8)
    except (TypeError, ValueError):
        return None


async def get_latest_code_from_history(page, digits, max_age_minutes=15):
    now_gmt8 = datetime.now(GMT8)
    max_age_seconds = max_age_minutes * 60
    try:
        rows = page.locator("table tbody tr")
        row_count = await rows.count()
        app.logger.info("History row count: %s", row_count)
        for index in range(row_count):
            row = rows.nth(index)
            cells = row.locator("td")
            if await cells.count() < 2:
                continue
            code_text = (await cells.nth(0).inner_text()).strip()
            time_text = (await cells.nth(1).inner_text()).strip()
            collected_at = parse_history_time(time_text)
            if not collected_at:
                continue
            age_seconds = (now_gmt8 - collected_at).total_seconds()
            app.logger.info(
                "History row %s: code=%r time=%r age=%s",
                index, code_text, time_text, age_seconds
            )
            if age_seconds < -120:
                continue
            if age_seconds > max_age_seconds:
                break
            if re.fullmatch(rf"\d{{{digits}}}", code_text):
                return code_text, time_text
        return None, None
    except Exception as exc:
        app.logger.exception("Unable to read code history: %s", exc)
        return None, None

# =========================================================
# 4-DIGIT SIGN-IN CODE
# =========================================================

def get_auto_sign_in_code(account_email, account_password):
    return asyncio.run(
        _get_auto_sign_in_code_async(
            account_email,
            account_password,
        )
    )


async def _get_auto_sign_in_code_async(
    account_email,
    account_password,
):
    account_email = (account_email or "").strip()
    account_password = (account_password or "").strip()

    real_password, password_error = resolve_account_password(
        account_email,
        account_password,
    )
    if password_error:
        return None, password_error

    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-blink-features=AutomationControlled",
            ],
        )
        try:
            context = await browser.new_context(
                viewport={"width": 1400, "height": 900},
                locale="en-US",
            )
            page = await context.new_page()
            page.set_default_timeout(30000)

            opened, open_error = await open_cdk_account(
                page, account_email, real_password
            )
            if not opened:
                return None, open_error

            completed, retrieve_error = await retrieve_all_latest_codes(
                page, max_clicks=10
            )
            if not completed:
                return None, retrieve_error

            code, collection_time = await get_latest_code_from_history(
                page, digits=4, max_age_minutes=15
            )
            if code:
                app.logger.info(
                    "Returning 4-digit history code %s from %s",
                    code, collection_time
                )
                return code, None

            return (
                None,
                "No recent 4-digit sign-in code was found. "
                "Please request a new sign-in code and try again.",
            )
        except Exception as exc:
            app.logger.exception("Sign-in code system error: %s", exc)
            return None, "System is busy or timed out. Please try again."
        finally:
            await browser.close()

# ---------------- OUTLOOK HOUSEHOLD CODE ----------------#

def get_outlook_household_code(user_email):
    return asyncio.run(_get_outlook_household_code_async(user_email))


async def _get_outlook_household_code_async(user_email):
    """
    Outlook / Hotmail household-code retrieval.

    The external site can load in English, Chinese, or Spanish.
    """
    user_email = (user_email or "").strip()

    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-blink-features=AutomationControlled",
            ],
        )

        try:
            context = await browser.new_context(
                viewport={"width": 1800, "height": 900},
                locale="en-US",
            )

            page = await context.new_page()
            page.set_default_timeout(30000)

            await page.goto(
                OUTLOOK_URL,
                wait_until="domcontentloaded",
                timeout=60000,
            )

            email_input = page.locator("input:visible").first
            await email_input.wait_for(
                state="visible",
                timeout=30000,
            )
            await email_input.fill(user_email)

            query_clicked = False
            query_names = (
                "Query verification code",
                "Get verification code",
                "Query",
                "Consulta",
                "Consultar",
                "查询验证码",
                "查询",
            )

            for button_name in query_names:
                try:
                    button = page.get_by_role(
                        "button",
                        name=button_name,
                        exact=True,
                    ).first

                    if (
                        await button.count() > 0
                        and await button.is_visible()
                    ):
                        await button.click(
                            timeout=10000,
                            force=True,
                        )
                        query_clicked = True
                        break
                except Exception:
                    continue

            if not query_clicked:
                try:
                    buttons = page.locator("button:visible")
                    button_count = await buttons.count()
                    for index in range(button_count):
                        button = buttons.nth(index)
                        try:
                            button_text = (
                                await button.inner_text()
                            ).strip()
                            if button_text:
                                await button.click(
                                    timeout=10000,
                                    force=True,
                                )
                                query_clicked = True
                                break
                        except Exception:
                            continue
                except Exception:
                    pass

            if not query_clicked:
                return None, (
                    "Unable to query the household code. "
                    "Please try again."
                )

            deadline = time.monotonic() + 20
            confirm_button = None

            no_code_messages = (
                "the email verification code data has not been obtained yet",
                "verification code data has not been obtained",
                "has not been obtained",
                "尚未获取到邮箱验证码数据",
                "未获取到邮箱验证码数据",
                "no se han obtenido datos del código de verificación del correo electrónico",
                "no se han obtenido datos del codigo de verificacion del correo electronico",
                "no se han obtenido datos del código de verificación",
                "no se han obtenido datos del codigo de verificacion",
            )

            expired_messages = (
                "verification code has expired",
                "code has expired",
                "邮箱验证码已过期",
                "验证码已过期",
                "已过期",
                "ha caducado",
                "caducado",
                "expirado",
            )

            confirm_texts = {
                "OK", "Confirm", "Yes",
                "确定", "確認", "确认",
                "Aceptar", "Confirmar", "Sí", "Si",
            }

            while time.monotonic() < deadline:
                body_text = await safe_body_text(page)
                normalized = " ".join(
                    (body_text or "").lower().split()
                )

                if any(message in normalized for message in no_code_messages):
                    return None, (
                        "No household code found. "
                        "Please send the household code email first "
                        "and try again."
                    )

                if any(message in normalized for message in expired_messages):
                    return None, (
                        "The household code has expired. "
                        "Please send a new household code and try again."
                    )

                modal_selectors = (
                    ".ant-modal-confirm:visible",
                    ".ant-modal:visible",
                    ".ant-modal-content:visible",
                )

                found_confirm = False

                for modal_selector in modal_selectors:
                    try:
                        modals = page.locator(modal_selector)
                        modal_count = await modals.count()
                        for modal_index in reversed(range(modal_count)):
                            modal = modals.nth(modal_index)
                            if not await modal.is_visible():
                                continue
                            buttons = modal.locator("button:visible")
                            button_count = await buttons.count()
                            for button_index in reversed(range(button_count)):
                                button = buttons.nth(button_index)
                                try:
                                    button_text = (
                                        await button.inner_text()
                                    ).strip()
                                    if button_text in confirm_texts:
                                        confirm_button = button
                                        found_confirm = True
                                        break
                                except Exception:
                                    continue
                            if found_confirm:
                                break
                        if found_confirm:
                            break
                    except Exception:
                        continue

                if found_confirm:
                    break

                await page.wait_for_timeout(200)

            if confirm_button is None:
                try:
                    timestamp = int(time.time())
                    screenshot_path = (
                        f"/tmp/household_result_not_found_{timestamp}.png"
                    )
                    await page.screenshot(
                        path=screenshot_path,
                        full_page=True,
                    )
                    app.logger.error(
                        "Household result not detected. URL=%s Screenshot=%s",
                        page.url,
                        screenshot_path,
                    )
                except Exception:
                    pass

                return None, (
                    "The household code service did not return a result. "
                    "Please try again."
                )

            pages_before = list(context.pages)

            try:
                await confirm_button.click(
                    timeout=10000,
                    force=True,
                )
            except Exception as exc:
                app.logger.exception(
                    "Household confirm click failed: %s",
                    exc,
                )
                return None, (
                    "Unable to confirm the household code request. "
                    "Please try again."
                )

            await page.wait_for_timeout(5000)

            current_pages = context.pages
            if len(current_pages) > len(pages_before):
                code_page = current_pages[-1]
            else:
                code_page = page

            try:
                await code_page.wait_for_load_state(
                    "domcontentloaded",
                    timeout=30000,
                )
            except Exception:
                pass

            await code_page.wait_for_timeout(1200)

            full_text = await safe_body_text(code_page)
            full_url = code_page.url
            full_normalized = " ".join(
                (full_text or "").lower().split()
            )

            result_expired_messages = (
                "this link is no longer valid",
                "please request again on the original device",
                "link is no longer valid",
                "此链接已失效",
                "链接已失效",
                "请在原设备上重新请求",
                "este enlace ya no es válido",
                "este enlace ya no es valido",
            )

            if any(
                message in full_normalized
                for message in result_expired_messages
            ):
                return None, (
                    "Link was expired. "
                    "Please resend the household code and try again."
                )

            match = re.search(
                r"\b\d{4}\b",
                f"{full_text} {full_url}",
            )

            if match:
                return match.group(0), None

            try:
                timestamp = int(time.time())
                screenshot_path = (
                    f"/tmp/household_code_not_found_{timestamp}.png"
                )
                await code_page.screenshot(
                    path=screenshot_path,
                    full_page=True,
                )
                app.logger.error(
                    "Household result opened but no 4-digit code found. URL=%s Screenshot=%s",
                    full_url,
                    screenshot_path,
                )
            except Exception:
                pass

            return None, (
                "Code page opened, but no 4-digit household code was found."
            )

        except Exception as exc:
            app.logger.exception(
                "Household code system error: %s",
                exc,
            )
            return None, (
                "System is busy or timed out. "
                "Please try again."
            )

        finally:
            await browser.close()

# =========================================================
# 6-DIGIT VERIFICATION CODE
# =========================================================

def get_verification_code(account_email, account_password):
    return asyncio.run(
        _get_verification_code_async(
            account_email,
            account_password,
        )
    )


async def _get_verification_code_async(
    account_email,
    account_password,
):
    account_email = (account_email or "").strip()
    account_password = (account_password or "").strip()

    real_password, password_error = resolve_account_password(
        account_email,
        account_password,
    )
    if password_error:
        return None, password_error

    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-blink-features=AutomationControlled",
            ],
        )
        try:
            context = await browser.new_context(
                viewport={"width": 1400, "height": 900},
                locale="en-US",
            )
            page = await context.new_page()
            page.set_default_timeout(30000)

            opened, open_error = await open_cdk_account(
                page, account_email, real_password
            )
            if not opened:
                return None, open_error

            completed, retrieve_error = await retrieve_all_latest_codes(
                page, max_clicks=10
            )
            if not completed:
                return None, retrieve_error

            code, collection_time = await get_latest_code_from_history(
                page, digits=6, max_age_minutes=15
            )
            if code:
                app.logger.info(
                    "Returning 6-digit history code %s from %s",
                    code, collection_time
                )
                return code, None

            return (
                None,
                "No recent 6-digit verification code was found. "
                "Please request a new verification code and try again.",
            )
        except Exception as exc:
            app.logger.exception("Verification code system error: %s", exc)
            return None, "System is busy or timed out. Please try again."
        finally:
            await browser.close()

# ---------------- HOUSEHOLD CODE ----------------
def _extract_code_from_verification_link(url: str):
    """Follow Netflix 'Temporary Access Code' link and get the OTP."""
    try:
        headers = {"User-Agent": "Mozilla/5.0"}
        res = requests.get(url, headers=headers, timeout=10)
        res.raise_for_status()
        soup = BeautifulSoup(res.text, "html.parser")

        if soup.find("div", class_="title", string="This link is no longer valid"):
            return None, "This code has expired. Please re-request on the original device (redeem within 15 minutes)."

        code_div = soup.find("div", {"data-uia": "travel-verification-otp"})
        if code_div and code_div.text.strip():
            return code_div.text.strip(), None

        return None, "Unable to fetch code. Make sure you redeem within 15 minutes."
    except Exception as e:
        app.logger.error("Verification link error: %s", e)
        return None, "Unable to access the verification link. Try again later."

@app.route("/household-code", methods=["GET", "POST"])
def household_code():
    """
    Looks for Netflix 'temporary access code' / 'Kod akses sementara'
    matching the entered @mantapnet.com email in the last 15 minutes.
    """
    code, error = None, None
    entered = ""

    if request.method == "POST":
        entered = (request.form.get("email") or "").strip().lower()
        if not entered.endswith("@mantapnet.com"):
            return render_template("household_code.html", email=entered, code=None,
                                   error="Please enter an @mantapnet.com email.")

        try:
            mail = imaplib.IMAP4_SSL(IMAP_HOST)
            mail.login(ADMIN_EMAIL, ADMIN_PASS)
            mail.select("inbox")

            since_str = (datetime.utcnow() - timedelta(days=1)).strftime("%d-%b-%Y")
            mail, (s1, d1) = imap_uid_safe(mail,"search", None, f'(SINCE {since_str} SUBJECT "temporary access code")')
            mail, (s2, d2) = imap_uid_safe(mail,"search", None, f'(SINCE {since_str} SUBJECT "Kod akses sementara")')

            ids1 = d1[0].split() if s1 == "OK" and d1 and d1[0] else []
            ids2 = d2[0].split() if s2 == "OK" and d2 and d2[0] else []
            all_ids = ids1 + ids2

            if not all_ids:
                error = "No recent 'Temporary Access Code' emails found."
            else:
                matched_uid = None
                cutoff = datetime.now(UTC) - timedelta(minutes=20)   # a bit wider window
                entered_l = entered.lower()

                # look at up to last 200 (safer if inbox busy)
                for uid in reversed(all_ids[-200:]):
                    mail, (st_hdr, hdr) = imap_uid_safe(mail,"fetch", uid, '(BODY.PEEK[HEADER.FIELDS (DATE SUBJECT TO FROM)])')
                    if st_hdr != "OK" or not hdr or not hdr[0]:
                        continue

                    msg_hdr = email.message_from_bytes(hdr[0][1])

                    # Parse header date -> aware UTC
                    dt_tuple = email.utils.parsedate_tz(msg_hdr.get("Date"))
                    if dt_tuple:
                        sent_utc = datetime.fromtimestamp(email.utils.mktime_tz(dt_tuple), tz=UTC)
                        # don't BREAK on older mail; just skip and continue
                        if sent_utc < cutoff:
                            continue

                    # Fetch full body once and extract
                    mail, (st_body, body_data) = imap_uid_safe(mail,"fetch", uid, "(BODY.PEEK[])")
                    if st_body != "OK" or not body_data or not body_data[0]:
                        continue

                    body = _extract_email_body(email.message_from_bytes(body_data[0][1])) or ""
                    if entered_l in body.lower():
                        matched_uid = uid
                        break

                if matched_uid:
                    mail, (st_full, full_data) = imap_uid_safe(mail,"fetch", matched_uid, "(BODY.PEEK[])")
                    if st_full == "OK" and full_data and full_data[0]:
                        full_msg = email.message_from_bytes(full_data[0][1])
                        body = _extract_email_body(full_msg) or ""

                        m = _re.search(r'https?://[^\s"<>\]]+', body)
                        link = m.group(0) if m else None

                        if link:
                            code, err = _extract_code_from_verification_link(link)
                            if err:
                                error = err
                        else:
                            error = "No verification link found in the email."
                    else:
                        error = "Unable to read the matched email."
                else:
                    error = "No matching email found for that address within the last 15 minutes."

            mail.logout()
        except Exception as e:
            app.logger.exception("Household code error: %s", e)
            error = f"Error: {e}"

    return render_template("household_code.html",
                           email=entered if request.method == "POST" else "",
                           code=code, error=error)

def should_append_xx39(
    account_email,
    account_password
):
    """
    Return True only when BOTH the email and password
    exactly match an entry in xx39_accounts.txt.

    Format:
        email----password
    """

    account_email = (
        account_email or ""
    ).strip().lower()

    account_password = (
        account_password or ""
    ).strip()

    try:
        if not os.path.exists(
            XX39_ACCOUNTS_FILE
        ):
            return False

        with open(
            XX39_ACCOUNTS_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            for raw_line in file:
                line = raw_line.strip()

                if (
                    not line
                    or "----" not in line
                ):
                    continue

                listed_email, listed_password = (
                    line.split("----", 1)
                )

                listed_email = (
                    listed_email
                    .strip()
                    .lower()
                )

                listed_password = (
                    listed_password
                    .strip()
                )

                if (
                    listed_email
                    == account_email
                    and
                    listed_password
                    == account_password
                ):
                    return True

    except Exception as exc:
        app.logger.exception(
            "Unable to read XX39 account list: %s",
            exc
        )

    return False

def build_cdk_password(
    account_email,
    account_password
):
    account_password = (
        account_password or ""
    ).strip()

    if should_append_xx39(
        account_email,
        account_password
    ):
        return account_password + "XX39"

    return account_password


def load_replacements():
    """Load replacement mappings from the secret file into a dict."""
    mapping = {}
    try:
        if os.path.exists(REPLACEMENT_FILE):
            with open(REPLACEMENT_FILE, "r", encoding="utf-8") as f:
                for raw in f:
                    line = raw.strip()
                    if not line or "----" not in line:
                        continue
                    old, new = line.split("----", 1)
                    mapping[old.strip().lower()] = new.strip()
    except Exception as e:
        app.logger.exception("Error reading replacements file: %s", e)
    return mapping

@app.route("/replace-email", methods=["GET", "POST"])
def replace_email():
    """
    User enters a non-working email. If a replacement exists in the server-side
    file it is returned. Otherwise show a friendly message.
    """
    result = None
    error = None
    entered = ""

    if request.method == "POST":
        entered = (request.form.get("email") or "").strip()
        if not entered:
            error = "Please enter an email address."
        else:
            # optional validation — don't block if invalid
            try:
                validate_email(entered)
            except EmailNotValidError:
                app.logger.info("replace-email: non-validated address entered: %s", entered)

            # HOT-RELOAD the mapping each request (so secret file edits apply)
            mapping = load_replacements()
            repl = mapping.get(entered.lower())

            if repl:
                result = {"found": True, "replacement": repl}
            else:
                result = {"found": False}

    return render_template("replace_email.html", email=entered, result=result, error=error)

@app.route("/fon.png")
def fon_link():
  external_url = "https://github.com/moviemembership/redeem-app/blob/485881a153a2ebc785e524b94f5a7d9fe232b157/fon.png?raw=true"
  return redirect(external_url)

@app.route("/tv.png")
def tv_link():
  external_url = "https://github.com/moviemembership/redeem-app/blob/main/tv.png?raw=true"
  return redirect(external_url)

def _fmt_date(dt_str):
    try:
        tup = email.utils.parsedate_to_datetime(dt_str)
        return tup.strftime("%Y-%m-%d %H:%M")
    except Exception:
        return dt_str or ""

@app.route("/view-mails", methods=["GET", "POST"])
def view_mails():
    """
    Admin-only page to preview the last 10 full HTML emails for a given address.
    Not linked publicly — accessible only by direct link.
    """
    """
    Hidden page: only accessible with a correct token in the URL.
    Example: https://yourapp/peek-inbox?token=XXXX
    """
    token = request.args.get("token", "")
    if not EMAIL_PEEK_TOKEN or token != EMAIL_PEEK_TOKEN:
        abort(404)  # do not reveal page existence
        
    entered = request.form.get("email", "").strip() if request.method == "POST" else ""
    rows, error = [], None

    if request.method == "POST" and entered:
        try:
            mail = imaplib.IMAP4_SSL(IMAP_HOST)
            mail.login(ADMIN_EMAIL, ADMIN_PASS)
            mail.select("inbox")

            # Search by TO field only (fast and precise)
            search_crit = f'(TO "{entered}")'
            mail, (status, data) = imap_uid_safe(mail,"search", None, search_crit)
            uids = data[0].split() if status == "OK" and data and data[0] else []

            if not uids:
                error = f"No emails found sent to {entered}"
            else:
                # Get last 10 only
                for uid in reversed(uids[-10:]):
                    mail, (st, fetched) = imap_uid_safe(mail,"fetch", uid, "(BODY.PEEK[])")
                    if st != "OK" or not fetched or not fetched[0]:
                        continue

                    msg = email.message_from_bytes(fetched[0][1])
                    subj_raw = email.header.decode_header(msg.get("Subject", "")) or [("", None)]
                    subject = ""
                    for s, enc in subj_raw:
                        try:
                            subject += s.decode(enc or "utf-8", errors="ignore") if isinstance(s, bytes) else str(s)
                        except Exception:
                            subject += str(s)

                    date_ = msg.get("Date", "")
                    # extract HTML or plain body
                    body = ""
                    if msg.is_multipart():
                        for part in msg.walk():
                            ctype = part.get_content_type()
                            disp = str(part.get("Content-Disposition"))
                            if "attachment" in disp:
                                continue
                            if ctype == "text/html":
                                body = part.get_payload(decode=True).decode("utf-8", errors="ignore")
                                break
                            elif ctype == "text/plain" and not body:
                                body = part.get_payload(decode=True).decode("utf-8", errors="ignore")
                    else:
                        body = msg.get_payload(decode=True).decode("utf-8", errors="ignore")

                    rows.append({
                        "subject": subject.strip() or "(no subject)",
                        "date": date_,
                        "body": body
                    })
            mail.logout()
        except Exception as e:
            error = f"Error: {e}"

    return render_template("view_mails.html", email=entered, rows=rows, error=error)

def _read_click_count() -> int:
    try:
        if os.path.exists(CLICK_COUNT_FILE):
            with open(CLICK_COUNT_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                return int(data.get("total", 0))
    except Exception:
        pass
    return 0

def _write_click_count(total: int) -> None:
    try:
        os.makedirs(os.path.dirname(CLICK_COUNT_FILE), exist_ok=True)
        with open(CLICK_COUNT_FILE, "w", encoding="utf-8") as f:
            json.dump({"total": int(total)}, f)
    except Exception:
        pass

@app.post("/track/shopee-click")
def track_shopee_click():
    total = _read_click_count() + 1
    _write_click_count(total)
    return jsonify({"ok": True, "total": total})

@app.route('/google0dae518ec9a0e9f1.html')
def google_verify():
    return send_from_directory('.', 'google0dae518ec9a0e9f1.html')

@app.route("/unable-to-log-in")
def unable_to_log_in():
    return render_template("unable_to_log_in.html")

@app.route("/outlook-code", methods=["GET", "POST"])
def outlook_code():
    code = None
    error = None
    entered = ""

    if request.method == "POST":
        entered = (request.form.get("email") or "").strip()
        code, error = get_outlook_household_code(entered)

    return render_template(
        "outlook.html",
        email=entered if request.method == "POST" else "",
        code=code,
        error=error
    )

@app.route("/sign-in-code-auto", methods=["GET", "POST"])
def sign_in_code_auto():
    code = None
    error = None
    entered_email = ""
    entered_password = ""

    if request.method == "POST":
        entered_email = (request.form.get("email") or "").strip()
        entered_password = (request.form.get("password") or "").strip()

        if not entered_email or not entered_password:
            error = "Please enter both email and password."
        else:
            code, error = get_auto_sign_in_code(entered_email, entered_password)

    return render_template(
        "sign_in_auto.html",
        email=entered_email,
        password=entered_password,
        code=code,
        error=error
    )

@app.route("/verification-code", methods=["GET", "POST"])
def verification_code():
    code = None
    error = None
    entered_email = ""
    entered_password = ""

    if request.method == "POST":
        entered_email = (request.form.get("email") or "").strip()
        entered_password = (request.form.get("password") or "").strip()

        if not entered_email or not entered_password:
            error = "Please enter both email and password."
        else:
            try:
                code, error = get_verification_code(
                    entered_email,
                    entered_password
                )
            except Exception as e:
                print("VERIFICATION ERROR:", str(e))
                error = "System is busy or timed out. Please try again."

    return render_template(
        "verification_code.html",
        email=entered_email,
        password=entered_password,
        code=code,
        error=error
    )

@app.route("/debug/<name>")
def debug_image(name):
    try:
        return send_file(f"/tmp/{name}.png", mimetype="image/png")
    except Exception as e:
        return f"Debug image not found: {str(e)}"

@app.route('/test/<path:filename>')
def static_files(filename):
    return send_from_directory('test', filename)

@app.route("/instructions")
def instructions():
    return render_template("instructions.html")

@app.route("/profile-compare")
def profile_compare():
    return render_template("profile_compare.html")

@app.route("/profile-comparision")
def profile_comparison():
    return render_template("profile_comparision.html")

@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404

@app.route("/superlink")
def telegram():
    return render_template("superlink.html")

@app.route("/netflix-private-profile")
def netflix_private_profile():
    return render_template("product_private_profile.html")

@app.route("/test-private-profile")
def test_private_profile():
    return render_template("test_private_profile.html")


@app.route("/test-private-profile-pay", methods=["POST"])
def test_private_profile_pay():
    name = request.form.get("name", "Customer")
    email = request.form.get("email", "test@example.com")
    phone = request.form.get("phone", "0123456789")
    quantity = int(request.form.get("quantity", 1))

    price_per_unit = 15.90
    total_rm = price_per_unit * quantity
    total_cent = int(total_rm * 100)

    order_id = f"TESTPP{int(time.time())}"

    bill_data = {
        "userSecretKey": TOYYIBPAY_SANDBOX_SECRET_KEY,
        "categoryCode": TOYYIBPAY_SANDBOX_CATEGORY_CODE,
        "billName": "Private Profile",
        "billDescription": f"Netflix Private Profile x{quantity}",
        "billPriceSetting": 1,
        "billPayorInfo": 1,
        "billAmount": total_cent,
        "billReturnUrl": "https://mantapnet.my/test-payment-return",
        "billCallbackUrl": "https://mantapnet.my/test-payment-callback",
        "billExternalReferenceNo": order_id,
        "billTo": name,
        "billEmail": email,
        "billPhone": phone,
        "billSplitPayment": 0,
        "billSplitPaymentArgs": "",
        "billPaymentChannel": 0,
        "billContentEmail": "Thank you for testing Mantapnet payment.",
        "billChargeToCustomer": 1,
        "billExpiryDays": 1
    }

    response = requests.post(
        f"{TOYYIBPAY_SANDBOX_BASE}/index.php/api/createBill",
        data=bill_data,
        timeout=20
    )

    result = response.json()

    if result and "BillCode" in result[0]:
        bill_code = result[0]["BillCode"]
        return redirect(f"{TOYYIBPAY_SANDBOX_BASE}/{bill_code}")

    return f"Unable to create sandbox bill: {result}"


@app.route("/test-payment-return")
def test_payment_return():
    return render_template("test_payment_return.html")


@app.route("/test-payment-callback", methods=["POST"])
def test_payment_callback():
    data = request.form.to_dict()
    print("TOYYIBPAY SANDBOX CALLBACK:", data)
    return "OK"

@app.route("/test-private-profile-checkout", methods=["POST"])
def private_profile_checkout():
    quantity = int(request.form.get("quantity", 1))
    total = quantity * 15.90

    return render_template(
        "test_private_profile_checkout.html",
        quantity=quantity,
        total=total
    )

@app.route("/get-code", methods=["GET", "POST"])
def get_code():
    selected = request.args.get(
        "type",
        "signin"
    )

    valid_types = {
        "signin",
        "verification",
        "household"
    }

    if selected not in valid_types:
        selected = "signin"

    email_value = ""
    password_value = ""
    code = None
    error = None

    if request.method == "POST":
        selected = request.form.get(
            "code_type",
            "signin"
        )

        if selected not in valid_types:
            selected = "signin"
            error = "Invalid code type."

        email_value = (
            request.form.get("email") or ""
        ).strip()

        password_value = (
            request.form.get("password") or ""
        ).strip()

        email_lower = email_value.lower()

        is_mantapnet_email = (
            email_lower.endswith("@mantapnet.com")
        )

        if not error:

            # =============================================
            # SIGN-IN CODE
            # =============================================
            if selected == "signin":

                if not email_value:
                    error = "Please enter the account email."

                elif is_mantapnet_email:
                    # Mantapnet email:
                    # use direct IMAP search, no password required.
                    code, error = get_mantapnet_signin_code(
                        email_value
                    )

                elif not password_value:
                    error = (
                        "Please enter both email and password."
                    )

                else:
                    # Outlook/Hotmail/other accounts:
                    # use your existing Playwright/CDK method.
                    try:
                        code, error = get_auto_sign_in_code(
                            email_value,
                            password_value
                        )

                    except Exception as exc:
                        app.logger.exception(
                            "Sign-in code error: %s",
                            exc
                        )

                        error = (
                            "System is busy or timed out. "
                            "Please try again."
                        )

            # =============================================
            # VERIFICATION CODE
            # =============================================
            elif selected == "verification":

                if not email_value:
                    error = "Please enter the account email."

                elif is_mantapnet_email:
                    # Search:
                    # Your verification code
                    # Kod pengesahan anda
                    code, error = (
                        get_mantapnet_verification_code(
                            email_value
                        )
                    )

                elif not password_value:
                    error = (
                        "Please enter both email and password."
                    )

                else:
                    try:
                        code, error = get_verification_code(
                            email_value,
                            password_value
                        )

                    except Exception as exc:
                        app.logger.exception(
                            "Verification code error: %s",
                            exc
                        )

                        error = (
                            "System is busy or timed out. "
                            "Please try again."
                        )

            # =============================================
            # HOUSEHOLD CODE
            # =============================================
            elif selected == "household":

                if not email_value:
                    error = "Please enter the account email."

                elif is_mantapnet_email:
                    # Use your existing Mantapnet household
                    # mailbox method.
                    try:
                        code, error = household_code_from_mailbox(
                            email_value
                        )

                    except NameError:
                        # Use this only if you have not yet
                        # extracted /household-code into a helper.
                        error = (
                            "The Mantapnet household helper has "
                            "not been connected yet."
                        )

                else:
                    # Outlook/Hotmail household method.
                    try:
                        code, error = (
                            get_outlook_household_code(
                                email_value
                            )
                        )

                    except Exception as exc:
                        app.logger.exception(
                            "Household code error: %s",
                            exc
                        )

                        error = (
                            "System is busy or timed out. "
                            "Please try again."
                        )

    return render_template(
        "get_code.html",
        selected=selected,
        email=email_value,
        password=password_value,
        code=code,
        error=error
    )

# =========================================================
# SHORT CODE GUIDE PAGES
# =========================================================

@app.route("/video/<path:filename>")
def video_files(filename):
    return send_from_directory(
        "video",
        filename
    )


@app.route("/s")
def signin_guide():
    return render_template(
        "signin_guide.html"
    )


@app.route("/v")
def verification_guide():
    return render_template(
        "verification_guide.html"
    )

@app.route("/p")
def use_password_picture():
    return render_template("use_password.html")

# ---------------- MAIN ----------------
if __name__ == "__main__":
    app.run(debug=True)
