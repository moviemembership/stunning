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
import os, imaplib, email, json
from flask import abort
import socket
from urllib.parse import quote
socket.setdefaulttimeout(12)  # global timeout for IMAP socket

EMAIL_PEEK_TOKEN = os.environ.get("EMAIL_PEEK_TOKEN")
REPLACEMENT_FILE = os.getenv("REPLACEMENTS_FILE", "/etc/secrets/replacements.txt")

CLICK_COUNT_FILE = os.getenv("CLICK_COUNT_FILE", "/var/data/shopee_clicks.json")

SIGNIN_URL = "https://yzmen.4knaifei.cn"

signin_playwright = None
signin_browser = None
signin_lock = threading.Lock()
signin_request_count = 0

OUTLOOK_URL = "https://yz.naifei.store/#/login"

AUTO_SIGNIN_URL = "https://yzmen.4knaifei.cn"

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

# ---------------- OUTLOOK SIGN IN CODE ----------------#
def get_auto_sign_in_code(account_email, account_password):
    return asyncio.run(_get_auto_sign_in_code_async(account_email, account_password))

async def _get_auto_sign_in_code_async(account_email, account_password):
    real_password = account_password.strip()

    if real_password == "qwe222":
        found_password = False
        try:
            with open("password.txt", "r", encoding="utf-8") as f:
                for line in f:
                    parts = re.split(r"\s+", line.strip())
                    if len(parts) >= 2 and parts[0].lower() == account_email.strip().lower():
                        real_password = parts[1]
                        found_password = True
                        break

            if not found_password:
                return None, "Email not updated. Please ask admin to update."

        except Exception as e:
            return None, f"Unable to read password.txt: {str(e)}"

    query_text = f"{account_email.strip()}----{real_password}"

    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-blink-features=AutomationControlled"
            ]
        )

        try:
            context = await browser.new_context(
                viewport={"width": 1400, "height": 900},
                locale="en-US"
            )

            page = await context.new_page()
            page.set_default_timeout(30000)

            cdk_value = quote(query_text, safe="")
            auto_url = f"https://yzmen.4knaifei.cn//#/?cdk={cdk_value}"
            
            await page.goto(
                auto_url,
                wait_until="domcontentloaded",
                timeout=45000
            )

            result = None
            start_time = time.time()

            while time.time() - start_time < 15:
                body_text = await page.locator("body").inner_text()

                if "CDK Does Not Exist" in body_text:
                    return None, "Password incorrect. Please check and try again."

                if "Click Replace" in body_text:
                    result = "replace"
                    break

                await page.wait_for_timeout(500)

            if result != "replace":
                return None, "Unable to verify account. Please try again."

            try:
                ok_btn = page.locator(".ant-modal-confirm-btns button").last
                if await ok_btn.count() > 0:
                    await ok_btn.click(timeout=5000)
                    await page.wait_for_timeout(1000)
            except Exception:
                pass

            await page.get_by_text("Click Replace", exact=True).click(timeout=8000, force=True)

            try:
                await page.get_by_text("OK", exact=True).click(timeout=8000)
            except Exception:
                pass

            try:
                await page.wait_for_function(
                    """
                    () => {
                        const text = document.body.innerText || "";
                        return (
                            text.includes("Successfully obtained verification code") ||
                            text.includes("We have not received the latest verification code")
                        );
                    }
                    """,
                    timeout=30000
                )
            except Exception:
                pass

            final_text = await page.locator("body").inner_text()

            latest_code = None

            inputs = await page.locator("input").all()
            for inp in inputs:
                try:
                    value = (await inp.input_value()).strip()
                    if re.fullmatch(r"\d{4}", value):
                        latest_code = value
                        break
                except Exception:
                    pass

            if latest_code:
                return latest_code, None

            if "We have not received the latest verification code" in final_text:
                return None, "No new code received. Please send the sign-in code first."

            return None, "No 4-digit code found. Please send the sign-in code first and try again."

        except Exception as e:
            return None, f"System error: {str(e)}"

        finally:
            await browser.close()

# ---------------- OUTLOOK HOUSEHOLD CODE ----------------#

def get_outlook_household_code(user_email):
    return asyncio.run(_get_outlook_household_code_async(user_email))


async def _get_outlook_household_code_async(user_email):
    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-blink-features=AutomationControlled"
            ]
        )

        try:
            context = await browser.new_context(
                viewport={"width": 1800, "height": 900},
                locale="en-US"
            )

            page = await context.new_page()
            page.set_default_timeout(30000)

            await page.goto(
                OUTLOOK_URL,
                wait_until="domcontentloaded",
                timeout=60000
            )

            # switch to English every time
            try:
                await page.locator("text=简体中文").click(timeout=5000)
                await page.get_by_text("English", exact=True).click(timeout=5000)
                await page.wait_for_timeout(800)
            except Exception:
                pass

            await page.locator("input").first.wait_for(state="visible", timeout=30000)
            await page.locator("input").first.fill(user_email)

            try:
                await page.get_by_text("Query verification code", exact=True).click(timeout=10000)
            except Exception:
                await page.locator("button").first.click(timeout=10000)

            await page.wait_for_timeout(1500)

            body_text = await page.locator("body").inner_text()

            if (
                "The email verification code data has not been obtained yet" in body_text
                or "尚未获取到邮箱验证码数据" in body_text
                or "has not been obtained" in body_text
            ):
                return None, "No household code found. Please make sure you sent the household code email first."

            if (
                "邮箱验证码已过期" in body_text
                or "expired" in body_text.lower()
                or "已过期" in body_text
            ):
                return None, "Link was expired. Please resend the code and try again."

            code_page = page
            clicked = False

            for txt in ["OK", "确定"]:
                if clicked:
                    break

                try:
                    async with context.expect_page(timeout=8000) as new_page_info:
                        await page.get_by_text(txt, exact=True).click(timeout=3000)

                    code_page = await new_page_info.value
                    clicked = True

                except Exception:
                    try:
                        await page.get_by_text(txt, exact=True).click(timeout=3000)
                        code_page = page
                        clicked = True
                    except Exception:
                        pass

            if not clicked:
                return None, "Confirm button not found. Please try again."

            await code_page.wait_for_load_state("domcontentloaded", timeout=30000)
            await code_page.wait_for_timeout(1500)

            full_text = await code_page.locator("body").inner_text()
            full_url = code_page.url

            if "This link is no longer valid" in full_text:
                return None, "Link was expired. Please resend the code and try again."

            if "Please request again on the original device" in full_text:
                return None, "Link was expired. Please resend the code and try again."

            match = re.search(r"\b\d{4}\b", full_text + " " + full_url)

            if match:
                return match.group(0), None

            return None, "Code page opened, but no 4-digit code found."

        except Exception as e:
            return None, f"System error: {str(e)}"

        finally:
            await browser.close()

# ---------------- 6-DIGIT VERIFICATION CODE ----------------
def get_verification_code(account_email, account_password):
    return asyncio.run(
        _get_verification_code_async(account_email, account_password)
    )


async def _get_verification_code_async(account_email, account_password):
    real_password = account_password.strip()

    # If user types qwe222, get real password from password.txt
    if real_password == "qwe222":
        found_password = False

        try:
            with open("password.txt", "r", encoding="utf-8") as f:
                for line in f:
                    parts = re.split(r"\s+", line.strip())

                    if len(parts) >= 2 and parts[0].lower() == account_email.strip().lower():
                        real_password = parts[1]
                        found_password = True
                        break

            if not found_password:
                return None, "Email not updated. Please ask admin to update."

        except Exception as e:
            return None, f"Unable to read password.txt: {str(e)}"

    query_text = f"{account_email.strip()}----{real_password}"

    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-blink-features=AutomationControlled"
            ]
        )

        try:
            context = await browser.new_context(
                viewport={"width": 1400, "height": 900},
                locale="en-US"
            )

            page = await context.new_page()
            page.set_default_timeout(30000)

            cdk_value = quote(query_text, safe="")
            auto_url = f"https://yzmen.4knaifei.cn//#/?cdk={cdk_value}"

            await page.goto(
                auto_url,
                wait_until="domcontentloaded",
                timeout=45000
            )

            result = None
            start_time = time.time()

            while time.time() - start_time < 15:
                body_text = await page.locator("body").inner_text()

                if "CDK Does Not Exist" in body_text:
                    return None, "Password incorrect. Please check and try again."

                if "Click Replace" in body_text:
                    result = "replace"
                    break

                await page.wait_for_timeout(500)

            if result != "replace":
                return None, "Unable to verify account. Please try again."

            # Close blocking modal first
            try:
                ok_btn = page.locator(".ant-modal-confirm-btns button").last
                if await ok_btn.count() > 0:
                    await ok_btn.click(timeout=5000)
                    await page.wait_for_timeout(1000)
            except Exception:
                pass

            await page.get_by_text("Click Replace", exact=True).click(
                timeout=8000,
                force=True
            )

            # Click OK popup if shown
            try:
                await page.get_by_text("OK", exact=True).click(timeout=8000)
            except Exception:
                pass

            # Wait for success / no-code prompt
            try:
                await page.wait_for_function(
                    """
                    () => {
                        const text = document.body.innerText || "";
                        return (
                            text.includes("Successfully obtained verification code") ||
                            text.includes("We have not received the latest verification code")
                        );
                    }
                    """,
                    timeout=30000
                )
            except Exception:
                pass

            final_text = await page.locator("body").inner_text()

            latest_code = None

            # ✅ Only accept 6-digit code
            inputs = await page.locator("input").all()
            for inp in inputs:
                try:
                    value = (await inp.input_value()).strip()

                    if re.fullmatch(r"\d{6}", value):
                        latest_code = value
                        break

                except Exception:
                    pass

            # Backup: search visible page text for 6 digits only
            if not latest_code:
                match = re.search(r"\b\d{6}\b", final_text)
                if match:
                    latest_code = match.group(0)

            if latest_code:
                return latest_code, None

            if "We have not received the latest verification code" in final_text:
                return None, "No new verification code received. Please send the verification code first."

            return None, "No 6-digit verification code found. Please send the verification code first and try again."

        except Exception as e:
            return None, f"System error: {str(e)}"

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

# ---------------- MAIN ----------------
if __name__ == "__main__":
    app.run(debug=True)
