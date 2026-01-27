import re
from datetime import datetime, timedelta, timezone, UTC
from flask import Flask, request, render_template, redirect, session, jsonify, send_from_directory
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
socket.setdefaulttimeout(12)  # global timeout for IMAP socket

EMAIL_PEEK_TOKEN = os.environ.get("EMAIL_PEEK_TOKEN")
REPLACEMENT_FILE = os.getenv("REPLACEMENTS_FILE", "/etc/secrets/replacements.txt")

CLICK_COUNT_FILE = os.getenv("CLICK_COUNT_FILE", "/var/data/shopee_clicks.json")

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

# ---------------- MAIN ----------------
if __name__ == "__main__":
    app.run(debug=True)
