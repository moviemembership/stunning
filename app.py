import re
from datetime import datetime, timedelta, timezone
from flask import Flask, request, render_template, redirect, session
from werkzeug.security import generate_password_hash, check_password_hash
from email_validator import validate_email, EmailNotValidError
import os
import smtplib, ssl, secrets, time
from email.message import EmailMessage
import imaplib, email, re as _re
import requests
from bs4 import BeautifulSoup
import pathlib

REPLACEMENT_FILE = os.getenv("REPLACEMENTS_FILE", "/etc/secrets/replacements.txt")

# ---------------- CONFIG ----------------

IMAP_HOST = "mail.mantapnet.com"
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL")
ADMIN_PASS = os.environ.get("ADMIN_PASS")

# ---------------- FLASK APP ----------------
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "devkey")  # required for session

# ---------------- HELPERS ----------------
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
    """
    Finds Netflix sign-in code emails (EN/MY) in the last 15 minutes,
    matching the entered email address inside the email body, and extracts a 4-digit code.
    """
    code = None
    error = None
    entered = ""

    if request.method == "POST":
        entered = (request.form.get("email") or "").strip()
        try:
            mail = imaplib.IMAP4_SSL(IMAP_HOST)
            mail.login(ADMIN_EMAIL, ADMIN_PASS)
            mail.select("inbox")

            since_1day = (datetime.utcnow() - timedelta(days=1)).strftime("%d-%b-%Y")
            crit = f'(SINCE {since_1day} OR (SUBJECT "Your sign-in code") (SUBJECT "Kod daftar masuk anda"))'
            status, data = mail.uid("search", None, crit)
            if status != "OK" or not data or not data[0]:
                error = "No recent sign-in email found."
            else:
                uids = data[0].split()
                cutoff = datetime.now(timezone.utc) - timedelta(minutes=15)

                for uid in reversed(uids[-30:]):  # newest 30 only
                    status, hdr = mail.uid("fetch", uid, '(BODY.PEEK[HEADER.FIELDS (DATE SUBJECT TO FROM)])')
                    if status != "OK" or not hdr or not hdr[0]:
                        continue

                    msg_hdr = email.message_from_bytes(hdr[0][1])
                    dt_tuple = email.utils.parsedate_tz(msg_hdr.get("Date"))
                    if not dt_tuple:
                        continue
                    sent_utc = datetime.fromtimestamp(email.utils.mktime_tz(dt_tuple), tz=timezone.utc)
                    if sent_utc < cutoff:
                        break

                    status, body_data = mail.uid("fetch", uid, "(BODY.PEEK[])")
                    if status != "OK" or not body_data or not body_data[0]:
                        continue

                    body = _extract_email_body(email.message_from_bytes(body_data[0][1])) or ""
                    if entered.lower() in body.lower():
                        m = _re.search(r"\b\d{4}\b", body)
                        if m:
                            code = m.group(0)
                            break

                if not code and not error:
                    error = "No recent sign-in email found for this address. Request a code again within 15 minutes."
            mail.logout()
        except Exception as e:
            error = f"Error: {e}"

    return render_template("sign_in_code.html", email=entered if request.method == "POST" else "", code=code, error=error)

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
    Looks for Netflix 'Temporary Access Code' / 'Kod akses sementara'
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
            s1, d1 = mail.uid("search", None, f'(SINCE {since_str} SUBJECT "Temporary Access Code")')
            s2, d2 = mail.uid("search", None, f'(SINCE {since_str} SUBJECT "Kod akses sementara")')

            ids1 = d1[0].split() if s1 == "OK" and d1 and d1[0] else []
            ids2 = d2[0].split() if s2 == "OK" and d2 and d2[0] else []
            all_ids = ids1 + ids2

            if not all_ids:
                error = "No recent 'Temporary Access Code' emails found."
            else:
                matched_uid = None
                cutoff = datetime.now(timezone.utc) - timedelta(minutes=15)

                for uid in reversed(all_ids[-50:]):
                    st_hdr, hdr = mail.uid("fetch", uid, '(BODY.PEEK[HEADER.FIELDS (DATE SUBJECT TO FROM)])')
                    if st_hdr != "OK" or not hdr or not hdr[0]:
                        continue

                    msg_hdr = email.message_from_bytes(hdr[0][1])
                    dt_tuple = email.utils.parsedate_tz(msg_hdr.get("Date"))
                    if not dt_tuple:
                        continue

                    sent_utc = datetime.fromtimestamp(email.utils.mktime_tz(dt_tuple), tz=timezone.utc)
                    if sent_utc < cutoff:
                        break

                    st_body, body_data = mail.uid("fetch", uid, "(BODY.PEEK[])")
                    if st_body != "OK" or not body_data or not body_data[0]:
                        continue

                    body = _extract_email_body(email.message_from_bytes(body_data[0][1])) or ""
                    if entered in body.lower():
                        matched_uid = uid
                        break

                if matched_uid:
                    st_full, full_data = mail.uid("fetch", matched_uid, "(BODY.PEEK[])")
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

# ---------------- MAIN ----------------
if __name__ == "__main__":
    app.run(debug=True)
