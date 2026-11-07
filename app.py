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
