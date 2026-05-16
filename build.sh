#!/usr/bin/env bash
set -o errexit

pip install -r requirements.txt
PLAYWRIGHT_BROWSERS_PATH=0 python -m playwright install chromium
