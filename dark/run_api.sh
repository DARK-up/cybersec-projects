#!/usr/bin/env bash
# DARK — Detection & Attack Reconnaissance Kit (Linux / macOS / Kali)
set -e
cd "$(dirname "$0")"

echo "============================================"
echo "   DARK  -  Unified CyberSec Suite API"
echo "============================================"
echo

python3 -m pip install -r requirements.txt

echo
echo "  Dashboard : http://localhost:8000"
echo "  API docs  : http://localhost:8000/docs"
echo
echo "  NOTE: live capture needs root: sudo .venv/bin/python3 -m uvicorn main:app"
echo

python3 -m uvicorn main:app --host 0.0.0.0 --port 8000
