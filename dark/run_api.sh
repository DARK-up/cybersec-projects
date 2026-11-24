#!/usr/bin/env bash
# DARK — Detection & Attack Reconnaissance Kit (Linux / macOS / Kali)
set -e
cd "$(dirname "$0")"

echo "============================================"
echo "   DARK  -  Unified CyberSec Suite API"
echo "============================================"
echo

# Kali/Debian 2023+ block global pip installs (PEP 668) -> use a venv
if [ ! -d ".venv" ]; then
  echo "[1/3] Creating virtual environment (.venv) ..."
  python3 -m venv .venv
else
  echo "[1/3] Virtual environment found."
fi

echo "[2/3] Installing dependencies ..."
.venv/bin/python -m pip install --upgrade pip >/dev/null 2>&1 || true
.venv/bin/python -m pip install -r requirements.txt

echo
echo "[3/3] Starting DARK API ..."
echo
DARK_HOST="${DARK_HOST:-127.0.0.1}"
DARK_PORT="${DARK_PORT:-8000}"
echo "   Dashboard : http://${DARK_HOST}:${DARK_PORT}"
echo "   API docs  : http://${DARK_HOST}:${DARK_PORT}/docs"
echo
echo "   NOTE: live capture needs root:"
echo "         sudo .venv/bin/python3 -m uvicorn main:app --host ${DARK_HOST} --port ${DARK_PORT}"
echo

.venv/bin/python -m uvicorn main:app --host "${DARK_HOST}" --port "${DARK_PORT}"
