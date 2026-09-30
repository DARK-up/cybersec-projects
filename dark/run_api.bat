@echo off
title DARK - Detection ^& Attack Reconnaissance Kit
cd /d "%~dp0"

echo ============================================
echo    DARK  -  Unified CyberSec Suite API
echo ============================================
echo.

where python >nul 2>nul
if errorlevel 1 (
  echo [X] Python not found! Install it from https://python.org
  echo     IMPORTANT: check "Add Python to PATH" during install
  pause
  exit /b 1
)

echo [1/2] Installing dependencies ...
python -m pip install --upgrade pip >nul 2>&1
python -m pip install -r requirements.txt

echo.
echo [2/2] Starting DARK API ...
echo.
echo   Dashboard : http://localhost:8000
echo   API docs  : http://localhost:8000/docs
echo.
echo   NOTE: NetSentry live capture needs Npcap (https://npcap.com)
echo         and running this file as Administrator.
echo.
python -m uvicorn main:app --host 0.0.0.0 --port 8000

pause
