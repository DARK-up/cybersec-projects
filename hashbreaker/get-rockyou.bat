@echo off
REM ---------------------------------------------------------------------------
REM  HashBreaker - get rockyou.txt on Windows (14.3M passwords, ~139 MB)
REM  Double-click this file, or run:  get-rockyou.bat
REM  rockyou.txt is NOT stored in git (GitHub rejects files larger than 100 MB).
REM ---------------------------------------------------------------------------
setlocal
cd /d "%~dp0wordlists"
set "DEST=rockyou.txt"
set "GZ=%TEMP%\rockyou.txt.gz"

if exist "%DEST%" (
  echo [+] %DEST% already present.
  goto :done
)

echo [*] Downloading rockyou wordlist ^(about 51 MB compressed^) ...
powershell -NoProfile -Command ^
  "$ErrorActionPreference='Stop';" ^
  "$urls=@('https://gitlab.com/kalilinux/packages/wordlists/-/raw/kali/master/rockyou.txt.gz','https://raw.githubusercontent.com/praetorian-inc/Hob0Rules/master/wordlists/rockyou.txt.gz');" ^
  "foreach($u in $urls){ try{ Invoke-WebRequest -Uri $u -OutFile '%GZ%' -UseBasicParsing; if((Get-Item '%GZ%').Length -gt 1000000){ break } }catch{} };" ^
  "$in=[IO.File]::OpenRead('%GZ%'); $gz=New-Object IO.Compression.GzipStream($in,[IO.Compression.CompressionMode]::Decompress);" ^
  "$out=[IO.File]::Create('%DEST%'); $gz.CopyTo($out); $out.Close(); $gz.Close(); $in.Close();"

if exist "%DEST%" (
  del "%GZ%" 2>nul
  echo [+] rockyou.txt is ready in %CD%
) else (
  echo [-] Download failed. Put any large wordlist at %CD%\%DEST%
)

:done
echo.
echo Select it in the DARK dashboard under HashBreaker ^> Wordlist ^> rockyou.txt
pause
