# WebVulnX v2.0 — Advanced Web Application Vulnerability Scanner

A full-featured web vulnerability scanner: smart crawler + a triple-engine SQLi
detector + XSS + directory brute-force + security misconfiguration auditing.

## ✨ Features

### 🔍 Smart Crawler
- Same-origin crawling with configurable depth (`--depth`) and page cap (`--max-urls`)
- Automatic form & parameter discovery
- Static asset filtering (images, CSS, ...)

### 💉 SQL Injection Engine (3 techniques)
| Technique | Description |
|-----------|-------------|
| **Error-Based** | 30+ DBMS error signatures (MySQL, MSSQL, Oracle, PostgreSQL, SQLite, MSAccess, DB2, ...) |
| **Boolean-Based Blind** | Response comparison via `difflib` similarity ratios |
| **Time-Based Blind** | SLEEP / WAITFOR / pg_sleep / DBMS_PIPE payloads with response-time analysis |

- Tests query parameters, form fields, and numeric URL path segments (`/item/123`)

### 🎯 Reflected XSS Engine
- 14 context-aware polyglot payloads with encoding bypasses
- Distinguishes **executable XSS** (script actually runs) from **reflected-only**
  (exploitability depends on context)

### 📂 Directory Brute-Force
- 200+ high-value paths (`.git`, `.env`, backups, admin panels, actuator, swagger, ...)
- Automatic severity scoring based on path sensitivity

### 🔒 Misconfiguration Audit
- Security headers (HSTS, CSP, X-Frame-Options, ...)
- Cookie flags (Secure, HttpOnly)
- Dangerous HTTP methods (TRACE / PUT / DELETE)
- Banner disclosure + `robots.txt` analysis

## 🚀 Usage

```bash
# Full scan (all engines)
python3 webvulnx.py -u https://target.example --full

# SQLi + XSS only
python3 webvulnx.py -u https://target.example/app --sqli --xss

# Directory busting with a custom wordlist
python3 webvulnx.py -u https://target.example --dirs -w wordlists/dirs.txt

# With JSON + HTML reports
python3 webvulnx.py -u https://target.example --full \
  --json reports/scan.json --html reports/scan.html

# Behind a proxy (e.g. Burp Suite) with session cookies
python3 webvulnx.py -u https://target.example --full \
  --proxy http://127.0.0.1:8080 --cookie "PHPSESSID=abc123"

# Basic WAF throttling (delay between requests)
python3 webvulnx.py -u https://target.example --sqli --delay 0.5 --time-blind 8
```

## 🧪 Try It on the Demo Lab

```bash
cd ../demo-lab && python3 vuln_app.py 8080 &
python3 webvulnx.py -u http://127.0.0.1:8080 --full --time-blind 3
```

Expected findings on the lab:

```
[Critical] SQL Injection (Error-Based)   [id]   -> /page?id=1
[High]     SQL Injection (Boolean-Blind) [id]   -> /news?id=1
[High]     SQL Injection (Time-Blind)    [id]   -> /news?id=1
[Critical] SQL Injection (Error-Based)   [user] -> /login  (POST)
[High]     Reflected XSS (Executable)    [q]    -> /search
[High]     Sensitive Path Exposed               -> /.env, /backup.sql
[Medium]   Sensitive Path Exposed               -> /admin
```

## 📊 Reporting

- **Console**: color-coded severity tags + evidence lines
- **JSON**: machine-readable output (SIEM-friendly)
- **HTML**: professional dark-theme report for stakeholders

## ⚖️ Legal

Only test applications you own or have explicit written authorization to assess.
Always obtain written permission before testing.
