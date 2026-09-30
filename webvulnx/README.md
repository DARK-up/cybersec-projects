# WebVulnX v2.0 — Advanced Web Application Vulnerability Scanner

A full-featured web vulnerability scanner: smart crawler + a triple-engine SQLi
detector + XSS + directory brute-force + security misconfiguration auditing.

## ✨ Features

### 🔍 Smart Crawler
- Same-origin crawling with configurable depth (`--depth`) and page cap (`--max-urls`)
- Automatic form & parameter discovery
- Static asset filtering (images, CSS, ...)

### 🌐 Automatic Scope Expansion (why sub-page URLs no longer return nothing)
Handing a scanner a deep URL such as `http://site/login.jsp` used to produce
*"1 URL crawled, 0 forms, 0 findings"* — not because the site was secure, but
because nothing was ever discovered. WebVulnX now expands the scope itself:

| Step | What it does |
|------|--------------|
| **Site root** | Always adds `scheme://host/` and follows its redirect chain |
| **robots.txt** | Harvests every advertised `Disallow:` / `Allow:` path |
| **sitemap.xml** | Follows `Sitemap:` directives and pulls `<loc>` URLs |
| **Entry points** | Probes 25 common paths (`/login`, `/admin`, `/search`, `/api`, `/index.php`, …) and keeps the ones that answer — including `401/403` (protected login walls are attack surface too) |

Disable it when you want a strict single-URL scope:
`--no-root-expansion` and/or `--no-probe-paths`.

### 📈 Scan Coverage — proof of work
Every run prints (and stores in the JSON report) exactly what was tested, so an
empty result is never ambiguous:

```
────── Scan Coverage (proof of work) ──────
  Seed URLs          : 6
  URLs crawled       : 20
  Forms found        : 22
  Parameters seen    : 40
  Modules executed   : 4 (param-discovery, misconfig-audit, sqli, xss)
  HTTP requests sent : 2418
  Connection errors  : 0
  Blocked (4xx/5xx)  : 0  | WAF/challenge pages: 0
  Status codes       : 200×2139, 405×219, 404×59, 500×1
```

Two honest verdicts are emitted automatically:

- **`Scan degraded — WAF / rate-limit blocking`** — raised when challenge pages
  (Cloudflare, Akamai, Incapsula, Sucuri, captcha…) are detected or more than
  35% of requests were blocked/failed. A clean result in this state is **not**
  proof the target is secure, and the report says so.
- **`No attack surface discovered`** — raised when the crawl reached ≤2 URLs
  with 0 parameters and 0 forms, i.e. the injection engines literally had
  nothing to test (SPA/JS app, auth wall, blocked crawl). The report tells you
  which knob to turn (scan the root, raise `--depth`/`--max-urls`, pass
  `--cookie`, enable `--dirs`).

Otherwise a zero-finding run is reported as **tested-clean**, together with the
request count that backs the claim.

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
