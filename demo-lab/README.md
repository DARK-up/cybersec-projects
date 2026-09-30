# Demo Lab — Safe Training Environment ⚠️

An **intentionally vulnerable** web app + fake network services so you can
practice with the NetRecon / WebVulnX tools **100% legally** on your own machine.

> 🚨 **Warning**: This application is insecure **on purpose**. Never deploy it
> on a public network or any production server.

## 🚀 Running the Lab

```bash
# Terminal 1: the vulnerable web app (port 8080)
python3 vuln_app.py 8080

# Terminal 2: fake services for NetRecon fingerprinting
python3 fake_services.py
```

## 🎯 Planted Vulnerabilities (for detection practice)

| Path | Vulnerability | Detecting tool |
|------|---------------|----------------|
| `/search?q=` | Reflected XSS (raw reflection) | WebVulnX XSS engine |
| `/page?id=` | Error-based SQLi (MySQL error message) | WebVulnX SQLi engine |
| `/news?id=` | Boolean + time-based blind SQLi | WebVulnX SQLi engine |
| `/login` (POST) | SQLi in the `user` field | WebVulnX SQLi engine |
| `/admin` | Hidden admin panel | DirBuster |
| `/backup.sql` | Database dump exposure | DirBuster (High) |
| `/robots.txt` | Discloses `/secret-panel` | DirBuster + Audit |
| `/.env` | Secrets leak (DB_PASS, API_KEY) | DirBuster (High) |
| Headers | No security headers + banner disclosure | Misconfig Audit |

## 🔧 Fake Services (fake_services.py)

| Port | Service | Banner |
|------|---------|--------|
| 2222 | SSH | OpenSSH_8.9p1 Ubuntu |
| 2121 | FTP | ProFTPD 1.3.5 (Debian) |
| 2525 | SMTP | Postfix (Ubuntu) |
| 1143 | IMAP | Dovecot |
| 6380 | Redis | +PONG |

## 🧪 Full Training Scenario

```bash
# 1) Start the lab
python3 vuln_app.py 8080 &
python3 fake_services.py &

# 2) Discover with NetRecon
cd ../netrecon
python3 netrecon.py -t 127.0.0.1 -p 2222,2121,2525,6380,1143,8080 --no-resolve

# 3) Scan the web app with WebVulnX
cd ../webvulnx
python3 webvulnx.py -u http://127.0.0.1:8080 --full --time-blind 3 \
  --json reports/lab.json --html reports/lab.html

# 4) Open the report
# reports/lab.html
```

## 📝 Notes

All "vulnerabilities" are lightweight simulations (Python stdlib only). The goal
is to teach the complete security-assessment workflow:
Recon → Crawl → Vulnerability scanning → Reporting.
