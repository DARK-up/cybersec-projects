# 🛡️ CyberSec Projects — Red Team Portfolio

**4 battle-tested offensive security projects + a safe local training lab**

> ⚖️ **Legal disclaimer:** These tools are for **authorized** security testing and
> education only. Do not use them against systems you do not own or lack explicit
> written permission to test. Unauthorized access is illegal. You are solely
> responsible for how you use this software.

---

## 📦 Projects

| # | Project | Description | Tech |
|---|---------|-------------|------|
| 1 | **[NetRecon](netrecon/)** | Advanced network reconnaissance framework — async port scanning, service fingerprinting, host discovery, HTML/JSON reporting | Python (asyncio) — zero dependencies |
| 2 | **[WebVulnX](webvulnx/)** | Web application vulnerability scanner — SQLi (Error / Boolean-blind / Time-blind) + XSS + crawler + dirbuster + misconfig audit | Python (requests) |
| 3 | **[HashBreaker](hashbreaker/)** | Hash identification & cracking suite — dictionary + rules + mask attacks, multiprocessing, pure-Python MD4/NTLM | Python (multiprocessing) — zero dependencies |
| 4 | **[NetSentry](netsentry/)** | Real-time network threat detection — ARP spoofing, port scans, DNS tunneling, cleartext credential leakage | Python (scapy) |
| 5 | **[Demo Lab](demo-lab/)** | Intentionally vulnerable web app + fake services — practice the tools legally on your own machine | Python (stdlib) |
| 6 | **[DARK](dark/)** | ⚡ Unified Enterprise Security Platform v4.0.0 — Web/API/Net/DNS/Cloud/Container/SAST/Forensics, Asset & Risk Intel, Compliance, Remediation, Signed Plugins, RBAC/2FA & Governance | Python (FastAPI + SQLite/PostgreSQL) |

### DARK v4.0.0 Hardening & Reliability Updates (26-Point Closure)
- **Multi-Tenant & Secrets Isolation:** Per-tenant `vault_secrets` composite key (`UNIQUE(tenant_id, name)`), credential redaction across jobs/exports/`jobs_state.json` (`0o600`), and fail-closed CSRF enforcement (`dark_csrf` cookie + `X-CSRF-Token` header) on all session-authenticated state-changing endpoints including `/api/auth/*`.
- **Deployment & Database Integrity:** Split development (`docker-compose.yml`, loopback `127.0.0.1:8000`, non-exposed Redis) and production (`docker-compose.prod.yml`, `DARK_ENV=production`, strict startup secret checks), loud failure on invalid `DARK_POSTGRES_DSN` without silent SQLite fallback, and canonical `v2` `audit_logs` hash chain with `tenant_id` protection.
- **Evidence & Accuracy Discipline:** Compliance defaults unassessed controls to `Not Assessed` (`0%`), executive posture returns `Unknown` when coverage is absent, non-HTML MIME gating precedes instant XSS reporting, `HttpClient` defaults to `verify=True` (blocking `Authorization` over insecure TLS), SAST reports Python parse failures (`Not Analyzed`), and NetRecon/NetSentry/HashBreaker expose explicit `CAPABILITY_MATRIX` & certainty labels (`Confirmed` vs `Potential` vs `Observation`).
- **Packaging, CI & DR:** Standard Python packaging (`pyproject.toml`, `dark-api` CLI entrypoint, Python `>=3.10` AST compatibility, CycloneDX SBOM, `dark/requirements-lock.txt`), strict `.github/workflows/ci.yml`, and verified disaster recovery paths (`docs/DISASTER_RECOVERY.md`, `get_backup_manifest()`).

### DARK Enterprise v3 Capabilities (`modules/` & `dark/`)
- **Asset Intelligence (`modules/asset_intel.py`):** Asset inventory, domain/IP/service/API/cloud relationship mapping, criticality classification, and new-asset diff tracking.
- **Vulnerability & Risk Intelligence (`modules/vuln_intel.py`):** NVD/CPE/CVSS v3.1 & v4.0/EPSS/CISA KEV feed + separate **Severity / Confidence / Exploitability** axes & composite Risk Prioritization.
- **DevSecOps & Specialized Auditors:** **Cloud Security** (AWS/Azure/GCP IAM & storage), **Container & K8s Security + CycloneDX SBOM**, **Code Security SAST** (Python AST, JS/TS, Java, PHP, C/C++), **API Security** (REST/OpenAPI/GraphQL/BOLA/Mass-assignment), and **Digital Forensics** (Linux auth, Windows Event Logs, IOC correlation, PCAP timeline).
- **Compliance & Remediation:** Automated control evaluation across **OWASP ASVS, CIS Benchmarks, NIST CSF 2.0, ISO 27001, PCI DSS v4.0** + **Remediation Center** (assign, SLA due date, fix evidence, verified retest closure).
- **Plugin Marketplace & Enterprise Governance:** HMAC-SHA256 signed plugin manifests with self-test cases (`modules/plugin_mgr.py`), **RBAC + RFC 6238 TOTP 2FA**, tamper-evident SHA-256 **Audit Trail**, encrypted **Credential Vault**, **Scope Allowlist**, **Emergency Stop**, Worker health, recurring **Scan Scheduler**, **Job Recovery**, **Backup & Restore**, plus `Dockerfile`, `docker-compose.yml`, and GitHub Actions CI.

---

## 🚀 Quick Start

```bash
# Install DARK + WebVulnX + NetSentry dependencies
pip install -r dark/requirements.txt

# 0) Launch the unified DARK platform (recommended)
cd dark
python3 -m uvicorn main:app --host 0.0.0.0 --port 8000
# Open http://127.0.0.1:8000

# 1) Start the local training lab
cd demo-lab
python3 vuln_app.py 8080 &        # vulnerable web app on http://127.0.0.1:8080
python3 fake_services.py &        # fake SSH/FTP/SMTP/IMAP/Redis banners

# 2) Discover the network
cd ../netrecon
python3 netrecon.py -t 127.0.0.1 -p top100 --json reports/scan.json --html reports/scan.html

# 3) Scan the web application (conservative default: 1.0 req/s)
cd ../webvulnx
# Safe Bug Bounty / external authorized scan with rate limiting & custom program headers:
python3 webvulnx.py -u https://target.example --full --rate-limit 1.0 \
  --header "Deck-Research: your-handle" --header "X-Bron-Bugbounty: your-handle" \
  --html reports/web.html

# Local training lab only (high-rate unlimited mode):
python3 webvulnx.py -u http://127.0.0.1:8080 --full --rate-limit 0 --html reports/web.html
```

### WebVulnX `--rate-limit` & `--header` Usage
- **`--rate-limit <RPS>` (default: `1.0` req/s):** Enforces a global maximum HTTP request rate across **all** modules (`Crawler`, `SqliScanner` including `time-blind` SQLi + neutral controls, `DeepXssScanner`, `DirBuster`, `AdvancedScanner`, `WorldScanner`, and retries). While `RateGate` pauses requests to respect the RPS cap, `SqliScanner` measures pure network RTT (`last_network_rtt`) separately so low `--rate-limit` values (e.g. `0.5` req/s) never cause time-based SQLi false positives. Pass `--rate-limit 0` only against local labs (`127.0.0.1`).
- **`--header "Name: Value"` (repeatable):** Injects custom HTTP headers into **every** outgoing request across all modules (such as bug-bounty identification requirements `Deck-Research` and `X-Bron-Bugbounty`), without being overwritten by stealth `Referer` defaults.

# 4) Crack sample hashes
cd ../hashbreaker
python3 hashbreaker.py identify -x 5f4dcc3b5aa765d61d8327deb882cf99
python3 hashbreaker.py crack -x 098f6bcd4621d373cade4e832627b4f6 -w wordlists/common-pass.txt --rules

# 5) Monitor the network (demo mode — no root needed)
cd ../netsentry
python3 netsentry.py --demo --report reports/summary.json
# or live capture (requires root):
# sudo python3 netsentry.py --live -i eth0 --gateway 192.168.1.1
```

---

## 🎯 Skills Covered

### Offensive / Red Team
- **Network & DNS reconnaissance**: async TCP scanning, banner grabbing, service/version fingerprinting, OS hinting, Nessus-style CVE plugins, DNS/SPF/DMARC/CAA audit, subdomain enumeration, and CNAME takeover detection
- **Web application security**: SQLi (error-based, boolean-blind, time-based blind), context-aware deep XSS + DOM analysis, Nuclei-style YAML templates, OpenAPI/Swagger ingestion, auto-login (CSRF + JWT), soft-404 dirbusting, LFI/SSTI/CMDi/SSRF/XXE/CORS/CRLF, and TLS/SSL auditing
- **Password security**: hash identification (25+ formats), multi-algorithm auto-matching (MD5, NTLM, MD4, MySQL5 `*...`, SHA1/SHA256/SHA512/SHA3/BLAKE2, LDAP, Django/Werkzeug PBKDF2, salted variants), dictionary / rules / mask attacks, and local hash generator
- **Threat detection**: ARP poisoning, SYN/XMAS scans, DNS tunneling, cleartext credential exposure
- **Unified DARK platform**: parallel isolated jobs, Stop & Partial Report, per-finding inline breakdown, project management, scan diff comparison, and unified Project Executive HTML/PDF reports

### Engineering Skills
- High-concurrency async programming (asyncio)
- Multiprocessing cracking engine
- Custom protocol fingerprinting databases
- Heuristic detection (similarity matching, entropy analysis, rate windows)
- Pure-Python MD4 implementation (RFC 1320) with full test-vector validation
- Professional reporting (JSON / HTML / JSONL)
- Clean CLI design (argparse) with timing profiles

---

## 📂 Repository Layout

```
cybersec-projects/
├── README.md                  ← you are here
├── netrecon/                  ← Project 1: network reconnaissance
│   ├── netrecon.py
│   ├── requirements.txt
│   └── reports/
├── webvulnx/                  ← Project 2: web vulnerability scanner
│   ├── webvulnx.py
│   ├── wordlists/dirs.txt
│   └── reports/
├── hashbreaker/               ← Project 3: hash cracking suite
│   ├── hashbreaker.py
│   ├── wordlists/common-pass.txt
│   └── reports/
├── netsentry/                 ← Project 4: network threat detection
│   ├── netsentry.py
│   └── reports/
└── demo-lab/                  ← legal local training target
    ├── vuln_app.py
    └── fake_services.py
```

---

## ✅ Actually Tested (not just written)

| Test | Result |
|------|--------|
| NetRecon: SSH / FTP / SMTP / IMAP / Redis / HTTP fingerprinting with versions | ✅ |
| NetRecon: OS hinting from banners + JSON/HTML reports | ✅ |
| WebVulnX: Error-based SQLi (Critical) on `/page` and `/login` | ✅ |
| WebVulnX: Boolean-blind + Time-blind SQLi on `/news` | ✅ |
| WebVulnX: Reflected XSS + DirBuster (`.env`, `backup.sql`, `admin`) | ✅ |
| HashBreaker: MD5/NTLM identification + dictionary / rules / mask cracking | ✅ |
| HashBreaker: pure-Python MD4 validated against the full RFC 1320 test suite | ✅ |
| NetSentry: ARP spoof + SYN scan + DNS tunnel + cleartext credential detection | ✅ |

---

## 📖 Certification Alignment

These projects map well to the practical domains of:
- **OSCP / eJPT / PNPT** (offensive track)
- **CEH / CompTIA Security+** (foundations)
- **Blue Team Level 1 (BTL1)** — NetSentry covers the defensive side

Each project is structured as a **portfolio piece** with an independent README,
real test results, and clean, readable code.
