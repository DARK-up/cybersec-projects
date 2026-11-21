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
| 6 | **[DARK](dark/)** | ⚡ Unified Enterprise Security Platform v3.0 — Web/API/Net/DNS/Cloud/Container/SAST/Forensics, Asset & Risk Intel, Compliance, Remediation, Signed Plugins, RBAC/2FA & Governance | Python (FastAPI + SQLite) |

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

# 3) Scan the web application
cd ../webvulnx
python3 webvulnx.py -u http://127.0.0.1:8080 --full --html reports/web.html

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
