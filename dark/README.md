# DARK — Detection & Attack Reconnaissance Kit

<p align="center">
  <img src="logo.png" alt="DARK logo" width="220">
</p>

**One API + one dashboard to drive all four security tools** — on Windows, Linux or macOS.

| Module | Tool | What it does |
|--------|------|--------------|
| `/api/jobs/network-scan` | **NetRecon** | Async port scan + service/OS fingerprinting |
| `/api/jobs/web-scan` | **WebVulnX** | SQLi (3 engines) + XSS + crawler + dirbuster + audit |
| `/api/hash/*` | **HashBreaker** | Hash identification + dictionary/rules/mask cracking |
| `/api/jobs/monitor-*` | **NetSentry** | ARP spoof / scans / DNS tunnel detection (live, pcap, demo) |

## 🚀 Quick Start

### Windows (easiest)
```bat
:: 1) Install Python from python.org (check "Add Python to PATH")
:: 2) Double-click:
run_api.bat
```

### Kali / Linux / macOS
```bash
chmod +x run_api.sh
./run_api.sh
```

Then open **http://localhost:8000** — the dashboard with the DARK logo 🎯

- **API docs (Swagger):** http://localhost:8000/docs
- **Health check:** `GET /api/health`

## 🖥️ Windows Notes

| Feature | Requirement |
|---------|-------------|
| Network scan / Web scan / Hashes | Python only — works out of the box |
| NetSentry live capture | Install **[Npcap](https://npcap.com)** + run as **Administrator** |
| NetSentry PCAP analysis | Npcap not required |

## 📡 API Examples (curl)

```bash
# Health
curl http://localhost:8000/api/health

# Network scan
curl -X POST http://localhost:8000/api/jobs/network-scan \
  -H "Content-Type: application/json" \
  -d '{"targets":["192.168.1.0/24"],"ports":"top100","timing":"normal"}'

# Web scan
curl -X POST http://localhost:8000/api/jobs/web-scan \
  -H "Content-Type: application/json" \
  -d '{"url":"http://target.example","sqli":true,"xss":true}'

# Identify a hash (instant response)
curl -X POST http://localhost:8000/api/hash/identify \
  -H "Content-Type: application/json" \
  -d '{"hashes":["5f4dcc3b5aa765d61d8327deb882cf99"]}'

# Crack with the built-in wordlist + rules
curl -X POST http://localhost:8000/api/jobs/hash-crack \
  -H "Content-Type: application/json" \
  -d '{"hashes":["098f6bcd4621d373cade4e832627b4f6"],"wordlist":"common","rules":true}'

# Monitor: synthetic demo (no root needed)
curl -X POST http://localhost:8000/api/jobs/monitor-demo -d '{}' -H "Content-Type: application/json"

# Poll any job
curl http://localhost:8000/api/jobs/<job_id>
```

## 🧩 Architecture

```
dark/
├── main.py          ← FastAPI app + background job engine
├── engine.py        ← adapters around the 4 tools
├── dashboard.html   ← web UI (logo + tabs + live job polling)
├── logo.png         ← DARK logo
├── run_api.bat      ← Windows one-click launcher
├── run_api.sh       ← Linux/macOS launcher
└── requirements.txt
```

All long-running scans execute as **background jobs** — the API stays
responsive; poll `GET /api/jobs/{id}` or watch them in the dashboard.

## ⚖️ Legal

Authorized security testing only. You must own the target or have explicit
written permission before scanning it.
