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

# Crack — "wordlist" accepts: auto (default, biggest available) | rockyou | common | none
curl -X POST http://localhost:8000/api/jobs/hash-crack \
  -H "Content-Type: application/json" \
  -d '{"hashes":["098f6bcd4621d373cade4e832627b4f6"],"wordlist":"auto","rules":true}'

# Monitor: synthetic demo (no root needed)
curl -X POST http://localhost:8000/api/jobs/monitor-demo -d '{}' -H "Content-Type: application/json"

# Poll any job
curl http://localhost:8000/api/jobs/<job_id>
```

## 🧾 Job Queue — statuses, isolation and the watchdog

**Jobs execute one at a time.** Every submission goes into a serial queue, so
two things can never happen again:

- **Log mixing** — each job captures its own stdout; a network scan can no
  longer show web-scan lines (`SQLi tests on …`) inside its console.
- **Self-inflicted rate limiting** — five concurrent scans of the same host
  used to trip its WAF and produce empty results.

| Status | Meaning |
|--------|---------|
| `waiting` | queued behind another job (shown as a yellow badge) |
| `running` | executing right now |
| `done` | finished with a result |
| `error` | the tool reported a failure (message + hint included) |
| `timeout` | the watchdog stopped it at its deadline |
| `interrupted` | the API restarted while the job was in flight — result lost, re-run it |

**No job can stay `running` forever.** A watchdog thread checks every 5 s and
applies a per-kind deadline (`web-scan` 60 min, `network-scan` 30 min,
`hash-crack` 60 min, monitors 15–60 min), then marks the job `timeout` with an
explanation. Job metadata is persisted to `dark/jobs_state.json`, so a restart
keeps the history and re-labels in-flight jobs as `interrupted` instead of
leaving a ghost `running` row (this is also why a job id can no longer return
an empty body after a restart).

The dashboard's Jobs tab **auto-refreshes every 3 s** and keeps the open result
pane in sync — the list and the `view` pane can no longer disagree.

## 🔎 Web-scan results you can trust

Every web-scan job returns a **coverage block** next to the findings:

```json
"stats": {
  "seed_urls": ["http://demo.testfire.net/login.jsp", "http://demo.testfire.net/", "http://demo.testfire.net/index.jsp"],
  "urls_crawled": 25, "forms": 27, "parameters": 55,
  "modules_run": ["param-discovery", "misconfig-audit", "sqli", "xss", "..."],
  "requests_sent": 3688, "blocked_responses": 0, "waf_challenge_pages": 0,
  "status_codes": {"200": 3100, "404": 210}, "degraded": false
}
```

Sub-page URLs are expanded automatically (site root + `robots.txt` +
`sitemap.xml` + probed entry points), which is what turns
*“1 URL crawled → 0 findings”* into a real scan. When nothing is found the
report states which of these it is:

1. **tested-clean** — N requests across M modules and P parameters were really
   sent and verified;
2. **scan degraded** — the target blocked/WAF-filtered the scanner, so the
   clean result is *not* trustworthy;
3. **no attack surface** — 0 parameters and 0 forms were discovered, so the
   injection engines had nothing to test (with the exact knob to turn).

## 🧩 Architecture

```
dark/
├── main.py          ← FastAPI app + serial job queue + watchdog + job persistence
├── engine.py        ← adapters around the 4 tools (streams wordlists, adds coverage)
├── dashboard.html   ← web UI (logo + tabs + auto-refreshing job queue)
├── jobs_state.json  ← persisted job history (created at runtime, git-ignored)
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
