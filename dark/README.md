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

## 🧾 Jobs — parallel execution, isolated output, live progress

**Every job starts immediately and jobs run in parallel.** There is no queue
and no ordering: launch a web scan, a network scan and a hash crack at the same
time and all three execute concurrently.

Output isolation is *not* achieved by serializing jobs. `engine.py` installs a
**context-aware stdout/stderr router**: each job binds its own buffer through a
`contextvars` stack, and every `print()` is tee'd only to the buffers of the
current execution context. Because CPython does not inherit `contextvars` in
new threads, the router also patches `threading.Thread.start` and
`ThreadPoolExecutor.submit` to copy the calling context — which is what keeps
NetRecon's 800 scan workers (and every other internal thread pool) writing into
the right job's log. A network scan can therefore never contain
`SQLi tests on …` lines, and two web scans of different hosts never mix.

Concurrency is capped only to protect the machine from thread exhaustion:
`DARK_MAX_PARALLEL` (default **16**). Beyond that a job briefly shows
`waiting`. Raise it to run everything at once:

```bash
DARK_MAX_PARALLEL=64 python3 -m uvicorn main:app --host 0.0.0.0 --port 8000
```

> Note: parallel scans of the **same** host multiply the request rate and can
> trip its WAF. If a target starts blocking, the report says so explicitly
> (`degraded: true`) — re-run that one target alone or with `delay`.

| Status | Meaning |
|--------|---------|
| `running` | executing right now (started immediately) |
| `waiting` | all `DARK_MAX_PARALLEL` slots are busy — starts as soon as one frees |
| `done` | finished with a result |
| `error` | the tool reported a failure (message + hint included) |
| `timeout` | the watchdog stopped it at its deadline |
| `interrupted` | the API restarted while the job was in flight — result lost, re-run it |

### Live progress

The watchdog publishes progress for every running job every 2 s, so a long scan
never looks frozen:

```json
"progress": {"elapsed_s": 96.0, "log_lines": 412, "chars": 38210,
             "last_line": "[*] XSS tests on http://target/search?q=… params=['q']"}
```

The Jobs tab shows that line per job and auto-refreshes every 2 s, keeping the
open result pane in sync — the list and the `view` pane can no longer disagree.

### No job runs forever

The same watchdog enforces a per-kind deadline (`web-scan` 60 min,
`network-scan` 30 min, `hash-crack` 60 min, monitors 15–60 min) and then marks
the job `timeout`, including the last 25 lines it produced. Job metadata is
persisted to `dark/jobs_state.json`, so a restart keeps the history and
re-labels in-flight jobs as `interrupted` instead of leaving a ghost `running`
row (this is also why a job id can no longer return an empty body after a
restart).

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
├── main.py          ← FastAPI app + parallel job runner + watchdog + persistence
├── engine.py        ← tool adapters + context-aware log router (parallel-safe capture)
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
