# DARK v4.0 – Technical Validation Report

**Validation Timestamp:** `2026-11-22T14:50:45Z` (Container UTC clock)  
**Platform Version:** `4.0.0` (verified via `GET /api/health`)  
**Tested Code Commit (`v4.0.0` Tag Target):** `f626a96e72f20496cfe1d8c8dabfe6efe0c9d119` (branch `main`)  
**Release Tag:** `v4.0.0` (annotated tag pointing directly to the tested code commit `f626a96e72f20496cfe1d8c8dabfe6efe0c9d119`)  
**Report & Evidence Commit:** Tracked on `main` immediately following `v4.0.0`, holding `DARK_v4.0_Technical_Validation_Report.md` and `validation_artifacts/` generated from `v4.0.0`.

> **Independent Review Notice:** Every metric below specifies its exact **unit of measurement** (Vulnerability Class, Finding, Static Test Vector, or HTTP Request) and scope. Results obtained on synthetic benchmarks or static HTML/trace parsers are never generalized to unseen production targets or unexecuted external environments.

---

## 1. Confusion Matrix & Accuracy Metrics (Explicit Units)

### A. Benchmark Lab — Vulnerability Class Level (`modules/benchmark_lab.py`, Run `BM-13DE9F05`)
- **Unit of Measurement:** Vulnerability Class (`10` planted vulnerable classes in `demo-lab/vuln_app.py`) + Hardened Baseline Endpoint Set (`3` hardened endpoints: `/`, `/q?s=ok`, `/404-fallback`, probed with `404` total HTTP requests).

| Metric | Value | Exact Definition & Breakdown |
|---|---:|---|
| **TP (Classes Detected)** | **9** | `sqli`, `xss`, `lfi`, `cmdi`, `ssti`, `open_redirect`, `cors`, `sensitive_exposure`, `security_headers` |
| **FN (Classes Missed)** | **1** | `crlf` (not triggered at `depth=2, max_urls=25`) |
| **FP (Hardened Baseline)** | **0** | `0` non-Info findings emitted on the hardened clean HTTP server (`1` Info coverage notice) |
| **TN (Hardened Endpoints)** | **3** | `/` , `/q?s=ok`, `/404-fallback` cleanly verified across `404` total HTTP probe requests (*note: 404 requests are scanner probe requests, not 404 statistically independent negative samples*) |
| **Scoped Precision (Class)** | **100.0%** | `9 / (9 + 0)` on this controlled baseline |
| **Scoped Recall (Class)** | **90.0%** | `9 / (9 + 1)` across the 10 planted benchmark classes |
| **Scoped F1 Score** | **0.9474** | `2 * 1.0 * 0.9 / (1.0 + 0.9)` |

- **Benchmark Lab — Finding-Level Output on `demo-lab/vuln_app.py` (`36` emitted findings):**
  `Critical: 9` | `High: 8` | `Medium: 9` | `Low: 7` | `Info: 3` (`33` actionable findings + `3` informational diagnostics).

### B. Deep XSS Static Context Verifier (`webvulnx/test_xss_deep.py`)
- **Unit of Measurement:** Independent static HTML / Content-Type test case (`N = 16` verification assertions, excluding browser DOM execution).

| Actual \ Predicted | Predicted Vulnerable | Predicted Safe | Total |
|---|---:|---:|---:|
| **Actual Vulnerable** | **TP = 5** (`3` unescaped exec + `2` HTML/sniffable CT) | **FN = 0** | 5 |
| **Actual Safe** | **FP = 0** | **TN = 11** (`7` trapped/encoded contexts + `4` non-HTML CTs) | 11 |

- **Scoped Static Precision:** `100.0%` | **Scoped Static Recall:** `100.0%` | **Scoped Static FPR:** `0.0%` (`0/11`).
- **Context Classifier:** `16 / 16` contexts (`100%`). **Community Vectors Corpus:** `1,622` evaluated, `996` marker-embeddable. **Limitation:** Static HTML/context parser only; live headless browser DOM execution was **not** tested.

---

## 2. Deployment Profiles (`Development` vs `Production`)

Implemented in `dark/main.py` via `DARK_ENV` / `DARK_PROFILE` (`get_deployment_profile()`), verified by `tests/security/test_production_profile.py`:

| Setting | `DARK_ENV=development` (Default Local) | `DARK_ENV=production` (Secure-by-Default) |
|---|---|---|
| **RBAC** | Optional (`rbac_enforced` DB flag) | **Mandatory** (`rbac_enforced` forced `True`) |
| **Authentication** | Optional unless lock/RBAC enabled | **Mandatory** (`401` on all unauthenticated `/api/` routes except `/api/health`, `/api/auth/*`, `/api/admin/users/login`) |
| **Tenant Isolation** | Enforced when authenticated | **Mandatory** (`403` on cross-tenant `X-Tenant-ID`; unauthenticated `X-Tenant-ID` ignored) |
| **Debug Mode** | Enabled (`debug_mode: true` in `/api/health`) | **Disabled** (`debug_mode: false`, `X-Dark-Profile: production`) |
| **CORS** | Localhost dev origins (`DARK_CORS_ORIGINS`) | **Strict Allowlist** (`*` stripped; explicit origins only) |
| **API Keys** | Optional | **Role-scoped & permission-checked** |
| **Audit Logging** | Security/admin mutations logged | **Mandatory** (every authenticated `/api/` request logged to tamper-evident hash-chained `audit_log`) |

### Live `DARK_ENV=production` Verification vs Local Preview Server
- **Local Preview Server (`:8000`):** Runs with `deployment_profile=development` (`debug_mode: true`) for interactive sandbox preview only; it must **not** be treated as a production deployment.
- **Independent Live Production Startup Check (`127.0.0.1:8011`, `DARK_ENV=production`, `DARK_CORS_ORIGINS=https://dark.example.com`):**
  - `GET /api/health` → `200`, `deployment_profile="production"`, `debug_mode=false`, `X-Dark-Profile="production"`.
  - Unauthenticated requests to `/api/findings`, `/api/posture/dashboard`, `/api/intel/security-graph`, `POST /api/jobs/webscan`, and forged `X-Tenant-ID: other-tenant` all returned **`401 Unauthorized`**.
  - Disallowed `Origin: https://evil.example.org` omitted `Access-Control-Allow-Origin` (`None`).
  - **Pre-Production Requirement (`v4.1 P0`):** Full pre-launch deployment validation behind TLS/reverse proxy across every authenticated route and RBAC matrix remains mandatory before actual production rollout.

---

## 3. Cryptography Fallback & Dependency Security

### A. Independent Verification of OpenSSL `libcrypto` AES-256-GCM Fallback
Because `cryptography` is `not-installed` in this container, `dark/security_hardening.py` executes AES-256-GCM via OpenSSL `libcrypto` EVP (`ctypes`). Verified independently by `tests/security/test_openssl_aes_gcm_fallback.py` (with `CRYPTOGRAPHY_AESGCM_OK` forced `False`):
- **Encryption/Decryption Round-Trip:** Verified (`pt == aes_gcm_decrypt(...)`).
- **Authentication Tag Verification:** 1-bit flip in 16-byte GCM tag rejected with exception.
- **Ciphertext & AAD Integrity:** 1-bit flip in ciphertext or mismatched tenant AAD (`tenant:evil:vault`) rejected.
- **Nonce Uniqueness:** Repeated encryptions of identical plaintext generate distinct 12-byte random nonces (`n1 != n2`, `ct1 != ct2`).
- **Vault Key Rotation & Backward Compatibility:** `rotate_vault_keys()` rotates keyring version (`v_n -> v_{n+1}`), re-encrypts stored secrets cleanly, and preserves decryption of older-versioned ciphertexts.

### B. Dependency & SAST Audit Scope (`validation_artifacts/dependency-audit.json` & `sast-report.json`)
- **Internal SAST (`modules/sast_audit.py`):** `0` runtime (non-test) findings within scanned directories `dark/`, `modules/`, `netrecon/`, `netsentry/`, `webvulnx/` (`2` test-fixture findings in `webvulnx/test_platform_wave.py`; `16` intentional MD5/SHA1 implementations in `hashbreaker/`). **Scope note:** Reflects `sast_audit.py` rules only, not external SAST engines.
- **Internal Container/SBOM Audit (`modules/container_audit.py`):** `0` findings across `Dockerfile` (`python:3.12-slim`), `docker-compose.yml` (`postgres:16-alpine`, `redis:7-alpine`), and all 5 `requirements.txt` files; CycloneDX v1.5 SBOM generated.
- **External CVE / Security Tools Status (Not Installed Locally):** `bandit=false`, `pip-audit=false`, `semgrep=false`, `trivy=false`. Live NVD/OSV CVE lookup against transitive dependencies (`fastapi==0.165.0`, `uvicorn==0.54.0`, `pydantic==2.14.3`, `requests==2.33.0`, `pyyaml==6.0.3`, `argon2-cffi==25.1.0`, `httpx==0.28.1`, `pytest==9.0.3`) was **not** run locally and remains delegated to CI (`ci/github-actions-ci.yml`).

---

## 4. Maturity Matrix (`Implemented → Unit Tested → Integration Tested → Externally Validated`)

| Capability / Module | Implemented | Unit Tested | Integration Tested | Externally Validated | Notes / Limitations |
|---|:---:|:---:|:---:|:---:|---|
| Core Platform, Auth, RBAC, Prod Profile, AES-GCM (`dark/`) | ✅ | ✅ | ✅ | ⏳ Pending CI | OpenSSL `libcrypto` fallback unit-tested; external pen-test pending |
| WebVulnX & Deep XSS / SSRF / JS / TLS (`webvulnx/`) | ✅ | ✅ | ✅ | ⚠️ Partial | Static HTML/Context XSS verified; **live Browser DOM (Playwright) NOT run** |
| NetRecon & DNS Recon (`netrecon/`) | ✅ | ✅ | ✅ | ⏳ Pending | Confidence/topology/DKIM/BIMI/MTA-STS tested; external internet targets N/A offline |
| HashBreaker & Password Audit (`hashbreaker/`) | ✅ | ✅ | ✅ | ✅ Local Bench | `MD5=706k H/s`, `SHA256=587k H/s`, `NTLM=21k H/s` |
| NetSentry (`netsentry/`) | ✅ | ✅ | ✅ | ⚠️ Scapy Absent | Core correlation/DNS/IOC unit-tested; live Scapy capture skipped (`scapy` not installed) |
| Centralized Intel Hub & Security Graph (`intel_hub.py`, `security_graph.py`) | ✅ | ✅ | ✅ | ⏳ Pending | No-merge & no-score-inflation invariants verified |
| Detection Engineering + Sigma (`detection_engineering.py`) | ✅ | ✅ | ✅ | ⏳ Pending | Sigma YAML import/export & TP/FP metrics verified |
| Executive Posture Dashboard (`posture_dashboard.py`) | ✅ | ✅ | ✅ | ⚠️ UI Only | API & HTML/JS syntax verified; live browser render pending Playwright |
| Identity, AD & Wireless Audits (`identity_security.py`, `ad_audit.py`, `wireless_audit.py`) | ✅ | ✅ | ✅ | ⏳ Pending | Offline JSON snapshots/inventories only; Confirmed vs Potential labeled |
| Malware Static Triage & Sandbox (`malware_analysis.py`, `malware_sandbox.py`) | ✅ | ✅ | ✅ | ❌ Not Executed in VM | Host execution blocked; **behavioral trace parser only — real VM detonation pending** |
| Frontend Dashboard (`dark/dashboard.html`, `api_studio.html`) | ✅ | ✅ | ⚠️ API Only | ❌ No Browser | HTML tag balance + `node --check` + `onclick` checks passed; **Playwright DOM tests pending** |

---

## 5. Module & API Inventory Summary
- **Runtime Modules:** **55** Python modules (`dark/`: 8, `modules/`: 29, `webvulnx/`: 13, `netrecon/`: 3, `netsentry/`: 1, `hashbreaker/`: 1).
- **API Endpoints:** **117** API paths / **137** HTTP operations verified via live `GET /openapi.json`.
- **Test Suites Executed:** **53 / 53 Pytest tests PASSED** (`100%` in `16.33s`) + `webvulnx/test_xss_deep.py` (**ALL PASSED**) + `compileall` clean.

---

## 6. Validation Evidence & Reproducibility

### A. Environment & Exact Versions
- **OS / Kernel:** `Linux-6.1.189+-x86_64-with-glibc2.41` (`2` vCPUs)
- **Python:** `3.13.18` | **Node.js:** `v20.20.2`
- **Libraries:** `fastapi==0.165.0`, `uvicorn==0.54.0`, `pydantic==2.14.3`, `requests==2.33.0`, `pyyaml==6.0.3`, `argon2-cffi==25.1.0`, `httpx==0.28.1`, `pytest==9.0.3` (`cryptography`, `scapy`, `reportlab` = `not-installed`).
- **Git Reference Topology:**
  - **Code Release (`v4.0.0`):** Annotated tag `v4.0.0` points directly to tested code commit `f626a96e72f20496cfe1d8c8dabfe6efe0c9d119` (all platform source, tests, and CI config).
  - **Report & Evidence Commit (`main` HEAD):** Contains `DARK_v4.0_Technical_Validation_Report.md` and `validation_artifacts/*` generated from `v4.0.0`, keeping release artifacts cleanly separated from the tagged code tree while maintaining strict commit traceability.

### B. Reproducible Commands
```bash
cd /home/user/cybersec-projects
git checkout v4.0.0
python3 -m compileall -q dark modules webvulnx netrecon hashbreaker netsentry demo-lab tests
python3 -m pytest -v --junitxml=/tmp/pytest-v4.0.0.xml \
  tests/unit tests/integration tests/security tests/regression \
  tests/test_enterprise_suite.py tests/test_roadmap_suite.py tests/test_expansion_v4.py \
  webvulnx/test_nessus_and_accuracy.py webvulnx/test_platform_wave.py
python3 webvulnx/test_xss_deep.py
```

### C. Generated Evidence Artifacts (`validation_artifacts/`)
- `validation_artifacts/pytest-results.xml` — JUnit XML (`53` passed, `0` failed, `0` skipped)
- `validation_artifacts/sast-report.json` — Full `sast_audit` output across all 6 packages
- `validation_artifacts/dependency-audit.json` — SBOMs, installed versions, and external scanner availability
- `validation_artifacts/benchmark-raw.json` — Raw benchmark metrics (`BM-13DE9F05`), severity breakdown (`36` findings), `404`-request clean baseline (`0` non-Info FPs), and concrete TP/TN examples

### D. Concrete Examples: Detected Findings (TP) vs Rejected False Positives (TN)
- **Detected Findings (TP):** `SQL Injection`, `XSS`, `LFI`, `CMDi` (quote-split canary `;echo DARK_CMDI_""9182` verified against actual execution output `DARK_CMDI_9182`), `Missing Security Header` (`HSTS`, `CSP`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`).
- **Rejected False Positives (TN):** `<textarea><script>var MARK=1</script></textarea>` (`null`); `{"q":"<script>var MARK=1</script>"}` with `application/json` (`null`); reflected `;echo DARK_CMDI_""9182` on `/search?q=` (rejected by `scan_cmdi` anti-reflection guard); `404` clean HTTP probe requests on `_CleanNeg` (`0` non-Info findings).

---

## 7. Release Evidence Standard & DARK v4.1 Reliability Roadmap

### A. Mandatory Release Evidence Policy (`validation_artifacts/`)
`validation_artifacts/` is maintained as a permanent release evidence archive for `v4.0.0` and every subsequent release, expanding to include:
1. CI pipeline run exports (`pytest-results.xml`, `sast-report.json`, `benchmark-raw.json`).
2. External Dependency CVE Reports (`pip-audit`, `trivy`, `bandit`, `semgrep`).
3. Browser Integration Test Results (Playwright DOM & XSS verification logs).
4. Automated Security Regression Results (RBAC, Production Profile, OpenSSL/AES-GCM).
5. Cross-Release Performance Comparisons (throughput, RAM/CPU deltas vs prior tags).

### B. DARK v4.1 Plan — Reliability & Verification First (No New Tools Added)
All existing modules, APIs, and capabilities remain intact while `v4.1` prioritizes verification hardening:

| Priority | Workstream | Scope |
|---|---|---|
| **P0** | **Production Deployment Validation** | Full end-to-end verification of `DARK_ENV=production` behind reverse proxy/TLS across all 117 API paths & RBAC roles |
| **P0** | **External Dependency Scanning** | Execute `pip-audit`, `trivy`, `bandit`, and `semgrep` in CI against pinned `requirements.txt` and container images |
| **P1** | **Playwright Browser Testing** | Headless Chromium validation of `dashboard.html`, `api_studio.html`, and real DOM XSS execution |
| **P1** | **Security Regression Automation** | Continuous PR gating for auth/RBAC, tenant isolation, SSRF, OpenSSL fallback, and zero-FP invariants |
| **P1** | **Intel Hub Integration Testing** | Cross-module ingestion, asset isolation, non-inflated risk scoring, and status history E2E verification |
| **P2** | **Performance & Load Testing** | Concurrency benchmarks, scan throughput, memory ceiling, and comparison against `v4.0.0` baseline |
| **P2** | **Centralized Logging & Monitoring** | Structured JSON logs, metrics endpoints, and tamper-evident audit stream forwarding |
| **P2** | **Backup Recovery Testing** | Automated SQLite/PostgreSQL + encrypted vault keyring restore drills |
