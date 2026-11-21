# DARK Enterprise Architecture

## High-Level Layers
1. **API & Middleware Layer (`dark/main.py`, `dark/enterprise_routes.py`)**
   - Security headers (`X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, `Cache-Control: no-store` on `/api/`).
   - Rate limiting, RBAC & API Key authentication, multi-tenant context propagation (`ContextVar`), and tamper-evident audit logging.
2. **Core Engines (`dark/engine.py`, `webvulnx/`, `netrecon/`, `hashbreaker/`, `netsentry/`)**
   - Parallel job isolation (`engine.bind_job_log`), cooperative cancellation (`stop_event`), and live progress tracking.
3. **Enterprise Intelligence & Governance (`modules/`)**
   - `asset_intel.py`: Attack Surface Graph (`resolves_to`, `hosts`, `exposes`, `connects_to`, `depends_on`, `owns_subdomain`), exposure history, CSV export.
   - `vuln_intel.py`: CVSS v3.1 & v4.0, CISA KEV, FIRST EPSS, CPE 2.3 matching, configurable 5-axis risk score, attack path correlation.
   - `verification.py`: Evidence redaction, `Confirmed`/`Likely`/`Unverified`/`False Positive` lifecycle, scoped HTTP retesting.
   - `threat_intel.py`: IOC feeds, STIX 2.1 bundle import/export, multi-source correlation.
   - `integrations.py`: HMAC-signed webhooks, SSRF guard, SIEM CEF, Jira/GitHub connectors, SARIF v2.1.0 import/export.
   - `reporting_analytics.py` & `benchmark_lab.py`: Role-redacted analytics & ground-truth TP/FP/FN/F1 QA lab.
4. **Persistence & Migrations (`dark/enterprise_db.py`, `dark/db_migrations.py`)**
   - Versioned schema migrations (v1–v4), Argon2id password hashing, account lockout, and PostgreSQL DSN awareness.
