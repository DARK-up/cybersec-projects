#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DARK API — Detection & Attack Reconnaissance Kit
================================================
One REST API + web dashboard to drive all four tools:

  POST /api/jobs/network-scan   NetRecon
  POST /api/jobs/web-scan       WebVulnX
  POST /api/hash/identify       HashBreaker (instant)
  POST /api/jobs/hash-crack     HashBreaker
  POST /api/jobs/hash-benchmark HashBreaker
  POST /api/jobs/monitor-demo   NetSentry (synthetic)
  POST /api/jobs/monitor-pcap   NetSentry (upload .pcap/.pcapng)
  POST /api/jobs/monitor-live   NetSentry (live capture)
  GET  /api/jobs/{id}           poll job status/result
  GET  /api/jobs                list all jobs

Run:  python -m uvicorn main:app --host 0.0.0.0 --port 8000
Docs: http://localhost:8000/docs
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from pydantic import BaseModel, Field

APP_DIR = Path(__file__).resolve().parent
if str(APP_DIR.parent) not in sys.path:
    sys.path.insert(0, str(APP_DIR.parent))
for _p in (str(APP_DIR), str(APP_DIR.parent / "modules")):
    if _p not in sys.path:
        sys.path.append(_p)

import engine
import enterprise_db as edb
import enterprise_routes as eroutes
import asset_intel as dasset
import security_hardening as sh
import verification as dverif
import reporting_analytics as drpt

def _load_platform():
    spec = importlib.util.spec_from_file_location("dark_workspace_platform", APP_DIR / "workspace_platform.py")
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod

dplat = _load_platform()
LEGAL = ("Authorized security testing only — you must own the target or have "
         "explicit written permission before scanning anything.")

# ---------------------------------------------------------------------------
# Job store (in-memory) — jobs execute ONE AT A TIME (serial queue):
# this prevents log mixing between jobs AND avoids WAF rate-limiting when
# several scans hit the same target.
# ---------------------------------------------------------------------------
JOBS: Dict[str, dict] = {}
JOBS_LOCK = threading.Lock()
JOBS_FILE = APP_DIR / "jobs_state.json"
MAX_JOBS_KEPT = 60
# Jobs run IN PARALLEL — there is no queue and no ordering. Output isolation is
# handled per execution context by engine.bind_job_log (a context-aware stdout
# router), so two scans can never write into each other's log.
# The cap below only protects the machine from thread exhaustion; raise it with
# the DARK_MAX_PARALLEL environment variable (set it very high for "all at once").
MAX_PARALLEL_JOBS = int(os.environ.get("DARK_MAX_PARALLEL", "16"))
JOB_SLOTS = threading.Semaphore(MAX_PARALLEL_JOBS)
# A job can NEVER stay "running" forever: the watchdog kills its status at
# the deadline even if the underlying scanner thread is still alive.
JOB_DEADLINES = {"web-scan": 3600, "network-scan": 1800, "hash-crack": 3600,
                 "hash-benchmark": 900, "monitor-demo": 900,
                 "monitor-pcap": 1200, "monitor-live": 3600}
JOB_DEADLINE_DEFAULT = 1800


_SENSITIVE_PAYLOAD_KEYS = {
    "cookie", "auth_header", "login_pass", "password", "pass", "token",
    "secret", "api_key", "apikey", "authorization", "private_key", "extra_headers",
}
JOB_RETENTION_DAYS = int(os.environ.get("DARK_JOB_RETENTION_DAYS", "7"))


def _redact_repro_payload(payload: dict) -> dict:
    """Replace credentials/cookies/headers in persisted/exposed job payloads with redaction tokens."""
    out: Dict[str, Any] = {}
    for k, v in (payload or {}).items():
        if k == "stop_event":
            continue
        kl = str(k).lower()
        if kl in _SENSITIVE_PAYLOAD_KEYS or any(s in kl for s in ("password", "secret", "token", "cookie", "auth_")):
            out[k] = "[REDACTED]" if v else v
        elif kl == "proxy" and isinstance(v, str) and "@" in v:
            out[k] = sh.redact_sensitive(v, max_len=200)
        elif isinstance(v, dict):
            out[k] = _redact_repro_payload(v)
        else:
            out[k] = v
    return out


def _jobs_to_disk() -> None:
    """Persist job metadata: history survives a restart, sensitive payloads are redacted,
    and file mode is restricted to 0600."""
    try:
        cutoff = time.time() - (max(1, JOB_RETENTION_DAYS) * 86400)
        with JOBS_LOCK:
            items = [
                j for j in sorted(JOBS.values(), key=lambda x: x.get("started_at") or 0, reverse=True)
                if (j.get("started_at") or time.time()) >= cutoff
            ][:MAX_JOBS_KEPT]
            slim = []
            for j in items:
                c = {k: v for k, v in j.items() if not k.startswith("_")}
                if isinstance(c.get("repro_payload"), dict):
                    c["repro_payload"] = _redact_repro_payload(c["repro_payload"])
                r = c.get("result")
                if isinstance(r, dict):
                    r = dict(r)
                    if isinstance(r.get("log"), str):
                        log_red = sh.redact_sensitive(r["log"], max_len=200_000)
                        if len(r["log"]) > 200_000:
                            log_red += "\n…[log truncated]…"
                        r["log"] = log_red
                    c["result"] = r
                c.pop("progress", None)
                slim.append(c)
        tmp = JOBS_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(slim, ensure_ascii=False, default=str),
                       encoding="utf-8")
        try:
            os.chmod(tmp, 0o600)
        except Exception:
            pass
        tmp.replace(JOBS_FILE)
        try:
            os.chmod(JOBS_FILE, 0o600)
        except Exception:
            pass
    except Exception:
        pass


def _jobs_from_disk() -> None:
    if not JOBS_FILE.is_file():
        return
    try:
        data = json.loads(JOBS_FILE.read_text(encoding="utf-8"))
    except Exception:
        return
    if not isinstance(data, list):
        return
    for j in data:
        jid = j.get("id")
        if not jid:
            continue
        if j.get("status") in ("running", "waiting"):
            j["status"] = "interrupted"
            j["error"] = ("The DARK API was restarted while this job was still "
                          "in flight, so its result was lost. Re-run the job.")
            j["finished_at"] = j.get("finished_at") or time.time()
        JOBS[jid] = j


def _watchdog() -> None:
    """Two jobs in one loop: (1) publish LIVE PROGRESS for running jobs so the
    UI never looks frozen, (2) enforce deadlines so nothing runs forever."""
    while True:
        time.sleep(2)
        now = time.time()
        changed = False
        with JOBS_LOCK:
            for j in JOBS.values():
                if j["status"] == "running":
                    buf = j.get("_log")
                    if buf is not None:
                        text = buf.snapshot()
                        lines = [l for l in text.splitlines() if l.strip()]
                        j["progress"] = {
                            "elapsed_s": round(now - (j.get("started_at") or now), 1),
                            "log_lines": len(lines),
                            "chars": len(text),
                            "last_line": lines[-1][:180] if lines else "starting…",
                        }
                if j["status"] not in ("running", "waiting"):
                    continue
                deadline = j.get("deadline") or (
                    (j.get("started_at") or now) + JOB_DEADLINE_DEFAULT)
                if now > deadline:
                    ev = j.get("_stop_event")
                    if ev is not None:
                        ev.set()
                    j["status"] = "timeout"
                    j["timed_out"] = True
                    j["stop_signaled_at"] = now
                    j["finished_at"] = now
                    buf = j.get("_log")
                    tail = buf.snapshot(tail_lines=25) if buf is not None else ""
                    j["error"] = (f"Job exceeded its "
                                  f"{int(JOB_DEADLINES.get(j['kind'], JOB_DEADLINE_DEFAULT))}s "
                                  f"limit; cooperative stop event signaled by watchdog. "
                                  f"Narrow the scan (fewer targets/URLs) or raise the limit."
                                  + (f"\n\nLast output before timeout:\n{tail}" if tail else ""))
                    changed = True
        try:
            with JOBS_LOCK:
                active_n = sum(1 for jb in JOBS.values() if jb.get("status") in ("running", "waiting"))
            edb.upsert_worker("local-primary", "DARK Primary Controller", active_jobs=active_n)
            if not edb.is_emergency_stopped():
                for sch in edb.pop_due_schedules():
                    _dispatch_scheduled_job(sch)
        except Exception:
            pass
        if changed:
            _jobs_to_disk()


def _dispatch_scheduled_job(sch: dict) -> None:
    kind = sch.get("kind")
    p = dict(sch.get("payload") or {})
    pid = sch.get("project_id") or "default"
    runners = {
        "web-scan": (engine.run_web_scan, p.get("url", "")),
        "network-scan": (engine.run_network_scan, ", ".join(p.get("targets", [])[:3])),
        "dns-recon": (engine.run_dns_recon, p.get("target", "")),
        "api-audit": (engine.run_api_audit, p.get("url", "")),
    }
    if kind in runners:
        fn, hint = runners[kind]
        start_job(kind, fn, project_id=pid, target_hint=hint, **p)


_jobs_from_disk()
threading.Thread(target=_watchdog, daemon=True).start()


def _public(job: dict) -> dict:
    """Strip private runtime handles and redact sensitive payload fields from API responses."""
    out = {k: v for k, v in job.items() if not k.startswith("_")}
    if isinstance(out.get("repro_payload"), dict):
        out["repro_payload"] = _redact_repro_payload(out["repro_payload"])
    return out


def start_job(kind: str, runner, project_id: str = "default",
              target_hint: str = "", **payload) -> str:
    import inspect
    if edb.is_emergency_stopped():
        raise HTTPException(403, "Emergency Stop is active — clear it in Administration before launching jobs")
    if kind in ("web-scan", "network-scan", "dns-recon", "api-audit"):
        targets_to_check = payload.get("targets") if kind == "network-scan" else [target_hint or payload.get("url") or payload.get("target") or ""]
        for t in (targets_to_check or []):
            ok_scope, reason = edb.check_target_in_scope(str(t))
            if not ok_scope:
                edb.log_audit("operator", "analyst", "scope:blocked", str(t), reason)
                raise HTTPException(403, f"Scope Enforcement blocked target: {reason}")

    job_id = uuid.uuid4().hex[:12]
    now = time.time()
    logbuf = engine.JobLog()
    stop_ev = threading.Event()
    pid = (project_id or "default").strip() or "default"
    actor_now = edb.get_current_actor()
    tid = actor_now.get("tenant_id", "default")
    repro_payload = _redact_repro_payload(payload)
    with JOBS_LOCK:
        JOBS[job_id] = {
            "id": job_id, "kind": kind, "status": "running",
            "project_id": pid, "tenant_id": tid, "target": target_hint,
            "repro_payload": repro_payload,
            "started_at": now, "finished_at": None,
            "deadline": now + JOB_DEADLINES.get(kind, JOB_DEADLINE_DEFAULT),
            "result": None, "error": None, "progress": None,
            "_log": logbuf, "_stop_event": stop_ev,
        }
    edb.enqueue_job_meta(job_id, tid, kind, target_hint, priority=5)
    _jobs_to_disk()

    try:
        accepts_stop = "stop_event" in inspect.signature(runner).parameters
    except Exception:
        accepts_stop = False
    if accepts_stop:
        payload["stop_event"] = stop_ev

    def _run():
        # PARALLEL execution: grab a slot if one is free, otherwise wait for a
        # free slot (only happens past DARK_MAX_PARALLEL concurrent jobs).
        got_slot = JOB_SLOTS.acquire(timeout=0)
        if not got_slot:
            with JOBS_LOCK:
                JOBS[job_id]["status"] = "waiting"
                JOBS[job_id]["progress"] = {
                    "elapsed_s": 0, "log_lines": 0, "chars": 0,
                    "last_line": f"waiting for a free slot "
                                 f"({MAX_PARALLEL_JOBS} jobs already running)"}
            _jobs_to_disk()
            JOB_SLOTS.acquire()
        with JOBS_LOCK:
            if JOBS[job_id]["status"] == "timeout":
                JOB_SLOTS.release()
                return                     # watchdog already gave up on it
            if stop_ev.is_set():
                JOBS[job_id].update(status="stopped", finished_at=time.time(),
                                    result={"target": target_hint, "findings": [], "stopped_early": True})
                JOB_SLOTS.release()
                _jobs_to_disk()
                return
            JOBS[job_id]["status"] = "running"
            JOBS[job_id]["started_at"] = time.time()
            JOBS[job_id]["deadline"] = (
                time.time() + JOB_DEADLINES.get(kind, JOB_DEADLINE_DEFAULT))
        _jobs_to_disk()
        try:
            with engine.bind_job_log(logbuf):
                result = runner(**payload)
            tgt = dplat.extract_target(kind, result if isinstance(result, dict) else {}, payload)
            with JOBS_LOCK:
                if JOBS[job_id]["status"] == "timeout":
                    return
                if tgt:
                    JOBS[job_id]["target"] = tgt
                if stop_ev.is_set():
                    if isinstance(result, dict):
                        result["stopped_early"] = True
                    JOBS[job_id].update(status="stopped", result=result,
                                        finished_at=time.time())
                elif isinstance(result, dict) and result.get("error"):
                    JOBS[job_id].update(status="error", error=result["error"],
                                        result=result, finished_at=time.time())
                elif isinstance(result, dict) and result.get("partial_failure"):
                    JOBS[job_id].update(status="partial", result=result,
                                        finished_at=time.time())
                else:
                    JOBS[job_id].update(status="done", result=result,
                                        finished_at=time.time())
                job_snapshot = _public(JOBS[job_id])
            try:
                if isinstance(job_snapshot.get("result"), dict):
                    dasset.ingest_job_assets(job_snapshot)
                    dverif.auto_ingest_job_verifications(job_snapshot)
            except Exception:
                pass
            edb.update_job_meta_status(job_id, job_snapshot.get("status", "done"))
        except Exception as e:  # never crash the server
            with JOBS_LOCK:
                JOBS[job_id].update(status="error",
                                    error=f"{type(e).__name__}: {e}",
                                    finished_at=time.time())
            edb.update_job_meta_status(job_id, "error")
        finally:
            with JOBS_LOCK:
                JOBS[job_id]["progress"] = None
            JOB_SLOTS.release()
            _jobs_to_disk()

    threading.Thread(target=_run, daemon=True).start()
    return job_id


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------
class NetworkScanReq(BaseModel):
    targets: List[str] = Field(..., example=[["192.168.1.0/24", "10.0.0.5", "scanme.nmap.org"]][0])
    ports: str = "top100"
    timing: str = "normal"
    probe: bool = True
    discover: bool = False
    vuln_audit: bool = True
    project_id: str = "default"


class WebScanReq(BaseModel):
    url: str = Field(..., example="http://testphp.vulnweb.com")
    crawl: bool = True
    sqli: bool = True
    xss: bool = True
    dirs: bool = True
    audit: bool = True
    advanced: bool = True          # LFI, SSTI, CMDi, open redirect, CORS, CRLF, ...
    param_fuzz: bool = True        # hidden parameter discovery
    default_creds: bool = False    # opt-in: tries admin:admin etc. on forms
    templates: bool = True         # Nuclei-style YAML templates
    fast: bool = False             # skip time-based SQLi (recommended on remote sites)
    depth: int = 3
    max_urls: int = 80
    timeout: float = 10.0
    delay: float = 0.0
    rate_limit: float = 1.0
    time_blind: float = 5.0
    cookie: Optional[str] = None
    auth_header: Optional[str] = None
    extra_headers: Optional[Dict[str, str]] = None
    login_url: Optional[str] = None
    login_user: Optional[str] = None
    login_pass: Optional[str] = None
    openapi_url: Optional[str] = None
    proxy: Optional[str] = None
    stealth: bool = True
    project_id: str = "default"


class DnsReconReq(BaseModel):
    target: str = Field(..., example="example.com")
    subdomains: bool = True
    passive_crtsh: bool = True
    extra_words: Optional[List[str]] = None
    project_id: str = "default"


class HashGenerateReq(BaseModel):
    text: str
    algo: str = "all"
    salt: str = ""


class TemplateSaveReq(BaseModel):
    yaml_text: str


class HashIdentifyReq(BaseModel):
    hashes: List[str] = Field(..., example=["5f4dcc3b5aa765d61d8327deb882cf99"])


class HashCrackReq(BaseModel):
    hashes: List[str] = Field(..., example=["098f6bcd4621d373cade4e832627b4f6"])
    words: Optional[List[str]] = None
    wordlist: Optional[str] = Field(None, description="'common' for the built-in list")
    rules: bool = True
    mask: Optional[str] = None
    algo: Optional[str] = None
    salt: Optional[str] = None
    workers: Optional[int] = None
    project_id: str = "default"


class MonitorReq(BaseModel):
    seconds: int = 10
    interface: Optional[str] = None
    gateway: Optional[str] = None
    bpf: str = ""
    syn_threshold: int = 25
    project_id: str = "default"


class ProjectReq(BaseModel):
    name: str
    description: str = ""
    color: str = "#22d3ee"


class NoteReq(BaseModel):
    text: str = ""


class AuthLoginReq(BaseModel):
    username: str = "dark"
    password: str


class AuthSetupReq(BaseModel):
    username: str = "dark"
    password: str
    enabled: bool = True


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
app = FastAPI(
    title="DARK API",
    description=("DARK — Detection & Attack Reconnaissance Kit. "
                 "Unified REST API for NetRecon / WebVulnX / HashBreaker / NetSentry "
                 "+ Enterprise Security, Intelligence, Compliance & Governance.\n\n"
                 + LEGAL),
    version="4.0.0",
    docs_url=None,
    redoc_url=None,
)
_CORS_ORIGINS = [
    o.strip()
    for o in os.environ.get(
        "DARK_CORS_ORIGINS",
        "http://localhost:8000,http://127.0.0.1:8000",
    ).split(",")
    if o.strip() and o.strip() != "*"
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_CORS_ORIGINS or ["http://127.0.0.1:8000"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-API-Key", "X-Dark-Token", "X-CSRF-Token", "X-Tenant-ID"],
)
eroutes.bind_hooks(start_job, JOBS, JOBS_LOCK, _jobs_to_disk, LEGAL)
app.include_router(eroutes.router)


def _required_permission(method: str, path: str) -> str:
    """Deny-by-default RBAC Permission Matrix mapping every /api/ endpoint."""
    m = method.upper()
    if path.startswith("/api/jobs/") and path.endswith("/stop") and m == "POST":
        return "scan:stop"
    if path.startswith("/api/jobs"):
        if m == "GET":
            return "report:read"
        return "scan:run"
    if path.startswith("/api/projects"):
        if m == "GET":
            return "report:read"
        return "asset:write"
    if path in ("/api/targets", "/api/compare", "/api/wordlists"):
        return "report:read"
    if path.startswith("/api/templates"):
        return "report:read" if m == "GET" else "plugin:manage"
    if path.startswith("/api/hash/"):
        return "scan:run"
    if path.startswith("/api/assets"):
        return "report:read" if m == "GET" else "asset:write"
    if path in ("/api/intel/sync", "/api/intel/risk/weights") and m == "POST":
        return "intel:sync"
    if path.startswith("/api/intel"):
        return "intel:read"
    if path.startswith("/api/detections"):
        return "intel:read" if m == "GET" else "plugin:manage"
    if path.startswith("/api/posture"):
        return "report:read"
    if path.startswith("/api/verification"):
        return "report:read" if m == "GET" else "remediation:write"
    if path.startswith("/api/threat-intel"):
        return "intel:read" if m == "GET" else "threat:write"
    if path.startswith("/api/compliance"):
        return "compliance:read"
    if path.startswith("/api/remediation"):
        return "report:read" if m == "GET" else "remediation:write"
    if path.startswith("/api/plugins"):
        return "report:read" if m == "GET" else "plugin:manage"
    if path.startswith("/api/integrations"):
        return "report:read" if m == "GET" else "admin:manage"
    if path.startswith("/api/benchmarks/run") and m == "POST":
        return "scan:run"
    if path.startswith("/api/benchmarks") or path.startswith("/api/analytics") or path == "/api/metrics":
        return "report:read"
    if path.startswith("/api/reports/"):
        return "report:read" if m == "GET" else "admin:manage"
    if path in ("/api/admin/backup", "/api/admin/restore"):
        return "backup:manage"
    if path.startswith("/api/admin/audit"):
        return "audit:read"
    if path.startswith("/api/admin/vault"):
        if path == "/api/admin/vault/rotate" and m == "POST":
            return "admin:manage"
        if m == "GET":
            return "vault:read"
        if m == "DELETE":
            return "vault:delete"
        return "vault:write"
    if path.startswith("/api/admin/users"):
        return "user:manage"
    if path.startswith("/api/admin/api-keys"):
        return "apikey:manage"
    if path.startswith("/api/admin/tenants"):
        return "tenant:manage"
    if path.startswith("/api/admin/"):
        return "admin:manage"
    # Deny-by-default for any unmapped API path
    return "admin:manage"


def get_deployment_profile() -> str:
    val = (os.environ.get("DARK_ENV") or os.environ.get("DARK_PROFILE") or "development").strip().lower()
    return "production" if val in ("prod", "production") else "development"


def is_production_profile() -> bool:
    return get_deployment_profile() == "production"


_PLACEHOLDER_SECRETS = ("dark_change_me", "changeme", "dev-secret", "test-secret", "replace-with-")


def validate_production_config(strict: bool = False) -> List[str]:
    """Validate production deployment config; raise RuntimeError on insecure defaults."""
    errors: List[str] = []
    if not is_production_profile():
        return errors
    vk = (os.environ.get("DARK_VAULT_KEY") or "").strip()
    dsn = (os.environ.get("DARK_POSTGRES_DSN") or "").strip()
    cors_raw = (os.environ.get("DARK_CORS_ORIGINS") or "").strip()
    if vk and any(p in vk.lower() for p in _PLACEHOLDER_SECRETS):
        errors.append("DARK_VAULT_KEY uses a placeholder/demo secret")
    if dsn and any(p in dsn.lower() for p in _PLACEHOLDER_SECRETS):
        errors.append("DARK_POSTGRES_DSN contains a placeholder/demo password")
    if "*" in cors_raw:
        errors.append("DARK_CORS_ORIGINS must not contain wildcard '*'")
    if strict or os.environ.get("DARK_STRICT_PROD_STARTUP") == "1":
        if not vk or len(vk) < 16:
            errors.append("DARK_VAULT_KEY must be set (>=16 chars) in strict production mode")
        if not cors_raw:
            errors.append("DARK_CORS_ORIGINS must be explicitly set in strict production mode")
        if not dsn:
            errors.append("DARK_POSTGRES_DSN must be configured in strict production mode")
    if errors:
        raise RuntimeError("Insecure production configuration: " + "; ".join(errors))
    return errors


validate_production_config(strict=False)


def _enforce_cookie_csrf(request: Request) -> Optional[JSONResponse]:
    """Fail-closed CSRF validation whenever state-changing requests authenticate via cookie."""
    if request.method.upper() not in ("POST", "PUT", "PATCH", "DELETE"):
        return None
    cookie_tok = request.cookies.get("dark_session") or ""
    header_tok = request.headers.get("X-Dark-Token") or ""
    auth_h = request.headers.get("Authorization") or ""
    api_key_hdr = request.headers.get("X-API-Key") or ""
    if not header_tok and auth_h.lower().startswith("bearer "):
        cand = auth_h.split(" ", 1)[1].strip()
        if cand.startswith("dark_"):
            api_key_hdr = api_key_hdr or cand
        else:
            header_tok = cand
    if cookie_tok and not header_tok and not api_key_hdr:
        csrf_cookie = request.cookies.get("dark_csrf") or ""
        csrf_hdr = request.headers.get("X-CSRF-Token") or ""
        if not csrf_cookie or not csrf_hdr or not edb.hmac.compare_digest(csrf_cookie, csrf_hdr):
            return JSONResponse(status_code=403, content={"error": "CSRF token missing or invalid"})
    return None


@app.middleware("http")
async def _auth_gate(request: Request, call_next):
    path = request.url.path
    prod_mode = is_production_profile()
    is_https = (
        (request.headers.get("x-forwarded-proto") or request.url.scheme or "").lower() == "https"
    )

    async def _finish(resp):
        for hk, hv in sh.build_security_headers(is_https=is_https).items():
            resp.headers.setdefault(hk, hv)
        resp.headers.setdefault("X-Dark-Profile", "production" if prod_mode else "development")
        if path.startswith("/api/"):
            resp.headers.setdefault("Cache-Control", "no-store")
        return resp

    if not path.startswith("/api/") or path.startswith("/api/auth/") or path in ("/api/health", "/api/admin/users/login"):
        if path in ("/api/auth/setup", "/api/auth/disable", "/api/auth/logout"):
            csrf_fail = _enforce_cookie_csrf(request)
            if csrf_fail is not None:
                return await _finish(csrf_fail)
        return await _finish(await call_next(request))

    ip = request.client.host if request.client else "global"
    ok_rl, rlim = edb.check_rate_limit(ip)
    if not ok_rl:
        return await _finish(JSONResponse(status_code=429, content={"error": f"Rate limit exceeded (max ~{rlim // 2} req/s)"}))

    api_key_hdr = request.headers.get("X-API-Key") or ""
    header_tok = request.headers.get("X-Dark-Token") or ""
    cookie_tok = request.cookies.get("dark_session") or ""
    if not header_tok:
        auth_h = request.headers.get("Authorization") or ""
        if auth_h.lower().startswith("bearer "):
            cand = auth_h.split(" ", 1)[1].strip()
            if cand.startswith("dark_") and not api_key_hdr:
                api_key_hdr = cand
            else:
                header_tok = cand
    tok = header_tok or cookie_tok

    api_key_rec = edb.authenticate_api_key(api_key_hdr) if api_key_hdr else None
    rbac_sess = edb.get_rbac_session(tok) if tok else None
    legacy_user = dplat.session_user(tok) if tok else None
    rbac_enforced = True if prod_mode else bool(edb.get_setting("rbac_enforced", False))
    lock_enforced = True if prod_mode else bool(dplat.auth_status().get("enabled"))

    # If caller explicitly presented a token or API key that is invalid/expired/revoked, ALWAYS reject 401
    if (tok or api_key_hdr) and not (rbac_sess or legacy_user or api_key_rec):
        return await _finish(JSONResponse(status_code=401, content={"error": "Invalid or expired session token / API key"}))

    # Fail-closed double-submit CSRF enforcement when authenticating via session cookie
    if request.method.upper() in ("POST", "PUT", "PATCH", "DELETE") and cookie_tok and not header_tok and not api_key_hdr and (rbac_sess or legacy_user):
        csrf_cookie = request.cookies.get("dark_csrf") or ""
        csrf_hdr = request.headers.get("X-CSRF-Token") or ""
        if not csrf_cookie or not csrf_hdr or not edb.hmac.compare_digest(csrf_cookie, csrf_hdr):
            return await _finish(JSONResponse(status_code=403, content={"error": "CSRF token missing or invalid"}))

    if (lock_enforced or rbac_enforced) and not (rbac_sess or legacy_user or api_key_rec):
        return await _finish(JSONResponse(status_code=401, content={"error": "authentication required — login via workspace lock, RBAC, or API Key"}))

    actor_name = "operator"
    actor_role = "admin"
    claimed_tenant = (request.headers.get("X-Tenant-ID") or "").strip()
    actor_tenant = "default"
    if rbac_sess:
        actor_name = rbac_sess["username"]
        actor_role = rbac_sess["role"]
        actor_tenant = rbac_sess.get("tenant_id") or "default"
        if claimed_tenant and claimed_tenant != actor_tenant:
            edb.log_audit(actor_name, actor_role, "tenant:cross_access_denied", path, f"claimed={claimed_tenant} actual={actor_tenant}", ip, tenant_id=actor_tenant)
            return await _finish(JSONResponse(status_code=403, content={"error": "Cross-tenant X-Tenant-ID override rejected"}))
    elif api_key_rec:
        actor_name = f"apikey:{api_key_rec['name']}"
        actor_role = api_key_rec["role"]
        actor_tenant = api_key_rec.get("tenant_id") or "default"
        if claimed_tenant and claimed_tenant != actor_tenant:
            edb.log_audit(actor_name, actor_role, "tenant:cross_access_denied", path, f"claimed={claimed_tenant} actual={actor_tenant}", ip, tenant_id=actor_tenant)
            return await _finish(JSONResponse(status_code=403, content={"error": "Cross-tenant X-Tenant-ID override rejected"}))
    elif legacy_user:
        actor_name = legacy_user
        actor_role = "admin"
        actor_tenant = "default"
    elif claimed_tenant and not prod_mode:
        # Unauthenticated dev/local mode only when neither RBAC nor workspace lock is enforced
        actor_tenant = claimed_tenant

    if rbac_sess or api_key_rec or legacy_user or rbac_enforced:
        req_perm = _required_permission(request.method, path)
        if req_perm and not edb.has_permission(actor_role, req_perm):
            edb.log_audit(actor_name, actor_role, "rbac:denied", path, f"Missing permission {req_perm}", ip, tenant_id=actor_tenant)
            return await _finish(JSONResponse(status_code=403, content={"error": f"RBAC denied: role '{actor_role}' lacks '{req_perm}'"}))

    if prod_mode:
        edb.log_audit(actor_name, actor_role, f"api:{request.method.lower()}", path, "", ip, tenant_id=actor_tenant)

    ctx_tok = edb.set_current_actor(actor_name, actor_role, ip, tenant_id=actor_tenant)
    try:
        return await _finish(await call_next(request))
    finally:
        edb.reset_current_actor(ctx_tok)


@app.get("/", include_in_schema=False)
def dashboard():
    return FileResponse(APP_DIR / "dashboard.html")


@app.get("/docs", include_in_schema=False)
@app.get("/api-studio", include_in_schema=False)
@app.get("/redoc", include_in_schema=False)
def api_studio():
    return FileResponse(APP_DIR / "api_studio.html")


@app.get("/static/logo.png", include_in_schema=False)
def logo():
    return FileResponse(APP_DIR / "logo.png")


@app.get("/api/health")
def health():
    backend = edb._dbm.get_backend_info()
    return {
        "name": "DARK",
        "version": "4.0.0",
        "status": "online",
        "deployment_profile": get_deployment_profile(),
        "debug_mode": not is_production_profile(),
        "db_engine": backend.get("active_engine", "sqlite"),
        "db_backend": backend,
        "platform": sys.platform,
        "tools": engine.tools_status(),
        "legal": LEGAL,
    }


# ---- jobs: lifecycle ------------------------------------------------------
@app.get("/api/jobs")
def list_jobs(project_id: Optional[str] = None):
    tid = edb.get_current_tenant()
    with JOBS_LOCK:
        items = sorted(JOBS.values(), key=lambda x: x["started_at"], reverse=True)
        if tid and tid != "default":
            items = [j for j in items if (j.get("tenant_id") or "default") == tid]
        if project_id:
            items = [j for j in items if (j.get("project_id") or "default") == project_id]
        return {"jobs": [_public(j) for j in items],
                "max_parallel": MAX_PARALLEL_JOBS}


def _assert_job_tenant(job: dict) -> None:
    tid = edb.get_current_tenant()
    jtid = (job.get("tenant_id") or "default").strip() or "default"
    if tid and tid != "default" and jtid != tid:
        raise HTTPException(403, "Cross-tenant job access denied")


@app.get("/api/jobs/{job_id}")
def get_job(job_id: str):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            raise HTTPException(404, f"job not found: {job_id}")
        snap = _public(job)
    _assert_job_tenant(snap)
    return snap


@app.get("/api/jobs/{job_id}/note")
def get_job_note(job_id: str):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if job:
            _assert_job_tenant(job)
    return {"job_id": job_id, "note": dplat.get_note(job_id)}


@app.put("/api/jobs/{job_id}/note")
def set_job_note(job_id: str, req: NoteReq):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if job:
            _assert_job_tenant(job)
    return {"job_id": job_id, "note": dplat.set_note(job_id, req.text)}


@app.post("/api/jobs/{job_id}/stop")
def stop_job(job_id: str):
    """Cooperatively stop a running job and flush all findings collected so far."""
    need_save = False
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            raise HTTPException(404, f"job not found: {job_id}")
        _assert_job_tenant(job)
        ev = job.get("_stop_event")
        if ev is not None:
            ev.set()
        st_now = job.get("status")
        if st_now in ("done", "stopped", "error", "timeout"):
            return {"job": _public(job)}
        if st_now == "interrupted" or (ev is None and st_now in ("running", "waiting", "stopping")):
            res = job.get("result")
            if not isinstance(res, dict):
                res = {"target": job.get("target") or job.get("kind") or "scan",
                       "findings": [], "stopped_early": True}
            else:
                res["stopped_early"] = True
            job.update(status="stopped", finished_at=job.get("finished_at") or time.time(),
                       result=res, progress=None)
            need_save = True
            pub = _public(job)
        elif st_now in ("running", "waiting"):
            job["status"] = "stopping"
            pub = None
        else:
            pub = None
    if need_save:
        _jobs_to_disk()
        return {"job": pub}
    # Wait up to 10.0s for the worker thread to finish flushing its partial result
    deadline = time.time() + 10.0
    while time.time() < deadline:
        with JOBS_LOCK:
            st = JOBS[job_id]["status"]
            if st in ("stopped", "done", "error", "timeout"):
                return {"job": _public(JOBS[job_id])}
        time.sleep(0.12)
    with JOBS_LOCK:
        return {"job": _public(JOBS[job_id])}


@app.post("/api/jobs/{job_id}/recover")
def recover_or_reproduce_job(job_id: str):
    """Re-run or recover an interrupted/completed job with identical parameters (Scan Reproducibility)."""
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            raise HTTPException(404, f"job not found: {job_id}")
        _assert_job_tenant(job)
        kind = job.get("kind") or ""
        pid = job.get("project_id") or "default"
        tgt = job.get("target") or ""
        payload = dict(job.get("repro_payload") or {})
    runner_map = {
        "web-scan": engine.run_web_scan,
        "network-scan": engine.run_network_scan,
        "dns-recon": engine.run_dns_recon,
        "hash-crack": engine.crack_hashes,
        "cloud-audit": engine.run_cloud_audit,
        "container-audit": engine.run_container_audit,
        "sast-audit": engine.run_sast_audit,
        "api-audit": engine.run_api_audit,
        "forensics": engine.run_forensics_audit,
        "monitor-demo": engine.run_monitor_demo,
    }
    fn = runner_map.get(kind)
    if not fn:
        raise HTTPException(400, f"Recovery not supported for kind '{kind}'")
    new_id = start_job(kind, fn, project_id=pid, target_hint=tgt, **payload)
    edb.log_audit("operator", "analyst", "job:recover", f"{job_id} -> {new_id}")
    return {"job_id": new_id, "recovered_from": job_id, "kind": kind}


eroutes._HOOKS["recover_fn"] = recover_or_reproduce_job


@app.delete("/api/jobs/{job_id}")
def delete_job(job_id: str):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            raise HTTPException(404, f"job not found: {job_id}")
        _assert_job_tenant(job)
        ev = job.get("_stop_event")
        if ev is not None:
            ev.set()
        del JOBS[job_id]
    _jobs_to_disk()
    return {"ok": True}


@app.get("/api/jobs/{job_id}/report")
def job_report(job_id: str, download: int = 0):
    """World-class executive HTML report (print-to-PDF from the browser).
    Works for BOTH completed ('done') AND stopped ('stopped') scans."""
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            raise HTTPException(404, f"job not found: {job_id}")
        job = _public(job)
    _assert_job_tenant(job)
    if job.get("status") not in ("done", "stopped"):
        raise HTTPException(409, f"job is {job.get('status')} — stop or wait until it finishes")
    result = job.get("result") or {}
    kind = job.get("kind")
    sys.path.insert(0, str(APP_DIR.parent / "webvulnx"))
    import report as dreport  # type: ignore
    extra_diag = []
    if job.get("status") == "stopped" or result.get("stopped_early"):
        extra_diag.append("Scan stopped early by operator — report contains all findings discovered prior to stop.")
    if kind == "web-scan":
        payload = dict(result)
        payload["diagnostics"] = extra_diag + list(payload.get("diagnostics") or [])
        html = dreport.render_html(payload)
    elif kind == "network-scan":
        rep = result.get("report") or {}
        hosts = rep.get("hosts") or []
        total_ports = sum(len(h.get("open_ports") or []) for h in hosts)
        html = dreport.render_html({
            "target": result.get("target") or job.get("target") or "network-scan",
            "stats": {
                "urls_crawled": len(hosts), "forms": total_ports, "parameters": 0,
                "requests_sent": rep.get("ports_per_host", 0) * max(len(hosts), 1),
                "modules_run": ["netrecon", "service-fingerprinting", "nessus-vuln-plugins", "tls-audit"],
                "duration_s": rep.get("duration_s") or round((job.get("finished_at") or 0) - (job.get("started_at") or 0), 1),
            },
            "findings": result.get("findings") or rep.get("findings") or [],
            "diagnostics": extra_diag + [
                f"DARK NetRecon + Nessus-style service CVE plugins — {len(hosts)} host(s), {total_ports} open port(s)"
            ],
        })
    elif kind == "dns-recon":
        subs = result.get("subdomains") or []
        html = dreport.render_html({
            "target": result.get("domain") or result.get("target") or "dns-recon",
            "stats": {
                "urls_crawled": len(subs), "forms": 0, "parameters": 0,
                "requests_sent": len(subs) + 7,
                "modules_run": ["dns-records", "spf-dmarc-caa-audit", "subdomain-enum", "takeover-check"],
                "duration_s": result.get("duration_s") or round((job.get("finished_at") or 0) - (job.get("started_at") or 0), 1),
            },
            "findings": result.get("findings") or [],
            "diagnostics": extra_diag + [
                f"DARK DNS & Email Security Recon — {len(subs)} subdomain(s) discovered"
            ],
        })
    else:
        # Wrap non-web jobs in the same cover so every DARK job has a report.
        html = dreport.render_html({
            "target": result.get("target") or kind,
            "stats": {
                "urls_crawled": 0, "forms": 0, "parameters": 0,
                "requests_sent": 0, "modules_run": [kind],
                "duration_s": round((job.get("finished_at") or 0) - (job.get("started_at") or 0), 1),
            },
            "findings": result.get("findings") or result.get("alerts") or [],
            "diagnostics": extra_diag + [f"DARK {kind} job {job_id}"],
        })
    headers = {}
    if download:
        headers["Content-Disposition"] = f'attachment; filename="DARK-{job_id}.html"'
    return HTMLResponse(html, headers=headers)


@app.get("/api/projects/{project_id}/report")
def project_report(project_id: str, download: int = 0):
    """Unified Project Executive HTML Report combining ALL jobs in a project."""
    proj = next((p for p in dplat.list_projects() if p.get("id") == project_id), {"id": project_id, "name": project_id})
    tid = edb.get_current_tenant()
    with JOBS_LOCK:
        jobs = [_public(j) for j in JOBS.values()
                if (j.get("project_id") or "default") == project_id
                and (not tid or tid == "default" or (j.get("tenant_id") or "default") == tid)
                and j.get("status") in ("done", "stopped")]
    sys.path.insert(0, str(APP_DIR.parent / "webvulnx"))
    import report as dreport  # type: ignore

    combined_findings: List[Dict[str, Any]] = []
    targets: List[str] = []
    modules: List[str] = []
    total_urls = 0
    total_reqs = 0
    total_dur = 0.0
    diagnostics: List[str] = [
        f"Unified Project Report for '{proj.get('name')}' ({len(jobs)} completed/stopped job(s))"
    ]

    seen_findings = set()
    for j in jobs:
        res = j.get("result") or {}
        kind = j.get("kind") or "job"
        tgt = res.get("target") or j.get("target") or kind
        if tgt and tgt not in targets:
            targets.append(tgt)
        if kind not in modules:
            modules.append(kind)
        st = res.get("stats") or {}
        total_urls += int(st.get("urls_crawled") or 0)
        total_reqs += int(st.get("requests_sent") or 0)
        total_dur += float(st.get("duration_s") or 0.0)
        note = dplat.get_note(j["id"])
        if note:
            diagnostics.append(f"Operator Note [{j['id']} / {tgt}]: {note}")

        raw_fs = res.get("findings") or (res.get("report") or {}).get("findings") or []
        for f in raw_fs:
            item = dict(f)
            if not item.get("url"):
                item["url"] = tgt
            fkey = (
                str(item.get("vuln_type") or ""),
                str(item.get("url") or "").rstrip("/"),
                str(item.get("parameter") or ""),
            )
            if fkey in seen_findings:
                continue
            seen_findings.add(fkey)
            item["detail"] = f"[{kind} | {tgt}] " + (item.get("detail") or "")
            combined_findings.append(item)

        if kind == "hash-crack":
            cracked = [r for r in (res.get("results") or []) if r.get("cracked")]
            if cracked:
                hkey = ("Cracked Credential Hashes", str(tgt), "HashBreaker")
                if hkey not in seen_findings:
                    seen_findings.add(hkey)
                    combined_findings.append({
                        "vuln_type": f"Cracked Credential Hashes ({len(cracked)})",
                        "severity": "High",
                        "url": tgt,
                        "parameter": "HashBreaker",
                        "evidence": ", ".join(f"{c.get('used_algo')}:{c.get('password')}" for c in cracked[:6]),
                        "detail": "Weak or dictionary passwords cracked during offline audit.",
                        "cvss_hint": 7.5,
                    })

    role_now = edb.get_current_actor().get("role", "admin")
    combined_findings = [drpt.redact_finding_for_role(f, role_now) for f in combined_findings]

    html = dreport.render_html({
        "target": f"Project: {proj.get('name')} ({', '.join(targets[:4]) or 'no targets'})",
        "stats": {
            "urls_crawled": total_urls,
            "forms": len(jobs),
            "parameters": len(targets),
            "requests_sent": total_reqs,
            "modules_run": modules or ["unified-project"],
            "duration_s": round(total_dur, 1),
        },
        "findings": combined_findings,
        "diagnostics": diagnostics,
    })
    headers = {}
    if download:
        headers["Content-Disposition"] = f'attachment; filename="DARK-Project-{project_id}.html"'
    return HTMLResponse(html, headers=headers)


# ---- platform: projects, targets, scan compare, auth ----------------------
@app.get("/api/projects")
def api_list_projects():
    return {"projects": dplat.list_projects()}


@app.post("/api/projects")
def api_create_project(req: ProjectReq):
    return {"project": dplat.create_project(req.name, req.description, req.color)}


@app.patch("/api/projects/{pid}")
def api_update_project(pid: str, req: ProjectReq):
    p = dplat.update_project(pid, name=req.name, description=req.description, color=req.color)
    if not p:
        raise HTTPException(404, "project not found")
    return {"project": p}


@app.delete("/api/projects/{pid}")
def api_delete_project(pid: str):
    if not dplat.delete_project(pid):
        raise HTTPException(400, "cannot delete default or unknown project")
    return {"ok": True}


@app.get("/api/targets")
def api_targets(project_id: Optional[str] = None):
    tid = edb.get_current_tenant()
    with JOBS_LOCK:
        items = [_public(j) for j in JOBS.values()
                 if not tid or tid == "default" or (j.get("tenant_id") or "default") == tid]
    if project_id:
        items = [j for j in items if (j.get("project_id") or "default") == project_id]
    return {"targets": dplat.build_target_history(items)}


@app.get("/api/compare")
def api_compare(a: str, b: str):
    with JOBS_LOCK:
        ja = JOBS.get(a)
        jb = JOBS.get(b)
        if not ja or not jb:
            raise HTTPException(404, "one or both jobs not found")
        ja_p, jb_p = _public(ja), _public(jb)
    _assert_job_tenant(ja_p)
    _assert_job_tenant(jb_p)
    return dplat.compare_jobs(ja_p, jb_p)


@app.get("/api/auth/status")
def api_auth_status(request: Request):
    st = dplat.auth_status()
    tok = request.cookies.get("dark_session") or request.headers.get("X-Dark-Token")
    st["authenticated"] = (not st["enabled"]) or bool(dplat.session_user(tok))
    if request.cookies.get("dark_csrf"):
        st["csrf_token"] = request.cookies.get("dark_csrf")
    return st


@app.post("/api/auth/login")
def api_auth_login(req: AuthLoginReq, request: Request):
    ip = request.client.host if request.client else "global"
    ok_rl, _ = edb.check_login_rate_limit(ip)
    if not ok_rl:
        raise HTTPException(429, "Too many login attempts — please wait before retrying")
    if not dplat.verify_password(req.username, req.password):
        edb.log_audit(req.username, "unknown", "workspace:login_fail", req.username, "Invalid credentials", ip)
        raise HTTPException(401, "invalid credentials")
    old_tok = request.cookies.get("dark_session") or request.headers.get("X-Dark-Token")
    tok = dplat.create_session(req.username, old_token=old_tok)
    csrf_tok = edb.secrets.token_urlsafe(24)
    samesite = os.environ.get("DARK_COOKIE_SAMESITE", "lax")
    sec_cookie = (
        os.environ.get("DARK_FORCE_SECURE_COOKIES") == "1"
        or (request.headers.get("x-forwarded-proto") or request.url.scheme or "").lower() == "https"
    )
    resp = JSONResponse({"ok": True, "token": tok, "csrf_token": csrf_tok, "username": req.username})
    resp.set_cookie(
        "dark_session", tok, httponly=True, samesite=samesite,
        secure=sec_cookie, max_age=dplat.SESSION_ABSOLUTE_TTL,
    )
    resp.set_cookie(
        "dark_csrf", csrf_tok, httponly=False, samesite=samesite,
        secure=sec_cookie, max_age=dplat.SESSION_ABSOLUTE_TTL,
    )
    return resp


@app.post("/api/auth/logout")
def api_auth_logout(request: Request):
    tok = request.cookies.get("dark_session") or request.headers.get("X-Dark-Token")
    dplat.drop_session(tok)
    resp = JSONResponse({"ok": True})
    resp.delete_cookie("dark_session")
    resp.delete_cookie("dark_csrf")
    return resp


@app.post("/api/auth/setup")
def api_auth_setup(req: AuthSetupReq, request: Request):
    if dplat.auth_status().get("enabled"):
        tok = request.cookies.get("dark_session") or request.headers.get("X-Dark-Token")
        if not dplat.session_user(tok):
            raise HTTPException(401, "login first before changing workspace password")
    try:
        st = dplat.set_password(req.username, req.password, req.enabled)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return st


@app.post("/api/auth/disable")
def api_auth_disable(request: Request):
    if dplat.auth_status().get("enabled"):
        tok = request.cookies.get("dark_session") or request.headers.get("X-Dark-Token")
        if not dplat.session_user(tok):
            raise HTTPException(401, "login required")
    return dplat.disable_auth()


@app.get("/api/jobs/{job_id}/export.csv")
def job_csv(job_id: str):
    import csv
    import io
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            raise HTTPException(404, f"job not found: {job_id}")
        snap = _public(job)
        result = (job.get("result") or {})
    _assert_job_tenant(snap)
    findings = result.get("findings") or result.get("alerts") or []
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["severity", "type", "parameter", "url", "payload", "evidence", "cvss"])
    for f in findings:
        w.writerow([
            f.get("severity") or "",
            f.get("vuln_type") or f.get("category") or "",
            f.get("parameter") or "",
            f.get("url") or f.get("src") or "",
            sh.redact_sensitive(str(f.get("payload") or ""), max_len=300),
            sh.redact_sensitive(str(f.get("evidence") or f.get("detail") or ""), max_len=400),
            f.get("cvss_hint") or "",
        ])
    return Response(buf.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="DARK-{job_id}.csv"'})


# ---- jobs: network & dns recon --------------------------------------------
@app.post("/api/jobs/network-scan")
def job_network_scan(req: NetworkScanReq):
    job_id = start_job(
        "network-scan", engine.run_network_scan,
        project_id=req.project_id,
        target_hint=", ".join(req.targets[:4]),
        targets=req.targets, ports=req.ports, timing=req.timing,
        probe=req.probe, discover=req.discover, vuln_audit=req.vuln_audit,
    )
    return {"job_id": job_id, "legal": LEGAL}


@app.post("/api/jobs/dns-recon")
def job_dns_recon(req: DnsReconReq):
    job_id = start_job(
        "dns-recon", engine.run_dns_recon,
        project_id=req.project_id,
        target_hint=req.target,
        target=req.target, subdomains=req.subdomains,
        passive_crtsh=req.passive_crtsh, extra_words=req.extra_words,
    )
    return {"job_id": job_id, "legal": LEGAL}


# ---- jobs: web ------------------------------------------------------------
@app.post("/api/jobs/web-scan")
def job_web_scan(req: WebScanReq):
    job_id = start_job(
        "web-scan", engine.run_web_scan,
        project_id=req.project_id,
        target_hint=req.url,
        url=req.url,
        modules={"crawl": req.crawl, "sqli": req.sqli, "xss": req.xss,
                 "dirs": req.dirs, "audit": req.audit, "advanced": req.advanced,
                 "param_fuzz": req.param_fuzz, "default_creds": req.default_creds,
                 "templates": req.templates},
        depth=req.depth, max_urls=req.max_urls, timeout=req.timeout,
        delay=req.delay, rate_limit=req.rate_limit,
        time_blind=None if req.fast else req.time_blind,
        cookie=req.cookie, proxy=req.proxy, stealth=req.stealth,
        auth_header=req.auth_header, extra_headers=req.extra_headers,
        login_url=req.login_url, login_user=req.login_user, login_pass=req.login_pass,
        openapi_url=req.openapi_url,
    )
    return {"job_id": job_id, "legal": LEGAL}


# ---- templates (Nuclei-style YAML) ----------------------------------------
@app.get("/api/templates")
def api_list_templates():
    sys.path.insert(0, str(APP_DIR.parent / "webvulnx"))
    import templates_engine as te  # type: ignore
    tpls = te.load_all_templates()
    return {
        "templates": [
            {
                "id": t.get("id"),
                "source": t.get("_source"),
                "file": t.get("_file"),
                "name": (t.get("info") or {}).get("name"),
                "severity": (t.get("info") or {}).get("severity"),
                "tags": (t.get("info") or {}).get("tags") or [],
                "description": (t.get("info") or {}).get("description") or "",
            }
            for t in tpls
        ]
    }


@app.post("/api/templates")
def api_save_template(req: TemplateSaveReq):
    sys.path.insert(0, str(APP_DIR.parent / "webvulnx"))
    import templates_engine as te  # type: ignore
    try:
        res = te.save_custom_template(req.yaml_text)
    except Exception as e:
        raise HTTPException(400, f"Invalid template YAML: {e}")
    return {"saved": res}


@app.delete("/api/templates/{tid}")
def api_delete_template(tid: str):
    sys.path.insert(0, str(APP_DIR.parent / "webvulnx"))
    import templates_engine as te  # type: ignore
    if not te.delete_custom_template(tid):
        raise HTTPException(404, "custom template not found")
    return {"ok": True}


# ---- hashes ---------------------------------------------------------------
@app.post("/api/hash/identify")
def hash_identify(req: HashIdentifyReq):
    return engine.identify_hashes(req.hashes)


@app.post("/api/hash/generate")
def hash_generate(req: HashGenerateReq):
    try:
        return engine.generate_hash(req.text, req.algo, req.salt)
    except Exception as e:
        raise HTTPException(400, str(e))


@app.post("/api/jobs/hash-crack")
def job_hash_crack(req: HashCrackReq):
    words = req.words
    wl_dir = APP_DIR.parent / "hashbreaker" / "wordlists"
    wordlist_path = None
    choice = (req.wordlist or "auto").lower()
    rockyou = wl_dir / "rockyou.txt"
    common = wl_dir / "common-pass.txt"
    if choice == "rockyou" and rockyou.is_file():
        wordlist_path = str(rockyou)
    elif choice == "common":
        wordlist_path = str(common)
    elif choice == "auto":
        # biggest available list wins — this is what makes cracking actually work
        wordlist_path = str(rockyou) if rockyou.is_file() else str(common)
    elif choice not in ("", "none"):
        cand = wl_dir / Path(choice).name      # path-traversal safe
        if cand.is_file():
            wordlist_path = str(cand)
    job_id = start_job(
        "hash-crack", engine.crack_hashes,
        project_id=req.project_id,
        target_hint=req.hashes[0][:24] if req.hashes else "hashes",
        hashes=req.hashes, words=words,
        rules=req.rules, mask=req.mask, algo=req.algo, salt=req.salt,
        wordlist_path=wordlist_path, workers=req.workers,
    )
    return {"job_id": job_id, "wordlist": Path(wordlist_path).name if wordlist_path else "inline",
            "legal": LEGAL}


@app.post("/api/jobs/hash-benchmark")
def job_hash_benchmark():
    job_id = start_job("hash-benchmark", engine.benchmark)
    return {"job_id": job_id}


# ---- monitor --------------------------------------------------------------
@app.post("/api/jobs/monitor-demo")
def job_monitor_demo(req: MonitorReq = MonitorReq()):
    job_id = start_job("monitor-demo", engine.run_monitor_demo,
                       project_id=req.project_id,
                       target_hint="monitor-demo",
                       syn_threshold=req.syn_threshold)
    return {"job_id": job_id, "legal": LEGAL}


@app.post("/api/jobs/monitor-pcap")
def job_monitor_pcap(file: UploadFile = File(...),
                     gateway: Optional[str] = None,
                     syn_threshold: int = 25,
                     project_id: str = "default"):
    suffix = Path(file.filename or "capture.pcap").suffix.lower() or ".pcap"
    if suffix not in (".pcap", ".pcapng", ".cap"):
        raise HTTPException(400, "Only .pcap / .pcapng / .cap files are permitted")
    up_dir = APP_DIR / "uploads"
    up_dir.mkdir(exist_ok=True)
    tmp = sh.safe_resolve_under(up_dir, f"{uuid.uuid4().hex[:10]}{suffix}")
    raw_bytes = file.file.read(50 * 1024 * 1024 + 1)
    if len(raw_bytes) > 50 * 1024 * 1024:
        raise HTTPException(413, "PCAP upload exceeds 50 MB limit")
    tmp.write_bytes(raw_bytes)
    job_id = start_job("monitor-pcap", engine.run_monitor_pcap,
                       project_id=project_id,
                       target_hint=file.filename or "pcap",
                       pcap_path=str(tmp), gateway=gateway,
                       syn_threshold=syn_threshold)
    return {"job_id": job_id, "file": file.filename, "legal": LEGAL}


@app.post("/api/jobs/monitor-live")
def job_monitor_live(req: MonitorReq = MonitorReq()):
    job_id = start_job(
        "monitor-live", engine.run_monitor_live,
        project_id=req.project_id,
        target_hint=req.interface or "live",
        seconds=req.seconds,
        iface=req.interface, gateway=req.gateway, bpf=req.bpf,
        syn_threshold=req.syn_threshold,
    )
    return {"job_id": job_id, "legal": LEGAL}


# ---- wordlists ------------------------------------------------------------
_WL_CACHE: Dict[str, Any] = {"ts": 0.0, "data": {}}


def _fast_line_count(path: Path) -> int:
    """Count newlines in 1 MB chunks — rockyou.txt (139 MB) counts in <1s
    instead of being slurped line by line."""
    n = 0
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                n += chunk.count(b"\n")
    except OSError:
        return 0
    return n


@app.get("/api/wordlists")
def wordlists():
    if time.time() - _WL_CACHE["ts"] < 60:
        return {"wordlists": _WL_CACHE["data"]}
    base = APP_DIR.parent
    out = {}
    wl_dir = base / "hashbreaker" / "wordlists"
    if wl_dir.exists():
        for f in sorted(wl_dir.glob("*.txt")):
            if not f.is_file():
                continue                      # dangling symlink / missing target
            out[f.stem] = {"path": str(f), "lines": _fast_line_count(f),
                           "size_mb": round(f.stat().st_size / 1e6, 1)}
    d_dir = base / "webvulnx" / "wordlists"
    if d_dir.exists():
        for f in sorted(d_dir.glob("*.txt")):
            if not f.is_file():
                continue
            out[f"dirs:{f.stem}"] = {"path": str(f), "lines": _fast_line_count(f),
                                     "size_mb": round(f.stat().st_size / 1e6, 1)}
    _WL_CACHE.update(ts=time.time(), data=out)
    return {"wordlists": out}


@app.exception_handler(Exception)
def on_error(request, exc):
    return JSONResponse(status_code=500, content={"error": f"{type(exc).__name__}: {exc}"})


def run_cli(argv: Optional[List[str]] = None) -> None:
    import argparse
    import uvicorn
    p = argparse.ArgumentParser(prog="dark-api", description="DARK Security Platform API Server")
    p.add_argument("--host", default=os.environ.get("DARK_HOST", "127.0.0.1"), help="Bind host (default: 127.0.0.1)")
    p.add_argument("--port", type=int, default=int(os.environ.get("DARK_PORT", "8000")), help="Bind port (default: 8000)")
    p.add_argument("--version", action="version", version=f"DARK {app.version}")
    args = p.parse_args(argv)
    uvicorn.run(app, host=args.host, port=args.port)
