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

import engine

APP_DIR = Path(__file__).resolve().parent

def _load_platform():
    spec = importlib.util.spec_from_file_location("dark_platform", APP_DIR / "platform.py")
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


def _jobs_to_disk() -> None:
    """Persist job metadata: history survives a restart and no job can be
    left displayed as 'running' after the API was restarted."""
    try:
        with JOBS_LOCK:
            items = sorted(JOBS.values(), key=lambda j: j.get("started_at") or 0,
                           reverse=True)[:MAX_JOBS_KEPT]
            slim = []
            for j in items:
                c = {k: v for k, v in j.items() if not k.startswith("_")}
                r = c.get("result")
                if isinstance(r, dict) and isinstance(r.get("log"), str) \
                        and len(r["log"]) > 200_000:
                    r = dict(r)
                    r["log"] = r["log"][:200_000] + "\n…[log truncated]…"
                    c["result"] = r
                c.pop("progress", None)
                slim.append(c)
        tmp = JOBS_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(slim, ensure_ascii=False, default=str),
                       encoding="utf-8")
        tmp.replace(JOBS_FILE)
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
                    j["status"] = "timeout"
                    j["finished_at"] = now
                    buf = j.get("_log")
                    tail = buf.snapshot(tail_lines=25) if buf is not None else ""
                    j["error"] = (f"Job exceeded its "
                                  f"{int(JOB_DEADLINES.get(j['kind'], JOB_DEADLINE_DEFAULT))}s "
                                  f"limit and was stopped by the watchdog. Narrow the scan "
                                  f"(fewer targets/URLs) or raise the limit."
                                  + (f"\n\nLast output before the stop:\n{tail}" if tail else ""))
                    changed = True
        if changed:
            _jobs_to_disk()


_jobs_from_disk()
threading.Thread(target=_watchdog, daemon=True).start()


def _public(job: dict) -> dict:
    """Strip private runtime handles (log buffers) from API responses."""
    return {k: v for k, v in job.items() if not k.startswith("_")}


def start_job(kind: str, runner, project_id: str = "default",
              target_hint: str = "", **payload) -> str:
    import inspect
    job_id = uuid.uuid4().hex[:12]
    now = time.time()
    logbuf = engine.JobLog()
    stop_ev = threading.Event()
    pid = (project_id or "default").strip() or "default"
    with JOBS_LOCK:
        JOBS[job_id] = {
            "id": job_id, "kind": kind, "status": "running",
            "project_id": pid, "target": target_hint,
            "started_at": now, "finished_at": None,
            "deadline": now + JOB_DEADLINES.get(kind, JOB_DEADLINE_DEFAULT),
            "result": None, "error": None, "progress": None,
            "_log": logbuf, "_stop_event": stop_ev,
        }
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
                else:
                    JOBS[job_id].update(status="done", result=result,
                                        finished_at=time.time())
        except Exception as e:  # never crash the server
            with JOBS_LOCK:
                JOBS[job_id].update(status="error",
                                    error=f"{type(e).__name__}: {e}",
                                    finished_at=time.time())
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
                 "Unified REST API for NetRecon / WebVulnX / HashBreaker / NetSentry.\n\n"
                 + LEGAL),
    version="2.0.0",
)
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)


@app.middleware("http")
async def _auth_gate(request: Request, call_next):
    path = request.url.path
    if path.startswith("/api/") and not path.startswith("/api/auth/") and path != "/api/health":
        if dplat.auth_status().get("enabled"):
            tok = request.cookies.get("dark_session") or request.headers.get("X-Dark-Token")
            if not dplat.session_user(tok):
                return JSONResponse(status_code=401, content={"error": "workspace locked — login required"})
    return await call_next(request)


@app.get("/", include_in_schema=False)
def dashboard():
    return FileResponse(APP_DIR / "dashboard.html")


@app.get("/static/logo.png", include_in_schema=False)
def logo():
    return FileResponse(APP_DIR / "logo.png")


@app.get("/api/health")
def health():
    return {
        "name": "DARK",
        "version": "2.0.0",
        "status": "online",
        "platform": sys.platform,
        "tools": engine.tools_status(),
        "legal": LEGAL,
    }


# ---- jobs: lifecycle ------------------------------------------------------
@app.get("/api/jobs")
def list_jobs(project_id: Optional[str] = None):
    with JOBS_LOCK:
        items = sorted(JOBS.values(), key=lambda x: x["started_at"], reverse=True)
        if project_id:
            items = [j for j in items if (j.get("project_id") or "default") == project_id]
        return {"jobs": [_public(j) for j in items],
                "max_parallel": MAX_PARALLEL_JOBS}


@app.get("/api/jobs/{job_id}")
def get_job(job_id: str):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            raise HTTPException(404, f"job not found: {job_id}")
        return _public(job)


@app.get("/api/jobs/{job_id}/note")
def get_job_note(job_id: str):
    return {"job_id": job_id, "note": dplat.get_note(job_id)}


@app.put("/api/jobs/{job_id}/note")
def set_job_note(job_id: str, req: NoteReq):
    return {"job_id": job_id, "note": dplat.set_note(job_id, req.text)}


@app.post("/api/jobs/{job_id}/stop")
def stop_job(job_id: str):
    """Cooperatively stop a running job and flush all findings collected so far."""
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            raise HTTPException(404, f"job not found: {job_id}")
        ev = job.get("_stop_event")
        if ev is not None:
            ev.set()
        if job.get("status") in ("running", "waiting"):
            job["status"] = "stopping"
    # Wait up to 4.0s for the worker thread to finish flushing its partial result
    deadline = time.time() + 4.0
    while time.time() < deadline:
        with JOBS_LOCK:
            st = JOBS[job_id]["status"]
            if st in ("stopped", "done", "error", "timeout"):
                return {"job": _public(JOBS[job_id])}
        time.sleep(0.15)
    with JOBS_LOCK:
        return {"job": _public(JOBS[job_id])}


@app.delete("/api/jobs/{job_id}")
def delete_job(job_id: str):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            raise HTTPException(404, f"job not found: {job_id}")
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
    with JOBS_LOCK:
        jobs = [_public(j) for j in JOBS.values()
                if (j.get("project_id") or "default") == project_id
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
            item["detail"] = f"[{kind} | {tgt}] " + (item.get("detail") or "")
            combined_findings.append(item)

        if kind == "hash-crack":
            cracked = [r for r in (res.get("results") or []) if r.get("cracked")]
            if cracked:
                combined_findings.append({
                    "vuln_type": f"Cracked Credential Hashes ({len(cracked)})",
                    "severity": "High",
                    "url": tgt,
                    "parameter": "HashBreaker",
                    "evidence": ", ".join(f"{c.get('used_algo')}:{c.get('password')}" for c in cracked[:6]),
                    "detail": "Weak or dictionary passwords cracked during offline audit.",
                    "cvss_hint": 7.5,
                })

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
    with JOBS_LOCK:
        items = [_public(j) for j in JOBS.values()]
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
    return dplat.compare_jobs(ja_p, jb_p)


@app.get("/api/auth/status")
def api_auth_status(request: Request):
    st = dplat.auth_status()
    tok = request.cookies.get("dark_session") or request.headers.get("X-Dark-Token")
    st["authenticated"] = (not st["enabled"]) or bool(dplat.session_user(tok))
    return st


@app.post("/api/auth/login")
def api_auth_login(req: AuthLoginReq):
    if not dplat.verify_password(req.username, req.password):
        raise HTTPException(401, "invalid credentials")
    tok = dplat.create_session(req.username)
    resp = JSONResponse({"ok": True, "token": tok, "username": req.username})
    resp.set_cookie("dark_session", tok, httponly=True, samesite="lax", max_age=7 * 24 * 3600)
    return resp


@app.post("/api/auth/logout")
def api_auth_logout(request: Request):
    tok = request.cookies.get("dark_session") or request.headers.get("X-Dark-Token")
    dplat.drop_session(tok)
    resp = JSONResponse({"ok": True})
    resp.delete_cookie("dark_session")
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
        result = (job.get("result") or {})
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
            (f.get("payload") or "")[:300],
            (f.get("evidence") or f.get("detail") or "")[:400],
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
        delay=req.delay, time_blind=None if req.fast else req.time_blind,
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
    suffix = Path(file.filename or "capture.pcap").suffix or ".pcap"
    tmp = APP_DIR / "uploads" / f"{uuid.uuid4().hex[:10]}{suffix}"
    tmp.parent.mkdir(exist_ok=True)
    tmp.write_bytes(file.file.read())
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
