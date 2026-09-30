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

import json
import os
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

import engine

APP_DIR = Path(__file__).resolve().parent
LEGAL = ("Authorized security testing only — you must own the target or have "
         "explicit written permission before scanning anything.")

# ---------------------------------------------------------------------------
# Job store (in-memory) — jobs execute ONE AT A TIME (serial queue):
# this prevents log mixing between jobs AND avoids WAF rate-limiting when
# several scans hit the same target.
# ---------------------------------------------------------------------------
JOBS: Dict[str, dict] = {}
JOBS_LOCK = threading.Lock()
JOB_EXEC_LOCK = threading.Lock()          # serializes job execution
JOBS_FILE = APP_DIR / "jobs_state.json"
MAX_JOBS_KEPT = 60
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
                c = dict(j)
                r = c.get("result")
                if isinstance(r, dict) and isinstance(r.get("log"), str) \
                        and len(r["log"]) > 200_000:
                    r = dict(r)
                    r["log"] = r["log"][:200_000] + "\n…[log truncated]…"
                    c["result"] = r
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
    while True:
        time.sleep(5)
        now = time.time()
        changed = False
        with JOBS_LOCK:
            for j in JOBS.values():
                if j["status"] not in ("running", "waiting"):
                    continue
                deadline = j.get("deadline") or (
                    (j.get("started_at") or now) + JOB_DEADLINE_DEFAULT)
                if now > deadline:
                    j["status"] = "timeout"
                    j["finished_at"] = now
                    j["error"] = (f"Job exceeded its {int(deadline - (j.get('started_at') or now))}s "
                                  f"limit and was stopped by the watchdog. "
                                  f"Narrow the scan (fewer targets/URLs) or raise the limit.")
                    changed = True
        if changed:
            _jobs_to_disk()


_jobs_from_disk()
threading.Thread(target=_watchdog, daemon=True).start()


def start_job(kind: str, runner, **payload) -> str:
    job_id = uuid.uuid4().hex[:12]
    now = time.time()
    deadline = now + JOB_DEADLINES.get(kind, JOB_DEADLINE_DEFAULT)
    with JOBS_LOCK:
        JOBS[job_id] = {
            "id": job_id, "kind": kind, "status": "waiting",
            "started_at": now, "finished_at": None, "deadline": deadline,
            "result": None, "error": None,
        }
    _jobs_to_disk()

    def _run():
        with JOB_EXEC_LOCK:                # one job at a time
            with JOBS_LOCK:
                if JOBS[job_id]["status"] == "timeout":
                    return                 # watchdog already gave up on it
                JOBS[job_id]["status"] = "running"
                JOBS[job_id]["started_at"] = time.time()
                JOBS[job_id]["deadline"] = (
                    time.time() + JOB_DEADLINES.get(kind, JOB_DEADLINE_DEFAULT))
            _jobs_to_disk()
            try:
                result = runner(**payload)
                with JOBS_LOCK:
                    if JOBS[job_id]["status"] == "timeout":
                        return
                    if isinstance(result, dict) and result.get("error"):
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
    fast: bool = False             # skip time-based SQLi (recommended on remote sites)
    depth: int = 3
    max_urls: int = 80
    timeout: float = 10.0
    delay: float = 0.0
    time_blind: float = 5.0
    cookie: Optional[str] = None
    proxy: Optional[str] = None


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


class MonitorReq(BaseModel):
    seconds: int = 10
    interface: Optional[str] = None
    gateway: Optional[str] = None
    bpf: str = ""
    syn_threshold: int = 25


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
app = FastAPI(
    title="DARK API",
    description=("DARK — Detection & Attack Reconnaissance Kit. "
                 "Unified REST API for NetRecon / WebVulnX / HashBreaker / NetSentry.\n\n"
                 + LEGAL),
    version="1.0.0",
)
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)


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
        "version": "1.0.0",
        "status": "online",
        "platform": sys.platform,
        "tools": engine.tools_status(),
        "legal": LEGAL,
    }


# ---- jobs: lifecycle ------------------------------------------------------
@app.get("/api/jobs")
def list_jobs():
    with JOBS_LOCK:
        return {"jobs": sorted(JOBS.values(), key=lambda j: j["started_at"], reverse=True)}


@app.get("/api/jobs/{job_id}")
def get_job(job_id: str):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
    if not job:
        raise HTTPException(404, "job not found")
    return job


# ---- jobs: network --------------------------------------------------------
@app.post("/api/jobs/network-scan")
def job_network_scan(req: NetworkScanReq):
    job_id = start_job(
        "network-scan", engine.run_network_scan,
        targets=req.targets, ports=req.ports, timing=req.timing,
        probe=req.probe, discover=req.discover,
    )
    return {"job_id": job_id, "legal": LEGAL}


# ---- jobs: web ------------------------------------------------------------
@app.post("/api/jobs/web-scan")
def job_web_scan(req: WebScanReq):
    job_id = start_job(
        "web-scan", engine.run_web_scan, url=req.url,
        modules={"crawl": req.crawl, "sqli": req.sqli, "xss": req.xss,
                 "dirs": req.dirs, "audit": req.audit, "advanced": req.advanced,
                 "param_fuzz": req.param_fuzz, "default_creds": req.default_creds},
        depth=req.depth, max_urls=req.max_urls, timeout=req.timeout,
        delay=req.delay, time_blind=None if req.fast else req.time_blind,
        cookie=req.cookie, proxy=req.proxy,
    )
    return {"job_id": job_id, "legal": LEGAL}


# ---- hashes ---------------------------------------------------------------
@app.post("/api/hash/identify")
def hash_identify(req: HashIdentifyReq):
    return engine.identify_hashes(req.hashes)


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
        "hash-crack", engine.crack_hashes, hashes=req.hashes, words=words,
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
                       syn_threshold=req.syn_threshold)
    return {"job_id": job_id, "legal": LEGAL}


@app.post("/api/jobs/monitor-pcap")
def job_monitor_pcap(file: UploadFile = File(...),
                     gateway: Optional[str] = None,
                     syn_threshold: int = 25):
    suffix = Path(file.filename or "capture.pcap").suffix or ".pcap"
    tmp = APP_DIR / "uploads" / f"{uuid.uuid4().hex[:10]}{suffix}"
    tmp.parent.mkdir(exist_ok=True)
    tmp.write_bytes(file.file.read())
    job_id = start_job("monitor-pcap", engine.run_monitor_pcap,
                       pcap_path=str(tmp), gateway=gateway,
                       syn_threshold=syn_threshold)
    return {"job_id": job_id, "file": file.filename, "legal": LEGAL}


@app.post("/api/jobs/monitor-live")
def job_monitor_live(req: MonitorReq = MonitorReq()):
    job_id = start_job(
        "monitor-live", engine.run_monitor_live, seconds=req.seconds,
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
