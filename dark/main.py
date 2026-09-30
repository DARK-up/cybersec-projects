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

import os
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Dict, List, Optional

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

import engine

APP_DIR = Path(__file__).resolve().parent
LEGAL = ("Authorized security testing only — you must own the target or have "
         "explicit written permission before scanning anything.")

# ---------------------------------------------------------------------------
# Job store (in-memory)
# ---------------------------------------------------------------------------
JOBS: Dict[str, dict] = {}
JOBS_LOCK = threading.Lock()


def start_job(kind: str, runner, **payload) -> str:
    job_id = uuid.uuid4().hex[:12]
    with JOBS_LOCK:
        JOBS[job_id] = {
            "id": job_id, "kind": kind, "status": "running",
            "started_at": time.time(), "finished_at": None,
            "result": None, "error": None,
        }

    def _run():
        try:
            result = runner(**payload)
            if isinstance(result, dict) and result.get("error"):
                with JOBS_LOCK:
                    JOBS[job_id].update(status="error", error=result["error"],
                                        result=result, finished_at=time.time())
            else:
                with JOBS_LOCK:
                    JOBS[job_id].update(status="done", result=result,
                                        finished_at=time.time())
        except Exception as e:  # never crash the server
            with JOBS_LOCK:
                JOBS[job_id].update(status="error",
                                    error=f"{type(e).__name__}: {e}",
                                    finished_at=time.time())

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
                 "dirs": req.dirs, "audit": req.audit},
        depth=req.depth, max_urls=req.max_urls, timeout=req.timeout,
        delay=req.delay, time_blind=req.time_blind, cookie=req.cookie,
        proxy=req.proxy,
    )
    return {"job_id": job_id, "legal": LEGAL}


# ---- hashes ---------------------------------------------------------------
@app.post("/api/hash/identify")
def hash_identify(req: HashIdentifyReq):
    return engine.identify_hashes(req.hashes)


@app.post("/api/jobs/hash-crack")
def job_hash_crack(req: HashCrackReq):
    words = req.words
    wordlist_path = None
    if req.wordlist == "common":
        wordlist_path = str(APP_DIR.parent / "hashbreaker" / "wordlists" / "common-pass.txt")
    job_id = start_job(
        "hash-crack", engine.crack_hashes, hashes=req.hashes, words=words,
        rules=req.rules, mask=req.mask, algo=req.algo, salt=req.salt,
        wordlist_path=wordlist_path, workers=req.workers,
    )
    return {"job_id": job_id, "legal": LEGAL}


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
@app.get("/api/wordlists")
def wordlists():
    base = APP_DIR.parent
    out = {}
    wl_dir = base / "hashbreaker" / "wordlists"
    if wl_dir.exists():
        for f in wl_dir.glob("*.txt"):
            out[f.stem] = {"path": str(f), "lines": sum(1 for _ in open(f, errors="ignore"))}
    d_dir = base / "webvulnx" / "wordlists"
    if d_dir.exists():
        for f in d_dir.glob("*.txt"):
            out[f"dirs:{f.stem}"] = {"path": str(f), "lines": sum(1 for _ in open(f, errors="ignore"))}
    return {"wordlists": out}


@app.exception_handler(Exception)
def on_error(request, exc):
    return JSONResponse(status_code=500, content={"error": f"{type(exc).__name__}: {exc}"})
