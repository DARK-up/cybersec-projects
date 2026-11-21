#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DARK Benchmark & Quality Assurance Lab.

Measures genuine, reproducible accuracy & resource metrics:
  - True Positives (TP), False Positives (FP), False Negatives (FN)
  - Precision, Recall, F1 Score
  - Average Scan Duration, CPU %, and RAM MB
Evaluated against the authorized local training lab (http://127.0.0.1:8080)
plus a hardened clean baseline.
"""
from __future__ import annotations

import json
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Dict, List

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT / "dark") not in sys.path:
    sys.path.insert(0, str(ROOT / "dark"))

import enterprise_db as edb  # noqa: E402
import engine  # noqa: E402

# Ground-truth vulnerability classes intentionally planted in demo-lab/vuln_app.py
LAB_GROUND_TRUTH = [
    ("sqli", ("sql injection", "sqli")),
    ("xss", ("xss", "cross-site scripting")),
    ("lfi", ("lfi", "path traversal", "local file")),
    ("cmdi", ("command injection", "cmdi", "os command")),
    ("ssti", ("ssti", "template injection")),
    ("open_redirect", ("open redirect", "redirect")),
    ("cors", ("cors",)),
    ("crlf", ("crlf",)),
    ("sensitive_exposure", (".env", "exposed", "secret", "backup", "sensitive")),
    ("security_headers", ("missing security header", "content-security-policy", "x-frame-options")),
]


def _run_clean_fp_probe() -> int:
    """Run WebVulnX against an isolated hardened local HTTP server; any non-Info finding is an FP."""
    class _Clean(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _hdrs(self):
            self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
            self.send_header("Content-Security-Policy", "default-src 'self'")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Permissions-Policy", "geolocation=()")

        def do_GET(self):
            if self.path in ("/", "/index.html"):
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self._hdrs()
                self.end_headers()
                self.wfile.write(b"<html><body><h1>Clean</h1><a href='/q?s=ok'>Q</a></body></html>")
            elif self.path.startswith("/q"):
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self._hdrs()
                self.end_headers()
                self.wfile.write(b"<html><body>Clean search</body></html>")
            else:
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self._hdrs()
                self.end_headers()
                self.wfile.write(b"<html><body><h1>404 Not Found</h1></body></html>")

    srv = HTTPServer(("127.0.0.1", 0), _Clean)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        res = engine.run_web_scan(f"http://127.0.0.1:{port}", time_blind=None, max_urls=8, depth=1)
        return len([f for f in (res.get("findings") or []) if f.get("severity") != "Info"])
    finally:
        srv.shutdown()


def run_benchmark(lab_url: str = "http://127.0.0.1:8080") -> dict:
    t0 = time.perf_counter()
    res = engine.run_web_scan(lab_url, time_blind=None, max_urls=25, depth=2)
    dur_lab = time.perf_counter() - t0
    findings = res.get("findings") or []
    blob = "\n".join(str(f.get("vuln_type") or "").lower() for f in findings)

    matched_classes = []
    missed_classes = []
    for cls_name, keywords in LAB_GROUND_TRUTH:
        if any(k in blob for k in keywords):
            matched_classes.append(cls_name)
        else:
            missed_classes.append(cls_name)

    tp = len(matched_classes)
    fn = len(missed_classes)
    fp = _run_clean_fp_probe()

    precision = round(tp / (tp + fp), 4) if (tp + fp) else 0.0
    recall = round(tp / (tp + fn), 4) if (tp + fn) else 0.0
    f1 = round((2 * precision * recall) / (precision + recall), 4) if (precision + recall) else 0.0
    cpu_pct, ram_mb = edb._sample_system_metrics()

    bid = "BM-" + uuid.uuid4().hex[:8].upper()
    now = time.time()
    details = {
        "total_lab_findings": len(findings),
        "matched_classes": matched_classes,
        "missed_classes": missed_classes,
        "coverage_pct": round((tp / len(LAB_GROUND_TRUTH)) * 100.0, 1),
    }

    with edb._DB_LOCK:
        c = edb._conn()
        try:
            c.execute(
                "INSERT INTO benchmark_runs(id, target, tp, fp, fn, precision_score, recall_score, f1_score, duration_s, ram_mb, cpu_pct, details_json, created_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (bid, lab_url, tp, fp, fn, precision, recall, f1, round(dur_lab, 2), ram_mb, cpu_pct, json.dumps(details), now),
            )
            c.commit()
        finally:
            c.close()

    return {
        "id": bid,
        "target": lab_url,
        "tp": tp, "fp": fp, "fn": fn,
        "precision": precision, "recall": recall, "f1_score": f1,
        "duration_s": round(dur_lab, 2),
        "ram_mb": ram_mb, "cpu_pct": cpu_pct,
        "details": details,
        "created_at": now,
    }


def list_benchmarks(limit: int = 20) -> List[dict]:
    with edb._DB_LOCK:
        c = edb._conn()
        try:
            rows = c.execute("SELECT * FROM benchmark_runs ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
            out = []
            for r in rows:
                d = dict(r)
                d["details"] = json.loads(d.pop("details_json") or "{}")
                out.append(d)
            return out
        finally:
            c.close()
