#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DARK Benchmark & Quality Assurance Lab.

Measures genuine, reproducible accuracy & resource metrics using a strictly
consistent unit of measurement (Vulnerability Class level, plus separate
finding-level counts — never mixing finding counts with class counts):
  - Class-level TP, FP, FN (same unit: distinct vulnerability class)
  - Class-level Precision, Recall, F1 Score
  - Explicit sample size, coverage, version, and runtime environment
"""
from __future__ import annotations

import json
import platform as _stdlib_platform
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Dict, List, Set

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


def _classify_finding_to_classes(vuln_type: str) -> Set[str]:
    low = (vuln_type or "").lower()
    hits: Set[str] = set()
    for cls_name, keywords in LAB_GROUND_TRUTH:
        if any(k in low for k in keywords):
            hits.add(cls_name)
    if not hits:
        hits.add(f"unmapped:{low.split('(')[0].strip()[:40] or 'other'}")
    return hits


def evaluate_class_confusion_matrix(
    lab_findings: List[dict],
    clean_findings: List[dict],
    ground_truth: List[tuple] = LAB_GROUND_TRUTH,
) -> dict:
    """Compute consistent class-level TP/FP/FN/TN without mixing units.

    Even if a scanner emits 10 duplicate findings or 5 FPs for one class,
    each vulnerability class is counted once in the class-level confusion matrix,
    while exact finding-level counts are reported separately.
    """
    gt_names = [cls_name for cls_name, _ in ground_truth]
    lab_blob = "\n".join(str(f.get("vuln_type") or "").lower() for f in (lab_findings or []))

    matched_classes = []
    missed_classes = []
    for cls_name, keywords in ground_truth:
        if any(k in lab_blob for k in keywords):
            matched_classes.append(cls_name)
        else:
            missed_classes.append(cls_name)

    clean_actionable = [f for f in (clean_findings or []) if f.get("severity") != "Info"]
    fp_classes_set: Set[str] = set()
    for f in clean_actionable:
        fp_classes_set.update(_classify_finding_to_classes(str(f.get("vuln_type") or "")))

    tp = len(matched_classes)
    fn = len(missed_classes)
    fp = len(fp_classes_set)
    # Clean baseline negative classes that remained clean
    tn = max(0, len(gt_names) - len(fp_classes_set & set(gt_names)))

    precision = round(tp / (tp + fp), 4) if (tp + fp) else 0.0
    recall = round(tp / (tp + fn), 4) if (tp + fn) else 0.0
    f1 = round((2 * precision * recall) / (precision + recall), 4) if (precision + recall) else 0.0
    return {
        "unit": "vulnerability_class",
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "matched_classes": matched_classes,
        "missed_classes": missed_classes,
        "fp_classes": sorted(fp_classes_set),
        "finding_counts": {
            "lab_total_findings": len(lab_findings or []),
            "clean_non_info_findings": len(clean_actionable),
            "clean_total_findings": len(clean_findings or []),
        },
    }


def _run_clean_fp_probe() -> List[dict]:
    """Run WebVulnX against an isolated hardened local HTTP server."""
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
        return list(res.get("findings") or [])
    finally:
        srv.shutdown()


def run_benchmark(lab_url: str = "http://127.0.0.1:8080") -> dict:
    t0 = time.perf_counter()
    res = engine.run_web_scan(lab_url, time_blind=None, max_urls=25, depth=2)
    dur_lab = time.perf_counter() - t0
    findings = res.get("findings") or []
    clean_findings = _run_clean_fp_probe()
    cm = evaluate_class_confusion_matrix(findings, clean_findings)
    cpu_pct, ram_mb = edb._sample_system_metrics()

    bid = "BM-" + uuid.uuid4().hex[:8].upper()
    now = time.time()
    details = {
        "unit_of_measurement": cm["unit"],
        "ground_truth_class_count": len(LAB_GROUND_TRUTH),
        "total_lab_findings": cm["finding_counts"]["lab_total_findings"],
        "clean_non_info_findings": cm["finding_counts"]["clean_non_info_findings"],
        "matched_classes": cm["matched_classes"],
        "missed_classes": cm["missed_classes"],
        "fp_classes": cm["fp_classes"],
        "coverage_pct": round((cm["tp"] / len(LAB_GROUND_TRUTH)) * 100.0, 1),
        "scope_warning": "Synthetic demo-lab + 1 hardened baseline only; do not generalize metrics to unseen targets.",
        "platform_version": "4.0.0",
        "environment": {
            "python": _stdlib_platform.python_version(),
            "platform": _stdlib_platform.platform(),
        },
    }

    with edb._DB_LOCK:
        c = edb._conn()
        try:
            c.execute(
                "INSERT INTO benchmark_runs(id, target, tp, fp, fn, precision_score, recall_score, f1_score, duration_s, ram_mb, cpu_pct, details_json, created_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (bid, lab_url, cm["tp"], cm["fp"], cm["fn"], cm["precision"], cm["recall"], cm["f1_score"],
                 round(dur_lab, 2), ram_mb, cpu_pct, json.dumps(details), now),
            )
            c.commit()
        finally:
            c.close()

    return {
        "id": bid,
        "target": lab_url,
        "unit": cm["unit"],
        "tp": cm["tp"], "fp": cm["fp"], "fn": cm["fn"], "tn": cm["tn"],
        "precision": cm["precision"], "recall": cm["recall"], "f1_score": cm["f1_score"],
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
