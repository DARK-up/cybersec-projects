#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DARK Executive Security Posture Dashboard Engine (v4.0).

Aggregates live platform telemetry into executive posture metrics and keeps
historical snapshots for period-over-period comparison:
  - Security Posture Score (0..100)
  - Critical Findings count
  - Exposed Assets count
  - Detection Coverage (%)
  - Remediation Progress (%)
  - Compliance Score (%)
  - Threat Activity count
"""
from __future__ import annotations

import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT / "dark") not in sys.path:
    sys.path.insert(0, str(ROOT / "dark"))

import asset_intel as ai  # noqa: E402
import compliance as comp  # noqa: E402
import detection_engineering as de  # noqa: E402
import enterprise_db as edb  # noqa: E402
import intel_hub as ih  # noqa: E402
import remediation as rem  # noqa: E402


def compute_posture_dashboard(jobs: List[Dict[str, Any]], project_id: Optional[str] = None) -> Dict[str, Any]:
    hub = ih.ingest_jobs_into_hub(jobs)
    findings = hub.get("findings", [])

    crit_count = sum(1 for f in findings if f.get("severity") == "Critical")
    high_count = sum(1 for f in findings if f.get("severity") == "High")

    assets_data = ai.list_assets(project_id=project_id)
    exposed_assets = sum(1 for a in assets_data.get("assets", []) if a.get("internet_exposed"))
    exposed_assets = max(exposed_assets, sum(1 for a in hub.get("assets", []) if a["asset"] not in ("127.0.0.1", "localhost")))

    rules = de.list_rules()
    tactics_covered = len(set(hub.get("mitre_attack", {}).get("by_tactic", {}).keys()) | {r.get("mitre_tactic") for r in rules})
    detection_coverage_pct = round(min(100.0, (tactics_covered / 14.0) * 100.0), 1)

    raw_tickets = rem.list_tickets(project_id=project_id)
    tickets = raw_tickets.get("tickets", []) if isinstance(raw_tickets, dict) else (raw_tickets or [])
    closed_t = sum(1 for t in tickets if t.get("status") in ("verified_closed", "accepted_risk"))
    remediation_progress_pct = round((closed_t / len(tickets)) * 100.0, 1) if tickets else (100.0 if crit_count == 0 else 0.0)

    comp_res = comp.evaluate_compliance(findings)
    fw_scores = [float(v.get("score_pct") or v.get("score") or 0) for v in (comp_res.get("frameworks") or {}).values()]
    compliance_score_pct = round(sum(fw_scores) / len(fw_scores), 1) if fw_scores else 100.0

    threat_activity = sum(
        1 for f in findings
        if any(s in ("threat-hunt", "forensics", "monitor-demo", "monitor-pcap", "phishing-analyze", "malware-triage") for s in f.get("sources", []))
    )

    # Composite Security Posture Score (0..100)
    penalty = min(65.0, crit_count * 12.0 + high_count * 4.0 + min(15.0, threat_activity * 2.0))
    bonus = (detection_coverage_pct * 0.15) + (compliance_score_pct * 0.10) + (remediation_progress_pct * 0.10)
    posture_score = round(max(0.0, min(100.0, (100.0 - penalty) * 0.65 + bonus)), 1)

    snapshot = {
        "project_id": project_id or "default",
        "generated_at": time.time(),
        "security_posture_score": posture_score,
        "critical_findings": crit_count,
        "high_findings": high_count,
        "exposed_assets": exposed_assets,
        "detection_coverage_pct": detection_coverage_pct,
        "remediation_progress_pct": remediation_progress_pct,
        "compliance_score_pct": compliance_score_pct,
        "threat_activity_count": threat_activity,
        "active_detection_rules": len(rules),
    }

    hist_key = f"posture_history:{project_id or 'default'}"
    hist = edb.get_setting(hist_key, []) or []
    delta = {}
    if hist:
        prev = hist[-1]
        delta = {
            "score_delta": round(posture_score - float(prev.get("security_posture_score", posture_score)), 1),
            "critical_delta": crit_count - int(prev.get("critical_findings", crit_count)),
            "exposed_assets_delta": exposed_assets - int(prev.get("exposed_assets", exposed_assets)),
        }
    hist = (hist + [snapshot])[-30:]
    edb.set_setting(hist_key, hist)
    snapshot["period_comparison"] = delta
    snapshot["history_points"] = len(hist)
    return snapshot
