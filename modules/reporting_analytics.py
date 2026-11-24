#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DARK Advanced Reporting & Analytics Engine.

Produces role-aware Executive Summaries, Risk Distributions, Asset Exposure,
Vulnerability Trends, Remediation Progress, Compliance Status, False Positive
Statistics, Security Posture Score, JSON/CSV/HTML outputs, and Custom Templates.
"""
from __future__ import annotations

import json
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parent.parent
for _p in (str(ROOT / "dark"), str(ROOT / "modules")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import enterprise_db as edb  # noqa: E402
import security_hardening as sh  # noqa: E402
import asset_intel as ai  # noqa: E402
import vuln_intel as vi  # noqa: E402
import verification as vf  # noqa: E402
import remediation as rem  # noqa: E402
import compliance as comp  # noqa: E402


def save_report_template(
    name: str,
    sections: List[str],
    header_text: str = "",
    footer_text: str = "",
    tenant_id: Optional[str] = None,
) -> dict:
    tid = (tenant_id or edb.get_current_tenant() or "default").strip() or "default"
    rid = uuid.uuid4().hex[:10]
    now = time.time()
    with edb._DB_LOCK:
        c = edb._conn()
        try:
            c.execute(
                "INSERT INTO report_templates(id, tenant_id, name, sections_json, header_text, footer_text, created_at) "
                "VALUES(?,?,?,?,?,?,?)",
                (rid, tid, (name or "Custom")[:80], json.dumps(sections), header_text[:300], footer_text[:300], now),
            )
            c.commit()
        finally:
            c.close()
    return {"id": rid, "tenant_id": tid, "name": name, "sections": sections}


def list_report_templates(tenant_id: Optional[str] = None) -> List[dict]:
    tid = (tenant_id or edb.get_current_tenant() or "default").strip() or "default"
    with edb._DB_LOCK:
        c = edb._conn()
        try:
            rows = c.execute("SELECT * FROM report_templates WHERE tenant_id=? ORDER BY created_at DESC", (tid,)).fetchall()
            out = []
            for r in rows:
                d = dict(r)
                d["sections"] = json.loads(d.pop("sections_json") or "[]")
                out.append(d)
            return out
        finally:
            c.close()


def redact_finding_for_role(f: dict, role: str) -> dict:
    """Role-based report filtering: viewer/auditor see redacted payloads & raw secrets."""
    item = dict(f)
    if role in ("viewer", "auditor"):
        if item.get("payload"):
            item["payload"] = "[REDACTED FOR ROLE]"
        if item.get("evidence"):
            item["evidence"] = sh.redact_sensitive(str(item["evidence"]), max_len=200)
    return item


def build_executive_analytics(
    jobs: List[dict],
    project_id: Optional[str] = None,
    tenant_id: Optional[str] = None,
    role: str = "admin",
) -> dict:
    tid = (tenant_id or edb.get_current_tenant() or "default").strip() or "default"
    all_findings: List[dict] = []
    trends: List[dict] = []
    by_sev = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    seen = set()

    scoped_jobs = [
        j for j in sorted(jobs, key=lambda x: x.get("started_at") or 0)
        if not (project_id and j.get("project_id") and j.get("project_id") != project_id)
    ]
    completed_jobs = [j for j in scoped_jobs if j.get("status") in ("done", "stopped")]
    failed_jobs = [j for j in scoped_jobs if j.get("status") in ("error", "timeout", "interrupted")]

    for j in completed_jobs:
        res = j.get("result") or {}
        fs = res.get("findings") or (res.get("report") or {}).get("findings") or []
        trends.append({
            "job_id": j["id"],
            "kind": j.get("kind"),
            "target": j.get("target"),
            "ts": j.get("finished_at") or j.get("started_at"),
            "findings": len(fs),
        })
        for f in fs:
            fk = (str(f.get("vuln_type")), str(f.get("url")).rstrip("/"), str(f.get("parameter")))
            if fk in seen:
                continue
            seen.add(fk)
            rf = redact_finding_for_role(f, role)
            all_findings.append(rf)
            s = str(rf.get("severity") or "Info").title()
            by_sev[s] = by_sev.get(s, 0) + 1

    risk_data = vi.prioritize_findings(all_findings, project_id=project_id or "default")
    assets_data = ai.list_assets(project_id=project_id, tenant_id=tid)
    verif_data = vf.list_verifications(project_id=project_id, tenant_id=tid)
    tickets = rem.list_tickets(project_id=project_id)
    assessed_d, failed_d = comp.domains_from_jobs(scoped_jobs)
    comp_data = comp.evaluate_compliance(all_findings, assessed_domains=assessed_d, failed_domains=failed_d)

    open_t = sum(1 for t in tickets if t["status"] in ("open", "in_progress"))
    closed_t = sum(1 for t in tickets if t["status"] == "verified_closed")

    # Security Posture Score (0-100): Unknown (None) when no completed scans exist
    now_ts = time.time()
    last_scan_ts = max((float(j.get("finished_at") or j.get("started_at") or 0) for j in completed_jobs), default=0.0)
    freshness_hours = round((now_ts - last_scan_ts) / 3600.0, 2) if last_scan_ts else None
    coverage_ratio = round(len(completed_jobs) / max(len(scoped_jobs), 1), 3) if scoped_jobs else 0.0

    if not completed_jobs:
        posture_score = None
        posture_status = "Unknown"
    else:
        penalty = by_sev["Critical"] * 12 + by_sev["High"] * 6 + by_sev["Medium"] * 2 + by_sev["Low"] * 0.5
        posture_score = round(max(5.0, min(100.0, 100.0 - min(90.0, penalty * 0.6))), 1)
        posture_status = "Healthy" if posture_score >= 80 else ("Moderate" if posture_score >= 50 else "At Risk")

    avg_comp = 0.0
    if comp_data["frameworks"]:
        avg_comp = round(sum(v["score_pct"] for v in comp_data["frameworks"].values()) / len(comp_data["frameworks"]), 1)

    return {
        "generated_at": time.time(),
        "tenant_id": tid,
        "project_id": project_id or "all",
        "viewer_role": role,
        "security_posture_score": posture_score,
        "posture_status": posture_status,
        "coverage_and_freshness": {
            "completed_scans": len(completed_jobs),
            "failed_scans": len(failed_jobs),
            "total_scans": len(scoped_jobs),
            "scan_success_ratio": coverage_ratio,
            "assessed_domains": sorted(assessed_d),
            "failed_domains": sorted(failed_d),
            "last_scan_age_hours": freshness_hours,
        },
        "executive_summary": {
            "total_unique_findings": len(all_findings),
            "by_severity": by_sev,
            "kev_exposed": risk_data["kev_count"],
            "attack_paths_detected": len(risk_data["attack_paths"]),
            "total_assets": assets_data["count"],
            "internet_exposed_assets": sum(1 for a in assets_data["assets"] if a["internet_exposed"]),
            "average_compliance_pct": avg_comp,
        },
        "risk_distribution": {
            "p0_immediate_count": len(risk_data["p0_immediate"]),
            "attack_paths": risk_data["attack_paths"],
        },
        "asset_exposure_summary": {
            "total": assets_data["count"],
            "exposed_unowned": assets_data["exposed_unowned_count"],
            "recent_changes": assets_data["history"][:10],
        },
        "remediation_progress": {
            "total_tickets": len(tickets),
            "open_or_in_progress": open_t,
            "verified_closed": closed_t,
        },
        "false_positive_statistics": {
            "verification_counts": verif_data["counts"],
            "false_positive_rate_pct": verif_data["false_positive_rate_pct"],
        },
        "compliance_status": {k: v["score_pct"] for k, v in comp_data["frameworks"].items()},
        "vulnerability_trends": trends[-20:],
        "top_findings": risk_data["findings"][:30],
    }


def _pdf_escape(text: str) -> str:
    clean = "".join(ch if 32 <= ord(ch) <= 126 else "?" for ch in (text or ""))
    return clean.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def render_pdf_bytes(title: str, findings: List[dict], stats: Optional[Dict[str, Any]] = None) -> bytes:
    """Generate a valid multi-page PDF 1.4 document with zero external dependencies."""
    st = stats or {}
    by_sev = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in findings:
        s = str(f.get("severity") or "Info").title()
        by_sev[s] = by_sev.get(s, 0) + 1

    lines: List[str] = [
        f"DARK ENTERPRISE SECURITY REPORT - {title}",
        f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}",
        f"Total Findings: {len(findings)} | Critical: {by_sev['Critical']} | High: {by_sev['High']} | Medium: {by_sev['Medium']} | Low: {by_sev['Low']} | Info: {by_sev['Info']}",
    ]
    if st:
        lines.append(f"Modules: {', '.join(st.get('modules_run') or [])} | Duration: {st.get('duration_s', 0)}s")
    lines.append("-" * 88)
    for idx, f in enumerate(findings[:150], 1):
        vt = str(f.get("vuln_type") or "Finding")[:65]
        sev = str(f.get("severity") or "Info")
        url = str(f.get("url") or "-")[:75]
        ev = sh.redact_sensitive(str(f.get("evidence") or "-"), max_len=90).replace("\n", " ")
        rem_txt = str(f.get("remediation") or "")[:85].replace("\n", " ")
        lines.append(f"#{idx} [{sev}] {vt}")
        lines.append(f"   Target: {url} | Param: {str(f.get('parameter') or '-')[:30]}")
        lines.append(f"   Evidence: {ev}")
        if rem_txt:
            lines.append(f"   Fix: {rem_txt}")
    if not findings:
        lines.append("No vulnerabilities detected during this assessment.")

    # Paginate 46 lines per US-Letter page
    pages = [lines[i:i + 46] for i in range(0, len(lines), 46)] or [["Empty Report"]]
    objects: List[bytes] = []
    # Obj 1: Catalog, Obj 2: Pages, Obj 3: Font
    objects.append(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")
    page_obj_nums = [4 + i * 2 for i in range(len(pages))]
    kids_str = " ".join(f"{n} 0 R" for n in page_obj_nums)
    objects.append(f"2 0 obj\n<< /Type /Pages /Kids [{kids_str}] /Count {len(pages)} >>\nendobj\n".encode("ascii"))
    objects.append(b"3 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>\nendobj\n")

    for i, pg_lines in enumerate(pages):
        p_num = 4 + i * 2
        c_num = p_num + 1
        objects.append(
            f"{p_num} 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            f"/Resources << /Font << /F1 3 0 R >> >> /Contents {c_num} 0 R >>\nendobj\n".encode("ascii")
        )
        stream_cmds = ["BT", "/F1 9 Tf", "36 756 Td", "14 TL"]
        for ln in pg_lines:
            stream_cmds.append(f"({_pdf_escape(ln[:98])}) Tj T*")
        stream_cmds.append("ET")
        stream_bytes = "\n".join(stream_cmds).encode("ascii")
        objects.append(
            f"{c_num} 0 obj\n<< /Length {len(stream_bytes)} >>\nstream\n".encode("ascii")
            + stream_bytes
            + b"\nendstream\nendobj\n"
        )

    buf = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for obj in objects:
        offsets.append(len(buf))
        buf.extend(obj)
    xref_pos = len(buf)
    buf.extend(f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode("ascii"))
    for off in offsets[1:]:
        buf.extend(f"{off:010d} 00000 n \n".encode("ascii"))
    buf.extend(f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n".encode("ascii"))
    return bytes(buf)

