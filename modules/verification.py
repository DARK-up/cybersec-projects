#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DARK Advanced Vulnerability Verification Engine.

Provides:
  - Verification Statuses: Confirmed, Likely, Unverified, False Positive
  - Sensitive Evidence Redaction (Authorization, Cookie, JWT, Secrets masked)
  - Scanner / Plugin / Asset linkage & Reproducibility Records
  - Manual Verification override & Safe scoped re-verification
  - Strict rule: raw marker/error observations alone never auto-mark Confirmed
"""
from __future__ import annotations

import hashlib
import json
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent.parent
for _p in (str(ROOT / "dark"), str(ROOT / "webvulnx")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import enterprise_db as edb  # noqa: E402
import security_hardening as sh  # noqa: E402

VALID_VERIFICATION_STATUSES = ("Confirmed", "Likely", "Unverified", "False Positive")


def _fkey(f: dict) -> str:
    raw = f"{f.get('vuln_type','')}|{f.get('url','')}|{f.get('parameter','')}"
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]


def classify_initial_verification(finding: dict) -> tuple[str, float]:
    """Ensure marker/error-only observations are NOT blindly marked Confirmed."""
    vt = str(finding.get("vuln_type") or "").lower()
    ev = str(finding.get("evidence") or "").lower()
    conf = float(finding.get("confidence") or 0.7)

    # Marker/error-only heuristics stay Likely or Unverified until verified
    if any(w in vt for w in ("potential", "possible", "heuristic", "recommended", "context-dependent")):
        return "Unverified", min(conf, 0.55)
    if ("error" in ev or "marker" in ev) and "confirmed" not in ev and "matched" not in ev and "executable" not in vt:
        return "Likely", min(max(conf, 0.65), 0.79)
    if conf >= 0.85 or "confirmed" in ev or "executable" in vt or "matched" in ev or "http " in ev:
        return "Confirmed", max(conf, 0.90)
    return "Likely", conf


def record_finding_verification(
    project_id: str,
    job_id: str,
    finding: dict,
    scanner: str = "webvulnx",
    plugin_id: str = "",
    request_raw: str = "",
    response_raw: str = "",
    repro_payload: Optional[dict] = None,
    tenant_id: Optional[str] = None,
) -> dict:
    tid = (tenant_id or edb.get_current_tenant() or "default").strip() or "default"
    fk = _fkey(finding)
    vid = uuid.uuid5(uuid.NAMESPACE_DNS, f"{tid}:{project_id}:{fk}").hex[:12]
    status, conf = classify_initial_verification(finding)
    url = str(finding.get("url") or "")
    asset_name = (urlsplit(url).hostname or url)[:120]
    req_red = sh.redact_sensitive(request_raw or f"{finding.get('how_it_entered','')} payload={finding.get('payload','')}")
    resp_red = sh.redact_sensitive(response_raw or str(finding.get("evidence") or ""))
    repro = json.dumps(repro_payload or {"url": url, "parameter": finding.get("parameter", "")}, ensure_ascii=False)
    now = time.time()

    with edb._DB_LOCK:
        c = edb._conn()
        try:
            existing = c.execute("SELECT status, verified_by FROM finding_verifications WHERE id=?", (vid,)).fetchone()
            # Preserve explicit manual False Positive / Confirmed overrides across re-scans
            if existing and existing["verified_by"] != "system":
                status = existing["status"]
            c.execute(
                "INSERT INTO finding_verifications"
                "(id, tenant_id, project_id, job_id, asset_name, scanner, plugin_id, finding_key, vuln_type, "
                "status, confidence, request_redacted, response_redacted, reproducibility_json, verified_by, notes, updated_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,'system','',?) "
                "ON CONFLICT(id) DO UPDATE SET job_id=excluded.job_id, status=?, confidence=excluded.confidence, "
                "request_redacted=excluded.request_redacted, response_redacted=excluded.response_redacted, updated_at=excluded.updated_at",
                (vid, tid, project_id or "default", job_id, asset_name, scanner, plugin_id, fk,
                 str(finding.get("vuln_type") or "")[:180], status, round(conf, 2),
                 req_red, resp_red, repro, now, status),
            )
            c.commit()
            row = c.execute("SELECT * FROM finding_verifications WHERE id=?", (vid,)).fetchone()
            d = dict(row)
            d["target_url"] = url
            d["redacted_evidence"] = d.get("response_redacted", "")
            d["reproducibility"] = json.loads(d.pop("reproducibility_json") or "{}")
            return d
        finally:
            c.close()


def record_verification(
    project_id: str,
    job_id: str,
    finding: dict,
    status: Optional[str] = None,
    note: str = "",
    manual_override: bool = False,
    tenant_id: Optional[str] = None,
) -> dict:
    rec = record_finding_verification(project_id, job_id, finding, tenant_id=tenant_id)
    if manual_override and status and status in VALID_VERIFICATION_STATUSES:
        actor = edb.get_current_actor().get("username", "analyst")
        updated = manual_verify(rec["id"], status, notes=note, actor=actor, tenant_id=tenant_id)
        if updated:
            return updated
    return rec


def auto_ingest_job_verifications(job: dict) -> int:
    pid = job.get("project_id") or "default"
    jid = job.get("id") or ""
    tid = job.get("tenant_id") or "default"
    kind = job.get("kind") or "scanner"
    res = job.get("result") or {}
    fs = res.get("findings") or (res.get("report") or {}).get("findings") or []
    cnt = 0
    for f in fs[:200]:
        record_finding_verification(pid, jid, f, scanner=kind, tenant_id=tid)
        cnt += 1
    return cnt


def list_verifications(
    project_id: Optional[str] = None,
    status: Optional[str] = None,
    tenant_id: Optional[str] = None,
) -> dict:
    tid = (tenant_id or edb.get_current_tenant() or "default").strip() or "default"
    with edb._DB_LOCK:
        c = edb._conn()
        try:
            q = "SELECT * FROM finding_verifications WHERE tenant_id=?"
            args: list = [tid]
            if project_id:
                q += " AND project_id=?"
                args.append(project_id)
            if status and status in VALID_VERIFICATION_STATUSES:
                q += " AND status=?"
                args.append(status)
            q += " ORDER BY updated_at DESC LIMIT 200"
            rows = c.execute(q, args).fetchall()
            items = []
            counts = {s: 0 for s in VALID_VERIFICATION_STATUSES}
            for r in rows:
                d = dict(r)
                repro = json.loads(d.pop("reproducibility_json") or "{}")
                d["reproducibility"] = repro
                d["target_url"] = repro.get("url") or d.get("asset_name") or ""
                d["redacted_evidence"] = d.get("response_redacted", "")
                counts[d["status"]] = counts.get(d["status"], 0) + 1
                items.append(d)
            total = len(items)
            fp_rate = round((counts["False Positive"] / total) * 100.0, 1) if total else 0.0
            return {"verifications": items, "counts": counts, "false_positive_rate_pct": fp_rate}
        finally:
            c.close()


def manual_verify(
    verification_id: str,
    status: str,
    notes: str = "",
    actor: str = "analyst",
    tenant_id: Optional[str] = None,
) -> Optional[dict]:
    if status not in VALID_VERIFICATION_STATUSES:
        raise ValueError(f"Status must be one of {VALID_VERIFICATION_STATUSES}")
    tid = (tenant_id or edb.get_current_tenant() or "default").strip() or "default"
    conf = {"Confirmed": 1.0, "Likely": 0.75, "Unverified": 0.4, "False Positive": 0.0}[status]
    with edb._DB_LOCK:
        c = edb._conn()
        try:
            cur = c.execute(
                "UPDATE finding_verifications SET status=?, confidence=?, notes=?, verified_by=?, updated_at=? "
                "WHERE id=? AND tenant_id=?",
                (status, conf, notes[:500], actor, time.time(), verification_id, tid),
            )
            c.commit()
            if cur.rowcount == 0:
                return None
            row = c.execute("SELECT * FROM finding_verifications WHERE id=?", (verification_id,)).fetchone()
            d = dict(row)
            d["reproducibility"] = json.loads(d.pop("reproducibility_json") or "{}")
            return d
        finally:
            c.close()


def safe_reverify_http(verification_id: str, tenant_id: Optional[str] = None) -> Optional[dict]:
    """Perform a safe, read-only scoped GET check on the stored reproducibility URL."""
    import requests
    tid = (tenant_id or edb.get_current_tenant() or "default").strip() or "default"
    with edb._DB_LOCK:
        c = edb._conn()
        try:
            row = c.execute("SELECT * FROM finding_verifications WHERE id=? AND tenant_id=?", (verification_id, tid)).fetchone()
            if not row:
                return None
            repro = json.loads(row["reproducibility_json"] or "{}")
            url = repro.get("url") or ""
        finally:
            c.close()

    if not url.startswith(("http://", "https://")):
        return manual_verify(verification_id, row["status"], notes="Non-HTTP target: manual retest required", actor="retest-safe", tenant_id=tid)
    ok_scope, reason = edb.check_target_in_scope(url)
    if not ok_scope:
        raise ValueError(f"Safe retest blocked by scope: {reason}")

    try:
        r = requests.get(url, timeout=5)
        snippet = sh.redact_sensitive(f"HTTP {r.status_code}\n{r.text[:400]}")
        note = f"Safe GET probe returned HTTP {r.status_code} ({len(r.text)} bytes)"
        with edb._DB_LOCK:
            c = edb._conn()
            try:
                c.execute(
                    "UPDATE finding_verifications SET response_redacted=?, notes=?, updated_at=? WHERE id=?",
                    (snippet, note, time.time(), verification_id),
                )
                c.commit()
            finally:
                c.close()
    except Exception as e:
        note = f"Target unreachable during safe retest ({type(e).__name__})"
    items = list_verifications(tenant_id=tid)["verifications"]
    return next((x for x in items if x["id"] == verification_id), items[0] if items else None)


def retest_verification(verification_id: str, allow_loopback: bool = True, tenant_id: Optional[str] = None) -> dict:
    """Safe scoped retest that checks whether payload/marker still executes or if remediated."""
    import requests
    tid = (tenant_id or edb.get_current_tenant() or "default").strip() or "default"
    with edb._DB_LOCK:
        c = edb._conn()
        try:
            row = c.execute("SELECT * FROM finding_verifications WHERE id=? AND tenant_id=?", (verification_id, tid)).fetchone()
            if not row:
                raise ValueError("Verification record not found")
            repro = json.loads(row["reproducibility_json"] or "{}")
            url = str(repro.get("url") or "")
            req_red = str(row["request_redacted"] or "")
        finally:
            c.close()

    still_vuln = False
    note = "Safe scoped HTTP retest completed"
    if url.startswith(("http://", "https://")):
        ok_ssrf, reason = sh.validate_outbound_url(url, allow_loopback=allow_loopback)
        if not ok_ssrf:
            raise ValueError(f"Retest URL blocked: {reason}")
        r = requests.get(url, timeout=5)
        body = r.text or ""
        # Check if an actual unencoded script/payload from request_redacted is echoed back in HTML
        m_pay = None
        if "payload=" in req_red:
            m_pay = req_red.split("payload=", 1)[1].strip()
        if m_pay and len(m_pay) >= 6 and m_pay in body and "text/html" in (r.headers.get("Content-Type", "text/html").lower()):
            still_vuln = True
            note = f"Payload still reflected unencoded (HTTP {r.status_code})"
        else:
            still_vuln = False
            note = f"Payload no longer reflected in response (HTTP {r.status_code})"

    new_status = "Confirmed" if still_vuln else "False Positive"
    updated = manual_verify(verification_id, new_status, notes=note, actor="retest-safe", tenant_id=tid)
    return {"still_vulnerable": still_vuln, "note": note, "verification": updated}
