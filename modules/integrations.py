#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DARK Enterprise Integrations Framework.

Supports:
  - Webhooks (HMAC-SHA256 signed + SSRF-guarded)
  - Jira / GitHub Issues / SIEM (CEF & Syslog JSON) connectors
  - SARIF v2.1.0 Import & Export
  - Integration Health Monitoring & Delivery History
"""
from __future__ import annotations

import hashlib
import hmac
import json
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT / "dark") not in sys.path:
    sys.path.insert(0, str(ROOT / "dark"))

import enterprise_db as edb  # noqa: E402
import security_hardening as sh  # noqa: E402

VALID_INTEGRATION_KINDS = ("webhook", "jira", "github", "siem")


def register_integration(
    kind: str,
    name: str,
    config: Dict[str, Any],
    tenant_id: Optional[str] = None,
) -> dict:
    k = (kind or "").strip().lower()
    if k not in VALID_INTEGRATION_KINDS:
        raise ValueError(f"Integration kind must be one of {VALID_INTEGRATION_KINDS}")
    tid = (tenant_id or edb.get_current_tenant() or "default").strip() or "default"
    # SSRF validation on outbound URLs
    url_val = str(config.get("url") or config.get("endpoint") or "").strip()
    if url_val:
        ok_ssrf, reason = sh.validate_outbound_url(url_val, allow_loopback=bool(config.get("allow_loopback", False)))
        if not ok_ssrf:
            raise ValueError(f"Unsafe integration URL: {reason}")
    iid = uuid.uuid4().hex[:10]
    nb, cb, mb = edb._encrypt_secret(json.dumps(config, ensure_ascii=False))
    enc_blob = json.dumps({"n": nb, "c": cb, "m": mb})
    now = time.time()
    with edb._DB_LOCK:
        c = edb._conn()
        try:
            c.execute(
                "INSERT INTO integrations(id, tenant_id, kind, name, config_enc_json, enabled, last_status, last_checked, created_at) "
                "VALUES(?,?,?,?,?,1,'configured',?,?)",
                (iid, tid, k, (name or k)[:80], enc_blob, now, now),
            )
            c.commit()
        finally:
            c.close()
    return {"id": iid, "tenant_id": tid, "kind": k, "name": (name or k)[:80], "enabled": True, "last_status": "configured"}


def list_integrations(tenant_id: Optional[str] = None) -> dict:
    tid = (tenant_id or edb.get_current_tenant() or "default").strip() or "default"
    with edb._DB_LOCK:
        c = edb._conn()
        try:
            rows = c.execute(
                "SELECT id, tenant_id, kind, name, enabled, last_status, last_checked, created_at "
                "FROM integrations WHERE tenant_id=? ORDER BY created_at DESC",
                (tid,),
            ).fetchall()
            deliveries = c.execute(
                "SELECT * FROM integration_deliveries WHERE tenant_id=? ORDER BY ts DESC LIMIT 30",
                (tid,),
            ).fetchall()
            return {"integrations": [dict(r) for r in rows], "deliveries": [dict(d) for d in deliveries]}
        finally:
            c.close()


def _load_config(integration_id: str, tenant_id: str) -> Optional[tuple[dict, dict]]:
    with edb._DB_LOCK:
        c = edb._conn()
        try:
            row = c.execute("SELECT * FROM integrations WHERE id=? AND tenant_id=?", (integration_id, tenant_id)).fetchone()
            if not row:
                return None
            blob = json.loads(row["config_enc_json"])
            cfg = json.loads(edb._decrypt_secret(blob["n"], blob["c"], blob["m"]))
            return dict(row), cfg
        finally:
            c.close()


def _log_delivery(tenant_id: str, integration_id: str, event_type: str, status: str, detail: str) -> None:
    now = time.time()
    with edb._DB_LOCK:
        c = edb._conn()
        try:
            c.execute(
                "INSERT INTO integration_deliveries(tenant_id, integration_id, event_type, status, detail, ts) "
                "VALUES(?,?,?,?,?,?)",
                (tenant_id, integration_id, event_type, status, detail[:300], now),
            )
            c.execute(
                "UPDATE integrations SET last_status=?, last_checked=? WHERE id=?",
                (status, now, integration_id),
            )
            c.commit()
        finally:
            c.close()


def format_siem_cef(finding: dict) -> str:
    sev_num = {"Critical": 10, "High": 8, "Medium": 5, "Low": 3, "Info": 1}.get(str(finding.get("severity")), 5)
    vt = str(finding.get("vuln_type") or "Finding").replace("|", "\\|")
    url = str(finding.get("url") or "").replace("=", "\\=")
    return f"CEF:0|DARK|EnterprisePlatform|3.0|100|{vt}|{sev_num}|request={url} cs1={finding.get('cwe','')}"


def dispatch_event(
    integration_id: str,
    event_type: str,
    payload: Dict[str, Any],
    tenant_id: Optional[str] = None,
) -> dict:
    tid = (tenant_id or edb.get_current_tenant() or "default").strip() or "default"
    loaded = _load_config(integration_id, tid)
    if not loaded:
        raise ValueError("Integration not found")
    meta, cfg = loaded
    kind = meta["kind"]
    url = str(cfg.get("url") or cfg.get("endpoint") or "").strip()

    if kind == "siem" and not url:
        cef_lines = [format_siem_cef(f) for f in (payload.get("findings") or [])[:20]]
        _log_delivery(tid, integration_id, event_type, "ok_formatted", f"{len(cef_lines)} CEF event(s)")
        return {"status": "ok_formatted", "cef": cef_lines}

    if not url:
        _log_delivery(tid, integration_id, event_type, "skipped_no_url", "No endpoint configured")
        return {"status": "skipped_no_url"}

    allow_lb = bool(cfg.get("allow_loopback", False))
    ok_ssrf, reason = sh.validate_outbound_url(url, allow_loopback=allow_lb, strict_dns=True)
    if not ok_ssrf:
        _log_delivery(tid, integration_id, event_type, "blocked_ssrf", reason)
        raise ValueError(reason)

    body_bytes = json.dumps({"event": event_type, "tenant_id": tid, "data": payload}, default=str).encode("utf-8")
    headers = {"Content-Type": "application/json", "User-Agent": "DARK-Integrations/4.0"}
    secret = str(cfg.get("secret") or "")
    if secret:
        sig = hmac.new(secret.encode("utf-8"), body_bytes, hashlib.sha256).hexdigest()
        headers["X-DARK-Signature-256"] = f"sha256={sig}"
    if cfg.get("token"):
        headers["Authorization"] = f"Bearer {cfg['token']}"

    try:
        r = sh.safe_outbound_request(
            "POST", url, allow_loopback=allow_lb, data=body_bytes, headers=headers, timeout=6.0
        )
        status = "delivered" if 200 <= r.status_code < 300 else f"http_{r.status_code}"
        _log_delivery(tid, integration_id, event_type, status, f"HTTP {r.status_code}")
        return {"status": status, "http_status": r.status_code}
    except ValueError as ve:
        _log_delivery(tid, integration_id, event_type, "blocked_ssrf", str(ve))
        raise
    except Exception as e:
        _log_delivery(tid, integration_id, event_type, "error", type(e).__name__)
        return {"status": "error", "error": type(e).__name__}


# ---------------------------------------------------------------------------
# SARIF v2.1.0 Export & Import
# ---------------------------------------------------------------------------
def export_sarif(job: dict) -> dict:
    res = job.get("result") or {}
    fs = res.get("findings") or (res.get("report") or {}).get("findings") or []
    rules = {}
    results = []
    sev_to_level = {"Critical": "error", "High": "error", "Medium": "warning", "Low": "note", "Info": "note"}
    for f in fs:
        rid = re_id = str(f.get("cwe") or f.get("vuln_type") or "DARK-RULE")[:60]
        if rid not in rules:
            rules[rid] = {
                "id": rid,
                "name": str(f.get("vuln_type") or rid)[:120],
                "shortDescription": {"text": str(f.get("vuln_type") or rid)[:200]},
                "help": {"text": str(f.get("remediation") or "")[:500]},
            }
        results.append({
            "ruleId": re_id,
            "level": sev_to_level.get(str(f.get("severity")), "warning"),
            "message": {"text": f"{f.get('vuln_type')} | {f.get('evidence') or ''}"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": str(f.get("url") or "unknown")}}}],
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "DARK Enterprise Platform", "version": "3.0.0", "rules": list(rules.values())}},
            "results": results,
        }],
    }


def parse_sarif_import(sarif_doc: dict) -> List[dict]:
    if not isinstance(sarif_doc, dict) or "runs" not in sarif_doc:
        raise ValueError("Invalid SARIF v2.1.0 document")
    level_to_sev = {"error": "High", "warning": "Medium", "note": "Low", "none": "Info"}
    findings: List[dict] = []
    for run in (sarif_doc.get("runs") or []):
        tool_name = ((run.get("tool") or {}).get("driver") or {}).get("name") or "ExternalSARIF"
        for res in (run.get("results") or []):
            locs = res.get("locations") or [{}]
            uri = (((locs[0].get("physicalLocation") or {}).get("artifactLocation") or {}).get("uri")) or "sarif-target"
            findings.append({
                "vuln_type": f"[SARIF:{tool_name}] {res.get('ruleId') or 'Finding'}",
                "severity": level_to_sev.get(str(res.get("level") or "warning").lower(), "Medium"),
                "url": uri,
                "parameter": str(res.get("ruleId") or "sarif"),
                "how_it_entered": f"Imported from SARIF ({tool_name})",
                "evidence": ((res.get("message") or {}).get("text") or "")[:300],
                "remediation": "Review imported SARIF rule recommendation and remediate.",
            })
    return findings


def export_cyclonedx(job: dict) -> dict:
    """Export job SBOM components and vulnerability findings in CycloneDX v1.5 JSON."""
    res = job.get("result") or {}
    sbom_comps = ((res.get("sbom") or {}).get("components")) or []
    fs = res.get("findings") or (res.get("report") or {}).get("findings") or []

    cdx_components = []
    for c in sbom_comps:
        nm = str(c.get("name") or "unknown")
        ver = str(c.get("version") or "0.0.0")
        cdx_components.append({
            "type": "library",
            "bom-ref": f"{nm}@{ver}",
            "name": nm,
            "version": ver,
            "purl": c.get("purl") or f"pkg:generic/{nm}@{ver}",
        })

    cdx_vulns = []
    for idx, f in enumerate(fs, 1):
        sev = str(f.get("severity") or "info").lower()
        cdx_vulns.append({
            "id": str(f.get("cve_id") or f"DARK-{idx}"),
            "source": {"name": "DARK Enterprise Platform"},
            "ratings": [{"severity": sev, "score": float(f.get("cvss_v31") or f.get("cvss_hint") or 5.0)}],
            "description": f"{f.get('vuln_type') or 'Finding'} at {f.get('url') or ''} — {f.get('evidence') or ''}"[:400],
            "recommendation": str(f.get("remediation") or "")[:300],
        })

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "tools": [{"vendor": "DARK", "name": "DARK Enterprise Platform", "version": "3.0.0"}],
            "component": {"type": "application", "name": str(job.get("target") or job.get("kind") or "target")},
        },
        "components": cdx_components,
        "vulnerabilities": cdx_vulns,
    }

