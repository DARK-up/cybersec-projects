#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DARK Threat Intelligence Integration Module.

Capabilities:
  - IOC Feeds (IP, Domain, URL, File Hash) with Confidence & Expiration
  - STIX 2.1 Bundle JSON import & export
  - Multi-source correlation (never treats a single uncorroborated IOC as proof)
  - Threat Intelligence History & Asset/Finding enrichment
"""
from __future__ import annotations

import json
import re
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT / "dark") not in sys.path:
    sys.path.insert(0, str(ROOT / "dark"))

import enterprise_db as edb  # noqa: E402

VALID_IOC_TYPES = ("ip", "domain", "url", "hash")

SEED_IOCS = [
    ("ip", "198.51.100.44", "dark-lab-feed", 0.65, "High", "Simulated C2 Beacon IP (RFC 5737 Lab)"),
    ("ip", "203.0.113.99", "dark-lab-feed", 0.60, "Medium", "Simulated Brute-Force Source IP (RFC 5737 Lab)"),
    ("domain", "evil-c2.example", "dark-lab-feed", 0.70, "High", "Simulated Malicious C2 Domain"),
    ("hash", "44d88612fea8a8f36de82e1278abb02f", "eicar-standard", 0.99, "Medium", "EICAR AV Test Signature MD5"),
]


def ensure_seed_iocs() -> None:
    now = time.time()
    with edb._DB_LOCK:
        c = edb._conn()
        try:
            cnt = c.execute("SELECT COUNT(*) AS n FROM threat_iocs").fetchone()["n"]
            if cnt == 0:
                for itype, val, src, conf, sev, ctx in SEED_IOCS:
                    iid = uuid.uuid5(uuid.NAMESPACE_DNS, f"default:{itype}:{val}:{src}").hex[:12]
                    c.execute(
                        "INSERT OR IGNORE INTO threat_iocs"
                        "(id, tenant_id, ioc_type, value, source, confidence, severity, context, expires_at, first_seen, last_seen) "
                        "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                        (iid, "default", itype, val.lower(), src, conf, sev, ctx, now + 365 * 86400, now, now),
                    )
                c.commit()
        finally:
            c.close()


ensure_seed_iocs()


def _detect_ioc_type(val: str) -> str:
    v = val.strip()
    if re.match(r'^(?:\d{1,3}\.){3}\d{1,3}$', v):
        return "ip"
    if v.startswith(("http://", "https://")):
        return "url"
    if re.match(r'^[a-fA-F0-9]{32,64}$', v):
        return "hash"
    return "domain"


def add_ioc(
    value: str,
    source: str = "manual-feed",
    ioc_type: Optional[str] = None,
    confidence: float = 0.7,
    severity: str = "Medium",
    context: str = "",
    ttl_days: int = 90,
    tenant_id: Optional[str] = None,
) -> dict:
    val = (value or "").strip().lower()
    if not val:
        raise ValueError("IOC value required")
    itype = (ioc_type or _detect_ioc_type(val)).lower()
    if itype not in VALID_IOC_TYPES:
        itype = "domain"
    tid = (tenant_id or edb.get_current_tenant() or "default").strip() or "default"
    src = (source or "manual-feed").strip()[:60]
    conf = max(0.05, min(1.0, float(confidence)))
    now = time.time()
    exp = now + max(1, int(ttl_days)) * 86400
    iid = uuid.uuid5(uuid.NAMESPACE_DNS, f"{tid}:{itype}:{val}:{src}").hex[:12]

    with edb._DB_LOCK:
        c = edb._conn()
        try:
            c.execute(
                "INSERT INTO threat_iocs"
                "(id, tenant_id, ioc_type, value, source, confidence, severity, context, expires_at, first_seen, last_seen) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(tenant_id, ioc_type, value, source) DO UPDATE SET "
                "confidence=excluded.confidence, severity=excluded.severity, context=excluded.context, "
                "expires_at=excluded.expires_at, last_seen=excluded.last_seen",
                (iid, tid, itype, val, src, conf, severity.title(), context[:300], exp, now, now),
            )
            c.execute(
                "INSERT INTO threat_history(tenant_id, ioc_value, source, action, detail, ts) VALUES(?,?,?,?,?,?)",
                (tid, val, src, "ingest", f"type={itype}, conf={conf}", now),
            )
            c.commit()
        finally:
            c.close()
    return {"id": iid, "tenant_id": tid, "ioc_type": itype, "value": val, "source": src,
            "confidence": conf, "severity": severity.title(), "expires_at": exp}


def import_stix_bundle(bundle: dict, source: str = "stix-bundle", tenant_id: Optional[str] = None) -> dict:
    """Import STIX 2.1 Bundle indicator patterns (`[ipv4-addr:value = '...']`, etc.)."""
    if not isinstance(bundle, dict) or bundle.get("type") != "bundle":
        raise ValueError("Expected STIX 2.1 JSON object with type='bundle'")
    imported = 0
    for obj in (bundle.get("objects") or []):
        if not isinstance(obj, dict) or obj.get("type") != "indicator":
            continue
        pat = str(obj.get("pattern") or "")
        conf = float(obj.get("confidence", 70)) / 100.0
        ctx = str(obj.get("name") or obj.get("description") or "STIX indicator")
        for kind_rx, itype in [
            (r"ipv4-addr:value\s*=\s*'([^']+)'", "ip"),
            (r"domain-name:value\s*=\s*'([^']+)'", "domain"),
            (r"url:value\s*=\s*'([^']+)'", "url"),
            (r"file:hashes\.[^=]+=\s*'([^']+)'", "hash"),
        ]:
            for m in re.findall(kind_rx, pat):
                add_ioc(m, source=source, ioc_type=itype, confidence=conf,
                        severity="High" if conf >= 0.8 else "Medium", context=ctx, tenant_id=tenant_id)
                imported += 1
    return {"imported": imported, "source": source}


def export_stix_bundle(tenant_id: Optional[str] = None) -> dict:
    iocs = list_iocs(tenant_id=tenant_id, include_expired=False)["iocs"]
    objs = []
    for i in iocs:
        pat_map = {
            "ip": f"[ipv4-addr:value = '{i['value']}']",
            "domain": f"[domain-name:value = '{i['value']}']",
            "url": f"[url:value = '{i['value']}']",
            "hash": f"[file:hashes.MD5 = '{i['value']}']",
        }
        objs.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid5(uuid.NAMESPACE_DNS, i['id'])}",
            "name": f"{i['ioc_type']}:{i['value']}",
            "description": i["context"],
            "pattern": pat_map.get(i["ioc_type"], f"[domain-name:value = '{i['value']}']"),
            "pattern_type": "stix",
            "confidence": int(i["confidence"] * 100),
            "labels": [i["source"], i["severity"]],
        })
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objs}


def list_iocs(tenant_id: Optional[str] = None, include_expired: bool = False) -> dict:
    tid = (tenant_id or edb.get_current_tenant() or "default").strip() or "default"
    now = time.time()
    with edb._DB_LOCK:
        c = edb._conn()
        try:
            q = "SELECT * FROM threat_iocs WHERE (tenant_id=? OR tenant_id='default')"
            args: list = [tid]
            if not include_expired:
                q += " AND (expires_at=0 OR expires_at>?)"
                args.append(now)
            q += " ORDER BY last_seen DESC LIMIT 500"
            rows = c.execute(q, args).fetchall()
            hist = [dict(r) for r in c.execute(
                "SELECT * FROM threat_history WHERE tenant_id=? OR tenant_id='default' ORDER BY ts DESC LIMIT 50",
                (tid,),
            ).fetchall()]
            return {"iocs": [dict(r) for r in rows], "history": hist}
        finally:
            c.close()


def match_observables(observables: List[str], tenant_id: Optional[str] = None) -> dict:
    """Correlate observables against active IOCs across multiple sources (never treats 1 source as final proof)."""
    active = list_iocs(tenant_id=tenant_id, include_expired=False)["iocs"]
    by_val: Dict[str, List[dict]] = {}
    for row in active:
        by_val.setdefault(row["value"].lower(), []).append(row)

    matches: List[dict] = []
    for obs in observables:
        o = (obs or "").strip().lower()
        if not o:
            continue
        cands = [o]
        if "://" in o:
            hn = (urlsplit(o).hostname or "").lower()
            if hn:
                cands.append(hn)
        for cand in cands:
            hits = by_val.get(cand)
            if not hits:
                continue
            sources = sorted({h["source"] for h in hits})
            avg_conf = round(sum(float(h["confidence"]) for h in hits) / len(hits), 2)
            corroborated = len(sources) >= 2
            matches.append({
                "observable": obs,
                "matched_ioc": cand,
                "sources": sources,
                "source_count": len(sources),
                "corroborated": corroborated,
                "confidence": min(0.98, avg_conf + (0.15 if corroborated else 0.0)),
                "advisory_note": (
                    "Corroborated across multiple threat intelligence feeds"
                    if corroborated
                    else "Single-source indicator only — correlate with behavioral/log evidence before blocking"
                ),
                "context": "; ".join(h["context"] for h in hits if h.get("context")),
            })
    return {"matches": matches, "checked": len(observables)}
