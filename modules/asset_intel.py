#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DARK Asset Intelligence — Inventory, Domain-IP-Service-API Relationship
Mapping, Criticality Classification, and New Asset Discovery Diff.
"""
from __future__ import annotations

import json
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


def upsert_asset(
    project_id: str,
    kind: str,
    name: str,
    criticality: str = "medium",
    internet_exposed: bool = True,
    meta: Optional[dict] = None,
) -> dict:
    name = (name or "").strip()
    if not name:
        raise ValueError("Asset name required")
    kind = (kind or "host").strip().lower()
    crit = criticality if criticality in ("critical", "high", "medium", "low") else "medium"
    now = time.time()
    aid = uuid.uuid5(uuid.NAMESPACE_DNS, f"{project_id}:{kind}:{name.lower()}").hex[:12]
    meta_str = json.dumps(meta or {}, ensure_ascii=False)
    is_new = False
    with edb._DB_LOCK:
        c = edb._conn()
        try:
            existing = c.execute("SELECT id, first_seen, meta_json FROM assets WHERE id=?", (aid,)).fetchone()
            if existing:
                old_meta = {}
                try:
                    old_meta = json.loads(existing["meta_json"] or "{}")
                except Exception:
                    pass
                old_meta.update(meta or {})
                c.execute(
                    "UPDATE assets SET last_seen=?, meta_json=? WHERE id=?",
                    (now, json.dumps(old_meta, ensure_ascii=False), aid),
                )
            else:
                is_new = True
                c.execute(
                    "INSERT INTO assets(id, project_id, kind, name, criticality, internet_exposed, meta_json, first_seen, last_seen) "
                    "VALUES(?,?,?,?,?,?,?,?,?)",
                    (aid, project_id or "default", kind, name, crit, 1 if internet_exposed else 0, meta_str, now, now),
                )
            c.commit()
        finally:
            c.close()
    return {"id": aid, "project_id": project_id or "default", "kind": kind, "name": name,
            "criticality": crit, "internet_exposed": bool(internet_exposed), "is_new": is_new, "last_seen": now}


def link_assets(project_id: str, src_id: str, dst_id: str, relation: str) -> None:
    if not src_id or not dst_id or src_id == dst_id:
        return
    rid = uuid.uuid5(uuid.NAMESPACE_DNS, f"{project_id}:{src_id}:{dst_id}:{relation}").hex[:12]
    with edb._DB_LOCK:
        c = edb._conn()
        try:
            c.execute(
                "INSERT OR IGNORE INTO asset_relations(id, project_id, src_asset_id, dst_asset_id, relation, created_at) "
                "VALUES(?,?,?,?,?,?)",
                (rid, project_id or "default", src_id, dst_id, relation, time.time()),
            )
            c.commit()
        finally:
            c.close()


def update_asset_meta(asset_id: str, criticality: Optional[str] = None, internet_exposed: Optional[bool] = None) -> bool:
    with edb._DB_LOCK:
        c = edb._conn()
        try:
            row = c.execute("SELECT id FROM assets WHERE id=?", (asset_id,)).fetchone()
            if not row:
                return False
            if criticality in ("critical", "high", "medium", "low"):
                c.execute("UPDATE assets SET criticality=? WHERE id=?", (criticality, asset_id))
            if internet_exposed is not None:
                c.execute("UPDATE assets SET internet_exposed=? WHERE id=?", (1 if internet_exposed else 0, asset_id))
            c.commit()
            return True
        finally:
            c.close()


def list_assets(project_id: Optional[str] = None) -> dict:
    with edb._DB_LOCK:
        c = edb._conn()
        try:
            if project_id:
                arows = c.execute("SELECT * FROM assets WHERE project_id=? ORDER BY last_seen DESC", (project_id,)).fetchall()
                rrows = c.execute("SELECT * FROM asset_relations WHERE project_id=?", (project_id,)).fetchall()
            else:
                arows = c.execute("SELECT * FROM assets ORDER BY last_seen DESC").fetchall()
                rrows = c.execute("SELECT * FROM asset_relations").fetchall()
            assets = []
            for r in arows:
                d = dict(r)
                d["internet_exposed"] = bool(d["internet_exposed"])
                d["meta"] = json.loads(d.pop("meta_json") or "{}")
                assets.append(d)
            relations = [dict(r) for r in rrows]
            return {"assets": assets, "relations": relations, "count": len(assets)}
        finally:
            c.close()


def ingest_job_assets(job: dict) -> dict:
    """Automatically extract & link Domains, IPs, Services, APIs, and Subdomains from any completed job."""
    pid = job.get("project_id") or "default"
    kind = job.get("kind") or ""
    res = job.get("result") or {}
    new_assets: List[dict] = []

    def _add(akind: str, name: str, crit: str = "medium", exposed: bool = True, meta: Optional[dict] = None) -> Optional[dict]:
        if not name:
            return None
        a = upsert_asset(pid, akind, name, crit, exposed, meta)
        if a["is_new"]:
            new_assets.append(a)
        return a

    if kind in ("web-scan", "api-audit"):
        tgt = res.get("target") or job.get("target") or ""
        if tgt:
            u = urlsplit(tgt if "://" in tgt else f"https://{tgt}")
            host = u.hostname or tgt
            exposed = host not in ("127.0.0.1", "localhost", "::1")
            dom = _add("domain", host, "high" if exposed else "low", exposed, {"url": tgt})
            app = _add("web_app" if kind == "web-scan" else "api", tgt, "high" if exposed else "medium", exposed,
                       {"findings_count": len(res.get("findings") or [])})
            if dom and app:
                link_assets(pid, dom["id"], app["id"], "hosts")

    elif kind == "network-scan":
        for h in (res.get("hosts") or []):
            ip = h.get("ip") or ""
            hn = h.get("hostname") or ""
            exposed = not (ip.startswith("127.") or ip.startswith("10.") or ip.startswith("192.168."))
            ip_a = _add("ip", ip, "high" if exposed else "medium", exposed, {"os_hint": h.get("os_hint", "")})
            if hn and ip_a:
                dom_a = _add("domain", hn, "high" if exposed else "medium", exposed)
                if dom_a:
                    link_assets(pid, dom_a["id"], ip_a["id"], "resolves_to")
            for p in (h.get("ports") or []):
                if p.get("state") != "open":
                    continue
                svc = f"{ip}:{p.get('port')}/{p.get('service') or 'tcp'}"
                svc_a = _add("service", svc, "high" if p.get("port") in (22, 445, 3389, 5432, 6379, 27017) else "medium",
                             exposed, {"port": p.get("port"), "service": p.get("service"), "version": p.get("version")})
                if ip_a and svc_a:
                    link_assets(pid, ip_a["id"], svc_a["id"], "exposes")

    elif kind == "dns-recon":
        dom_name = res.get("domain") or job.get("target") or ""
        dom_a = _add("domain", dom_name, "high", True, {"records": list((res.get("records") or {}).keys())})
        for ip in (res.get("records") or {}).get("A", []):
            ip_a = _add("ip", ip, "high", True)
            if dom_a and ip_a:
                link_assets(pid, dom_a["id"], ip_a["id"], "resolves_to")
        for sub in (res.get("subdomains") or []):
            sub_name = sub.get("subdomain") or ""
            sub_a = _add("subdomain", sub_name, "medium", True, {"ips": sub.get("ips", [])})
            if dom_a and sub_a:
                link_assets(pid, dom_a["id"], sub_a["id"], "owns_subdomain")
            for ip in (sub.get("ips") or []):
                ip_a = _add("ip", ip, "medium", True)
                if sub_a and ip_a:
                    link_assets(pid, sub_a["id"], ip_a["id"], "resolves_to")

    elif kind == "cloud-audit":
        provider = res.get("provider") or "cloud"
        _add("cloud", f"{provider}:{res.get('target') or 'audit'}", "high", True,
             {"findings": len(res.get("findings") or [])})

    elif kind == "container-audit":
        _add("container", res.get("target") or "container-audit", "high", False,
             {"sbom_components": len((res.get("sbom") or {}).get("components") or [])})

    return {"new_assets": new_assets, "new_count": len(new_assets)}
