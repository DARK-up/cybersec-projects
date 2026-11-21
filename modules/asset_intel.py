#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DARK Advanced Attack Surface Management (ASM) — Multi-tenant Asset Inventory,
Relationship Graph (resolves_to, hosts, exposes, connects_to, depends_on,
owns_subdomain), Asset Change History, Exposure Timeline, Ownership & Export.
"""
from __future__ import annotations

import csv
import io
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

VALID_RELATIONS = ("resolves_to", "hosts", "exposes", "connects_to", "depends_on", "owns_subdomain")


def _record_history(c, tenant_id: str, project_id: str, asset_id: str,
                    asset_name: str, change_type: str, detail: str = "") -> None:
    c.execute(
        "INSERT INTO asset_history(tenant_id, project_id, asset_id, asset_name, change_type, detail, ts) "
        "VALUES(?,?,?,?,?,?,?)",
        (tenant_id or "default", project_id or "default", asset_id, asset_name, change_type, detail[:300], time.time()),
    )


def upsert_asset(
    project_id: str,
    kind: str,
    name: str,
    criticality: str = "medium",
    internet_exposed: bool = True,
    meta: Optional[dict] = None,
    tenant_id: Optional[str] = None,
    owner: str = "",
    tags: Optional[List[str]] = None,
    business_context: str = "",
) -> dict:
    name = (name or "").strip()
    if not name:
        raise ValueError("Asset name required")
    tid = (tenant_id or edb.get_current_tenant() or "default").strip() or "default"
    kind = (kind or "host").strip().lower()
    crit = criticality if criticality in ("critical", "high", "medium", "low") else "medium"
    now = time.time()
    aid = uuid.uuid5(uuid.NAMESPACE_DNS, f"{tid}:{project_id}:{kind}:{name.lower()}").hex[:12]
    meta_str = json.dumps(meta or {}, ensure_ascii=False)
    tags_str = json.dumps(tags or [], ensure_ascii=False)
    is_new = False
    changed = False

    with edb._DB_LOCK:
        c = edb._conn()
        try:
            existing = c.execute(
                "SELECT * FROM assets WHERE id=? OR (project_id=? AND kind=? AND LOWER(name)=LOWER(?))",
                (aid, project_id or "default", kind, name),
            ).fetchone()
            if existing:
                aid = existing["id"]
                old_meta = {}
                try:
                    old_meta = json.loads(existing["meta_json"] or "{}")
                except Exception:
                    pass
                merged = dict(old_meta)
                merged.update(meta or {})
                if merged != old_meta or existing["status"] == "disappeared":
                    changed = True
                    _record_history(c, tid, project_id, aid, name, "changed",
                                    f"Asset metadata or active status updated ({kind})")
                c.execute(
                    "UPDATE assets SET last_seen=?, status='active', tenant_id=?, meta_json=?, "
                    "owner=CASE WHEN ?!='' THEN ? ELSE owner END, "
                    "business_context=CASE WHEN ?!='' THEN ? ELSE business_context END WHERE id=?",
                    (now, tid, json.dumps(merged, ensure_ascii=False), owner, owner[:80],
                     business_context, business_context[:240], aid),
                )
            else:
                is_new = True
                c.execute(
                    "INSERT INTO assets(id, tenant_id, project_id, kind, name, criticality, internet_exposed, "
                    "status, owner, tags_json, business_context, meta_json, first_seen, last_seen) "
                    "VALUES(?,?,?,?,?,?,?,'active',?,?,?,?,?,?)",
                    (aid, tid, project_id or "default", kind, name, crit, 1 if internet_exposed else 0,
                     owner[:80], tags_str, business_context[:240], meta_str, now, now),
                )
                _record_history(c, tid, project_id, aid, name, "discovered",
                                f"New {kind} asset discovered (exposed={internet_exposed})")
            c.commit()
        finally:
            c.close()
    return {
        "id": aid, "tenant_id": tid, "project_id": project_id or "default",
        "kind": kind, "name": name, "criticality": crit,
        "internet_exposed": bool(internet_exposed), "status": "active",
        "is_new": is_new, "changed": changed, "last_seen": now,
    }


def link_assets(
    a1: str,
    a2: str,
    a3: str,
    a4: str = "connects_to",
    tenant_id: Optional[str] = None,
) -> dict:
    """Supports both link_assets(project_id, src_id, dst_id, relation) and link_assets(src_id, dst_id, relation)."""
    if a3 in VALID_RELATIONS or a4 == "connects_to" and a3 not in VALID_RELATIONS and len(a1) == 12:
        project_id, src_id, dst_id, relation = "default", a1, a2, a3
    else:
        project_id, src_id, dst_id, relation = a1, a2, a3, a4
    if not src_id or not dst_id or src_id == dst_id:
        raise ValueError("Distinct source and target assets required")
    tid = (tenant_id or edb.get_current_tenant() or "default").strip() or "default"
    rel = relation if relation in VALID_RELATIONS else "connects_to"
    rid = uuid.uuid5(uuid.NAMESPACE_DNS, f"{tid}:{project_id}:{src_id}:{dst_id}:{rel}").hex[:12]
    with edb._DB_LOCK:
        c = edb._conn()
        try:
            c.execute(
                "INSERT INTO asset_relations(id, tenant_id, project_id, src_asset_id, dst_asset_id, relation, created_at) "
                "VALUES(?,?,?,?,?,?,?) "
                "ON CONFLICT(project_id, src_asset_id, dst_asset_id, relation) DO UPDATE SET tenant_id=excluded.tenant_id",
                (rid, tid, project_id or "default", src_id, dst_id, rel, time.time()),
            )
            c.commit()
        finally:
            c.close()
    return {"id": rid, "src_asset_id": src_id, "dst_asset_id": dst_id, "relation": rel}


def mark_disappeared_assets(project_id: str, kind: str, active_names: List[str], tenant_id: Optional[str] = None) -> int:
    """Detect assets of a given kind that were previously active but vanished in the latest scan."""
    tid = (tenant_id or edb.get_current_tenant() or "default").strip() or "default"
    active_low = {n.strip().lower() for n in active_names if n}
    disappeared = 0
    with edb._DB_LOCK:
        c = edb._conn()
        try:
            rows = c.execute(
                "SELECT id, name FROM assets WHERE tenant_id=? AND project_id=? AND kind=? AND status='active'",
                (tid, project_id or "default", kind),
            ).fetchall()
            for r in rows:
                if r["name"].lower() not in active_low:
                    c.execute("UPDATE assets SET status='disappeared' WHERE id=?", (r["id"],))
                    _record_history(c, tid, project_id, r["id"], r["name"], "disappeared",
                                    f"Asset no longer observed in latest {kind} sweep")
                    disappeared += 1
            c.commit()
        finally:
            c.close()
    return disappeared


def update_asset_meta(
    asset_id: str,
    criticality: Optional[str] = None,
    internet_exposed: Optional[bool] = None,
    owner: Optional[str] = None,
    tags: Optional[List[str]] = None,
    business_context: Optional[str] = None,
    tenant_id: Optional[str] = None,
) -> bool:
    tid = (tenant_id or edb.get_current_tenant() or "default").strip() or "default"
    with edb._DB_LOCK:
        c = edb._conn()
        try:
            row = c.execute("SELECT * FROM assets WHERE id=? AND tenant_id=?", (asset_id, tid)).fetchone()
            if not row:
                return False
            if criticality in ("critical", "high", "medium", "low"):
                c.execute("UPDATE assets SET criticality=? WHERE id=?", (criticality, asset_id))
            if internet_exposed is not None:
                c.execute("UPDATE assets SET internet_exposed=? WHERE id=?", (1 if internet_exposed else 0, asset_id))
            if owner is not None:
                c.execute("UPDATE assets SET owner=? WHERE id=?", (owner[:80], asset_id))
            if tags is not None:
                c.execute("UPDATE assets SET tags_json=? WHERE id=?", (json.dumps(tags), asset_id))
            if business_context is not None:
                c.execute("UPDATE assets SET business_context=? WHERE id=?", (business_context[:240], asset_id))
            _record_history(c, tid, row["project_id"], asset_id, row["name"], "updated", "Asset context/criticality updated")
            c.commit()
            return True
        finally:
            c.close()


def list_assets(
    project_id: Optional[str] = None,
    tenant_id: Optional[str] = None,
    kind: Optional[str] = None,
    criticality: Optional[str] = None,
    q: Optional[str] = None,
    exposed: Optional[bool] = None,
    owner: Optional[str] = None,
    tag: Optional[str] = None,
    status: Optional[str] = None,
) -> dict:
    tid = (tenant_id or edb.get_current_tenant() or "default").strip() or "default"
    with edb._DB_LOCK:
        c = edb._conn()
        try:
            sql = "SELECT * FROM assets WHERE tenant_id=?"
            args: list = [tid]
            if project_id:
                sql += " AND project_id=?"
                args.append(project_id)
            if kind:
                sql += " AND kind=?"
                args.append(kind.lower())
            if criticality:
                sql += " AND criticality=?"
                args.append(criticality.lower())
            if exposed is not None:
                sql += " AND internet_exposed=?"
                args.append(1 if exposed else 0)
            if owner:
                sql += " AND LOWER(owner)=LOWER(?)"
                args.append(owner.strip())
            if status:
                sql += " AND status=?"
                args.append(status.strip())
            sql += " ORDER BY last_seen DESC"
            arows = c.execute(sql, args).fetchall()

            rsql = "SELECT * FROM asset_relations WHERE tenant_id=?"
            rargs: list = [tid]
            if project_id:
                rsql += " AND project_id=?"
                rargs.append(project_id)
            rrows = c.execute(rsql, rargs).fetchall()

            hsql = "SELECT * FROM asset_history WHERE tenant_id=?"
            hargs: list = [tid]
            if project_id:
                hsql += " AND project_id=?"
                hargs.append(project_id)
            hsql += " ORDER BY ts DESC LIMIT 100"
            hrows = c.execute(hsql, hargs).fetchall()

            assets = []
            ql = (q or "").strip().lower()
            for r in arows:
                d = dict(r)
                d["internet_exposed"] = bool(d["internet_exposed"])
                d["meta"] = json.loads(d.pop("meta_json") or "{}")
                d["tags"] = json.loads(d.pop("tags_json") or "[]")
                if ql and ql not in f"{d['name']} {d['kind']} {d.get('owner','')} {d.get('business_context','')}".lower():
                    continue
                assets.append(d)
            relations = [dict(r) for r in rrows]
            history = [dict(r) for r in hrows]
            exposed_unowned = [a for a in assets if a["internet_exposed"] and not a.get("owner")]
            return {
                "tenant_id": tid,
                "assets": assets,
                "relations": relations,
                "history": history,
                "exposed_unowned_count": len(exposed_unowned),
                "count": len(assets),
            }
        finally:
            c.close()


def build_attack_surface_graph(
    project_id: Optional[str] = None,
    tenant_id: Optional[str] = None,
    findings: Optional[List[dict]] = None,
) -> dict:
    """Return node/edge graph model linking Assets, Relations, and Vulnerability counts."""
    data = list_assets(project_id=project_id, tenant_id=tenant_id)
    vuln_counts: Dict[str, int] = {}
    crit_counts: Dict[str, int] = {}
    for f in (findings or []):
        u = str(f.get("url") or "")
        host = (urlsplit(u).hostname or u).lower()
        for key in (u.lower(), host):
            if key:
                vuln_counts[key] = vuln_counts.get(key, 0) + 1
                if str(f.get("severity") or "").title() in ("Critical", "High"):
                    crit_counts[key] = crit_counts.get(key, 0) + 1

    nodes = []
    node_ids = set()
    for a in data["assets"]:
        nm_low = a["name"].lower()
        host_part = (urlsplit(nm_low).hostname or nm_low.split(":")[0]).lower()
        vc = vuln_counts.get(nm_low, 0) or vuln_counts.get(host_part, 0)
        cc = crit_counts.get(nm_low, 0) or crit_counts.get(host_part, 0)
        nodes.append({
            "id": a["id"],
            "label": a["name"],
            "kind": a["kind"],
            "criticality": a["criticality"],
            "exposed": a["internet_exposed"],
            "status": a.get("status", "active"),
            "vulns": vc,
            "critical_high_vulns": cc,
        })
        node_ids.add(a["id"])

    edges = [
        {
            "from": r["src_asset_id"], "to": r["dst_asset_id"], "label": r["relation"],
            "source": r["src_asset_id"], "target": r["dst_asset_id"], "relation": r["relation"],
        }
        for r in data["relations"]
        if r["src_asset_id"] in node_ids and r["dst_asset_id"] in node_ids
    ]
    return {"nodes": nodes, "edges": edges, "history": data["history"][:30]}


def export_assets_csv(project_id: Optional[str] = None, tenant_id: Optional[str] = None) -> str:
    data = list_assets(project_id=project_id, tenant_id=tenant_id)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["id", "tenant_id", "project_id", "kind", "name", "criticality",
                "internet_exposed", "status", "owner", "tags", "business_context", "first_seen", "last_seen"])
    for a in data["assets"]:
        w.writerow([
            a["id"], a["tenant_id"], a["project_id"], a["kind"], a["name"], a["criticality"],
            a["internet_exposed"], a.get("status", "active"), a.get("owner", ""),
            "|".join(a.get("tags") or []), a.get("business_context", ""), a["first_seen"], a["last_seen"],
        ])
    return buf.getvalue()


def ingest_job_assets(job: dict) -> dict:
    """Extract & link Domains, Subdomains, IPs, Services, Web Apps, APIs, Cloud & Containers."""
    pid = job.get("project_id") or "default"
    tid = job.get("tenant_id") or edb.get_current_tenant() or "default"
    kind = job.get("kind") or ""
    res = job.get("result") or {}
    new_assets: List[dict] = []

    def _add(akind: str, name: str, crit: str = "medium", exposed: bool = True, meta: Optional[dict] = None) -> Optional[dict]:
        if not name:
            return None
        a = upsert_asset(pid, akind, name, crit, exposed, meta, tenant_id=tid)
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
                link_assets(pid, dom["id"], app["id"], "hosts", tenant_id=tid)
            # Connect OpenAPI / Inventory sub-endpoints if discovered
            for ep in (res.get("inventory") or [])[:15]:
                ep_name = f"{ep.get('method', 'GET')} {tgt.rstrip('/')}{ep.get('path', '')}"
                ep_a = _add("api", ep_name, "medium", exposed, ep)
                if app and ep_a:
                    link_assets(pid, app["id"], ep_a["id"], "exposes", tenant_id=tid)

    elif kind == "network-scan":
        seen_services: List[str] = []
        hosts_list = res.get("hosts") or (res.get("report") or {}).get("hosts") or []
        for h in hosts_list:
            ip = h.get("ip") or h.get("host") or ""
            hn = h.get("hostname") or ""
            exposed = not (ip.startswith("127.") or ip.startswith("10.") or ip.startswith("192.168."))
            ip_a = _add("ip", ip, "high" if exposed else "medium", exposed, {"os_hint": h.get("os_hint", "")})
            if hn and ip_a:
                dom_a = _add("domain", hn, "high" if exposed else "medium", exposed)
                if dom_a:
                    link_assets(pid, dom_a["id"], ip_a["id"], "resolves_to", tenant_id=tid)
            ports = h.get("open_ports") or h.get("ports") or []
            for p in ports:
                if p.get("state", "open") != "open":
                    continue
                svc = f"{ip}:{p.get('port')}/{p.get('service') or 'tcp'}"
                seen_services.append(svc)
                svc_a = _add("service", svc, "high" if p.get("port") in (22, 445, 3389, 5432, 6379, 27017) else "medium",
                             exposed, {"port": p.get("port"), "service": p.get("service"), "version": p.get("version")})
                if ip_a and svc_a:
                    link_assets(pid, ip_a["id"], svc_a["id"], "exposes", tenant_id=tid)
        if seen_services:
            mark_disappeared_assets(pid, "service", seen_services, tenant_id=tid)

    elif kind == "dns-recon":
        dom_name = res.get("domain") or job.get("target") or ""
        dom_a = _add("domain", dom_name, "high", True, {"records": list((res.get("records") or {}).keys())})
        for ip in (res.get("records") or {}).get("A", []):
            ip_a = _add("ip", ip, "high", True)
            if dom_a and ip_a:
                link_assets(pid, dom_a["id"], ip_a["id"], "resolves_to", tenant_id=tid)
        for sub in (res.get("subdomains") or []):
            sub_name = sub.get("host") or sub.get("subdomain") or ""
            sub_a = _add("subdomain", sub_name, "medium", True, {"ips": sub.get("ips", [])})
            if dom_a and sub_a:
                link_assets(pid, dom_a["id"], sub_a["id"], "owns_subdomain", tenant_id=tid)
            for ip in (sub.get("ips") or []):
                ip_a = _add("ip", ip, "medium", True)
                if sub_a and ip_a:
                    link_assets(pid, sub_a["id"], ip_a["id"], "resolves_to", tenant_id=tid)

    elif kind == "cloud-audit":
        provider = res.get("provider") or "cloud"
        _add("cloud", f"{provider}:{res.get('target') or 'audit'}", "high", True,
             {"findings": len(res.get("findings") or [])})

    elif kind == "container-audit":
        cont_a = _add("container", res.get("target") or "container-audit", "high", False,
                      {"sbom_components": len((res.get("sbom") or {}).get("components") or [])})
        for comp_item in ((res.get("sbom") or {}).get("components") or [])[:15]:
            pkg_name = f"{comp_item.get('name')}@{comp_item.get('version')}"
            pkg_a = _add("dependency", pkg_name, "medium", False, comp_item)
            if cont_a and pkg_a:
                link_assets(pid, cont_a["id"], pkg_a["id"], "depends_on", tenant_id=tid)

    return {"new_assets": new_assets, "new_count": len(new_assets)}
