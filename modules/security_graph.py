#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DARK Security Graph Engine (v4.0).

Builds a unified, multi-entity Security Graph connecting:
  - Internet Exposure, Domains, IP Addresses, Assets, Services
  - Users, Credentials, Vulnerabilities, Threat Indicators, Security Events

Capabilities:
  - Relationship Mapping & Graph Visualization payload (nodes/edges)
  - Risk Propagation across multi-hop paths
  - Attack Path Analysis (Entry -> Pivot -> Critical/Sensitive Target)
  - Historical Graph Diffing (added/removed nodes & edges across snapshots)
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT / "dark") not in sys.path:
    sys.path.insert(0, str(ROOT / "dark"))

import enterprise_db as edb  # noqa: E402
import intel_hub as ih  # noqa: E402

_SEV_SCORE = {"Critical": 95.0, "High": 75.0, "Medium": 50.0, "Low": 25.0, "Info": 5.0}


def build_security_graph(
    jobs: List[Dict[str, Any]],
    assets_list: Optional[List[Dict[str, Any]]] = None,
    iocs: Optional[List[Dict[str, Any]]] = None,
    project_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Construct the Security Graph with Risk Propagation & Attack Paths."""
    hub = ih.ingest_jobs_into_hub(jobs)
    nodes: Dict[str, Dict[str, Any]] = {}
    edges: Dict[Tuple[str, str, str], Dict[str, Any]] = {}

    def add_node(nid: str, ntype: str, label: str, risk: float = 0.0, meta: Optional[dict] = None):
        if nid not in nodes:
            nodes[nid] = {
                "id": nid,
                "type": ntype,
                "label": label,
                "base_risk": round(risk, 1),
                "propagated_risk": round(risk, 1),
                "meta": meta or {},
            }
        else:
            nodes[nid]["base_risk"] = max(nodes[nid]["base_risk"], round(risk, 1))
            nodes[nid]["propagated_risk"] = max(nodes[nid]["propagated_risk"], round(risk, 1))

    def add_edge(src: str, dst: str, rel: str):
        key = (src, dst, rel)
        if key not in edges:
            edges[key] = {"source": src, "target": dst, "relation": rel}

    add_node("exposure:internet", "internet_exposure", "Internet Exposure", risk=10.0)

    # Register assets from ASM inventory
    for a in (assets_list or []):
        aid = f"asset:{a.get('name')}"
        crit_risk = {"critical": 90.0, "high": 70.0, "medium": 45.0, "low": 20.0}.get(
            str(a.get("criticality") or "medium").lower(), 40.0
        )
        add_node(aid, str(a.get("kind") or "asset"), str(a.get("name")), risk=crit_risk, meta={"owner": a.get("owner", ""), "criticality": a.get("criticality", "medium")})
        if a.get("internet_exposed"):
            add_edge("exposure:internet", aid, "exposes")

    # Populate from Intelligence Hub assets & findings
    for a in hub.get("assets", []):
        host = a["asset"]
        aid = f"asset:{host}"
        add_node(aid, "asset", host, risk=float(a.get("asset_risk_score") or 0.0))
        if host not in ("127.0.0.1", "localhost"):
            add_edge("exposure:internet", aid, "exposes")
        for svc in a.get("services", []):
            sid = f"svc:{host}:{svc.get('port')}/{svc.get('service')}"
            add_node(sid, "service", f"{svc.get('port')}/{svc.get('service')}", risk=30.0, meta={"version": svc.get("version")})
            add_edge(aid, sid, "runs_service")

    for idx, f in enumerate(hub.get("findings", [])):
        host = f["asset"]
        aid = f"asset:{host}"
        add_node(aid, "asset", host, risk=float(f.get("risk_score") or 0.0))
        vid = f"vuln:{idx}:{f['vuln_type'][:40]}"
        v_risk = float(f.get("risk_score") or _SEV_SCORE.get(f["severity"], 40.0))
        add_node(vid, "vulnerability", f["vuln_type"], risk=v_risk, meta={"severity": f["severity"], "cwe": f.get("cwe", "")})
        add_edge(aid, vid, "has_vulnerability")

        # Link to Threat Events / Indicators if applicable
        if any(s in ("threat-hunt", "forensics", "monitor-demo", "monitor-pcap", "phishing-analyze") for s in f.get("sources", [])):
            ev_id = f"event:{idx}"
            add_node(ev_id, "security_event", f["vuln_type"], risk=v_risk)
            add_edge(vid, ev_id, "triggers_alert")

    # Link cracked credentials from HashBreaker jobs
    for j in jobs:
        if j.get("kind") == "hash-crack" and j.get("status") in ("done", "stopped"):
            for r in (j.get("result") or {}).get("results", []):
                if r.get("cracked"):
                    cid = f"cred:{r.get('used_algo')}:{r.get('hash')[:10]}"
                    add_node(cid, "credential", f"Weak/Cracked ({r.get('used_algo')})", risk=88.0)
                    for nid, n in list(nodes.items()):
                        if n["type"] == "asset":
                            add_edge(cid, nid, "compromises_access")

    # Link IOCs
    for ioc in (iocs or [])[:50]:
        iid = f"ioc:{ioc.get('value')}"
        add_node(iid, "threat_indicator", str(ioc.get("value")), risk=_SEV_SCORE.get(str(ioc.get("severity") or "Medium"), 50.0))

    # Risk Propagation (3-hop forward propagation with 0.85 decay)
    edge_list = list(edges.values())
    for _ in range(3):
        for e in edge_list:
            src_n = nodes.get(e["source"])
            dst_n = nodes.get(e["target"])
            if src_n and dst_n:
                prop = round(src_n["propagated_risk"] * 0.85, 1)
                if prop > dst_n["propagated_risk"]:
                    dst_n["propagated_risk"] = prop

    # Attack Path Analysis: BFS/DFS from Internet Exposure or Cracked Credential to high-risk Vulns/Assets
    adj: Dict[str, List[str]] = {}
    for e in edge_list:
        adj.setdefault(e["source"], []).append(e["target"])

    attack_paths: List[Dict[str, Any]] = []
    entry_nodes = [nid for nid, n in nodes.items() if n["type"] in ("internet_exposure", "credential")]
    for start in entry_nodes:
        stack: List[Tuple[str, List[str]]] = [(start, [start])]
        while stack and len(attack_paths) < 25:
            cur, path = stack.pop()
            if len(path) >= 3:
                leaf = nodes[cur]
                if leaf["propagated_risk"] >= 60.0:
                    attack_paths.append({
                        "entry": nodes[start]["label"],
                        "target": leaf["label"],
                        "path_nodes": [nodes[p]["label"] for p in path],
                        "hops": len(path) - 1,
                        "path_risk": leaf["propagated_risk"],
                    })
                    continue
            if len(path) >= 5:
                continue
            for nxt in adj.get(cur, []):
                if nxt not in path:
                    stack.append((nxt, path + [nxt]))

    attack_paths.sort(key=lambda p: -p["path_risk"])
    graph_obj = {
        "engine": "DARK Security Graph Engine v4.0",
        "project_id": project_id or "default",
        "generated_at": time.time(),
        "node_count": len(nodes),
        "edge_count": len(edge_list),
        "nodes": list(nodes.values()),
        "edges": edge_list,
        "attack_paths": attack_paths[:20],
    }
    return graph_obj


def diff_security_graphs(prev_graph: Dict[str, Any], curr_graph: Dict[str, Any]) -> Dict[str, Any]:
    """Compare two historical Security Graph snapshots."""
    prev_n = {n["id"] for n in (prev_graph.get("nodes") or [])}
    curr_n = {n["id"] for n in (curr_graph.get("nodes") or [])}
    prev_e = {(e["source"], e["target"], e["relation"]) for e in (prev_graph.get("edges") or [])}
    curr_e = {(e["source"], e["target"], e["relation"]) for e in (curr_graph.get("edges") or [])}
    return {
        "added_nodes": sorted(curr_n - prev_n),
        "removed_nodes": sorted(prev_n - curr_n),
        "added_edges": [list(x) for x in sorted(curr_e - prev_e)],
        "removed_edges": [list(x) for x in sorted(prev_e - curr_e)],
    }


def save_graph_snapshot(graph: Dict[str, Any]) -> Dict[str, Any]:
    """Persist graph snapshot in enterprise settings for historical change tracking."""
    pid = str(graph.get("project_id") or "default")
    key = f"security_graph_history:{pid}"
    hist = edb.get_setting(key, []) or []
    prev = hist[-1] if hist else None
    diff = diff_security_graphs(prev, graph) if prev else {
        "added_nodes": [n["id"] for n in graph.get("nodes", [])],
        "removed_nodes": [],
        "added_edges": [],
        "removed_edges": [],
    }
    snap = {
        "generated_at": graph["generated_at"],
        "node_count": graph["node_count"],
        "edge_count": graph["edge_count"],
        "nodes": graph["nodes"][:200],
        "edges": graph["edges"][:400],
    }
    hist = (hist + [snap])[-10:]
    edb.set_setting(key, hist)
    return {"history_count": len(hist), "diff_since_previous": diff}
