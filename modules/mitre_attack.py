#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DARK Evidence-Based MITRE ATT&CK Mapping Engine (v4.0).

Maps verified findings and alerts to ATT&CK Tactics & Techniques ONLY when
concrete supporting evidence exists (never fabricates techniques for Info or
low-signal noise).
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

_RULES: List[Dict[str, Any]] = [
    {
        "keywords": ("sql injection", "sqli"),
        "tactic": "Initial Access",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
    },
    {
        "keywords": ("ssrf", "server-side request forgery"),
        "tactic": "Initial Access / Lateral Movement",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application (SSRF)",
    },
    {
        "keywords": ("command injection", "rce", "ssti", "template injection"),
        "tactic": "Execution",
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
    },
    {
        "keywords": ("xss", "cross-site scripting"),
        "tactic": "Execution / Initial Access",
        "technique_id": "T1059.007",
        "technique_name": "JavaScript Execution",
    },
    {
        "keywords": ("lfi", "path traversal", "xxe", "external entity"),
        "tactic": "Collection",
        "technique_id": "T1005",
        "technique_name": "Data from Local System",
    },
    {
        "keywords": ("port-scan", "port scan", "syn scan", "xmas"),
        "tactic": "Discovery",
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
    },
    {
        "keywords": ("arp-spoof", "arp spoof", "mitm"),
        "tactic": "Credential Access / Collection",
        "technique_id": "T1557.002",
        "technique_name": "Adversary-in-the-Middle: ARP Cache Poisoning",
    },
    {
        "keywords": ("dns-tunnel", "dns tunnel", "dga", "dns-burst"),
        "tactic": "Command and Control",
        "technique_id": "T1071.004",
        "technique_name": "Application Layer Protocol: DNS",
    },
    {
        "keywords": ("cleartext-cred", "credential", ".env", "secret", "password"),
        "tactic": "Credential Access",
        "technique_id": "T1552",
        "technique_name": "Unsecured Credentials",
    },
    {
        "keywords": ("wildcard iam", "iam", "rbac", "privilege"),
        "tactic": "Privilege Escalation",
        "technique_id": "T1078",
        "technique_name": "Valid Accounts / Over-Privileged IAM",
    },
    {
        "keywords": ("privileged", "docker socket", "container escape"),
        "tactic": "Privilege Escalation",
        "technique_id": "T1611",
        "technique_name": "Escape to Host",
    },
    {
        "keywords": ("1102", "audit log cleared", "log cleared"),
        "tactic": "Defense Evasion",
        "technique_id": "T1070.001",
        "technique_name": "Indicator Removal: Clear Windows Event Logs",
    },
]


def map_finding_to_attack(finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Return ATT&CK mapping when finding has severity > Info and concrete evidence."""
    sev = str(finding.get("severity") or "Info").title()
    ev = str(finding.get("evidence") or finding.get("detail") or "").strip()
    if sev == "Info" and not finding.get("category"):
        return None
    if len(ev) < 4:
        return None

    blob = " ".join([
        str(finding.get("vuln_type") or ""),
        str(finding.get("category") or ""),
        str(finding.get("detail") or ""),
    ]).lower()

    for rule in _RULES:
        if any(k in blob for k in rule["keywords"]):
            conf = float(finding.get("confidence") or 0.75)
            return {
                "tactic": rule["tactic"],
                "technique_id": rule["technique_id"],
                "technique_name": rule["technique_name"],
                "confidence": round(min(1.0, max(0.1, conf)), 2),
                "evidence_basis": ev[:180],
            }
    return None


def summarize_attack_matrix(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Aggregate observed MITRE ATT&CK techniques across findings/alerts."""
    by_tech: Dict[str, Dict[str, Any]] = {}
    tactics: Dict[str, int] = {}
    for f in findings:
        m = map_finding_to_attack(f)
        if not m:
            continue
        tid = m["technique_id"]
        rec = by_tech.setdefault(tid, {
            "technique_id": tid,
            "technique_name": m["technique_name"],
            "tactic": m["tactic"],
            "count": 0,
            "max_confidence": 0.0,
            "examples": [],
        })
        rec["count"] += 1
        rec["max_confidence"] = max(rec["max_confidence"], m["confidence"])
        if len(rec["examples"]) < 5:
            rec["examples"].append(f.get("url") or f.get("src") or f.get("vuln_type") or "")
        tactics[m["tactic"]] = tactics.get(m["tactic"], 0) + 1

    techniques = sorted(by_tech.values(), key=lambda x: (-x["count"], x["technique_id"]))
    return {
        "techniques_observed": len(techniques),
        "tactics": tactics,
        "techniques": techniques,
    }
