#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DARK Proactive Threat Hunting Engine (v4.0).

Executes hypothesis-driven threat hunts across telemetry logs, IOC matches,
command-line strings, and network alert timelines, mapping verified detections
to MITRE ATT&CK techniques.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

HUNT_HYPOTHESES: List[Dict[str, Any]] = [
    {
        "id": "HUNT-01",
        "name": "Encoded / Obfuscated Command Execution",
        "pattern": re.compile(r"(?i)(?:powershell(?:\.exe)?\s+.*(?:-enc|-encodedcommand)|base64\s+-d\s*\|\s*(?:sh|bash)|certutil\s+-urlcache)"),
        "severity": "Critical",
        "tactic": "Execution / Defense Evasion",
        "technique_id": "T1059",
        "cwe": "CWE-94",
        "remediation": "Isolate host, inspect process tree & parent PID, and block unauthorized living-off-the-land binaries.",
    },
    {
        "id": "HUNT-02",
        "name": "Credential Dumping / LSASS / SAM Access",
        "pattern": re.compile(r"(?i)(?:mimikatz|sekurlsa|procdump.*lsass|/etc/shadow|ntds\.dit|vssadmin\s+create\s+shadow)"),
        "severity": "Critical",
        "tactic": "Credential Access",
        "technique_id": "T1003",
        "cwe": "CWE-522",
        "remediation": "Rotate affected privileged credentials immediately, enable Credential Guard/LSA Protection, and investigate lateral movement.",
    },
    {
        "id": "HUNT-03",
        "name": "Persistence via Cron / Scheduled Task / Run Key",
        "pattern": re.compile(r"(?i)(?:schtasks\s+/create|/etc/cron|crontab\s+-|CurrentVersion\\Run|systemctl\s+enable)"),
        "severity": "High",
        "tactic": "Persistence",
        "technique_id": "T1053",
        "cwe": "CWE-284",
        "remediation": "Audit newly registered scheduled tasks/cron entries and verify digital signatures of referenced binaries.",
    },
    {
        "id": "HUNT-04",
        "name": "Lateral Movement & Remote Execution",
        "pattern": re.compile(r"(?i)(?:psexec|wmic\s+/node:|winrs\s+-r:|ssh\s+.*-o\s*StrictHostKeyChecking=no|evil-winrm)"),
        "severity": "High",
        "tactic": "Lateral Movement",
        "technique_id": "T1021",
        "cwe": "CWE-284",
        "remediation": "Restrict administrative remote protocols via jump hosts, MFA, and network segmentation.",
    },
    {
        "id": "HUNT-05",
        "name": "Defense Evasion & Log Tampering",
        "pattern": re.compile(r"(?i)(?:wevtutil\s+cl|EventID=1102|history\s+-c|unset\s+HISTFILE|rm\s+-rf\s+/var/log)"),
        "severity": "Critical",
        "tactic": "Defense Evasion",
        "technique_id": "T1070",
        "cwe": "CWE-778",
        "remediation": "Forward logs to an immutable remote SIEM and investigate the initiating session immediately.",
    },
]


def run_threat_hunt(
    telemetry_text: str = "",
    events: Optional[List[Dict[str, Any]]] = None,
    custom_iocs: Optional[List[str]] = None,
    hypothesis_ids: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Run proactive hunting hypotheses against raw telemetry and structured events."""
    lines: List[str] = []
    if telemetry_text:
        lines.extend(ln.strip() for ln in telemetry_text.splitlines() if ln.strip())
    for ev in (events or []):
        lines.append(" ".join(f"{k}={v}" for k, v in ev.items()))

    active_hyps = [
        h for h in HUNT_HYPOTHESES
        if not hypothesis_ids or h["id"] in hypothesis_ids
    ]

    findings: List[Dict[str, Any]] = []
    ioc_hits: List[str] = []
    low_iocs = [i.strip().lower() for i in (custom_iocs or []) if i.strip()]

    for idx, line in enumerate(lines, 1):
        for h in active_hyps:
            m = h["pattern"].search(line)
            if m:
                findings.append({
                    "vuln_type": f"Threat Hunt [{h['id']}]: {h['name']}",
                    "severity": h["severity"],
                    "url": f"telemetry:line:{idx}",
                    "parameter": h["technique_id"],
                    "payload": h["id"],
                    "evidence": f"Matched '{m.group(0)[:60]}' in event #{idx}",
                    "detail": f"Proactive hunt hypothesis {h['id']} ({h['tactic']} / {h['technique_id']}) triggered.",
                    "cwe": h["cwe"],
                    "cvss_hint": 9.0 if h["severity"] == "Critical" else 7.8,
                    "confidence": 0.90,
                    "mitre_attack": {
                        "tactic": h["tactic"],
                        "technique_id": h["technique_id"],
                        "technique_name": h["name"],
                        "confidence": 0.90,
                    },
                    "remediation": h["remediation"],
                })
        low_line = line.lower()
        for ioc in low_iocs:
            if ioc in low_line:
                ioc_hits.append(ioc)
                findings.append({
                    "vuln_type": "Threat Hunt: Custom IOC Sighting",
                    "severity": "High",
                    "url": f"telemetry:line:{idx}",
                    "parameter": "ioc",
                    "payload": ioc,
                    "evidence": f"Observed IOC '{ioc}' in telemetry line #{idx}",
                    "detail": "Manual hunt indicator sighted in endpoint/network telemetry.",
                    "cwe": "CWE-200",
                    "cvss_hint": 8.0,
                    "confidence": 0.92,
                    "remediation": "Quarantine affected host/account and trace upstream origin of the indicator.",
                })

    return {
        "tool": "DARK Threat Hunting Engine",
        "events_analyzed": len(lines),
        "hypotheses_run": [h["id"] for h in active_hyps],
        "ioc_hits": sorted(set(ioc_hits)),
        "findings": findings,
    }
