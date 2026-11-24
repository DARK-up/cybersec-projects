#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DARK Digital Forensics — Linux Auth Logs, Windows Event Logs,
Timeline Analysis, IOC Extraction & Matching, and NetSentry PCAP integration.
"""
from __future__ import annotations

import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(ROOT / "netsentry") not in sys.path:
    sys.path.append(str(ROOT / "netsentry"))

KNOWN_BAD_IOCS = {
    "198.51.100.44": "Simulated C2 Beacon IP",
    "203.0.113.99": "Known Scanner / Brute-Force Host",
    "evil-c2.example": "Simulated Malicious C2 Domain",
    "44d88612fea8a8f36de82e1278abb02f": "EICAR Test MD5 Hash",
}

WIN_EVENT_MAP = {
    "4625": ("Failed Logon Attempt", "Medium"),
    "4624": ("Successful Logon", "Info"),
    "4672": ("Special Privileges Assigned to New Logon", "Medium"),
    "4720": ("New User Account Created", "High"),
    "1102": ("Security Audit Log Cleared", "Critical"),
    "4688": ("New Process Created", "Info"),
    "7045": ("New Service Installed", "High"),
}


def analyze_forensics(
    log_text: str = "",
    log_type: str = "auto",
    custom_iocs: Optional[List[str]] = None,
    pcap_path: Optional[str] = None,
) -> dict:
    timeline: List[dict] = []
    findings: List[dict] = []
    iocs_found: Dict[str, List[str]] = {"ips": [], "domains": [], "hashes": [], "matched_bad": []}

    bad_set = dict(KNOWN_BAD_IOCS)
    for x in (custom_iocs or []):
        x = (x or "").strip()
        if x:
            bad_set[x.lower()] = "Operator-Supplied IOC"

    # 1. Optional PCAP bridge via NetSentry
    pcap_summary = None
    if pcap_path and Path(pcap_path).is_file():
        try:
            import netsentry as ns  # type: ignore
            pcap_summary = ns.analyze_pcap(pcap_path)
            for al in (pcap_summary.get("alerts") or []):
                findings.append({
                    "vuln_type": f"[Forensics:PCAP] {al.get('type', 'Network Alert')}",
                    "severity": str(al.get("severity", "Medium")).title(),
                    "url": pcap_path,
                    "parameter": "pcap",
                    "how_it_entered": "PCAP forensic packet analysis via NetSentry",
                    "evidence": al.get("detail", ""),
                    "remediation": "Isolate affected host and investigate network session.",
                    "cwe": "CWE-200",
                })
        except Exception as e:
            pcap_summary = {"error": str(e)}

    text = log_text or ""
    if text.strip():
        lines = text.splitlines()
        detected = log_type
        if detected == "auto":
            if "EventID" in text or '"event_id"' in text.lower() or "4625" in text:
                detected = "windows"
            elif "sshd" in text or "sudo:" in text or "Failed password" in text:
                detected = "linux_auth"
            else:
                detected = "generic"

        # Extract IOCs
        ips = sorted(set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)))
        hashes = sorted(set(re.findall(r'\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{64})\b', text)))
        domains = sorted(set(re.findall(r'\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|example|ru|cn|xyz)\b', text)))
        iocs_found["ips"] = ips[:50]
        iocs_found["hashes"] = hashes[:50]
        iocs_found["domains"] = domains[:50]
        for cand in ips + hashes + domains:
            if cand.lower() in bad_set:
                desc = bad_set[cand.lower()]
                iocs_found["matched_bad"].append(f"{cand} ({desc})")
                findings.append({
                    "vuln_type": f"[Forensics:IOC] Matched Threat Indicator ({cand})",
                    "severity": "Critical",
                    "url": cand,
                    "parameter": "ioc",
                    "how_it_entered": "Log IOC extraction and threat indicator correlation",
                    "evidence": f"Indicator {cand} matched: {desc}",
                    "remediation": "Block indicator at perimeter/EDR and perform host containment.",
                    "cwe": "CWE-506",
                })

        # Linux Auth log analysis
        failed_ips: Counter = Counter()
        for idx, ln in enumerate(lines, 1):
            m_ts = re.match(r'^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})', ln)
            ts_str = m_ts.group(1) if m_ts else f"line:{idx}"

            if "Failed password" in ln or "Invalid user" in ln:
                ipm = re.search(r'from\s+(\d+\.\d+\.\d+\.\d+)', ln)
                src_ip = ipm.group(1) if ipm else "unknown"
                failed_ips[src_ip] += 1
                timeline.append({"ts": ts_str, "source": "linux_auth", "event": "SSH Failed Auth", "detail": ln.strip()[:180]})
            elif "Accepted password" in ln or "Accepted publickey" in ln:
                if "for root" in ln:
                    findings.append({
                        "vuln_type": "[Forensics:Linux] Direct Root SSH Login Detected",
                        "severity": "High",
                        "url": "sshd",
                        "parameter": "root",
                        "how_it_entered": f"Auth log line {idx}",
                        "evidence": ln.strip()[:200],
                        "remediation": "Set PermitRootLogin no in /etc/ssh/sshd_config.",
                        "cwe": "CWE-250",
                    })
                timeline.append({"ts": ts_str, "source": "linux_auth", "event": "SSH Accepted Auth", "detail": ln.strip()[:180]})
            elif "sudo:" in ln and ("COMMAND=" in ln or "authentication failure" in ln):
                timeline.append({"ts": ts_str, "source": "linux_auth", "event": "Sudo Activity", "detail": ln.strip()[:180]})

            # Windows Event ID checks
            m_ev = re.search(r'(?:EventID[=:\s">]+|"event_id"\s*:\s*)(\d{4})', ln, re.I)
            if m_ev:
                eid = m_ev.group(1)
                label, sev = WIN_EVENT_MAP.get(eid, (f"Windows Event {eid}", "Info"))
                timeline.append({"ts": ts_str, "source": "windows_event", "event": f"Event {eid}: {label}", "detail": ln.strip()[:180]})
                if eid in ("1102", "4720", "7045"):
                    findings.append({
                        "vuln_type": f"[Forensics:Windows] Event {eid} — {label}",
                        "severity": sev,
                        "url": f"EventID:{eid}",
                        "parameter": "windows_security",
                        "how_it_entered": f"Windows Security/System Event Log line {idx}",
                        "evidence": ln.strip()[:200],
                        "remediation": "Investigate account/service creation or log tampering immediately.",
                        "cwe": "CWE-778",
                    })
                elif eid == "4625":
                    failed_ips["win-4625"] += 1

        for ip, cnt in failed_ips.items():
            if cnt >= 5:
                findings.append({
                    "vuln_type": f"[Forensics] Brute-Force Authentication Spike ({ip}: {cnt} failures)",
                    "severity": "High",
                    "url": ip,
                    "parameter": "auth",
                    "how_it_entered": "Authentication log frequency correlation",
                    "evidence": f"{cnt} failed authentication events attributed to {ip}",
                    "remediation": "Block offending source IP, enforce fail2ban/account lockout and MFA.",
                    "cwe": "CWE-307",
                })

    return {
        "target": pcap_path or "forensics-analysis",
        "timeline": timeline[:200],
        "timeline_count": len(timeline),
        "iocs": iocs_found,
        "pcap_summary": pcap_summary,
        "findings": findings,
        "stats": {"urls_crawled": len(timeline), "requests_sent": len(iocs_found["ips"]), "duration_s": 0.1},
    }
