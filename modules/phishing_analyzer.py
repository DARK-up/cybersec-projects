#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DARK Phishing & Email Threat Analyzer (v4.0).

Inspects raw .eml / email headers and body content for:
  - SPF / DKIM / DMARC Authentication-Results failures
  - From vs Reply-To / Return-Path spoofing mismatch
  - Punycode (xn--) & homograph / lookalike domain spoofing
  - Credential-harvesting urgency lures, risky executable attachments, and suspicious URLs
"""
from __future__ import annotations

import email
import re
from email import policy
from typing import Any, Dict, List
from urllib.parse import urlsplit

_RISKY_EXTS = (".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".iso", ".lnk", ".xlsm", ".docm")
_URGENCY_RX = re.compile(r"(?i)(?:verify your account|suspended within 24|urgent password reset|wire transfer|confirm your identity|invoice overdue)")
_URL_RX = re.compile(r"https?://[^\s\"'<>]+", re.I)


def _extract_domain(addr: str) -> str:
    m = re.search(r"@([A-Za-z0-9.\-]+)", addr or "")
    return m.group(1).lower() if m else ""


def analyze_email(raw_eml: str) -> Dict[str, Any]:
    """Analyze a raw RFC-5322 email or header/body snippet for phishing indicators."""
    msg = email.message_from_string(raw_eml or "", policy=policy.default)
    from_hdr = str(msg.get("From") or "")
    reply_to = str(msg.get("Reply-To") or "")
    return_path = str(msg.get("Return-Path") or "")
    auth_res = str(msg.get("Authentication-Results") or "")
    subject = str(msg.get("Subject") or "")

    from_dom = _extract_domain(from_hdr)
    reply_dom = _extract_domain(reply_to)
    rp_dom = _extract_domain(return_path)

    body_parts: List[str] = []
    attachments: List[str] = []
    if msg.is_multipart():
        for part in msg.walk():
            fn = part.get_filename()
            if fn:
                attachments.append(fn)
            ctype = part.get_content_type()
            if ctype in ("text/plain", "text/html"):
                try:
                    body_parts.append(part.get_content())
                except Exception:
                    pass
    else:
        try:
            body_parts.append(msg.get_content() if hasattr(msg, "get_content") else (raw_eml or ""))
        except Exception:
            body_parts.append(raw_eml or "")

    full_body = "\n".join(str(p) for p in body_parts)
    urls = sorted(set(_URL_RX.findall(full_body)))[:30]

    findings: List[Dict[str, Any]] = []

    if auth_res:
        for proto in ("spf", "dkim", "dmarc"):
            if re.search(rf"\b{proto}=(?:fail|softfail|none|temperror)\b", auth_res, re.I):
                findings.append({
                    "vuln_type": f"Phishing Indicator: {proto.upper()} Authentication Failure",
                    "severity": "High",
                    "url": from_dom or "email-header",
                    "parameter": proto,
                    "payload": auth_res[:120],
                    "evidence": f"Authentication-Results reported {proto} failure",
                    "detail": f"Sender failed {proto.upper()} verification, indicating potential domain spoofing.",
                    "cwe": "CWE-290",
                    "cvss_hint": 7.5,
                    "confidence": 0.90,
                    "remediation": "Quarantine message and enforce DMARC p=reject / quarantine policy.",
                })

    if from_dom and reply_dom and from_dom != reply_dom:
        findings.append({
            "vuln_type": "Phishing Indicator: From / Reply-To Domain Mismatch",
            "severity": "High",
            "url": from_dom,
            "parameter": "Reply-To",
            "payload": f"{from_dom} != {reply_dom}",
            "evidence": f"From domain '{from_dom}' differs from Reply-To domain '{reply_dom}'",
            "detail": "Replies are redirected to an external domain controlled by a potential attacker.",
            "cwe": "CWE-345",
            "cvss_hint": 7.4,
            "confidence": 0.88,
            "remediation": "Inspect sender legitimacy out-of-band before replying or clicking links.",
        })

    if from_dom and rp_dom and from_dom != rp_dom:
        findings.append({
            "vuln_type": "Phishing Indicator: Return-Path Alignment Mismatch",
            "severity": "Medium",
            "url": from_dom,
            "parameter": "Return-Path",
            "payload": f"{from_dom} != {rp_dom}",
            "evidence": f"Envelope Return-Path '{rp_dom}' does not align with From '{from_dom}'",
            "detail": "Unaligned Return-Path violates DMARC alignment and is common in spoofed emails.",
            "cwe": "CWE-290",
            "cvss_hint": 5.9,
            "confidence": 0.80,
            "remediation": "Enforce strict SPF/DMARC alignment on inbound mail gateways.",
        })

    for u in urls:
        host = (urlsplit(u).hostname or "").lower()
        if "xn--" in host or re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", host):
            findings.append({
                "vuln_type": "Phishing Indicator: Suspicious Punycode or Raw-IP URL",
                "severity": "High",
                "url": u,
                "parameter": "body-url",
                "payload": host,
                "evidence": f"Embedded URL uses IDN punycode or raw IP host '{host}'",
                "detail": "Lookalike IDN domains and raw IP links are frequently used in credential phishing.",
                "cwe": "CWE-451",
                "cvss_hint": 7.6,
                "confidence": 0.87,
                "remediation": "Block URL at proxy/email gateway and warn targeted recipients.",
            })

    for att in attachments:
        if att.lower().endswith(_RISKY_EXTS):
            findings.append({
                "vuln_type": "Phishing Indicator: High-Risk Attachment Type",
                "severity": "Critical",
                "url": att,
                "parameter": "attachment",
                "payload": att,
                "evidence": f"Risky executable/macro attachment '{att}'",
                "detail": "Attachment carries an active script, executable, or macro-enabled file extension.",
                "cwe": "CWE-434",
                "cvss_hint": 9.0,
                "confidence": 0.93,
                "remediation": "Strip/quarantine executable attachments at the email gateway and detonate in Malware Triage.",
            })

    if _URGENCY_RX.search(subject + "\n" + full_body):
        findings.append({
            "vuln_type": "Phishing Indicator: Social-Engineering Urgency Lure",
            "severity": "Medium",
            "url": from_dom or "email-body",
            "parameter": "content",
            "payload": subject[:80],
            "evidence": "Message contains classic credential/payment urgency lure phrases",
            "detail": "Social-engineering cues attempting to bypass user scrutiny.",
            "cwe": "CWE-451",
            "cvss_hint": 5.3,
            "confidence": 0.72,
            "remediation": "Flag email with external warning banner and verify request via trusted channel.",
        })

    risk_score = min(100, sum({"Critical": 40, "High": 25, "Medium": 15, "Low": 5}.get(f["severity"], 10) for f in findings))
    verdict = "Phishing / Malicious" if risk_score >= 50 else ("Suspicious" if risk_score >= 20 else "Low Risk")
    return {
        "tool": "DARK Phishing & Email Threat Analyzer",
        "from": from_hdr,
        "subject": subject,
        "urls": urls,
        "attachments": attachments,
        "risk_score": risk_score,
        "verdict": verdict,
        "findings": findings,
    }
