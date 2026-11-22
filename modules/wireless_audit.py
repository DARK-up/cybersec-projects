#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DARK Wireless Security Assessment Engine (v4.0).

Performs authorized, passive configuration and access-point inventory assessment
for 802.11 networks:
  - Deprecated WEP / Open / WPA1-TKIP encryption
  - Missing Protected Management Frames (802.11w / PMF)
  - WPS PIN enabled (Brute-force / Pixie-Dust risk)
  - WPA2-PSK weak-passphrase / PMKID exposure without SAE (WPA3)
  - Potential Rogue / Evil-Twin SSID BSSID anomalies
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional


def audit_wireless_inventory(
    aps: Optional[List[Dict[str, Any]]] = None,
    raw_json: str = "",
) -> Dict[str, Any]:
    """Assess wireless AP configuration & observed beacon metadata passively."""
    items = aps if aps is not None else []
    if not items and raw_json:
        parsed = json.loads(raw_json)
        items = parsed.get("access_points", parsed) if isinstance(parsed, dict) else parsed
    if not isinstance(items, list):
        raise ValueError("Wireless inventory must be a list of access point records")

    findings: List[Dict[str, Any]] = []
    ssid_bssid_map: Dict[str, set] = {}

    for ap in items:
        ssid = str(ap.get("ssid") or "<hidden>")
        bssid = str(ap.get("bssid") or "00:00:00:00:00:00")
        enc = str(ap.get("encryption") or "OPEN").upper()
        pmf = bool(ap.get("pmf_enabled", False))
        wps = bool(ap.get("wps_enabled", False))
        psk_len = int(ap.get("psk_length", 16) or 0)
        is_corp = bool(ap.get("corporate", False))
        trusted_bssids = {x.lower() for x in (ap.get("trusted_bssids") or [])}

        ssid_bssid_map.setdefault(ssid, set()).add(bssid.lower())

        if enc in ("OPEN", "NONE"):
            findings.append({
                "vuln_type": "Wireless Risk: Unencrypted Open SSID",
                "severity": "High" if is_corp else "Medium",
                "url": f"wifi://{ssid}/{bssid}",
                "parameter": "encryption",
                "payload": enc,
                "evidence": f"SSID '{ssid}' ({bssid}) broadcasts without link-layer encryption",
                "detail": "Cleartext wireless frames can be passively sniffed on the air.",
                "cwe": "CWE-319",
                "cvss_hint": 7.4 if is_corp else 5.3,
                "confidence": 0.96,
                "remediation": "Enable WPA3-Enterprise (802.1X) or WPA3-OWE for guest isolation.",
            })
        elif "WEP" in enc or "TKIP" in enc:
            findings.append({
                "vuln_type": f"Wireless Risk: Broken Legacy Cipher ({enc})",
                "severity": "Critical",
                "url": f"wifi://{ssid}/{bssid}",
                "parameter": "encryption",
                "payload": enc,
                "evidence": f"SSID '{ssid}' uses broken {enc} encryption",
                "detail": "WEP and WPA1-TKIP keys can be recovered rapidly from captured traffic.",
                "cwe": "CWE-327",
                "cvss_hint": 9.0,
                "confidence": 0.98,
                "remediation": "Decommission WEP/TKIP immediately and migrate to AES-CCMP / GCMP (WPA2/WPA3).",
            })
        elif "PSK" in enc and is_corp:
            findings.append({
                "vuln_type": "Wireless Risk: Shared PSK Used on Corporate SSID",
                "severity": "High",
                "url": f"wifi://{ssid}/{bssid}",
                "parameter": "auth",
                "payload": enc,
                "evidence": f"Corporate SSID '{ssid}' relies on a shared PSK instead of 802.1X",
                "detail": "Shared PSKs prevent per-user revocation and enable offline PMKID/4-way handshake cracking.",
                "cwe": "CWE-287",
                "cvss_hint": 7.5,
                "confidence": 0.92,
                "remediation": "Upgrade corporate wireless to WPA3-Enterprise (EAP-TLS / 802.1X).",
            })

        if "PSK" in enc and psk_len and psk_len < 14:
            findings.append({
                "vuln_type": "Wireless Risk: Weak/Short WPA Passphrase",
                "severity": "High",
                "url": f"wifi://{ssid}/{bssid}",
                "parameter": "psk_length",
                "payload": f"len={psk_len}",
                "evidence": f"SSID '{ssid}' PSK length is {psk_len} (< 14 chars)",
                "detail": "Short WPA2-PSK passphrases are vulnerable to GPU PMKID/handshake cracking.",
                "cwe": "CWE-521",
                "cvss_hint": 7.4,
                "confidence": 0.90,
                "remediation": "Use a random 20+ character passphrase or migrate to WPA3-SAE / 802.1X.",
            })

        if wps:
            findings.append({
                "vuln_type": "Wireless Risk: WPS Enabled",
                "severity": "Medium",
                "url": f"wifi://{ssid}/{bssid}",
                "parameter": "wps",
                "payload": "enabled",
                "evidence": f"WPS is active on '{ssid}' ({bssid})",
                "detail": "WPS PIN mechanism is susceptible to offline Pixie-Dust and online brute-force attacks.",
                "cwe": "CWE-307",
                "cvss_hint": 6.5,
                "confidence": 0.93,
                "remediation": "Disable WPS on all wireless access points.",
            })

        if enc not in ("OPEN", "NONE") and not pmf:
            findings.append({
                "vuln_type": "Wireless Risk: Protected Management Frames (802.11w) Disabled",
                "severity": "Medium",
                "url": f"wifi://{ssid}/{bssid}",
                "parameter": "pmf",
                "payload": "disabled",
                "evidence": f"802.11w PMF not enforced on '{ssid}' ({bssid})",
                "detail": "Without PMF, clients can be deauthenticated to force handshake capture.",
                "cwe": "CWE-345",
                "cvss_hint": 5.4,
                "confidence": 0.88,
                "remediation": "Enable 802.11w Protected Management Frames (required in WPA3).",
            })

        if trusted_bssids and bssid.lower() not in trusted_bssids:
            findings.append({
                "vuln_type": "Wireless Risk: Unauthorized / Rogue BSSID Detected",
                "severity": "Critical",
                "url": f"wifi://{ssid}/{bssid}",
                "parameter": "bssid",
                "payload": bssid,
                "evidence": f"BSSID '{bssid}' advertising '{ssid}' is absent from trusted_bssids allowlist",
                "detail": "Indicates a potential Rogue AP or Evil-Twin interception attempt.",
                "cwe": "CWE-290",
                "cvss_hint": 8.9,
                "confidence": 0.94,
                "remediation": "Physically locate and disconnect the unauthorized BSSID; enable WIDS/WIPS containment.",
            })

    for f in findings:
        f["data_source"] = "Wireless Passive AP Inventory / Beacon Metadata JSON"
        vt = f.get("vuln_type", "")
        if any(k in vt for k in ("Open SSID", "Broken Legacy Cipher", "WPS Enabled", "Shared PSK")):
            f["finding_certainty"] = "Confirmed Configuration Finding"
            f["verification_status"] = "Confirmed"
        else:
            f["finding_certainty"] = "Potential Exposure Indicator"
            f["verification_status"] = "Likely"

    return {
        "tool": "DARK Wireless Security Assessment",
        "data_source": "Passive AP Configuration & Beacon Inventory JSON (no active RF deauth/injection)",
        "limitations": "Assesses supplied AP/beacon inventory records; does not perform active RF monitor-mode packet injection or live WPA handshake capture.",
        "aps_assessed": len(items),
        "unique_ssids": len(ssid_bssid_map),
        "confirmed_count": sum(1 for f in findings if f.get("finding_certainty") == "Confirmed Configuration Finding"),
        "potential_count": sum(1 for f in findings if f.get("finding_certainty") == "Potential Exposure Indicator"),
        "findings": findings,
    }
