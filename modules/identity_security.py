#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DARK Identity Security Module (v4.0).

Extends Active Directory Auditing into enterprise Identity Security:
  - Privileged Account Auditing & Privilege Exposure Analysis
  - Stale Account Detection (inactive > threshold days)
  - Password Policy Assessment
  - MFA Coverage % Assessment
  - Service Account Review (SPN, non-expiring, interactive logon risk)
  - Explicit Data Source + Confirmed vs Potential classification
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

import ad_audit as ada


def audit_identity_posture(
    snapshot: Optional[Dict[str, Any]] = None,
    raw_json: str = "",
    stale_days_threshold: int = 90,
) -> Dict[str, Any]:
    data = snapshot or {}
    if not data and raw_json:
        data = json.loads(raw_json)
    if not isinstance(data, dict):
        raise ValueError("Identity snapshot must be a JSON object")

    ad_res = ada.audit_ad_snapshot(snapshot=data)
    findings: List[Dict[str, Any]] = list(ad_res.get("findings") or [])

    users = data.get("users") or []
    policies = data.get("policies") or {}
    mfa_enabled_count = 0
    privileged_count = 0
    stale_accounts: List[str] = []
    service_accounts: List[str] = []

    for u in users:
        name = str(u.get("name") or u.get("samaccountname") or "unknown")
        enabled = bool(u.get("enabled", True))
        is_priv = bool(u.get("admincount") or u.get("privileged"))
        is_svc = bool(u.get("service_account") or u.get("spns") or u.get("serviceprincipalnames"))
        has_mfa = bool(u.get("mfa_enabled", False))
        inactive_days = int(u.get("inactive_days", 0) or 0)

        if has_mfa:
            mfa_enabled_count += 1
        if is_priv:
            privileged_count += 1
            if not has_mfa and enabled:
                findings.append({
                    "vuln_type": "Identity Risk: Privileged Account Without MFA",
                    "severity": "Critical",
                    "url": f"identity://users/{name}",
                    "parameter": "mfa_enabled",
                    "payload": "False",
                    "evidence": f"Privileged account '{name}' is enabled without MFA protection",
                    "detail": "Compromise of a single password grants direct administrative access.",
                    "cwe": "CWE-308",
                    "cvss_hint": 9.1,
                    "confidence": 0.95,
                    "data_source": "Identity Directory Snapshot JSON",
                    "finding_certainty": "Confirmed Configuration Finding",
                    "verification_status": "Confirmed",
                    "remediation": f"Enforce phishing-resistant MFA (FIDO2/WebAuthn) for '{name}'.",
                })

        if enabled and inactive_days >= stale_days_threshold:
            stale_accounts.append(name)
            findings.append({
                "vuln_type": "Identity Risk: Stale Enabled Account",
                "severity": "High" if is_priv else "Medium",
                "url": f"identity://users/{name}",
                "parameter": "inactive_days",
                "payload": str(inactive_days),
                "evidence": f"Account '{name}' inactive for {inactive_days} days (>= {stale_days_threshold}) while still enabled",
                "detail": "Dormant enabled accounts increase credential-stuffing and unnoticed lateral movement risk.",
                "cwe": "CWE-284",
                "cvss_hint": 7.5 if is_priv else 5.5,
                "confidence": 0.90,
                "data_source": "Identity Directory Snapshot JSON",
                "finding_certainty": "Confirmed Configuration Finding",
                "verification_status": "Confirmed",
                "remediation": f"Disable or deprovision stale account '{name}' after owner review.",
            })

        if is_svc:
            service_accounts.append(name)
            if u.get("interactive_logon_allowed"):
                findings.append({
                    "vuln_type": "Identity Risk: Service Account Permits Interactive Logon",
                    "severity": "High",
                    "url": f"identity://service-accounts/{name}",
                    "parameter": "interactive_logon_allowed",
                    "payload": "True",
                    "evidence": f"Service account '{name}' allows interactive console/RDP logon",
                    "detail": "Service accounts should be restricted from interactive sessions to prevent credential harvesting.",
                    "cwe": "CWE-250",
                    "cvss_hint": 7.4,
                    "confidence": 0.88,
                    "data_source": "Identity Directory Snapshot JSON",
                    "finding_certainty": "Potential Exposure Indicator",
                    "verification_status": "Likely",
                    "remediation": f"Restrict '{name}' via 'Deny log on locally' / 'Deny log on through Remote Desktop Services' GPO.",
                })

    min_pw = int(policies.get("min_password_length", 12) or 0)
    if min_pw and min_pw < 12:
        findings.append({
            "vuln_type": "Identity Policy Risk: Weak Minimum Password Length",
            "severity": "High",
            "url": "identity://policies/password",
            "parameter": "min_password_length",
            "payload": str(min_pw),
            "evidence": f"Domain password policy enforces only {min_pw} chars (< 12)",
            "detail": "Short domain passwords are vulnerable to password spraying and offline cracking.",
            "cwe": "CWE-521",
            "cvss_hint": 7.2,
            "confidence": 0.95,
            "data_source": "Identity Directory Snapshot JSON",
            "finding_certainty": "Confirmed Configuration Finding",
            "verification_status": "Confirmed",
            "remediation": "Raise minimum password length to >= 14 characters and enable banned-password filtering.",
        })

    mfa_cov = round((mfa_enabled_count / len(users)) * 100.0, 1) if users else 0.0
    return {
        "tool": "DARK Identity Security Module",
        "data_source": "Offline Identity & Directory Snapshot JSON (non-intrusive)",
        "limitations": "Evaluates supplied IdP/AD user & policy snapshot; live IdP API polling requires connector credentials.",
        "users_evaluated": len(users),
        "privileged_accounts": privileged_count,
        "stale_accounts": stale_accounts,
        "service_accounts": service_accounts,
        "mfa_coverage_pct": mfa_cov,
        "findings": findings,
    }
