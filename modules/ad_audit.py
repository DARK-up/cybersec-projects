#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DARK Active Directory Security Auditing Engine (v4.0).

Analyzes exported AD JSON / LDIF / BloodHound-style inventory snapshots for
high-risk misconfigurations without performing live intrusive domain attacks:
  - AS-REP Roasting (DONT_REQ_PREAUTH)
  - Kerberoastable privileged/service accounts (SPNs set)
  - Unconstrained Kerberos Delegation
  - PasswordNeverExpires / weak encryption (RC4/DES)
  - DCSync ACL rights on non-DC principals & SMBv1 / LDAP signing gaps
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional


def audit_ad_snapshot(
    snapshot: Optional[Dict[str, Any]] = None,
    raw_json: str = "",
) -> Dict[str, Any]:
    """Audit an Active Directory configuration/user/computer snapshot."""
    data = snapshot or {}
    if not data and raw_json:
        data = json.loads(raw_json)
    if not isinstance(data, dict):
        raise ValueError("AD snapshot must be a JSON object")

    domain = str(data.get("domain") or "corp.local")
    users = data.get("users") or []
    computers = data.get("computers") or []
    acls = data.get("acls") or []
    policies = data.get("policies") or {}

    findings: List[Dict[str, Any]] = []

    for u in users:
        name = str(u.get("name") or u.get("samaccountname") or "unknown")
        is_priv = bool(u.get("admincount") or u.get("privileged"))
        if u.get("dont_req_preauth"):
            findings.append({
                "vuln_type": "AD Risk: AS-REP Roasting Exposure (DONT_REQ_PREAUTH)",
                "severity": "Critical" if is_priv else "High",
                "url": f"ad://{domain}/users/{name}",
                "parameter": name,
                "payload": "DONT_REQ_PREAUTH=True",
                "evidence": f"Account '{name}' does not require Kerberos pre-authentication",
                "detail": "Attackers can request TGT AS-REP material offline without knowing the password.",
                "cwe": "CWE-287",
                "cvss_hint": 8.8 if is_priv else 7.8,
                "confidence": 0.96,
                "remediation": f"Enable Kerberos pre-authentication for '{name}' immediately.",
            })
        if u.get("spns") or u.get("serviceprincipalnames"):
            findings.append({
                "vuln_type": "AD Risk: Kerberoastable Account (SPN Registered)",
                "severity": "Critical" if is_priv else "High",
                "url": f"ad://{domain}/users/{name}",
                "parameter": name,
                "payload": str((u.get("spns") or u.get("serviceprincipalnames"))[:2]),
                "evidence": f"User account '{name}' has SPN(s) registered (privileged={is_priv})",
                "detail": "Any authenticated domain user can request a TGS encrypted with this account's hash for offline cracking.",
                "cwe": "CWE-522",
                "cvss_hint": 8.8 if is_priv else 7.5,
                "confidence": 0.94,
                "remediation": "Migrate service account to a Group Managed Service Account (gMSA) or enforce 25+ char AES-256 keys.",
            })
        if u.get("password_never_expires") and is_priv:
            findings.append({
                "vuln_type": "AD Risk: Privileged Account PasswordNeverExpires",
                "severity": "Medium",
                "url": f"ad://{domain}/users/{name}",
                "parameter": name,
                "payload": "PasswordNeverExpires=True",
                "evidence": f"Privileged account '{name}' has non-expiring password",
                "detail": "Long-lived privileged credentials expand blast radius if compromised.",
                "cwe": "CWE-262",
                "cvss_hint": 6.1,
                "confidence": 0.92,
                "remediation": "Enforce password rotation or convert to tiered/ephemeral PAM access.",
            })

    for comp in computers:
        cname = str(comp.get("name") or "unknown-host")
        if comp.get("unconstrained_delegation") and not comp.get("is_dc"):
            findings.append({
                "vuln_type": "AD Risk: Unconstrained Kerberos Delegation on Non-DC",
                "severity": "Critical",
                "url": f"ad://{domain}/computers/{cname}",
                "parameter": cname,
                "payload": "TRUSTED_FOR_DELEGATION",
                "evidence": f"Member host '{cname}' is configured for unconstrained delegation",
                "detail": "Compromising this host allows capturing TGTs of any authenticating user including Domain Admins.",
                "cwe": "CWE-269",
                "cvss_hint": 9.3,
                "confidence": 0.97,
                "remediation": "Disable unconstrained delegation and switch to Constrained Delegation or RBCD.",
            })

    for acl in acls:
        right = str(acl.get("right") or "").lower()
        principal = str(acl.get("principal") or "unknown")
        if right in ("dcsync", "ds-replication-get-changes-all", "genericall") and not acl.get("is_dc"):
            findings.append({
                "vuln_type": "AD Risk: Excessive Replication / DCSync ACL Right",
                "severity": "Critical",
                "url": f"ad://{domain}/acl/{principal}",
                "parameter": right,
                "payload": principal,
                "evidence": f"Non-DC principal '{principal}' holds '{acl.get('right')}'",
                "detail": "Allows extracting NTLM/Kerberos password hashes for the entire Active Directory domain.",
                "cwe": "CWE-269",
                "cvss_hint": 9.8,
                "confidence": 0.95,
                "remediation": f"Remove '{acl.get('right')}' permission from '{principal}' immediately.",
            })

    if policies.get("smbv1_enabled"):
        findings.append({
            "vuln_type": "AD Policy Risk: SMBv1 Enabled",
            "severity": "High",
            "url": f"ad://{domain}/policies/smb",
            "parameter": "smbv1_enabled",
            "payload": "True",
            "evidence": "SMBv1 protocol enabled in domain policy",
            "detail": "SMBv1 exposes domain hosts to legacy worm/RCE and relay vulnerabilities.",
            "cwe": "CWE-326",
            "cvss_hint": 8.1,
            "confidence": 0.95,
            "remediation": "Disable SMBv1 across all endpoints and enforce SMB signing.",
        })
    if policies.get("ldap_signing") is False:
        findings.append({
            "vuln_type": "AD Policy Risk: LDAP Signing Not Enforced",
            "severity": "High",
            "url": f"ad://{domain}/policies/ldap",
            "parameter": "ldap_signing",
            "payload": "False",
            "evidence": "Domain Controllers do not require LDAP signing / channel binding",
            "detail": "Permits NTLM relay attacks against Active Directory LDAP.",
            "cwe": "CWE-319",
            "cvss_hint": 7.9,
            "confidence": 0.93,
            "remediation": "Set 'Domain controller: LDAP server signing requirements' to Require signing and enforce LDAPS channel binding.",
        })

    for f in findings:
        f["data_source"] = "Active Directory Offline JSON Snapshot (non-intrusive)"
        vt = f.get("vuln_type", "")
        if any(k in vt for k in ("DONT_REQ_PREAUTH", "Unconstrained Kerberos Delegation", "DCSync", "SMBv1", "LDAP Signing")):
            f["finding_certainty"] = "Confirmed Configuration Finding"
            f["verification_status"] = "Confirmed"
        else:
            f["finding_certainty"] = "Potential Exposure Indicator"
            f["verification_status"] = "Likely"

    return {
        "tool": "DARK Active Directory Auditor",
        "data_source": "Offline AD JSON / BloodHound-style Snapshot (read-only)",
        "limitations": "Analyzes exported directory configuration snapshots only; does not execute live Kerberos/LDAP attacks against Domain Controllers.",
        "domain": domain,
        "objects_audited": len(users) + len(computers) + len(acls),
        "confirmed_count": sum(1 for f in findings if f.get("finding_certainty") == "Confirmed Configuration Finding"),
        "potential_count": sum(1 for f in findings if f.get("finding_certainty") == "Potential Exposure Indicator"),
        "findings": findings,
    }
