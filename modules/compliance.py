#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DARK Compliance Engine — OWASP ASVS, CIS Benchmarks, NIST CSF 2.0,
ISO/IEC 27001:2022, and PCI DSS v4.0 assessment from real findings & evidence.
"""
from __future__ import annotations

from typing import Dict, List

FRAMEWORKS: Dict[str, List[dict]] = {
    "OWASP_ASVS": [
        {"id": "ASVS-V2", "title": "Authentication Verification", "keywords": ["auth", "login", "password", "brute", "2fa", "totp", "credential", "jwt"],
         "evidence": "Authentication scan results, MFA configuration, password/hash audit"},
        {"id": "ASVS-V4", "title": "Access Control & Authorization", "keywords": ["idor", "bola", "cors", "access", "iam", "privilege", "role", "root"],
         "evidence": "API authz audit, IAM least-privilege checks, admin surface checks"},
        {"id": "ASVS-V5", "title": "Validation, Sanitization & Encoding", "keywords": ["sql", "xss", "ssti", "cmdi", "lfi", "crlf", "injection", "eval"],
         "evidence": "DAST injection results + SAST input validation audit"},
        {"id": "ASVS-V9", "title": "Communications & TLS Security", "keywords": ["tls", "ssl", "hsts", "certificate", "https", "http://"],
         "evidence": "TLS audit, HSTS headers, encrypted transport checks"},
        {"id": "ASVS-V14", "title": "Configuration & Security Headers", "keywords": ["header", "csp", "x-frame", "cookie", "banner", "sri", "exposed", ".env", ".git"],
         "evidence": "MisconfigAudit headers, cookie flags, secret exposure checks"},
    ],
    "CIS_BENCHMARKS": [
        {"id": "CIS-1", "title": "Identity & Least Privilege IAM", "keywords": ["iam", "root", "owner", "privilege", "passrole", "wildcard"],
         "evidence": "Cloud IAM policy audit & Linux/Container non-root checks"},
        {"id": "CIS-2", "title": "Container & Kubernetes Hardening", "keywords": ["container", "privileged", "hostnetwork", "latest", "capabilities", "dockerfile"],
         "evidence": "Dockerfile & Kubernetes manifest hardening audit"},
        {"id": "CIS-3", "title": "Network & Perimeter Exposure", "keywords": ["0.0.0.0/0", "ssh", "rdp", "redis", "mongodb", "port", "spf", "dmarc"],
         "evidence": "NetRecon port/service exposure & Cloud SG rules"},
    ],
    "NIST_CSF": [
        {"id": "GV.OC / ID.AM", "title": "Identify — Asset & Vulnerability Inventory", "keywords": ["cve", "sbom", "dependency", "outdated", "banner"],
         "evidence": "DARK Asset Inventory + SBOM + CVE feed matching"},
        {"id": "PR.AA / PR.DS", "title": "Protect — Access Control & Data Security", "keywords": ["tls", "https", "encryption", "secret", "key", "auth", "s3", "blob"],
         "evidence": "Cloud encryption, Credential Vault, TLS & secret scanning"},
        {"id": "DE.CM", "title": "Detect — Continuous Monitoring & Forensics", "keywords": ["forensics", "brute", "ioc", "arp", "dns", "log"],
         "evidence": "NetSentry monitoring, Digital Forensics & Audit Trail"},
        {"id": "RS.MI", "title": "Respond — Remediation & Retest Verification", "keywords": ["critical", "high", "kev"],
         "evidence": "Remediation Center tickets & verified retest history"},
    ],
    "ISO_27001": [
        {"id": "A.8.9", "title": "Configuration Management", "keywords": ["header", "misconfig", "container", "dockerfile", "s3", "storage"],
         "evidence": "Web/Cloud/Container configuration baseline audits"},
        {"id": "A.8.24", "title": "Use of Cryptography", "keywords": ["tls", "ssl", "md5", "sha1", "weak hash", "jwt"],
         "evidence": "TLS audit, SAST crypto checks, HashBreaker password audit"},
        {"id": "A.8.25 / A.8.28", "title": "Secure Development & Coding (SAST)", "keywords": ["sast", "sql", "xss", "pickle", "yaml.load", "eval", "strcpy"],
         "evidence": "DARK SAST source code & dependency audit reports"},
        {"id": "A.8.15", "title": "Logging & Audit Trail Integrity", "keywords": ["audit", "1102", "forensics", "log"],
         "evidence": "Tamper-evident SHA-256 Audit Trail & Log Forensics"},
    ],
    "PCI_DSS": [
        {"id": "PCI-Req-2", "title": "Secure Configurations & No Vendor Defaults", "keywords": ["default", "banner", "header", "redis", "mongodb", "unauth"],
         "evidence": "Default credential checks & service configuration scans"},
        {"id": "PCI-Req-4", "title": "Protect Cardholder Data in Transit", "keywords": ["tls", "ssl", "hsts", "https", "cleartext", "http://"],
         "evidence": "TLS v1.2/1.3 enforcement & HSTS verification"},
        {"id": "PCI-Req-6", "title": "Secure Systems & Software Development", "keywords": ["cve", "sql", "xss", "sast", "dependency", "jquery", "outdated"],
         "evidence": "SAST + DAST + SBOM/CVE vulnerability management"},
        {"id": "PCI-Req-10", "title": "Log & Monitor All Access", "keywords": ["audit", "1102", "forensics", "brute"],
         "evidence": "Immutable audit logs & authentication log monitoring"},
    ],
}


def evaluate_compliance(findings: List[dict], framework: Optional[str] = None) -> dict:
    fw_keys = [framework] if (framework and framework in FRAMEWORKS) else list(FRAMEWORKS.keys())
    results: Dict[str, dict] = {}

    searchable = [
        (f, f"{f.get('vuln_type', '')} {f.get('detail', '')} {f.get('evidence', '')} {f.get('cwe', '')}".lower())
        for f in (findings or [])
    ]

    for fw in fw_keys:
        controls_out: List[dict] = []
        passed = 0
        for ctrl in FRAMEWORKS[fw]:
            matched = []
            for orig, blob in searchable:
                if any(k in blob for k in ctrl["keywords"]):
                    matched.append({
                        "vuln_type": orig.get("vuln_type"),
                        "severity": orig.get("severity"),
                        "url": orig.get("url"),
                    })
            has_high = any(m["severity"] in ("Critical", "High") for m in matched)
            if not matched:
                status = "Pass"
                passed += 1
            elif has_high:
                status = "Fail"
            else:
                status = "Partial"
                passed += 0.5
            controls_out.append({
                "id": ctrl["id"],
                "title": ctrl["title"],
                "status": status,
                "matched_findings_count": len(matched),
                "sample_findings": matched[:5],
                "required_evidence": ctrl["evidence"],
            })
        total = len(controls_out) or 1
        results[fw] = {
            "framework": fw,
            "score_pct": round((passed / total) * 100.0, 1),
            "controls": controls_out,
        }

    return {"frameworks": results, "findings_evaluated": len(findings or [])}
