#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DARK Compliance Engine — OWASP ASVS, CIS Benchmarks, NIST CSF 2.0,
ISO/IEC 27001:2022, and PCI DSS v4.0 assessment from verified findings & evidence.

Default control status is 'Not Assessed'. A control NEVER receives 'Pass' from
empty findings or missing scans; 'Pass' requires explicit verified assessment
coverage for that control's domain with zero negative findings.
"""
from __future__ import annotations

from typing import Dict, Iterable, List, Optional, Set

FRAMEWORK_META: Dict[str, dict] = {
    "OWASP_ASVS": {"version": "4.0.3", "reference": "https://owasp.org/www-project-application-security-verification-standard/"},
    "CIS_BENCHMARKS": {"version": "v8 / Container-K8s-Cloud", "reference": "https://www.cisecurity.org/cis-benchmarks"},
    "NIST_CSF": {"version": "2.0", "reference": "https://www.nist.gov/cyberframework"},
    "ISO_27001": {"version": "ISO/IEC 27001:2022", "reference": "https://www.iso.org/standard/27001"},
    "PCI_DSS": {"version": "v4.0", "reference": "https://www.pcisecuritystandards.org/"},
}

FRAMEWORKS: Dict[str, List[dict]] = {
    "OWASP_ASVS": [
        {"id": "ASVS-V2", "domain": "auth", "reference": "OWASP ASVS 4.0.3 V2",
         "title": "Authentication Verification", "keywords": ["auth", "login", "password", "brute", "2fa", "totp", "credential", "jwt"],
         "evidence": "Authentication scan results, MFA configuration, password/hash audit"},
        {"id": "ASVS-V4", "domain": "access_control", "reference": "OWASP ASVS 4.0.3 V4",
         "title": "Access Control & Authorization", "keywords": ["idor", "bola", "cors", "access", "iam", "privilege", "role", "root"],
         "evidence": "API authz audit, IAM least-privilege checks, admin surface checks"},
        {"id": "ASVS-V5", "domain": "web_dast", "reference": "OWASP ASVS 4.0.3 V5",
         "title": "Validation, Sanitization & Encoding", "keywords": ["sql", "xss", "ssti", "cmdi", "lfi", "crlf", "injection", "eval"],
         "evidence": "DAST injection results + SAST input validation audit"},
        {"id": "ASVS-V9", "domain": "tls", "reference": "OWASP ASVS 4.0.3 V9",
         "title": "Communications & TLS Security", "keywords": ["tls", "ssl", "hsts", "certificate", "https", "http://"],
         "evidence": "TLS audit, HSTS headers, encrypted transport checks"},
        {"id": "ASVS-V14", "domain": "web_config", "reference": "OWASP ASVS 4.0.3 V14",
         "title": "Configuration & Security Headers", "keywords": ["header", "csp", "x-frame", "cookie", "banner", "sri", "exposed", ".env", ".git"],
         "evidence": "MisconfigAudit headers, cookie flags, secret exposure checks"},
    ],
    "CIS_BENCHMARKS": [
        {"id": "CIS-1", "domain": "cloud_iam", "reference": "CIS Controls v8 Control 5/6",
         "title": "Identity & Least Privilege IAM", "keywords": ["iam", "root", "owner", "privilege", "passrole", "wildcard"],
         "evidence": "Cloud IAM policy audit & Linux/Container non-root checks"},
        {"id": "CIS-2", "domain": "container", "reference": "CIS Docker/Kubernetes Benchmark",
         "title": "Container & Kubernetes Hardening", "keywords": ["container", "privileged", "hostnetwork", "latest", "capabilities", "dockerfile"],
         "evidence": "Dockerfile & Kubernetes manifest hardening audit"},
        {"id": "CIS-3", "domain": "network", "reference": "CIS Controls v8 Control 12/13",
         "title": "Network & Perimeter Exposure", "keywords": ["0.0.0.0/0", "ssh", "rdp", "redis", "mongodb", "port", "spf", "dmarc"],
         "evidence": "NetRecon port/service exposure & Cloud SG rules"},
    ],
    "NIST_CSF": [
        {"id": "GV.OC / ID.AM", "domain": "sbom_assets", "reference": "NIST CSF 2.0 ID.AM",
         "title": "Identify — Asset & Vulnerability Inventory", "keywords": ["cve", "sbom", "dependency", "outdated", "banner"],
         "evidence": "DARK Asset Inventory + SBOM + CVE feed matching"},
        {"id": "PR.AA / PR.DS", "domain": "tls", "reference": "NIST CSF 2.0 PR.AA/PR.DS",
         "title": "Protect — Access Control & Data Security", "keywords": ["tls", "https", "encryption", "secret", "key", "auth", "s3", "blob"],
         "evidence": "Cloud encryption, Credential Vault, TLS & secret scanning"},
        {"id": "DE.CM", "domain": "forensics_net", "reference": "NIST CSF 2.0 DE.CM",
         "title": "Detect — Continuous Monitoring & Forensics", "keywords": ["forensics", "brute", "ioc", "arp", "dns", "log"],
         "evidence": "NetSentry monitoring, Digital Forensics & Audit Trail"},
        {"id": "RS.MI", "domain": "remediation", "reference": "NIST CSF 2.0 RS.MI",
         "title": "Respond — Remediation & Retest Verification", "keywords": ["critical", "high", "kev"],
         "evidence": "Remediation Center tickets & verified retest history"},
    ],
    "ISO_27001": [
        {"id": "A.8.9", "domain": "web_config", "reference": "ISO/IEC 27001:2022 A.8.9",
         "title": "Configuration Management", "keywords": ["header", "misconfig", "container", "dockerfile", "s3", "storage"],
         "evidence": "Web/Cloud/Container configuration baseline audits"},
        {"id": "A.8.24", "domain": "tls", "reference": "ISO/IEC 27001:2022 A.8.24",
         "title": "Use of Cryptography", "keywords": ["tls", "ssl", "md5", "sha1", "weak hash", "jwt"],
         "evidence": "TLS audit, SAST crypto checks, HashBreaker password audit"},
        {"id": "A.8.25 / A.8.28", "domain": "sast", "reference": "ISO/IEC 27001:2022 A.8.25/A.8.28",
         "title": "Secure Development & Coding (SAST)", "keywords": ["sast", "sql", "xss", "pickle", "yaml.load", "eval", "strcpy"],
         "evidence": "DARK SAST source code & dependency audit reports"},
        {"id": "A.8.15", "domain": "forensics_net", "reference": "ISO/IEC 27001:2022 A.8.15",
         "title": "Logging & Audit Trail Integrity", "keywords": ["audit", "1102", "forensics", "log"],
         "evidence": "Tamper-evident SHA-256 Audit Trail & Log Forensics"},
    ],
    "PCI_DSS": [
        {"id": "PCI-Req-2", "domain": "network", "reference": "PCI DSS v4.0 Req 2",
         "title": "Secure Configurations & No Vendor Defaults", "keywords": ["default", "banner", "header", "redis", "mongodb", "unauth"],
         "evidence": "Default credential checks & service configuration scans"},
        {"id": "PCI-Req-4", "domain": "tls", "reference": "PCI DSS v4.0 Req 4",
         "title": "Protect Cardholder Data in Transit", "keywords": ["tls", "ssl", "hsts", "https", "cleartext", "http://"],
         "evidence": "TLS v1.2/1.3 enforcement & HSTS verification"},
        {"id": "PCI-Req-6", "domain": "sast", "reference": "PCI DSS v4.0 Req 6",
         "title": "Secure Systems & Software Development", "keywords": ["cve", "sql", "xss", "sast", "dependency", "jquery", "outdated"],
         "evidence": "SAST + DAST + SBOM/CVE vulnerability management"},
        {"id": "PCI-Req-10", "domain": "forensics_net", "reference": "PCI DSS v4.0 Req 10",
         "title": "Log & Monitor All Access", "keywords": ["audit", "1102", "forensics", "brute"],
         "evidence": "Immutable audit logs & authentication log monitoring"},
    ],
}

JOB_KIND_DOMAINS: Dict[str, Set[str]] = {
    "web-scan": {"web_dast", "web_config", "tls", "auth", "access_control"},
    "network-scan": {"network", "tls", "sbom_assets"},
    "dns-recon": {"network", "forensics_net"},
    "api-audit": {"access_control", "auth", "web_dast"},
    "cloud-audit": {"cloud_iam", "web_config", "tls"},
    "container-audit": {"container", "sbom_assets"},
    "sast-audit": {"sast", "web_dast", "sbom_assets"},
    "forensics": {"forensics_net"},
    "monitor-demo": {"forensics_net"},
    "monitor-pcap": {"forensics_net"},
    "monitor-live": {"forensics_net"},
    "hash-crack": {"auth", "tls"},
    "secrets-scan": {"sast", "web_config"},
    "ad-audit": {"auth", "access_control", "cloud_iam"},
    "identity-audit": {"auth", "access_control"},
}


def domains_from_jobs(jobs: List[dict]) -> tuple[Set[str], Set[str]]:
    """Derive successfully assessed domains vs failed assessment domains from jobs."""
    assessed: Set[str] = set()
    failed: Set[str] = set()
    for j in (jobs or []):
        kind = j.get("kind") or ""
        doms = JOB_KIND_DOMAINS.get(kind, set())
        st = j.get("status")
        if st == "done":
            assessed.update(doms)
        elif st in ("error", "timeout", "interrupted"):
            failed.update(doms)
    # A failed domain that never succeeded remains marked failed
    failed -= assessed
    return assessed, failed


def evaluate_compliance(
    findings: List[dict],
    framework: Optional[str] = None,
    assessed_domains: Optional[Iterable[str]] = None,
    failed_domains: Optional[Iterable[str]] = None,
    evidence_records: Optional[Dict[str, str]] = None,
) -> dict:
    fw_keys = [framework] if (framework and framework in FRAMEWORKS) else list(FRAMEWORKS.keys())
    results: Dict[str, dict] = {}
    assessed_set: Set[str] = {str(d).strip().lower() for d in (assessed_domains or []) if d}
    failed_set: Set[str] = {str(d).strip().lower() for d in (failed_domains or []) if d} - assessed_set
    ev_map = evidence_records or {}

    searchable = [
        (f, f"{f.get('vuln_type', '')} {f.get('detail', '')} {f.get('evidence', '')} {f.get('cwe', '')}".lower())
        for f in (findings or [])
    ]

    for fw in fw_keys:
        meta = FRAMEWORK_META.get(fw, {})
        controls_out: List[dict] = []
        passed_pts = 0.0
        assessed_count = 0
        not_assessed_count = 0
        failed_assessment_count = 0
        passed_count = 0
        fail_count = 0

        for ctrl in FRAMEWORKS[fw]:
            dom = str(ctrl.get("domain") or "general").lower()
            matched = []
            for orig, blob in searchable:
                if any(k in blob for k in ctrl["keywords"]):
                    matched.append({
                        "vuln_type": orig.get("vuln_type"),
                        "severity": orig.get("severity"),
                        "url": orig.get("url"),
                    })
            has_high = any(m["severity"] in ("Critical", "High") for m in matched)

            if dom in failed_set and not matched:
                status = "Failed Assessment"
                failed_assessment_count += 1
                ev_detail = ev_map.get(dom) or f"Assessment for domain '{dom}' failed or timed out; cannot assert compliance."
            elif matched:
                assessed_count += 1
                if has_high:
                    status = "Fail"
                    fail_count += 1
                else:
                    status = "Partial"
                    passed_pts += 0.5
                ev_detail = f"{len(matched)} finding(s) mapped from executed scan artifacts."
            elif dom in assessed_set:
                assessed_count += 1
                status = "Pass"
                passed_count += 1
                passed_pts += 1.0
                ev_detail = ev_map.get(dom) or f"Verified clean by completed '{dom}' assessment with 0 negative findings."
            else:
                status = "Not Assessed"
                not_assessed_count += 1
                ev_detail = "No completed assessment evidence covering this control domain."

            controls_out.append({
                "id": ctrl["id"],
                "title": ctrl["title"],
                "domain": dom,
                "reference": ctrl.get("reference") or meta.get("reference", ""),
                "status": status,
                "matched_findings_count": len(matched),
                "sample_findings": matched[:5],
                "required_evidence": ctrl["evidence"],
                "evidence_detail": ev_detail,
            })

        total = len(controls_out) or 1
        coverage_pct = round((assessed_count / total) * 100.0, 1)
        score_pct: Optional[float] = round((passed_pts / assessed_count) * 100.0, 1) if assessed_count > 0 else 0.0
        assessment_status = "Not Assessed" if assessed_count == 0 else ("Incomplete" if (not_assessed_count > 0 or failed_assessment_count > 0) else "Assessed")
        results[fw] = {
            "framework": fw,
            "framework_version": meta.get("version", ""),
            "reference": meta.get("reference", ""),
            "assessment_status": assessment_status,
            "score_pct": score_pct,
            "coverage_pct": coverage_pct,
            "assessed_controls": assessed_count,
            "not_assessed_controls": not_assessed_count,
            "failed_assessment_controls": failed_assessment_count,
            "passed_controls": passed_count,
            "failed_controls": fail_count,
            "controls": controls_out,
        }

    return {
        "frameworks": results,
        "findings_evaluated": len(findings or []),
        "assessed_domains": sorted(assessed_set),
        "failed_domains": sorted(failed_set),
    }
