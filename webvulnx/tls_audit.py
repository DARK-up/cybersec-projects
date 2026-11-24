#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""TLS / SSL & Certificate Compliance Auditor (Nessus SSL-family style).

Shared by WebVulnX (HTTPS targets) and NetRecon (TLS service ports such as
443, 8443, 993, 995, 465, 636). Performs safe, read-only handshake and
certificate inspection — never degrades or alters target state.
"""
from __future__ import annotations

import datetime
import ipaddress
import re
import socket
import ssl
from typing import Dict, List, Optional, Tuple


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _match_hostname(pattern: str, host: str) -> bool:
    pattern = pattern.lower().strip()
    host = host.lower().strip()
    if pattern == host:
        return True
    if pattern.startswith("*."):
        suffix = pattern[1:]  # ".example.com"
        return host.endswith(suffix) and "." not in host[:-len(suffix)]
    return False


def _parse_asn1_time(val: Optional[str]) -> Optional[datetime.datetime]:
    if not val:
        return None
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b  %d %H:%M:%S %Y %Z"):
        try:
            dt = datetime.datetime.strptime(val, fmt)
            return dt.replace(tzinfo=datetime.timezone.utc)
        except ValueError:
            continue
    return None


def _connect_tls(host: str, port: int, timeout: float,
                 verify: bool = True,
                 proto_ver: Optional[ssl.TLSVersion] = None) -> Tuple[Optional[dict], Optional[str]]:
    # verify=False is used strictly to inspect peer metadata after verified handshake fails; no credentials are sent.
    ctx = ssl.create_default_context() if verify else ssl._create_unverified_context()  # nosemgrep: python.lang.security.unverified-ssl-context.unverified-ssl-context
    if proto_ver is not None and hasattr(ssl, "TLSVersion"):
        try:
            ctx.minimum_version = proto_ver
            ctx.maximum_version = proto_ver
        except Exception:
            return None, "unsupported_local_tls_version"
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sni = None if _is_ip(host) else host
            with ctx.wrap_socket(sock, server_hostname=sni) as ssock:
                cert = ssock.getpeercert() or {}
                cipher = ssock.cipher()
                version = ssock.version()
                der = ssock.getpeercert(binary_form=True)
                return {
                    "cert": cert,
                    "cipher": cipher,
                    "version": version,
                    "der_len": len(der) if der else 0,
                }, None
    except ssl.SSLCertVerificationError as e:
        return None, f"verify_error:{e.verify_message or e}"
    except ssl.SSLError as e:
        return None, f"ssl_error:{e.reason or e}"
    except OSError as e:
        return None, f"net_error:{e}"


def audit_tls(host: str, port: int = 443, timeout: float = 5.0,
              hsts_header: Optional[str] = None,
              check_deprecated: bool = True) -> Tuple[List[dict], dict]:
    """Run a non-destructive Nessus-style TLS/SSL & certificate audit.

    Returns (findings_dicts, tls_summary_dict).
    """
    findings: List[dict] = []
    summary: Dict[str, object] = {
        "host": host, "port": port, "reachable": False,
        "protocol": None, "cipher": None, "subject": None,
        "issuer": None, "not_after": None, "sans": [],
    }
    target_label = f"https://{host}" if port == 443 else f"{host}:{port}"

    verified_info, verify_err = _connect_tls(host, port, timeout, verify=True)
    raw_info = verified_info
    if raw_info is None:
        raw_info, raw_err = _connect_tls(host, port, timeout, verify=False)
        if raw_info is None:
            return findings, summary

    summary["reachable"] = True
    summary["protocol"] = raw_info.get("version")
    cipher_tuple = raw_info.get("cipher")
    if cipher_tuple:
        summary["cipher"] = f"{cipher_tuple[0]} ({cipher_tuple[2]} bits)"

    cert = raw_info.get("cert") or {}
    # Note: unverified sockets in Python return an empty getpeercert() dict
    # unless a CA file is loaded; verified_info always has parsed fields.
    if verify_err:
        err_low = verify_err.lower()
        if "self-signed" in err_low or "self signed" in err_low or "unable to get local issuer" in err_low:
            findings.append({
                "plugin_id": "DARK-SSL-1001",
                "vuln_type": "TLS Untrusted / Self-Signed Certificate",
                "severity": "Medium",
                "url": target_label,
                "parameter": f"tcp/{port}",
                "evidence": verify_err[:180],
                "detail": "The TLS certificate is self-signed or lacks a trusted chain, "
                          "exposing clients to man-in-the-middle interception.",
                "cwe": "CWE-295",
                "cvss_hint": 5.9,
            })
        elif "expired" in err_low:
            findings.append({
                "plugin_id": "DARK-SSL-1002",
                "vuln_type": "TLS Certificate Expired",
                "severity": "High",
                "url": target_label,
                "parameter": f"tcp/{port}",
                "evidence": verify_err[:180],
                "detail": "The server presents an expired TLS certificate.",
                "cwe": "CWE-295",
                "cvss_hint": 7.4,
            })
        elif "hostname" in err_low or "mismatch" in err_low or "ip address" in err_low:
            findings.append({
                "plugin_id": "DARK-SSL-1003",
                "vuln_type": "TLS Certificate Hostname Mismatch",
                "severity": "Medium",
                "url": target_label,
                "parameter": f"tcp/{port}",
                "evidence": verify_err[:180],
                "detail": "The certificate Common Name / SAN does not match the target hostname.",
                "cwe": "CWE-297",
                "cvss_hint": 5.3,
            })

    if cert:
        subj = dict(x[0] for x in cert.get("subject", ()) if x)
        iss = dict(x[0] for x in cert.get("issuer", ()) if x)
        sans = [v for k, v in cert.get("subjectAltName", ()) if k in ("DNS", "IP Address")]
        summary["subject"] = subj.get("commonName")
        summary["issuer"] = iss.get("organizationName") or iss.get("commonName")
        summary["not_after"] = cert.get("notAfter")
        summary["sans"] = sans[:20]

        exp = _parse_asn1_time(cert.get("notAfter"))
        if exp:
            days_left = (exp - datetime.datetime.now(datetime.timezone.utc)).days
            if days_left < 0 and not any(f["plugin_id"] == "DARK-SSL-1002" for f in findings):
                findings.append({
                    "plugin_id": "DARK-SSL-1002",
                    "vuln_type": "TLS Certificate Expired",
                    "severity": "High",
                    "url": target_label,
                    "parameter": f"tcp/{port}",
                    "evidence": f"notAfter={cert.get('notAfter')} ({days_left}d)",
                    "detail": "The server TLS certificate has expired.",
                    "cwe": "CWE-295",
                    "cvss_hint": 7.4,
                })
            elif 0 <= days_left <= 30:
                findings.append({
                    "plugin_id": "DARK-SSL-1004",
                    "vuln_type": "TLS Certificate Expiring Soon",
                    "severity": "Low",
                    "url": target_label,
                    "parameter": f"tcp/{port}",
                    "evidence": f"expires in {days_left} day(s) ({cert.get('notAfter')})",
                    "detail": "Renew the certificate before expiration to avoid outages.",
                    "cwe": "CWE-298",
                    "cvss_hint": 3.1,
                })

        if not _is_ip(host) and sans and not any(_match_hostname(s, host) for s in sans):
            if not any(f["plugin_id"] == "DARK-SSL-1003" for f in findings):
                findings.append({
                    "plugin_id": "DARK-SSL-1003",
                    "vuln_type": "TLS Certificate Hostname Mismatch",
                    "severity": "Medium",
                    "url": target_label,
                    "parameter": f"tcp/{port}",
                    "evidence": f"host={host}, SANs={', '.join(sans[:5])}",
                    "detail": "Target hostname is not covered by certificate SAN entries.",
                    "cwe": "CWE-297",
                    "cvss_hint": 5.3,
                })

    # Cipher strength inspection
    if cipher_tuple:
        cname, _, bits = cipher_tuple
        up = cname.upper()
        if any(w in up for w in ("RC4", "DES", "3DES", "MD5", "NULL", "EXP", "EXPORT")):
            findings.append({
                "plugin_id": "DARK-SSL-1005",
                "vuln_type": "TLS Weak Cipher Suite Negotiated",
                "severity": "Medium",
                "url": target_label,
                "parameter": cname,
                "evidence": f"cipher={cname}, bits={bits}",
                "detail": "A deprecated or weak cipher suite (RC4/3DES/DES/EXPORT) was negotiated.",
                "cwe": "CWE-327",
                "cvss_hint": 5.9,
            })
        elif isinstance(bits, int) and bits < 128:
            findings.append({
                "plugin_id": "DARK-SSL-1005",
                "vuln_type": "TLS Weak Cipher Key Length",
                "severity": "Medium",
                "url": target_label,
                "parameter": cname,
                "evidence": f"cipher={cname}, key_bits={bits}",
                "detail": "Cipher suite key length is below 128 bits.",
                "cwe": "CWE-326",
                "cvss_hint": 5.3,
            })

    # Deprecated TLS 1.0 / 1.1 check
    if check_deprecated and hasattr(ssl, "TLSVersion"):
        deprecated = []
        for label, tv in (("TLSv1.0", getattr(ssl.TLSVersion, "TLSv1", None)),
                          ("TLSv1.1", getattr(ssl.TLSVersion, "TLSv1_1", None))):
            if tv is None:
                continue
            info_dep, _ = _connect_tls(host, port, min(timeout, 3.0), verify=False, proto_ver=tv)
            if info_dep is not None:
                deprecated.append(label)
        if deprecated:
            findings.append({
                "plugin_id": "DARK-SSL-1006",
                "vuln_type": "Deprecated TLS Protocol Enabled",
                "severity": "Medium",
                "url": target_label,
                "parameter": ", ".join(deprecated),
                "evidence": f"Server accepted handshake over {', '.join(deprecated)}",
                "detail": "TLS 1.0 and 1.1 are deprecated (RFC 8996) and vulnerable to "
                          "downgrade/BEAST/POODLE-era weaknesses. Enforce TLS 1.2+ and TLS 1.3.",
                "cwe": "CWE-326",
                "cvss_hint": 5.3,
            })

    # HSTS quality check (only when an HTTP header string was passed)
    if hsts_header is not None:
        if not hsts_header.strip():
            findings.append({
                "plugin_id": "DARK-SSL-1007",
                "vuln_type": "Missing Strict-Transport-Security (HSTS)",
                "severity": "Low",
                "url": target_label,
                "parameter": "Strict-Transport-Security",
                "evidence": "HTTPS endpoint lacks Strict-Transport-Security header",
                "detail": "Without HSTS, initial plain-HTTP requests can be downgraded.",
                "cwe": "CWE-319",
                "cvss_hint": 3.7,
            })
        else:
            m = re.search(r"max-age\s*=\s*(\d+)", hsts_header, re.I)
            age = int(m.group(1)) if m else 0
            if age < 15768000:
                findings.append({
                    "plugin_id": "DARK-SSL-1008",
                    "vuln_type": "Weak HSTS max-age Configuration",
                    "severity": "Low",
                    "url": target_label,
                    "parameter": "Strict-Transport-Security",
                    "evidence": f"max-age={age} (< 15768000 / 6 months)",
                    "detail": "Set HSTS max-age to at least 31536000 (1 year) with includeSubDomains.",
                    "cwe": "CWE-319",
                    "cvss_hint": 3.1,
                })

    return findings, summary


def build_tls_intelligence(summary: Dict[str, object], findings: List[dict]) -> Dict[str, object]:
    """Produce an SSL/TLS Intelligence posture grade (A+..F) and protocol/cipher assessment."""
    if not summary.get("reachable"):
        return {"grade": "N/A", "reachable": False, "summary": summary, "issues": len(findings)}
    score = 100
    proto = str(summary.get("protocol") or "")
    if "TLSv1.3" in proto:
        score += 5
    elif "TLSv1.0" in proto or "TLSv1.1" in proto:
        score -= 35
    for f in findings:
        sev = str(f.get("severity") or "Low")
        score -= {"Critical": 40, "High": 30, "Medium": 15, "Low": 5}.get(sev, 5)
    score = max(0, min(100, score))
    if score >= 95:
        grade = "A+"
    elif score >= 85:
        grade = "A"
    elif score >= 70:
        grade = "B"
    elif score >= 55:
        grade = "C"
    elif score >= 40:
        grade = "D"
    else:
        grade = "F"
    return {
        "grade": grade,
        "score": score,
        "reachable": True,
        "protocol": proto,
        "cipher": summary.get("cipher"),
        "not_after": summary.get("not_after"),
        "issue_count": len(findings),
    }
