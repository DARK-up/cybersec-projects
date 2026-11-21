#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""NetRecon Nessus-style Vulnerability & Compliance Plugin Engine.

Evaluates discovered open ports, service banners, and TLS endpoints against
curated CVE version ranges and network-service security checks.
"""
from __future__ import annotations

import asyncio
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple


VerTuple = Tuple[int, ...]


def _parse_ver(raw: str) -> Optional[VerTuple]:
    if not raw:
        return None
    m = re.search(r"(\d+(?:\.\d+){1,3})", raw)
    if not m:
        return None
    parts = [int(x) for x in m.group(1).split(".")]
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:4])


def _cmp(a: VerTuple, b: VerTuple) -> int:
    n = max(len(a), len(b))
    aa = a + (0,) * (n - len(a))
    bb = b + (0,) * (n - len(b))
    return -1 if aa < bb else (1 if aa > bb else 0)


def _in_range(v: VerTuple, min_inc: Optional[str], max_exc: Optional[str]) -> bool:
    if min_inc:
        mv = _parse_ver(min_inc)
        if mv and _cmp(v, mv) < 0:
            return False
    if max_exc:
        xv = _parse_ver(max_exc)
        if xv and _cmp(v, xv) >= 0:
            return False
    return True


# (plugin_id, family, product_regex, ver_regex, min_inc, max_exc,
#  severity, cvss, cves, title, remediation)
SERVICE_CVE_PLUGINS: List[Tuple] = [
    (
        "DARK-NET-1001", "SSH", re.compile(r"OpenSSH", re.I),
        re.compile(r"OpenSSH[_\s-]*([\d.]+)(?:p(\d+))?", re.I),
        "8.5", "9.8", "High", 8.1, ("CVE-2024-6387",),
        "OpenSSH regreSSHion Signal Handler Race Condition (8.5p1–9.7p1)",
        "Upgrade OpenSSH to 9.8p1+ (or verify distro backport) and restrict SSH exposure.",
    ),
    (
        "DARK-NET-1002", "SSH", re.compile(r"OpenSSH", re.I),
        re.compile(r"OpenSSH[_\s-]*([\d.]+)", re.I),
        "1.0", "8.0", "Medium", 5.3, ("CVE-2018-15473", "CVE-2020-14145"),
        "Outdated OpenSSH (< 8.0) User Enumeration / Legacy Crypto",
        "Upgrade OpenSSH to 9.8p1+ and disable legacy CBC/SHA-1 algorithms.",
    ),
    (
        "DARK-NET-1010", "Web Servers", re.compile(r"Apache", re.I),
        re.compile(r"Apache/([\d.]+)", re.I),
        "2.4.49", "2.4.51", "Critical", 9.8, ("CVE-2021-41773", "CVE-2021-42013"),
        "Apache HTTP Server 2.4.49/2.4.50 Path Traversal & RCE",
        "Upgrade Apache HTTP Server to 2.4.59+.",
    ),
    (
        "DARK-NET-1011", "Web Servers", re.compile(r"Apache", re.I),
        re.compile(r"Apache/([\d.]+)", re.I),
        "2.4.0", "2.4.59", "High", 7.5, ("CVE-2024-27316", "CVE-2023-25690"),
        "Apache HTTP Server < 2.4.59 HTTP/2 DoS & Smuggling CVEs",
        "Upgrade Apache HTTP Server to 2.4.59+.",
    ),
    (
        "DARK-NET-1012", "Web Servers", re.compile(r"nginx", re.I),
        re.compile(r"nginx/([\d.]+)", re.I),
        "0.6.0", "1.20.1", "High", 7.5, ("CVE-2021-23017",),
        "nginx < 1.20.1 DNS Resolver Heap Overflow",
        "Upgrade nginx to 1.26.x / 1.24.x.",
    ),
    (
        "DARK-NET-1013", "Web Servers", re.compile(r"Microsoft-IIS", re.I),
        re.compile(r"Microsoft-IIS/([\d.]+)", re.I),
        "5.0", "8.0", "High", 7.5, ("CVE-2015-1635", "CVE-2017-7269"),
        "Legacy Microsoft IIS (< 8.0) Exposed",
        "Decommission or upgrade Windows Server / IIS to a supported version.",
    ),
    (
        "DARK-NET-1020", "FTP", re.compile(r"vsFTPd", re.I),
        re.compile(r"vsFTPd\s+([\d.]+)", re.I),
        "2.0.0", "3.0.0", "High", 7.5, ("CVE-2011-2523", "CVE-2015-1419"),
        "Outdated vsftpd 2.x Server Detected",
        "Upgrade vsftpd to 3.0.5+ or migrate to SFTP.",
    ),
    (
        "DARK-NET-1021", "FTP", re.compile(r"ProFTPD", re.I),
        re.compile(r"ProFTPD\s+([\d.]+)", re.I),
        "1.0.0", "1.3.7", "High", 7.5, ("CVE-2020-9273", "CVE-2019-12815"),
        "Outdated ProFTPD (< 1.3.7) Detected",
        "Upgrade ProFTPD to 1.3.8+ or migrate to SFTP.",
    ),
    (
        "DARK-NET-1030", "Mail", re.compile(r"Exim", re.I),
        re.compile(r"Exim\s+([\d.]+)", re.I),
        "4.0.0", "4.97.1", "High", 8.1, ("CVE-2023-42115", "CVE-2024-39929"),
        "Outdated Exim Mail Server (< 4.97.1)",
        "Upgrade Exim to 4.97.1+ / 4.98+.",
    ),
    (
        "DARK-NET-1040", "Databases", re.compile(r"MySQL|MariaDB", re.I),
        re.compile(r"(\d+\.\d+\.\d+)(?:-MariaDB)?", re.I),
        "5.0.0", "8.0.0", "Medium", 6.5, ("CVE-2021-2166", "CVE-2020-14812"),
        "Legacy MySQL 5.x Branch Detected",
        "Migrate to MySQL 8.0/8.4 LTS or supported MariaDB LTS and bind to private interface.",
    ),
]


# Port-level Nessus-style exposure / cleartext / misconfiguration rules
EXPOSED_PORT_RULES: Dict[int, dict] = {
    23: {
        "plugin_id": "DARK-NET-2001", "family": "Cleartext Services",
        "severity": "High", "cvss": 7.5, "cwe": "CWE-319",
        "title": "Telnet Cleartext Administration Port Open",
        "remediation": "Disable Telnet immediately and use SSH (port 22) with key auth.",
    },
    21: {
        "plugin_id": "DARK-NET-2002", "family": "Cleartext Services",
        "severity": "Low", "cvss": 3.7, "cwe": "CWE-319",
        "title": "Unencrypted FTP Service Exposed",
        "remediation": "Replace plain FTP with SFTP or enforce FTPS (TLS).",
    },
    139: {
        "plugin_id": "DARK-NET-2003", "family": "SMB / NetBIOS",
        "severity": "Medium", "cvss": 5.3, "cwe": "CWE-284",
        "title": "NetBIOS Session Service (TCP/139) Exposed",
        "remediation": "Firewall TCP/139 from untrusted networks and disable NetBIOS over TCP.",
    },
    445: {
        "plugin_id": "DARK-NET-2004", "family": "SMB / NetBIOS",
        "severity": "High", "cvss": 7.5, "cwe": "CWE-284",
        "title": "SMB File Sharing (TCP/445) Exposed",
        "remediation": "Never expose SMB/445 directly to the internet; require SMBv3 signing & VPN.",
    },
    3389: {
        "plugin_id": "DARK-NET-2005", "family": "Remote Access",
        "severity": "Medium", "cvss": 6.5, "cwe": "CWE-284",
        "title": "RDP Remote Desktop Service (TCP/3389) Exposed",
        "remediation": "Restrict RDP behind VPN/bastion, enforce NLA + MFA, and patch BlueKeep/DejaBlue.",
    },
    5900: {
        "plugin_id": "DARK-NET-2006", "family": "Remote Access",
        "severity": "High", "cvss": 7.5, "cwe": "CWE-319",
        "title": "VNC Remote Framebuffer Service (TCP/5900) Exposed",
        "remediation": "Tunnel VNC over SSH/VPN and require strong authentication.",
    },
    2375: {
        "plugin_id": "DARK-NET-2007", "family": "Containers / Cloud",
        "severity": "Critical", "cvss": 9.8, "cwe": "CWE-306",
        "title": "Unencrypted Docker Remote API Port (TCP/2375) Exposed",
        "remediation": "Disable unauthenticated TCP/2375; bind to unix socket or enforce mutual TLS on 2376.",
    },
    9200: {
        "plugin_id": "DARK-NET-2008", "family": "Databases",
        "severity": "High", "cvss": 7.5, "cwe": "CWE-306",
        "title": "Elasticsearch HTTP Interface (TCP/9200) Exposed",
        "remediation": "Bind Elasticsearch to localhost/private VPC and enable X-Pack TLS & auth.",
    },
    27017: {
        "plugin_id": "DARK-NET-2009", "family": "Databases",
        "severity": "High", "cvss": 7.5, "cwe": "CWE-306",
        "title": "MongoDB Database Port (TCP/27017) Exposed",
        "remediation": "Bind MongoDB to internal interface only and enforce SCRAM authentication + TLS.",
    },
    6443: {
        "plugin_id": "DARK-NET-2010", "family": "Containers / Cloud",
        "severity": "Medium", "cvss": 5.3, "cwe": "CWE-284",
        "title": "Kubernetes API Server (TCP/6443) Reachable",
        "remediation": "Restrict Kubernetes API access via IP allowlists / private cluster endpoint.",
    },
}

TLS_PORTS = {443, 8443, 465, 636, 993, 995}


async def _check_ftp_anonymous(host: str, port: int, timeout: float = 2.0) -> Optional[str]:
    """Safe, read-only FTP anonymous capability check (no file listing/writes)."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
    except Exception:
        return None
    try:
        await asyncio.wait_for(reader.read(512), timeout=timeout)
        writer.write(b"USER anonymous\r\n")
        await writer.drain()
        r1 = (await asyncio.wait_for(reader.read(512), timeout=timeout)).decode("utf-8", "replace")
        if r1.startswith("230"):
            return "FTP accepted USER anonymous without password (230)"
        if r1.startswith("331"):
            writer.write(b"PASS anonymous@example.com\r\n")
            await writer.drain()
            r2 = (await asyncio.wait_for(reader.read(512), timeout=timeout)).decode("utf-8", "replace")
            if r2.startswith("230"):
                return "FTP anonymous login succeeded (230)"
        writer.write(b"QUIT\r\n")
        await writer.drain()
    except Exception:
        return None
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
    return None


async def evaluate_host(host: str, open_ports: list, timeout: float = 3.0) -> List[dict]:
    """Run Nessus-style plugins against a host's discovered open ports."""
    vulns: List[dict] = []
    seen = set()

    def add(v: dict) -> None:
        key = (v["plugin_id"], v.get("port"), v.get("parameter"))
        if key not in seen:
            seen.add(key)
            vulns.append(v)

    for pr in open_ports:
        port = int(pr.port)
        svc = pr.service or "unknown"
        ver = pr.version or ""
        ban = pr.banner or ""
        blob = f"{svc} {ver} {ban}".strip()

        # 1. Banner / Service CVE plugins
        for (pid, fam, prod_rx, ver_rx, mn, mx, sev, cvss, cves, title, rem) in SERVICE_CVE_PLUGINS:
            if not prod_rx.search(blob):
                continue
            m = ver_rx.search(blob)
            if not m:
                continue
            v_str = m.group(1)
            if len(m.groups()) >= 2 and m.group(2):
                # Handle OpenSSH 9.6p1 -> (9, 6, 1)
                v_str = f"{m.group(1)}.{m.group(2)}"
            vt = _parse_ver(v_str)
            if vt and _in_range(vt, mn, mx):
                add({
                    "plugin_id": pid,
                    "family": fam,
                    "vuln_type": f"[{pid}] {title}",
                    "severity": sev,
                    "cvss_hint": cvss,
                    "cves": list(cves),
                    "port": port,
                    "service": svc,
                    "parameter": f"tcp/{port} ({svc})",
                    "url": f"{host}:{port}",
                    "evidence": f"{blob[:140]} — CVEs: {', '.join(cves)}",
                    "detail": f"Service version matched vulnerable range. Remediation: {rem}",
                })

        # 2. Unauthenticated service proof checks from protocol probes
        if svc == "Redis" or port == 6379:
            if "+PONG" in ban:
                add({
                    "plugin_id": "DARK-NET-2101",
                    "family": "Databases",
                    "vuln_type": "[DARK-NET-2101] Unauthenticated Redis Server Exposed",
                    "severity": "Critical",
                    "cvss_hint": 9.8,
                    "cves": [],
                    "port": port,
                    "service": "Redis",
                    "parameter": f"tcp/{port} (Redis)",
                    "url": f"{host}:{port}",
                    "evidence": "PING returned +PONG without AUTH",
                    "detail": "Redis responds to commands without authentication. Bind to "
                              "localhost/private VPC and configure requirepass / ACLs.",
                })
        if svc == "Memcached" or port == 11211:
            if "STAT pid" in ban:
                add({
                    "plugin_id": "DARK-NET-2102",
                    "family": "Databases",
                    "vuln_type": "[DARK-NET-2102] Unauthenticated Memcached Exposed",
                    "severity": "High",
                    "cvss_hint": 7.5,
                    "cves": ["CVE-2018-1000115"],
                    "port": port,
                    "service": "Memcached",
                    "parameter": f"tcp/{port} (Memcached)",
                    "url": f"{host}:{port}",
                    "evidence": "stats command returned STAT pid",
                    "detail": "Memcached is accessible without authentication, exposing cached "
                              "data and UDP amplification risk. Bind to private loopback.",
                })

        # 3. Exposed / cleartext port rules
        if port in EXPOSED_PORT_RULES:
            r = EXPOSED_PORT_RULES[port]
            add({
                "plugin_id": r["plugin_id"],
                "family": r["family"],
                "vuln_type": f"[{r['plugin_id']}] {r['title']}",
                "severity": r["severity"],
                "cvss_hint": r["cvss"],
                "cves": [],
                "port": port,
                "service": svc,
                "parameter": f"tcp/{port}",
                "url": f"{host}:{port}",
                "evidence": f"Open port tcp/{port} ({svc}) {ver}".strip(),
                "detail": f"CWE: {r['cwe']}. Remediation: {r['remediation']}",
            })

        # 4. Safe FTP anonymous login check
        if port == 21 or svc == "FTP":
            anon = await _check_ftp_anonymous(host, port, timeout=min(timeout, 2.0))
            if anon:
                add({
                    "plugin_id": "DARK-NET-2103",
                    "family": "FTP",
                    "vuln_type": "[DARK-NET-2103] FTP Anonymous Login Enabled",
                    "severity": "Medium",
                    "cvss_hint": 5.3,
                    "cves": [],
                    "port": port,
                    "service": "FTP",
                    "parameter": f"tcp/{port} (FTP)",
                    "url": f"{host}:{port}",
                    "evidence": anon,
                    "detail": "Disable anonymous FTP access unless intentionally serving public files.",
                })

        # 5. TLS/SSL compliance audit on TLS ports
        if port in TLS_PORTS or "HTTPS" in svc.upper():
            try:
                wx_dir = str(Path(__file__).resolve().parent.parent / "webvulnx")
                if wx_dir not in sys.path:
                    sys.path.insert(0, wx_dir)
                import tls_audit  # type: ignore
                tls_findings, _ = tls_audit.audit_tls(
                    host, port=port, timeout=min(timeout, 3.0),
                    hsts_header=None, check_deprecated=True,
                )
                for tf in tls_findings:
                    add({
                        "plugin_id": tf["plugin_id"],
                        "family": "TLS / SSL",
                        "vuln_type": f"[{tf['plugin_id']}] {tf['vuln_type']}",
                        "severity": tf["severity"],
                        "cvss_hint": tf["cvss_hint"],
                        "cves": [],
                        "port": port,
                        "service": svc,
                        "parameter": tf.get("parameter") or f"tcp/{port}",
                        "url": tf.get("url") or f"{host}:{port}",
                        "evidence": tf.get("evidence") or "",
                        "detail": tf.get("detail") or "",
                    })
            except Exception:
                pass

    return vulns
