#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Subdomain, DNS, Email Security (SPF/DMARC/CAA) & Takeover Recon for DARK.

Pure Python stdlib (UDP DNS wire queries + socket + requests for optional
crt.sh / takeover fingerprint verification). Works with zero external binaries.
"""
from __future__ import annotations

import os
import random
import re
import socket
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlsplit

import requests

# DNS record type codes
QTYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "MX": 15, "TXT": 16, "AAAA": 28, "CAA": 257}

COMMON_SUBDOMAINS = [
    "www", "api", "dev", "staging", "stage", "test", "beta", "admin",
    "portal", "app", "auth", "sso", "login", "mail", "webmail", "smtp",
    "imap", "mx", "vpn", "remote", "git", "gitlab", "jenkins", "ci",
    "docs", "cdn", "static", "assets", "media", "files", "backup", "db",
    "sql", "internal", "intranet", "monitor", "grafana", "kibana",
    "metrics", "status", "blog", "shop", "store", "support", "help",
    "mobile", "m", "ws", "graphql", "v1", "v2", "sandbox", "uat", "qa",
    "preprod", "dashboard", "panel", "cpanel", "ftp",
]

TAKEOVER_SIGNATURES = (
    ("github.io", ("There isn't a GitHub Pages site here",)),
    ("herokuapp.com", ("No such app", "herokucdn.com/error-pages/no-such-app")),
    ("s3.amazonaws.com", ("NoSuchBucket", "The specified bucket does not exist")),
    ("amazonaws.com", ("NoSuchBucket",)),
    ("azurewebsites.net", ("Error 404 - Web app not found", "404 Web Site not found")),
    ("cloudapp.net", ("404 Web Site not found",)),
    ("netlify.app", ("Not Found - Request ID:",)),
    ("netlify.com", ("Not Found - Request ID:",)),
    ("vercel.app", ("The deployment could not be found on Vercel", "DEPLOYMENT_NOT_FOUND")),
    ("myshopify.com", ("Sorry, this shop is currently unavailable",)),
    ("fastly.net", ("Fastly error: unknown domain",)),
    ("zendesk.com", ("Help Center Closed", "Oops, this help center no longer exists")),
    ("ghost.io", ("The thing you were looking for is no longer here",)),
    ("bitbucket.io", ("Repository not found",)),
    ("surge.sh", ("project not found",)),
    ("pantheonsite.io", ("404 error unknown site",)),
    ("unbouncepages.com", ("The requested URL was not found on this server",)),
    ("wpengine.com", ("The site you were looking for couldn't be found",)),
)


def normalize_domain(raw: str) -> str:
    s = (raw or "").strip()
    if "://" in s:
        s = urlsplit(s).hostname or s
    s = s.split("/")[0].split(":")[0].strip(".").lower()
    return s


def _system_dns_servers() -> List[str]:
    servers: List[str] = []
    try:
        with open("/etc/resolv.conf", "r", encoding="utf-8", errors="ignore") as fh:
            for ln in fh:
                ln = ln.strip()
                if ln.startswith("nameserver"):
                    parts = ln.split()
                    if len(parts) >= 2 and re.fullmatch(r"\d+\.\d+\.\d+\.\d+", parts[1]):
                        servers.append(parts[1])
    except OSError:
        pass
    for fallback in ("8.8.8.8", "1.1.1.1"):
        if fallback not in servers:
            servers.append(fallback)
    return servers


def _encode_name(name: str) -> bytes:
    out = bytearray()
    for part in name.strip(".").split("."):
        b = part.encode("idna")
        out.append(len(b))
        out.extend(b)
    out.append(0)
    return bytes(out)


def _decode_name(pkt: bytes, offset: int) -> Tuple[str, int]:
    labels: List[str] = []
    orig_off = offset
    jumped = False
    hops = 0
    while offset < len(pkt) and hops < 20:
        hops += 1
        length = pkt[offset]
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(pkt):
                break
            ptr = ((length & 0x3F) << 8) | pkt[offset + 1]
            if not jumped:
                orig_off = offset + 2
            offset = ptr
            jumped = True
        elif length == 0:
            offset += 1
            break
        else:
            offset += 1
            labels.append(pkt[offset:offset + length].decode("utf-8", errors="replace"))
            offset += length
    return ".".join(labels), (orig_off if jumped else offset)


def dns_query(domain: str, rtype: str = "A", timeout: float = 2.5,
              servers: Optional[List[str]] = None) -> List[str]:
    qtype = QTYPES.get(rtype.upper())
    if qtype is None:
        return []
    txid = random.randint(1, 65534)
    header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    question = _encode_name(domain) + struct.pack("!HH", qtype, 1)
    query = header + question

    for srv in (servers or _system_dns_servers()):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(query, (srv, 53))
            pkt, _ = sock.recvfrom(4096)
        except OSError:
            continue
        finally:
            sock.close()

        if len(pkt) < 12:
            continue
        _, flags, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", pkt[:12])
        if (flags & 0x0F) not in (0,):  # NXDOMAIN / SERVFAIL -> valid server reply, no records
            if (flags & 0x0F) == 3:
                return []
        off = 12
        for _ in range(qdcount):
            _, off = _decode_name(pkt, off)
            off += 4
        results: List[str] = []
        for _ in range(ancount):
            if off >= len(pkt):
                break
            _, off = _decode_name(pkt, off)
            if off + 10 > len(pkt):
                break
            rr_type, _, _, rdlen = struct.unpack("!HHIH", pkt[off:off + 10])
            off += 10
            rdata = pkt[off:off + rdlen]
            if rr_type != qtype:
                off += rdlen
                continue
            if rr_type == 1 and rdlen == 4:
                results.append(socket.inet_ntop(socket.AF_INET, rdata))
            elif rr_type == 28 and rdlen == 16:
                results.append(socket.inet_ntop(socket.AF_INET6, rdata))
            elif rr_type in (2, 5):
                nm, _ = _decode_name(pkt, off)
                results.append(nm.rstrip("."))
            elif rr_type == 15 and rdlen >= 3:
                pref = struct.unpack("!H", rdata[:2])[0]
                exch, _ = _decode_name(pkt, off + 2)
                results.append(f"{pref} {exch.rstrip('.')}")
            elif rr_type == 16:
                pos = 0
                chunks: List[str] = []
                while pos < len(rdata):
                    ln = rdata[pos]
                    pos += 1
                    chunks.append(rdata[pos:pos + ln].decode("utf-8", errors="replace"))
                    pos += ln
                results.append("".join(chunks))
            elif rr_type == 257 and rdlen >= 2:
                flags_b = rdata[0]
                tlen = rdata[1]
                tag = rdata[2:2 + tlen].decode("ascii", errors="replace")
                val = rdata[2 + tlen:].decode("utf-8", errors="replace")
                results.append(f"{flags_b} {tag} \"{val}\"")
            off += rdlen
        return results
    return []


def _passive_crtsh(domain: str, timeout: float = 4.5) -> Set[str]:
    subs: Set[str] = set()
    try:
        r = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=timeout,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        if r.status_code == 200 and r.text.strip().startswith("["):
            for row in r.json()[:250]:
                nv = str(row.get("name_value") or "")
                for line in nv.splitlines():
                    h = line.strip().lower().lstrip("*.")
                    if h.endswith("." + domain) and "*" not in h and len(h) <= 120:
                        subs.add(h)
    except Exception:
        pass
    return subs


def _check_takeover(sub: str, cname: str) -> Optional[Dict[str, Any]]:
    clow = cname.lower()
    for svc, sigs in TAKEOVER_SIGNATURES:
        if svc in clow:
            for scheme in ("https", "http"):
                try:
                    r = requests.get(f"{scheme}://{sub}", timeout=3.5, allow_redirects=True,
                                     headers={"User-Agent": "Mozilla/5.0"})
                    body = r.text or ""
                    for sig in sigs:
                        if sig.lower() in body.lower():
                            return {
                                "service": svc,
                                "signature": sig,
                                "url": f"{scheme}://{sub}",
                                "status": r.status_code,
                            }
                    break
                except requests.RequestException:
                    continue
    return None


def run_dns_recon(target: str, subdomains: bool = True,
                  passive_crtsh: bool = True,
                  extra_words: Optional[List[str]] = None,
                  stop_event: Optional[threading.Event] = None) -> Dict[str, Any]:
    t0 = time.time()
    domain = normalize_domain(target)
    if not domain or "." not in domain:
        return {"error": f"invalid domain name: {target!r}"}

    servers = _system_dns_servers()
    print(f"[*] DNS & Email Security Recon on {domain} (resolvers={servers[:2]})")

    records: Dict[str, List[str]] = {}
    for rt in ("A", "AAAA", "MX", "NS", "TXT", "CAA"):
        if stop_event is not None and stop_event.is_set():
            break
        records[rt] = dns_query(domain, rt, timeout=2.5, servers=servers)

    # Fallback A lookup via OS resolver if UDP DNS returned empty
    if not records.get("A"):
        try:
            infos = socket.getaddrinfo(domain, None, socket.AF_INET)
            records["A"] = sorted({i[4][0] for i in infos})
        except OSError:
            pass

    dmarc_txt = dns_query(f"_dmarc.{domain}", "TXT", timeout=2.5, servers=servers)
    records["DMARC"] = dmarc_txt

    findings: List[Dict[str, Any]] = []

    def add_finding(vuln_type: str, severity: str, url: str, param: str,
                    evidence: str, detail: str, cvss: float, payload: str = ""):
        findings.append({
            "vuln_type": vuln_type,
            "severity": severity,
            "url": url,
            "parameter": param,
            "payload": payload or param,
            "evidence": evidence,
            "detail": detail,
            "cvss_hint": cvss,
        })

    # 1. SPF Audit
    spf_recs = [t for t in records.get("TXT", []) if t.lower().startswith("v=spf1")]
    if not spf_recs:
        add_finding(
            "Missing SPF Record (Email Spoofing Risk)", "Medium",
            f"dns://{domain}", "TXT (SPF)",
            f"No v=spf1 TXT record found for {domain}",
            "Without an SPF record, attackers can spoof outbound emails appearing to come from this domain.",
            5.3, f"{domain} IN TXT",
        )
    else:
        if len(spf_recs) > 1:
            add_finding(
                "Multiple SPF Records (RFC 7208 PermError)", "Medium",
                f"dns://{domain}", "TXT (SPF)",
                f"Found {len(spf_recs)} SPF records: {spf_recs}",
                "RFC 7208 allows only one SPF TXT record; multiple records cause receivers to fail SPF evaluation.",
                5.0,
            )
        spf = spf_recs[0]
        if "+all" in spf.lower():
            add_finding(
                "Permissive SPF (+all Allows Any Sender)", "High",
                f"dns://{domain}", "TXT (SPF)",
                spf,
                "SPF ends with '+all', explicitly authorizing any IP on the Internet to send mail for this domain.",
                7.5,
            )
        elif "?all" in spf.lower():
            add_finding(
                "Weak SPF Policy (?all Neutral)", "Medium",
                f"dns://{domain}", "TXT (SPF)",
                spf,
                "SPF ends with '?all' (neutral), providing no spoofing protection.",
                4.3,
            )
        elif "~all" in spf.lower():
            add_finding(
                "SPF SoftFail (~all instead of -all)", "Low",
                f"dns://{domain}", "TXT (SPF)",
                spf,
                "Consider tightening '~all' to '-all' once all legitimate mail senders are verified and DMARC is enforced.",
                2.6,
            )

    # 2. DMARC Audit
    dmarc_recs = [t for t in dmarc_txt if "v=dmarc1" in t.lower()]
    if not dmarc_recs:
        add_finding(
            "Missing DMARC Record", "Medium",
            f"dns://_dmarc.{domain}", "TXT (_dmarc)",
            f"No v=DMARC1 record found at _dmarc.{domain}",
            "Without DMARC, receiving mail servers lack policy instructions (quarantine/reject) for unauthenticated mail.",
            5.3, f"_dmarc.{domain} IN TXT",
        )
    else:
        dm = dmarc_recs[0]
        m_pol = re.search(r"\bp=([a-z]+)", dm, re.I)
        pol = m_pol.group(1).lower() if m_pol else ""
        if pol == "none":
            add_finding(
                "DMARC Policy Set to Monitoring Only (p=none)", "Low",
                f"dns://_dmarc.{domain}", "TXT (_dmarc)",
                dm,
                "DMARC p=none logs reports without blocking spoofed messages. Progress toward p=quarantine or p=reject.",
                3.1,
            )

    # 3. CAA Audit
    if not records.get("CAA"):
        add_finding(
            "Missing DNS CAA Record", "Low",
            f"dns://{domain}", "CAA",
            f"No CAA record found for {domain}",
            "Adding a CAA record restricts which Certificate Authorities are allowed to issue TLS certificates for this domain.",
            2.5, f"{domain} IN CAA",
        )

    # 4. Subdomain Enumeration + Takeover Check
    discovered_subs: List[Dict[str, Any]] = []
    if subdomains and not (stop_event is not None and stop_event.is_set()):
        cand_names: Set[str] = {f"{w}.{domain}" for w in COMMON_SUBDOMAINS}
        for w in (extra_words or []):
            w = w.strip().strip(".")
            if w:
                cand_names.add(w if w.endswith(domain) else f"{w}.{domain}")
        if passive_crtsh:
            print(f"[*] Querying certificate transparency (crt.sh) for *.{domain}...")
            cand_names.update(_passive_crtsh(domain))

        def _probe_sub(fqdn: str) -> Optional[Dict[str, Any]]:
            if stop_event is not None and stop_event.is_set():
                return None
            cnames = dns_query(fqdn, "CNAME", timeout=2.0, servers=servers)
            ips = dns_query(fqdn, "A", timeout=2.0, servers=servers)
            if not ips and not cnames:
                try:
                    ips = sorted({i[4][0] for i in socket.getaddrinfo(fqdn, None, socket.AF_INET)})
                except OSError:
                    pass
            if not ips and not cnames:
                return None
            return {"host": fqdn, "ips": ips, "cname": cnames[0] if cnames else ""}

        print(f"[*] Resolving {len(cand_names)} candidate subdomain(s)...")
        with ThreadPoolExecutor(max_workers=12) as ex:
            futs = [ex.submit(_probe_sub, s) for s in sorted(cand_names)]
            for fut in as_completed(futs):
                if stop_event is not None and stop_event.is_set():
                    break
                row = fut.result()
                if row:
                    discovered_subs.append(row)

        discovered_subs.sort(key=lambda x: x["host"])
        for row in discovered_subs:
            if row["cname"]:
                tk = _check_takeover(row["host"], row["cname"])
                if tk:
                    row["takeover"] = tk
                    add_finding(
                        f"Potential Subdomain Takeover ({tk['service']})", "High",
                        tk["url"], row["host"],
                        f"CNAME -> {row['cname']} | matched '{tk['signature']}' (HTTP {tk['status']})",
                        "Dangling CNAME points to an unclaimed third-party cloud service; an attacker may register the target resource and serve arbitrary content on your subdomain.",
                        8.2, f"CNAME {row['cname']}",
                    )

    if discovered_subs:
        print(f"[+] Discovered {len(discovered_subs)} live subdomain(s) under {domain}")
        add_finding(
            "Subdomains Discovered", "Info",
            f"dns://{domain}", "subdomain",
            ", ".join(s["host"] for s in discovered_subs[:15]) + ("..." if len(discovered_subs) > 15 else ""),
            f"Total {len(discovered_subs)} active subdomain(s) resolved via DNS/CT logs.",
            0.0,
        )

    dt = round(time.time() - t0, 2)
    return {
        "target": domain,
        "domain": domain,
        "records": records,
        "subdomains": discovered_subs,
        "findings": findings,
        "stopped_early": bool(stop_event is not None and stop_event.is_set()),
        "duration_s": dt,
    }
