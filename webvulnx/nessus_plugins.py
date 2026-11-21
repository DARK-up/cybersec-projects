#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Nessus-style Web Technology Fingerprinter & CVE Plugin Engine.

Performs passive + safe version fingerprinting across headers, HTML meta tags,
script/CSS assets, and framework markers, then evaluates structured CVE plugins
using semantic version range bounds (avoiding regex false positives).
"""
from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


VerTuple = Tuple[int, ...]


def parse_ver(raw: str) -> Optional[VerTuple]:
    if not raw:
        return None
    m = re.search(r"(\d+(?:\.\d+){1,3})", raw)
    if not m:
        return None
    parts = [int(x) for x in m.group(1).split(".")]
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:4])


def ver_cmp(a: VerTuple, b: VerTuple) -> int:
    n = max(len(a), len(b))
    aa = a + (0,) * (n - len(a))
    bb = b + (0,) * (n - len(b))
    return -1 if aa < bb else (1 if aa > bb else 0)


def ver_in_range(v: VerTuple, min_inc: Optional[str], max_exc: Optional[str]) -> bool:
    if min_inc:
        mv = parse_ver(min_inc)
        if mv and ver_cmp(v, mv) < 0:
            return False
    if max_exc:
        xv = parse_ver(max_exc)
        if xv and ver_cmp(v, xv) >= 0:
            return False
    return True


@dataclass(frozen=True)
class WebCvePlugin:
    plugin_id: str
    product: str
    family: str
    min_ver: Optional[str]
    max_exc: Optional[str]
    severity: str
    cvss: float
    cves: Tuple[str, ...]
    title: str
    remediation: str
    cwe: str = "CWE-1104"


# Curated, high-confidence web server, runtime, CMS, and JS library CVEs.
WEB_CVE_PLUGINS: List[WebCvePlugin] = [
    # --- Apache HTTP Server ---
    WebCvePlugin(
        "DARK-WEB-1001", "Apache HTTP Server", "Web Servers", "2.4.49", "2.4.51",
        "Critical", 9.8, ("CVE-2021-41773", "CVE-2021-42013"),
        "Apache HTTP Server 2.4.49/2.4.50 Path Traversal & RCE",
        "Upgrade Apache HTTP Server to 2.4.58 or later.",
        "CWE-22",
    ),
    WebCvePlugin(
        "DARK-WEB-1002", "Apache HTTP Server", "Web Servers", "2.4.0", "2.4.59",
        "High", 7.5, ("CVE-2024-27316", "CVE-2023-43622", "CVE-2023-25690"),
        "Apache HTTP Server < 2.4.59 HTTP/2 DoS & Request Smuggling CVEs",
        "Upgrade Apache HTTP Server to 2.4.59+ (or latest distro-patched build).",
        "CWE-444",
    ),
    WebCvePlugin(
        "DARK-WEB-1003", "Apache HTTP Server", "Web Servers", "2.0.0", "2.4.0",
        "High", 7.5, ("CVE-2017-9798", "CVE-2011-3192"),
        "End-of-Life Apache HTTP Server 2.0/2.2 Branch",
        "Migrate to a supported Apache HTTP Server 2.4.x release.",
    ),
    # --- nginx ---
    WebCvePlugin(
        "DARK-WEB-1010", "nginx", "Web Servers", "0.6.0", "1.20.1",
        "High", 7.5, ("CVE-2021-23017",),
        "nginx < 1.20.1 Off-by-One DNS Resolver Heap Overflow",
        "Upgrade nginx to 1.24.x / 1.26.x or apply vendor backport.",
        "CWE-193",
    ),
    WebCvePlugin(
        "DARK-WEB-1011", "nginx", "Web Servers", "1.20.1", "1.25.5",
        "Medium", 5.9, ("CVE-2024-24989", "CVE-2023-44487"),
        "nginx < 1.25.5 HTTP/2 & HTTP/3 DoS / Rapid Reset Advisories",
        "Upgrade nginx to 1.25.5+ / 1.26+ and tune HTTP/2 stream limits.",
        "CWE-400",
    ),
    # --- Microsoft IIS ---
    WebCvePlugin(
        "DARK-WEB-1020", "Microsoft IIS", "Web Servers", "5.0", "8.0",
        "High", 7.5, ("CVE-2015-1635", "CVE-2017-7269"),
        "Legacy Microsoft IIS (< 8.0) Remote Code Execution / EOL Surface",
        "Upgrade Windows Server / IIS to a currently supported release.",
    ),
    # --- Apache Tomcat ---
    WebCvePlugin(
        "DARK-WEB-1030", "Apache Tomcat", "Application Servers", "7.0.0", "9.0.86",
        "High", 7.5, ("CVE-2024-23672", "CVE-2020-1938"),
        "Apache Tomcat Outdated Release (WebSocket / AJP Ghostcat CVEs)",
        "Upgrade Apache Tomcat to 9.0.86+, 10.1.19+, or 11.x.",
    ),
    # --- OpenSSL ---
    WebCvePlugin(
        "DARK-WEB-1040", "OpenSSL", "Cryptography", "0.9.0", "1.1.1",
        "High", 7.5, ("CVE-2014-0160", "CVE-2016-2107"),
        "End-of-Life OpenSSL < 1.1.1",
        "Upgrade OpenSSL to 3.0 LTS or 3.2+.",
    ),
    WebCvePlugin(
        "DARK-WEB-1041", "OpenSSL", "Cryptography", "3.0.0", "3.0.7",
        "High", 7.5, ("CVE-2022-3602", "CVE-2022-3786"),
        "OpenSSL 3.0.0–3.0.6 X.509 Punycode Buffer Overrun",
        "Upgrade OpenSSL to 3.0.13+ or 3.2+.",
        "CWE-787",
    ),
    # --- PHP ---
    WebCvePlugin(
        "DARK-WEB-1050", "PHP", "Runtimes", "4.0.0", "8.1.0",
        "High", 7.5, ("CVE-2024-4577", "CVE-2022-31629", "CVE-2019-11043"),
        "End-of-Life PHP (< 8.1) Exposed via Headers",
        "Upgrade PHP to 8.2+ or 8.3+ and set expose_php=Off.",
    ),
    WebCvePlugin(
        "DARK-WEB-1051", "PHP", "Runtimes", "8.1.0", "8.3.8",
        "Medium", 6.5, ("CVE-2024-4577", "CVE-2024-5458"),
        "PHP < 8.3.8 CGI Argument Injection / Filter Bypass Advisories",
        "Upgrade PHP to 8.2.20+ / 8.3.8+ and disable expose_php.",
    ),
    # --- WordPress & CMS ---
    WebCvePlugin(
        "DARK-WEB-1060", "WordPress", "CMS", "3.0.0", "6.5.0",
        "Medium", 6.1, ("CVE-2024-31210", "CVE-2023-39999", "CVE-2022-21661"),
        "Outdated WordPress Core (< 6.5) with Known XSS/SQLi Advisories",
        "Update WordPress Core and all installed plugins/themes.",
    ),
    WebCvePlugin(
        "DARK-WEB-1061", "Drupal", "CMS", "7.0.0", "10.2.0",
        "High", 7.5, ("CVE-2018-7600", "CVE-2022-25277"),
        "Outdated Drupal Core Detected",
        "Upgrade Drupal to 10.2+ and apply security advisories.",
    ),
    # --- DevOps / Admin Platforms ---
    WebCvePlugin(
        "DARK-WEB-1070", "Jenkins", "DevOps", "1.0.0", "2.442",
        "Critical", 9.8, ("CVE-2024-23897",),
        "Jenkins < 2.442 Arbitrary File Read via CLI Argument Expansion",
        "Upgrade Jenkins to 2.442+ / LTS 2.426.3+ and restrict anonymous access.",
        "CWE-22",
    ),
    WebCvePlugin(
        "DARK-WEB-1071", "Grafana", "DevOps", "5.0.0", "10.2.0",
        "High", 7.5, ("CVE-2021-43798", "CVE-2023-3128"),
        "Outdated Grafana Release (< 10.2)",
        "Upgrade Grafana to the latest patched 10.x/11.x release.",
    ),
    # --- Frontend JS Libraries ---
    WebCvePlugin(
        "DARK-WEB-1101", "jQuery", "JavaScript Libraries", "1.0.0", "3.5.0",
        "Medium", 6.1, ("CVE-2020-11022", "CVE-2020-11023"),
        "jQuery < 3.5.0 HTML Prefilter Cross-Site Scripting",
        "Upgrade jQuery to 3.5.0+ (3.7.1 recommended).",
        "CWE-79",
    ),
    WebCvePlugin(
        "DARK-WEB-1102", "jQuery UI", "JavaScript Libraries", "1.0.0", "1.13.0",
        "Medium", 6.1, ("CVE-2021-41182", "CVE-2021-41183", "CVE-2021-41184"),
        "jQuery UI < 1.13.0 Multiple XSS Vulnerabilities",
        "Upgrade jQuery UI to 1.13.2+.",
        "CWE-79",
    ),
    WebCvePlugin(
        "DARK-WEB-1103", "AngularJS", "JavaScript Libraries", "1.0.0", "1.9.0",
        "Medium", 6.1, ("CVE-2022-25869", "CVE-2023-26116"),
        "End-of-Life AngularJS 1.x Client-Side Template/XSS Risk",
        "Migrate from EOL AngularJS 1.x to modern Angular or apply strict sanitization.",
        "CWE-79",
    ),
    WebCvePlugin(
        "DARK-WEB-1104", "Lodash", "JavaScript Libraries", "1.0.0", "4.17.21",
        "High", 7.4, ("CVE-2021-23337", "CVE-2020-8203"),
        "Lodash < 4.17.21 Prototype Pollution & Command Injection",
        "Upgrade Lodash to 4.17.21+.",
        "CWE-1321",
    ),
    WebCvePlugin(
        "DARK-WEB-1105", "Bootstrap", "JavaScript Libraries", "2.0.0", "4.3.1",
        "Medium", 6.1, ("CVE-2019-8331", "CVE-2018-14041"),
        "Bootstrap < 4.3.1 Tooltip/Popover XSS",
        "Upgrade Bootstrap to 4.6+ or 5.3+.",
        "CWE-79",
    ),
    WebCvePlugin(
        "DARK-WEB-1106", "Handlebars", "JavaScript Libraries", "1.0.0", "4.7.7",
        "High", 8.1, ("CVE-2021-23369",),
        "Handlebars < 4.7.7 Prototype Pollution",
        "Upgrade Handlebars to 4.7.7+.",
        "CWE-1321",
    ),
    WebCvePlugin(
        "DARK-WEB-1107", "Moment.js", "JavaScript Libraries", "1.0.0", "2.29.4",
        "Medium", 5.3, ("CVE-2022-24785", "CVE-2022-31129"),
        "Moment.js < 2.29.4 ReDoS / Path Traversal",
        "Upgrade Moment.js to 2.29.4+ or migrate to Luxon/date-fns.",
    ),
]


def fingerprint_from_responses(pages: List[dict]) -> List[dict]:
    """Extract normalized technology stack records from captured HTTP responses.

    Each item in `pages` has keys: url, headers (dict), body (str), cookies (dict/list).
    Returns deduplicated list of {product, version, category, source, evidence}.
    """
    found: Dict[Tuple[str, str], dict] = {}

    def add(product: str, version: str, category: str, source: str, evidence: str) -> None:
        key = (product, version or "")
        if key not in found:
            found[key] = {
                "product": product,
                "version": version or "",
                "category": category,
                "source": source,
                "evidence": evidence[:140],
            }

    for p in pages:
        url = p.get("url") or ""
        hdrs = {str(k).lower(): str(v) for k, v in (p.get("headers") or {}).items()}
        body = (p.get("body") or "")[:120_000]

        srv = hdrs.get("server", "")
        if srv:
            for rx, prod, cat in (
                (r"Apache(?:/([\d.]+))?", "Apache HTTP Server", "Web Servers"),
                (r"nginx(?:/([\d.]+))?", "nginx", "Web Servers"),
                (r"Microsoft-IIS(?:/([\d.]+))?", "Microsoft IIS", "Web Servers"),
                (r"LiteSpeed(?:/([\d.]+))?", "LiteSpeed", "Web Servers"),
                (r"cloudflare", "Cloudflare WAF/CDN", "CDN / WAF"),
                (r"Apache-Coyote(?:/([\d.]+))?|Tomcat(?:/([\d.]+))?", "Apache Tomcat", "Application Servers"),
                (r"OpenSSL/([\d.]+[a-z]?)", "OpenSSL", "Cryptography"),
            ):
                m = re.search(rx, srv, re.I)
                if m:
                    ver = next((g for g in m.groups() if g), "") if m.groups() else ""
                    add(prod, ver, cat, "Server header", srv)

        xp = hdrs.get("x-powered-by", "")
        if xp:
            for rx, prod, cat in (
                (r"PHP(?:/([\d.]+))?", "PHP", "Runtimes"),
                (r"ASP\.NET(?:\s+([\d.]+))?", "ASP.NET", "Frameworks"),
                (r"Express", "Express.js", "Frameworks"),
                (r"Next\.js(?:\s*([\d.]+))?", "Next.js", "Frameworks"),
            ):
                m = re.search(rx, xp, re.I)
                if m:
                    ver = next((g for g in m.groups() if g), "") if m.groups() else ""
                    add(prod, ver, cat, "X-Powered-By", xp)

        if hdrs.get("x-jenkins"):
            add("Jenkins", hdrs["x-jenkins"], "DevOps", "X-Jenkins", hdrs["x-jenkins"])
        if "x-aspnet-version" in hdrs:
            add("ASP.NET", hdrs["x-aspnet-version"], "Frameworks", "X-AspNet-Version", hdrs["x-aspnet-version"])
        if "x-drupal-cache" in hdrs or "x-generator" in hdrs and "drupal" in hdrs["x-generator"].lower():
            m = re.search(r"Drupal\s+([\d.]+)", hdrs.get("x-generator", ""), re.I)
            add("Drupal", m.group(1) if m else "", "CMS", "Header", hdrs.get("x-generator", "X-Drupal-Cache"))

        # Cookies hint
        set_cookie = hdrs.get("set-cookie", "")
        if "phpsessid" in set_cookie.lower():
            add("PHP", "", "Runtimes", "Cookie", "PHPSESSID")
        if "jsessionid" in set_cookie.lower():
            add("Java Servlet / Tomcat", "", "Application Servers", "Cookie", "JSESSIONID")
        if "laravel_session" in set_cookie.lower():
            add("Laravel", "", "Frameworks", "Cookie", "laravel_session")
        if "csrftoken" in set_cookie.lower() and "django" in body.lower():
            add("Django", "", "Frameworks", "Cookie", "csrftoken")

        # HTML meta generators
        for gm in re.finditer(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', body, re.I):
            gen = gm.group(1)
            for rx, prod, cat in (
                (r"WordPress\s*([\d.]+)?", "WordPress", "CMS"),
                (r"Drupal\s*([\d.]+)?", "Drupal", "CMS"),
                (r"Joomla!?\s*([\d.]+)?", "Joomla", "CMS"),
                (r"Ghost\s*([\d.]+)?", "Ghost", "CMS"),
            ):
                m = re.search(rx, gen, re.I)
                if m:
                    add(prod, (m.group(1) or "") if m.groups() else "", cat, "meta generator", gen)

        # WordPress asset/plugin fingerprints
        for pm in re.finditer(r"/wp-content/plugins/([a-z0-9_-]+)/[^\"'\s>]*?(?:\?ver=([\d.]+))?", body, re.I):
            slug = pm.group(1)
            pver = pm.group(2) or ""
            add(f"WordPress Plugin: {slug}", pver, "CMS Plugins", url, pm.group(0)[:80])

        # Next.js / React / Vue / Grafana markers
        if "__NEXT_DATA__" in body or "/_next/static/" in body:
            add("Next.js", "", "Frameworks", url, "/_next/static/ or __NEXT_DATA__")
        if "wp-includes/" in body and not any(k[0] == "WordPress" for k in found):
            vm = re.search(r"ver=([\d.]+)", body)
            add("WordPress", vm.group(1) if vm else "", "CMS", url, "wp-includes/")
        if "Grafana" in body and ("grafanaBootData" in body or "grafana-app" in body):
            vm = re.search(r'"version"\s*:\s*"([\d.]+)"', body)
            add("Grafana", vm.group(1) if vm else "", "DevOps", url, "grafanaBootData")

        # JS library versions (URLs + inline banners)
        for rx, prod in (
            (r"jquery(?:\.min)?[.\-/]v?(\d+\.\d+\.\d+)|jQuery\s+v?(\d+\.\d+\.\d+)", "jQuery"),
            (r"jquery-ui(?:\.min)?[.\-/]v?(\d+\.\d+\.\d+)|jQuery UI\s+-?\s*v?(\d+\.\d+\.\d+)", "jQuery UI"),
            (r"angular(?:\.min)?[.\-/]v?(\d+\.\d+\.\d+)|AngularJS\s+v?(\d+\.\d+\.\d+)", "AngularJS"),
            (r"lodash(?:\.min)?[.\-/]v?(\d+\.\d+\.\d+)", "Lodash"),
            (r"bootstrap(?:\.bundle)?(?:\.min)?[.\-/]v?(\d+\.\d+\.\d+)|Bootstrap\s+v(\d+\.\d+\.\d+)", "Bootstrap"),
            (r"handlebars(?:\.min)?[.\-/]v?(\d+\.\d+\.\d+)", "Handlebars"),
            (r"moment(?:\.min)?[.\-/]v?(\d+\.\d+\.\d+)", "Moment.js"),
        ):
            for m in re.finditer(rx, body, re.I):
                ver = next((g for g in m.groups() if g), "")
                if ver:
                    add(prod, ver, "JavaScript Libraries", url, m.group(0)[:80])

    return list(found.values())


class NessusWebAuditor:
    """Evaluates fingerprinted web technologies against curated CVE plugins."""

    def __init__(self, client, state, finding_cls):
        self.client = client
        self.state = state
        self.F = finding_cls

    def run(self) -> List[dict]:
        pages: List[dict] = []
        urls = [self.state.base_url] + [
            u for u in list(self.state.crawled_urls)[:20] if u != self.state.base_url
        ]
        for u in urls:
            resp = self.client.get(u, cache=True)
            if resp is None:
                continue
            pages.append({
                "url": resp.url or u,
                "headers": dict(resp.headers),
                "body": resp.text or "",
            })

        stack = fingerprint_from_responses(pages)
        setattr(self.state, "tech_stack", stack)

        emitted = set()
        for item in stack:
            prod = item["product"]
            ver_s = item["version"]
            ver = parse_ver(ver_s)
            if not ver:
                continue
            for plg in WEB_CVE_PLUGINS:
                if plg.product.lower() != prod.lower():
                    continue
                if ver_in_range(ver, plg.min_ver, plg.max_exc):
                    key = (plg.plugin_id, prod, ver_s)
                    if key in emitted:
                        continue
                    emitted.add(key)
                    cves = ", ".join(plg.cves)
                    self.state.add(self.F(
                        vuln_type=f"[{plg.plugin_id}] {plg.title}",
                        severity=plg.severity,
                        url=self.state.base_url,
                        parameter=f"{prod} {ver_s}",
                        evidence=f"{prod} {ver_s} ({item['source']}: {item['evidence']}) — {cves}",
                        detail=f"Family: {plg.family} | CWE: {plg.cwe} | CVEs: {cves}. "
                               f"Remediation: {plg.remediation}",
                        cvss_hint=plg.cvss,
                    ))
        return stack
