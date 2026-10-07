#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""World-surface scanner — famous, high-confidence vulnerability classes.

Every check here is proof-based (a unique artefact in the response). We
never report a 200 OK on a sensitive path as a finding by itself — that
is what the directory brute-forcer already does at lower confidence.
"""
from __future__ import annotations

import json
import re
import urllib.parse
from typing import List, Optional, Tuple

GIT_HEAD_RX = re.compile(r"^(ref:\s+refs/|([0-9a-f]{40})\s*$)", re.I | re.M)
ENV_LINE_RX = re.compile(r"^[A-Z][A-Z0-9_]{1,60}=.+$", re.M)
ENV_SECRET_RX = re.compile(
    r"^(AWS|SECRET|PASSWORD|PASSWD|TOKEN|API_KEY|DATABASE|DB_|MYSQL|POSTGRES|"
    r"REDIS|MAIL|SMTP|PRIVATE|JWT|APP_KEY|DJANGO_SECRET)", re.M | re.I)
PHPINFO_RX = re.compile(r"PHP Version\s+\d+\.\d+|phpinfo\(\)", re.I)
DJANGO_DEBUG_RX = re.compile(
    r"You're seeing this error because you have\s+<code>DEBUG\s*=\s*True</code>",
    re.I)
ACTUATOR_RX = re.compile(r"\"propertySources\"\s*:|\"beans\"\s*:|\"status\"\s*:\s*\"UP\"")
S3_RX = re.compile(r"<ListBucketResult[\s>]")
WP_GEN_RX = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+WordPress\s*([\d.]+)?', re.I)
WP_LOGIN_RX = re.compile(r'name=["\']log["\']|id=["\']wp-submit["\']|wp-login\.php', re.I)
DRUPAL_RX = re.compile(r"Drupal\s+([\d.]+)|jQuery\.extend\(Drupal", re.I)
JOOMLA_RX = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+Joomla', re.I)
SOURCE_RX = re.compile(r"<\?php|<%[=\s]|#!/usr/bin|package\s+\w+;|using\s+System;")
WS_RX = re.compile(r"""(?:new\s+WebSocket|wss?://)[^'"\s]+""", re.I)

GRAPHQL_QUERY = {"query": "{__schema{queryType{name}mutationType{name}types{name}}}"}

# Paths we probe with CONTENT checks (not mere 200 OK).
PROBES: List[Tuple[str, str, str, str, float]] = [
    # path, vuln_type, severity, evidence-must-match-name, cvss
    (".git/HEAD", "Source-Control Metadata Exposed", "Critical", "git", 8.6),
    (".git/config", "Source-Control Metadata Exposed", "Critical", "gitconfig", 8.6),
    (".svn/entries", "Source-Control Metadata Exposed", "High", "svn", 7.5),
    (".env", "Environment / Secrets File Exposed", "Critical", "env", 9.8),
    (".env.local", "Environment / Secrets File Exposed", "Critical", "env", 9.8),
    (".env.production", "Environment / Secrets File Exposed", "Critical", "env", 9.8),
    (".aws/credentials", "Environment / Secrets File Exposed", "Critical", "aws", 9.8),
    ("phpinfo.php", "Debug / Diagnostic Endpoint Exposed", "High", "phpinfo", 7.5),
    ("info.php", "Debug / Diagnostic Endpoint Exposed", "High", "phpinfo", 7.5),
    ("actuator/env", "Debug / Diagnostic Endpoint Exposed", "High", "actuator", 7.5),
    ("actuator/health", "Debug / Diagnostic Endpoint Exposed", "Medium", "actuator_health", 5.3),
    ("swagger.json", "OpenAPI / Swagger Spec Exposed", "Medium", "openapi", 5.3),
    ("swagger/v1/swagger.json", "OpenAPI / Swagger Spec Exposed", "Medium", "openapi", 5.3),
    ("openapi.json", "OpenAPI / Swagger Spec Exposed", "Medium", "openapi", 5.3),
    ("v2/api-docs", "OpenAPI / Swagger Spec Exposed", "Medium", "openapi", 5.3),
    ("api-docs", "OpenAPI / Swagger Spec Exposed", "Medium", "openapi", 5.3),
    ("graphql", "GraphQL Introspection Enabled", "Medium", "graphql_get", 5.3),
    ("api/graphql", "GraphQL Introspection Enabled", "Medium", "graphql_get", 5.3),
    ("wp-login.php", "CMS Fingerprint / Attack Surface", "Info", "wp_login", 3.1),
    ("xmlrpc.php", "CMS Fingerprint / Attack Surface", "Low", "xmlrpc", 3.1),
    ("wp-json/wp/v2/users", "CMS Fingerprint / Attack Surface", "Medium", "wp_users", 5.3),
]


def _looks_like(kind: str, body: str, headers: dict) -> Optional[str]:
    ct = (headers.get("Content-Type") or "").lower()
    text = body[:8000]
    if kind == "git":
        if GIT_HEAD_RX.search(text.strip()[:200]):
            return text.strip().splitlines()[0][:80]
        return None
    if kind == "gitconfig":
        if "[core]" in text and "repositoryformatversion" in text:
            return "[core] repositoryformatversion present"
        return None
    if kind == "svn":
        if "dir" in text.splitlines()[:4] or "svn://" in text:
            return "SVN entries file"
        return None
    if kind == "env":
        lines = ENV_LINE_RX.findall(text)
        if len(lines) >= 2 and ENV_SECRET_RX.search(text):
            return f"{len(lines)} KEY=value lines, secret-like keys present"
        return None
    if kind == "aws":
        if "[default]" in text and "aws_access_key_id" in text.lower():
            return "aws_access_key_id present"
        return None
    if kind == "phpinfo":
        if PHPINFO_RX.search(text) and ("phpinfo()" in text.lower() or "Configuration" in text):
            m = re.search(r"PHP Version\s*([\d.]+)", text)
            return f"phpinfo() PHP {m.group(1) if m else '?'}"
        return None
    if kind == "actuator":
        if "propertySources" in text or "systemEnvironment" in text:
            return "Spring Actuator env document"
        return None
    if kind == "actuator_health":
        if re.search(r'"status"\s*:\s*"UP"', text) and "json" in ct:
            return "Spring Actuator health = UP"
        return None
    if kind == "openapi":
        try:
            data = json.loads(text)
        except Exception:
            return None
        if isinstance(data, dict) and (data.get("swagger") or data.get("openapi")):
            title = (data.get("info") or {}).get("title") or "untitled"
            ver = data.get("swagger") or data.get("openapi")
            n = len(data.get("paths") or {})
            return f"{title} (spec {ver}, {n} path(s))"
        return None
    if kind == "graphql_get":
        # GET on /graphql often 400 JSON — not enough. Handled by POST probe.
        return None
    if kind == "wp_login":
        if WP_LOGIN_RX.search(text):
            return "WordPress login form"
        return None
    if kind == "xmlrpc":
        if "XML-RPC" in text or "xmlrpc.php" in text.lower() or \
                (headers.get("Allow") and "POST" in (headers.get("Allow") or "")):
            if "XML-RPC" in text or "<methodResponse" in text or "xmlrpc" in text.lower():
                return "WordPress XML-RPC endpoint"
        return None
    if kind == "wp_users":
        try:
            data = json.loads(text)
        except Exception:
            return None
        if isinstance(data, list) and data and isinstance(data[0], dict) \
                and ("slug" in data[0] or "name" in data[0]):
            names = [u.get("slug") or u.get("name") for u in data[:5]]
            return f"{len(data)} user(s) enumerated: {', '.join(str(n) for n in names if n)}"
        return None
    return None


class WorldScanner:
    """Famous-vuln surface: source control, secrets, GraphQL, OpenAPI, CMS, backups."""

    def __init__(self, client, state, finding_cls):
        self.client = client
        self.state = state
        self.F = finding_cls
        self.client.module = "world-surface"

    def _add(self, **kw) -> None:
        self.state.add(self.F(**kw))

    def _get(self, path: str):
        url = urllib.parse.urljoin(self.state.base_url.rstrip("/") + "/", path)
        return url, self.client.get(url)

    def run(self) -> None:
        print("[*] World-surface probes (source control, secrets, GraphQL, CMS, backups)")
        self._probe_famous_paths()
        self._graphql()
        self._cms_from_html()
        self._s3_listing()
        self._django_debug()
        self._backups()
        self._websockets()
        self._clickjacking()

    def _probe_famous_paths(self) -> None:
        seen = set()
        for path, vtype, sev, kind, cvss in PROBES:
            url, resp = self._get(path)
            if resp is None or resp.status_code >= 400:
                continue
            body = resp.text or ""
            if len(body) < 4:
                continue
            evidence = _looks_like(kind, body, resp.headers)
            if not evidence:
                continue
            key = (vtype, urllib.parse.urlsplit(url).path)
            if key in seen:
                continue
            seen.add(key)
            self._add(vuln_type=vtype, severity=sev, url=url,
                      evidence=evidence, cvss_hint=cvss,
                      detail="Confirmed by unique response artefact — not a mere 200 OK.")

    def _graphql(self) -> None:
        for path in ("graphql", "api/graphql", "graphiql", "graphql/console", "v1/graphql"):
            url = urllib.parse.urljoin(self.state.base_url.rstrip("/") + "/", path)
            resp = self.client.request(
                "POST", url, json=GRAPHQL_QUERY,
                headers={"Content-Type": "application/json",
                         "Accept": "application/json"})
            if resp is None:
                continue
            body = resp.text or ""
            try:
                data = json.loads(body)
            except Exception:
                continue
            schema = (data.get("data") or {}).get("__schema") if isinstance(data, dict) else None
            if schema:
                q = (schema.get("queryType") or {}).get("name")
                types = schema.get("types") or []
                self._add(
                    vuln_type="GraphQL Introspection Enabled",
                    severity="Medium", url=url, payload=str(GRAPHQL_QUERY),
                    evidence=f"__schema returned (queryType={q}, {len(types)} types)",
                    detail="Full GraphQL schema is public. Map mutations and "
                           "hidden fields without source access.",
                    cvss_hint=5.3,
                )
                return
            # Some servers disable introspection but still expose the endpoint
            errs = data.get("errors") if isinstance(data, dict) else None
            if isinstance(errs, list) and errs:
                msg = str(errs[0].get("message") or "")
                if "introspection" in msg.lower() and "disabled" in msg.lower():
                    return  # endpoint exists, introspection off — not a finding

    def _cms_from_html(self) -> None:
        resp = self.client.get(self.state.base_url)
        if resp is None:
            return
        body = resp.text or ""
        m = WP_GEN_RX.search(body)
        if m:
            ver = m.group(1) or "unknown"
            self._add(vuln_type="CMS Fingerprint / Attack Surface",
                      severity="Info", url=self.state.base_url, parameter="WordPress",
                      evidence=f"generator meta: WordPress {ver}",
                      detail="WordPress version advertised. Keep core/plugins patched "
                             "and disable author enumeration / xmlrpc if unused.",
                      cvss_hint=3.1)
        if DRUPAL_RX.search(body):
            self._add(vuln_type="CMS Fingerprint / Attack Surface",
                      severity="Info", url=self.state.base_url, parameter="Drupal",
                      evidence="Drupal JS/marker present",
                      detail="Drupal install fingerprinted.",
                      cvss_hint=3.1)
        if JOOMLA_RX.search(body):
            self._add(vuln_type="CMS Fingerprint / Attack Surface",
                      severity="Info", url=self.state.base_url, parameter="Joomla",
                      evidence="Joomla generator meta present",
                      detail="Joomla install fingerprinted.",
                      cvss_hint=3.1)

    def _s3_listing(self) -> None:
        resp = self.client.get(self.state.base_url)
        if resp is not None and S3_RX.search(resp.text or ""):
            self._add(vuln_type="Cloud Storage Listing Exposed",
                      severity="High", url=self.state.base_url,
                      evidence="<ListBucketResult> XML listing",
                      detail="Public cloud-storage listing — every object is enumerable.",
                      cvss_hint=7.5)

    def _django_debug(self) -> None:
        # Force a 404 that Django DEBUG would render as a technical 404
        url = urllib.parse.urljoin(self.state.base_url.rstrip("/") + "/",
                                   "dark-debug-probe-404/")
        resp = self.client.get(url)
        if resp is None:
            return
        if DJANGO_DEBUG_RX.search(resp.text or "") or \
                ("Django" in (resp.text or "")[:2000] and "DEBUG = True" in (resp.text or "")):
            self._add(vuln_type="Debug / Diagnostic Endpoint Exposed",
                      severity="High", url=url,
                      evidence="Django DEBUG=True technical 404 page",
                      detail="Django debug pages leak settings, URLconf and sometimes secrets.",
                      cvss_hint=7.5)

    def _backups(self) -> None:
        """For a few crawled scripts, try classic editor/backup suffixes.
        Confirmed only when source tokens appear (<?php, etc.)."""
        cands = []
        for u in list(self.state.crawled_urls)[:12]:
            path = urllib.parse.urlsplit(u).path
            if re.search(r"\.(php|asp|aspx|jsp|py|rb|js)$", path, re.I):
                cands.append(u)
        suffixes = (".bak", ".old", "~", ".swp", ".orig", ".copy")
        tried = 0
        for u in cands:
            if tried >= 16:
                break
            for suf in suffixes:
                tried += 1
                target = u + suf
                resp = self.client.get(target)
                if resp is None or resp.status_code >= 400:
                    continue
                body = resp.text or ""
                ct = (resp.headers.get("Content-Type") or "").lower()
                if SOURCE_RX.search(body[:4000]) or \
                        ("text/plain" in ct and SOURCE_RX.search(body[:4000])):
                    self._add(vuln_type="Backup / Source File Exposed",
                              severity="High", url=target,
                              evidence="source tokens in backup/swap file",
                              detail="A backup of an executable script is served as a "
                                     "downloadable file — source and secrets leak.",
                              cvss_hint=7.5)
                    return

    def _websockets(self) -> None:
        seen = set()
        for u in list(self.state.crawled_urls)[:15]:
            resp = self.client.get(u)
            if resp is None:
                continue
            for m in WS_RX.finditer(resp.text or ""):
                ep = m.group(0)[:120]
                if ep in seen:
                    continue
                seen.add(ep)
                self._add(vuln_type="Information Disclosure",
                          severity="Info", url=u, parameter="WebSocket",
                          evidence=ep,
                          detail="WebSocket endpoint advertised in page source. "
                                 "Not a vulnerability by itself — test auth on the socket.",
                          cvss_hint=0.0)
                if len(seen) >= 3:
                    return

    def _clickjacking(self) -> None:
        resp = self.client.get(self.state.base_url)
        if resp is None:
            return
        xfo = resp.headers.get("X-Frame-Options", "")
        csp = resp.headers.get("Content-Security-Policy", "")
        if xfo or re.search(r"frame-ancestors", csp, re.I):
            return
        # Missing-header module already reports X-Frame-Options. We only add
        # a dedicated clickjacking finding when BOTH XFO and CSP are absent,
        # so the report has a named, remediable item.
        self._add(vuln_type="Clickjacking (missing frame protection)",
                  severity="Low", url=self.state.base_url,
                  evidence="no X-Frame-Options and no CSP frame-ancestors",
                  detail="The page can be framed by any origin.",
                  cvss_hint=4.3)
