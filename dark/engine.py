#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DARK Engine — Detection & Attack Reconnaissance Kit
====================================================
Unified adapters that wrap the four portfolio tools behind one API:

  * NetRecon    -> run_network_scan()
  * WebVulnX    -> run_web_scan()
  * HashBreaker -> identify_hashes() / crack_hashes() / benchmark()
  * NetSentry   -> run_monitor_demo() / run_monitor_pcap() / run_monitor_live()

Works on Windows, Linux and macOS (Python 3.9+).
"""

from __future__ import annotations

import asyncio
import concurrent.futures as cf
import contextlib
import contextvars
import functools
import io
import sys
import threading
import time
from dataclasses import asdict
from pathlib import Path
from typing import Dict, List, Optional

ROOT = Path(__file__).resolve().parent.parent
for _tool in ("netrecon", "webvulnx", "hashbreaker", "netsentry", "modules", "dark"):
    _p = str(ROOT / _tool)
    if _p not in sys.path:
        sys.path.insert(0, _p)


def tools_status() -> Dict[str, bool]:
    """Which tool modules can be imported on this machine."""
    status = {}
    for name in ("netrecon", "webvulnx", "hashbreaker", "netsentry"):
        try:
            __import__(name)
            status[name] = True
        except Exception:
            status[name] = False
    return status


class JobLog(io.StringIO):
    """Thread-safe text buffer — several worker threads write to it while the
    watchdog reads it to publish live progress."""

    def __init__(self):
        super().__init__()
        self._lock = threading.Lock()

    def write(self, s):
        with self._lock:
            return super().write(s)

    def snapshot(self, tail_lines: int = 0) -> str:
        with self._lock:
            text = self.getvalue()
        if tail_lines:
            text = "\n".join(text.splitlines()[-tail_lines:])
        return text


# The API runs MANY JOBS IN PARALLEL. The old implementation swapped the global
# sys.stdout, so two concurrent scans wrote into each other's log — that is why
# jobs used to be serialized. Now stdout/stderr go through a context-aware
# router: every job (and every nested capture) pushes its own buffer onto a
# contextvar stack, and each write is tee'd only to the buffers of the CURRENT
# execution context. Parallel jobs stay perfectly isolated.
LOG_STACK: contextvars.ContextVar = contextvars.ContextVar(
    "dark_log_stack", default=None)


class _Router(io.TextIOBase):
    def __init__(self, fallback):
        self.fallback = fallback

    def write(self, s):
        stack = LOG_STACK.get()
        if not stack:
            return self.fallback.write(s)
        for buf in stack:
            try:
                buf.write(s)
            except Exception:
                pass
        return len(s)

    def flush(self):
        try:
            self.fallback.flush()
        except Exception:
            pass

    def isatty(self):
        return False

    def writable(self):
        return True

    @property
    def encoding(self):
        return getattr(self.fallback, "encoding", "utf-8") or "utf-8"

    def fileno(self):
        return self.fallback.fileno()


def _propagate_context_to_threads() -> None:
    """CPython does NOT inherit contextvars in new threads, and the tools use
    threads internally (NetRecon scans with up to 800 workers). Without this
    patch their output would escape the owning job's buffer."""
    if getattr(threading.Thread.start, "_dark_patched", False):
        return

    orig_start = threading.Thread.start

    def start(self):
        ctx = contextvars.copy_context()
        target = self._target
        if target is not None and not getattr(target, "_dark_ctx", False):
            def wrapped(*a, _ctx=ctx, _t=target, **kw):
                _ctx.run(_t, *a, **kw)
            wrapped._dark_ctx = True
            self._target = wrapped
        orig_start(self)

    start._dark_patched = True
    threading.Thread.start = start

    orig_submit = cf.ThreadPoolExecutor.submit

    def submit(self, fn, *args, **kwargs):
        if getattr(fn, "_dark_ctx", False):
            return orig_submit(self, fn, *args, **kwargs)
        ctx = contextvars.copy_context()
        part = functools.partial(ctx.run, fn)
        part._dark_ctx = True
        return orig_submit(self, part, *args, **kwargs)

    submit._dark_patched = True
    cf.ThreadPoolExecutor.submit = submit


def install_log_router() -> None:
    """Idempotent: route stdout/stderr through the context-aware proxy."""
    if isinstance(sys.stdout, _Router):
        return
    real_out, real_err = sys.stdout, sys.stderr
    sys.stdout = _Router(real_out)
    sys.stderr = _Router(real_err)
    _propagate_context_to_threads()


install_log_router()


@contextlib.contextmanager
def bind_job_log(buf: JobLog):
    """Outermost binding for a job: everything printed by the tool — including
    nested captures and worker threads — is tee'd into `buf` for live progress."""
    stack = list(LOG_STACK.get() or [])
    stack.insert(0, buf)
    token = LOG_STACK.set(stack)
    try:
        yield buf
    finally:
        LOG_STACK.reset(token)


class _Capture:
    """Capture a tool's console output for THIS execution context only."""

    def __init__(self):
        self.buf = JobLog()

    def __enter__(self):
        stack = list(LOG_STACK.get() or [])
        stack.append(self.buf)
        self._token = LOG_STACK.set(stack)
        return self

    def __exit__(self, *exc):
        LOG_STACK.reset(self._token)
        return False

    @property
    def text(self) -> str:
        return self.buf.snapshot()


def _enrich_finding_dict(f: Dict, default_method: str = "HTTP") -> Dict:
    """Attach catalog metadata (CWE, OWASP, CVSS, impact, remediation) and a
    clear `how_it_entered` attack-vector explanation onto every finding."""
    import catalog as dcat
    out = dict(f)
    vt = str(out.get("vuln_type") or "")
    meta = dcat.enrich(vt, float(out.get("cvss_hint") or 0.0))
    out.setdefault("cwe", meta.get("cwe", "CWE-693"))
    out.setdefault("owasp", meta.get("owasp", "A05:2021 Security Misconfiguration"))
    if not out.get("cvss"):
        out["cvss"] = meta.get("cvss", 0.0)
    if not out.get("impact"):
        out["impact"] = meta.get("impact", out.get("detail") or "")
    if not out.get("remediation"):
        out["remediation"] = meta.get("remediation", "")
    if not out.get("refs"):
        out["refs"] = meta.get("refs", [])
    if not out.get("how_it_entered"):
        param = out.get("parameter") or ""
        payload = out.get("payload") or ""
        url = out.get("url") or ""
        parts = []
        if default_method:
            parts.append(default_method)
        if url:
            parts.append(f"at {url}")
        if param:
            parts.append(f"via parameter/vector '{param}'")
        if payload:
            parts.append(f"using payload `{payload[:120]}`")
        out["how_it_entered"] = " ".join(parts) if parts else (out.get("evidence") or "")
    try:
        import vuln_intel as vi
        out = vi.score_finding_axes(out)
    except Exception:
        pass
    return out


# ---------------------------------------------------------------------------
# NetRecon
# ---------------------------------------------------------------------------
def run_network_scan(targets: List[str], ports: str = "top100", timing: str = "normal",
                     probe: bool = True, discover: bool = False,
                     vuln_audit: bool = True,
                     stop_event=None) -> Dict:
    import netrecon as nr

    hosts = nr.parse_targets(targets)
    port_list = nr.parse_ports(ports)
    if not hosts:
        return {"error": "no valid targets"}
    if not port_list:
        return {"error": "no valid ports"}

    scanner = nr.NetRecon(
        targets=hosts, ports=port_list, timing=timing,
        probe=probe, discover=discover, resolve=True, randomize=True,
        vuln_audit=vuln_audit, stop_event=stop_event,
    )
    with _Capture() as cap:
        asyncio.run(scanner.run())
    rep = scanner.to_dict()
    try:
        rep["topology"] = nr.build_network_topology(rep)
    except Exception:
        pass
    findings = [_enrich_finding_dict(f, default_method="TCP/Service Probe")
                for f in (rep.get("findings") or [])]
    return {
        "target": ", ".join(hosts[:6]),
        "report": rep,
        "topology": rep.get("topology", {}),
        "findings": findings,
        "stopped_early": bool(stop_event is not None and stop_event.is_set()),
        "log": cap.text,
    }


def run_dns_recon(target: str, subdomains: bool = True,
                  passive_crtsh: bool = True,
                  extra_words: Optional[List[str]] = None,
                  stop_event=None) -> Dict:
    import dns_recon as dr
    with _Capture() as cap:
        res = dr.run_dns_recon(
            target=target, subdomains=subdomains,
            passive_crtsh=passive_crtsh, extra_words=extra_words,
            stop_event=stop_event,
        )
    if "error" in res:
        return res
    res["findings"] = [_enrich_finding_dict(f, default_method="DNS / Email Audit")
                       for f in (res.get("findings") or [])]
    res["log"] = cap.text
    return res


# ---------------------------------------------------------------------------
# WebVulnX
# ---------------------------------------------------------------------------
def run_web_scan(url: str, modules: Optional[Dict[str, bool]] = None,
                 depth: int = 3, max_urls: int = 80, timeout: float = 10.0,
                 delay: float = 0.0, time_blind: float = 5.0,
                 wordlist_path: Optional[str] = None,
                 cookie: Optional[str] = None, proxy: Optional[str] = None,
                 stealth: bool = True,
                 auth_header: Optional[str] = None,
                 extra_headers: Optional[Dict[str, str]] = None,
                 login_url: Optional[str] = None,
                 login_user: Optional[str] = None,
                 login_pass: Optional[str] = None,
                 openapi_url: Optional[str] = None,
                 stop_event=None) -> Dict:
    import webvulnx as wx

    modules = modules or {}
    do_crawl = modules.get("crawl", True)
    do_sqli = modules.get("sqli", True)
    do_xss = modules.get("xss", True)
    do_dirs = modules.get("dirs", True)
    do_audit = modules.get("audit", True)
    do_advanced = modules.get("advanced", True)
    do_param_fuzz = modules.get("param_fuzz", True)
    do_default_creds = modules.get("default_creds", False)
    do_templates = modules.get("templates", True)

    url = wx.ensure_scheme(url)
    cookies = {}
    if cookie:
        for part in cookie.split(";"):
            if "=" in part:
                k, _, v = part.partition("=")
                cookies[k.strip()] = v.strip()

    hdrs: Dict[str, str] = {}
    if extra_headers:
        for k, v in extra_headers.items():
            if k and v is not None:
                hdrs[str(k).strip()] = str(v).strip()
    if auth_header and auth_header.strip():
        hdrs["Authorization"] = auth_header.strip()

    client = wx.HttpClient(timeout=timeout, delay=delay, cookies=cookies,
                           headers=hdrs or None, proxy=proxy,
                           stealth=stealth, target=url)
    client.stop_event = stop_event
    state = wx.ScanState(base_url=url, start_ts=time.time(), stop_event=stop_event)

    probe = client.get(url)
    if probe is None:
        err = client.last_error or "unknown error"
        return {"error": f"Cannot reach {url}", "detail": err,
                "hint": wx.diagnose_error(err)}

    debug = {
        "probe_status": probe.status_code,
        "server": probe.headers.get("Server", "?"),
        "content_length": len(probe.content),
        "content_type": probe.headers.get("Content-Type", "?"),
        "final_url": probe.url,
        "preview": probe.text[:200].replace("\n", " "),
    }

    def run_module(name, fn, *a, **kw):
        if state.should_stop():
            return None
        client.module = name
        state.modules_run.append(name)
        try:
            return fn(*a, **kw)
        except Exception as e:      # one broken module must not kill the scan
            print(f"[!] module {name} crashed: {type(e).__name__}: {e}")
            state.note(f"Module {name} failed: {type(e).__name__}: {e}")
            return None

    seeds = [url]
    auth_info = None
    openapi_info = None
    with _Capture() as cap:
        if login_url and login_user and not state.should_stop():
            try:
                import openapi_auth as oa
                auth_info = oa.perform_auto_login(client, wx.ensure_scheme(login_url),
                                                  login_user, login_pass or "")
                print(f"[*] Auto-login ({auth_info.get('method') or 'none'}): {auth_info.get('detail')}")
                if not auth_info.get("ok"):
                    state.note(f"Auto-login warning: {auth_info.get('detail')}")
            except Exception as e:
                print(f"[!] Auto-login error: {e}")

        if not state.should_stop():
            try:
                import openapi_auth as oa
                openapi_info = oa.ingest_openapi(
                    client, url, state, wx.Finding,
                    openapi_url=(wx.ensure_scheme(openapi_url) if openapi_url else None),
                )
                if openapi_info.get("found"):
                    print(f"[+] OpenAPI/Swagger ingested {openapi_info['endpoints']} endpoint(s) from {openapi_info['spec_url']}")
            except Exception as e:
                print(f"[!] OpenAPI ingestion error: {e}")

        if do_audit and not state.should_stop():
            run_module("misconfig-audit", wx.MisconfigAudit(client, state).run, url)

        if do_crawl and not state.should_stop():
            seeds = wx.discover_seeds(client, url, state, expand_root=True,
                                      probe_paths=True)
            wx.Crawler(client, state, max_depth=depth,
                       max_urls=max_urls).run(url, seeds=seeds)
            state.crawled_urls.add(url)
        else:
            state.crawled_urls.add(url)
            if not do_crawl:
                state.note("Crawling disabled: only the given URL was tested")
        if do_param_fuzz and not state.should_stop():
            run_module("param-discovery", wx.ParamFuzzer(client, state).run)
        if do_sqli and not state.should_stop():
            run_module("sqli", wx.SqliScanner(client, state, time_delay=time_blind).run)
        if do_xss and not state.should_stop():
            try:
                import xss_deep as xd
                deep = xd.DeepXssScanner(
                    client, state, wx.Finding,
                    payload_limit=int(modules.get("xss_payload_limit") or 14),
                    brute=bool(modules.get("xss_brute")),
                    brute_limit=int(modules.get("xss_brute_limit") or 250),
                    test_headers=modules.get("xss_headers", True),
                    stored_sweep=modules.get("xss_stored", True),
                    dom_analysis=modules.get("xss_dom", True),
                )
                run_module("xss-deep", deep.run)
                state.xss_deep = deep.stats()
            except Exception as e:
                print(f"[!] deep XSS engine unavailable ({type(e).__name__}: {e}) "
                      f"— falling back to legacy XSS")
                run_module("xss", wx.XssScanner(client, state).run)
        if do_dirs and not state.should_stop():
            wordlist = wx.load_wordlist(wordlist_path)
            run_module("dirbuster",
                       wx.DirBuster(client, state, wordlist).run, url)
        if do_templates and not state.should_stop():
            try:
                import templates_engine as te
                run_module("yaml-templates", te.run_templates, client, url, state, wx.Finding)
            except Exception as e:
                print(f"[!] yaml-templates module failed: {type(e).__name__}: {e}")
        if do_advanced and not state.should_stop():
            adv = wx.AdvancedScanner(client, state)
            for nm, fn in (("lfi", adv.scan_lfi), ("ssti", adv.scan_ssti),
                           ("cmdi", adv.scan_cmdi),
                           ("open-redirect", adv.scan_open_redirect),
                           ("cors", adv.scan_cors), ("crlf", adv.scan_crlf),
                           ("dir-listing", adv.scan_dir_listing),
                           ("js-libs", adv.scan_js_libs),
                           ("sensitive-data", adv.scan_sensitive),
                           ("known-cves", adv.scan_known_vulns),
                           ("csrf", adv.scan_csrf), ("xxe", adv.scan_xxe),
                           ("ssrf", adv.scan_ssrf),
                           ("host-header", adv.scan_host_header),
                           ("jwt", adv.scan_jwt),
                           ("stored-xss", adv.scan_stored_xss)):
                if state.should_stop():
                    break
                run_module(nm, fn)
        if do_default_creds and not state.should_stop():
            run_module("default-creds",
                       wx.AdvancedScanner(client, state).scan_default_creds)
        if (do_advanced or do_audit) and not state.should_stop():
            try:
                import js_security as jsec
                for jf in jsec.analyze_js_and_auth_surface(probe.url or url, probe.text or "", dict(probe.headers)):
                    state.add(wx.Finding(
                        vuln_type=jf["vuln_type"], severity=jf["severity"],
                        url=jf["url"], parameter=jf["parameter"],
                        payload=jf.get("payload", ""), evidence=jf["evidence"],
                        detail=jf["detail"], cvss_hint=jf.get("cvss_hint", 0.0),
                        confidence=jf.get("confidence", 0.78),
                        cwe=jf.get("cwe", "CWE-79"),
                        remediation=jf.get("remediation", ""),
                    ))
            except Exception as e:
                print(f"[!] js-security module failed: {type(e).__name__}: {e}")
        if (do_advanced or do_audit or do_dirs) and not state.should_stop():
            try:
                import worldscan as ws
                run_module("world-surface",
                           ws.WorldScanner(client, state, wx.Finding).run)
            except Exception as e:
                print(f"[!] world-surface module failed: {type(e).__name__}: {e}")
        if do_templates and not state.should_stop():
            try:
                import plugin_mgr as pm
                for pf in pm.execute_enabled_plugins(client, url):
                    state.findings.append(wx.Finding(
                        vuln_type=pf["vuln_type"], severity=pf["severity"],
                        url=pf["url"], parameter=pf["parameter"],
                        evidence=pf["evidence"], detail=pf["remediation"],
                    ))
            except Exception as e:
                print(f"[!] signed plugins failed: {type(e).__name__}: {e}")

    # ---- coverage + honest diagnosis of an empty result -------------------
    st = client.stats
    total = max(st["requests"], 1)
    block_ratio = (st["blocked"] + st["errors"]) / total
    n_params = sum(len(v) for v in state.params.values())
    state.tests_run = st["requests"]

    if st["waf_hits"] >= 5 or (st["waf_hits"] / total) > 0.10 or block_ratio > 0.35:
        state.degraded = True
        msg = (f"SCAN DEGRADED — {st['waf_hits']} WAF/challenge page(s), "
               f"{round(block_ratio * 100)}% of {st['requests']} requests were "
               f"blocked or failed. A clean result here is NOT proof the site "
               f"is secure.")
        state.note(msg)
        state.findings.append(wx.Finding(
            vuln_type="Scan degraded — WAF / rate-limit blocking", severity="Info",
            url=url,
            evidence=f"{st['blocked']} blocked, {st['errors']} errors, "
                     f"{st['waf_hits']} WAF pages of {st['requests']} requests",
            detail="Re-run with delay=0.5, a browser User-Agent, authenticated "
                   "cookies, or from an allowed source IP."))
    if len(state.crawled_urls) <= 2 and n_params == 0 and not state.forms:
        msg = (f"NO ATTACK SURFACE FOUND — only {len(state.crawled_urls)} URL(s) "
               f"reachable, 0 parameters, 0 forms: injection modules had nothing "
               f"to test (SPA/JS app, auth wall, or blocked crawl).")
        state.note(msg)
        state.findings.append(wx.Finding(
            vuln_type="No attack surface discovered (nothing was testable)",
            severity="Info", url=url,
            evidence=f"urls={len(state.crawled_urls)} forms={len(state.forms)} "
                     f"params={n_params} requests={st['requests']}",
            detail="Scan the site ROOT url, raise depth/max_urls, pass session "
                   "cookies, enable dir brute-force, or target a URL that "
                   "already has query parameters."))

    counts: Dict[str, int] = {}
    for f in state.findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    actionable = [f for f in state.findings if f.severity != "Info"]

    enriched_findings = [_enrich_finding_dict(asdict(f), default_method="HTTP")
                         for f in state.findings]
    tls_sum = getattr(state, "tls_summary", {}) or {}
    tls_intel = {}
    if tls_sum:
        try:
            import tls_audit as ta
            tls_findings = [f for f in enriched_findings if "TLS" in (f.get("vuln_type") or "") or "HSTS" in (f.get("vuln_type") or "")]
            tls_intel = ta.build_tls_intelligence(tls_sum, tls_findings)
        except Exception:
            pass
    return {
        "target": url,
        "debug": debug,
        "stopped_early": bool(state.stopped_early or (stop_event is not None and stop_event.is_set())),
        "auth_info": auth_info,
        "openapi_info": openapi_info,
        "stats": {
            "urls_crawled": len(state.crawled_urls),
            "forms": len(state.forms),
            "parameters": n_params,
            "findings": len(state.findings),
            "actionable": len(actionable),
            "by_severity": counts,
            "seed_urls": state.seeds_used,
            "modules_run": state.modules_run,
            "requests_sent": st["requests"],
            "connection_errors": st["errors"],
            "blocked_responses": st["blocked"],
            "waf_challenge_pages": st["waf_hits"],
            "status_codes": st["statuses"],
            "requests_by_module": st["by_module"],
            "degraded": state.degraded,
            "duration_s": round(time.time() - state.start_ts, 2),
        },
        "coverage": state.coverage(),
        "diagnostics": state.diagnostics,
        "tech_stack": getattr(state, "tech_stack", []) or [],
        "tls_summary": tls_sum,
        "tls_intelligence": tls_intel,
        "findings": enriched_findings,
        "xss_deep": getattr(state, "xss_deep", {}) or {},
        "log": cap.text,
    }


# ---------------------------------------------------------------------------
# HashBreaker
# ---------------------------------------------------------------------------
def generate_hash(text: str, algo: str = "md5", salt: str = "") -> Dict:
    import hashbreaker as hb
    a = (algo or "md5").strip().lower()
    if a == "all":
        algos = ["md5", "sha1", "sha256", "sha512", "sha3-256", "ntlm", "mysql5"]
        return {
            "text": text,
            "hashes": {k: hb.compute(k, text, salt) for k in algos},
        }
    return {"text": text, "algo": a, "hash": hb.compute(a, text, salt)}


def identify_hashes(hashes: List[str]) -> Dict:
    import hashbreaker as hb

    out = []
    for h in hashes:
        hi = hb.identify_hash(h.strip())
        out.append(asdict(hi))
    return {"results": out}


def crack_hashes(hashes: List[str], words: Optional[List[str]] = None,
                 rules: bool = True, mask: Optional[str] = None,
                 algo: Optional[str] = None, salt: Optional[str] = None,
                 wordlist_path: Optional[str] = None,
                 workers: Optional[int] = None,
                 stop_event=None) -> Dict:
    import hashbreaker as hb

    def _count_lines(p: str) -> int:
        n = 0
        with open(p, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                n += chunk.count(b"\n")
        return n

    stream = None
    wl_name = "inline word list"
    wl_words = len(words) if words else 0
    if not words and wordlist_path:
        if not Path(wordlist_path).is_file():
            return {"error": f"wordlist not found: {wordlist_path}"}
        wl_name = Path(wordlist_path).name
        wl_words = _count_lines(wordlist_path)

        def _lines(p=wordlist_path):
            # streamed lazily — rockyou.txt is ~139 MB / 14.3 M lines and
            # must never be loaded into RAM as a list of Python strings
            with open(p, "r", encoding="utf-8", errors="ignore") as fh:
                for ln in fh:
                    yield ln.rstrip("\r\n")

        stream = _lines()
    if not words and stream is None and not mask:
        return {"error": "provide words (or a wordlist file) and/or a mask"}

    # Mangling rules multiply every word ~10x. On a 14 M-word list that means
    # 100 M+ attempts (hours), so rules are auto-disabled for big wordlists.
    use_rules = bool(rules)
    rules_note = None
    if use_rules and wl_words > 250_000:
        use_rules = False
        rules_note = (f"Rules auto-disabled: mangling {wl_words:,} words would "
                      f"need 100M+ attempts. Raw wordlist is used instead.")

    targets = []
    identified = []
    for h in hashes:
        raw = h.strip()
        hi = hb.identify_hash(raw)
        identified.append({"hash": raw, "type": hi.name,
                           "candidates": hi.candidates, "length": hi.length})
        t = hb.Target(hash_str=raw)
        hb.resolve_algos(t, algo)
        if salt and not t.salt:
            t.salt = salt
        targets.append(t)

    cracker = hb.Cracker(
        targets=targets, wordlist=(words if words else stream), workers=workers,
        use_rules=use_rules, mask=mask, stop_event=stop_event,
    )
    t0 = time.time()
    with _Capture() as cap:
        try:
            cracker.run()
        except KeyboardInterrupt:
            pass
    elapsed = max(time.time() - t0, 0.001)
    rate = int(cracker.attempts / elapsed)

    cracked_map = {c["hash_str"]: c for c in cracker.cracked}
    results = []
    for t, info_ in zip(targets, identified):
        c = cracked_map.get(t.hash_str)
        results.append({
            "hash": t.hash_str,
            "hash_type": info_["type"],
            "candidates": info_["candidates"],
            "used_algo": (c or {}).get("algo") or t.algo,
            "tried_algos": getattr(t, "candidate_algos", None) or [t.algo],
            "salt": t.salt or None,
            "cracked": bool(c),
            "password": (c or {}).get("plain"),
            "attempts": (c or {}).get("attempts"),
            "not_found_reason": None if c else (
                "Password is not present in this wordlist "
                f"({wl_words:,} words tried, {cracker.attempts:,} candidate "
                "hashes computed). It may be salted, a strong/random password, "
                "or not a plain unsalted hash of a password at all."),
        })

    n_cracked = len(cracker.cracked)
    summary = {
        "wordlist": wl_name,
        "wordlist_words": wl_words,
        "rules": use_rules,
        "rules_note": rules_note,
        "attempts": cracker.attempts,
        "rate_hps": rate,
        "duration_s": round(elapsed, 2),
        "cracked_count": n_cracked,
        "total": len(targets),
    }
    if n_cracked == len(targets) and n_cracked:
        summary["verdict"] = "ALL HASHES CRACKED ✅"
    elif n_cracked:
        summary["verdict"] = f"PARTIAL — {n_cracked}/{len(targets)} cracked"
    else:
        summary["verdict"] = (
            "NOT CRACKED — the plaintext is not in this wordlist. "
            "Next steps: try the rockyou wordlist (14.3 M words), enable rules "
            "on a smaller list, run a mask attack (?l?l?l?l?d?d), supply the "
            "salt if the format is salted, or move to hashcat on a GPU.")

    password_audit = {}
    try:
        password_audit = hb.build_password_audit_report(targets, cracker.cracked)
    except Exception:
        pass
    return {
        "results": results,
        "summary": summary,
        "password_audit": password_audit,
        "targets": [asdict(t) for t in targets],
        "cracked": cracker.cracked,
        "attempts": cracker.attempts,
        "log": cap.text,
    }


def benchmark() -> Dict:
    import hashbreaker as hb

    with _Capture() as cap:
        hb.benchmark()
    return {"log": cap.text}


# ---------------------------------------------------------------------------
# NetSentry
# ---------------------------------------------------------------------------
def run_monitor_demo(syn_threshold: int = 25) -> Dict:
    import netsentry as ns

    if not ns.SCAPY_OK:
        return {"error": "scapy is not installed (pip install scapy)"}

    bus = ns.AlertBus(log_path=None, quiet=True)
    engine = ns.NetSentry(bus, gateway="192.168.1.1", syn_threshold=syn_threshold)
    with _Capture() as cap:
        ns.run_demo(None, engine)   # synthetic attack traffic (no root needed)
    return {
        "summary": engine.summary(),
        "alerts": [asdict(a) for a in bus.alerts],
        "log": cap.text,
    }


def run_monitor_pcap(pcap_path: str, syn_threshold: int = 25,
                     gateway: Optional[str] = None) -> Dict:
    import netsentry as ns

    if not ns.SCAPY_OK:
        return {"error": "scapy is not installed (pip install scapy)"}

    bus = ns.AlertBus(log_path=None, quiet=True)
    engine = ns.NetSentry(bus, gateway=gateway, syn_threshold=syn_threshold)
    with _Capture() as cap:
        packets = ns.rdpcap(pcap_path)
        for pkt in packets:
            engine.handle(pkt)
    return {
        "packets": len(packets),
        "summary": engine.summary(),
        "alerts": [asdict(a) for a in bus.alerts],
        "log": cap.text,
    }


def run_monitor_live(seconds: int = 10, iface: Optional[str] = None,
                     gateway: Optional[str] = None, bpf: str = "",
                     syn_threshold: int = 25) -> Dict:
    import netsentry as ns

    if not ns.SCAPY_OK:
        return {"error": "scapy is not installed (pip install scapy)"}

    bus = ns.AlertBus(log_path=None, quiet=True)
    engine = ns.NetSentry(bus, gateway=gateway, syn_threshold=syn_threshold)
    with _Capture() as cap:
        try:
            ns.sniff(
                filter=bpf or None, iface=iface or None,
                prn=engine.handle, store=False, timeout=seconds,
            )
        except PermissionError:
            return {"error": "Permission denied — live capture needs root "
                             "(Linux) or Administrator + Npcap (Windows)."}
        except Exception as e:
            return {"error": f"capture failed: {type(e).__name__}: {e}"}
    return {
        "summary": engine.summary(),
        "alerts": [asdict(a) for a in bus.alerts],
        "log": cap.text,
    }


# ---------------------------------------------------------------------------
# DARK Enterprise v3 Modules (Cloud, Container/SBOM, SAST, API, Forensics)
# ---------------------------------------------------------------------------
def run_cloud_audit(provider: str = "aws", content: str = "",
                    target_path: Optional[str] = None) -> Dict:
    import cloud_audit as ca
    with _Capture() as cap:
        res = ca.audit_cloud_config(provider=provider, content=content, target_path=target_path)
    res["findings"] = [_enrich_finding_dict(f, default_method="Cloud Audit")
                       for f in (res.get("findings") or [])]
    res["log"] = cap.text
    return res


def run_container_audit(content: str = "", target_path: Optional[str] = None,
                        manifest_kind: str = "auto") -> Dict:
    import container_audit as cta
    with _Capture() as cap:
        res = cta.audit_container_and_sbom(content=content, target_path=target_path, kind=manifest_kind)
    res["findings"] = [_enrich_finding_dict(f, default_method="Container/SBOM")
                       for f in (res.get("findings") or [])]
    res["log"] = cap.text
    return res


def run_sast_audit(code: str = "", target_path: Optional[str] = None,
                   language: str = "auto") -> Dict:
    import sast_audit as sa
    with _Capture() as cap:
        res = sa.scan_sast(code=code, target_path=target_path, language=language)
    res["findings"] = [_enrich_finding_dict(f, default_method="SAST")
                       for f in (res.get("findings") or [])]
    res["log"] = cap.text
    return res


def run_api_audit(url: str, openapi_url: Optional[str] = None,
                  spec_json: Optional[str] = None,
                  auth_header: Optional[str] = None,
                  check_graphql: bool = True) -> Dict:
    import api_audit as aa
    with _Capture() as cap:
        res = aa.run_api_audit(
            url=url, openapi_url=openapi_url, spec_json=spec_json,
            auth_header=auth_header, check_graphql=check_graphql,
        )
    res["findings"] = [_enrich_finding_dict(f, default_method="API Audit")
                       for f in (res.get("findings") or [])]
    res["log"] = cap.text
    return res


def run_forensics_audit(log_text: str = "", log_type: str = "auto",
                        custom_iocs: Optional[List[str]] = None,
                        pcap_path: Optional[str] = None) -> Dict:
    import forensics as fx
    with _Capture() as cap:
        res = fx.analyze_forensics(
            log_text=log_text, log_type=log_type,
            custom_iocs=custom_iocs, pcap_path=pcap_path,
        )
    res["findings"] = [_enrich_finding_dict(f, default_method="Digital Forensics")
                       for f in (res.get("findings") or [])]
    res["log"] = cap.text
    return res


# ---------------------------------------------------------------------------
# DARK v4.0 Expanded Domain Runners & Centralized Intelligence Engine
# ---------------------------------------------------------------------------
def run_secrets_scan(content: str = "", target_path: Optional[str] = None) -> Dict:
    import secrets_scanner as ss
    with _Capture() as cap:
        res = ss.scan_secrets(content=content, target_path=target_path)
    res["findings"] = [_enrich_finding_dict(f, default_method="Secrets Detection")
                       for f in (res.get("findings") or [])]
    res["log"] = cap.text
    return res


def run_threat_hunt(events: Optional[List[Dict]] = None, raw_logs: str = "",
                    custom_iocs: Optional[List[str]] = None) -> Dict:
    import threat_hunting as th
    with _Capture() as cap:
        res = th.run_threat_hunt(telemetry_text=raw_logs, events=events, custom_iocs=custom_iocs)
    res["findings"] = [_enrich_finding_dict(f, default_method="Threat Hunting")
                       for f in (res.get("findings") or [])]
    res["log"] = cap.text
    return res


def run_malware_triage(file_path: Optional[str] = None, content_b64: str = "",
                       filename: str = "sample.bin") -> Dict:
    import base64
    import malware_analysis as ma_mod
    raw_bytes = base64.b64decode(content_b64) if content_b64 else None
    with _Capture() as cap:
        res = ma_mod.analyze_sample(data=raw_bytes, file_path=file_path, sample_name=filename)
    res["findings"] = [_enrich_finding_dict(f, default_method="Malware Static Triage")
                       for f in (res.get("findings") or [])]
    res["log"] = cap.text
    return res


def run_phishing_analyze(raw_eml: str) -> Dict:
    import phishing_analyzer as pa
    with _Capture() as cap:
        res = pa.analyze_email(raw_eml=raw_eml)
    res["findings"] = [_enrich_finding_dict(f, default_method="Phishing & Email Analysis")
                       for f in (res.get("findings") or [])]
    res["log"] = cap.text
    return res


def run_ad_audit(snapshot: Optional[Dict] = None, raw_json: str = "") -> Dict:
    import ad_audit as ada
    with _Capture() as cap:
        res = ada.audit_ad_snapshot(snapshot=snapshot, raw_json=raw_json)
    res["findings"] = [_enrich_finding_dict(f, default_method="Active Directory Audit")
                       for f in (res.get("findings") or [])]
    res["log"] = cap.text
    return res


def run_wireless_audit(aps: Optional[List[Dict]] = None, raw_json: str = "") -> Dict:
    import wireless_audit as wa
    with _Capture() as cap:
        res = wa.audit_wireless_inventory(aps=aps, raw_json=raw_json)
    res["findings"] = [_enrich_finding_dict(f, default_method="Wireless Security Assessment")
                       for f in (res.get("findings") or [])]
    res["log"] = cap.text
    return res


def run_intel_hub(jobs: List[Dict]) -> Dict:
    import intel_hub as ih
    return ih.ingest_jobs_into_hub(jobs)


def run_identity_audit(snapshot: Optional[Dict] = None, raw_json: str = "",
                       stale_days_threshold: int = 90) -> Dict:
    import identity_security as idsec
    with _Capture() as cap:
        res = idsec.audit_identity_posture(
            snapshot=snapshot, raw_json=raw_json,
            stale_days_threshold=stale_days_threshold,
        )
    res["findings"] = [_enrich_finding_dict(f, default_method="Identity Security")
                       for f in (res.get("findings") or [])]
    res["log"] = cap.text
    return res


def run_malware_sandbox(trace: Optional[Dict] = None, content_b64: str = "",
                        filename: str = "sample.bin") -> Dict:
    import base64
    import malware_sandbox as msb
    raw = base64.b64decode(content_b64) if content_b64 else None
    with _Capture() as cap:
        res = msb.analyze_sandbox_telemetry(trace=trace, sample_data=raw, sample_name=filename)
    res["findings"] = [_enrich_finding_dict(f, default_method="Malware Dynamic Sandbox")
                       for f in (res.get("findings") or [])]
    res["log"] = cap.text
    return res
