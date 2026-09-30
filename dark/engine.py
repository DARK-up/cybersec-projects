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
import contextlib
import io
import sys
import time
from dataclasses import asdict
from pathlib import Path
from typing import Dict, List, Optional

ROOT = Path(__file__).resolve().parent.parent
for _tool in ("netrecon", "webvulnx", "hashbreaker", "netsentry"):
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


class _Capture:
    """Capture a tool's console output so the API can return it as a log."""

    def __init__(self):
        self.buf = io.StringIO()

    def __enter__(self):
        self._stdout, self._stderr = sys.stdout, sys.stderr
        sys.stdout = sys.stderr = self.buf
        return self

    def __exit__(self, *exc):
        sys.stdout, sys.stderr = self._stdout, self._stderr
        return False

    @property
    def text(self) -> str:
        return self.buf.getvalue()


# ---------------------------------------------------------------------------
# NetRecon
# ---------------------------------------------------------------------------
def run_network_scan(targets: List[str], ports: str = "top100", timing: str = "normal",
                     probe: bool = True, discover: bool = False) -> Dict:
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
    )
    with _Capture() as cap:
        asyncio.run(scanner.run())
    return {"report": scanner.to_dict(), "log": cap.text}


# ---------------------------------------------------------------------------
# WebVulnX
# ---------------------------------------------------------------------------
def run_web_scan(url: str, modules: Optional[Dict[str, bool]] = None,
                 depth: int = 3, max_urls: int = 80, timeout: float = 10.0,
                 delay: float = 0.0, time_blind: float = 5.0,
                 wordlist_path: Optional[str] = None,
                 cookie: Optional[str] = None, proxy: Optional[str] = None) -> Dict:
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

    url = wx.ensure_scheme(url)
    cookies = {}
    if cookie:
        for part in cookie.split(";"):
            if "=" in part:
                k, _, v = part.partition("=")
                cookies[k.strip()] = v.strip()

    client = wx.HttpClient(timeout=timeout, delay=delay, cookies=cookies, proxy=proxy)
    state = wx.ScanState(base_url=url, start_ts=time.time())

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
        client.module = name
        state.modules_run.append(name)
        try:
            return fn(*a, **kw)
        except Exception as e:      # one broken module must not kill the scan
            print(f"[!] module {name} crashed: {type(e).__name__}: {e}")
            state.note(f"Module {name} failed: {type(e).__name__}: {e}")
            return None

    seeds = [url]
    with _Capture() as cap:
        if do_crawl:
            seeds = wx.discover_seeds(client, url, state, expand_root=True,
                                      probe_paths=True)
            wx.Crawler(client, state, max_depth=depth,
                       max_urls=max_urls).run(url, seeds=seeds)
            state.crawled_urls.add(url)
        else:
            state.crawled_urls.add(url)
            state.note("Crawling disabled: only the given URL was tested")
        if do_param_fuzz:
            run_module("param-discovery", wx.ParamFuzzer(client, state).run)
        if do_audit:
            run_module("misconfig-audit", wx.MisconfigAudit(client, state).run, url)
        if do_sqli:
            run_module("sqli", wx.SqliScanner(client, state, time_delay=time_blind).run)
        if do_xss:
            run_module("xss", wx.XssScanner(client, state).run)
        if do_dirs:
            wordlist = wx.load_wordlist(wordlist_path)
            run_module("dirbuster",
                       wx.DirBuster(client, state, wordlist).run, url)
        if do_advanced:
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
                run_module(nm, fn)
        if do_default_creds:
            run_module("default-creds",
                       wx.AdvancedScanner(client, state).scan_default_creds)

    # ---- coverage + honest diagnosis of an empty result -------------------
    st = client.stats
    total = max(st["requests"], 1)
    block_ratio = (st["blocked"] + st["errors"]) / total
    n_params = sum(len(v) for v in state.params.values())
    state.tests_run = st["requests"]

    if st["waf_hits"] or block_ratio > 0.35:
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

    return {
        "target": url,
        "debug": debug,
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
        "findings": [asdict(f) for f in state.findings],
        "log": cap.text,
    }


# ---------------------------------------------------------------------------
# HashBreaker
# ---------------------------------------------------------------------------
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
                 workers: Optional[int] = None) -> Dict:
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
        use_rules=use_rules, mask=mask,
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
            "used_algo": t.algo,
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

    return {
        "results": results,
        "summary": summary,
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
