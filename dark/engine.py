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

    with _Capture() as cap:
        if do_crawl:
            wx.Crawler(client, state, max_depth=depth, max_urls=max_urls).run(url)
            state.crawled_urls.add(url)
        else:
            state.crawled_urls.add(url)
        if do_audit:
            wx.MisconfigAudit(client, state).run(url)
        if do_sqli:
            wx.SqliScanner(client, state, time_delay=time_blind).run()
        if do_xss:
            wx.XssScanner(client, state).run()
        if do_dirs:
            wordlist = wx.load_wordlist(wordlist_path)
            wx.DirBuster(client, state, wordlist).run(url)

    counts: Dict[str, int] = {}
    for f in state.findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    return {
        "target": url,
        "stats": {
            "urls_crawled": len(state.crawled_urls),
            "forms": len(state.forms),
            "findings": len(state.findings),
            "by_severity": counts,
        },
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

    if not words and wordlist_path:
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as fh:
            words = fh.readlines()
    if not words and not mask:
        return {"error": "provide words (or a wordlist file) and/or a mask"}

    targets = []
    for h in hashes:
        t = hb.Target(hash_str=h.strip())
        hb.resolve_algos(t, algo)
        if salt and not t.salt:
            t.salt = salt
        targets.append(t)

    cracker = hb.Cracker(
        targets=targets, wordlist=words or [], workers=workers,
        use_rules=rules, mask=mask,
    )
    with _Capture() as cap:
        try:
            cracker.run()
        except KeyboardInterrupt:
            pass

    return {
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
