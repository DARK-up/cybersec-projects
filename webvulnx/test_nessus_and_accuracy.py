#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Verification suite for Nessus plugins, Soft-404 calibration, and FP controls."""
from __future__ import annotations

import asyncio
import http.server
import socketserver
import sys
import threading
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "webvulnx"))
sys.path.insert(0, str(ROOT / "netrecon"))

import nessus_plugins as np
import vuln_plugins as nvp
import webvulnx as wx


def test_nessus_web_plugins():
    pages = [{
        "url": "https://example.test/",
        "headers": {"Server": "Apache/2.4.49 (Ubuntu)", "X-Powered-By": "PHP/7.4.3"},
        "body": (
            '<html><head><meta name="generator" content="WordPress 5.8.2">'
            '<script src="/js/jquery-3.4.1.min.js"></script>'
            '<script src="/js/lodash-4.17.20.min.js"></script>'
            '</head><body>/wp-content/plugins/contact-form-7/a.js?ver=5.5</body></html>'
        ),
    }]
    stack = np.fingerprint_from_responses(pages)
    prods = {s["product"]: s["version"] for s in stack}
    assert prods.get("Apache HTTP Server") == "2.4.49", prods
    assert prods.get("PHP") == "7.4.3", prods
    assert prods.get("WordPress") == "5.8.2", prods
    assert prods.get("jQuery") == "3.4.1", prods
    assert prods.get("Lodash") == "4.17.20", prods

    # Check safe versions DO NOT match CVEs
    v_safe = np.parse_ver("2.4.62")
    assert not any(
        p.product == "Apache HTTP Server" and np.ver_in_range(v_safe, p.min_ver, p.max_exc)
        for p in np.WEB_CVE_PLUGINS
    ), "Apache 2.4.62 should not match CVEs"
    v_vuln = np.parse_ver("2.4.49")
    matched = [p.plugin_id for p in np.WEB_CVE_PLUGINS
               if p.product == "Apache HTTP Server" and np.ver_in_range(v_vuln, p.min_ver, p.max_exc)]
    assert "DARK-WEB-1001" in matched, matched
    print("  OK   Nessus Web Tech Fingerprinter & semantic CVE range matching")


def test_nessus_net_plugins():
    class P:
        def __init__(self, port, service, version="", banner=""):
            self.port, self.service, self.version, self.banner = port, service, version, banner

    ports = [
        P(22, "SSH", "2.0 OpenSSH_9.6p1", "SSH-2.0-OpenSSH_9.6p1 Ubuntu"),
        P(6379, "Redis", "", "+PONG"),
        P(23, "Telnet", "", ""),
    ]
    vulns = asyncio.run(nvp.evaluate_host("127.0.0.1", ports, timeout=1.0))
    pids = {v["plugin_id"] for v in vulns}
    assert "DARK-NET-1001" in pids, pids   # regreSSHion 9.6p1
    assert "DARK-NET-2101" in pids, pids   # Redis +PONG unauth
    assert "DARK-NET-2001" in pids, pids   # Telnet exposed

    # Verify OpenSSH 9.8p1 does NOT trigger regreSSHion
    safe_vulns = asyncio.run(nvp.evaluate_host(
        "127.0.0.1", [P(22, "SSH", "2.0 OpenSSH_9.8p1", "SSH-2.0-OpenSSH_9.8p1")], timeout=1.0
    ))
    assert not any(v["plugin_id"] == "DARK-NET-1001" for v in safe_vulns), safe_vulns
    print("  OK   NetRecon Nessus-style service CVE & unauth plugins")


def test_soft404_and_dynamic_stability():
    class SpaHandler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            # Dynamic timestamp + nonce + catch-all 200 HTML SPA response for any path
            if self.path.startswith("/real-secret.txt"):
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"TOP_SECRET_CONFIG=1\n")
                return
            tok = uuid.uuid4().hex
            body = (
                f"<!doctype html><html><head>"
                f"<script src='https://cdn.example.com/app.js'></script></head>"
                f"<body><h1>App Shell</h1><span data-ts='{time.time()}' data-n='{tok}'></span>"
                f"</body></html>"
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(body)

        def do_TRACE(self):
            self.send_response(501)
            self.end_headers()

        def do_PUT(self):
            self.do_GET()

        def do_DELETE(self):
            self.do_GET()

    srv = socketserver.TCPServer(("127.0.0.1", 0), SpaHandler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        base = f"http://127.0.0.1:{port}/"
        client = wx.HttpClient(timeout=3.0, stealth=True, target=base)
        state = wx.ScanState(base_url=base, start_ts=time.time())

        # 1. DirBuster soft-404 calibration MUST filter fake catch-all 200s,
        #    while keeping genuinely different real files.
        db = wx.DirBuster(client, state, ["admin", "login", ".env", "backup.zip", "real-secret.txt"])
        db.run(base)
        urls = [f.url for f in state.findings]
        assert any("real-secret.txt" in u for u in urls), f"missed real file: {urls}"
        assert not any("admin" in u or ".env" in u or "backup.zip" in u for u in urls), f"Soft-404 FP: {urls}"

        # 2. MisconfigAudit must NOT flag 501 TRACE or catch-all PUT/DELETE,
        #    and SHOULD flag missing SRI on external CDN script.
        state2 = wx.ScanState(base_url=base, start_ts=time.time())
        wx.MisconfigAudit(client, state2).run(base)
        vtypes = [f.vuln_type for f in state2.findings]
        assert "Dangerous HTTP Method Enabled" not in vtypes, vtypes
        assert "Missing Subresource Integrity (SRI) on CDN Asset" in vtypes, vtypes

        # 3. SqliScanner on noisy dynamic page must NOT emit Boolean-blind SQLi FP
        state3 = wx.ScanState(base_url=base, start_ts=time.time())
        wx.SqliScanner(client, state3, time_delay=None).scan_params(base + "?id=1", ["id"], "GET")
        assert not state3.findings, f"Dynamic page SQLi FP: {state3.findings}"

        print("  OK   Soft-404 filter + HTTP 501/catch-all FP elimination + Dynamic SQLi stability")
    finally:
        srv.shutdown()
        srv.server_close()


if __name__ == "__main__":
    print("Running Nessus & Real-World Accuracy Tests...")
    test_nessus_web_plugins()
    test_nessus_net_plugins()
    test_soft404_and_dynamic_stability()
    print("ALL ACCURACY & NESSUS TESTS PASSED")
