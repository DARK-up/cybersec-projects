#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit & Integration Tests for WebVulnX v4.0 (Phases 5-6):
  - Centralized YAML Payload Management System + safe_scope gating
  - Multi-signal SQLi / XSS (CSP audit, JSON anti-FP) / LFI / SSTI / CMDi / XXE / SSRF
  - Safe canary verification against local demo-lab VulnHandler
"""
from __future__ import annotations

import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
for p in (str(ROOT / "webvulnx"), str(ROOT / "demo-lab"), str(ROOT / "dark")):
    if p not in sys.path:
        sys.path.insert(0, p)

import payload_mgr as pm  # noqa: E402
import ssrf_scanner as ssrf_mod  # noqa: E402
import webvulnx as wx  # noqa: E402
import xss_deep as xd  # noqa: E402
import vuln_app as demo_lab  # noqa: E402


def test_yaml_payload_catalog_and_safe_scoping():
    summary = pm.catalog_summary()
    assert summary["total"] >= 20
    for cat in ("sqli", "xss", "lfi", "ssti", "ssrf", "xxe", "cmdi", "redirect"):
        assert cat in summary["categories"] and summary["categories"][cat] >= 2

    # External public target MUST NOT receive demo_lab_only payloads when safe_only=True
    ext_lfi = pm.get_payloads("lfi", target_url="https://public.example.com/view?file=a", safe_only=True)
    assert all(p.get("safe_scope") != "demo_lab_only" for p in ext_lfi)
    assert any("dark_canary.txt" in p["payload"] for p in ext_lfi)

    # Local demo-lab target CAN use demo_lab_only payloads
    lab_lfi = pm.get_payloads("lfi", target_url="http://127.0.0.1:8080/lfi?file=a", safe_only=True)
    assert len(lab_lfi) > len(ext_lfi)


def test_csp_audit_and_json_anti_fp():
    strict = xd.audit_csp({"Content-Security-Policy": "default-src 'self'; script-src 'self' 'nonce-abc123'"})
    assert strict["present"] and strict["blocks_inline"] is True

    weak = xd.audit_csp({"Content-Security-Policy": "default-src *; script-src 'self' 'unsafe-inline'"})
    assert weak["present"] and weak["blocks_inline"] is False and weak["allows_unsafe_inline"] is True

    # JSON response reflecting <script> must NOT trigger XssScanner finding
    class _JsonReflect(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"echo":"<script>alert(\\"XSS\\")</script>"}')

    srv = HTTPServer(("127.0.0.1", 0), _JsonReflect)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        client = wx.HttpClient(stealth=False)
        state = wx.ScanState(base_url=f"http://127.0.0.1:{port}")
        state.params[f"http://127.0.0.1:{port}/api?q=hi"] = {"q"}
        wx.XssScanner(client, state).run()
        assert len(state.findings) == 0
    finally:
        srv.shutdown()


def test_safe_canaries_against_demo_lab_and_ssrf_module():
    srv = HTTPServer(("127.0.0.1", 0), demo_lab.VulnHandler)
    port = srv.server_address[1]
    base = f"http://127.0.0.1:{port}"
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        client = wx.HttpClient(stealth=False, timeout=5.0)
        state = wx.ScanState(base_url=base)
        state.crawled_urls.update({
            f"{base}/lfi?file=index.php",
            f"{base}/tpl?name=guest",
            f"{base}/ping?host=127.0.0.1",
            f"{base}/xxe",
            f"{base}/fetch?url=http://example.com",
            f"{base}/page?id=1",
        })
        state.params[f"{base}/lfi?file=index.php"] = {"file"}
        state.params[f"{base}/tpl?name=guest"] = {"name"}
        state.params[f"{base}/ping?host=127.0.0.1"] = {"host"}
        state.params[f"{base}/fetch?url=http://example.com"] = {"url"}
        state.params[f"{base}/page?id=1"] = {"id"}

        wx.SqliScanner(client, state, time_delay=None).run()
        adv = wx.AdvancedScanner(client, state)
        adv.scan_lfi()
        adv.scan_ssti()
        adv.scan_cmdi()
        adv.scan_xxe()
        adv.scan_ssrf()

        types = {f.vuln_type for f in state.findings}
        assert "SQL Injection (Error-Based)" in types
        assert "Local File Inclusion / Path Traversal" in types
        assert "Server-Side Template Injection (SSTI)" in types
        assert "OS Command Injection" in types
        assert "XML External Entity (XXE)" in types
        assert "Server-Side Request Forgery (SSRF)" in types

        # Verify confidence & CWE metadata populated on confirmed findings
        for f in state.findings:
            assert f.confidence >= 0.85
            assert f.verification_status == "Confirmed"
            assert f.cwe.startswith("CWE-")
            assert f.remediation
    finally:
        srv.shutdown()


def test_ssrf_baseline_anti_fp():
    # Page that always contains "connection refused" in static text must NOT trigger SSRF FP
    class _StaticText(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body>Troubleshooting: ECONNREFUSED means port is closed.</body></html>")

    srv = HTTPServer(("127.0.0.1", 0), _StaticText)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        client = wx.HttpClient(stealth=False)
        state = wx.ScanState(base_url=f"http://127.0.0.1:{port}")
        hits = ssrf_mod.scan_ssrf_targets(
            client, state,
            [(f"http://127.0.0.1:{port}/fetch?url=https://example.com", "GET", "url", {"url": "https://example.com"})],
            wx.Finding,
        )
        assert hits == 0 and len(state.findings) == 0
    finally:
        srv.shutdown()
