#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Offline unit tests for DARK v2 platform capabilities:
  1. Nuclei-style YAML template engine (matchers + custom template CRUD)
  2. Auto-Login (CSRF HTML form + JSON Bearer token) & OpenAPI v3 ingestion
  3. DNS/Email security audit (SPF/DMARC/CAA & DNS wire codec)
  4. HashBreaker CrackStation multi-algo parity (NTLM, MySQL5, SHA3, salted, LDAP, Django)
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
for _p in (str(ROOT / "webvulnx"), str(ROOT / "netrecon"), str(ROOT / "hashbreaker"), str(ROOT / "dark")):
    if _p not in sys.path:
        sys.path.append(_p)

import webvulnx as wx  # noqa: E402
import templates_engine as te  # noqa: E402
import openapi_auth as oa  # noqa: E402
import dns_recon as dr  # noqa: E402
import hashbreaker as hb  # noqa: E402
import engine as dark_engine  # noqa: E402


OPENAPI_SPEC = {
    "openapi": "3.0.0",
    "paths": {
        "/api/search": {
            "get": {"parameters": [{"name": "q", "in": "query"}]},
            "post": {
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {"title": {"type": "string"}, "note": {"type": "string"}},
                            }
                        }
                    }
                }
            },
        }
    },
}


class _MockServer(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path == "/.env":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"DB_HOST=127.0.0.1\nDB_PASS=s3cr3t\n")
        elif self.path == "/metrics":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"# HELP http_requests Total\n# TYPE http_requests counter\n")
        elif self.path == "/login":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(
                b'<form method="POST" action="/login">'
                b'<input type="hidden" name="csrf" value="tok99">'
                b'<input name="username"><input type="password" name="password"></form>'
            )
        elif self.path == "/openapi.json":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(OPENAPI_SPEC).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        ln = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(ln).decode(errors="ignore")
        if self.path == "/login" and "csrf=tok99" in body and "username=admin" in body:
            self.send_response(200)
            self.send_header("Set-Cookie", "sess=authed_ok; Path=/")
            self.end_headers()
            self.wfile.write(b"Welcome admin")
            return
        if self.path == "/api/login" and "secret" in body:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"token": "eyJhbGciOiJIUzI1NiJ9.dark_jwt_token_test"}).encode())
            return
        self.send_response(404)
        self.end_headers()


def test_templates():
    tpls = te.load_all_templates()
    assert len(tpls) >= 15, f"expected >=15 built-in templates, got {len(tpls)}"
    custom = """id: unit-test-tpl
info:
  name: Unit Test Custom YAML
  severity: Low
http:
  - method: GET
    path: ['{{BaseURL}}/.env']
    matchers:
      - type: status
        status: [200]
      - type: word
        words: ['DB_PASS=']
"""
    te.save_custom_template(custom)
    try:
        assert any(t["id"] == "unit-test-tpl" for t in te.load_all_templates())
        srv = HTTPServer(("127.0.0.1", 0), _MockServer)
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            client = wx.HttpClient(target=f"http://127.0.0.1:{port}", stealth=False, rate_limit=0)
            state = wx.ScanState(base_url=f"http://127.0.0.1:{port}")
            hits = te.run_templates(client, f"http://127.0.0.1:{port}", state, wx.Finding)
            assert hits >= 3, f"expected env + metrics + custom hits, got {hits}"
            assert any("env-file-exposed" in f.vuln_type for f in state.findings)
            assert any("prometheus-metrics" in f.vuln_type for f in state.findings)
        finally:
            srv.shutdown()
    finally:
        assert te.delete_custom_template("unit-test-tpl")
    print("  OK   Nuclei-style YAML template engine + CRUD")


def test_openapi_and_autologin():
    srv = HTTPServer(("127.0.0.1", 0), _MockServer)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}"
    try:
        c1 = wx.HttpClient(target=base, stealth=False, rate_limit=0)
        r1 = oa.perform_auto_login(c1, f"{base}/login", "admin", "pass123")
        assert r1["ok"] and c1.sess.cookies.get("sess") == "authed_ok", r1

        c2 = wx.HttpClient(target=base, stealth=False, rate_limit=0)
        r2 = oa.perform_auto_login(c2, f"{base}/api/login", "admin", "secret")
        assert r2["ok"] and "Bearer eyJ" in c2.sess.headers.get("Authorization", ""), r2

        state = wx.ScanState(base_url=base)
        oares = oa.ingest_openapi(c1, base, state, wx.Finding)
        assert oares["found"] and oares["endpoints"] == 1
        assert "q" in state.params[f"{base}/api/search"]
        assert len(state.forms) == 1 and state.forms[0]["method"] == "POST"
    finally:
        srv.shutdown()
    print("  OK   Auto-Login (CSRF form + JSON JWT) & OpenAPI v3 ingestion")


def test_dns_wire_and_audit(monkeypatch_dns: bool = True):
    enc = dr._encode_name("sub.example.com")
    assert enc.startswith(b"\x03sub\x07example\x03com\x00")
    # Mock dns_query to test SPF/DMARC/CAA audit offline deterministically
    orig = dr.dns_query
    try:
        def fake_dns(domain, rtype="A", timeout=2.5, servers=None):
            if domain == "vuln.example" and rtype == "TXT":
                return ["v=spf1 +all"]
            if domain == "_dmarc.vuln.example" and rtype == "TXT":
                return []
            if domain == "vuln.example" and rtype == "A":
                return ["93.184.216.34"]
            return []
        dr.dns_query = fake_dns
        res = dr.run_dns_recon("vuln.example", subdomains=False, passive_crtsh=False)
        titles = [f["vuln_type"] for f in res["findings"]]
        assert any("+all" in t for t in titles), titles
        assert any("Missing DMARC" in t for t in titles), titles
        assert any("Missing DNS CAA" in t for t in titles), titles
    finally:
        dr.dns_query = orig
    print("  OK   DNS wire codec & SPF (+all) / DMARC / CAA audit")


def test_hashbreaker_crackstation():
    wl = str(ROOT / "hashbreaker" / "wordlists" / "common-pass.txt")
    ntlm_h = hb.compute("ntlm", "Password123").upper()
    mysql5_h = hb.compute("mysql5", "admin").upper()
    sha3_h = hb.compute("sha3-256", "cairo")
    salted_h = hashlib.md5(b"salt99" + b"secret", usedforsecurity=False).hexdigest() + ":salt99"  # nosemgrep: python.lang.security.insecure-hash-algorithms-md5.insecure-hash-algorithm-md5 (unit test fixture)
    ldap_h = "{SHA}" + base64.b64encode(hashlib.sha1(b"letmein", usedforsecurity=False).digest()).decode()  # nosemgrep: python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-sha1 (unit test fixture)
    dk = hashlib.pbkdf2_hmac("sha256", b"hello123", b"s1", 1000)
    dj_h = "pbkdf2_sha256$1000$s1$" + base64.b64encode(dk).decode()

    res = dark_engine.crack_hashes(
        [ntlm_h, mysql5_h, sha3_h, salted_h, ldap_h, dj_h],
        algo="auto", wordlist_path=wl, rules=False,
    )
    for r in res["results"]:
        assert r["cracked"], f"failed to crack {r}"
    print("  OK   HashBreaker CrackStation multi-algo parity (6/6 cracked)")


if __name__ == "__main__":
    print("Running DARK v2 Platform Wave Unit Tests...")
    test_templates()
    test_openapi_and_autologin()
    test_dns_wire_and_audit()
    test_hashbreaker_crackstation()
    print("ALL PLATFORM WAVE TESTS PASSED")
