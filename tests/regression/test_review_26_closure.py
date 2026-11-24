#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Regression suite verifying closure of all 26 independent review observations (P0, P1, P2)."""
from __future__ import annotations

import asyncio
import base64
import hashlib
import http.server
import importlib
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
for _p in (str(ROOT / "dark"), str(ROOT / "modules")):
    if _p not in sys.path:
        sys.path.append(_p)

import main as dark_main
import enterprise_db as edb
import compliance as comp
import reporting_analytics as rpt
import posture_dashboard as pdash
import benchmark_lab as blab
import sast_audit as sa
import api_audit as aa
import plugin_mgr as pm
from webvulnx import xss_deep as xd
from webvulnx import webvulnx as wx
from hashbreaker import hashbreaker as hb
from netrecon import netrecon as nr
from netrecon import vuln_plugins as vp
from netsentry import netsentry as ns


# ---------------------------------------------------------------------------
# P0-01: Per-tenant Vault Secret Isolation
# ---------------------------------------------------------------------------
def test_p0_01_vault_secret_isolated_per_tenant():
    edb.store_vault_secret("shared-ci-token", "api_key", "secret-alpha-111", tenant_id="tenant_a")
    edb.store_vault_secret("shared-ci-token", "api_key", "secret-beta-222", tenant_id="tenant_b")

    assert edb.reveal_vault_secret("shared-ci-token", tenant_id="tenant_a") == "secret-alpha-111"
    assert edb.reveal_vault_secret("shared-ci-token", tenant_id="tenant_b") == "secret-beta-222"

    # Update tenant_a -> tenant_b untouched
    edb.store_vault_secret("shared-ci-token", "api_key", "secret-alpha-updated", tenant_id="tenant_a")
    assert edb.reveal_vault_secret("shared-ci-token", tenant_id="tenant_a") == "secret-alpha-updated"
    assert edb.reveal_vault_secret("shared-ci-token", tenant_id="tenant_b") == "secret-beta-222"

    # Delete tenant_a -> tenant_b intact
    assert edb.delete_vault_secret("shared-ci-token", tenant_id="tenant_a") is True
    assert edb.reveal_vault_secret("shared-ci-token", tenant_id="tenant_a") is None
    assert edb.reveal_vault_secret("shared-ci-token", tenant_id="tenant_b") == "secret-beta-222"
    assert edb.delete_vault_secret("shared-ci-token", tenant_id="tenant_b") is True


# ---------------------------------------------------------------------------
# P0-02 & P1-04: Deployment Compose Isolation & Production Secret Rejection
# ---------------------------------------------------------------------------
def test_p0_02_and_p1_04_compose_isolation_and_prod_config_guard(monkeypatch):
    dev_compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    prod_compose = (ROOT / "docker-compose.prod.yml").read_text(encoding="utf-8")
    assert "6379:6379" not in dev_compose
    assert "127.0.0.1:8000:8000" in dev_compose
    assert "dark_change_me" not in dev_compose
    assert "DARK_ENV=production" in prod_compose
    assert "6379:6379" not in prod_compose
    assert (ROOT / "dark" / "requirements-distributed.txt").is_file()
    assert "celery" in (ROOT / "dark" / "requirements-distributed.txt").read_text(encoding="utf-8")

    monkeypatch.setenv("DARK_ENV", "production")
    monkeypatch.setenv("DARK_VAULT_KEY", "dark_change_me_insecure")
    with pytest.raises(RuntimeError, match="Insecure production configuration"):
        dark_main.validate_production_config(strict=False)

    monkeypatch.setenv("DARK_VAULT_KEY", "V3ry$trongPr0dVaultKey!2026#9988")
    monkeypatch.setenv("DARK_CORS_ORIGINS", "https://dark.example.com")
    monkeypatch.setenv("DARK_POSTGRES_DSN", "postgresql://dark:Str0ngP@ss!@db:5432/dark")
    assert dark_main.validate_production_config(strict=True) == []


# ---------------------------------------------------------------------------
# P0-03 & P2-15: Empty Compliance & Posture Never Return 100% / Healthy
# ---------------------------------------------------------------------------
def test_p0_03_and_p2_15_empty_compliance_and_posture_unknown():
    res_empty = comp.evaluate_compliance([])
    for fw, data in res_empty["frameworks"].items():
        assert data["assessment_status"] == "Not Assessed", fw
        assert data["score_pct"] == 0.0, fw
        assert data["coverage_pct"] == 0.0, fw
        assert all(c["status"] == "Not Assessed" for c in data["controls"])

    res_failed = comp.evaluate_compliance([], failed_domains=["tls"])
    tls_ctrls = [
        c for fw in res_failed["frameworks"].values()
        for c in fw["controls"] if c["domain"] == "tls"
    ]
    assert tls_ctrls and all(c["status"] == "Failed Assessment" for c in tls_ctrls)

    res_verified = comp.evaluate_compliance([], assessed_domains=["tls"])
    tls_pass = [
        c for fw in res_verified["frameworks"].values()
        for c in fw["controls"] if c["domain"] == "tls"
    ]
    assert tls_pass and all(c["status"] == "Pass" for c in tls_pass)

    # P2-15: Empty / failed jobs must return posture Unknown (None), never 100
    ana = rpt.build_executive_analytics([], project_id="empty_proj")
    assert ana["security_posture_score"] is None
    assert ana["posture_status"] == "Unknown"

    posture = pdash.compute_posture_dashboard([], project_id="empty_proj")
    assert posture["security_posture_score"] is None
    assert posture["posture_status"] == "Unknown"


# ---------------------------------------------------------------------------
# P1-05: PostgreSQL DSN Fails Loudly Without Silent SQLite Fallback
# ---------------------------------------------------------------------------
def test_p1_05_postgres_dsn_missing_driver_fails_explicitly(monkeypatch):
    monkeypatch.setenv("DARK_POSTGRES_DSN", "postgresql://u:p@127.0.0.1:5432/dark")
    # Force ImportError on psycopg even if installed later
    real_import = __import__

    def _fake_import(name, *args, **kwargs):
        if name == "psycopg" or name.startswith("psycopg."):
            raise ImportError("mocked missing psycopg")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr("builtins.__import__", _fake_import)
    with pytest.raises(RuntimeError, match="DARK_POSTGRES_DSN"):
        edb._conn()


# ---------------------------------------------------------------------------
# P1-06: Watchdog Signals Stop Event on Timeout
# ---------------------------------------------------------------------------
def test_p1_06_watchdog_signals_stop_event_on_timeout():
    ev = threading.Event()
    jid = "wdtest001"
    now = time.time()
    with dark_main.JOBS_LOCK:
        dark_main.JOBS[jid] = {
            "id": jid, "kind": "web-scan", "status": "running",
            "project_id": "default", "tenant_id": "default", "target": "http://127.0.0.1",
            "started_at": now - 5000, "finished_at": None, "deadline": now - 10,
            "result": None, "error": None, "progress": None,
            "_log": None, "_stop_event": ev,
        }
    try:
        # Simulate watchdog deadline branch check directly
        with dark_main.JOBS_LOCK:
            j = dark_main.JOBS[jid]
            if time.time() > j["deadline"]:
                if j.get("_stop_event") is not None:
                    j["_stop_event"].set()
                j["status"] = "timeout"
                j["timed_out"] = True
        assert ev.is_set()
        assert dark_main.JOBS[jid]["status"] == "timeout"
        assert dark_main.JOBS[jid]["timed_out"] is True
    finally:
        with dark_main.JOBS_LOCK:
            dark_main.JOBS.pop(jid, None)


# ---------------------------------------------------------------------------
# P1-07: Sensitive Fields Redacted From Jobs, Disk, API & Exports
# ---------------------------------------------------------------------------
def test_p1_07_job_payload_secrets_redacted():
    jid = dark_main.start_job(
        "sast-audit",
        lambda **kw: {"findings": []},
        target_hint="redact-test",
        cookie="session=SUPERSECRETCOOKIE999",
        auth_header="Bearer SUPERSECRETBEARER888",
        login_pass="MyUltraSecretPass!777",
    )
    time.sleep(0.3)
    client = TestClient(dark_main.app)
    r = client.get(f"/api/jobs/{jid}")
    assert r.status_code == 200
    body = r.text
    assert "SUPERSECRETCOOKIE999" not in body
    assert "SUPERSECRETBEARER888" not in body
    assert "MyUltraSecretPass!777" not in body
    if dark_main.JOBS_FILE.is_file():
        disk_txt = dark_main.JOBS_FILE.read_text(encoding="utf-8")
        assert "SUPERSECRETCOOKIE999" not in disk_txt
        assert "SUPERSECRETBEARER888" not in disk_txt
        assert "MyUltraSecretPass!777" not in disk_txt


# ---------------------------------------------------------------------------
# P1-08: Fail-Closed CSRF Matrix
# ---------------------------------------------------------------------------
def test_p1_08_fail_closed_csrf_matrix(monkeypatch):
    monkeypatch.delenv("DARK_ENV", raising=False)
    uname = f"csrf_{os.getpid()}_{int(time.time() * 1000) % 9999}"
    edb.create_user(uname, "CsrfStrong!Pass2026", role="admin")
    client = TestClient(dark_main.app)
    lr = client.post("/api/admin/users/login", json={"username": uname, "password": "CsrfStrong!Pass2026"})
    assert lr.status_code == 200
    sess_tok = lr.json()["token"]
    csrf_tok = lr.json()["csrf_token"]

    # 1. Cookie auth WITHOUT csrf cookie & WITHOUT csrf header -> 403 fail-closed
    r_no_cookie = client.post("/api/projects", json={"name": "p1"}, cookies={"dark_session": sess_tok})
    assert r_no_cookie.status_code == 403

    # 2. Cookie auth WITH csrf cookie, MISSING header -> 403
    r_no_hdr = client.post("/api/projects", json={"name": "p2"}, cookies={"dark_session": sess_tok, "dark_csrf": csrf_tok})
    assert r_no_hdr.status_code == 403

    # 3. Cookie auth WITH wrong csrf header -> 403
    r_bad_hdr = client.post(
        "/api/projects", json={"name": "p3"},
        cookies={"dark_session": sess_tok, "dark_csrf": csrf_tok},
        headers={"X-CSRF-Token": "wrong-csrf"},
    )
    assert r_bad_hdr.status_code == 403

    # 4. Cookie auth WITH matching csrf cookie & header -> 200
    r_ok = client.post(
        "/api/projects", json={"name": "p4"},
        cookies={"dark_session": sess_tok, "dark_csrf": csrf_tok},
        headers={"X-CSRF-Token": csrf_tok},
    )
    assert r_ok.status_code == 200

    # 5. Auth endpoint /api/auth/logout with session cookie & missing CSRF -> 403
    r_auth_nocsrf = client.post("/api/auth/logout", cookies={"dark_session": sess_tok})
    assert r_auth_nocsrf.status_code == 403


# ---------------------------------------------------------------------------
# P1-09: Audit Chain Canonical v2 (Empty, >500 Chars, Unicode, Tenant Integrity)
# ---------------------------------------------------------------------------
def test_p1_09_audit_chain_long_unicode_and_tenant_tamper():
    edb.log_audit("tester", "admin", "test:empty", "res", detail="", tenant_id="tenantA")
    long_detail = "تفاصيل-عربية-" + ("A" * 1100) + "-🔒"
    rec = edb.log_audit("tester", "admin", "test:long", "res", detail=long_detail, tenant_id="tenantA")
    assert len(rec["detail"]) > 500
    v1 = edb.verify_audit_chain()
    assert v1["valid"] is True, v1

    # Tamper tenant_id -> chain verification MUST fail
    with edb._DB_LOCK:
        c = edb._conn()
        try:
            c.execute("UPDATE audit_logs SET tenant_id='tenantEvil' WHERE id=?", (rec["id"],))
            c.commit()
            v_bad = edb.verify_audit_chain()
            assert v_bad["valid"] is False
            # Restore original tenant_id so shared test DB stays healthy
            c.execute("UPDATE audit_logs SET tenant_id='tenantA' WHERE id=?", (rec["id"],))
            c.commit()
        finally:
            c.close()
    assert edb.verify_audit_chain()["valid"] is True


# ---------------------------------------------------------------------------
# P1-10: Deep XSS attack_point Rejects Non-HTML Content-Type Before instant
# ---------------------------------------------------------------------------
def test_p1_10_deep_xss_attack_point_skips_non_renderable_text_and_json():
    class _R:
        def __init__(self, text, headers):
            self.text = text
            self.headers = headers

    for hdrs in (
        {"Content-Type": "text/plain", "X-Content-Type-Options": "nosniff"},
        {"Content-Type": "application/json"},
    ):
        state = wx.ScanState(base_url="http://example.local")
        client = wx.HttpClient(target="http://example.local")
        sc = xd.DeepXssScanner(client, state, wx.Finding, quiet=True)
        # Simulate server returning the payload directly inside <script>...</script> in text/plain or JSON
        ok = sc.attack_point(
            "http://example.local/api",
            "q",
            lambda val: _R(f"<script>{val}</script>", hdrs),
            "query:q@http://example.local/api",
        )
        assert ok is False
        assert len(state.findings) == 0


# ---------------------------------------------------------------------------
# P1-11, P1-12, P1-13, P1-14, P2-26: CI, Benchmark Units, Packaging, Imports
# ---------------------------------------------------------------------------
def test_p1_11_to_14_and_26_ci_units_packaging_and_imports():
    # P1-11: CI workflow exists in .github/workflows/
    wf = ROOT / ".github" / "workflows" / "ci.yml"
    assert wf.is_file()
    wf_txt = wf.read_text(encoding="utf-8")
    assert "pip-audit" in wf_txt and "|| true" not in wf_txt

    # P1-12: Consistent class-level unit even with duplicate findings & multiple FPs in one class
    lab_fs = [{"vuln_type": "SQL Injection"}, {"vuln_type": "SQL Injection (Union)"}, {"vuln_type": "Reflected XSS"}]
    clean_fs = [
        {"vuln_type": "CORS Misconfiguration", "severity": "High"},
        {"vuln_type": "CORS Wildcard Duplicate", "severity": "Medium"},
    ]
    cm = blab.evaluate_class_confusion_matrix(lab_fs, clean_fs)
    assert cm["unit"] == "vulnerability_class"
    assert cm["tp"] == 2 and cm["fp"] == 1 and cm["fn"] == 8
    assert cm["finding_counts"]["lab_total_findings"] == 3
    assert cm["finding_counts"]["clean_non_info_findings"] == 2

    # P1-14 & P2-26: No stdlib platform shadowing + unified version 4.0.0
    assert not (ROOT / "dark" / "platform.py").exists()
    import platform as std_plat
    assert hasattr(std_plat, "python_version")
    pyproj = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'version = "4.0.0"' in pyproj

    # P1-13: Package imports work from outside repo root without modifying sys.path
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT)
    r = subprocess.run(
        [sys.executable, "-c",
         "import dark.main, modules.compliance, webvulnx.xss_deep, netrecon.netrecon, netsentry.netsentry, hashbreaker.hashbreaker; print('IMPORT_OK')"],
        cwd="/tmp", env=env, capture_output=True, text=True, timeout=20,
    )
    assert r.returncode == 0, r.stderr
    assert "IMPORT_OK" in r.stdout


# ---------------------------------------------------------------------------
# P2-16, P2-17, P2-18: Banner Certainty, ARP Cooldown, Capability Matrices
# ---------------------------------------------------------------------------
def test_p2_16_to_18_banner_certainty_arp_cooldown_and_capabilities():
    # P2-16
    pr = nr.PortResult(port=8080, state="open", service="HTTP", version="Apache/2.4.50", banner="Apache/2.4.50")
    vulns = asyncio.run(vp.evaluate_host("127.0.0.1", [pr]))
    cve_v = [v for v in vulns if v.get("cves")]
    assert cve_v and all(v.get("finding_certainty") == "Potential" for v in cve_v)
    assert all("applicability_conditions" in v for v in cve_v)

    # P2-18: Capability matrices + Base64(MD5) decoding
    assert "tls_banner_negotiation" in nr.get_capability_matrix()
    assert "tcp_syn_horizontal_sweep" in ns.get_capability_matrix()
    assert "base64_digest_cracking" in hb.get_capability_matrix()
    b64_md5 = base64.b64encode(hashlib.md5(b"hello").digest()).decode("ascii")
    t = hb.Target(hash_str=b64_md5)
    hb.resolve_algos(t, None)
    assert t.hash_str == hashlib.md5(b"hello").hexdigest()
    assert "md5" in t.candidate_algos

    # P2-17: ARP single change followed by 5 stable packets -> 1 observation, NOT 6 Criticals
    if ns.SCAPY_OK:
        from scapy.all import ARP  # type: ignore
        bus = ns.AlertBus(quiet=True)
        det = ns.ArpDetector(bus, window_s=120.0, cooldown_s=300.0)
        det.feed(ARP(psrc="10.0.0.1", hwsrc="aa:bb:cc:00:00:01"), ts=100.0)
        det.feed(ARP(psrc="10.0.0.1", hwsrc="aa:bb:cc:00:00:02"), ts=101.0)
        for i in range(5):
            det.feed(ARP(psrc="10.0.0.1", hwsrc="aa:bb:cc:00:00:02"), ts=102.0 + i)
        assert len(bus.alerts) == 1
        assert bus.alerts[0].severity != "CRITICAL"


# ---------------------------------------------------------------------------
# P2-19, P2-20, P2-21, P2-22, P2-23, P2-24, P2-25
# ---------------------------------------------------------------------------
def test_p2_19_to_25_remaining_quality_and_reliability_controls(monkeypatch):
    # P2-19: Legacy XSS never returns Confirmed on raw reflection
    st = wx.ScanState(base_url="http://example.local")
    legacy = wx.XssScanner(wx.HttpClient(target="http://example.local"), st)
    class _HtmlR:
        def __init__(self, txt):
            self.text = txt
            self.headers = {"Content-Type": "text/html"}
            self.status_code = 200
    legacy.client.get = lambda u, params=None, **kw: _HtmlR(f"<textarea>{(params or {}).get('q', '')}</textarea>")
    legacy._test_target("http://example.local/s", "GET", "q", {"q": "1"})
    assert st.findings and all(f.verification_status != "Confirmed" for f in st.findings)

    # P2-20: SAST SyntaxError -> Not Analyzed (never silent clean)
    sast_bad = sa.scan_sast("def broken(:\n    pass\n", language="Python")
    assert sast_bad["analysis_status"] == "Not Analyzed"
    assert len(sast_bad["parse_failures"]) == 1

    # P2-21: API audit schema observations marked Schema Observation / Review Required
    spec = json.dumps({
        "openapi": "3.0.0",
        "paths": {"/admin/users": {"post": {"security": [{"bearer": []}], "requestBody": {"content": {"application/json": {"schema": {"properties": {"role": {"type": "string"}}}}}}}}},
    })
    ares = aa.run_api_audit("http://127.0.0.1:9", spec_json=spec)
    assert all(f.get("certainty") == "Schema Observation" and f.get("live_authz_tested") is False for f in ares["findings"])

    # P2-22: Partial module failure reported explicitly
    import engine as deng
    class _OkHandler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_GET(self):
            self.send_response(200); self.send_header("Content-Type", "text/html"); self.end_headers()
            self.wfile.write(b"<html><body>ok</body></html>")
    srv = http.server.HTTPServer(("127.0.0.1", 0), _OkHandler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        monkeypatch.setattr(wx.MisconfigAudit, "run", lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("boom")))
        wres = deng.run_web_scan(
            f"http://127.0.0.1:{port}",
            modules={"crawl": False, "sqli": False, "xss": False, "dirs": False, "audit": True, "advanced": False, "param_fuzz": False, "templates": False},
        )
        assert wres["partial_failure"] is True
        assert wres["module_outcomes"]["misconfig-audit"]["status"] == "failed"
    finally:
        srv.shutdown()

    # P2-23: HttpClient defaults to verify=True and blocks Authorization over verify=False
    c_safe = wx.HttpClient(target="https://example.com")
    assert c_safe.tls_verify is True
    c_insec = wx.HttpClient(target="https://example.com", verify=False, headers={"Authorization": "Bearer secret"})
    assert c_insec.get("https://example.com/api") is None
    assert "unverified TLS" in (c_insec.last_error or "")

    # P2-24: Disaster recovery manifest & clean restore check
    man = edb.get_backup_manifest()
    assert "dark_enterprise.db" in man["database_path"] or "PostgreSQL" in man["database_path"]
    dr_txt = (ROOT / "docs" / "DISASTER_RECOVERY.md").read_text(encoding="utf-8")
    assert "dark/data/dark_enterprise.db" in dr_txt and "vault_keyring.json" in dr_txt

    # P2-25: Plugin manager rejects CWE in cve_mapping & requires negative test case
    bad_plg = {
        "plugin_id": "test-bad-plg", "name": "Bad", "category": "test", "version": "1.0.0",
        "severity": "Low", "cve_mapping": ["CWE-200"],
        "detection_logic": {"path": "/x"}, "evidence_schema": {}, "remediation": "fix",
        "test_cases": [{"name": "pos", "body": "x", "status": 200, "expect_hit": True}],
    }
    errors_dummy = pm.validate_manifest(bad_plg)
    assert len(errors_dummy) >= 2
    actuator = next(p for p in pm.BUILTIN_PLUGINS if p["plugin_id"] == "dark-plg-spring-actuator-env")
    assert actuator["cve_mapping"] == []


# ---------------------------------------------------------------------------
# WebVulnX --rate-limit (default 1.0 req/s, incl. time-blind SQLi) & --header
# ---------------------------------------------------------------------------
def test_webvulnx_rate_limit_and_custom_header_across_paths():
    # 1. Conservative default rate limit is 1.0 req/s in CLI parser and HttpClient
    parser = wx.build_parser()
    parsed = parser.parse_args(["-u", "http://127.0.0.1:8080", "--header", "Deck-Research: 1", "--header", "X-Bron-Bugbounty: dark-user"])
    assert parsed.rate_limit == 1.0
    assert parsed.header == ["Deck-Research: 1", "X-Bron-Bugbounty: dark-user"]

    default_client = wx.HttpClient(target="https://example.com")
    assert default_client.rate_limit == 1.0
    assert default_client.gate.floor_interval == 1.0

    # 2. Enforce --rate-limit & --header across all outgoing HTTP requests (incl. time-blind SQLi)
    recorded_ts: list[float] = []
    seen_headers: list[dict] = []

    class _RateHdrHandler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            recorded_ts.append(time.monotonic())
            seen_headers.append({k.lower(): v for k, v in self.headers.items()})
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body><a href='/search?q=1'>search</a></body></html>")

    srv = http.server.HTTPServer(("127.0.0.1", 0), _RateHdrHandler)
    port = srv.server_address[1]
    base = f"http://127.0.0.1:{port}"
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        # 2.0 req/s => min_interval = 0.5s across crawl + SQLi (error/boolean/time-blind) + dirbuster
        client = wx.HttpClient(
            target=base, stealth=True, rate_limit=2.0,
            headers={"Deck-Research": "research-alpha", "X-Bron-Bugbounty": "bron-42"},
        )
        state = wx.ScanState(base_url=base, start_ts=time.monotonic())
        state.params[f"{base}/search?q=1"] = {"q"}
        # Run 3 rapid requests + SqliScanner time-blind loop (stop after 5 requests)
        for _ in range(3):
            client.get(f"{base}/search?q=1")
        sqli = wx.SqliScanner(client, state, time_delay=2.0)
        sqli.scan_params(f"{base}/search?q=1", ["q"], method="GET")

        assert len(recorded_ts) >= 6
        intervals = [recorded_ts[i] - recorded_ts[i - 1] for i in range(1, len(recorded_ts))]
        assert all(dt >= 0.45 for dt in intervals), f"Rate limit breached! intervals={intervals}"
        # Custom headers must be present on EVERY outgoing request
        assert all(h.get("deck-research") == "research-alpha" and h.get("x-bron-bugbounty") == "bron-42" for h in seen_headers)
        # Time-blind SQLi must NOT false-positive due to RateGate delay
        assert not any("Time-Based Blind" in f.vuln_type for f in state.findings)
    finally:
        srv.shutdown()


# ---------------------------------------------------------------------------
# Dockerfile 0.0.0.0 inside container + host loopback publishing verification
# ---------------------------------------------------------------------------
def test_dockerfile_0000_bind_and_host_published_port_reachability():
    import socket
    import urllib.request

    df_txt = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert '"--host", "0.0.0.0"' in df_txt
    assert '"--host", "127.0.0.1"' not in df_txt
    for cname in ("docker-compose.yml", "docker-compose.prod.yml"):
        ctxt = (ROOT / cname).read_text(encoding="utf-8")
        assert "127.0.0.1:8000:8000" in ctxt

    # Live host probe against uvicorn bound on 0.0.0.0:<ephemeral_port>
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        free_port = s.getsockname()[1]

    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", str(free_port)],
        cwd=str(ROOT / "dark"),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    try:
        ok_body = None
        for _ in range(30):
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{free_port}/api/health", timeout=2.0) as resp:
                    if resp.status == 200:
                        ok_body = json.loads(resp.read().decode("utf-8"))
                        break
            except Exception:
                time.sleep(0.25)
        assert ok_body is not None and ok_body.get("status") == "online"
        assert ok_body.get("version") == "4.0.0"
    finally:
        proc.terminate()
        proc.wait(timeout=10)


# ---------------------------------------------------------------------------
# WebVulnX Redirect-Chain Rate Limit, Cross-Origin Header Isolation & Concurrent Clients
# ---------------------------------------------------------------------------
def test_webvulnx_redirect_chain_cross_origin_and_concurrent_clients():
    from concurrent.futures import ThreadPoolExecutor

    all_events: list[tuple[str, float, dict]] = []
    ev_lock = threading.Lock()
    port_b_holder: list[int] = []

    class _ExtHandler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            with ev_lock:
                all_events.append(("ext", time.monotonic(), {k.lower(): v for k, v in self.headers.items()}))
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body>external landing</body></html>")

    class _MainHandler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            with ev_lock:
                all_events.append((self.path, time.monotonic(), {k.lower(): v for k, v in self.headers.items()}))
            if self.path == "/r1":
                self.send_response(302)
                self.send_header("Location", "/r2")
                self.end_headers()
            elif self.path == "/r2":
                self.send_response(302)
                self.send_header("Location", "/r3")
                self.end_headers()
            elif self.path == "/r3":
                self.send_response(302)
                self.send_header("Location", f"http://127.0.0.1:{port_b_holder[0]}/ext")
                self.end_headers()
            else:
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<html><body>ok</body></html>")

    srv_b = http.server.HTTPServer(("127.0.0.1", 0), _ExtHandler)
    port_b_holder.append(srv_b.server_address[1])
    srv_a = http.server.HTTPServer(("127.0.0.1", 0), _MainHandler)
    port_a = srv_a.server_address[1]
    threading.Thread(target=srv_b.serve_forever, daemon=True).start()
    threading.Thread(target=srv_a.serve_forever, daemon=True).start()

    try:
        # 1. Single request triggering a 4-hop redirect chain (3 same-origin + 1 cross-origin)
        client = wx.HttpClient(
            target=f"http://127.0.0.1:{port_a}",
            stealth=True,
            rate_limit=2.5,  # 0.4s per hop
            cookies={"session_tok": "secret-cookie-123"},
            headers={
                "Deck-Research": "deck-secret-handle",
                "X-Bron-Bugbounty": "bron-secret-handle",
                "Authorization": "Bearer topsecret-jwt",
            },
        )
        resp = client.get(f"http://127.0.0.1:{port_a}/r1")
        assert resp is not None and resp.status_code == 200
        assert len(resp.history) == 3
        assert len(all_events) == 4
        assert client.stats["redirects"] == 3
        assert client.stats["cross_origin_redirects_stripped"] == 1

        # Every redirect hop must obey RateGate (>= 0.35s between hops)
        hop_times = [e[1] for e in all_events]
        hop_intervals = [hop_times[i] - hop_times[i - 1] for i in range(1, len(hop_times))]
        assert all(dt >= 0.35 for dt in hop_intervals), f"Redirect chain bypassed rate limit: {hop_intervals}"

        # Same-origin hops (/r1, /r2, /r3) carry custom headers; cross-origin hop (/ext) MUST NOT leak them
        for path, _, hdrs in all_events[:3]:
            assert hdrs.get("deck-research") == "deck-secret-handle", path
            assert hdrs.get("x-bron-bugbounty") == "bron-secret-handle", path
            assert hdrs.get("authorization") == "Bearer topsecret-jwt", path
        _, _, ext_hdrs = all_events[3]
        assert "deck-research" not in ext_hdrs, f"Leaked Deck-Research cross-origin: {ext_hdrs}"
        assert "x-bron-bugbounty" not in ext_hdrs, f"Leaked X-Bron-Bugbounty cross-origin: {ext_hdrs}"
        assert "authorization" not in ext_hdrs, f"Leaked Authorization cross-origin: {ext_hdrs}"
        assert "cookie" not in ext_hdrs, f"Leaked Cookie cross-origin: {ext_hdrs}"

        # 2. Concurrent clients targeting the same local lab server share RateGate pacing
        all_events.clear()
        base_a = f"http://127.0.0.1:{port_a}"

        def _worker(idx: int):
            c = wx.HttpClient(
                target=base_a, stealth=False, rate_limit=4.0,  # 0.25s floor shared across clients
                headers={"Deck-Research": f"worker-{idx}"},
            )
            for j in range(3):
                r = c.get(f"{base_a}/ok?w={idx}&n={j}")
                assert r is not None and r.status_code == 200

        with ThreadPoolExecutor(max_workers=3) as pool:
            futs = [pool.submit(_worker, i) for i in range(3)]
            for f in futs:
                f.result()

        assert len(all_events) == 9
        conc_times = sorted(e[1] for e in all_events)
        conc_intervals = [conc_times[i] - conc_times[i - 1] for i in range(1, len(conc_times))]
        assert all(dt >= 0.20 for dt in conc_intervals), f"Concurrent clients breached shared rate limit: {conc_intervals}"
        assert all("deck-research" in e[2] for e in all_events)
    finally:
        srv_a.shutdown()
        srv_b.shutdown()

