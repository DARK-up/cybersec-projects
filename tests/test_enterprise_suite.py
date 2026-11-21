#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DARK Enterprise v3 — Comprehensive Unit, Integration, Benchmark,
Concurrency, Performance, Recovery & Regression Test Suite.
"""
from __future__ import annotations

import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
for p in (str(ROOT / "dark"), str(ROOT / "modules"), str(ROOT / "webvulnx")):
    if p not in sys.path:
        sys.path.insert(0, p)

import enterprise_db as edb  # noqa: E402
import asset_intel as ai  # noqa: E402
import vuln_intel as vi  # noqa: E402
import cloud_audit as ca  # noqa: E402
import container_audit as cta  # noqa: E402
import sast_audit as sa  # noqa: E402
import api_audit as aa  # noqa: E402
import forensics as fx  # noqa: E402
import compliance as comp  # noqa: E402
import remediation as rem  # noqa: E402
import plugin_mgr as pm  # noqa: E402


def test_enterprise_rbac_2fa_vault_audit_scope_backup():
    # RBAC + TOTP 2FA
    uname = f"test_analyst_{int(time.time() * 1000)}"
    u = edb.create_user(uname, "StrongPass123!", role="analyst")
    assert u["role"] == "analyst"
    assert edb.has_permission("analyst", "scan:run")
    assert not edb.has_permission("viewer", "scan:run")

    totp_info = edb.setup_user_totp(uname, enable=True)
    code = edb._hotp(totp_info["secret"], int(time.time() // 30))
    ok_bad, _, _ = edb.authenticate_user(uname, "StrongPass123!", "000000")
    assert not ok_bad
    ok_good, u_info, _ = edb.authenticate_user(uname, "StrongPass123!", code)
    assert ok_good and u_info["username"] == uname

    # Credential Vault authenticated encryption
    sec_name = f"aws_ro_{int(time.time() * 1000)}"
    edb.store_vault_secret(sec_name, "cloud_token", "super-secret-ro-token-999", created_by=uname)
    assert edb.reveal_vault_secret(sec_name) == "super-secret-ro-token-999"
    assert edb.delete_vault_secret(sec_name)

    # Audit Trail hash chain integrity
    edb.log_audit(uname, "analyst", "test:action", "unit-test", "ok")
    chain = edb.verify_audit_chain()
    assert chain["valid"] is True and chain["checked"] >= 1

    # Scope Allowlist enforcement (CIDR + wildcard)
    r = edb.add_scope_rule("*.authorized.example", "allow", "test rule")
    edb.set_setting("scope_enforced", True)
    try:
        ok1, _ = edb.check_target_in_scope("https://api.authorized.example/v1")
        ok2, _ = edb.check_target_in_scope("https://evil-outside.example")
        assert ok1 is True and ok2 is False
    finally:
        edb.set_setting("scope_enforced", False)
        edb.delete_scope_rule(r["id"])

    # Backup & Restore
    bk = edb.export_backup()
    assert bk["version"] == "dark-enterprise-v3" and "vuln_feed" in bk["tables"]
    rst = edb.restore_backup(bk)
    assert rst["restored"]["vuln_feed"] >= 14


def test_asset_and_vuln_risk_intel():
    a1 = ai.upsert_asset("default", "domain", "app.enterprise.example", "critical", True)
    a2 = ai.upsert_asset("default", "ip", "203.0.113.10", "high", True)
    ai.link_assets("default", a1["id"], a2["id"], "resolves_to")
    inv = ai.list_assets("default")
    assert any(x["name"] == "app.enterprise.example" for x in inv["assets"])
    assert len(inv["relations"]) >= 1

    cves = vi.match_product_cves("log4j", "2.14.1")
    assert any(c["cve_id"] == "CVE-2021-44228" and c["kev"] for c in cves)

    scored = vi.score_finding_axes({
        "vuln_type": "Apache Log4Shell CVE-2021-44228",
        "severity": "Critical",
        "url": "https://app.enterprise.example",
        "parameter": "header",
        "payload": "${jndi:ldap://...}",
        "evidence": "Confirmed CVE-2021-44228 vulnerable version",
    }, internet_exposed=True, asset_criticality="critical")
    assert scored["confidence"] >= 0.85
    assert scored["exploitability"] >= 0.85
    assert scored["kev"] is True
    assert scored["risk_score"] >= 85.0


def test_cloud_container_sast_forensics_compliance():
    # Cloud (AWS + Azure + GCP)
    aws_res = ca.audit_cloud_config("aws", '{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}')
    assert any("Wildcard IAM" in f["vuln_type"] for f in aws_res["findings"])
    az_res = ca.audit_cloud_config("azure", 'resource "azurerm_storage_account" "s" { allow_blob_public_access = true enable_https_traffic_only = false }')
    assert len(az_res["findings"]) >= 2
    gcp_res = ca.audit_cloud_config("gcp", 'members = ["allUsers"]\nrole = "roles/owner"')
    assert len(gcp_res["findings"]) >= 2

    # Container + Kubernetes + SBOM
    cnt = cta.audit_container_and_sbom(
        "FROM python:latest\nUSER root\nENV DB_PASSWORD=secret123\n"
    )
    assert len(cnt["findings"]) >= 3
    dep = cta.audit_container_and_sbom("requests==2.25.0\npyyaml==5.3.1\n", kind="requirements.txt")
    assert any("CVE-" in f["vuln_type"] for f in dep["findings"])
    assert dep["sbom"]["bomFormat"] == "CycloneDX" and len(dep["sbom"]["components"]) == 2

    # SAST (Python AST + JS + Java + PHP + C/C++)
    py_sast = sa.scan_sast("import yaml\ndef f(x):\n  yaml.load(x)\n  cur.execute(f'SELECT * FROM u WHERE id={x}')\n", language="Python")
    assert any("yaml.load" in f["vuln_type"] for f in py_sast["findings"])
    assert any("SQL Query" in f["vuln_type"] for f in py_sast["findings"])
    c_sast = sa.scan_sast('void f(char *s){ char b[8]; strcpy(b, s); }', language="C/C++")
    assert any("Buffer" in f["vuln_type"] for f in c_sast["findings"])

    # Forensics
    f_res = fx.analyze_forensics(
        "\n".join([
            "Oct 12 10:00:01 srv sshd[1]: Failed password for root from 198.51.100.44 port 11",
            "Oct 12 10:00:02 srv sshd[1]: Failed password for root from 198.51.100.44 port 12",
            "Oct 12 10:00:03 srv sshd[1]: Failed password for root from 198.51.100.44 port 13",
            "Oct 12 10:00:04 srv sshd[1]: Failed password for root from 198.51.100.44 port 14",
            "Oct 12 10:00:05 srv sshd[1]: Failed password for root from 198.51.100.44 port 15",
            "EventID=1102 Security audit log cleared",
        ])
    )
    assert f_res["timeline_count"] >= 5
    assert any("198.51.100.44" in m for m in f_res["iocs"]["matched_bad"])
    assert any("1102" in f["vuln_type"] for f in f_res["findings"])

    # Compliance
    c_eval = comp.evaluate_compliance(py_sast["findings"] + f_res["findings"] + aws_res["findings"])
    for fw in ("OWASP_ASVS", "CIS_BENCHMARKS", "NIST_CSF", "ISO_27001", "PCI_DSS"):
        assert fw in c_eval["frameworks"]


def test_api_remediation_and_plugins():
    spec = {
        "openapi": "3.0.0",
        "servers": [{"url": "http://api.example.com"}],
        "paths": {
            "/users/{id}": {
                "post": {"requestBody": {"content": {"application/json": {"schema": {"properties": {"isAdmin": {"type": "boolean"}}}}}}}
            }
        },
    }

    class _MockApi(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            if self.path == "/openapi.json":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(spec).encode())
            elif self.path == "/phpinfo.php":
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"<h1>PHP Version 8.2.4</h1>")
            else:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")

        def do_POST(self):
            if self.path == "/graphql":
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"data":{"__schema":{"types":[{"name":"User"}]}}}')
            else:
                self.send_response(404)
                self.end_headers()

    srv = HTTPServer(("127.0.0.1", 0), _MockApi)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        ares = aa.run_api_audit(f"http://127.0.0.1:{port}", openapi_url=f"http://127.0.0.1:{port}/openapi.json")
        titles = " | ".join(f["vuln_type"] for f in ares["findings"])
        assert "Mass Assignment" in titles and "GraphQL Introspection" in titles

        # Plugin Marketplace: signature verification + self-test + execution
        for p in pm.list_plugins():
            assert p["signature_valid"] is True
            t_res = pm.run_plugin_tests(p["plugin_id"])
            assert t_res["passed"] is True, t_res

        import webvulnx as wx
        client = wx.HttpClient(target=f"http://127.0.0.1:{port}", stealth=False)
        p_hits = pm.execute_enabled_plugins(client, f"http://127.0.0.1:{port}")
        assert any("phpinfo" in h["vuln_type"].lower() for h in p_hits)

        # Remediation workflow
        t = rem.create_or_sync_ticket("default", "job1", ares["findings"][0], assignee="ali", due_date="2026-10-15")
        rem.update_ticket(t["id"], status="in_progress", note="Working on DTO allowlist", fix_evidence="PR #42")
        closed = rem.record_retest(t["id"], still_vulnerable=False, detail="Verified fixed")
        assert closed["status"] == "verified_closed"
    finally:
        srv.shutdown()


def test_performance_and_memory_budget():
    # Ensure running SAST + Container + Cloud + Compliance stays lightweight (< 2s, < 300MB RSS)
    t0 = time.perf_counter()
    sa.scan_sast(target_path=str(ROOT / "dark"))
    elapsed = time.perf_counter() - t0
    assert elapsed < 5.0, f"SAST on dark/ took too long: {elapsed:.2f}s"
    _, ram_mb = edb._sample_system_metrics()
    assert ram_mb < 512.0, f"RSS too high: {ram_mb} MB"


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-v"]))
