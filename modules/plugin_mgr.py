#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DARK Plugin Marketplace Architecture — Declarative, signed, verifiable
detection plugins decoupled from the core scanner engine.

Each plugin manifest defines:
  - plugin_id, name, category, version, severity, cve_mapping
  - detection_logic (declarative HTTP path/header/body/regex check)
  - evidence_schema, remediation, test_cases
  - HMAC-SHA256 integrity signature verified before execution
"""
from __future__ import annotations

import difflib
import hashlib
import hmac
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT / "dark") not in sys.path:
    sys.path.insert(0, str(ROOT / "dark"))

import enterprise_db as edb  # noqa: E402

REQUIRED_FIELDS = (
    "plugin_id", "name", "category", "version", "severity",
    "cve_mapping", "detection_logic", "evidence_schema", "remediation", "test_cases",
)

BUILTIN_PLUGINS: List[dict] = [
    {
        "plugin_id": "dark-plg-security-txt",
        "name": "RFC 9116 security.txt Presence Check",
        "category": "web-hygiene",
        "version": "1.0.0",
        "min_dark_version": "4.0.0",
        "provenance": "DARK Core Builtin Ruleset (HMAC-SHA256 local integrity check)",
        "severity": "Info",
        "cwe_ids": ["CWE-200"],
        "cve_mapping": [],
        "detection_logic": {"type": "http_absent_or_match", "path": "/.well-known/security.txt", "expect_status": [200], "must_contain": "Contact:", "flag_when": "missing"},
        "evidence_schema": {"required_keys": ["url", "status_code", "detail"]},
        "remediation": "Publish /.well-known/security.txt per RFC 9116 with a security contact.",
        "test_cases": [
            {"name": "sample_pass", "body": "Contact: mailto:sec@example.com", "status": 200, "expect_hit": False},
            {"name": "sample_missing", "body": "Not Found", "status": 404, "expect_hit": True},
        ],
    },
    {
        "plugin_id": "dark-plg-phpinfo-exposure",
        "name": "Exposed phpinfo() Diagnostic Page",
        "category": "misconfiguration",
        "version": "1.1.0",
        "min_dark_version": "4.0.0",
        "provenance": "DARK Core Builtin Ruleset (HMAC-SHA256 local integrity check)",
        "severity": "Medium",
        "cwe_ids": ["CWE-200"],
        "cve_mapping": [],
        "detection_logic": {"type": "http_match", "path": "/phpinfo.php", "expect_status": [200], "regex": r"PHP Version\s+[0-9]+\.[0-9]+", "flag_when": "matched"},
        "evidence_schema": {"required_keys": ["url", "status_code", "matched_regex"]},
        "remediation": "Remove phpinfo.php and diagnostic scripts from production web roots.",
        "test_cases": [
            {"name": "phpinfo_hit", "body": "<title>phpinfo()</title><h1>PHP Version 8.2.1</h1>", "status": 200, "expect_hit": True},
            {"name": "phpinfo_clean", "body": "<html><body>Home</body></html>", "status": 200, "expect_hit": False},
        ],
    },
    {
        "plugin_id": "dark-plg-spring-actuator-env",
        "name": "Spring Boot Actuator /actuator/env Exposure",
        "category": "api-security",
        "version": "1.0.3",
        "min_dark_version": "4.0.0",
        "provenance": "DARK Core Builtin Ruleset (HMAC-SHA256 local integrity check)",
        "severity": "High",
        "cwe_ids": ["CWE-200", "CWE-284"],
        "cve_mapping": [],
        "detection_logic": {"type": "http_match", "path": "/actuator/env", "expect_status": [200], "must_contain": "propertySources", "flag_when": "matched"},
        "evidence_schema": {"required_keys": ["url", "status_code", "detail"]},
        "remediation": "Disable sensitive Actuator endpoints or restrict behind authenticated admin network.",
        "test_cases": [
            {"name": "actuator_hit", "body": '{"activeProfiles":[],"propertySources":[]}', "status": 200, "expect_hit": True},
            {"name": "actuator_clean", "body": '{"status":"UP"}', "status": 200, "expect_hit": False},
        ],
    },
    {
        "plugin_id": "dark-plg-graphql-playground",
        "name": "Exposed GraphQL Playground / GraphiQL IDE",
        "category": "api-security",
        "version": "1.0.0",
        "min_dark_version": "4.0.0",
        "provenance": "DARK Core Builtin Ruleset (HMAC-SHA256 local integrity check)",
        "severity": "Low",
        "cwe_ids": ["CWE-200"],
        "cve_mapping": [],
        "detection_logic": {"type": "http_match", "path": "/graphiql", "expect_status": [200], "regex": r"(GraphiQL|graphql-playground)", "flag_when": "matched"},
        "evidence_schema": {"required_keys": ["url", "status_code"]},
        "remediation": "Disable interactive GraphQL IDEs in production environments.",
        "test_cases": [
            {"name": "graphiql_hit", "body": "<title>GraphiQL</title>", "status": 200, "expect_hit": True},
            {"name": "graphiql_clean", "body": '{"errors":[{"message":"forbidden"}]}', "status": 403, "expect_hit": False},
        ],
    },
]


def _signing_key() -> bytes:
    env = os.environ.get("DARK_PLUGIN_SIGNING_KEY", "")
    if env:
        return env.encode("utf-8")
    return hashlib.sha256(b"dark-plugin-trust|" + edb._get_vault_master_key()).digest()


def sign_manifest(manifest: dict) -> str:
    canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hmac.new(_signing_key(), canonical, hashlib.sha256).hexdigest()


def verify_manifest_signature(manifest: dict, signature: str) -> bool:
    if not signature:
        return False
    expected = sign_manifest(manifest)
    return hmac.compare_digest(expected, signature)


def validate_manifest(manifest: dict, require_negative_tests: bool = True) -> List[str]:
    errs = []
    for k in REQUIRED_FIELDS:
        if k not in manifest:
            errs.append(f"Missing required manifest field '{k}'")
    logic = manifest.get("detection_logic") or {}
    if not isinstance(logic, dict) or not logic.get("path"):
        errs.append("detection_logic must be an object containing 'path'")
    for bad_cve in (manifest.get("cve_mapping") or []):
        if str(bad_cve).upper().startswith("CWE-"):
            errs.append(f"CWE identifier '{bad_cve}' must be placed in cwe_ids, not cve_mapping")
    tcs = manifest.get("test_cases") or []
    if require_negative_tests:
        if not any(bool(tc.get("expect_hit")) is True for tc in tcs):
            errs.append("Plugin manifest must include at least one positive test case (expect_hit=True)")
        if not any(bool(tc.get("expect_hit")) is False for tc in tcs):
            errs.append("Plugin manifest must include at least one negative test case (expect_hit=False)")
    # Safety check: refuse arbitrary shell/eval code in declarative plugins
    blob = json.dumps(manifest).lower()
    if any(bad in blob for bad in ("os.system", "subprocess", "__import__", "eval(", "exec(")):
        errs.append("Plugin manifest failed safety policy (executable code tokens forbidden)")
    return errs


def ensure_builtin_plugins() -> int:
    with edb._DB_LOCK:
        c = edb._conn()
        try:
            cnt = c.execute("SELECT COUNT(*) AS n FROM plugins").fetchone()["n"]
            if cnt == 0:
                now = time.time()
                for m in BUILTIN_PLUGINS:
                    sig = sign_manifest(m)
                    en = 0 if m["plugin_id"] == "dark-plg-security-txt" else 1
                    c.execute(
                        "INSERT OR IGNORE INTO plugins(plugin_id, manifest_json, signature, enabled, verified, created_at) "
                        "VALUES(?,?,?,?,1,?)",
                        (m["plugin_id"], json.dumps(m, ensure_ascii=False), sig, en, now),
                    )
                c.commit()
                return len(BUILTIN_PLUGINS)
            return cnt
        finally:
            c.close()


ensure_builtin_plugins()


def register_plugin(manifest: dict) -> dict:
    errs = validate_manifest(manifest, require_negative_tests=True)
    if errs:
        raise ValueError("; ".join(errs))
    sig = sign_manifest(manifest)
    now = time.time()
    pid = manifest["plugin_id"]
    with edb._DB_LOCK:
        c = edb._conn()
        try:
            c.execute(
                "INSERT INTO plugins(plugin_id, manifest_json, signature, enabled, verified, created_at) "
                "VALUES(?,?,?,1,1,?) "
                "ON CONFLICT(plugin_id) DO UPDATE SET manifest_json=excluded.manifest_json, signature=excluded.signature, verified=1",
                (pid, json.dumps(manifest, ensure_ascii=False), sig, now),
            )
            c.commit()
        finally:
            c.close()
    return {
        "plugin_id": pid,
        "signature": sig,
        "integrity_check": "HMAC-SHA256 (shared local key — not third-party PKI)",
        "verified": True,
        "enabled": True,
    }


def list_plugins() -> List[dict]:
    ensure_builtin_plugins()
    with edb._DB_LOCK:
        c = edb._conn()
        try:
            rows = c.execute("SELECT * FROM plugins ORDER BY plugin_id ASC").fetchall()
            out = []
            for r in rows:
                m = json.loads(r["manifest_json"])
                sig_ok = verify_manifest_signature(m, r["signature"])
                out.append({
                    "plugin_id": r["plugin_id"],
                    "manifest": m,
                    "signature": r["signature"],
                    "signature_valid": sig_ok,
                    "integrity_status": "HMAC-Verified (Shared Key — Not Independent Publisher PKI)" if sig_ok else "HMAC-Invalid",
                    "enabled": bool(r["enabled"]),
                })
            return out
        finally:
            c.close()


def toggle_plugin(plugin_id: str, enabled: bool) -> bool:
    with edb._DB_LOCK:
        c = edb._conn()
        try:
            cur = c.execute("UPDATE plugins SET enabled=? WHERE plugin_id=?", (1 if enabled else 0, plugin_id))
            c.commit()
            return cur.rowcount > 0
        finally:
            c.close()


def _eval_logic(logic: dict, status: int, body: str) -> bool:
    statuses = logic.get("expect_status") or [200]
    status_ok = status in statuses
    cond_ok = status_ok
    if cond_ok and logic.get("must_contain"):
        cond_ok = logic["must_contain"] in body
    if cond_ok and logic.get("regex"):
        cond_ok = bool(re.search(logic["regex"], body))
    flag_when = logic.get("flag_when", "matched")
    return (not cond_ok) if flag_when == "missing" else cond_ok


def run_plugin_tests(plugin_id: str) -> dict:
    for p in list_plugins():
        if p["plugin_id"] == plugin_id:
            if not p["signature_valid"]:
                return {"plugin_id": plugin_id, "passed": False, "error": "Signature verification failed"}
            m = p["manifest"]
            results = []
            all_ok = True
            for tc in (m.get("test_cases") or []):
                hit = _eval_logic(m["detection_logic"], int(tc.get("status", 200)), str(tc.get("body", "")))
                ok = (hit == bool(tc.get("expect_hit")))
                all_ok = all_ok and ok
                results.append({"name": tc.get("name"), "ok": ok, "got_hit": hit, "want_hit": bool(tc.get("expect_hit"))})
            return {"plugin_id": plugin_id, "passed": all_ok, "cases": results}
    raise ValueError("Plugin not found")


def execute_enabled_plugins(client, base_url: str) -> List[dict]:
    findings: List[dict] = []
    # Soft-404 calibration: catch-all 200 responses must never trigger plugin matches
    s404_status = None
    s404_body = ""
    probe_r = client.request("GET", urljoin(base_url.rstrip("/") + "/", "dark-nonexistent-plugin-probe-91827"))
    if probe_r is not None and probe_r.status_code == 200:
        s404_status = 200
        s404_body = probe_r.text or ""

    for p in list_plugins():
        if not p["enabled"] or not p["signature_valid"]:
            continue
        m = p["manifest"]
        logic = m["detection_logic"]
        target_url = urljoin(base_url.rstrip("/") + "/", str(logic["path"]).lstrip("/"))
        r = client.request("GET", target_url)
        if r is None:
            continue
        body = r.text or ""
        if s404_status == 200 and r.status_code == 200 and s404_body:
            if body == s404_body or difflib.SequenceMatcher(None, s404_body[:2000], body[:2000]).ratio() >= 0.88:
                continue
        if _eval_logic(logic, r.status_code, body):
            findings.append({
                "vuln_type": f"[Plugin:{m['plugin_id']}] {m['name']}",
                "severity": m["severity"],
                "url": target_url,
                "parameter": m["plugin_id"],
                "how_it_entered": f"Signed Plugin Marketplace check ({m['plugin_id']} v{m['version']})",
                "evidence": f"HTTP {r.status_code} matched plugin logic on {logic['path']}",
                "remediation": m["remediation"],
                "cwe": (m.get("cve_mapping") or ["CWE-200"])[0],
            })
    return findings
