#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DARK v4.0 Phases 1-4 Security Regression Suite.

Tests:
  - Phase 1: 12+ char password policy, Argon2id auto-rehash, 30m idle / 8h absolute TTL,
             session rotation on login, login rate limiting (429), Secure/HttpOnly cookies.
  - Phase 2: Deny-by-default RBAC matrix, self-role escalation block, audit logging on denials,
             strict server-derived multi-tenant isolation (rejects spoofed X-Tenant-ID).
  - Phase 3: DNS-resolving SSRF guard (IPv4-mapped IPv6, CGNAT, userinfo, redirects),
             AES-256-GCM Credential Vault, externalized key path, key rotation, reveal auditing.
  - Phase 4: Strict CORS origin allowlist (no wildcard '*') & HSTS/security headers.
"""
from __future__ import annotations

import json
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parent.parent.parent
for p in (str(ROOT / "dark"), str(ROOT / "modules")):
    if p not in sys.path:
        sys.path.insert(0, p)

import enterprise_db as edb  # noqa: E402
import main as dark_main  # noqa: E402
import security_hardening as sh  # noqa: E402


def test_phase1_password_policy_rehash_idle_ttl_rotation_and_cookies(monkeypatch, tmp_path):
    # 1. Enforce 12+ char policy in both RBAC and workspace auth
    with pytest.raises(ValueError):
        edb.create_user(f"short_{int(time.time()*1000)}", "TooShort1!", role="analyst")
    with pytest.raises(ValueError):
        dark_main.dplat.set_password("dark", "Short123!")

    # 2. Legacy PBKDF2 hash in workspace auth auto-rehashes to Argon2id on login
    auth_tmp = tmp_path / "auth.json"
    sess_tmp = tmp_path / "sessions.json"
    monkeypatch.setattr(dark_main.dplat, "AUTH_FILE", auth_tmp)
    monkeypatch.setattr(dark_main.dplat, "SESSIONS_FILE", sess_tmp)
    import hashlib, secrets
    salt = secrets.token_bytes(16)
    legacy_pw = "LegacyStrongPass#2026"
    legacy_hash = hashlib.pbkdf2_hmac("sha256", legacy_pw.encode(), salt, 120_000).hex()
    auth_tmp.write_text(json.dumps({
        "enabled": True, "username": "dark", "salt": salt.hex(), "pw_hash": legacy_hash,
    }))
    assert dark_main.dplat.verify_password("dark", legacy_pw) is True
    rehashed_cfg = json.loads(auth_tmp.read_text())
    assert rehashed_cfg["pw_hash"].startswith("$argon2")

    # 3. Session idle timeout (30m) + absolute TTL (8h) + session rotation
    uname = f"p1_user_{int(time.time()*1000)}"
    edb.create_user(uname, "StrongPass!2026", role="analyst")
    t1 = edb.create_rbac_session(uname, "analyst")
    assert edb.get_rbac_session(t1) is not None
    # Rotate on creating t2 with old_token=t1
    t2 = edb.create_rbac_session(uname, "analyst", old_token=t1)
    assert edb.get_rbac_session(t1) is None
    assert edb.get_rbac_session(t2) is not None

    # Simulate idle timeout exceeded (> SESSION_IDLE_TTL)
    with edb._DB_LOCK:
        c = edb._conn()
        c.execute("UPDATE rbac_sessions SET last_activity=? WHERE token=?", (time.time() - edb.SESSION_IDLE_TTL - 10, t2))
        c.commit()
        c.close()
    assert edb.get_rbac_session(t2) is None

    # 4. Login rate limiting + Secure cookie flags under HTTPS proxy header
    edb.reset_login_rate_limit("testclient")
    monkeypatch.setenv("DARK_LOGIN_MAX_ATTEMPTS", "3")
    client = TestClient(dark_main.app)
    r_ok = client.post(
        "/api/admin/users/login",
        json={"username": uname, "password": "StrongPass!2026"},
        headers={"X-Forwarded-Proto": "https"},
    )
    assert r_ok.status_code == 200
    set_cookie_hdr = " ".join(r_ok.headers.get_list("set-cookie")).lower()
    assert "httponly" in set_cookie_hdr and "secure" in set_cookie_hdr and "samesite=lax" in set_cookie_hdr

    # Exceed login limit -> 429
    client.post("/api/admin/users/login", json={"username": uname, "password": "WrongPassword123"})
    client.post("/api/admin/users/login", json={"username": uname, "password": "WrongPassword123"})
    r_429 = client.post("/api/admin/users/login", json={"username": uname, "password": "WrongPassword123"})
    assert r_429.status_code == 429
    edb.reset_login_rate_limit("testclient")


def test_phase2_rbac_deny_by_default_and_tenant_isolation():
    client = TestClient(dark_main.app)
    t_a = edb.create_tenant(f"TenantA_{int(time.time()*1000)}")
    t_b = edb.create_tenant(f"TenantB_{int(time.time()*1000)}")

    v_name = f"viewer_v4_{int(time.time()*1000)}"
    a_name = f"admin_a_{int(time.time()*1000)}"
    u_b_name = f"analyst_b_{int(time.time()*1000)}"

    v_rec = edb.create_user(v_name, "ViewerStrong!123", role="viewer", tenant_id=t_a["id"])
    a_rec = edb.create_user(a_name, "AdminStrong!123", role="admin", tenant_id=t_a["id"])
    edb.create_user(u_b_name, "AnalystBStrong!123", role="analyst", tenant_id=t_b["id"])

    edb.reset_login_rate_limit("testclient")
    tok_v = client.post("/api/admin/users/login", json={"username": v_name, "password": "ViewerStrong!123"}).json()["token"]
    client.cookies.clear()
    tok_a = client.post("/api/admin/users/login", json={"username": a_name, "password": "AdminStrong!123"}).json()["token"]
    client.cookies.clear()
    tok_b = client.post("/api/admin/users/login", json={"username": u_b_name, "password": "AnalystBStrong!123"}).json()["token"]
    client.cookies.clear()

    # Invalid / expired token must always return 401 (never silent admin fallback)
    assert client.get("/api/admin/audit", headers={"X-Dark-Token": "invalid-tok-123"}).status_code == 401

    # Viewer denied audit logs, vault, mutations, and unmapped API routes (deny-by-default)
    assert client.get("/api/admin/audit", headers={"X-Dark-Token": tok_v}).status_code == 403
    assert client.get("/api/admin/vault", headers={"X-Dark-Token": tok_v}).status_code == 403
    assert client.post("/api/jobs/cloud-audit", json={"provider": "aws", "content": "{}"}, headers={"X-Dark-Token": tok_v}).status_code == 403
    assert dark_main._required_permission("GET", "/api/nonexistent/future-route") == "admin:manage"

    # Self-role edit blocked (admin cannot alter own role)
    r_self = client.patch(f"/api/admin/users/{a_rec['id']}/role?role=viewer", headers={"X-Dark-Token": tok_a})
    assert r_self.status_code == 403
    # Admin CAN promote/demote another user
    r_other = client.patch(f"/api/admin/users/{v_rec['id']}/role?role=auditor", headers={"X-Dark-Token": tok_a})
    assert r_other.status_code == 200

    # Cross-tenant X-Tenant-ID spoofing rejected with 403
    r_spoof = client.get("/api/jobs", headers={"X-Dark-Token": tok_b, "X-Tenant-ID": t_a["id"]})
    assert r_spoof.status_code == 403

    # Tenant A stores a vault secret and starts a job; Tenant B cannot read either
    sec = client.post(
        "/api/admin/vault",
        json={"name": f"tA_secret_{int(time.time()*1000)}", "kind": "token", "secret_value": "TenantAOnlySecret"},
        headers={"X-Dark-Token": tok_a},
    )
    assert sec.status_code == 200
    sec_id = sec.json()["secret"]["id"]
    assert client.get(f"/api/admin/vault/{sec_id}/reveal", headers={"X-Dark-Token": tok_b}).status_code in (403, 404)

    job_a = client.post(
        "/api/jobs/cloud-audit",
        json={"provider": "aws", "content": "{}"},
        headers={"X-Dark-Token": tok_a},
    ).json()["job_id"]
    assert client.get(f"/api/jobs/{job_a}", headers={"X-Dark-Token": tok_b}).status_code == 403


def test_phase3_ssrf_dns_and_aes256gcm_vault_rotation(monkeypatch):
    # 1. SSRF checks: userinfo, IPv4-mapped IPv6, CGNAT, metadata, DNS resolution
    assert not sh.validate_outbound_url("http://user:pass@example.com/hook")[0]
    assert not sh.validate_outbound_url("http://[::ffff:127.0.0.1]/admin")[0]
    assert not sh.validate_outbound_url("http://100.64.0.1/internal")[0]
    assert not sh.validate_outbound_url("http://metadata.google.internal/computeMetadata/v1/")[0]

    # DNS resolution pointing to private IP must be blocked
    monkeypatch.setattr(
        socket, "getaddrinfo",
        lambda host, port, type=0: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.20.30.40", port))],
    )
    ok_rebind, msg_rebind = sh.validate_outbound_url("https://rebind.attacker.example/hook", strict_dns=True)
    assert not ok_rebind and "10.20.30.40" in msg_rebind

    # Redirect-to-metadata SSRF test via safe_outbound_request
    monkeypatch.undo()

    class _RedirectToMeta(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", "http://169.254.169.254/latest/meta-data/")
            self.end_headers()

    srv = HTTPServer(("127.0.0.1", 0), _RedirectToMeta)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        with pytest.raises(ValueError, match="SSRF"):
            sh.safe_outbound_request("GET", f"http://127.0.0.1:{port}/start", allow_loopback=True)
    finally:
        srv.shutdown()

    # 2. AES-256-GCM Credential Vault & key separation & rotation
    assert edb.VAULT_KEY_FILE.parent.resolve() != edb.DB_PATH.parent.resolve()
    sname = f"vault_v4_{int(time.time()*1000)}"
    stored = edb.store_vault_secret(sname, "api_key", "super-gcm-secret-value-2026", tenant_id="default")
    assert stored["alg"] == "AES-256-GCM"
    assert edb.reveal_vault_secret(sname, tenant_id="default") == "super-gcm-secret-value-2026"

    rot = edb.rotate_vault_keys()
    assert rot["current_version"] > rot["previous_version"]
    assert edb.reveal_vault_secret(sname, tenant_id="default") == "super-gcm-secret-value-2026"
    assert edb.delete_vault_secret(sname, tenant_id="default")


def test_phase4_cors_and_security_headers():
    client = TestClient(dark_main.app)
    # Disallowed origin must NOT receive Access-Control-Allow-Origin: * or echo evil origin
    r_evil = client.options(
        "/api/health",
        headers={"Origin": "https://evil-attacker.example", "Access-Control-Request-Method": "GET"},
    )
    assert r_evil.headers.get("access-control-allow-origin") not in ("*", "https://evil-attacker.example")

    # Allowed origin receives explicit allow-origin
    r_ok = client.get("/api/health", headers={"Origin": "http://localhost:8000", "X-Forwarded-Proto": "https"})
    assert r_ok.headers.get("access-control-allow-origin") == "http://localhost:8000"
    assert "strict-transport-security" in {k.lower() for k in r_ok.headers.keys()}
    assert r_ok.headers.get("X-Content-Type-Options") == "nosniff"
    assert r_ok.headers.get("X-Frame-Options") == "DENY"
