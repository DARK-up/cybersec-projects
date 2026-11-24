#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DARK Enterprise Core — SQLite persistence, RBAC, TOTP 2FA, Tamper-evident
Audit Trail, Credential Vault, Scope Allowlist, Worker Health, Scheduler,
Job Recovery, and Backup/Restore.
"""
from __future__ import annotations

import base64
import contextvars
import hashlib
import hmac
import ipaddress
import json
import os
import secrets
import sqlite3
import struct
import threading
import time
import uuid
from collections import deque
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

APP_DIR = Path(__file__).resolve().parent
DATA_DIR = APP_DIR / "data"
DB_PATH = DATA_DIR / "dark_enterprise.db"
VAULT_KEY_FILE = Path(
    os.environ.get("DARK_VAULT_KEY_PATH")
    or str(Path.home() / ".dark_keys" / "vault_keyring.json")
)

import sys as _sys
if str(APP_DIR) not in _sys.path:
    _sys.path.insert(0, str(APP_DIR))
import db_migrations as _dbm
import security_hardening as _sh

_DB_LOCK = threading.RLock()
PBKDF2_ROUNDS = 120_000
SESSION_IDLE_TTL = int(os.environ.get("DARK_SESSION_IDLE_TTL", str(30 * 60)))
SESSION_ABSOLUTE_TTL = int(os.environ.get("DARK_SESSION_ABSOLUTE_TTL", str(8 * 3600)))

ROLES: Dict[str, List[str]] = {
    "admin": [
        "scan:run", "scan:stop", "report:read", "remediation:write",
        "plugin:manage", "intel:read", "intel:sync", "compliance:read",
        "audit:read", "asset:write", "threat:write",
        "vault:read", "vault:write", "vault:delete", "vault:use",
        "user:manage", "apikey:manage", "tenant:manage",
        "backup:manage", "admin:manage",
    ],
    "analyst": [
        "scan:run", "scan:stop", "report:read", "remediation:write",
        "intel:read", "intel:sync", "compliance:read",
        "asset:write", "threat:write", "vault:read", "vault:use",
    ],
    "auditor": [
        "report:read", "compliance:read", "audit:read",
        "remediation:write", "intel:read",
    ],
    "viewer": [
        "report:read", "compliance:read", "intel:read",
    ],
}


def _conn() -> Any:
    pg_dsn = os.environ.get("DARK_POSTGRES_DSN", "").strip()
    if pg_dsn:
        try:
            import psycopg  # type: ignore
            from psycopg.rows import dict_row  # type: ignore
        except ImportError as e:
            raise RuntimeError(
                "DARK_POSTGRES_DSN is configured, but the PostgreSQL driver ('psycopg') is not installed. "
                "Install 'psycopg[binary]' or unset DARK_POSTGRES_DSN to use SQLite."
            ) from e
        try:
            return _dbm.PostgresCompatConnection(psycopg.connect(pg_dsn, row_factory=dict_row))
        except Exception as e:
            raise RuntimeError(f"Failed to connect to PostgreSQL configured via DARK_POSTGRES_DSN: {e}") from e
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(str(DB_PATH), check_same_thread=False, timeout=15.0)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA foreign_keys=ON")
    return c


def init_db() -> None:
    with _DB_LOCK:
        c = _conn()
        try:
            c.executescript(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    role TEXT NOT NULL DEFAULT 'analyst',
                    pw_hash TEXT NOT NULL,
                    pw_salt TEXT NOT NULL,
                    totp_secret TEXT DEFAULT '',
                    totp_enabled INTEGER NOT NULL DEFAULT 0,
                    active INTEGER NOT NULL DEFAULT 1,
                    created_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts REAL NOT NULL,
                    actor TEXT NOT NULL,
                    role TEXT NOT NULL,
                    action TEXT NOT NULL,
                    resource TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    ip TEXT NOT NULL DEFAULT '',
                    prev_hash TEXT NOT NULL,
                    entry_hash TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS vault_secrets (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    nonce_b64 TEXT NOT NULL,
                    cipher_b64 TEXT NOT NULL,
                    mac_b64 TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    tenant_id TEXT NOT NULL DEFAULT 'default',
                    key_version INTEGER NOT NULL DEFAULT 1,
                    alg TEXT NOT NULL DEFAULT 'AES-256-GCM',
                    updated_at REAL NOT NULL DEFAULT 0,
                    UNIQUE(tenant_id, name)
                );
                CREATE TABLE IF NOT EXISTS scope_rules (
                    id TEXT PRIMARY KEY,
                    pattern TEXT NOT NULL,
                    rule_type TEXT NOT NULL DEFAULT 'allow',
                    note TEXT DEFAULT '',
                    created_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS assets (
                    id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL DEFAULT 'default',
                    kind TEXT NOT NULL,
                    name TEXT NOT NULL,
                    criticality TEXT NOT NULL DEFAULT 'medium',
                    internet_exposed INTEGER NOT NULL DEFAULT 1,
                    meta_json TEXT NOT NULL DEFAULT '{}',
                    first_seen REAL NOT NULL,
                    last_seen REAL NOT NULL,
                    UNIQUE(project_id, kind, name)
                );
                CREATE TABLE IF NOT EXISTS asset_relations (
                    id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL DEFAULT 'default',
                    src_asset_id TEXT NOT NULL,
                    dst_asset_id TEXT NOT NULL,
                    relation TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    UNIQUE(project_id, src_asset_id, dst_asset_id, relation)
                );
                CREATE TABLE IF NOT EXISTS vuln_feed (
                    cve_id TEXT PRIMARY KEY,
                    cpe_prefix TEXT NOT NULL DEFAULT '',
                    product TEXT NOT NULL DEFAULT '',
                    version_lt TEXT NOT NULL DEFAULT '',
                    severity TEXT NOT NULL DEFAULT 'High',
                    cvss_v31 REAL NOT NULL DEFAULT 7.5,
                    cvss_v40 REAL NOT NULL DEFAULT 7.5,
                    epss REAL NOT NULL DEFAULT 0.15,
                    kev INTEGER NOT NULL DEFAULT 0,
                    summary TEXT NOT NULL DEFAULT '',
                    remediation TEXT NOT NULL DEFAULT '',
                    updated_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS remediation_tickets (
                    id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL DEFAULT 'default',
                    job_id TEXT DEFAULT '',
                    finding_key TEXT NOT NULL,
                    title TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    target TEXT NOT NULL,
                    assignee TEXT DEFAULT '',
                    due_date TEXT DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'open',
                    notes_json TEXT NOT NULL DEFAULT '[]',
                    evidence_json TEXT NOT NULL DEFAULT '[]',
                    retest_history_json TEXT NOT NULL DEFAULT '[]',
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS workers (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'online',
                    capacity INTEGER NOT NULL DEFAULT 16,
                    active_jobs INTEGER NOT NULL DEFAULT 0,
                    cpu_pct REAL NOT NULL DEFAULT 0.0,
                    ram_mb REAL NOT NULL DEFAULT 0.0,
                    last_heartbeat REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS schedules (
                    id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL DEFAULT 'default',
                    name TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    interval_minutes INTEGER NOT NULL DEFAULT 1440,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    last_run REAL DEFAULT 0,
                    next_run REAL NOT NULL,
                    created_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS plugins (
                    plugin_id TEXT PRIMARY KEY,
                    manifest_json TEXT NOT NULL,
                    signature TEXT NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    verified INTEGER NOT NULL DEFAULT 1,
                    created_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS rbac_sessions (
                    token TEXT PRIMARY KEY,
                    username TEXT NOT NULL,
                    role TEXT NOT NULL,
                    expires_at REAL NOT NULL
                );
                """
            )
            c.commit()
            _dbm.apply_sqlite_migrations(c)
        finally:
            c.close()


init_db()

_CURRENT_ACTOR: contextvars.ContextVar = contextvars.ContextVar("dark_actor", default=None)
_RATE_BUCKETS: Dict[str, deque] = {}
_LOGIN_BUCKETS: Dict[str, deque] = {}
_RATE_LOCK = threading.Lock()


def set_current_actor(username: str, role: str, ip: str = "", tenant_id: str = "default") -> Any:
    return _CURRENT_ACTOR.set({"username": username, "role": role, "ip": ip, "tenant_id": tenant_id or "default"})


def reset_current_actor(token: Any) -> None:
    if token is not None:
        try:
            _CURRENT_ACTOR.reset(token)
        except Exception:
            pass


def get_current_actor() -> dict:
    return _CURRENT_ACTOR.get() or {"username": "operator", "role": "admin", "ip": "", "tenant_id": "default"}


def get_current_tenant() -> str:
    return (get_current_actor().get("tenant_id") or "default").strip() or "default"


def log_current_audit(action: str, resource: str = "", detail: str = "") -> None:
    act = get_current_actor()
    log_audit(
        act.get("username", "operator"),
        act.get("role", "admin"),
        action,
        resource,
        detail,
        act.get("ip", ""),
        tenant_id=act.get("tenant_id", "default"),
    )


def check_rate_limit(client_ip: str = "global") -> Tuple[bool, int]:
    cfg = get_rate_limit_config()
    limit = int(cfg.get("max_requests_per_sec") or 25) * 2
    now = time.time()
    key = client_ip or "global"
    with _RATE_LOCK:
        dq = _RATE_BUCKETS.setdefault(key, deque())
        while dq and now - dq[0] > 2.0:
            dq.popleft()
        if len(dq) >= limit:
            return False, limit
        dq.append(now)
        return True, limit


def check_login_rate_limit(client_ip: str = "global", max_attempts: int = 12, window_s: float = 60.0) -> Tuple[bool, int]:
    """Strict rate limiter for authentication endpoints (prevents online brute-force)."""
    now = time.time()
    key = client_ip or "global"
    limit = int(os.environ.get("DARK_LOGIN_MAX_ATTEMPTS", str(max_attempts)))
    with _RATE_LOCK:
        dq = _LOGIN_BUCKETS.setdefault(key, deque())
        while dq and now - dq[0] > window_s:
            dq.popleft()
        if len(dq) >= limit:
            return False, limit
        dq.append(now)
        return True, limit


def reset_login_rate_limit(client_ip: str = "global") -> None:
    key = client_ip or "global"
    with _RATE_LOCK:
        _LOGIN_BUCKETS.pop(key, None)


def get_db_status() -> dict:
    return _dbm.get_backend_info()


def create_rbac_session(
    username: str,
    role: str,
    ttl_seconds: Optional[int] = None,
    tenant_id: str = "default",
    old_token: Optional[str] = None,
) -> str:
    tok = secrets.token_urlsafe(32)
    now = time.time()
    abs_ttl = int(ttl_seconds if ttl_seconds is not None else SESSION_ABSOLUTE_TTL)
    exp = now + abs_ttl
    tid = (tenant_id or "default").strip() or "default"
    with _DB_LOCK:
        c = _conn()
        try:
            if old_token:
                c.execute("DELETE FROM rbac_sessions WHERE token=?", (old_token,))
            c.execute("DELETE FROM rbac_sessions WHERE expires_at < ?", (now,))
            c.execute(
                "INSERT INTO rbac_sessions(token, username, role, tenant_id, expires_at, created_at, last_activity) "
                "VALUES(?,?,?,?,?,?,?)",
                (tok, username, role, tid, exp, now, now),
            )
            c.commit()
        finally:
            c.close()
    return tok


def get_rbac_session(token: Optional[str]) -> Optional[dict]:
    if not token:
        return None
    now = time.time()
    with _DB_LOCK:
        c = _conn()
        try:
            row = c.execute(
                "SELECT token, username, role, tenant_id, expires_at, created_at, last_activity "
                "FROM rbac_sessions WHERE token=?",
                (token,),
            ).fetchone()
            if not row:
                return None
            last_act = float(row["last_activity"] or row["created_at"] or now)
            if float(row["expires_at"]) < now or (now - last_act) > SESSION_IDLE_TTL:
                c.execute("DELETE FROM rbac_sessions WHERE token=?", (token,))
                c.commit()
                return None
            if (now - last_act) >= 5.0 or not row["last_activity"]:
                c.execute("UPDATE rbac_sessions SET last_activity=? WHERE token=?", (now, token))
                c.commit()
            return {
                "username": row["username"],
                "role": row["role"],
                "tenant_id": row["tenant_id"] or "default",
                "permissions": ROLES.get(row["role"], []),
                "expires_at": row["expires_at"],
                "last_activity": now,
            }
        finally:
            c.close()


def revoke_user_sessions(username: str) -> int:
    with _DB_LOCK:
        c = _conn()
        try:
            cur = c.execute("DELETE FROM rbac_sessions WHERE username=?", (username,))
            c.commit()
            return cur.rowcount
        finally:
            c.close()


def delete_rbac_session(token: Optional[str]) -> None:
    if not token:
        return
    with _DB_LOCK:
        c = _conn()
        try:
            c.execute("DELETE FROM rbac_sessions WHERE token=?", (token,))
            c.commit()
        finally:
            c.close()


# ---------------------------------------------------------------------------
# Settings & Governance (Scope Allowlist, Rate Limits, Emergency Stop)
# ---------------------------------------------------------------------------
def get_setting(key: str, default: Any = None) -> Any:
    with _DB_LOCK:
        c = _conn()
        try:
            row = c.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
            if not row:
                return default
            return json.loads(row["value"])
        except Exception:
            return default
        finally:
            c.close()


def set_setting(key: str, value: Any) -> None:
    with _DB_LOCK:
        c = _conn()
        try:
            c.execute(
                "INSERT INTO settings(key, value) VALUES(?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, json.dumps(value)),
            )
            c.commit()
        finally:
            c.close()


def is_emergency_stopped() -> bool:
    return bool(get_setting("emergency_stop", False))


def set_emergency_stop(flag: bool) -> None:
    set_setting("emergency_stop", bool(flag))


def get_rate_limit_config() -> dict:
    return get_setting("rate_limit", {"max_requests_per_sec": 25, "max_concurrent_jobs": 16})


def set_rate_limit_config(max_rps: int = 25, max_jobs: int = 16) -> dict:
    cfg = {
        "max_requests_per_sec": max(1, min(int(max_rps), 500)),
        "max_concurrent_jobs": max(1, min(int(max_jobs), 64)),
    }
    set_setting("rate_limit", cfg)
    return cfg


def list_scope_rules() -> List[dict]:
    with _DB_LOCK:
        c = _conn()
        try:
            rows = c.execute("SELECT * FROM scope_rules ORDER BY created_at DESC").fetchall()
            return [dict(r) for r in rows]
        finally:
            c.close()


def add_scope_rule(pattern: str, rule_type: str = "allow", note: str = "") -> dict:
    pat = (pattern or "").strip()
    if not pat:
        raise ValueError("Scope pattern required")
    rtype = "deny" if rule_type == "deny" else "allow"
    rule = {
        "id": uuid.uuid4().hex[:10],
        "pattern": pat,
        "rule_type": rtype,
        "note": (note or "")[:200],
        "created_at": time.time(),
    }
    with _DB_LOCK:
        c = _conn()
        try:
            c.execute(
                "INSERT INTO scope_rules(id, pattern, rule_type, note, created_at) VALUES(?,?,?,?,?)",
                (rule["id"], rule["pattern"], rule["rule_type"], rule["note"], rule["created_at"]),
            )
            c.commit()
        finally:
            c.close()
    return rule


def delete_scope_rule(rule_id: str) -> bool:
    with _DB_LOCK:
        c = _conn()
        try:
            cur = c.execute("DELETE FROM scope_rules WHERE id=?", (rule_id,))
            c.commit()
            return cur.rowcount > 0
        finally:
            c.close()


def _extract_host(target: str) -> str:
    t = (target or "").strip()
    if not t:
        return ""
    if "://" in t:
        return (urlsplit(t).hostname or "").lower()
    return t.split("/")[0].split(":")[0].lower()


def _match_scope_pattern(host: str, target: str, pat: str) -> bool:
    p = pat.strip().lower()
    if not p:
        return False
    if p == "*":
        return True
    # CIDR match
    if "/" in p and "://" not in p:
        try:
            net = ipaddress.ip_network(p, strict=False)
            ip = ipaddress.ip_address(host)
            return ip in net
        except Exception:
            pass
    # Wildcard domain (*.example.com)
    if p.startswith("*."):
        suf = p[1:]
        return host == p[2:] or host.endswith(suf)
    return host == p or p in target.lower()


def check_target_in_scope(target: str) -> Tuple[bool, str]:
    """Enforce scope allowlist/denylist when configured or scope_enforced=True."""
    enforced = bool(get_setting("scope_enforced", False))
    rules = list_scope_rules()
    host = _extract_host(target)
    if not host:
        return (not enforced), ("Empty target host" if enforced else "No host")
    denies = [r for r in rules if r["rule_type"] == "deny"]
    for r in denies:
        if _match_scope_pattern(host, target, r["pattern"]):
            return False, f"Target '{host}' blocked by deny rule '{r['pattern']}'"
    allows = [r for r in rules if r["rule_type"] == "allow"]
    if not enforced and not allows:
        return True, "Scope unrestricted"
    if enforced and not allows:
        return False, "Scope enforcement is ON with an empty allowlist"
    for r in allows:
        if _match_scope_pattern(host, target, r["pattern"]):
            return True, f"Matched allow rule '{r['pattern']}'"
    if enforced:
        return False, f"Target '{host}' is outside configured scope allowlist"
    return True, "Allowed"


# ---------------------------------------------------------------------------
# Tamper-Evident Audit Trail (SHA-256 Hash Chain, Canonical JSON v2)
# ---------------------------------------------------------------------------
AUDIT_CHECKPOINT_FILE = VAULT_KEY_FILE.parent / "audit_checkpoint.json"


def _audit_canonical_v2(
    ts: float, actor: str, role: str, action: str, resource: str,
    detail: str, ip: str, tenant_id: str, prev_hash: str,
) -> str:
    obj = {
        "v": 2,
        "ts": f"{float(ts):.6f}",
        "actor": str(actor or "system"),
        "role": str(role or "system"),
        "action": str(action),
        "resource": str(resource),
        "detail": str(detail or ""),
        "ip": str(ip or ""),
        "tenant_id": str(tenant_id or "default"),
        "prev_hash": str(prev_hash),
    }
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _write_audit_checkpoint(last_id: int, entry_hash: str, ts: float) -> None:
    try:
        AUDIT_CHECKPOINT_FILE.parent.mkdir(parents=True, exist_ok=True)
        AUDIT_CHECKPOINT_FILE.write_text(
            json.dumps({"last_id": int(last_id), "head_hash": entry_hash, "ts": ts}),
            encoding="utf-8",
        )
    except Exception:
        pass


def log_audit(actor: str, role: str, action: str, resource: str,
              detail: str = "", ip: str = "", tenant_id: Optional[str] = None) -> dict:
    ctx = _CURRENT_ACTOR.get()
    if ctx and actor in ("operator", "admin", ""):
        actor = ctx.get("username") or actor
        role = ctx.get("role") or role
        if not ip:
            ip = ctx.get("ip") or ""
    tid = tenant_id or (ctx.get("tenant_id") if ctx else None) or "default"
    actor_s = actor or "system"
    role_s = role or "system"
    detail_stored = str(detail or "")[:2000]
    ts = time.time()
    with _DB_LOCK:
        c = _conn()
        try:
            last = c.execute("SELECT entry_hash FROM audit_logs ORDER BY id DESC LIMIT 1").fetchone()
            prev_hash = last["entry_hash"] if last else ("0" * 64)
            payload = _audit_canonical_v2(ts, actor_s, role_s, action, resource, detail_stored, ip, tid, prev_hash)
            entry_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
            cur = c.execute(
                "INSERT INTO audit_logs(ts, actor, role, action, resource, detail, ip, prev_hash, entry_hash, tenant_id, chain_version) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,2)",
                (ts, actor_s, role_s, action, resource, detail_stored, ip, prev_hash, entry_hash, tid),
            )
            c.commit()
            _write_audit_checkpoint(cur.lastrowid, entry_hash, ts)
            return {
                "id": cur.lastrowid, "ts": ts, "actor": actor_s, "role": role_s, "tenant_id": tid,
                "action": action, "resource": resource, "detail": detail_stored,
                "ip": ip, "prev_hash": prev_hash, "entry_hash": entry_hash, "chain_version": 2,
            }
        finally:
            c.close()


def list_audit_logs(limit: int = 100, tenant_id: Optional[str] = None) -> List[dict]:
    with _DB_LOCK:
        c = _conn()
        try:
            if tenant_id:
                rows = c.execute(
                    "SELECT * FROM audit_logs WHERE tenant_id=? ORDER BY id DESC LIMIT ?",
                    (tenant_id, max(1, min(limit, 1000))),
                ).fetchall()
            else:
                rows = c.execute(
                    "SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?", (max(1, min(limit, 1000)),)
                ).fetchall()
            return [dict(r) for r in rows]
        finally:
            c.close()


def verify_audit_chain() -> dict:
    with _DB_LOCK:
        c = _conn()
        try:
            rows = c.execute("SELECT * FROM audit_logs ORDER BY id ASC").fetchall()
            prev = "0" * 64
            for r in rows:
                if r["prev_hash"] != prev:
                    return {"valid": False, "broken_at_id": r["id"], "checked": len(rows)}
                ver = int(r["chain_version"] or 1) if "chain_version" in r.keys() else 1
                if ver >= 2:
                    rtid = r["tenant_id"] if "tenant_id" in r.keys() else "default"
                    payload = _audit_canonical_v2(
                        r["ts"], r["actor"], r["role"], r["action"],
                        r["resource"], r["detail"], r["ip"], rtid, r["prev_hash"],
                    )
                else:
                    payload = f"{r['ts']:.6f}|{r['actor']}|{r['role']}|{r['action']}|{r['resource']}|{r['detail']}|{r['ip']}|{r['prev_hash']}"
                expected = hashlib.sha256(payload.encode("utf-8")).hexdigest()
                if not hmac.compare_digest(expected, r["entry_hash"]):
                    return {"valid": False, "broken_at_id": r["id"], "checked": len(rows)}
                prev = r["entry_hash"]
            return {"valid": True, "checked": len(rows), "head_hash": prev}
        finally:
            c.close()


# ---------------------------------------------------------------------------
# Users, RBAC & RFC 6238 TOTP 2FA
# ---------------------------------------------------------------------------
def _hash_pw(pw: str, salt_hex: Optional[str] = None) -> Tuple[str, str]:
    salt = bytes.fromhex(salt_hex) if salt_hex else secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt, PBKDF2_ROUNDS)
    return dk.hex(), salt.hex()


def _hotp(secret_b32: str, counter: int, digits: int = 6) -> str:
    pad = "=" * ((8 - len(secret_b32) % 8) % 8)
    key = base64.b32decode(secret_b32.upper() + pad, casefold=True)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    off = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[off:off + 4])[0] & 0x7FFFFFFF
    return str(code % (10 ** digits)).zfill(digits)


def generate_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def verify_totp(secret_b32: str, code: str, window: int = 1) -> bool:
    code = (code or "").strip().replace(" ", "")
    if not secret_b32 or not code.isdigit():
        return False
    now_step = int(time.time() // 30)
    for delta in range(-window, window + 1):
        if hmac.compare_digest(_hotp(secret_b32, now_step + delta), code):
            return True
    return False


def create_user(username: str, password: str, role: str = "analyst", tenant_id: str = "default") -> dict:
    uname = (username or "").strip().lower()
    if len(uname) < 2:
        raise ValueError("Username must be at least 2 characters")
    _sh.validate_password_policy(password)
    if role not in ROLES:
        raise ValueError(f"Role must be one of {list(ROLES)}")
    pw_hash, pw_salt = _sh.hash_password(password)
    uid = uuid.uuid4().hex[:10]
    now = time.time()
    tid = (tenant_id or "default").strip() or "default"
    with _DB_LOCK:
        c = _conn()
        try:
            c.execute(
                "INSERT INTO users(id, username, role, pw_hash, pw_salt, tenant_id, created_at) VALUES(?,?,?,?,?,?,?)",
                (uid, uname, role, pw_hash, pw_salt, tid, now),
            )
            c.commit()
        finally:
            c.close()
    return {"id": uid, "username": uname, "role": role, "tenant_id": tid,
            "totp_enabled": False, "active": True, "created_at": now}


def list_users(tenant_id: Optional[str] = None) -> List[dict]:
    with _DB_LOCK:
        c = _conn()
        try:
            if tenant_id:
                rows = c.execute(
                    "SELECT id, username, role, tenant_id, totp_enabled, active, failed_attempts, locked_until, created_at "
                    "FROM users WHERE tenant_id=? ORDER BY created_at ASC",
                    (tenant_id,),
                ).fetchall()
            else:
                rows = c.execute(
                    "SELECT id, username, role, tenant_id, totp_enabled, active, failed_attempts, locked_until, created_at "
                    "FROM users ORDER BY created_at ASC"
                ).fetchall()
            out = []
            for r in rows:
                d = dict(r)
                d["totp_enabled"] = bool(d["totp_enabled"])
                d["active"] = bool(d["active"])
                d["locked"] = bool((d.get("locked_until") or 0) > time.time())
                d["permissions"] = ROLES.get(d["role"], [])
                out.append(d)
            return out
        finally:
            c.close()


LOCKOUT_THRESHOLD = 5
LOCKOUT_SECONDS = 300


def authenticate_user(username: str, password: str, totp_code: str = "") -> Tuple[bool, Optional[dict], str]:
    uname = (username or "").strip().lower()
    now = time.time()
    with _DB_LOCK:
        c = _conn()
        try:
            row = c.execute("SELECT * FROM users WHERE username=?", (uname,)).fetchone()
            if not row or not row["active"]:
                return False, None, "Invalid credentials"
            locked_until = float(row["locked_until"] or 0)
            if locked_until > now:
                rem_s = int(locked_until - now)
                return False, None, f"Account temporarily locked ({rem_s}s remaining)"
            ok_pw, needs_rehash = _sh.verify_password(password, row["pw_hash"], row["pw_salt"])
            if not ok_pw:
                fails = int(row["failed_attempts"] or 0) + 1
                new_lock = (now + LOCKOUT_SECONDS) if fails >= LOCKOUT_THRESHOLD else 0.0
                c.execute(
                    "UPDATE users SET failed_attempts=?, locked_until=? WHERE id=?",
                    (fails, new_lock, row["id"]),
                )
                c.commit()
                return False, None, ("Account locked after repeated failed attempts" if new_lock else "Invalid credentials")
            if row["totp_enabled"]:
                if not verify_totp(row["totp_secret"], totp_code):
                    return False, None, "2FA TOTP code required or invalid"
            if needs_rehash:
                nh, ns = _sh.hash_password(password)
                c.execute("UPDATE users SET pw_hash=?, pw_salt=? WHERE id=?", (nh, ns, row["id"]))
            c.execute("UPDATE users SET failed_attempts=0, locked_until=0 WHERE id=?", (row["id"],))
            c.commit()
            return True, {
                "id": row["id"], "username": row["username"], "role": row["role"],
                "tenant_id": row["tenant_id"] if "tenant_id" in row.keys() else "default",
                "permissions": ROLES.get(row["role"], []), "totp_enabled": bool(row["totp_enabled"]),
            }, "OK"
        finally:
            c.close()


# ---------------------------------------------------------------------------
# Multi-Tenant Organizations & API Key Management & Job Queue Metadata
# ---------------------------------------------------------------------------
def list_tenants() -> List[dict]:
    with _DB_LOCK:
        c = _conn()
        try:
            rows = c.execute("SELECT * FROM tenants ORDER BY created_at ASC").fetchall()
            out = []
            for r in rows:
                d = dict(r)
                d["active"] = bool(d["active"])
                out.append(d)
            return out
        finally:
            c.close()


def create_tenant(name: str, plan: str = "enterprise", quota_jobs_per_day: int = 500) -> dict:
    nm = (name or "").strip()[:80]
    if len(nm) < 2:
        raise ValueError("Organization name required")
    tid = uuid.uuid4().hex[:10]
    now = time.time()
    with _DB_LOCK:
        c = _conn()
        try:
            existing = c.execute("SELECT * FROM tenants WHERE name=?", (nm,)).fetchone()
            if existing:
                d = dict(existing)
                d["active"] = bool(d["active"])
                return d
            c.execute(
                "INSERT INTO tenants(id, name, plan, active, quota_jobs_per_day, created_at) VALUES(?,?,?,1,?,?)",
                (tid, nm, plan[:40], max(10, int(quota_jobs_per_day)), now),
            )
            c.commit()
        finally:
            c.close()
    return {"id": tid, "name": nm, "plan": plan, "active": True, "quota_jobs_per_day": quota_jobs_per_day, "created_at": now}


def create_api_key(name: str, role: str = "analyst", tenant_id: Optional[str] = None, expires_days: int = 90) -> dict:
    if role not in ROLES:
        raise ValueError("Invalid role")
    tid = (tenant_id or get_current_tenant() or "default").strip() or "default"
    raw_key = "dark_" + secrets.token_urlsafe(24)
    khash = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
    kid = uuid.uuid4().hex[:10]
    now = time.time()
    exp = now + max(1, int(expires_days)) * 86400
    with _DB_LOCK:
        c = _conn()
        try:
            c.execute(
                "INSERT INTO api_keys(id, tenant_id, name, key_prefix, key_hash, role, active, expires_at, created_at) "
                "VALUES(?,?,?,?,?,?,1,?,?)",
                (kid, tid, (name or "api-key")[:80], raw_key[:10], khash, role, exp, now),
            )
            c.commit()
        finally:
            c.close()
    return {"id": kid, "tenant_id": tid, "name": name, "key_prefix": raw_key[:10],
            "raw_key": raw_key, "api_key": raw_key, "role": role, "expires_at": exp}


def list_api_keys(tenant_id: Optional[str] = None) -> List[dict]:
    with _DB_LOCK:
        c = _conn()
        try:
            if tenant_id:
                rows = c.execute(
                    "SELECT id, tenant_id, name, key_prefix, role, active, expires_at, last_used, created_at "
                    "FROM api_keys WHERE tenant_id=? ORDER BY created_at DESC", (tenant_id,)
                ).fetchall()
            else:
                rows = c.execute(
                    "SELECT id, tenant_id, name, key_prefix, role, active, expires_at, last_used, created_at "
                    "FROM api_keys ORDER BY created_at DESC"
                ).fetchall()
            return [dict(r) for r in rows]
        finally:
            c.close()


def verify_api_key(raw_key: Optional[str]) -> Optional[dict]:
    if not raw_key or not (raw_key.startswith("dark_") or raw_key.startswith("dk_")):
        return None
    khash = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
    now = time.time()
    with _DB_LOCK:
        c = _conn()
        try:
            row = c.execute("SELECT * FROM api_keys WHERE key_hash=?", (khash,)).fetchone()
            if not row or not row["active"]:
                return None
            if row["expires_at"] and row["expires_at"] < now:
                return None
            c.execute("UPDATE api_keys SET last_used=? WHERE id=?", (now, row["id"]))
            c.commit()
            return {"id": row["id"], "name": row["name"], "tenant_id": row["tenant_id"],
                    "username": f"apikey:{row['name']}", "role": row["role"]}
        finally:
            c.close()


authenticate_api_key = verify_api_key


def enqueue_job_meta(job_id: str, tenant_id: str = "default", kind: str = "", target: str = "", priority: int = 5) -> None:
    with _DB_LOCK:
        c = _conn()
        try:
            c.execute(
                "INSERT INTO job_queue_meta(job_id, tenant_id, kind, target, status, priority, updated_at) "
                "VALUES(?,?,?,?,'running',?,?) "
                "ON CONFLICT(job_id) DO UPDATE SET status='running', updated_at=excluded.updated_at",
                (job_id, tenant_id or "default", kind, target[:200], int(priority), time.time()),
            )
            c.commit()
        finally:
            c.close()


def update_job_meta_status(job_id: str, status: str) -> None:
    with _DB_LOCK:
        c = _conn()
        try:
            c.execute("UPDATE job_queue_meta SET status=?, updated_at=? WHERE job_id=?", (status, time.time(), job_id))
            c.commit()
        finally:
            c.close()


def revoke_api_key(kid: str) -> bool:
    with _DB_LOCK:
        c = _conn()
        try:
            cur = c.execute("UPDATE api_keys SET active=0 WHERE id=?", (kid,))
            c.commit()
            return cur.rowcount > 0
        finally:
            c.close()


def record_job_meta(job_id: str, tenant_id: str = "default", dedup_key: str = "",
                    priority: int = 5, retry_count: int = 0, max_retries: int = 1,
                    worker_id: str = "local-primary") -> None:
    with _DB_LOCK:
        c = _conn()
        try:
            c.execute(
                "INSERT INTO job_queue_meta(job_id, tenant_id, dedup_key, priority, retry_count, max_retries, worker_id, updated_at) "
                "VALUES(?,?,?,?,?,?,?,?) "
                "ON CONFLICT(job_id) DO UPDATE SET retry_count=excluded.retry_count, worker_id=excluded.worker_id, updated_at=excluded.updated_at",
                (job_id, tenant_id or "default", dedup_key, int(priority), int(retry_count), int(max_retries), worker_id, time.time()),
            )
            c.commit()
        finally:
            c.close()


def list_job_meta(tenant_id: Optional[str] = None) -> List[dict]:
    with _DB_LOCK:
        c = _conn()
        try:
            if tenant_id:
                rows = c.execute("SELECT * FROM job_queue_meta WHERE tenant_id=? ORDER BY updated_at DESC LIMIT 100", (tenant_id,)).fetchall()
            else:
                rows = c.execute("SELECT * FROM job_queue_meta ORDER BY updated_at DESC LIMIT 100").fetchall()
            return [dict(r) for r in rows]
        finally:
            c.close()


def update_user_role(user_id: str, role: str, actor_username: Optional[str] = None) -> bool:
    if role not in ROLES:
        raise ValueError("Invalid role")
    with _DB_LOCK:
        c = _conn()
        try:
            row = c.execute("SELECT id, username FROM users WHERE id=? OR username=?", (user_id, user_id)).fetchone()
            if not row:
                return False
            if actor_username and row["username"].lower() == actor_username.strip().lower():
                raise PermissionError("Cannot modify your own role (privilege escalation guard)")
            cur = c.execute("UPDATE users SET role=? WHERE id=?", (role, row["id"]))
            c.commit()
            return cur.rowcount > 0
        finally:
            c.close()


def setup_user_totp(username: str, enable: bool = True, secret: Optional[str] = None) -> dict:
    uname = (username or "").strip().lower()
    sec = secret or generate_totp_secret()
    with _DB_LOCK:
        c = _conn()
        try:
            c.execute(
                "UPDATE users SET totp_secret=?, totp_enabled=? WHERE username=?",
                (sec if enable else "", 1 if enable else 0, uname),
            )
            c.commit()
        finally:
            c.close()
    uri = f"otpauth://totp/DARK:{uname}?secret={sec}&issuer=DARK"
    return {"username": uname, "totp_enabled": enable, "secret": sec if enable else "", "otpauth_uri": uri if enable else ""}


def has_permission(role: str, perm: str) -> bool:
    return perm in ROLES.get(role or "viewer", [])


# ---------------------------------------------------------------------------
# Credential Vault (AES-256-GCM AEAD + External Key Separation + Rotation)
# ---------------------------------------------------------------------------
_LEGACY_VAULT_KEY_FILE = DATA_DIR / ".vault.key"


def _load_vault_keyring() -> dict:
    """Load versioned master keys from env or external key file (separate from DB_PATH)."""
    env_k = os.environ.get("DARK_VAULT_KEY", "").strip()
    if env_k:
        keys = {1: hashlib.sha256(env_k.encode("utf-8")).digest()}
        ver = 1
        # Optional rotated keys DARK_VAULT_KEY_V2, DARK_VAULT_KEY_V3, ...
        for v in range(2, 20):
            vk = os.environ.get(f"DARK_VAULT_KEY_V{v}", "").strip()
            if vk:
                keys[v] = hashlib.sha256(vk.encode("utf-8")).digest()
                ver = v
        return {"current_version": ver, "keys": keys}

    VAULT_KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
    if not VAULT_KEY_FILE.is_file():
        # Migrate legacy key if present so existing vault secrets remain readable as v1
        if _LEGACY_VAULT_KEY_FILE.is_file():
            raw_v1 = _LEGACY_VAULT_KEY_FILE.read_bytes()[:32]
        else:
            raw_v1 = secrets.token_bytes(32)
        ring_disk = {
            "current_version": 1,
            "keys": {"1": base64.b64encode(raw_v1).decode("ascii")},
        }
        VAULT_KEY_FILE.write_text(json.dumps(ring_disk), encoding="utf-8")
        try:
            os.chmod(VAULT_KEY_FILE, 0o600)
        except Exception:
            pass
    try:
        data = json.loads(VAULT_KEY_FILE.read_text(encoding="utf-8"))
        keys = {int(k): base64.b64decode(v)[:32] for k, v in (data.get("keys") or {}).items()}
        cur_v = int(data.get("current_version") or max(keys.keys()))
        return {"current_version": cur_v, "keys": keys}
    except Exception:
        raw = VAULT_KEY_FILE.read_bytes()[:32]
        return {"current_version": 1, "keys": {1: raw}}


def _get_vault_key_versioned(version: Optional[int] = None) -> Tuple[int, bytes]:
    ring = _load_vault_keyring()
    ver = version if (version is not None and version in ring["keys"]) else ring["current_version"]
    return ver, ring["keys"][ver]


def _get_vault_master_key() -> bytes:
    """Return primary master key bytes (backward-compatible helper)."""
    _, key = _get_vault_key_versioned(1)
    return key


def _derive_aes_key(master: bytes, key_version: int) -> bytes:
    return hashlib.sha256(f"dark-vault-aes256gcm|v{key_version}|".encode("utf-8") + master).digest()


def _encrypt_secret(plaintext: str, aad_context: str = "vault") -> Tuple[str, str, str]:
    key_ver, master = _get_vault_key_versioned()
    aes_key = _derive_aes_key(master, key_ver)
    aad = f"{aad_context}:v{key_ver}".encode("utf-8")
    nonce, ct, tag = _sh.aes_gcm_encrypt(aes_key, plaintext.encode("utf-8"), aad=aad)
    return (
        base64.b64encode(nonce).decode("ascii"),
        base64.b64encode(ct).decode("ascii"),
        base64.b64encode(tag).decode("ascii"),
    )


def _legacy_keystream(enc_key: bytes, nonce: bytes, length: int) -> bytes:
    out = bytearray()
    ctr = 0
    while len(out) < length:
        out.extend(hashlib.sha256(enc_key + nonce + struct.pack(">I", ctr)).digest())
        ctr += 1
    return bytes(out[:length])


def _decrypt_secret(
    nonce_b64: str,
    cipher_b64: str,
    mac_b64: str,
    key_version: int = 1,
    alg: str = "AES-256-GCM",
    aad_context: str = "vault",
) -> str:
    _, master = _get_vault_key_versioned(key_version)
    nonce = base64.b64decode(nonce_b64)
    ct = base64.b64decode(cipher_b64)
    tag_or_mac = base64.b64decode(mac_b64)

    if alg == "AES-256-GCM" and len(nonce) == 12 and len(tag_or_mac) == 16:
        aes_key = _derive_aes_key(master, key_version)
        aad = f"{aad_context}:v{key_version}".encode("utf-8")
        pt = _sh.aes_gcm_decrypt(aes_key, nonce, ct, tag_or_mac, aad=aad)
        return pt.decode("utf-8")

    # Legacy CTR-HMAC fallback for older rows created before v4.0
    enc_key = hashlib.sha256(b"enc|" + master).digest()
    mac_key = hashlib.sha256(b"mac|" + master).digest()
    expected = hmac.new(mac_key, nonce + ct, hashlib.sha256).digest()
    if not hmac.compare_digest(tag_or_mac, expected):
        raise ValueError("Vault integrity check failed")
    ks = _legacy_keystream(enc_key, nonce, len(ct))
    pt = bytes(a ^ b for a, b in zip(ct, ks))
    return pt.decode("utf-8")


def store_vault_secret(
    name: str,
    kind: str,
    secret_value: str,
    created_by: str = "admin",
    tenant_id: Optional[str] = None,
) -> dict:
    if not name or not secret_value:
        raise ValueError("Name and secret_value required")
    tid = (tenant_id or get_current_tenant() or "default").strip() or "default"
    key_ver, _ = _get_vault_key_versioned()
    nb, cb, mb = _encrypt_secret(secret_value, aad_context=f"vault:{tid}")
    sid = uuid.uuid4().hex[:10]
    now = time.time()
    with _DB_LOCK:
        c = _conn()
        try:
            c.execute(
                "INSERT INTO vault_secrets(id, name, kind, nonce_b64, cipher_b64, mac_b64, created_by, created_at, tenant_id, key_version, alg, updated_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,'AES-256-GCM',?) "
                "ON CONFLICT(tenant_id, name) DO UPDATE SET kind=excluded.kind, nonce_b64=excluded.nonce_b64, "
                "cipher_b64=excluded.cipher_b64, mac_b64=excluded.mac_b64, created_by=excluded.created_by, "
                "key_version=excluded.key_version, alg='AES-256-GCM', updated_at=excluded.updated_at",
                (sid, name.strip(), (kind or "generic").strip(), nb, cb, mb, created_by, now, tid, key_ver, now),
            )
            row_id = c.execute("SELECT id FROM vault_secrets WHERE tenant_id=? AND name=?", (tid, name.strip())).fetchone()
            if row_id:
                sid = row_id["id"]
            c.commit()
        finally:
            c.close()
    return {
        "id": sid, "name": name.strip(), "kind": kind or "generic",
        "tenant_id": tid, "key_version": key_ver, "alg": "AES-256-GCM",
        "created_by": created_by, "created_at": now,
    }


def list_vault_secrets(tenant_id: Optional[str] = None) -> List[dict]:
    tid = (tenant_id or get_current_tenant() or "default").strip() or "default"
    with _DB_LOCK:
        c = _conn()
        try:
            rows = c.execute(
                "SELECT id, name, kind, tenant_id, key_version, alg, created_by, created_at, updated_at "
                "FROM vault_secrets WHERE tenant_id=? ORDER BY created_at DESC",
                (tid,),
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            c.close()


def reveal_vault_secret(name_or_id: str, tenant_id: Optional[str] = None) -> Optional[str]:
    tid = (tenant_id or get_current_tenant() or "default").strip() or "default"
    with _DB_LOCK:
        c = _conn()
        try:
            row = c.execute(
                "SELECT nonce_b64, cipher_b64, mac_b64, tenant_id, key_version, alg "
                "FROM vault_secrets WHERE (id=? OR name=?) AND tenant_id=?",
                (name_or_id, name_or_id, tid),
            ).fetchone()
        finally:
            c.close()
    if not row:
        return None
    kv = int(row["key_version"] or 1) if "key_version" in row.keys() else 1
    alg = str(row["alg"] or "CTR-HMAC-SHA256") if "alg" in row.keys() else "CTR-HMAC-SHA256"
    try:
        return _decrypt_secret(
            row["nonce_b64"], row["cipher_b64"], row["mac_b64"],
            key_version=kv, alg=alg, aad_context=f"vault:{tid}",
        )
    except Exception:
        # Backward compatibility if row was written without tenant AAD
        return _decrypt_secret(
            row["nonce_b64"], row["cipher_b64"], row["mac_b64"],
            key_version=kv, alg=alg, aad_context="vault",
        )


def delete_vault_secret(sid: str, tenant_id: Optional[str] = None) -> bool:
    tid = (tenant_id or get_current_tenant() or "default").strip() or "default"
    with _DB_LOCK:
        c = _conn()
        try:
            cur = c.execute("DELETE FROM vault_secrets WHERE (id=? OR name=?) AND tenant_id=?", (sid, sid, tid))
            c.commit()
            return cur.rowcount > 0
        finally:
            c.close()


def rotate_vault_keys(tenant_id: Optional[str] = None) -> dict:
    """Rotate vault master key to a fresh version and re-encrypt all secrets with AES-256-GCM."""
    if os.environ.get("DARK_VAULT_KEY", "").strip():
        raise ValueError("Cannot auto-rotate env-managed DARK_VAULT_KEY; set DARK_VAULT_KEY_V<n> and re-encrypt")
    ring = _load_vault_keyring()
    old_ver = int(ring["current_version"])
    new_ver = old_ver + 1
    new_raw = secrets.token_bytes(32)
    ring_disk = {
        "current_version": new_ver,
        "keys": {str(k): base64.b64encode(v).decode("ascii") for k, v in ring["keys"].items()},
    }
    ring_disk["keys"][str(new_ver)] = base64.b64encode(new_raw).decode("ascii")
    VAULT_KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
    VAULT_KEY_FILE.write_text(json.dumps(ring_disk), encoding="utf-8")
    try:
        os.chmod(VAULT_KEY_FILE, 0o600)
    except Exception:
        pass

    reencrypted = 0
    now = time.time()
    with _DB_LOCK:
        c = _conn()
        try:
            if tenant_id:
                rows = c.execute("SELECT * FROM vault_secrets WHERE tenant_id=?", (tenant_id,)).fetchall()
            else:
                rows = c.execute("SELECT * FROM vault_secrets").fetchall()
            for r in rows:
                rtid = r["tenant_id"] if "tenant_id" in r.keys() else "default"
                kv = int(r["key_version"] or 1) if "key_version" in r.keys() else 1
                alg = str(r["alg"] or "CTR-HMAC-SHA256") if "alg" in r.keys() else "CTR-HMAC-SHA256"
                try:
                    pt = _decrypt_secret(r["nonce_b64"], r["cipher_b64"], r["mac_b64"], key_version=kv, alg=alg, aad_context=f"vault:{rtid}")
                except Exception:
                    pt = _decrypt_secret(r["nonce_b64"], r["cipher_b64"], r["mac_b64"], key_version=kv, alg=alg, aad_context="vault")
                nb, cb, mb = _encrypt_secret(pt, aad_context=f"vault:{rtid}")
                c.execute(
                    "UPDATE vault_secrets SET nonce_b64=?, cipher_b64=?, mac_b64=?, key_version=?, alg='AES-256-GCM', updated_at=? WHERE id=?",
                    (nb, cb, mb, new_ver, now, r["id"]),
                )
                reencrypted += 1
            c.commit()
        finally:
            c.close()
    return {"previous_version": old_ver, "current_version": new_ver, "reencrypted": reencrypted}


# ---------------------------------------------------------------------------
# Worker Health Monitoring & Recurring Scan Scheduler
# ---------------------------------------------------------------------------
def _sample_system_metrics() -> Tuple[float, float]:
    cpu_pct = 0.0
    ram_mb = 0.0
    try:
        load1 = os.getloadavg()[0]
        cpus = os.cpu_count() or 1
        cpu_pct = round(min(100.0, (load1 / cpus) * 100.0), 1)
    except Exception:
        pass
    try:
        for ln in Path("/proc/self/status").read_text().splitlines():
            if ln.startswith("VmRSS:"):
                ram_mb = round(int(ln.split()[1]) / 1024.0, 1)
                break
    except Exception:
        pass
    return cpu_pct, ram_mb


def upsert_worker(worker_id: str, name: str, active_jobs: int = 0, capacity: int = 16) -> dict:
    cpu_pct, ram_mb = _sample_system_metrics()
    now = time.time()
    with _DB_LOCK:
        c = _conn()
        try:
            c.execute(
                "INSERT INTO workers(id, name, status, capacity, active_jobs, cpu_pct, ram_mb, last_heartbeat) "
                "VALUES(?, ?, 'online', ?, ?, ?, ?, ?) "
                "ON CONFLICT(id) DO UPDATE SET name=excluded.name, status='online', capacity=excluded.capacity, "
                "active_jobs=excluded.active_jobs, cpu_pct=excluded.cpu_pct, ram_mb=excluded.ram_mb, "
                "last_heartbeat=excluded.last_heartbeat",
                (worker_id, name, capacity, active_jobs, cpu_pct, ram_mb, now),
            )
            c.commit()
        finally:
            c.close()
    return {"id": worker_id, "name": name, "status": "online", "capacity": capacity,
            "active_jobs": active_jobs, "cpu_pct": cpu_pct, "ram_mb": ram_mb, "last_heartbeat": now}


def list_workers() -> List[dict]:
    now = time.time()
    with _DB_LOCK:
        c = _conn()
        try:
            rows = c.execute("SELECT * FROM workers ORDER BY id ASC").fetchall()
            out = []
            for r in rows:
                d = dict(r)
                if now - (d.get("last_heartbeat") or 0) > 120:
                    d["status"] = "stale"
                out.append(d)
            return out
        finally:
            c.close()


def create_schedule(project_id: str, name: str, kind: str, payload: dict, interval_minutes: int = 1440) -> dict:
    sid = uuid.uuid4().hex[:10]
    now = time.time()
    mins = max(5, min(int(interval_minutes), 43200))
    nxt = now + mins * 60
    with _DB_LOCK:
        c = _conn()
        try:
            c.execute(
                "INSERT INTO schedules(id, project_id, name, kind, payload_json, interval_minutes, enabled, last_run, next_run, created_at) "
                "VALUES(?,?,?,?,?,?,1,0,?,?)",
                (sid, project_id or "default", name[:80], kind, json.dumps(payload), mins, nxt, now),
            )
            c.commit()
        finally:
            c.close()
    return {"id": sid, "project_id": project_id or "default", "name": name[:80],
            "kind": kind, "payload": payload, "interval_minutes": mins, "enabled": True, "next_run": nxt}


def list_schedules() -> List[dict]:
    with _DB_LOCK:
        c = _conn()
        try:
            rows = c.execute("SELECT * FROM schedules ORDER BY created_at DESC").fetchall()
            out = []
            for r in rows:
                d = dict(r)
                d["payload"] = json.loads(d.pop("payload_json") or "{}")
                d["enabled"] = bool(d["enabled"])
                out.append(d)
            return out
        finally:
            c.close()


def delete_schedule(sid: str) -> bool:
    with _DB_LOCK:
        c = _conn()
        try:
            cur = c.execute("DELETE FROM schedules WHERE id=?", (sid,))
            c.commit()
            return cur.rowcount > 0
        finally:
            c.close()


def pop_due_schedules() -> List[dict]:
    now = time.time()
    due: List[dict] = []
    with _DB_LOCK:
        c = _conn()
        try:
            rows = c.execute("SELECT * FROM schedules WHERE enabled=1 AND next_run<=?", (now,)).fetchall()
            for r in rows:
                d = dict(r)
                d["payload"] = json.loads(d.pop("payload_json") or "{}")
                due.append(d)
                c.execute(
                    "UPDATE schedules SET last_run=?, next_run=? WHERE id=?",
                    (now, now + int(d["interval_minutes"]) * 60, d["id"]),
                )
            c.commit()
        finally:
            c.close()
    return due


# ---------------------------------------------------------------------------
# Backup & Restore
# ---------------------------------------------------------------------------
_BACKUP_SELECT_SQL = {
    "scope_rules": "SELECT * FROM scope_rules",
    "settings": "SELECT * FROM settings",
    "assets": "SELECT * FROM assets",
    "asset_relations": "SELECT * FROM asset_relations",
    "vuln_feed": "SELECT * FROM vuln_feed",
    "remediation_tickets": "SELECT * FROM remediation_tickets",
    "schedules": "SELECT * FROM schedules",
    "plugins": "SELECT * FROM plugins",
}

_BACKUP_INSERT_SQL = {
    "scope_rules": ("id", "pattern", "rule_type", "note", "created_at"),
    "settings": ("key", "value"),
    "assets": ("id", "project_id", "kind", "name", "criticality", "internet_exposed", "meta_json", "first_seen", "last_seen"),
    "asset_relations": ("id", "project_id", "src_asset_id", "dst_asset_id", "relation", "created_at"),
    "vuln_feed": ("cve_id", "cpe_prefix", "product", "version_lt", "severity", "cvss_v31", "cvss_v40", "epss", "kev", "summary", "remediation", "updated_at"),
    "remediation_tickets": ("id", "project_id", "job_id", "finding_key", "title", "severity", "target", "assignee", "due_date", "status", "notes_json", "evidence_json", "retest_history_json", "created_at", "updated_at"),
    "schedules": ("id", "project_id", "name", "kind", "payload_json", "interval_minutes", "enabled", "last_run", "next_run", "created_at"),
    "plugins": ("plugin_id", "manifest_json", "signature", "enabled", "verified", "created_at"),
}


def get_backup_manifest() -> dict:
    """Return authoritative storage paths for database, external vault keyring, and audit checkpoint."""
    backend = _dbm.get_backend_info()
    return {
        "schema_version": "4.0.0",
        "db_engine": backend.get("active_engine", "sqlite"),
        "database_path": str(DB_PATH) if backend.get("active_engine") == "sqlite" else "DARK_POSTGRES_DSN (external PostgreSQL)",
        "vault_keyring_path": "env:DARK_VAULT_KEY" if os.environ.get("DARK_VAULT_KEY", "").strip() else str(VAULT_KEY_FILE),
        "audit_checkpoint_path": str(AUDIT_CHECKPOINT_FILE),
        "jobs_state_path": str(APP_DIR / "jobs_state.json"),
    }


def export_backup() -> dict:
    with _DB_LOCK:
        c = _conn()
        try:
            dump: Dict[str, Any] = {"version": "dark-enterprise-v3", "exported_at": time.time(), "tables": {}}
            for t, sql in _BACKUP_SELECT_SQL.items():
                dump["tables"][t] = [dict(r) for r in c.execute(sql).fetchall()]
            return dump
        finally:
            c.close()


def restore_backup(dump: dict) -> dict:
    if not isinstance(dump, dict) or "tables" not in dump:
        raise ValueError("Invalid backup payload")
    restored = {}
    with _DB_LOCK:
        c = _conn()
        try:
            static_inserts = {
                "scope_rules": "INSERT OR REPLACE INTO scope_rules(id,pattern,rule_type,note,created_at) VALUES(?,?,?,?,?)",
                "settings": "INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)",
                "assets": "INSERT OR REPLACE INTO assets(id,project_id,kind,name,criticality,internet_exposed,meta_json,first_seen,last_seen) VALUES(?,?,?,?,?,?,?,?,?)",
                "asset_relations": "INSERT OR REPLACE INTO asset_relations(id,project_id,src_asset_id,dst_asset_id,relation,created_at) VALUES(?,?,?,?,?,?)",
                "vuln_feed": "INSERT OR REPLACE INTO vuln_feed(cve_id,cpe_prefix,product,version_lt,severity,cvss_v31,cvss_v40,epss,kev,summary,remediation,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                "remediation_tickets": "INSERT OR REPLACE INTO remediation_tickets(id,project_id,job_id,finding_key,title,severity,target,assignee,due_date,status,notes_json,evidence_json,retest_history_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                "schedules": "INSERT OR REPLACE INTO schedules(id,project_id,name,kind,payload_json,interval_minutes,enabled,last_run,next_run,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                "plugins": "INSERT OR REPLACE INTO plugins(plugin_id,manifest_json,signature,enabled,verified,created_at) VALUES(?,?,?,?,?,?)",
            }
            for t, rows in (dump.get("tables") or {}).items():
                if t not in static_inserts or not isinstance(rows, list):
                    continue
                cols = _BACKUP_INSERT_SQL[t]
                sql = static_inserts[t]
                count = 0
                for row in rows:
                    if not isinstance(row, dict) or not row:
                        continue
                    c.execute(sql, [row.get(col) for col in cols])
                    count += 1
                restored[t] = count
            c.commit()
        finally:
            c.close()
    return {"restored": restored, "restored_at": time.time()}
