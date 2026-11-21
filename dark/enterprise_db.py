#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DARK Enterprise Core — SQLite persistence, RBAC, TOTP 2FA, Tamper-evident
Audit Trail, Credential Vault, Scope Allowlist, Worker Health, Scheduler,
Job Recovery, and Backup/Restore.
"""
from __future__ import annotations

import base64
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
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

APP_DIR = Path(__file__).resolve().parent
DATA_DIR = APP_DIR / "data"
DB_PATH = DATA_DIR / "dark_enterprise.db"
VAULT_KEY_FILE = DATA_DIR / ".vault.key"

_DB_LOCK = threading.RLock()
PBKDF2_ROUNDS = 120_000

ROLES: Dict[str, List[str]] = {
    "admin": [
        "scan:run", "scan:stop", "remediation:write", "plugin:manage",
        "intel:sync", "compliance:read", "admin:manage", "backup:manage", "vault:use",
    ],
    "analyst": [
        "scan:run", "scan:stop", "remediation:write", "plugin:manage",
        "intel:sync", "compliance:read", "vault:use",
    ],
    "auditor": [
        "compliance:read", "remediation:write", "intel:sync",
    ],
    "viewer": [
        "compliance:read",
    ],
}


def _conn() -> sqlite3.Connection:
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
                    name TEXT UNIQUE NOT NULL,
                    kind TEXT NOT NULL,
                    nonce_b64 TEXT NOT NULL,
                    cipher_b64 TEXT NOT NULL,
                    mac_b64 TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    created_at REAL NOT NULL
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
                """
            )
            c.commit()
        finally:
            c.close()


init_db()


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
# Tamper-Evident Audit Trail (SHA-256 Hash Chain)
# ---------------------------------------------------------------------------
def log_audit(actor: str, role: str, action: str, resource: str,
              detail: str = "", ip: str = "") -> dict:
    ts = time.time()
    with _DB_LOCK:
        c = _conn()
        try:
            last = c.execute("SELECT entry_hash FROM audit_logs ORDER BY id DESC LIMIT 1").fetchone()
            prev_hash = last["entry_hash"] if last else ("0" * 64)
            payload = f"{ts:.6f}|{actor}|{role}|{action}|{resource}|{detail}|{ip}|{prev_hash}"
            entry_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
            cur = c.execute(
                "INSERT INTO audit_logs(ts, actor, role, action, resource, detail, ip, prev_hash, entry_hash) "
                "VALUES(?,?,?,?,?,?,?,?,?)",
                (ts, actor or "system", role or "system", action, resource, detail[:500], ip, prev_hash, entry_hash),
            )
            c.commit()
            return {
                "id": cur.lastrowid, "ts": ts, "actor": actor, "role": role,
                "action": action, "resource": resource, "detail": detail[:500],
                "ip": ip, "prev_hash": prev_hash, "entry_hash": entry_hash,
            }
        finally:
            c.close()


def list_audit_logs(limit: int = 100) -> List[dict]:
    with _DB_LOCK:
        c = _conn()
        try:
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


def create_user(username: str, password: str, role: str = "analyst") -> dict:
    uname = (username or "").strip().lower()
    if len(uname) < 2:
        raise ValueError("Username must be at least 2 characters")
    if len(password or "") < 6:
        raise ValueError("Password must be at least 6 characters")
    if role not in ROLES:
        raise ValueError(f"Role must be one of {list(ROLES)}")
    pw_hash, pw_salt = _hash_pw(password)
    uid = uuid.uuid4().hex[:10]
    now = time.time()
    with _DB_LOCK:
        c = _conn()
        try:
            c.execute(
                "INSERT INTO users(id, username, role, pw_hash, pw_salt, created_at) VALUES(?,?,?,?,?,?)",
                (uid, uname, role, pw_hash, pw_salt, now),
            )
            c.commit()
        finally:
            c.close()
    return {"id": uid, "username": uname, "role": role, "totp_enabled": False, "active": True, "created_at": now}


def list_users() -> List[dict]:
    with _DB_LOCK:
        c = _conn()
        try:
            rows = c.execute(
                "SELECT id, username, role, totp_enabled, active, created_at FROM users ORDER BY created_at ASC"
            ).fetchall()
            out = []
            for r in rows:
                d = dict(r)
                d["totp_enabled"] = bool(d["totp_enabled"])
                d["active"] = bool(d["active"])
                d["permissions"] = ROLES.get(d["role"], [])
                out.append(d)
            return out
        finally:
            c.close()


def authenticate_user(username: str, password: str, totp_code: str = "") -> Tuple[bool, Optional[dict], str]:
    uname = (username or "").strip().lower()
    with _DB_LOCK:
        c = _conn()
        try:
            row = c.execute("SELECT * FROM users WHERE username=?", (uname,)).fetchone()
        finally:
            c.close()
    if not row or not row["active"]:
        return False, None, "Invalid credentials"
    cand, _ = _hash_pw(password, row["pw_salt"])
    if not hmac.compare_digest(cand, row["pw_hash"]):
        return False, None, "Invalid credentials"
    if row["totp_enabled"]:
        if not verify_totp(row["totp_secret"], totp_code):
            return False, None, "2FA TOTP code required or invalid"
    return True, {
        "id": row["id"], "username": row["username"], "role": row["role"],
        "permissions": ROLES.get(row["role"], []), "totp_enabled": bool(row["totp_enabled"]),
    }, "OK"


def update_user_role(user_id: str, role: str) -> bool:
    if role not in ROLES:
        raise ValueError("Invalid role")
    with _DB_LOCK:
        c = _conn()
        try:
            cur = c.execute("UPDATE users SET role=? WHERE id=?", (role, user_id))
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
# Credential Vault (Authenticated Encryption: PBKDF2 + CTR-HMAC-SHA256)
# ---------------------------------------------------------------------------
def _get_vault_master_key() -> bytes:
    env_k = os.environ.get("DARK_VAULT_KEY", "")
    if env_k:
        return hashlib.sha256(env_k.encode("utf-8")).digest()
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not VAULT_KEY_FILE.is_file():
        VAULT_KEY_FILE.write_bytes(secrets.token_bytes(32))
        try:
            os.chmod(VAULT_KEY_FILE, 0o600)
        except Exception:
            pass
    return VAULT_KEY_FILE.read_bytes()[:32]


def _keystream(enc_key: bytes, nonce: bytes, length: int) -> bytes:
    out = bytearray()
    ctr = 0
    while len(out) < length:
        out.extend(hashlib.sha256(enc_key + nonce + struct.pack(">I", ctr)).digest())
        ctr += 1
    return bytes(out[:length])


def _encrypt_secret(plaintext: str) -> Tuple[str, str, str]:
    master = _get_vault_master_key()
    enc_key = hashlib.sha256(b"enc|" + master).digest()
    mac_key = hashlib.sha256(b"mac|" + master).digest()
    nonce = secrets.token_bytes(16)
    pt = plaintext.encode("utf-8")
    ks = _keystream(enc_key, nonce, len(pt))
    ct = bytes(a ^ b for a, b in zip(pt, ks))
    mac = hmac.new(mac_key, nonce + ct, hashlib.sha256).digest()
    return (
        base64.b64encode(nonce).decode(),
        base64.b64encode(ct).decode(),
        base64.b64encode(mac).decode(),
    )


def _decrypt_secret(nonce_b64: str, cipher_b64: str, mac_b64: str) -> str:
    master = _get_vault_master_key()
    enc_key = hashlib.sha256(b"enc|" + master).digest()
    mac_key = hashlib.sha256(b"mac|" + master).digest()
    nonce = base64.b64decode(nonce_b64)
    ct = base64.b64decode(cipher_b64)
    mac = base64.b64decode(mac_b64)
    expected = hmac.new(mac_key, nonce + ct, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, expected):
        raise ValueError("Vault integrity check failed")
    ks = _keystream(enc_key, nonce, len(ct))
    pt = bytes(a ^ b for a, b in zip(ct, ks))
    return pt.decode("utf-8")


def store_vault_secret(name: str, kind: str, secret_value: str, created_by: str = "admin") -> dict:
    if not name or not secret_value:
        raise ValueError("Name and secret_value required")
    nb, cb, mb = _encrypt_secret(secret_value)
    sid = uuid.uuid4().hex[:10]
    now = time.time()
    with _DB_LOCK:
        c = _conn()
        try:
            c.execute(
                "INSERT INTO vault_secrets(id, name, kind, nonce_b64, cipher_b64, mac_b64, created_by, created_at) "
                "VALUES(?,?,?,?,?,?,?,?) "
                "ON CONFLICT(name) DO UPDATE SET kind=excluded.kind, nonce_b64=excluded.nonce_b64, "
                "cipher_b64=excluded.cipher_b64, mac_b64=excluded.mac_b64, created_by=excluded.created_by",
                (sid, name.strip(), (kind or "generic").strip(), nb, cb, mb, created_by, now),
            )
            c.commit()
        finally:
            c.close()
    return {"id": sid, "name": name.strip(), "kind": kind or "generic", "created_by": created_by, "created_at": now}


def list_vault_secrets() -> List[dict]:
    with _DB_LOCK:
        c = _conn()
        try:
            rows = c.execute(
                "SELECT id, name, kind, created_by, created_at FROM vault_secrets ORDER BY created_at DESC"
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            c.close()


def reveal_vault_secret(name_or_id: str) -> Optional[str]:
    with _DB_LOCK:
        c = _conn()
        try:
            row = c.execute(
                "SELECT nonce_b64, cipher_b64, mac_b64 FROM vault_secrets WHERE id=? OR name=?",
                (name_or_id, name_or_id),
            ).fetchone()
        finally:
            c.close()
    if not row:
        return None
    return _decrypt_secret(row["nonce_b64"], row["cipher_b64"], row["mac_b64"])


def delete_vault_secret(sid: str) -> bool:
    with _DB_LOCK:
        c = _conn()
        try:
            cur = c.execute("DELETE FROM vault_secrets WHERE id=? OR name=?", (sid, sid))
            c.commit()
            return cur.rowcount > 0
        finally:
            c.close()


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
def export_backup() -> dict:
    with _DB_LOCK:
        c = _conn()
        try:
            tables = ["scope_rules", "settings", "assets", "asset_relations",
                      "vuln_feed", "remediation_tickets", "schedules", "plugins"]
            dump: Dict[str, Any] = {"version": "dark-enterprise-v3", "exported_at": time.time(), "tables": {}}
            for t in tables:
                dump["tables"][t] = [dict(r) for r in c.execute(f"SELECT * FROM {t}").fetchall()]
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
            for t, rows in (dump.get("tables") or {}).items():
                if t not in {"scope_rules", "settings", "assets", "asset_relations",
                             "vuln_feed", "remediation_tickets", "schedules", "plugins"}:
                    continue
                if not isinstance(rows, list):
                    continue
                count = 0
                for row in rows:
                    if not isinstance(row, dict) or not row:
                        continue
                    cols = list(row.keys())
                    placeholders = ",".join("?" for _ in cols)
                    col_list = ",".join(cols)
                    c.execute(
                        f"INSERT OR REPLACE INTO {t}({col_list}) VALUES({placeholders})",
                        [row[k] for k in cols],
                    )
                    count += 1
                restored[t] = count
            c.commit()
        finally:
            c.close()
    return {"restored": restored, "restored_at": time.time()}
