#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DARK workspace layer — projects, target history, scan comparison, auth.

This is the commercial-platform surface: every job belongs to a project,
every target has a history, any two scans of the same kind can be diffed,
and the dashboard can be locked with a password.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

APP_DIR = Path(__file__).resolve().parent
DATA_DIR = APP_DIR / "data"
PROJECTS_FILE = DATA_DIR / "projects.json"
AUTH_FILE = DATA_DIR / "auth.json"
SESSIONS_FILE = DATA_DIR / "sessions.json"
NOTES_FILE = DATA_DIR / "notes.json"

_LOCK = threading.Lock()
PBKDF2_ROUNDS = 120_000
SESSION_TTL = 7 * 24 * 3600
DEFAULT_PROJECT = {
    "id": "default",
    "name": "Default",
    "description": "Unassigned jobs land here",
    "color": "#22d3ee",
    "created_at": 0,
}


def _atomic_write(path: Path, obj: Any) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(obj, ensure_ascii=False, indent=2, default=str),
                   encoding="utf-8")
    tmp.replace(path)


def _load(path: Path, default):
    try:
        if path.is_file():
            return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        pass
    return default


# ---------------------------------------------------------------------------
# Projects
# ---------------------------------------------------------------------------
def list_projects() -> List[dict]:
    with _LOCK:
        items = _load(PROJECTS_FILE, [])
    if not any(p.get("id") == "default" for p in items):
        items = [dict(DEFAULT_PROJECT, created_at=time.time())] + items
        _atomic_write(PROJECTS_FILE, items)
    return items


def get_project(pid: str) -> Optional[dict]:
    for p in list_projects():
        if p.get("id") == pid:
            return p
    return None


def create_project(name: str, description: str = "", color: str = "#22d3ee") -> dict:
    name = (name or "").strip() or "Untitled"
    proj = {
        "id": uuid.uuid4().hex[:10],
        "name": name[:80],
        "description": (description or "")[:400],
        "color": color if (color or "").startswith("#") else "#22d3ee",
        "created_at": time.time(),
    }
    with _LOCK:
        items = _load(PROJECTS_FILE, [])
        if not any(p.get("id") == "default" for p in items):
            items.insert(0, dict(DEFAULT_PROJECT, created_at=time.time()))
        items.append(proj)
        _atomic_write(PROJECTS_FILE, items)
    return proj


def update_project(pid: str, **fields) -> Optional[dict]:
    if pid == "default" and fields.get("name") == "":
        return get_project(pid)
    with _LOCK:
        items = _load(PROJECTS_FILE, [])
        for p in items:
            if p.get("id") != pid:
                continue
            if "name" in fields and fields["name"]:
                p["name"] = str(fields["name"])[:80]
            if "description" in fields:
                p["description"] = str(fields["description"] or "")[:400]
            if "color" in fields and str(fields["color"]).startswith("#"):
                p["color"] = fields["color"]
            _atomic_write(PROJECTS_FILE, items)
            return p
    return None


def delete_project(pid: str) -> bool:
    if pid == "default":
        return False
    with _LOCK:
        items = _load(PROJECTS_FILE, [])
        nxt = [p for p in items if p.get("id") != pid]
        if len(nxt) == len(items):
            return False
        _atomic_write(PROJECTS_FILE, nxt)
    return True


# ---------------------------------------------------------------------------
# Notes (operator annotations on a job)
# ---------------------------------------------------------------------------
def get_note(job_id: str) -> str:
    return (_load(NOTES_FILE, {}) or {}).get(job_id, "")


def set_note(job_id: str, text: str) -> str:
    with _LOCK:
        notes = _load(NOTES_FILE, {})
        notes[job_id] = (text or "")[:4000]
        _atomic_write(NOTES_FILE, notes)
    return notes[job_id]


# ---------------------------------------------------------------------------
# Auth — optional workspace lock
# ---------------------------------------------------------------------------
def _hash_password(password: str, salt: bytes) -> str:
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ROUNDS)
    return dk.hex()


def auth_status() -> dict:
    env_user = os.environ.get("DARK_USER") or "dark"
    env_pass = os.environ.get("DARK_PASSWORD")
    cfg = _load(AUTH_FILE, {})
    enabled = bool(cfg.get("enabled")) or bool(env_pass)
    return {
        "enabled": enabled,
        "username": cfg.get("username") or env_user,
        "configured": bool(cfg.get("pw_hash")) or bool(env_pass),
        "source": "env" if env_pass else ("file" if cfg.get("pw_hash") else "off"),
    }


def set_password(username: str, password: str, enabled: bool = True) -> dict:
    if not password or len(password) < 4:
        raise ValueError("password must be at least 4 characters")
    salt = secrets.token_bytes(16)
    cfg = {
        "enabled": bool(enabled),
        "username": (username or "dark").strip()[:40] or "dark",
        "salt": salt.hex(),
        "pw_hash": _hash_password(password, salt),
        "updated_at": time.time(),
    }
    _atomic_write(AUTH_FILE, cfg)
    return auth_status()


def disable_auth() -> dict:
    cfg = _load(AUTH_FILE, {})
    cfg["enabled"] = False
    _atomic_write(AUTH_FILE, cfg)
    return auth_status()


def verify_password(username: str, password: str) -> bool:
    env_user = os.environ.get("DARK_USER") or "dark"
    env_pass = os.environ.get("DARK_PASSWORD")
    if env_pass:
        return hmac.compare_digest(username or "", env_user) and \
               hmac.compare_digest(password or "", env_pass)
    cfg = _load(AUTH_FILE, {})
    if not cfg.get("enabled") or not cfg.get("pw_hash"):
        return False
    if not hmac.compare_digest(username or "", cfg.get("username") or "dark"):
        return False
    try:
        salt = bytes.fromhex(cfg["salt"])
    except Exception:
        return False
    return hmac.compare_digest(_hash_password(password, salt), cfg["pw_hash"])


def _sessions() -> dict:
    return _load(SESSIONS_FILE, {})


def create_session(username: str) -> str:
    token = secrets.token_urlsafe(32)
    with _LOCK:
        s = _sessions()
        now = time.time()
        # drop expired
        s = {k: v for k, v in s.items()
             if isinstance(v, dict) and v.get("expires", 0) > now}
        s[token] = {"username": username, "created": now,
                    "expires": now + SESSION_TTL}
        _atomic_write(SESSIONS_FILE, s)
    return token


def session_user(token: Optional[str]) -> Optional[str]:
    if not token:
        return None
    s = _sessions()
    rec = s.get(token)
    if not rec or rec.get("expires", 0) < time.time():
        return None
    return rec.get("username")


def drop_session(token: Optional[str]) -> None:
    if not token:
        return
    with _LOCK:
        s = _sessions()
        s.pop(token, None)
        _atomic_write(SESSIONS_FILE, s)


# ---------------------------------------------------------------------------
# Target extraction + history
# ---------------------------------------------------------------------------
def extract_target(kind: str, result: Optional[dict], extra: Optional[dict] = None) -> str:
    extra = extra or {}
    r = result or {}
    if kind == "web-scan":
        return r.get("target") or extra.get("url") or ""
    if kind == "network-scan":
        hosts = ((r.get("report") or {}).get("hosts")) or []
        if hosts:
            return ", ".join(h.get("host") or h.get("hostname") or "?" for h in hosts[:6])
        t = extra.get("targets")
        if isinstance(t, list):
            return ", ".join(str(x) for x in t[:6])
        return str(t or "")
    if kind in ("hash-crack", "hash-benchmark"):
        rows = r.get("results") or r.get("cracked") or []
        if rows and isinstance(rows[0], dict):
            return (rows[0].get("hash") or "")[:32]
        return extra.get("hash") or "hashes"
    if kind.startswith("monitor"):
        return extra.get("file") or extra.get("interface") or kind
    return extra.get("target") or ""


def _host_key(target: str) -> str:
    t = (target or "").strip()
    if "://" in t:
        u = urlsplit(t)
        return (u.netloc or u.path or t).lower()
    return t.lower()


def build_target_history(jobs: List[dict]) -> List[dict]:
    """Aggregate every finished job into a per-target timeline."""
    buckets: Dict[str, dict] = {}
    for j in jobs:
        tgt = j.get("target") or extract_target(j.get("kind") or "", j.get("result"), j)
        if not tgt:
            continue
        key = _host_key(tgt)
        b = buckets.setdefault(key, {
            "key": key, "target": tgt, "kinds": {}, "jobs": 0,
            "last_at": 0, "last_job": None, "last_status": None,
            "findings_total": 0, "by_severity": {},
            "open_ports": 0, "cracked": 0, "alerts": 0,
            "project_ids": [],
        })
        b["jobs"] += 1
        kind = j.get("kind") or "?"
        b["kinds"][kind] = b["kinds"].get(kind, 0) + 1
        started = j.get("started_at") or 0
        if started >= b["last_at"]:
            b["last_at"] = started
            b["last_job"] = j.get("id")
            b["last_status"] = j.get("status")
            b["target"] = tgt
        pid = j.get("project_id") or "default"
        if pid not in b["project_ids"]:
            b["project_ids"].append(pid)
        r = j.get("result") or {}
        if j.get("kind") == "web-scan":
            st = r.get("stats") or {}
            b["findings_total"] += int(st.get("findings") or len(r.get("findings") or []))
            for sev, n in (st.get("by_severity") or {}).items():
                b["by_severity"][sev] = b["by_severity"].get(sev, 0) + int(n)
        elif j.get("kind") == "network-scan":
            hosts = ((r.get("report") or {}).get("hosts")) or []
            b["open_ports"] += sum(len(h.get("open_ports") or []) for h in hosts)
        elif j.get("kind") == "hash-crack":
            b["cracked"] += int((r.get("summary") or {}).get("cracked_count") or 0)
        elif str(j.get("kind", "")).startswith("monitor"):
            b["alerts"] += int((r.get("summary") or {}).get("alerts_total") or 0)
    out = sorted(buckets.values(), key=lambda x: x["last_at"], reverse=True)
    return out


# ---------------------------------------------------------------------------
# Scan comparison (the Invicti/Acunetix "retest" feature)
# ---------------------------------------------------------------------------
_SEV_RANK = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Info": 1,
             "CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2}


def finding_key(f: dict) -> Tuple[str, str, str]:
    return (
        (f.get("vuln_type") or "").strip(),
        (f.get("url") or "").split("?")[0].strip(),
        (f.get("parameter") or "").strip(),
    )


def _index_findings(findings: List[dict]) -> Dict[Tuple[str, str, str], dict]:
    idx = {}
    for f in findings or []:
        idx[finding_key(f)] = f
    return idx


def compare_web(a: dict, b: dict) -> dict:
    fa = (a.get("result") or {}).get("findings") or []
    fb = (b.get("result") or {}).get("findings") or []
    ia, ib = _index_findings(fa), _index_findings(fb)
    ka, kb = set(ia), set(ib)
    added = [ib[k] for k in sorted(kb - ka)]
    resolved = [ia[k] for k in sorted(ka - kb)]
    still = [ib[k] for k in sorted(ka & kb)]

    def _sev_counts(items):
        c: Dict[str, int] = {}
        for f in items:
            s = f.get("severity") or "Info"
            c[s] = c.get(s, 0) + 1
        return c

    def _score(items):
        return sum(_SEV_RANK.get(f.get("severity") or "Info", 0) for f in items)

    return {
        "kind": "web-scan",
        "a": {"id": a.get("id"), "target": a.get("target"),
              "started_at": a.get("started_at"), "findings": len(fa)},
        "b": {"id": b.get("id"), "target": b.get("target"),
              "started_at": b.get("started_at"), "findings": len(fb)},
        "added": added,               # new in B
        "resolved": resolved,         # gone in B
        "still_open": still,
        "counts": {
            "added": len(added), "resolved": len(resolved),
            "still_open": len(still),
            "added_by_severity": _sev_counts(added),
            "resolved_by_severity": _sev_counts(resolved),
            "still_by_severity": _sev_counts(still),
        },
        "risk_delta": _score(fb) - _score(fa),
        "verdict": (
            "IMPROVED — findings closed" if _score(fb) < _score(fa)
            else "REGRESSED — new / worse findings" if _score(fb) > _score(fa)
            else "UNCHANGED risk score"
        ),
    }


def compare_network(a: dict, b: dict) -> dict:
    def ports(job):
        out = {}
        for h in ((job.get("result") or {}).get("report") or {}).get("hosts") or []:
            host = h.get("host") or h.get("hostname") or "?"
            for p in h.get("open_ports") or []:
                out[(host, int(p.get("port") or 0))] = p
        return out
    pa, pb = ports(a), ports(b)
    ka, kb = set(pa), set(pb)
    opened = [{"host": h, "port": p, **pb[(h, p)]} for h, p in sorted(kb - ka)]
    closed = [{"host": h, "port": p, **pa[(h, p)]} for h, p in sorted(ka - kb)]
    same = [{"host": h, "port": p, **pb[(h, p)]} for h, p in sorted(ka & kb)]
    return {
        "kind": "network-scan",
        "a": {"id": a.get("id"), "target": a.get("target"), "ports": len(pa)},
        "b": {"id": b.get("id"), "target": b.get("target"), "ports": len(pb)},
        "opened": opened, "closed": closed, "unchanged": same,
        "counts": {"opened": len(opened), "closed": len(closed),
                   "unchanged": len(same)},
        "verdict": (
            "surface grew" if opened and not closed
            else "surface shrank" if closed and not opened
            else "mixed change" if opened or closed
            else "identical open-port set"
        ),
    }


def compare_jobs(a: dict, b: dict) -> dict:
    ka, kb = a.get("kind"), b.get("kind")
    if ka == "web-scan" and kb == "web-scan":
        return compare_web(a, b)
    if ka == "network-scan" and kb == "network-scan":
        return compare_network(a, b)
    return {"error": f"cannot compare {ka} with {kb} — pick two jobs of the same kind"}
