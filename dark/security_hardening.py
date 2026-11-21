#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DARK Security Hardening Utilities — Argon2id password hashing (with legacy
PBKDF2 compatibility), sensitive evidence redaction, SSRF URL validation,
path-traversal protection, security headers, and structured JSON logging.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import secrets
import time
from pathlib import Path
from typing import Tuple
from urllib.parse import urlsplit

try:
    from argon2 import PasswordHasher  # type: ignore
    from argon2.exceptions import VerifyMismatchError  # type: ignore
    _PH = PasswordHasher(time_cost=2, memory_cost=65536, parallelism=2)
    ARGON2_OK = True
except Exception:
    _PH = None
    ARGON2_OK = False


def hash_password(password: str) -> Tuple[str, str]:
    """Hash password with Argon2id (preferred) or PBKDF2-HMAC-SHA256 fallback."""
    if ARGON2_OK and _PH is not None:
        return _PH.hash(password), "argon2id"
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 120_000)
    return dk.hex(), salt.hex()


def verify_password(password: str, stored_hash: str, stored_salt: str) -> Tuple[bool, bool]:
    """Verify password and return (valid, needs_rehash_to_argon2id)."""
    if stored_hash.startswith("$argon2") and ARGON2_OK and _PH is not None:
        try:
            ok = _PH.verify(stored_hash, password)
            return ok, _PH.check_needs_rehash(stored_hash)
        except Exception:
            return False, False
    # Legacy PBKDF2-HMAC-SHA256
    try:
        salt = bytes.fromhex(stored_salt)
        cand = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 120_000).hex()
        ok = hmac.compare_digest(cand, stored_hash)
        return ok, (ok and ARGON2_OK)
    except Exception:
        return False, False


_SECRET_HDR_RX = re.compile(
    r'(?im)^((?:authorization|cookie|set-cookie|x-api-key|x-dark-token|x-auth-token)\s*:\s*)(.+)$'
)
_SECRET_BODY_RX = re.compile(
    r'(?i)("?(?:password|passwd|secret|api_key|token|access_token|refresh_token|private_key)"?\s*[:=]\s*"?)([A-Za-z0-9._\-/+=]{6,})("?)'
)
_BEARER_RX = re.compile(r'(?i)(Bearer\s+)[A-Za-z0-9\-_.=+/]{8,}')
_INLINE_AUTH_RX = re.compile(r'(?i)((?:authorization|x-api-key|x-dark-token)\s*:\s*)([^\s,;]{8,})')


def redact_sensitive(text: str, max_len: int = 2000) -> str:
    """Mask Authorization headers, cookies, JWTs, API keys, and passwords in stored evidence."""
    if not text:
        return ""
    out = _SECRET_HDR_RX.sub(r'\1[REDACTED]', text)
    out = _BEARER_RX.sub(r'\1[REDACTED_TOKEN]', out)
    out = _INLINE_AUTH_RX.sub(r'\1[REDACTED]', out)
    out = _SECRET_BODY_RX.sub(r'\1[REDACTED]\3', out)
    return out[:max_len]


def safe_resolve_under(base_dir: Path, user_path: str) -> Path:
    """Prevent path traversal outside base_dir."""
    base = base_dir.resolve()
    cand = (base / user_path).resolve()
    if cand != base and not cand.is_relative_to(base):
        raise ValueError("Path traversal blocked")
    return cand


def validate_outbound_url(url: str, allow_loopback: bool = False) -> Tuple[bool, str]:
    """SSRF guard for outbound webhook/integration URLs (blocks metadata & private IPs)."""
    try:
        u = urlsplit((url or "").strip())
    except Exception:
        return False, "Malformed URL"
    if u.scheme not in ("http", "https"):
        return False, "Only http/https schemes allowed"
    host = (u.hostname or "").lower()
    if not host:
        return False, "Missing hostname"
    if host in ("169.254.169.254", "metadata.google.internal"):
        return False, "Cloud metadata endpoint blocked (SSRF guard)"
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_link_local or ip.is_multicast:
            return False, f"Link-local/multicast IP {host} blocked"
        if ip.is_loopback and not allow_loopback:
            return False, f"Loopback IP {host} blocked"
        if ip.is_private and not allow_loopback:
            return False, f"Private RFC1918 IP {host} blocked"
    except ValueError:
        if host in ("localhost",) and not allow_loopback:
            return False, "localhost blocked"
    return True, "OK"


SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
        "connect-src 'self'; frame-ancestors 'none'"
    ),
}


def get_structured_logger(name: str = "dark") -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        h = logging.StreamHandler()

        class _JsonFmt(logging.Formatter):
            def format(self, record):
                return json.dumps({
                    "ts": round(time.time(), 3),
                    "level": record.levelname,
                    "logger": record.name,
                    "msg": record.getMessage(),
                }, ensure_ascii=False)

        h.setFormatter(_JsonFmt())
        logger.addHandler(h)
        logger.setLevel(getattr(logging, os.environ.get("DARK_LOG_LEVEL", "INFO").upper(), logging.INFO))
    return logger
