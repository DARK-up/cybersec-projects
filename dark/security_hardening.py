#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DARK Security Hardening Utilities — Argon2id password hashing & 12+ char
password policy, AES-256-GCM AEAD encryption (cryptography or OpenSSL libcrypto),
sensitive evidence redaction, DNS-resolving SSRF guard + safe outbound HTTP,
path-traversal protection, security headers, and structured JSON logging.
"""
from __future__ import annotations

import base64
import ctypes
import ctypes.util
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import secrets
import socket
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urljoin, urlsplit

try:
    from argon2 import PasswordHasher  # type: ignore
    _PH = PasswordHasher(time_cost=2, memory_cost=65536, parallelism=2)
    ARGON2_OK = True
except Exception:
    _PH = None
    ARGON2_OK = False

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _CryptAESGCM  # type: ignore
    CRYPTOGRAPHY_AESGCM_OK = True
except Exception:
    _CryptAESGCM = None
    CRYPTOGRAPHY_AESGCM_OK = False

MIN_PASSWORD_LENGTH = 12


def validate_password_policy(password: str, min_len: int = MIN_PASSWORD_LENGTH) -> None:
    """Enforce strong password policy (>= 12 chars, non-blank)."""
    pw = password or ""
    if len(pw) < min_len:
        raise ValueError(f"Password must be at least {min_len} characters")
    if not pw.strip():
        raise ValueError("Password cannot be whitespace only")


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


# ---------------------------------------------------------------------------
# Standard AES-256-GCM AEAD (cryptography.hazmat or OpenSSL libcrypto EVP)
# ---------------------------------------------------------------------------
_LIBCRYPTO = None
_EVP_CTRL_GCM_SET_IVLEN = 0x9
_EVP_CTRL_GCM_GET_TAG = 0x10
_EVP_CTRL_GCM_SET_TAG = 0x11


def _get_libcrypto():
    global _LIBCRYPTO
    if _LIBCRYPTO is not None:
        return _LIBCRYPTO
    candidates = [ctypes.util.find_library("crypto"), "libcrypto.so.3", "libcrypto.so.1.1", "libcrypto.dylib"]
    for cand in candidates:
        if not cand:
            continue
        try:
            lib = ctypes.CDLL(cand)
            lib.EVP_aes_256_gcm.restype = ctypes.c_void_p
            lib.EVP_CIPHER_CTX_new.restype = ctypes.c_void_p
            lib.EVP_CIPHER_CTX_free.argtypes = [ctypes.c_void_p]
            lib.EVP_EncryptInit_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
            lib.EVP_EncryptUpdate.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_int), ctypes.c_char_p, ctypes.c_int]
            lib.EVP_EncryptFinal_ex.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_int)]
            lib.EVP_CIPHER_CTX_ctrl.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
            lib.EVP_DecryptInit_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
            lib.EVP_DecryptUpdate.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_int), ctypes.c_char_p, ctypes.c_int]
            lib.EVP_DecryptFinal_ex.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_int)]
            _LIBCRYPTO = lib
            return lib
        except OSError:
            continue
    raise RuntimeError("Neither Python 'cryptography' nor OpenSSL libcrypto is available for AES-256-GCM")


def aes_gcm_encrypt(key_32: bytes, plaintext: bytes, aad: bytes = b"") -> Tuple[bytes, bytes, bytes]:
    """Encrypt with standard NIST AES-256-GCM. Returns (nonce_12, ciphertext, tag_16)."""
    if len(key_32) != 32:
        raise ValueError("AES-256-GCM requires a 32-byte key")
    nonce = secrets.token_bytes(12)
    if CRYPTOGRAPHY_AESGCM_OK and _CryptAESGCM is not None:
        ct_tag = _CryptAESGCM(key_32).encrypt(nonce, plaintext, aad or None)
        return nonce, ct_tag[:-16], ct_tag[-16:]

    lib = _get_libcrypto()
    ctx = lib.EVP_CIPHER_CTX_new()
    if not ctx:
        raise RuntimeError("EVP_CIPHER_CTX_new failed")
    try:
        if lib.EVP_EncryptInit_ex(ctx, lib.EVP_aes_256_gcm(), None, None, None) != 1:
            raise RuntimeError("EVP_EncryptInit_ex cipher failed")
        if lib.EVP_CIPHER_CTX_ctrl(ctx, _EVP_CTRL_GCM_SET_IVLEN, len(nonce), None) != 1:
            raise RuntimeError("EVP_CTRL_GCM_SET_IVLEN failed")
        if lib.EVP_EncryptInit_ex(ctx, None, None, key_32, nonce) != 1:
            raise RuntimeError("EVP_EncryptInit_ex key/iv failed")
        outl = ctypes.c_int(0)
        if aad:
            if lib.EVP_EncryptUpdate(ctx, None, ctypes.byref(outl), aad, len(aad)) != 1:
                raise RuntimeError("EVP_EncryptUpdate AAD failed")
        buf = ctypes.create_string_buffer(len(plaintext) + 16)
        if plaintext:
            if lib.EVP_EncryptUpdate(ctx, buf, ctypes.byref(outl), plaintext, len(plaintext)) != 1:
                raise RuntimeError("EVP_EncryptUpdate plaintext failed")
        ct_len = outl.value
        fbuf = ctypes.create_string_buffer(16)
        if lib.EVP_EncryptFinal_ex(ctx, fbuf, ctypes.byref(outl)) != 1:
            raise RuntimeError("EVP_EncryptFinal_ex failed")
        ct = buf.raw[:ct_len] + fbuf.raw[:outl.value]
        tag = ctypes.create_string_buffer(16)
        if lib.EVP_CIPHER_CTX_ctrl(ctx, _EVP_CTRL_GCM_GET_TAG, 16, tag) != 1:
            raise RuntimeError("EVP_CTRL_GCM_GET_TAG failed")
        return nonce, ct, tag.raw
    finally:
        lib.EVP_CIPHER_CTX_free(ctx)


def aes_gcm_decrypt(key_32: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes = b"") -> bytes:
    """Decrypt and authenticate with AES-256-GCM."""
    if len(key_32) != 32:
        raise ValueError("AES-256-GCM requires a 32-byte key")
    if len(tag) != 16:
        raise ValueError("Invalid GCM tag length")
    if CRYPTOGRAPHY_AESGCM_OK and _CryptAESGCM is not None:
        return _CryptAESGCM(key_32).decrypt(nonce, ciphertext + tag, aad or None)

    lib = _get_libcrypto()
    ctx = lib.EVP_CIPHER_CTX_new()
    if not ctx:
        raise RuntimeError("EVP_CIPHER_CTX_new failed")
    try:
        if lib.EVP_DecryptInit_ex(ctx, lib.EVP_aes_256_gcm(), None, None, None) != 1:
            raise RuntimeError("EVP_DecryptInit_ex cipher failed")
        if lib.EVP_CIPHER_CTX_ctrl(ctx, _EVP_CTRL_GCM_SET_IVLEN, len(nonce), None) != 1:
            raise RuntimeError("EVP_CTRL_GCM_SET_IVLEN failed")
        if lib.EVP_DecryptInit_ex(ctx, None, None, key_32, nonce) != 1:
            raise RuntimeError("EVP_DecryptInit_ex key/iv failed")
        outl = ctypes.c_int(0)
        if aad:
            if lib.EVP_DecryptUpdate(ctx, None, ctypes.byref(outl), aad, len(aad)) != 1:
                raise RuntimeError("EVP_DecryptUpdate AAD failed")
        dbuf = ctypes.create_string_buffer(len(ciphertext) + 16)
        if ciphertext:
            if lib.EVP_DecryptUpdate(ctx, dbuf, ctypes.byref(outl), ciphertext, len(ciphertext)) != 1:
                raise RuntimeError("EVP_DecryptUpdate ciphertext failed")
        d_len = outl.value
        tag_buf = ctypes.create_string_buffer(tag, 16)
        if lib.EVP_CIPHER_CTX_ctrl(ctx, _EVP_CTRL_GCM_SET_TAG, 16, tag_buf) != 1:
            raise RuntimeError("EVP_CTRL_GCM_SET_TAG failed")
        fbuf = ctypes.create_string_buffer(16)
        ok = lib.EVP_DecryptFinal_ex(ctx, fbuf, ctypes.byref(outl))
        if ok != 1:
            raise ValueError("AES-256-GCM authentication tag verification failed")
        return dbuf.raw[:d_len] + fbuf.raw[:outl.value]
    finally:
        lib.EVP_CIPHER_CTX_free(ctx)


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


# ---------------------------------------------------------------------------
# DNS-Resolving SSRF Protection + Redirect Re-Validation
# ---------------------------------------------------------------------------
_BLOCKED_METADATA_HOSTS = {
    "169.254.169.254",
    "metadata.google.internal",
    "metadata.azure.internal",
    "metadata",
    "100.100.100.200",
}
_CGNAT_NET = ipaddress.ip_network("100.64.0.0/10")


def _host_in_allowlist(host: str, allowlist: Optional[Iterable[str]]) -> bool:
    items = list(allowlist) if allowlist is not None else [
        x.strip().lower() for x in os.environ.get("DARK_OUTBOUND_ALLOWLIST", "").split(",") if x.strip()
    ]
    if not items:
        return True
    h = host.lower()
    for pat in items:
        if pat == "*":
            return True
        if "/" in pat:
            try:
                if ipaddress.ip_address(h) in ipaddress.ip_network(pat, strict=False):
                    return True
            except Exception:
                pass
        if pat.startswith("*."):
            if h == pat[2:] or h.endswith(pat[1:]):
                return True
        elif h == pat:
            return True
    return False


def _is_blocked_ip(ip_obj: ipaddress._BaseAddress, allow_loopback: bool = False) -> Tuple[bool, str]:
    # Unwrap IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1)
    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped is not None:
        ip_obj = ip_obj.ipv4_mapped
    if ip_obj.is_unspecified:
        return True, f"Unspecified IP {ip_obj} blocked"
    if ip_obj.is_link_local or ip_obj.is_multicast:
        return True, f"Link-local/multicast IP {ip_obj} blocked"
    if isinstance(ip_obj, ipaddress.IPv4Address) and ip_obj in _CGNAT_NET:
        return True, f"CGNAT IP {ip_obj} blocked"
    if ip_obj.is_loopback:
        if allow_loopback:
            return False, "OK"
        return True, f"Loopback IP {ip_obj} blocked"
    if ip_obj.is_private or ip_obj.is_reserved:
        return True, f"Private/reserved IP {ip_obj} blocked"
    return False, "OK"


def validate_outbound_url(
    url: str,
    allow_loopback: bool = False,
    allowlist: Optional[Iterable[str]] = None,
    strict_dns: bool = False,
) -> Tuple[bool, str]:
    """SSRF guard for outbound URLs: validates scheme, rejects userinfo, blocks
    metadata/internal hosts, resolves DNS and verifies every returned IP."""
    try:
        u = urlsplit((url or "").strip())
    except Exception:
        return False, "Malformed URL"
    if u.scheme not in ("http", "https"):
        return False, "Only http/https schemes allowed"
    if u.username or u.password:
        return False, "Embedded URL credentials rejected (SSRF guard)"
    host = (u.hostname or "").lower().rstrip(".")
    if not host:
        return False, "Missing hostname"
    if host in _BLOCKED_METADATA_HOSTS or host.endswith(".internal") or host.endswith(".local"):
        return False, f"Internal/metadata host '{host}' blocked (SSRF guard)"
    if not _host_in_allowlist(host, allowlist):
        return False, f"Host '{host}' not in DARK_OUTBOUND_ALLOWLIST"

    try:
        ip = ipaddress.ip_address(host)
        blocked, reason = _is_blocked_ip(ip, allow_loopback=allow_loopback)
        return (not blocked), reason
    except ValueError:
        if host in ("localhost", "localhost.localdomain") and not allow_loopback:
            return False, "localhost blocked"

    port = u.port or (443 if u.scheme == "https" else 80)
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror:
        if strict_dns:
            return False, f"DNS resolution failed for '{host}'"
        return True, "OK"

    if not infos:
        return (not strict_dns), ("No DNS records returned" if strict_dns else "OK")

    for info in infos:
        addr_str = info[4][0].split("%", 1)[0]
        try:
            resolved_ip = ipaddress.ip_address(addr_str)
        except ValueError:
            return False, f"Unparseable resolved IP '{addr_str}'"
        blocked, reason = _is_blocked_ip(resolved_ip, allow_loopback=allow_loopback)
        if blocked:
            return False, f"DNS for '{host}' resolved to blocked IP ({reason})"
    return True, "OK"


def safe_outbound_request(
    method: str,
    url: str,
    *,
    allow_loopback: bool = False,
    allowlist: Optional[Iterable[str]] = None,
    max_redirects: int = 5,
    timeout: float = 6.0,
    **kwargs: Any,
):
    """Execute an HTTP request with pre-flight DNS SSRF validation and manual
    redirect re-validation (blocks redirect-to-metadata / DNS rebinding)."""
    import requests

    cur_url = url
    kwargs.pop("allow_redirects", None)
    for _ in range(max_redirects + 1):
        ok, reason = validate_outbound_url(
            cur_url, allow_loopback=allow_loopback, allowlist=allowlist, strict_dns=True
        )
        if not ok:
            raise ValueError(f"SSRF blocked outbound request: {reason}")
        resp = requests.request(method, cur_url, allow_redirects=False, timeout=timeout, **kwargs)
        if resp.status_code in (301, 302, 303, 307, 308):
            loc = resp.headers.get("Location")
            if not loc:
                return resp
            cur_url = urljoin(cur_url, loc)
            continue
        return resp
    raise ValueError("Too many outbound redirects (SSRF guard)")


SECURITY_HEADERS: Dict[str, str] = {
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


def build_security_headers(is_https: bool = False) -> Dict[str, str]:
    hdrs = dict(SECURITY_HEADERS)
    if is_https or os.environ.get("DARK_ENABLE_HSTS") == "1":
        hdrs["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return hdrs


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
