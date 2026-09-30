#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HashBreaker v2.0 - Advanced Hash Identification & Cracking Suite
================================================================
Author : CyberSec Portfolio Project (Red Team Track)
Purpose: Authorized password auditing / hash recovery ONLY.

Features
--------
* Hash identification engine (25+ formats: MD5, SHA1/2 family, NTLM,
  MySQL, MSSQL, PostgreSQL, bcrypt, sha256/512crypt, Django, Joomla...)
* Dictionary attack with intelligent mangling rules
* Mask / hybrid brute-force attack (custom charsets, ?l ?u ?d ?s ?a)
* Multiprocessing cracking (all CPU cores)
* Salted hashes (raw salted + hmac-sha256/sha512)
* pwdump / shadow file input (user:hash)
* Auto-detect & chain: dictionary -> rules -> mask
* Benchmark mode (hashes/sec per algorithm)
* Cracked results export (JSON / text)

LEGAL: Only crack hashes you are authorized to audit.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import itertools
import json
import multiprocessing as mp
import os
import re
import sys
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Optional, Tuple

BANNER = r"""
  _   _            _     _                _             
 | | | | __ _  ___| | __| | ___ _ __ ___| | ___ _ __   
 | |_| |/ _` |/ __| |/ _` |/ _ \ '__/ _ \ |/ _ \ '__|  
 |  _  | (_| | (__| | (_| |  __/ | |  __/ |  __/ |     
 |_| |_|\__,_|\___|_|\__,_|\___|_|  \___|_|\___|_|     
  Advanced Hash Identification & Cracking Suite v2.0
"""

C = {
    "red": "\033[91m", "green": "\033[92m", "yellow": "\033[93m",
    "blue": "\033[94m", "cyan": "\033[96m", "bold": "\033[1m",
    "dim": "\033[2m", "reset": "\033[0m",
}


def colorize(t: str, c: str) -> str:
    return t if not sys.stdout.isatty() else f"{C.get(c, '')}{t}{C['reset']}"


def info(m): print(f"{colorize('[*]', 'blue')} {m}")
def ok(m):   print(f"{colorize('[+]', 'green')} {m}")
def warn(m): print(f"{colorize('[!]', 'yellow')} {m}")
def fail(m): print(f"{colorize('[-]', 'red')} {m}")
def found(m): print(f"{colorize('[FOUND]', 'green')}{colorize(' ' + m, 'bold')}")


# ============================================================================
# Hash identification
# ============================================================================
@dataclass
class HashInfo:
    name: str
    digest: str
    length: int
    charset: str
    candidates: List[str]


def _charset_of(h: str) -> str:
    if re.fullmatch(r"[0-9a-f]+", h):
        return "hex-lower"
    if re.fullmatch(r"[0-9A-F]+", h):
        return "hex-upper"
    if re.fullmatch(r"[0-9a-fA-F]+", h):
        return "hex-mixed"
    if re.fullmatch(r"[A-Za-z0-9+/=]+", h):
        return "base64"
    return "other"


HEX_FORMATS: Dict[int, List[str]] = {
    32: ["MD5", "MD4", "NTLM", "MySQL 3.x (old)", "LM (partial)", "Double MD5"],
    40: ["SHA1", "MySQL 4.1/5.x (20-byte)", "RIPEMD-160", "Double SHA1"],
    56: ["SHA224", "Double SHA224"],
    64: ["SHA256", "Double SHA256", "SHA3-256", "BLAKE2s"],
    96: ["SHA384", "Double SHA384"],
    128: ["SHA512", "SHA3-512", "BLAKE2b", "Whirlpool"],
    16: ["MySQL HASH(short)", "CRC64"],
}

PREFIX_FORMATS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$"), "bcrypt ($2a/$2b/$2y)"),
    (re.compile(r"^\$6\$[^\$]*\$[./A-Za-z0-9]{86}$"), "sha512crypt (Unix)"),
    (re.compile(r"^\$5\$[^\$]*\$[./A-Za-z0-9]{43}$"), "sha256crypt (Unix)"),
    (re.compile(r"^\$1\$[^\$]*\$[./A-Za-z0-9]{22}$"), "md5crypt (Unix)"),
    (re.compile(r"^\$apr1\$[^\$]*\$[./A-Za-z0-9]{22}$"), "Apache MD5 (apr1)"),
    (re.compile(r"^\$y\$[^\$]+\$[^\$]+\$[^\$]+$"), "yescrypt"),
    (re.compile(r"^\$argon2(id|i|d)\$"), "Argon2"),
    (re.compile(r"^[0-9a-f]{32}:[0-9a-f]{32}$"), "MD5(pass:pass) double-dash"),
    (re.compile(r"^\$P\$[./A-Za-z0-9]{31}$"), "phpass (WordPress)"),
    (re.compile(r"^\$H\$[./A-Za-z0-9]{31}$"), "phpass (phpBB)"),
    (re.compile(r"^[0-9a-f]{32}:[0-9a-f]{32}$"), "MD5(pass:pass) double-dash"),
    (re.compile(r"^0x0100[0-9a-f]{88}$", re.I), "MSSQL 2005+"),
    (re.compile(r"^0x0100[0-9a-f]{48}$", re.I), "MSSQL 2000"),
    (re.compile(r"^[0-9a-f]{40}:[0-9a-f]{20}$", re.I), "MySQL 4.1+ (hash:salt)"),
    (re.compile(r"^sha1\$[^\$]+\$[0-9a-f]{40}$", re.I), "Django SHA1"),
    (re.compile(r"^sha256\$[^\$]+\$[0-9a-f]{64}$", re.I), "Django SHA256"),
    (re.compile(r"^pbkdf2_sha256\$\d+\$"), "Django PBKDF2-SHA256"),
    (re.compile(r"^pbkdf2:sha256:\d+\$"), "Flask/Werkzeug PBKDF2"),
    (re.compile(r"^\{SSHA\}"), "LDAP SSHA"),
    (re.compile(r"^\{SHA\}"), "LDAP SHA"),
    (re.compile(r"^[0-9a-f]{32}:[0-9a-f]+$", re.I), "MD5+salt (hex:salt)"),
    (re.compile(r"^[0-9a-f]{64}:[0-9a-f]+$", re.I), "SHA256+salt (hex:salt)"),
    (re.compile(r"^md5\$[^\$]+\$[0-9a-f]{32}$", re.I), "Django MD5"),
    (re.compile(r"^scrypt\$"), "scrypt"),
    (re.compile(r"^\$argon2"), "Argon2"),
]


def identify_hash(h: str) -> HashInfo:
    h = h.strip()
    digest = h.split(":")[0] if ":" in h else h
    info_obj = HashInfo(
        name="Unknown",
        digest=h,
        length=len(digest),
        charset=_charset_of(digest),
        candidates=[],
    )
    for rx, name in PREFIX_FORMATS:
        if rx.match(h):
            info_obj.name = name
            info_obj.candidates = [name]
            return info_obj

    if info_obj.charset in ("hex-lower", "hex-upper", "hex-mixed"):
        cands = HEX_FORMATS.get(len(digest), [])
        info_obj.candidates = cands[:]
        if cands:
            info_obj.name = cands[0]
    elif info_obj.charset == "base64":
        try:
            dec = base64.b64decode(digest + "=" * (-len(digest) % 4))
            cands = HEX_FORMATS.get(len(dec) * 2, [])
            info_obj.candidates = [f"Base64({c})" for c in cands] or ["Base64(unknown)"]
            if cands:
                info_obj.name = info_obj.candidates[0]
        except Exception:
            pass
    return info_obj


# ============================================================================
# Mangling rules (hashcat-lite)
# ============================================================================
def mangle(word: str) -> Iterable[str]:
    """Yield common mutations of a word."""
    w = word.rstrip("\n")
    seen = set()
    variants = [
        w,
        w.lower(), w.upper(), w.capitalize(), w.swapcase(),
        w[::-1],
        w + "1", w + "12", w + "123", w + "1234", w + "12345", w + "123456",
        w + "!", w + "@", w + "#", w + "!", w + "2024", w + "2025", w + "2026",
        w + "123!", w + "@123", w + "123456789", w + "01", w + "007",
        "!" + w, "@" + w,
        w.lower() + "1", w.capitalize() + "1",
        w.replace("a", "@"), w.replace("a", "4"), w.replace("e", "3"),
        w.replace("i", "1"), w.replace("o", "0"), w.replace("s", "$"),
        w.replace("a", "@").replace("e", "3").replace("i", "1").replace("o", "0"),
        w + w[::-1],
    ]
    for v in variants:
        if v and v not in seen:
            seen.add(v)
            yield v


# ============================================================================
# Hash computation
# ============================================================================
# OpenSSL 3 removed MD4 from the default provider — NTLM/MD4/LM need it.
# Ship a pure-Python MD4 (RFC 1320) fallback so cracking works everywhere.
def _md4_pure(data: bytes) -> bytes:
    import struct

    def F(x, y, z): return (x & y) | (~x & z)
    def G(x, y, z): return (x & y) | (x & z) | (y & z)
    def H(x, y, z): return x ^ y ^ z

    def rol(x, n): return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    msg = bytearray(data)
    ml = len(data) * 8
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack("<Q", ml)

    a, b, c, d = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    for off in range(0, len(msg), 64):
        X = struct.unpack("<16I", msg[off:off + 64])
        A, B, C, D = a, b, c, d

        # Round 1
        for i in range(16):
            s = (3, 7, 11, 19)[i % 4]
            if i % 4 == 0:
                A = rol((A + F(B, C, D) + X[i]) & 0xFFFFFFFF, s)
            elif i % 4 == 1:
                D = rol((D + F(A, B, C) + X[i]) & 0xFFFFFFFF, s)
            elif i % 4 == 2:
                C = rol((C + F(D, A, B) + X[i]) & 0xFFFFFFFF, s)
            else:
                B = rol((B + F(C, D, A) + X[i]) & 0xFFFFFFFF, s)

        # Round 2
        g = 0x5A827999
        order = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]
        shifts = [3, 5, 9, 13]
        for i in range(16):
            k, s = order[i], shifts[i % 4]
            if i % 4 == 0:
                A = rol((A + G(B, C, D) + X[k] + g) & 0xFFFFFFFF, s)
            elif i % 4 == 1:
                D = rol((D + G(A, B, C) + X[k] + g) & 0xFFFFFFFF, s)
            elif i % 4 == 2:
                C = rol((C + G(D, A, B) + X[k] + g) & 0xFFFFFFFF, s)
            else:
                B = rol((B + G(C, D, A) + X[k] + g) & 0xFFFFFFFF, s)

        # Round 3
        g = 0x6ED9EBA1
        order = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
        shifts = [3, 9, 11, 15]
        for i in range(16):
            k, s = order[i], shifts[i % 4]
            if i % 4 == 0:
                A = rol((A + H(B, C, D) + X[k] + g) & 0xFFFFFFFF, s)
            elif i % 4 == 1:
                D = rol((D + H(A, B, C) + X[k] + g) & 0xFFFFFFFF, s)
            elif i % 4 == 2:
                C = rol((C + H(D, A, B) + X[k] + g) & 0xFFFFFFFF, s)
            else:
                B = rol((B + H(C, D, A) + X[k] + g) & 0xFFFFFFFF, s)

        a = (a + A) & 0xFFFFFFFF
        b = (b + B) & 0xFFFFFFFF
        c = (c + C) & 0xFFFFFFFF
        d = (d + D) & 0xFFFFFFFF
    return struct.pack("<4I", a, b, c, d)


def _md4(data: bytes) -> bytes:
    try:
        return bytes.fromhex(hashlib.new("md4", data).hexdigest())
    except ValueError:
        return _md4_pure(data)


@dataclass
class Target:
    user: str = ""
    hash_str: str = ""
    algo: str = ""
    salt: str = ""
    plain: str = ""


def compute(algo: str, password: str, salt: str = "") -> str:
    pw = password.encode("utf-8", errors="ignore")
    sl = salt.encode("utf-8", errors="ignore") if salt else b""
    if algo == "md5":
        return hashlib.md5(pw).hexdigest()
    if algo == "md4":
        return _md4(pw).hex()
    if algo == "ntlm":
        return _md4(password.encode("utf-16le")).hex()
    if algo == "sha1":
        return hashlib.sha1(pw).hexdigest()
    if algo == "sha224":
        return hashlib.sha224(pw).hexdigest()
    if algo == "sha256":
        return hashlib.sha256(pw).hexdigest()
    if algo == "sha384":
        return hashlib.sha384(pw).hexdigest()
    if algo == "sha512":
        return hashlib.sha512(pw).hexdigest()
    if algo == "md5+salt":
        return hashlib.md5(pw + sl).hexdigest()
    if algo == "sha1+salt":
        return hashlib.sha1(pw + sl).hexdigest()
    if algo == "sha256+salt":
        return hashlib.sha256(pw + sl).hexdigest()
    if algo == "sha512+salt":
        return hashlib.sha512(pw + sl).hexdigest()
    if algo == "hmac-sha256":
        return hmac.new(sl, pw, hashlib.sha256).hexdigest()
    if algo == "hmac-sha512":
        return hmac.new(sl, pw, hashlib.sha512).hexdigest()
    if algo == "md5(md5)":
        return hashlib.md5(hashlib.md5(pw).digest()).hexdigest()
    if algo == "sha256(sha256)":
        return hashlib.sha256(hashlib.sha256(pw).digest()).hexdigest()
    if algo == "sha512(sha512)":
        return hashlib.sha512(hashlib.sha512(pw).digest()).hexdigest()
    if algo == "mysql3":
        nr = 1345345333
        add = 7
        nr2 = 0x12345671
        for c in pw:
            if c in (32, 9):  # space, tab
                continue
            nr ^= (((nr & 63) + add) * c) + ((nr << 8) & 0xFFFFFFFF)
            nr &= 0xFFFFFFFF
            nr2 = (nr2 + ((nr2 << 8) ^ nr)) & 0xFFFFFFFF
            add = (add + c) & 0xFFFFFFFF
        return f"{nr & 0x7fffffff:08x}{nr2 & 0x7fffffff:08x}"
    raise ValueError(f"unknown algo: {algo}")


ALGO_MAP = {
    "MD5": "md5", "MD4": "md4", "NTLM": "ntlm", "LM (partial)": "md4",
    "Double MD5": "md5(md5)", "Double SHA1": "sha1", "Double SHA256": "sha256(sha256)",
    "Double SHA512": "sha512(sha512)", "SHA1": "sha1", "SHA224": "sha224",
    "SHA256": "sha256", "SHA384": "sha384", "SHA512": "sha512",
    "MySQL 3.x (old)": "mysql3", "MySQL 4.1/5.x (20-byte)": "sha1",
    "MySQL HASH(short)": "mysql3",
}


# ============================================================================
# Mask engine
# ============================================================================
CHARSETS = {
    "l": "abcdefghijklmnopqrstuvwxyz",
    "u": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "d": "0123456789",
    "s": "!@#$%^&*()-_=+[]{};:'\",.<>/?|`~ ",
    "a": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+",
    "h": "0123456789abcdef",
    "H": "0123456789ABCDEF",
}


def parse_mask(mask: str, custom: Optional[Dict[str, str]] = None) -> List[str]:
    """'?l?l?d?d' -> list of charsets for each position."""
    custom = custom or {}
    positions: List[str] = []
    i = 0
    while i < len(mask):
        if mask[i] == "?" and i + 1 < len(mask):
            key = mask[i + 1]
            if key in custom:
                positions.append(custom[key])
            elif key in CHARSETS:
                positions.append(CHARSETS[key])
            else:
                fail(f"Unknown mask token ?{key}")
                sys.exit(1)
            i += 2
        else:
            positions.append(mask[i])
            i += 1
    return positions


def mask_stream(positions: List[str], limit: Optional[int] = None) -> Iterable[str]:
    total = 1
    for p in positions:
        total *= len(p)
    if limit and total > limit:
        return
    for combo in itertools.product(*positions):
        yield "".join(combo)


def estimate_mask(mask: str) -> int:
    n = 1
    for p in parse_mask(mask):
        n *= len(p)
    return n


# ============================================================================
# Cracking engine (multiprocessing)
# ============================================================================
def _worker_check(args) -> Optional[Tuple[str, str]]:
    """Check a batch of passwords against one target. Returns (password, user)."""
    algo, salt, target_hash, batch, user = args
    for pw in batch:
        try:
            if compute(algo, pw, salt) == target_hash.lower():
                return pw, user
        except Exception:
            continue
    return None


def _chunked(it: Iterable[str], size: int):
    batch = []
    for x in it:
        batch.append(x)
        if len(batch) >= size:
            yield batch
            batch = []
    if batch:
        yield batch


class Cracker:
    def __init__(self, targets: List[Target], wordlist: Optional[List[str]],
                 workers: Optional[int] = None, use_rules: bool = False,
                 mask: Optional[str] = None, custom_charsets: Optional[Dict[str, str]] = None,
                 max_mask: int = 5_000_000):
        self.targets = targets
        self.wordlist = wordlist or []
        self.workers = workers or max(1, (os.cpu_count() or 2) - 0)
        self.use_rules = use_rules
        self.mask = mask
        self.custom_charsets = custom_charsets or {}
        self.max_mask = max_mask
        self.cracked: List[Dict] = []
        self.attempts = 0

    def _password_stream(self) -> Iterable[str]:
        if self.wordlist:
            for w in self.wordlist:
                if self.use_rules:
                    yield from mangle(w)
                else:
                    yield w.rstrip("\n")
        if self.mask:
            positions = parse_mask(self.mask, self.custom_charsets)
            est = 1
            for p in positions:
                est *= len(p)
            if est > self.max_mask:
                warn(f"Mask keyspace {est:,} exceeds cap {self.max_mask:,} — skipped. "
                     f"Use --max-mask to raise the cap.")
            else:
                yield from mask_stream(positions, limit=self.max_mask)

    def run(self) -> List[Dict]:
        t0 = time.time()
        stream = self._password_stream()
        remaining = {i: t for i, t in enumerate(self.targets)}
        batch_size = 5000

        info(f"Workers: {self.workers} | Targets: {len(self.targets)} | "
             f"Rules: {'ON' if self.use_rules else 'OFF'} | Mask: {self.mask or 'OFF'}")

        pool = mp.Pool(self.workers)
        try:
            for batch in _chunked(stream, batch_size * self.workers):
                if not remaining:
                    break
                self.attempts += len(batch) * max(len(remaining), 1)
                tasks = []
                for idx, t in list(remaining.items()):
                    tasks.append((t.algo, t.salt, t.hash_str.lower(), batch, t.user or f"#{idx}"))
                for res in pool.imap_unordered(_worker_check, tasks):
                    if res:
                        pw, user = res
                        for idx, t in list(remaining.items()):
                            if (t.user or f"#{idx}") == user:
                                t.plain = pw
                                self.cracked.append(asdict(t))
                                found(f"user={user} algo={t.algo} password={colorize(pw, 'yellow')}")
                                del remaining[idx]
                # progress
                sys.stdout.write(
                    f"\r{colorize('[~]', 'cyan')} attempts≈{self.attempts:,} "
                    f"remaining={len(remaining)}   "
                )
                sys.stdout.flush()
        finally:
            pool.close()
            pool.join()
            sys.stdout.write("\r" + " " * 60 + "\r")

        dt = time.time() - t0
        rate = self.attempts / dt if dt > 0 else 0
        ok(f"Done in {dt:.2f}s | rate ≈ {rate:,.0f} H/s | cracked {len(self.cracked)}/{len(self.targets)}")
        return self.cracked


# ============================================================================
# Input parsing
# ============================================================================
def parse_hash_file(path: str) -> List[Target]:
    """
    Accepts:
      hash
      user:hash
      user:rid:lm:ntlm:::   (pwdump)
      user:$6$salt$hash     (shadow)
    """
    targets: List[Target] = []
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("$") or ":" not in line:
                h = line
                targets.append(Target(user="", hash_str=h, algo="", salt=""))
                continue
            parts = line.split(":")
            user = parts[0]
            # pwdump: user:rid:lmhash:nthash:::
            if len(parts) >= 4 and len(parts[3]) == 32 and re.fullmatch(r"[0-9a-fA-F]{32}", parts[3]):
                targets.append(Target(user=user, hash_str=parts[3], algo="", salt=""))
                continue
            # shadow / user:hash
            h = parts[1] if len(parts) > 1 else parts[0]
            targets.append(Target(user=user, hash_str=h, algo="", salt=""))
    return targets


def resolve_algos(t: Target, force_algo: Optional[str]) -> None:
    """Assign concrete cracking algo + salt from hash format."""
    if force_algo:
        t.algo = force_algo
        return
    hi = identify_hash(t.hash_str)
    name = hi.name
    h = t.hash_str

    # salted formats first
    if re.fullmatch(r"[0-9a-fA-F]{40}:[0-9a-f]+", h):
        digest, _, salt = h.partition(":")
        t.hash_str, t.salt, t.algo = digest, salt, "sha1+salt"
        return
    if re.fullmatch(r"[0-9a-fA-F]{64}:[0-9a-f]+", h):
        digest, _, salt = h.partition(":")
        t.hash_str, t.salt, t.algo = digest, salt, "sha256+salt"
        return
    if re.fullmatch(r"[0-9a-fA-F]{32}:[0-9a-f]+", h):
        digest, _, salt = h.partition(":")
        t.hash_str, t.salt, t.algo = digest, salt, "md5+salt"
        return
    if name in ALGO_MAP:
        t.algo = ALGO_MAP[name]
    elif name.startswith("Base64"):
        t.algo = "sha1"
    else:
        t.algo = "md5" if len(h) == 32 else ("sha1" if len(h) == 40 else
                                             "sha256" if len(h) == 64 else
                                             "sha512" if len(h) == 128 else "md5")


# ============================================================================
# Benchmark
# ============================================================================
def benchmark() -> None:
    info("Benchmarking hash algorithms (2 seconds each)...")
    password = b"benchmark-password-123"
    algos = ["md5", "sha1", "sha256", "sha512", "ntlm", "hmac-sha256", "md5+salt", "sha256+salt"]
    for algo in algos:
        t0, n = time.time(), 0
        while time.time() - t0 < 2.0:
            for _ in range(5000):
                compute(algo, password.decode(), "salt")
                n += 5000
            dt = time.time() - t0
            if dt >= 2.0:
                break
        dt = time.time() - t0
        print(f"  {algo:<14} {n / dt:>14,.0f} H/s")


# ============================================================================
# CLI
# ============================================================================
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="hashbreaker",
        description="HashBreaker v2.0 - Hash Identification & Cracking Suite",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 hashbreaker.py identify -x 5f4dcc3b5aa765d61d8327deb882cf99\n"
            "  python3 hashbreaker.py crack -f hashes.txt -w wordlists/rockyou-mini.txt --rules\n"
            "  python3 hashbreaker.py crack -H 098f6bcd4621d373cade4e832627b4f6 --mask '?l?l?l?l'\n"
            "  python3 hashbreaker.py crack -f hashes.txt -a ntlm -w wordlist.txt --workers 4\n"
            "  python3 hashbreaker.py benchmark\n\n"
            "Mask tokens: ?l=lower ?u=upper ?d=digits ?s=special ?a=all ?h=hex-lower ?H=hex-upper\n"
            "LEGAL: Only crack hashes you are authorized to audit."
        ),
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    pi = sub.add_parser("identify", help="Identify hash type")
    pi.add_argument("-x", "--hash", help="Single hash string")
    pi.add_argument("-f", "--file", help="File with hashes")

    pc = sub.add_parser("crack", help="Crack hashes")
    pc.add_argument("-x", "--hash", help="Single hash")
    pc.add_argument("-f", "--file", help="Hashes file (hash / user:hash / pwdump / shadow)")
    pc.add_argument("-w", "--wordlist", help="Wordlist file")
    pc.add_argument("--rules", action="store_true", help="Enable mangling rules")
    pc.add_argument("--mask", help="Mask attack, e.g. '?l?l?l?d?d'")
    pc.add_argument("-s", "--salt", help="Salt (for -a *+salt / hmac-*)")
    pc.add_argument("-a", "--algo", help="Force algorithm (skip identification)")
    pc.add_argument("--workers", type=int, help="CPU workers [default: all cores]")
    pc.add_argument("--max-mask", type=int, default=5_000_000,
                    help="Max mask keyspace [5,000,000]")
    pc.add_argument("--charset", action="append", default=[],
                    help='Custom charset "?X=abc" (repeatable)')
    pc.add_argument("--json", metavar="FILE", help="Export cracked results JSON")

    sub.add_parser("benchmark", help="Benchmark algorithms")
    return p


def main() -> None:
    args = build_parser().parse_args()
    print(colorize(BANNER, "cyan"))

    if args.cmd == "benchmark":
        benchmark()
        return

    if args.cmd == "identify":
        hashes: List[str] = []
        if args.hash:
            hashes.append(args.hash.strip())
        if args.file:
            with open(args.file, "r", encoding="utf-8", errors="ignore") as fh:
                hashes.extend(l.strip() for l in fh if l.strip() and not l.startswith("#"))
        if not hashes:
            fail("Provide -x or -f")
            sys.exit(1)
        for h in hashes:
            hi = identify_hash(h)
            cand = ", ".join(hi.candidates) if hi.candidates else "—"
            print(f"\n  Hash     : {colorize(h[:72], 'dim')}")
            print(f"  Length   : {hi.length}")
            print(f"  Charset  : {hi.charset}")
            print(f"  Likely   : {colorize(hi.name, 'cyan')}")
            print(f"  Candidates: {colorize(cand, 'yellow')}")
        return

    # ---- crack ----
    targets: List[Target] = []
    if args.hash:
        targets.append(Target(hash_str=args.hash.strip()))
    if args.file:
        targets.extend(parse_hash_file(args.file))
    if not targets:
        fail("Provide -x or -f")
        sys.exit(1)

    for t in targets:
        resolve_algos(t, args.algo)
        if args.salt and not t.salt:
            t.salt = args.salt

    info(f"Loaded {len(targets)} target hash(es)")
    for t in targets[:10]:
        hi = identify_hash(t.hash_str)
        print(f"  {colorize((t.user or '(anon)'), 'cyan'):<16} {t.hash_str[:48]:<50} "
              f"-> algo={t.algo} salt={t.salt or '-'}")

    wordlist: List[str] = []
    if args.wordlist:
        try:
            with open(args.wordlist, "r", encoding="utf-8", errors="ignore") as fh:
                wordlist = fh.readlines()
            ok(f"Wordlist: {args.wordlist} ({len(wordlist):,} words)")
        except OSError:
            fail(f"Wordlist not found: {args.wordlist}")
            sys.exit(1)

    if not wordlist and not args.mask:
        fail("Provide a wordlist (-w) and/or a mask (--mask)")
        sys.exit(1)

    custom = {}
    for cs in args.charset:
        if "=" in cs:
            k, _, v = cs.partition("=")
            k = k.lstrip("?")
            custom[k] = v

    cracker = Cracker(
        targets=targets, wordlist=wordlist, workers=args.workers,
        use_rules=args.rules, mask=args.mask, custom_charsets=custom,
        max_mask=args.max_mask,
    )
    try:
        cracker.run()
    except KeyboardInterrupt:
        warn("\nInterrupted.")

    print(colorize("\n────── Cracked ──────", "bold"))
    for c in cracker.cracked:
        print(f"  {c['user'] or '(anon)':<16} {c['algo']:<12} -> {colorize(c['plain'], 'green')}")
    if not cracker.cracked:
        warn("Nothing cracked — try a bigger wordlist or longer masks.")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump({
                "tool": "HashBreaker v2.0",
                "cracked_at": datetime.now(timezone.utc).isoformat(),
                "attempts": cracker.attempts,
                "cracked": cracker.cracked,
            }, fh, indent=2, ensure_ascii=False)
        ok(f"JSON export: {args.json}")


if __name__ == "__main__":
    main()
