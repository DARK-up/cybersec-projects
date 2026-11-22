#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DARK Secrets Detection Engine (v4.0).

Scans text, configs, .env files, JavaScript bundles, or directories for leaked
credentials, cloud keys, tokens, and private keys. Always redacts discovered
secret values in findings so raw secrets are never re-exposed in reports.
"""
from __future__ import annotations

import math
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_SECRET_RULES: List[Tuple[str, str, re.Pattern, float]] = [
    ("AWS Access Key ID", "Critical", re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b"), 9.3),
    ("Private Key Material", "Critical", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"), 9.8),
    ("GitHub Token", "Critical", re.compile(r"\b(gh[pousr]_[A-Za-z0-9_]{20,})\b"), 9.1),
    ("Slack Token", "High", re.compile(r"\b(xox[baprs]-[0-9A-Za-z\-]{10,})\b"), 8.4),
    ("Stripe Live Secret Key", "Critical", re.compile(r"\b(sk_live_[0-9a-zA-Z]{16,})\b"), 9.4),
    ("Google API Key", "High", re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b"), 8.2),
    ("JWT Token Embedded", "Medium", re.compile(r"\b(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*)\b"), 6.5),
    ("Database URI with Credentials", "Critical", re.compile(r"\b((?:postgres|postgresql|mysql|mongodb|redis)://[^:\s]+:[^@\s]{3,}@[^\s\"']+)"), 9.0),
    ("Hardcoded API/Password Assignment", "High", re.compile(r"(?i)\b(api_key|apikey|secret_key|client_secret|db_pass(?:word)?|auth_token|access_token)\s*[:=]\s*[\"']([A-Za-z0-9_.\-/+=]{10,})[\"']"), 7.8),
]


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: Dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    ln = float(len(s))
    return -sum((c / ln) * math.log2(c / ln) for c in counts.values())


def _mask_secret(raw: str) -> str:
    s = raw.strip()
    if len(s) <= 8:
        return "[REDACTED]"
    return s[:4] + "..." + s[-3:] + " [REDACTED]"


def scan_secrets(
    content: str = "",
    target_path: Optional[str] = None,
    entropy_threshold: float = 4.2,
) -> Dict[str, Any]:
    """Scan inline content or a workspace file/directory for exposed secrets."""
    sources: List[Tuple[str, str]] = []
    if content:
        sources.append(("inline-input", content))
    if target_path:
        p = Path(target_path)
        if p.is_file():
            sources.append((str(p), p.read_text(encoding="utf-8", errors="ignore")[:500_000]))
        elif p.is_dir():
            for fp in sorted(p.rglob("*")):
                if not fp.is_file():
                    continue
                if any(part in (".git", "node_modules", "__pycache__", ".venv") for part in fp.parts):
                    continue
                if fp.suffix.lower() in (".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".pyc", ".db"):
                    continue
                try:
                    sources.append((str(fp), fp.read_text(encoding="utf-8", errors="ignore")[:250_000]))
                except Exception:
                    continue

    findings: List[Dict[str, Any]] = []
    seen = set()
    for src_name, text in sources:
        for lineno, line in enumerate(text.splitlines(), 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith("//"):
                continue
            for title, sev, rx, cvss in _SECRET_RULES:
                m = rx.search(line)
                if not m:
                    continue
                secret_val = m.group(m.lastindex or 0)
                if any(ph in secret_val.lower() for ph in ("example", "placeholder", "changeme", "redacted", "dummy")):
                    continue
                key = (title, src_name, lineno)
                if key in seen:
                    continue
                seen.add(key)
                findings.append({
                    "vuln_type": f"Exposed Secret: {title}",
                    "severity": sev,
                    "url": src_name,
                    "parameter": f"line:{lineno}",
                    "payload": title,
                    "evidence": f"Detected {title} at line {lineno}: {_mask_secret(secret_val)}",
                    "detail": "Hardcoded secrets in source or configuration files risk unauthorized access if repositories or artifacts are exposed.",
                    "cwe": "CWE-798",
                    "cvss_hint": cvss,
                    "confidence": 0.92,
                    "remediation": "Revoke and rotate the exposed credential immediately, and move secrets into DARK Credential Vault or an environment secret manager.",
                })

            # High-entropy quoted token check (only for key-like assignments)
            m_ent = re.search(r"(?i)(?:token|secret|key|password)\w*\s*[:=]\s*[\"']([A-Za-z0-9+/=_\-]{24,})[\"']", line)
            if m_ent:
                cand = m_ent.group(1)
                ent = _entropy(cand)
                if ent >= entropy_threshold:
                    key = ("High-Entropy Secret", src_name, lineno)
                    if key not in seen:
                        seen.add(key)
                        findings.append({
                            "vuln_type": "Exposed Secret: High-Entropy Credential",
                            "severity": "High",
                            "url": src_name,
                            "parameter": f"line:{lineno}",
                            "payload": f"entropy={ent:.2f}",
                            "evidence": f"High-entropy value (H={ent:.2f}) at line {lineno}: {_mask_secret(cand)}",
                            "detail": "High-entropy credential literal detected in assignment.",
                            "cwe": "CWE-798",
                            "cvss_hint": 7.5,
                            "confidence": 0.80,
                            "remediation": "Replace hardcoded secrets with runtime secret injection.",
                        })

    by_sev: Dict[str, int] = {}
    for f in findings:
        s = f["severity"]
        by_sev[s] = by_sev.get(s, 0) + 1
    return {
        "tool": "DARK Secrets Detection",
        "files_scanned": len(sources),
        "findings": findings,
        "summary": {"total": len(findings), "by_severity": by_sev},
    }
