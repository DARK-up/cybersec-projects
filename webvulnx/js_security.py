#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DARK WebVulnX JavaScript Security & Auth / Business-Logic Analyzer (v4.0).

Inspects client-side JavaScript bundles, HTML forms, and session/auth response
patterns without intrusive brute-force or destructive state mutation:
  - Hardcoded API keys / tokens in client-side JS
  - Unsafe DOM sinks (eval, innerHTML, document.write, dangerouslySetInnerHTML)
  - Exposed internal/admin API routes in JS bundles
  - Weak session cookie flags & missing CSRF / rate-limit indicators on auth forms
  - Client-side price/role/discount business-logic trust indicators
"""
from __future__ import annotations

import re
from typing import Any, Dict, List

_DOM_SINKS = (
    ("eval(", "Unsafe eval() Execution Sink"),
    ("document.write(", "DOM XSS Sink: document.write()"),
    (".innerHTML", "DOM XSS Sink: innerHTML Assignment"),
    ("dangerouslySetInnerHTML", "React dangerouslySetInnerHTML Usage"),
    ("postMessage(", "Cross-Origin postMessage() Handler Review Needed"),
)

_JS_SECRET_PATTERNS = (
    (re.compile(r"(?:api[_-]?key|secret|bearer|client_secret)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]", re.I), "Hardcoded Client-Side Secret/API Key"),
    (re.compile(r"AIza[0-9A-Za-z_\-]{35}"), "Google API Key in Client-Side JS"),
    (re.compile(r"sk_(?:live|test)_[0-9a-zA-Z]{20,}"), "Stripe Key in Client-Side JS"),
)

_BIZLOGIC_FIELDS = re.compile(r"name=['\"]?(?:price|amount|total|discount|role|is_admin|admin|credit|balance)['\"]?", re.I)


def analyze_js_and_auth_surface(url: str, html_or_js: str, headers: Dict[str, str] | None = None) -> List[Dict[str, Any]]:
    """Analyze fetched HTML/JS response and headers for JS, Auth, and Business-Logic risks."""
    body = html_or_js or ""
    hdrs = {k.lower(): v for k, v in (headers or {}).items()}
    findings: List[Dict[str, Any]] = []

    for token, title in _DOM_SINKS:
        if token in body:
            findings.append({
                "vuln_type": f"JS Security: {title}",
                "severity": "Medium",
                "url": url,
                "parameter": "client-js",
                "payload": token,
                "evidence": f"Client-side script contains '{token}'",
                "detail": "DOM sink can enable client-side XSS if untrusted input reaches it.",
                "cwe": "CWE-79",
                "cvss_hint": 6.1,
                "confidence": 0.78,
                "remediation": "Use textContent / safe DOM APIs and enforce strict CSP.",
            })

    for rx, title in _JS_SECRET_PATTERNS:
        m = rx.search(body)
        if m:
            snippet = m.group(0)
            masked = snippet[:8] + "..." + snippet[-4:]
            findings.append({
                "vuln_type": f"JS Security: {title}",
                "severity": "High",
                "url": url,
                "parameter": "js-bundle",
                "payload": masked,
                "evidence": f"Credential pattern found in client code ({masked})",
                "detail": "Secrets shipped in browser JavaScript are accessible to every visitor.",
                "cwe": "CWE-798",
                "cvss_hint": 7.8,
                "confidence": 0.90,
                "remediation": "Move credentials to backend proxy/vault and rotate exposed keys.",
            })

    # Auth / Session surface checks
    set_cookie = hdrs.get("set-cookie", "")
    if set_cookie:
        low_sc = set_cookie.lower()
        missing = []
        if "httponly" not in low_sc:
            missing.append("HttpOnly")
        if url.lower().startswith("https://") and "secure" not in low_sc:
            missing.append("Secure")
        if "samesite" not in low_sc:
            missing.append("SameSite")
        if missing:
            findings.append({
                "vuln_type": "Auth Security: Weak Session Cookie Flags",
                "severity": "Medium",
                "url": url,
                "parameter": "Set-Cookie",
                "payload": ", ".join(missing),
                "evidence": f"Set-Cookie missing attributes: {', '.join(missing)}",
                "detail": "Missing HttpOnly/Secure/SameSite exposes session tokens to XSS or CSRF.",
                "cwe": "CWE-614",
                "cvss_hint": 5.4,
                "confidence": 0.92,
                "remediation": "Set HttpOnly, Secure, and SameSite=Lax/Strict on all session cookies.",
            })

    if re.search(r"<form[^>]*>.*?type=['\"]?password['\"]?.*?</form>", body, re.I | re.S):
        if not re.search(r"csrf|xsrf|_token|authenticity_token", body, re.I):
            findings.append({
                "vuln_type": "Auth Security: Login/Auth Form Missing Visible CSRF Token",
                "severity": "Medium",
                "url": url,
                "parameter": "auth-form",
                "payload": "password-form",
                "evidence": "Password form lacks standard anti-CSRF token field",
                "detail": "Authentication/password-change forms without CSRF defenses risk login/account CSRF.",
                "cwe": "CWE-352",
                "cvss_hint": 5.3,
                "confidence": 0.76,
                "remediation": "Include cryptographic anti-CSRF tokens or custom header verification.",
            })

    # Business-logic client-trust indicator
    biz = _BIZLOGIC_FIELDS.findall(body)
    if biz and re.search(r"type=['\"]?hidden['\"]?", body, re.I):
        findings.append({
            "vuln_type": "Business Logic Risk: Sensitive Price/Role Parameter in Client Form",
            "severity": "Medium",
            "url": url,
            "parameter": biz[0],
            "payload": ", ".join(sorted(set(biz))[:4]),
            "evidence": "Client-side form references price/discount/role field alongside hidden inputs",
            "detail": "If server trusts client-supplied price, quantity, or role values, attackers can tamper with transactions or privilege.",
            "cwe": "CWE-472",
            "cvss_hint": 6.5,
            "confidence": 0.75,
            "remediation": "Recompute all prices, discounts, and authorization roles strictly server-side.",
        })

    return findings
