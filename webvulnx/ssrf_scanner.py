#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Dedicated SSRF Verification & Detection Module for WebVulnX (DARK v4.0)."""
from __future__ import annotations

import re
import time
import urllib.parse
from typing import Callable, Dict, List, Optional, Tuple

import payload_mgr as pm

SSRF_PARAM_NAMES = {
    "url", "uri", "fetch", "proxy", "link", "src", "dest",
    "path", "site", "feed", "callback", "domain", "host",
    "image", "img", "load", "redirect", "webhook", "endpoint",
}


def _clean_url(url: str) -> str:
    p = urllib.parse.urlsplit(url)
    return urllib.parse.urlunsplit((p.scheme, p.netloc, p.path, "", ""))


def scan_ssrf_targets(
    client,
    state,
    params_iter: List[Tuple[str, str, str, Dict[str, str]]],
    finding_cls,
    log_fn: Optional[Callable[[str], None]] = None,
) -> int:
    """Scan candidate URL/endpoint parameters for SSRF with baseline comparison
    and scoped YAML payloads. Returns number of findings added."""
    if log_fn:
        log_fn("SSRF dedicated module tests")
    found = 0
    tested = set()

    for url, method, param, base in params_iter:
        if state.should_stop():
            return found
        if param.lower() not in SSRF_PARAM_NAMES:
            continue
        key = (url, param)
        if key in tested:
            continue
        tested.add(key)

        clean = _clean_url(url)
        # Baseline request with benign public example domain to avoid matching static page text
        b_params = dict(base)
        b_params[param] = "https://example.com/"
        t_b0 = time.monotonic()
        base_resp = (
            client.request("GET", clean, params=b_params)
            if method.upper() == "GET"
            else client.request("POST", clean, data=b_params)
        )
        base_text = base_resp.text if base_resp is not None else ""
        base_rtt = time.monotonic() - t_b0

        payload_entries = pm.get_payloads("ssrf", target_url=url, safe_only=True)
        for entry in payload_entries:
            if state.should_stop():
                return found
            payload = str(entry.get("payload") or "")
            expect_pat = str(entry.get("expect") or "")
            if not payload or not expect_pat:
                continue
            rx = re.compile(expect_pat, re.I)

            # Anti-FP: skip if baseline already matched the error/content pattern
            if base_text and rx.search(base_text):
                continue

            inj_params = dict(base)
            inj_params[param] = payload
            t0 = time.monotonic()
            resp = (
                client.request("GET", clean, params=inj_params)
                if method.upper() == "GET"
                else client.request("POST", clean, data=inj_params)
            )
            rtt = time.monotonic() - t0
            if resp is None:
                continue

            m = rx.search(resp.text)
            if m:
                is_meta = "169.254.169.254" in payload or "file://" in payload
                conf = 0.92 if is_meta else 0.86
                sev = "Critical" if is_meta else "High"
                state.add(finding_cls(
                    vuln_type="Server-Side Request Forgery (SSRF)",
                    severity=sev,
                    url=url,
                    parameter=param,
                    payload=payload,
                    evidence=f"SSRF oracle matched '{m.group(0)[:60]}' (absent from baseline; rtt={rtt:.2f}s vs base={base_rtt:.2f}s)",
                    detail="The server fetches attacker-supplied URLs without network egress filtering or IP validation — internal port probing and cloud metadata access are possible.",
                    cvss_hint=9.1 if is_meta else 8.5,
                    confidence=conf,
                    verification_status="Confirmed",
                    cwe="CWE-918",
                    remediation="Enforce strict URL scheme (http/https), resolve DNS and block loopback/RFC1918/link-local/metadata IPs before connecting, and disable automatic HTTP redirects.",
                    signals=[f"oracle:{entry.get('id')}", "baseline-negative"],
                ))
                found += 1
                break
    return found
