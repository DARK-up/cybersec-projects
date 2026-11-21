#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DARK API Security Auditor — REST, OpenAPI/Swagger, GraphQL, Auth & AuthZ Configuration."""
from __future__ import annotations

import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT / "webvulnx") not in sys.path:
    sys.path.insert(0, str(ROOT / "webvulnx"))

import webvulnx as wx  # noqa: E402
import openapi_auth as oa  # noqa: E402


def _afind(title: str, sev: str, url: str, param: str, evidence: str, rem: str, cwe: str = "CWE-284") -> dict:
    return {
        "vuln_type": f"[API] {title}",
        "severity": sev,
        "url": url,
        "parameter": param,
        "how_it_entered": f"API security assessment on {url} [{param}]",
        "evidence": evidence,
        "impact": "API schema, authentication, or authorization weaknesses can expose business endpoints or sensitive user objects.",
        "remediation": rem,
        "cwe": cwe,
        "owasp": "API2:2023 / API3:2023",
    }


def run_api_audit(
    url: str,
    openapi_url: Optional[str] = None,
    spec_json: Optional[str] = None,
    auth_header: Optional[str] = None,
    check_graphql: bool = True,
) -> dict:
    target = wx.ensure_scheme(url.strip())
    headers = {}
    if auth_header:
        headers["Authorization"] = auth_header
    client = wx.HttpClient(target=target, headers=headers or None, stealth=True, timeout=6.0)
    state = wx.ScanState(base_url=target)
    findings: List[dict] = []
    inventory: List[dict] = []

    # 1. OpenAPI / Swagger Ingestion & Schema Validation
    spec_doc = None
    spec_src = openapi_url or target
    if spec_json and spec_json.strip():
        try:
            spec_doc = json.loads(spec_json)
            spec_src = "inline-openapi-spec"
        except Exception:
            pass
    if spec_doc is None:
        oares = oa.ingest_openapi(client, target, state, wx.Finding, openapi_url=openapi_url)
        if oares.get("found"):
            spec_src = oares["spec_url"]
            r = client.request("GET", spec_src)
            if r is not None:
                try:
                    spec_doc = r.json()
                except Exception:
                    spec_doc = None

    if isinstance(spec_doc, dict) and isinstance(spec_doc.get("paths"), dict):
        # Validate transport & global security
        for srv in (spec_doc.get("servers") or []):
            su = str((srv or {}).get("url") or "")
            if su.startswith("http://") and "127.0.0.1" not in su and "localhost" not in su:
                findings.append(_afind(
                    "Cleartext HTTP Server Defined in OpenAPI Spec", "Medium", spec_src, "servers",
                    f"Server URL uses http:// ({su})", "Enforce https:// in all production OpenAPI server entries.", "CWE-319"
                ))
        global_sec = spec_doc.get("security")
        for path, methods in spec_doc["paths"].items():
            if not isinstance(methods, dict):
                continue
            for m, op in methods.items():
                if m.lower() not in ("get", "post", "put", "patch", "delete"):
                    continue
                if not isinstance(op, dict):
                    continue
                ep_url = urljoin(target.rstrip("/") + "/", path.lstrip("/"))
                has_sec = bool(op.get("security") if "security" in op else global_sec)
                inventory.append({"method": m.upper(), "path": path, "authenticated": has_sec})
                if not has_sec and not any(pub in path.lower() for pub in ("health", "login", "auth", "public", "docs")):
                    findings.append(_afind(
                        "API Endpoint Lacks Security Scheme in Schema", "Medium", ep_url, m.upper(),
                        f"{m.upper()} {path} defines no OpenAPI security requirement",
                        "Define bearerAuth/OAuth2 security requirements explicitly or mark public routes intentionally.", "CWE-306"
                    ))
                # Mass Assignment risk check on writable body schemas
                rb = json.dumps(op.get("requestBody") or {}).lower()
                for sensitive_field in ('"role"', '"isadmin"', '"is_admin"', '"admin"', '"permissions"'):
                    if sensitive_field in rb:
                        findings.append(_afind(
                            "Potential Mass Assignment Field in API Request Schema", "High", ep_url, sensitive_field.strip('"'),
                            f"Writable schema on {m.upper()} {path} exposes {sensitive_field}",
                            "Remove privileged fields from public DTOs/request schemas and enforce server-side allowlists.", "CWE-915"
                        ))
                # IDOR / BOLA indicator check
                if "{id}" in path.lower() or "userid" in path.lower() or "accountid" in path.lower():
                    findings.append(_afind(
                        "Object-Level Authorization Review Recommended (BOLA/IDOR Surface)", "Info", ep_url, path,
                        f"Path {m.upper()} {path} accepts direct object identifier",
                        "Verify object ownership checks on every request for this identifier.", "CWE-639"
                    ))

    # 2. Live API Security Headers, CORS & Rate-Limit check
    r_root = client.request("GET", target)
    if r_root is not None:
        hdrs = {k.lower(): v for k, v in r_root.headers.items()}
        if hdrs.get("access-control-allow-origin") == "*" and hdrs.get("access-control-allow-credentials", "").lower() == "true":
            findings.append(_afind(
                "Permissive CORS with Credentials on API", "High", target, "CORS",
                "Access-Control-Allow-Origin: * with Allow-Credentials: true",
                "Allowlist explicit trusted origins instead of wildcard.", "CWE-942"
            ))
        if not any(h in hdrs for h in ("x-ratelimit-limit", "ratelimit-limit", "retry-after")):
            findings.append(_afind(
                "No Rate-Limit Response Headers Detected", "Low", target, "RateLimit",
                "Missing X-RateLimit-Limit / RateLimit-Limit headers on API response",
                "Enforce per-user/IP API rate limiting and return standard RateLimit headers.", "CWE-770"
            ))

    # 3. GraphQL Introspection Check
    if check_graphql:
        for gp in ("/graphql", "/api/graphql"):
            gurl = urljoin(target.rstrip("/") + "/", gp.lstrip("/"))
            rg = client.request("POST", gurl, json={"query": "{__schema{types{name}}}"})
            if rg is not None and rg.status_code == 200 and "__schema" in (rg.text or ""):
                inventory.append({"method": "POST", "path": gp, "authenticated": bool(auth_header)})
                findings.append(_afind(
                    "GraphQL Introspection Enabled", "Medium", gurl, "query",
                    "Introspection query {__schema{types{name}}} returned schema metadata",
                    "Disable GraphQL introspection in production environments.", "CWE-200"
                ))

    for f in state.findings:
        findings.append(asdict(f))

    return {
        "target": target,
        "spec_source": spec_src,
        "inventory": inventory,
        "findings": findings,
        "stats": {"urls_crawled": len(inventory) + 1, "requests_sent": client.stats.get("requests", 0), "duration_s": 0.2},
    }
