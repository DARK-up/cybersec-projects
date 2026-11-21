#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Auto-Login & OpenAPI/Swagger Endpoint Ingestion for WebVulnX / DARK.

* Auto-Login: logs into an HTML login form (preserving hidden CSRF tokens) OR
  a JSON auth endpoint (capturing JWT/Bearer token) using the scan's HttpClient
  so all downstream modules run authenticated.
* OpenAPI/Swagger Ingestion: fetches a user-supplied spec URL or auto-probes
  common paths (/openapi.json, /swagger.json, /v3/api-docs, /v2/api-docs) and
  populates state.crawled_urls, state.params, and state.forms with real API
  endpoints, query parameters, and JSON/form body fields.
"""
from __future__ import annotations

import json
import re
import urllib.parse
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Tuple


class _FormExtractor(HTMLParser):
    def __init__(self, base: str):
        super().__init__()
        self.base = base
        self.forms: List[Dict[str, Any]] = []
        self._cur: Optional[Dict[str, Any]] = None

    def handle_starttag(self, tag: str, attrs):
        a = dict(attrs)
        if tag == "form":
            action = urllib.parse.urljoin(self.base, a.get("action") or self.base)
            self._cur = {
                "url": action,
                "method": (a.get("method") or "POST").upper(),
                "inputs": [],
            }
        elif tag in ("input", "select", "textarea") and self._cur is not None:
            name = a.get("name") or a.get("id") or ""
            if name:
                self._cur["inputs"].append({
                    "name": name,
                    "type": (a.get("type") or "text").lower(),
                    "value": a.get("value") or "",
                })

    def handle_endtag(self, tag: str):
        if tag == "form" and self._cur is not None:
            self.forms.append(self._cur)
            self._cur = None


def _extract_token(obj: Any) -> Optional[str]:
    if isinstance(obj, dict):
        for k in ("token", "access_token", "jwt", "id_token", "auth_token"):
            v = obj.get(k)
            if isinstance(v, str) and len(v) > 12:
                return v
        for v in obj.values():
            found = _extract_token(v)
            if found:
                return found
    elif isinstance(obj, list):
        for item in obj:
            found = _extract_token(item)
            if found:
                return found
    return None


def perform_auto_login(client, login_url: str, username: str, password: str) -> Dict[str, Any]:
    """Authenticate `client` against an HTML form or JSON login endpoint."""
    res: Dict[str, Any] = {"ok": False, "method": None, "detail": ""}
    if not login_url or not username:
        return res

    r = client.get(login_url, allow_redirects=True)
    if r is not None and "html" in (r.headers.get("Content-Type") or "").lower():
        parser = _FormExtractor(r.url or login_url)
        try:
            parser.feed(r.text or "")
        except Exception:
            pass
        # Pick the form containing a password input, or first form
        target_form = None
        for f in parser.forms:
            if any(i["type"] == "password" or "pass" in i["name"].lower() for i in f["inputs"]):
                target_form = f
                break
        if target_form is None and parser.forms:
            target_form = parser.forms[0]
        if target_form:
            payload: Dict[str, str] = {}
            user_set = False
            pass_set = False
            for inp in target_form["inputs"]:
                nm = inp["name"]
                low = nm.lower()
                tp = inp["type"]
                if tp == "password" or any(k in low for k in ("pass", "pwd", "secret")):
                    payload[nm] = password
                    pass_set = True
                elif tp in ("email", "text") and (
                    not user_set or any(k in low for k in ("user", "email", "login", "name", "uname"))
                ):
                    if not user_set:
                        payload[nm] = username
                        user_set = True
                    else:
                        payload[nm] = inp["value"] or "1"
                elif tp == "hidden":
                    payload[nm] = inp["value"]
                elif tp not in ("submit", "button", "reset", "image"):
                    payload[nm] = inp["value"] or "1"
                elif tp == "submit" and nm:
                    payload[nm] = inp["value"] or "Login"

            if user_set and pass_set:
                cookies_before = dict(client.sess.cookies)
                if target_form["method"] == "GET":
                    lr = client.get(target_form["url"], params=payload, allow_redirects=True)
                else:
                    lr = client.request("POST", target_form["url"], data=payload, allow_redirects=True)
                cookies_after = dict(client.sess.cookies)
                new_cookies = [k for k in cookies_after if cookies_after[k] != cookies_before.get(k)]
                body_low = (lr.text or "").lower() if lr is not None else ""
                failed_hint = any(w in body_low for w in (
                    "invalid password", "invalid username", "login failed",
                    "incorrect password", "authentication failed", "bad credentials",
                ))
                if lr is not None and lr.status_code < 400 and not failed_hint:
                    res["ok"] = True
                    res["method"] = f"form-{target_form['method']}"
                    res["detail"] = (
                        f"Submitted form to {target_form['url']} (HTTP {lr.status_code}); "
                        f"session cookies: {list(cookies_after.keys())}"
                    )
                    if new_cookies:
                        res["new_cookies"] = new_cookies
                    return res

    # JSON API fallback (e.g. OWASP Juice Shop /rest/user/login, /api/auth/login)
    for body in (
        {"email": username, "password": password},
        {"username": username, "password": password},
    ):
        jr = client.request("POST", login_url, json=body, allow_redirects=True)
        if jr is not None and jr.status_code < 400:
            try:
                jdata = jr.json()
            except Exception:
                jdata = None
            tok = _extract_token(jdata) if jdata is not None else None
            if tok:
                client.sess.headers["Authorization"] = f"Bearer {tok}"
                res["ok"] = True
                res["method"] = "json-bearer"
                res["detail"] = f"Authenticated via JSON at {login_url}; captured Bearer token"
                return res
            if dict(client.sess.cookies):
                res["ok"] = True
                res["method"] = "json-cookie"
                res["detail"] = f"Authenticated via JSON at {login_url}; captured session cookie"
                return res

    res["detail"] = f"Auto-login attempt at {login_url} did not confirm new session/token"
    return res


OPENAPI_CANDIDATES = (
    "/openapi.json",
    "/swagger.json",
    "/v3/api-docs",
    "/v2/api-docs",
    "/api-docs",
    "/api/openapi.json",
    "/api/swagger.json",
    "/swagger/v1/swagger.json",
)


def _schema_fields(schema: Dict[str, Any], components: Dict[str, Any], depth: int = 0) -> List[str]:
    if not isinstance(schema, dict) or depth > 3:
        return []
    if "$ref" in schema:
        ref = str(schema["$ref"])
        parts = ref.lstrip("#/").split("/")
        cur: Any = components
        # handle #/components/schemas/Foo or #/definitions/Foo
        if len(parts) >= 2:
            sub = parts[-1]
            for container in (
                components.get("schemas", {}),
                components.get("definitions", {}),
                components,
            ):
                if isinstance(container, dict) and sub in container:
                    return _schema_fields(container[sub], components, depth + 1)
        return []
    props = schema.get("properties")
    if isinstance(props, dict):
        return [str(k) for k in props.keys()][:20]
    return []


def ingest_openapi(client, base_url: str, state, FindingCls,
                   openapi_url: Optional[str] = None) -> Dict[str, Any]:
    """Fetch and parse OpenAPI 3.x / Swagger 2.0 spec into WebVulnX state."""
    summary: Dict[str, Any] = {
        "found": False, "spec_url": None, "endpoints": 0, "params": 0, "forms": 0,
    }
    candidates = [openapi_url] if openapi_url else [
        urllib.parse.urljoin(base_url.rstrip("/") + "/", p.lstrip("/"))
        for p in OPENAPI_CANDIDATES
    ]

    spec = None
    spec_url = None
    for cand in candidates:
        if state.should_stop():
            break
        r = client.get(cand, cache=True)
        if r is None or r.status_code >= 400:
            continue
        try:
            data = r.json()
        except Exception:
            continue
        if isinstance(data, dict) and ("paths" in data) and ("openapi" in data or "swagger" in data):
            spec = data
            spec_url = cand
            break

    if spec is None:
        return summary

    summary["found"] = True
    summary["spec_url"] = spec_url
    state.add(FindingCls(
        vuln_type="OpenAPI / Swagger Schema Publicly Exposed",
        severity="Info",
        url=spec_url,
        parameter="schema",
        evidence=f"OpenAPI/Swagger JSON with {len(spec.get('paths') or {})} path(s)",
        detail="Public API schema reveals every route, HTTP verb, and expected parameter.",
        cvss_hint=2.5,
    ))

    base_path = spec.get("basePath") or ""
    if not base_path and isinstance(spec.get("servers"), list) and spec["servers"]:
        srv_url = str(spec["servers"][0].get("url") or "")
        if srv_url.startswith("/"):
            base_path = srv_url

    components = {
        "schemas": (spec.get("components") or {}).get("schemas") or {},
        "definitions": spec.get("definitions") or {},
    }

    paths = spec.get("paths") or {}
    for raw_path, methods in list(paths.items())[:60]:
        if state.should_stop() or not isinstance(methods, dict):
            break
        # Replace {id} / {userId} path templates with sample value 1
        concrete_path = re.sub(r"\{[^}]+\}", "1", str(raw_path))
        full_path = (base_path.rstrip("/") + "/" + concrete_path.lstrip("/")) if base_path else concrete_path
        full_url = urllib.parse.urljoin(base_url.rstrip("/") + "/", full_path.lstrip("/"))
        state.crawled_urls.add(full_url)
        summary["endpoints"] += 1

        path_level_params = methods.get("parameters") or []
        for verb, op in methods.items():
            v = str(verb).upper()
            if v not in ("GET", "POST", "PUT", "PATCH", "DELETE") or not isinstance(op, dict):
                continue
            op_params = list(path_level_params) + list(op.get("parameters") or [])
            query_names: List[str] = []
            body_names: List[str] = []
            for p in op_params:
                if not isinstance(p, dict):
                    continue
                pname = p.get("name")
                pin = (p.get("in") or "query").lower()
                if not pname:
                    continue
                if pin == "query":
                    query_names.append(str(pname))
                elif pin in ("formdata", "body"):
                    if pin == "body" and isinstance(p.get("schema"), dict):
                        body_names.extend(_schema_fields(p["schema"], components))
                    else:
                        body_names.append(str(pname))

            # OpenAPI v3 requestBody
            req_body = op.get("requestBody") or {}
            content = req_body.get("content") or {}
            for ct_key in ("application/json", "application/x-www-form-urlencoded", "multipart/form-data"):
                if ct_key in content and isinstance(content[ct_key], dict):
                    sch = content[ct_key].get("schema") or {}
                    body_names.extend(_schema_fields(sch, components))

            if query_names:
                state.params.setdefault(full_url, set()).update(query_names)
                summary["params"] += len(query_names)
            if body_names and v in ("POST", "PUT", "PATCH"):
                dedup_body = list(dict.fromkeys(body_names))[:15]
                state.forms.append({
                    "url": full_url,
                    "method": v,
                    "inputs": [{"name": n, "type": "text", "value": "test"} for n in dedup_body],
                })
                summary["forms"] += 1

    return summary
