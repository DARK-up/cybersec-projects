#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Nuclei-style YAML Template Loader & Runner for WebVulnX / DARK.

Loads built-in safe templates from `webvulnx/templates/*.yaml` AND custom
operator templates from `dark/data/templates/*.yaml`. Evaluates HTTP requests
and status/word/regex matchers safely with cooperative stop_event support.
"""
from __future__ import annotations

import re
import urllib.parse
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

BUILTIN_DIR = Path(__file__).resolve().parent / "templates"
CUSTOM_DIR = Path(__file__).resolve().parent.parent / "dark" / "data" / "templates"


def _parse_yaml_templates(path: Path, source: str) -> List[Dict[str, Any]]:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return []
    docs = raw if isinstance(raw, list) else ([raw] if isinstance(raw, dict) else [])
    out: List[Dict[str, Any]] = []
    for doc in docs:
        if not isinstance(doc, dict) or not doc.get("id") or not doc.get("info"):
            continue
        doc["_source"] = source
        doc["_file"] = path.name
        out.append(doc)
    return out


def load_all_templates() -> List[Dict[str, Any]]:
    templates: List[Dict[str, Any]] = []
    if BUILTIN_DIR.is_dir():
        for p in sorted(BUILTIN_DIR.glob("*.yaml")):
            templates.extend(_parse_yaml_templates(p, "builtin"))
    if CUSTOM_DIR.is_dir():
        for p in sorted(CUSTOM_DIR.glob("*.yaml")):
            templates.extend(_parse_yaml_templates(p, "custom"))
    return templates


def save_custom_template(yaml_text: str) -> Dict[str, Any]:
    parsed = yaml.safe_load(yaml_text)
    docs = parsed if isinstance(parsed, list) else [parsed]
    if not docs or not isinstance(docs[0], dict) or not docs[0].get("id") or not docs[0].get("info"):
        raise ValueError("Template YAML must include 'id' and 'info' (and 'http' rules)")
    tid = re.sub(r"[^a-zA-Z0-9_-]", "-", str(docs[0]["id"])).strip("-")
    if not tid:
        raise ValueError("Invalid template id")
    CUSTOM_DIR.mkdir(parents=True, exist_ok=True)
    dest = CUSTOM_DIR / f"{tid}.yaml"
    dest.write_text(yaml_text, encoding="utf-8")
    return {"id": tid, "file": dest.name, "info": docs[0].get("info")}


def delete_custom_template(tid: str) -> bool:
    safe = re.sub(r"[^a-zA-Z0-9_-]", "-", tid).strip("-")
    p = CUSTOM_DIR / f"{safe}.yaml"
    if p.is_file():
        p.unlink()
        return True
    return False


def _match_rule(matcher: Dict[str, Any], resp) -> bool:
    mtype = (matcher.get("type") or "").lower()
    part = (matcher.get("part") or "body").lower()
    cond = (matcher.get("condition") or "or").lower()
    neg = bool(matcher.get("negative", False))

    hdr_str = "\n".join(f"{k}: {v}" for k, v in (resp.headers or {}).items())
    if part == "header":
        hay = hdr_str
    elif part == "all":
        hay = hdr_str + "\n\n" + (resp.text or "")
    else:
        hay = resp.text or ""

    matched = False
    if mtype == "status":
        statuses = [int(s) for s in (matcher.get("status") or [])]
        matched = resp.status_code in statuses
    elif mtype == "word":
        words = [str(w) for w in (matcher.get("words") or [])]
        hits = [(w in hay) for w in words]
        matched = all(hits) if cond == "and" else any(hits)
    elif mtype == "regex":
        regs = [str(r) for r in (matcher.get("regex") or [])]
        hits = [bool(re.search(r, hay)) for r in regs]
        matched = all(hits) if cond == "and" else any(hits)

    return (not matched) if neg else matched


def run_templates(client, base_url: str, state, FindingCls,
                  template_ids: Optional[List[str]] = None) -> int:
    templates = load_all_templates()
    if template_ids:
        want = set(template_ids)
        templates = [t for t in templates if t.get("id") in want]

    base = base_url.rstrip("/")
    hits = 0
    for tpl in templates:
        if state.should_stop():
            break
        info = tpl.get("info") or {}
        tid = tpl.get("id")
        name = info.get("name") or tid
        sev = str(info.get("severity") or "Info").capitalize()
        if sev not in ("Critical", "High", "Medium", "Low", "Info"):
            sev = "Info"
        cvss = float(info.get("cvss") or 0.0)
        desc = info.get("description") or ""
        remed = info.get("remediation") or ""

        for req_spec in (tpl.get("http") or []):
            if state.should_stop():
                break
            method = str(req_spec.get("method") or "GET").upper()
            paths = req_spec.get("path") or []
            if isinstance(paths, str):
                paths = [paths]
            headers = req_spec.get("headers") or {}
            body = req_spec.get("body")
            m_cond = (req_spec.get("matchers-condition") or "and").lower()
            matchers = req_spec.get("matchers") or []

            for p in paths:
                if state.should_stop():
                    break
                url = str(p).replace("{{BaseURL}}", base)
                if not url.startswith("http"):
                    url = urllib.parse.urljoin(base + "/", url.lstrip("/"))
                resp = client.request(
                    method, url,
                    headers=headers or None,
                    data=body if isinstance(body, str) else None,
                    allow_redirects=False,
                )
                if resp is None or not matchers:
                    continue
                results = [_match_rule(m, resp) for m in matchers]
                ok = all(results) if m_cond == "and" else any(results)
                if ok:
                    hits += 1
                    state.add(FindingCls(
                        vuln_type=f"[{tid}] {name}",
                        severity=sev,
                        url=url,
                        parameter=f"{method} template:{tid}",
                        payload=str(p).replace("{{BaseURL}}", ""),
                        evidence=f"HTTP {resp.status_code}, {len(resp.content)} bytes matched template '{tid}'",
                        detail=f"{desc}" + (f" Remediation: {remed}" if remed else ""),
                        cvss_hint=cvss,
                    ))
                    break
    return hits
