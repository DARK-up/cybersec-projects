#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Centralized YAML Payload Management System for WebVulnX (DARK v4.0).

Loads metadata-rich YAML payload catalogs from `webvulnx/payloads/catalog/*.yaml`
and enforces safe scoping:
  - `safe_scope: any`          -> safe non-exfiltrating probes allowed on all authorized targets
  - `safe_scope: demo_lab_only` -> restricted to local loopback / demo-lab / private lab targets
"""
from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

import yaml

CATALOG_DIR = Path(__file__).resolve().parent / "payloads" / "catalog"
_CACHE: Dict[str, List[Dict[str, Any]]] = {}


def is_local_or_lab_target(url: str) -> bool:
    """Return True if URL targets loopback / RFC1918 lab / explicit demo-lab."""
    try:
        host = (urlsplit((url or "").strip()).hostname or "").lower().rstrip(".")
    except Exception:
        return False
    if not host:
        return False
    if host in ("localhost", "localhost.localdomain", "demo-lab") or host.endswith(".local"):
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_loopback or ip.is_private
    except ValueError:
        return False


def load_category(category: str, force_reload: bool = False) -> List[Dict[str, Any]]:
    cat = (category or "").strip().lower()
    if not force_reload and cat in _CACHE:
        return list(_CACHE[cat])
    path = CATALOG_DIR / f"{cat}.yaml"
    if not path.is_file():
        return []
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    if not isinstance(raw, list):
        return []
    entries = [dict(item) for item in raw if isinstance(item, dict) and item.get("payload") is not None]
    _CACHE[cat] = entries
    return list(entries)


def get_payloads(
    category: str,
    target_url: str = "",
    safe_only: bool = True,
    engine: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Return filtered payloads for `category`, gating `demo_lab_only` payloads
    unless `safe_only=False` or `target_url` is a local lab."""
    items = load_category(category)
    local_lab = is_local_or_lab_target(target_url)
    out: List[Dict[str, Any]] = []
    for item in items:
        scope = str(item.get("safe_scope") or "any").lower()
        if safe_only and scope == "demo_lab_only" and not local_lab:
            continue
        if engine and str(item.get("engine") or "").lower() != engine.lower():
            continue
        out.append(item)
    return out


def catalog_summary() -> Dict[str, Any]:
    """Return counts and metadata breakdown across all YAML payload catalogs."""
    cats: Dict[str, int] = {}
    safe_count = 0
    lab_only_count = 0
    for p in sorted(CATALOG_DIR.glob("*.yaml")):
        cat = p.stem
        entries = load_category(cat)
        cats[cat] = len(entries)
        for e in entries:
            if str(e.get("safe_scope") or "any").lower() == "demo_lab_only":
                lab_only_count += 1
            else:
                safe_count += 1
    return {
        "catalog_dir": str(CATALOG_DIR),
        "categories": cats,
        "total": sum(cats.values()),
        "safe_any_target": safe_count,
        "demo_lab_only": lab_only_count,
    }
