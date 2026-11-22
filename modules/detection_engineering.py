#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DARK Detection Engineering Framework (v4.0).

Allows analysts to create, version, import/export (including Sigma YAML),
test, and measure detection rules WITHOUT modifying core engine code:
  - Custom Detection Rules & Versioning (v1, v2, ...)
  - Sigma Rule YAML Import / Export
  - Unit Detection Testing against positive/negative events (TP/FP/TN/FN)
  - False Positive Tracking & Rule Performance Metrics (avg eval latency)
  - MITRE ATT&CK Mapping
"""
from __future__ import annotations

import json
import re
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT / "dark") not in sys.path:
    sys.path.insert(0, str(ROOT / "dark"))

import enterprise_db as edb  # noqa: E402

_RULES_KEY = "detection_engineering_rules"


def _load_rules() -> List[Dict[str, Any]]:
    rules = edb.get_setting(_RULES_KEY, None)
    if rules is None:
        rules = [
            {
                "id": "DR-001",
                "name": "Encoded PowerShell Execution",
                "version": 1,
                "severity": "Critical",
                "status": "stable",
                "mitre_tactic": "Execution",
                "mitre_technique": "T1059.001",
                "keywords": ["powershell", "-enc"],
                "regex": r"(?i)powershell(?:\.exe)?\s+.*(?:-enc|-encodedcommand)",
                "fp_count": 0,
                "tp_count": 0,
                "eval_count": 0,
                "avg_eval_ms": 0.0,
                "created_at": time.time(),
            },
            {
                "id": "DR-002",
                "name": "Security Audit Log Cleared (Event 1102 / wevtutil)",
                "version": 1,
                "severity": "Critical",
                "status": "stable",
                "mitre_tactic": "Defense Evasion",
                "mitre_technique": "T1070.001",
                "keywords": ["wevtutil", "EventID=1102"],
                "regex": r"(?i)(?:wevtutil\s+cl|EventID=1102)",
                "fp_count": 0,
                "tp_count": 0,
                "eval_count": 0,
                "avg_eval_ms": 0.0,
                "created_at": time.time(),
            },
        ]
        edb.set_setting(_RULES_KEY, rules)
    return rules


def _save_rules(rules: List[Dict[str, Any]]) -> None:
    edb.set_setting(_RULES_KEY, rules)


def list_rules() -> List[Dict[str, Any]]:
    out = []
    for r in _load_rules():
        item = dict(r)
        total = int(item.get("tp_count", 0)) + int(item.get("fp_count", 0))
        item["fp_rate"] = round(int(item.get("fp_count", 0)) / total, 4) if total else 0.0
        out.append(item)
    return out


def upsert_rule(rule_def: Dict[str, Any]) -> Dict[str, Any]:
    rules = _load_rules()
    rid = str(rule_def.get("id") or f"DR-{uuid.uuid4().hex[:6].upper()}")
    existing = next((r for r in rules if r["id"] == rid), None)
    now = time.time()
    if existing:
        existing["version"] = int(existing.get("version", 1)) + 1
        for k in ("name", "severity", "status", "mitre_tactic", "mitre_technique", "keywords", "regex"):
            if k in rule_def and rule_def[k] is not None:
                existing[k] = rule_def[k]
        existing["updated_at"] = now
        rec = existing
    else:
        rec = {
            "id": rid,
            "name": str(rule_def.get("name") or "Custom Detection Rule"),
            "version": 1,
            "severity": str(rule_def.get("severity") or "Medium"),
            "status": str(rule_def.get("status") or "experimental"),
            "mitre_tactic": str(rule_def.get("mitre_tactic") or "Execution"),
            "mitre_technique": str(rule_def.get("mitre_technique") or "T1059"),
            "keywords": list(rule_def.get("keywords") or []),
            "regex": str(rule_def.get("regex") or ""),
            "fp_count": 0,
            "tp_count": 0,
            "eval_count": 0,
            "avg_eval_ms": 0.0,
            "created_at": now,
        }
        rules.append(rec)
    _save_rules(rules)
    return rec


def import_sigma_yaml(sigma_yaml: str) -> Dict[str, Any]:
    """Parse a Sigma YAML rule and register it as a versioned DARK detection rule."""
    doc = yaml.safe_load(sigma_yaml) or {}
    if not isinstance(doc, dict) or not doc.get("title"):
        raise ValueError("Invalid Sigma YAML: missing 'title'")
    tags = [str(t) for t in (doc.get("tags") or [])]
    tech = next((t.replace("attack.", "").upper() for t in tags if re.match(r"attack\.t\d+", t, re.I)), "T1059")
    tactic = next((t.replace("attack.", "").replace("_", " ").title() for t in tags if t.startswith("attack.") and not re.match(r"attack\.t\d+", t, re.I)), "Execution")

    # Extract detection keywords recursively from Sigma 'detection' block
    keywords: List[str] = []
    det = doc.get("detection") or {}

    def _collect(obj: Any):
        if isinstance(obj, str):
            keywords.append(obj)
        elif isinstance(obj, list):
            for x in obj:
                _collect(x)
        elif isinstance(obj, dict):
            for k, v in obj.items():
                if k != "condition":
                    _collect(v)

    _collect(det)
    level_map = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "informational": "Info"}
    sev = level_map.get(str(doc.get("level") or "medium").lower(), "Medium")
    rid = str(doc.get("id") or f"SIGMA-{uuid.uuid4().hex[:6].upper()}")
    rx = "|".join(re.escape(k) for k in keywords[:12]) if keywords else ""
    return upsert_rule({
        "id": rid,
        "name": str(doc["title"]),
        "severity": sev,
        "status": str(doc.get("status") or "experimental"),
        "mitre_tactic": tactic,
        "mitre_technique": tech,
        "keywords": keywords[:20],
        "regex": f"(?i)(?:{rx})" if rx else "",
    })


def export_sigma_yaml(rule_id: str) -> str:
    r = next((x for x in _load_rules() if x["id"] == rule_id), None)
    if not r:
        raise ValueError("Rule not found")
    sigma = {
        "title": r["name"],
        "id": r["id"],
        "status": r.get("status", "experimental"),
        "level": r.get("severity", "medium").lower(),
        "tags": [
            f"attack.{r.get('mitre_tactic', 'execution').lower().replace(' ', '_')}",
            f"attack.{r.get('mitre_technique', 't1059').lower()}",
        ],
        "logsource": {"category": "process_creation"},
        "detection": {
            "selection": {"CommandLine|contains": r.get("keywords") or [r.get("regex", "")]},
            "condition": "selection",
        },
    }
    return yaml.safe_dump(sigma, sort_keys=False)


def _match_rule(rule: Dict[str, Any], text: str) -> bool:
    rx = rule.get("regex") or ""
    if rx:
        try:
            if re.search(rx, text):
                return True
        except re.error:
            pass
    kws = rule.get("keywords") or []
    if kws:
        low = text.lower()
        return any(str(k).lower() in low for k in kws)
    return False


def test_rule(rule_id: str, positive_samples: List[str], negative_samples: List[str]) -> Dict[str, Any]:
    """Evaluate a detection rule against positive & negative test events and track metrics."""
    rules = _load_rules()
    r = next((x for x in rules if x["id"] == rule_id), None)
    if not r:
        raise ValueError("Rule not found")

    t0 = time.perf_counter()
    tp = sum(1 for s in positive_samples if _match_rule(r, s))
    fn = len(positive_samples) - tp
    fp = sum(1 for s in negative_samples if _match_rule(r, s))
    tn = len(negative_samples) - fp
    elapsed_ms = (time.perf_counter() - t0) * 1000.0

    n_ev = max(len(positive_samples) + len(negative_samples), 1)
    r["tp_count"] = int(r.get("tp_count", 0)) + tp
    r["fp_count"] = int(r.get("fp_count", 0)) + fp
    r["eval_count"] = int(r.get("eval_count", 0)) + n_ev
    r["avg_eval_ms"] = round(elapsed_ms / n_ev, 4)
    _save_rules(rules)

    prec = round(tp / (tp + fp), 4) if (tp + fp) else 1.0
    rec = round(tp / (tp + fn), 4) if (tp + fn) else 1.0
    return {
        "rule_id": rule_id,
        "version": r["version"],
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": prec, "recall": rec,
        "avg_eval_ms": r["avg_eval_ms"],
    }


def record_false_positive(rule_id: str, is_fp: bool = True) -> Dict[str, Any]:
    rules = _load_rules()
    r = next((x for x in rules if x["id"] == rule_id), None)
    if not r:
        raise ValueError("Rule not found")
    if is_fp:
        r["fp_count"] = int(r.get("fp_count", 0)) + 1
    else:
        r["tp_count"] = int(r.get("tp_count", 0)) + 1
    _save_rules(rules)
    total = r["tp_count"] + r["fp_count"]
    return {"rule_id": rule_id, "tp_count": r["tp_count"], "fp_count": r["fp_count"],
            "fp_rate": round(r["fp_count"] / total, 4) if total else 0.0}
