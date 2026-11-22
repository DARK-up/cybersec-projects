#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Regression Tests for DARK v4.0 Zero-False-Positive & Self-SAST Guarantees."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
for p in (str(ROOT / "dark"), str(ROOT / "modules"), str(ROOT / "webvulnx")):
    if p not in sys.path:
        sys.path.insert(0, p)

import sast_audit as sa  # noqa: E402
import verification as vf  # noqa: E402


def test_dark_core_passes_self_sast_with_zero_findings():
    res = sa.scan_sast(target_path=str(ROOT / "dark"))
    assert len(res["findings"]) == 0, f"Unexpected SAST findings in dark/: {res['findings']}"


def test_marker_only_never_auto_confirmed_regression():
    rec = vf.record_verification(
        "default", "reg-v4",
        {"vuln_type": "Potential SQLi (Heuristic)", "severity": "Medium", "url": "https://ex.com", "evidence": "marker reflected"},
    )
    assert rec["status"] != "Confirmed"
