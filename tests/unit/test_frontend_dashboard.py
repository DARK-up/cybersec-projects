#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Frontend validation for dark/dashboard.html and dark/api_studio.html:
  1. HTML Tag Balance & Structure Validation
  2. Tab Button -> Section Binding Validation
  3. Embedded JavaScript Syntax Check via `node --check`
  4. Frontend Handler Integrity (every static onclick function exists in JS)
"""
from __future__ import annotations

import re
import subprocess
import tempfile
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent


class _StrictHtmlChecker(HTMLParser):
    VOID = {"meta", "link", "input", "br", "hr", "img", "source", "area", "base", "col", "embed", "param", "track", "wbr"}

    def __init__(self):
        super().__init__()
        self.stack = []
        self.errors = []
        self.ids = set()
        self.dup_ids = []
        self.tab_buttons = []
        self.sections = set()
        self.onclick_fns = set()

    def handle_starttag(self, tag, attrs):
        t = tag.lower()
        amap = dict(attrs)
        if "id" in amap and amap["id"]:
            if amap["id"] in self.ids:
                self.dup_ids.append(amap["id"])
            self.ids.add(amap["id"])
        if t == "button" and amap.get("data-tab"):
            self.tab_buttons.append(amap["data-tab"])
        if t == "section" and amap.get("id", "").startswith("tab-"):
            self.sections.add(amap["id"][4:])
        if amap.get("onclick"):
            m = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(", amap["onclick"])
            if m:
                self.onclick_fns.add(m.group(1))
        if t not in self.VOID:
            self.stack.append((t, self.getpos()))

    def handle_endtag(self, tag):
        t = tag.lower()
        if t in self.VOID:
            return
        if not self.stack:
            self.errors.append(f"Unexpected </{t}> at {self.getpos()}")
            return
        if self.stack[-1][0] == t:
            self.stack.pop()
        elif any(x[0] == t for x in self.stack):
            while self.stack and self.stack[-1][0] != t:
                un = self.stack.pop()
                self.errors.append(f"Unclosed <{un[0]}> from {un[1]} before </{t}> at {self.getpos()}")
            if self.stack:
                self.stack.pop()
        else:
            self.errors.append(f"Stray </{t}> at {self.getpos()}")


def test_dashboard_html_structure_js_syntax_and_handlers():
    html = (ROOT / "dark" / "dashboard.html").read_text(encoding="utf-8")
    checker = _StrictHtmlChecker()
    checker.feed(html)
    assert checker.errors == [], f"HTML errors: {checker.errors}"
    assert checker.stack == [], f"Unclosed tags: {checker.stack}"
    assert checker.dup_ids == [], f"Duplicate DOM IDs: {checker.dup_ids}"
    for tab in checker.tab_buttons:
        assert tab in checker.sections, f"Missing <section id='tab-{tab}'>"

    scripts = re.findall(r"<script[^>]*>(.*?)</script>", html, re.S)
    js_blob = "\n".join(scripts)
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as tf:
        tf.write(js_blob)
        js_path = tf.name
    try:
        subprocess.check_call(["node", "--check", js_path])
    finally:
        Path(js_path).unlink(missing_ok=True)

    defined_fns = set(re.findall(r"(?:async\s+)?function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", js_blob))
    missing = sorted(fn for fn in checker.onclick_fns if fn not in defined_fns)
    assert missing == [], f"onclick handlers missing JS definitions: {missing}"


def test_api_studio_html_structure():
    html = (ROOT / "dark" / "api_studio.html").read_text(encoding="utf-8")
    checker = _StrictHtmlChecker()
    checker.feed(html)
    assert checker.errors == [], f"HTML errors: {checker.errors}"
    assert checker.stack == [], f"Unclosed tags: {checker.stack}"
