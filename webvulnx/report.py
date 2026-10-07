#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DARK / WebVulnX executive HTML report.

A self-contained, print-ready document (no external CSS/JS/fonts) designed
to look like a commercial DAST deliverable: cover, risk score, OWASP matrix,
finding cards with CWE/CVSS/impact/remediation, and a methodology appendix.
Open in a browser and Print → Save as PDF for a client-ready PDF.
"""
from __future__ import annotations

import html as htmlmod
import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from catalog import OWASP_TOP10, enrich

SEV_ORDER = ["Critical", "High", "Medium", "Low", "Info"]
SEV_COLOR = {
    "Critical": "#f43f5e", "High": "#f97316", "Medium": "#fbbf24",
    "Low": "#22d3ee", "Info": "#60a5fa",
}
SEV_WEIGHT = {"Critical": 25, "High": 12, "Medium": 5, "Low": 2, "Info": 0}


def _esc(s: Any) -> str:
    return htmlmod.escape("" if s is None else str(s), quote=True)


def _risk(findings: List[dict]) -> Dict[str, Any]:
    counts = {s: 0 for s in SEV_ORDER}
    for f in findings:
        s = f.get("severity") or "Info"
        if s not in counts:
            s = "Info"
        counts[s] += 1
    score = min(100, sum(counts[s] * SEV_WEIGHT[s] for s in SEV_ORDER))
    if counts["Critical"]:
        rating, band = "CRITICAL", "#f43f5e"
    elif score >= 50 or counts["High"]:
        rating, band = "HIGH", "#f97316"
    elif score >= 20 or counts["Medium"]:
        rating, band = "MEDIUM", "#fbbf24"
    elif score > 0:
        rating, band = "LOW", "#22d3ee"
    else:
        rating, band = "CLEAN", "#34d399"
    return {"score": score, "rating": rating, "color": band, "counts": counts}


def _donut(counts: Dict[str, int]) -> str:
    total = sum(counts.values()) or 1
    r, c, circ = 42, 50, 2 * 3.1416 * 42
    acc = 0.0
    arcs = []
    for sev in SEV_ORDER:
        n = counts.get(sev, 0)
        if not n:
            continue
        frac = n / total
        dash = circ * frac
        gap = circ - dash
        rot = -90 + acc * 360
        acc += frac
        arcs.append(
            f'<circle cx="{c}" cy="{c}" r="{r}" fill="none" '
            f'stroke="{SEV_COLOR[sev]}" stroke-width="12" '
            f'stroke-dasharray="{dash:.2f} {gap:.2f}" '
            f'transform="rotate({rot:.2f} {c} {c})"/>'
        )
    legend = "".join(
        f'<span class="lg"><i style="background:{SEV_COLOR[s]}"></i>'
        f'{s} {counts.get(s, 0)}</span>'
        for s in SEV_ORDER if counts.get(s)
    )
    return (
        f'<svg viewBox="0 0 100 100" width="140" height="140">{"".join(arcs)}</svg>'
        f'<div class="legend">{legend or "<span class=lg>No findings</span>"}</div>'
    )


def _bars(counts: Dict[str, int]) -> str:
    m = max(list(counts.values()) + [1])
    rows = []
    for s in SEV_ORDER:
        n = counts.get(s, 0)
        pct = int(100 * n / m) if m else 0
        rows.append(
            f'<div class="bar-row"><span class="bar-lab">{s}</span>'
            f'<span class="bar"><span style="width:{pct}%;background:{SEV_COLOR[s]}"></span></span>'
            f'<span class="bar-n">{n}</span></div>'
        )
    return "".join(rows)


def _exec_summary(target: str, risk: dict, stats: dict, findings: List[dict]) -> str:
    n = len(findings)
    act = sum(1 for f in findings if f.get("severity") not in ("Info", None))
    c, h = risk["counts"]["Critical"], risk["counts"]["High"]
    req = int(stats.get("requests_sent") or stats.get("requests") or 0)
    urls = int(stats.get("urls_crawled") or 0)
    mods = stats.get("modules_run") or []
    if risk["rating"] == "CLEAN":
        body = (
            f"DARK tested <b>{_esc(target)}</b> with {req:,} HTTP requests across "
            f"{len(mods)} module(s) and {urls} crawled URL(s). No confirmed, "
            f"exploitable vulnerability was identified on the tested surface. "
            f"This is a <b>tested-clean</b> result, not an absence of testing."
        )
    else:
        top = next((f for f in findings
                    if f.get("severity") in ("Critical", "High")), findings[0] if findings else {})
        body = (
            f"DARK assessed <b>{_esc(target)}</b> and confirmed <b>{n}</b> finding(s) "
            f"({act} actionable; {c} Critical, {h} High) after {req:,} requests "
            f"across {urls} URL(s). Overall risk rating: "
            f"<b style='color:{risk['color']}'>{risk['rating']}</b> "
            f"(score {risk['score']}/100). "
        )
        if top:
            body += (
                f"The highest-impact issue is <b>{_esc(top.get('vuln_type'))}</b>"
                + (f" on <code>{_esc(top.get('url'))}</code>." if top.get("url") else ".")
            )
    if stats.get("degraded"):
        body += (" <span class='warn'>The scan was DEGRADED by WAF / rate-limiting "
                 "— a clean-looking result in this state is not proof of security.</span>")
    return body


def _owasp_matrix(findings: List[dict]) -> str:
    types = " | ".join((f.get("vuln_type") or "") for f in findings)
    rows = []
    for name, needles in OWASP_TOP10:
        hits = [f for f in findings
                if any(n.lower() in (f.get("vuln_type") or "").lower() for n in needles)]
        tested = bool(needles)  # we have a module for this class
        if name.startswith("A09"):
            status, cls = "Not in scope", "na"
        elif hits:
            status, cls = f"{len(hits)} finding(s)", "hit"
        elif tested:
            status, cls = "Tested — none confirmed", "ok"
        else:
            status, cls = "Not in scope", "na"
        rows.append(
            f"<tr class='{cls}'><td>{_esc(name)}</td>"
            f"<td>{'Yes' if tested and not name.startswith('A09') else '—'}</td>"
            f"<td>{status}</td></tr>"
        )
    return (
        "<table class='matrix'><thead><tr><th>OWASP Top 10:2021</th>"
        "<th>Tested</th><th>Result</th></tr></thead><tbody>"
        + "".join(rows) + "</tbody></table>"
    )


def _finding_card(i: int, f: dict) -> str:
    sev = f.get("severity") or "Info"
    color = SEV_COLOR.get(sev, "#60a5fa")
    meta = enrich(f.get("vuln_type") or "", float(f.get("cvss_hint") or 0))
    cvss = f.get("cvss_hint") or meta.get("cvss") or 0
    fid = f"DARK-{i:03d}"
    refs = "".join(
        f'<li><a href="{_esc(u)}">{_esc(u)}</a></li>' for u in (meta.get("refs") or [])[:3]
    )
    payload = f.get("payload") or ""
    evidence = f.get("evidence") or ""
    detail = f.get("detail") or ""
    return f"""
<article class="card" id="{fid}">
  <header>
    <span class="fid">{fid}</span>
    <span class="sev" style="background:{color}">{_esc(sev)}</span>
    <h3>{_esc(f.get("vuln_type") or "Finding")}</h3>
  </header>
  <dl class="meta">
    <div><dt>CVSS</dt><dd>{cvss}</dd></div>
    <div><dt>CWE</dt><dd>{_esc(meta.get("cwe"))}</dd></div>
    <div><dt>OWASP</dt><dd>{_esc(meta.get("owasp"))}</dd></div>
    <div><dt>Parameter</dt><dd><code>{_esc(f.get("parameter") or "—")}</code></dd></div>
  </dl>
  <p class="url">URL <a href="{_esc(f.get('url') or '#')}">{_esc(f.get('url') or '—')}</a></p>
  <h4>Impact</h4>
  <p>{_esc(meta.get("impact"))}</p>
  {"<h4>What the scanner observed</h4><p>" + _esc(detail) + "</p>" if detail else ""}
  {"<h4>Evidence</h4><pre>" + _esc(evidence) + "</pre>" if evidence else ""}
  {"<h4>Payload</h4><pre>" + _esc(payload[:800]) + "</pre>" if payload else ""}
  <h4>Remediation</h4>
  <p>{_esc(meta.get("remediation"))}</p>
  {"<h4>References</h4><ul class='refs'>" + refs + "</ul>" if refs else ""}
</article>
"""


def _css() -> str:
    return """
:root{--bg:#070b10;--panel:#10161f;--ink:#e8f0f7;--muted:#8aa0b8;--line:#243044;--cyan:#22d3ee;--rose:#f43f5e}
*{box-sizing:border-box}
html,body{margin:0;padding:0;background:var(--bg);color:var(--ink);
  font-family:ui-sans-serif,system-ui,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;line-height:1.45}
.wrap{max-width:980px;margin:0 auto;padding:28px 24px 80px}
.cover{border:1px solid var(--line);border-radius:18px;padding:36px 40px;background:
  radial-gradient(1200px 400px at 10% -10%,rgba(34,211,238,.12),transparent),
  linear-gradient(180deg,#0e1622,var(--panel));margin-bottom:28px}
.brand{letter-spacing:8px;font-size:42px;font-weight:800;margin:0}
.brand span{color:var(--cyan)}
.tag{color:var(--muted);letter-spacing:2px;font-size:11px;margin-top:4px}
.conf{display:inline-block;margin-top:16px;border:1px solid var(--rose);color:#ffb4c0;
  padding:4px 12px;border-radius:999px;font-size:11px;letter-spacing:1px}
h1,h2,h3{margin:0 0 8px}
h2{color:var(--cyan);font-size:18px;letter-spacing:1px;margin-top:32px;
  border-bottom:1px solid var(--line);padding-bottom:8px}
.target{font-size:22px;margin:18px 0 4px;word-break:break-all}
.when{color:var(--muted);font-size:12px}
.scorebox{display:flex;gap:28px;align-items:center;flex-wrap:wrap;margin-top:22px}
.score{width:120px;height:120px;border-radius:50%;display:flex;flex-direction:column;
  align-items:center;justify-content:center;border:6px solid currentColor}
.score b{font-size:32px;line-height:1}
.score small{font-size:11px;letter-spacing:2px}
.kpis{display:flex;gap:10px;flex-wrap:wrap;margin-top:16px}
.kpi{background:#0b1018;border:1px solid var(--line);border-radius:10px;padding:10px 14px;min-width:110px}
.kpi b{display:block;font-size:18px;color:var(--cyan)}
.kpi span{font-size:11px;color:var(--muted)}
.summary{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:18px 22px;margin:18px 0}
.warn{color:#ffb27d}
.legend{display:flex;flex-direction:column;gap:4px;font-size:12px}
.lg{display:flex;align-items:center;gap:6px}
.lg i{width:10px;height:10px;border-radius:2px;display:inline-block}
.chart{display:flex;gap:24px;align-items:center;flex-wrap:wrap}
.bar-row{display:grid;grid-template-columns:90px 1fr 40px;gap:8px;align-items:center;margin:4px 0;font-size:12px}
.bar{background:#0b1018;border:1px solid var(--line);height:10px;border-radius:6px;overflow:hidden}
.bar span{display:block;height:100%}
table{width:100%;border-collapse:collapse;font-size:13px;margin:12px 0 24px}
th,td{border:1px solid var(--line);padding:8px 10px;text-align:left;vertical-align:top}
th{background:#0e1622;color:var(--cyan)}
.matrix tr.hit td:last-child{color:var(--rose);font-weight:700}
.matrix tr.ok td:last-child{color:#34d399}
.matrix tr.na td{color:var(--muted)}
.toc a{color:var(--cyan);text-decoration:none}
.card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:18px 20px;margin:16px 0;page-break-inside:avoid}
.card header{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:8px}
.card h3{font-size:16px;flex:1}
.fid{font-family:ui-monospace,Consolas,monospace;font-size:12px;color:var(--muted)}
.sev{color:#041018;font-weight:800;font-size:11px;padding:3px 10px;border-radius:999px;letter-spacing:1px}
.meta{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin:10px 0}
.meta dt{font-size:10px;color:var(--muted);letter-spacing:1px}
.meta dd{margin:0;font-weight:700}
.url{font-size:12px;word-break:break-all}
a{color:var(--cyan)}
pre{background:#0b1018;border:1px solid var(--line);border-radius:8px;padding:10px 12px;
  overflow:auto;font-size:12px;white-space:pre-wrap;word-break:break-all}
h4{margin:14px 0 4px;font-size:12px;letter-spacing:1px;color:var(--muted);text-transform:uppercase}
.refs{padding-left:18px;font-size:12px}
.foot{margin-top:40px;color:var(--muted);font-size:11px;border-top:1px solid var(--line);padding-top:14px}
@media print{
  body{background:#fff;color:#111}
  .cover,.card,.summary{break-inside:avoid;border-color:#ccc}
  a{color:#0645ad}
  .brand span{color:#0e7490}
}
"""


def render_html(payload: Dict[str, Any]) -> str:
    """Build the full HTML document from a job-result-like dict.

    Expected keys: target, stats, findings, diagnostics, coverage, log (optional).
    """
    target = payload.get("target") or payload.get("url") or "unknown"
    stats = payload.get("stats") or {}
    findings = list(payload.get("findings") or [])
    diagnostics = payload.get("diagnostics") or []
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    duration = stats.get("duration_s") or payload.get("duration_s") or ""
    risk = _risk(findings)
    findings_sorted = sorted(
        findings,
        key=lambda f: SEV_ORDER.index(f.get("severity") if f.get("severity") in SEV_ORDER else "Info"),
    )
    cards = "\n".join(_finding_card(i + 1, f) for i, f in enumerate(findings_sorted))
    toc = "".join(
        f"<li><a href='#DARK-{i+1:03d}'>DARK-{i+1:03d}</a> "
        f"<span class='sev' style='background:{SEV_COLOR.get(f.get('severity'),'#60a5fa')}'>"
        f"{_esc(f.get('severity'))}</span> {_esc(f.get('vuln_type'))}</li>"
        for i, f in enumerate(findings_sorted)
    ) or "<li>No confirmed findings.</li>"

    kpis = [
        ("URLs crawled", stats.get("urls_crawled", 0)),
        ("Forms", stats.get("forms", 0)),
        ("Parameters", stats.get("parameters", 0)),
        ("Requests", f"{int(stats.get('requests_sent') or 0):,}"),
        ("Modules", len(stats.get("modules_run") or [])),
        ("Findings", len(findings)),
    ]
    kpi_html = "".join(
        f"<div class='kpi'><b>{_esc(v)}</b><span>{_esc(k)}</span></div>" for k, v in kpis
    )
    diag = "".join(f"<li>{_esc(d)}</li>" for d in diagnostics)
    modules = ", ".join(str(m) for m in (stats.get("modules_run") or [])) or "—"
    seeds = ", ".join(str(s) for s in (stats.get("seed_urls") or [])[:12]) or "—"
    rid = hashlib.sha1(f"{target}{generated}".encode()).hexdigest()[:10].upper()

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DARK Assessment Report — {_esc(target)}</title>
<style>{_css()}</style>
</head>
<body>
<div class="wrap">

<section class="cover">
  <div class="brand">D<span>A</span>RK</div>
  <div class="tag">DETECTION &amp; ATTACK RECONNAISSANCE KIT — WEB APPLICATION ASSESSMENT</div>
  <div class="conf">CONFIDENTIAL — AUTHORIZED TESTING ONLY</div>
  <div class="target">{_esc(target)}</div>
  <div class="when">Report {rid} · generated {generated}"
       {f" · scan duration {duration}s" if duration else ""}</div>
  <div class="scorebox">
    <div class="score" style="color:{risk['color']}">
      <b>{risk['score']}</b><small>{risk['rating']}</small>
    </div>
    <div class="chart">{_donut(risk['counts'])}</div>
    <div style="flex:1;min-width:220px">{_bars(risk['counts'])}</div>
  </div>
  <div class="kpis">{kpi_html}</div>
</section>

<h2>1. Executive summary</h2>
<div class="summary">{_exec_summary(target, risk, stats, findings)}</div>

<h2>2. OWASP Top 10 coverage</h2>
<p style="color:var(--muted);font-size:13px">Every class DARK has a module for is marked
tested. “Tested — none confirmed” means the checks ran and did not meet the
proof threshold — not that the class is theoretically impossible.</p>
{_owasp_matrix(findings)}

<h2>3. Findings index</h2>
<ol class="toc">{toc}</ol>

<h2>4. Technical findings</h2>
{cards or "<p>No confirmed findings on the tested surface.</p>"}

<h2>5. Methodology &amp; coverage</h2>
<div class="summary">
  <p><b>Modules executed:</b> {_esc(modules)}</p>
  <p><b>Seed URLs:</b> {_esc(seeds)}</p>
  <p><b>HTTP requests:</b> {int(stats.get('requests_sent') or 0):,}
     · errors {stats.get('connection_errors') or 0}
     · blocked {stats.get('blocked_responses') or 0}
     · WAF pages {stats.get('waf_challenge_pages') or 0}</p>
  <p>DARK reports a finding only when a unique artefact proves it (SQL error
     signature, executable XSS context, file contents, schema document, etc.).
     Reflections that cannot execute, JSON/API bodies, and mere HTTP 200s on
     interesting paths are not raised as High/Critical.</p>
  {"<p><b>Diagnostics</b></p><ul>" + diag + "</ul>" if diag else ""}
</div>

<div class="foot">
  DARK — Detection &amp; Attack Reconnaissance Kit · Report {_esc(rid)} ·
  This document is intended for the system owner. Scanning systems without
  written authorisation is illegal. Print this page to produce a PDF.
</div>
</div>
</body>
</html>
"""


def write_html_report(path: str, payload: Dict[str, Any]) -> str:
    html = render_html(payload)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)
    return path
