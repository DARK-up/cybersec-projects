#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DARK Vulnerability Intelligence & Risk Prioritization Engine.

Capabilities:
  - Local + NVD/CISA KEV/EPSS-syncable CVE & CPE intelligence feed
  - CVSS v3.1 & v4.0 scoring, EPSS probability, CISA KEV flags
  - Separate 3-axis Finding scoring:
      1. severity       (Critical / High / Medium / Low / Info)
      2. confidence     (0.0 - 1.0 + Confirmed/High/Medium/Tentative)
      3. exploitability (0.0 - 1.0 + High/Moderate/Low based on safe evidence & KEV/EPSS)
  - Risk Intelligence Engine: asset criticality + internet exposure + KEV/EPSS + chained flaws
"""
from __future__ import annotations

import json
import re
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT / "dark") not in sys.path:
    sys.path.insert(0, str(ROOT / "dark"))

import enterprise_db as edb  # noqa: E402

SEED_CVES: List[dict] = [
    {"cve_id": "CVE-2021-44228", "cpe_prefix": "cpe:2.3:a:apache:log4j", "product": "log4j", "version_lt": "2.17.1",
     "severity": "Critical", "cvss_v31": 10.0, "cvss_v40": 10.0, "epss": 0.976, "kev": 1,
     "summary": "Apache Log4j2 JNDI remote code execution (Log4Shell).", "remediation": "Upgrade Log4j2 to >= 2.17.1."},
    {"cve_id": "CVE-2021-41773", "cpe_prefix": "cpe:2.3:a:apache:http_server", "product": "apache", "version_lt": "2.4.51",
     "severity": "Critical", "cvss_v31": 9.8, "cvss_v40": 9.3, "epss": 0.972, "kev": 1,
     "summary": "Apache HTTP Server 2.4.49 path traversal and file disclosure.", "remediation": "Upgrade Apache httpd to >= 2.4.51."},
    {"cve_id": "CVE-2024-6387", "cpe_prefix": "cpe:2.3:a:openbsd:openssh", "product": "openssh", "version_lt": "9.8",
     "severity": "High", "cvss_v31": 8.1, "cvss_v40": 8.1, "epss": 0.640, "kev": 0,
     "summary": "OpenSSH regreSSHion unauthenticated signal handler race condition.", "remediation": "Upgrade OpenSSH to >= 9.8p1."},
    {"cve_id": "CVE-2023-44487", "cpe_prefix": "cpe:2.3:a:nginx:nginx", "product": "nginx", "version_lt": "1.25.3",
     "severity": "High", "cvss_v31": 7.5, "cvss_v40": 8.2, "epss": 0.944, "kev": 1,
     "summary": "HTTP/2 Rapid Reset denial-of-service vulnerability.", "remediation": "Upgrade NGINX / apply HTTP/2 stream limits."},
    {"cve_id": "CVE-2022-22965", "cpe_prefix": "cpe:2.3:a:vmware:spring_framework", "product": "spring", "version_lt": "5.3.18",
     "severity": "Critical", "cvss_v31": 9.8, "cvss_v40": 9.5, "epss": 0.971, "kev": 1,
     "summary": "Spring4Shell class loader manipulation via data binding.", "remediation": "Upgrade Spring Framework to >= 5.3.18 / 5.2.20."},
    {"cve_id": "CVE-2023-38545", "cpe_prefix": "cpe:2.3:a:haxx:curl", "product": "curl", "version_lt": "8.4.0",
     "severity": "Critical", "cvss_v31": 9.8, "cvss_v40": 9.3, "epss": 0.780, "kev": 0,
     "summary": "libcurl SOCKS5 heap-based buffer overflow.", "remediation": "Upgrade curl/libcurl to >= 8.4.0."},
    {"cve_id": "CVE-2024-3094", "cpe_prefix": "cpe:2.3:a:tukaani:xz", "product": "xz-utils", "version_lt": "5.6.2",
     "severity": "Critical", "cvss_v31": 10.0, "cvss_v40": 10.0, "epss": 0.910, "kev": 1,
     "summary": "XZ Utils backdoor affecting versions 5.6.0 and 5.6.1.", "remediation": "Downgrade/upgrade xz-utils outside 5.6.0-5.6.1."},
    {"cve_id": "CVE-2023-22515", "cpe_prefix": "cpe:2.3:a:atlassian:confluence", "product": "confluence", "version_lt": "8.5.2",
     "severity": "Critical", "cvss_v31": 10.0, "cvss_v40": 10.0, "epss": 0.974, "kev": 1,
     "summary": "Broken access control allowing unauthorized admin creation.", "remediation": "Patch Confluence to >= 8.5.2."},
    {"cve_id": "CVE-2024-21626", "cpe_prefix": "cpe:2.3:a:linuxfoundation:runc", "product": "runc", "version_lt": "1.1.12",
     "severity": "High", "cvss_v31": 8.6, "cvss_v40": 8.6, "epss": 0.580, "kev": 1,
     "summary": "runc container breakout via leaked file descriptor.", "remediation": "Upgrade runc to >= 1.1.12."},
    {"cve_id": "CVE-2020-11022", "cpe_prefix": "cpe:2.3:a:jquery:jquery", "product": "jquery", "version_lt": "3.5.0",
     "severity": "Medium", "cvss_v31": 6.1, "cvss_v40": 6.3, "epss": 0.420, "kev": 0,
     "summary": "jQuery DOM XSS when passing untrusted HTML to htmlPrefilter.", "remediation": "Upgrade jQuery to >= 3.5.0."},
    {"cve_id": "CVE-2021-23337", "cpe_prefix": "cpe:2.3:a:lodash:lodash", "product": "lodash", "version_lt": "4.17.21",
     "severity": "High", "cvss_v31": 7.2, "cvss_v40": 7.5, "epss": 0.350, "kev": 0,
     "summary": "Lodash command injection via template function.", "remediation": "Upgrade lodash to >= 4.17.21."},
    {"cve_id": "CVE-2023-32681", "cpe_prefix": "cpe:2.3:a:python:requests", "product": "requests", "version_lt": "2.31.0",
     "severity": "Medium", "cvss_v31": 6.1, "cvss_v40": 5.9, "epss": 0.140, "kev": 0,
     "summary": "Proxy-Authorization header leak on cross-origin redirects.", "remediation": "Upgrade requests to >= 2.31.0."},
    {"cve_id": "CVE-2023-36665", "cpe_prefix": "cpe:2.3:a:pyyaml:pyyaml", "product": "pyyaml", "version_lt": "5.4",
     "severity": "Critical", "cvss_v31": 9.8, "cvss_v40": 9.3, "epss": 0.610, "kev": 0,
     "summary": "Arbitrary code execution via unsafe yaml.load().", "remediation": "Upgrade PyYAML >= 5.4 and use yaml.safe_load()."},
    {"cve_id": "CVE-2024-35195", "cpe_prefix": "cpe:2.3:a:urllib3:urllib3", "product": "urllib3", "version_lt": "2.2.2",
     "severity": "Medium", "cvss_v31": 5.6, "cvss_v40": 5.4, "epss": 0.080, "kev": 0,
     "summary": "TLS verification bypass on reused connection pools.", "remediation": "Upgrade urllib3 to >= 2.2.2."},
]


def ensure_seed_feed() -> int:
    now = time.time()
    with edb._DB_LOCK:
        c = edb._conn()
        try:
            cnt = c.execute("SELECT COUNT(*) AS n FROM vuln_feed").fetchone()["n"]
            if cnt == 0:
                for item in SEED_CVES:
                    c.execute(
                        "INSERT OR IGNORE INTO vuln_feed"
                        "(cve_id, cpe_prefix, product, version_lt, severity, cvss_v31, cvss_v40, epss, kev, summary, remediation, updated_at) "
                        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                        (item["cve_id"], item["cpe_prefix"], item["product"], item["version_lt"],
                         item["severity"], item["cvss_v31"], item["cvss_v40"], item["epss"],
                         item["kev"], item["summary"], item["remediation"], now),
                    )
                c.commit()
                return len(SEED_CVES)
            return cnt
        finally:
            c.close()


ensure_seed_feed()


def _ver_tuple(v: str) -> Tuple[int, ...]:
    nums = [int(x) for x in re.findall(r"\d+", str(v or ""))[:4]]
    return tuple(nums) if nums else (0,)


def match_product_cves(product: str, version: str = "") -> List[dict]:
    ensure_seed_feed()
    prod = (product or "").strip().lower()
    if not prod:
        return []
    with edb._DB_LOCK:
        c = edb._conn()
        try:
            rows = c.execute(
                "SELECT * FROM vuln_feed WHERE LOWER(product)=? OR LOWER(cpe_prefix) LIKE ?",
                (prod, f"%{prod}%"),
            ).fetchall()
        finally:
            c.close()
    matches: List[dict] = []
    vt = _ver_tuple(version) if version else None
    for r in rows:
        d = dict(r)
        d["kev"] = bool(d["kev"])
        if vt and d.get("version_lt"):
            if vt >= _ver_tuple(d["version_lt"]):
                continue
        matches.append(d)
    return matches


def list_vuln_feed(limit: int = 100, kev_only: bool = False) -> List[dict]:
    ensure_seed_feed()
    with edb._DB_LOCK:
        c = edb._conn()
        try:
            q = "SELECT * FROM vuln_feed"
            if kev_only:
                q += " WHERE kev=1"
            q += " ORDER BY kev DESC, cvss_v31 DESC LIMIT ?"
            rows = c.execute(q, (max(1, min(limit, 500)),)).fetchall()
            out = []
            for r in rows:
                d = dict(r)
                d["kev"] = bool(d["kev"])
                out.append(d)
            return out
        finally:
            c.close()


def sync_live_feeds(fetch_cisa_kev: bool = True, fetch_nvd_keyword: str = "") -> dict:
    """Sync CISA KEV and optional NVD CVE JSON 2.0 entries into vuln_feed (safe fallback offline)."""
    import requests
    ensure_seed_feed()
    added_or_updated = 0
    errors: List[str] = []
    now = time.time()

    if fetch_cisa_kev:
        try:
            r = requests.get(
                "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                timeout=8,
            )
            if r.status_code == 200:
                vulns = (r.json().get("vulnerabilities") or [])[:50]
                with edb._DB_LOCK:
                    c = edb._conn()
                    try:
                        for v in vulns:
                            cid = v.get("cveID") or ""
                            if not cid:
                                continue
                            prod = (v.get("product") or "").lower()[:60]
                            c.execute(
                                "INSERT INTO vuln_feed(cve_id, cpe_prefix, product, version_lt, severity, cvss_v31, cvss_v40, epss, kev, summary, remediation, updated_at) "
                                "VALUES(?,?,?,?,?,?,?,?,1,?,?,?) "
                                "ON CONFLICT(cve_id) DO UPDATE SET kev=1, updated_at=excluded.updated_at",
                                (cid, f"cpe:2.3:a:*:{prod}", prod, "", "High", 8.5, 8.5, 0.75,
                                 (v.get("shortDescription") or "")[:300],
                                 (v.get("requiredAction") or "")[:300], now),
                            )
                            added_or_updated += 1
                        c.commit()
                    finally:
                        c.close()
        except Exception as e:
            errors.append(f"CISA KEV sync offline/skipped: {type(e).__name__}")

    if fetch_nvd_keyword:
        try:
            r = requests.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={"keywordSearch": fetch_nvd_keyword, "resultsPerPage": 15},
                timeout=8,
            )
            if r.status_code == 200:
                with edb._DB_LOCK:
                    c = edb._conn()
                    try:
                        for item in (r.json().get("vulnerabilities") or []):
                            cve = item.get("cve") or {}
                            cid = cve.get("id") or ""
                            if not cid:
                                continue
                            metrics = cve.get("metrics") or {}
                            v31 = 7.5
                            sev = "High"
                            if metrics.get("cvssMetricV31"):
                                cd = metrics["cvssMetricV31"][0].get("cvssData") or {}
                                v31 = float(cd.get("baseScore") or 7.5)
                                sev = str(cd.get("baseSeverity") or "High").title()
                            descs = cve.get("descriptions") or []
                            summ = descs[0].get("value", "")[:300] if descs else ""
                            c.execute(
                                "INSERT INTO vuln_feed(cve_id, cpe_prefix, product, version_lt, severity, cvss_v31, cvss_v40, epss, kev, summary, remediation, updated_at) "
                                "VALUES(?,?,?,?,?,?,?,?,0,?,?,?) "
                                "ON CONFLICT(cve_id) DO UPDATE SET cvss_v31=excluded.cvss_v31, severity=excluded.severity, updated_at=excluded.updated_at",
                                (cid, "", fetch_nvd_keyword.lower(), "", sev, v31, v31, 0.2, summ, "Apply vendor security advisory patch.", now),
                            )
                            added_or_updated += 1
                        c.commit()
                    finally:
                        c.close()
        except Exception as e:
            errors.append(f"NVD sync offline/skipped: {type(e).__name__}")

    # Live FIRST.org EPSS probability sync for known CVEs in feed
    try:
        top_cves = [r["cve_id"] for r in list_vuln_feed(50) if str(r.get("cve_id", "")).startswith("CVE-")]
        if top_cves:
            er = requests.get(
                "https://api.first.org/data/v1/epss",
                params={"cve": ",".join(top_cves[:30])},
                timeout=6,
            )
            if er.status_code == 200:
                with edb._DB_LOCK:
                    c = edb._conn()
                    try:
                        for row in (er.json().get("data") or []):
                            cid = row.get("cve")
                            epss_val = float(row.get("epss") or 0.0)
                            if cid:
                                c.execute("UPDATE vuln_feed SET epss=?, updated_at=? WHERE cve_id=?", (round(epss_val, 4), now, cid))
                                added_or_updated += 1
                        c.commit()
                    finally:
                        c.close()
    except Exception as e:
        errors.append(f"EPSS sync offline/skipped: {type(e).__name__}")

    return {"synced": added_or_updated, "total_feed": len(list_vuln_feed(500)), "notes": errors}


# ---------------------------------------------------------------------------
# 3-Axis Scoring (Severity, Confidence, Exploitability) & Risk Intelligence
# ---------------------------------------------------------------------------
_SEV_BASE = {"Critical": 9.5, "High": 7.5, "Medium": 5.0, "Low": 2.5, "Info": 0.5}


def score_finding_axes(finding: dict, internet_exposed: bool = True, asset_criticality: str = "medium") -> dict:
    """Attach separate Severity, Confidence, Exploitability, CVE/KEV/EPSS, and composite Risk Score."""
    f = dict(finding)
    sev = str(f.get("severity") or "Info").title()
    if sev not in _SEV_BASE:
        sev = "Info"

    ev = str(f.get("evidence") or "")
    vt = str(f.get("vuln_type") or "").lower()
    param = str(f.get("parameter") or "")

    # 1. Confidence (how certain we are that the flaw really exists)
    conf = 0.72
    if "confirmed" in ev.lower() or "matched" in ev.lower() or "verified" in ev.lower():
        conf = 0.95
    elif param and f.get("payload"):
        conf = 0.88
    elif "header" in vt or "banner" in vt or "cookie" in vt or "tls" in vt:
        conf = 0.92
    elif "heuristic" in vt or "potential" in vt or "possible" in vt:
        conf = 0.55
    conf_label = "Confirmed" if conf >= 0.9 else ("High" if conf >= 0.75 else "Medium")

    # 2. Exploitability (safe defensive assessment of likelihood/reachability)
    cve_match = None
    for cid in re.findall(r"CVE-\d{4}-\d{4,7}", json.dumps(f)):
        with edb._DB_LOCK:
            c = edb._conn()
            try:
                row = c.execute("SELECT * FROM vuln_feed WHERE cve_id=?", (cid,)).fetchone()
                if row:
                    cve_match = dict(row)
                    break
            finally:
                c.close()

    expl = {"Critical": 0.88, "High": 0.72, "Medium": 0.45, "Low": 0.22, "Info": 0.05}[sev]
    if cve_match:
        expl = max(expl, min(0.99, float(cve_match.get("epss") or 0.3) + (0.2 if cve_match.get("kev") else 0.0)))
        f["cve_id"] = cve_match["cve_id"]
        f["cvss_v31"] = cve_match["cvss_v31"]
        f["cvss_v40"] = cve_match["cvss_v40"]
        f["epss"] = cve_match["epss"]
        f["kev"] = bool(cve_match["kev"])
    else:
        f.setdefault("cvss_v31", float(f.get("cvss_hint") or _SEV_BASE[sev]))
        f.setdefault("cvss_v40", float(f.get("cvss_hint") or _SEV_BASE[sev]))
        f.setdefault("epss", round(expl * 0.6, 3))
        f.setdefault("kev", False)

    if not internet_exposed:
        expl = round(expl * 0.75, 2)
    expl = round(min(0.99, max(0.05, expl)), 2)
    expl_label = "High" if expl >= 0.7 else ("Moderate" if expl >= 0.4 else "Low")

    # 3. Composite Risk Prioritization Score (0 - 100)
    crit_mult = {"critical": 1.2, "high": 1.1, "medium": 1.0, "low": 0.8}.get(asset_criticality, 1.0)
    exp_mult = 1.15 if internet_exposed else 0.85
    kev_bonus = 15.0 if f.get("kev") else 0.0
    raw_risk = (_SEV_BASE[sev] * 6.5 * crit_mult * exp_mult) + (expl * 18.0) + kev_bonus
    risk_score = round(min(100.0, max(1.0, raw_risk)), 1)

    f["severity"] = sev
    f["confidence"] = round(conf, 2)
    f["confidence_label"] = conf_label
    f["exploitability"] = expl
    f["exploitability_label"] = expl_label
    f["risk_score"] = risk_score
    return f


def prioritize_findings(findings: List[dict], project_id: str = "default") -> dict:
    """Group and rank findings by Risk Score, KEV status, and chained asset exposure."""
    scored: List[dict] = []
    by_target: Dict[str, List[dict]] = {}
    for f in findings:
        sf = score_finding_axes(f)
        tgt = str(sf.get("url") or "unknown").split("?")[0]
        by_target.setdefault(tgt, []).append(sf)
        scored.append(sf)

    # Chained-weakness boost: assets with >=3 distinct findings get +8 risk priority
    for sf in scored:
        tgt = str(sf.get("url") or "unknown").split("?")[0]
        if len(by_target.get(tgt, [])) >= 3:
            sf["chained_exposure"] = True
            sf["risk_score"] = round(min(100.0, sf["risk_score"] + 8.0), 1)
        else:
            sf["chained_exposure"] = False

    scored.sort(key=lambda x: (x.get("kev", False), x.get("risk_score", 0)), reverse=True)
    return {
        "total": len(scored),
        "kev_count": sum(1 for s in scored if s.get("kev")),
        "p0_immediate": [s for s in scored if s["risk_score"] >= 80][:25],
        "findings": scored,
    }
