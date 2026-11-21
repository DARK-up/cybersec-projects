#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DARK Enterprise REST Router — Assets & ASM Graph, Vuln/Risk Intel,
Verification Engine, Threat Intel (STIX 2.1), Cloud/Container/SAST/API/Forensics,
Compliance, Remediation Center, Plugin Marketplace, Integrations (Webhooks/SARIF/SIEM),
Benchmark QA Lab, Advanced Analytics, Multi-Tenant RBAC/2FA/API-Keys, Audit, Vault,
Scope Governance, Workers, Scheduler, Metrics & Backup.
"""
from __future__ import annotations

import csv
import io
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel

ROOT = Path(__file__).resolve().parent.parent
for _p in (str(ROOT / "dark"), str(ROOT / "modules")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import enterprise_db as edb  # noqa: E402
import engine  # noqa: E402
import asset_intel as ai  # noqa: E402
import vuln_intel as vi  # noqa: E402
import verification as vf  # noqa: E402
import threat_intel as ti  # noqa: E402
import integrations as integ  # noqa: E402
import benchmark_lab as blab  # noqa: E402
import reporting_analytics as rpt  # noqa: E402
import compliance as comp  # noqa: E402
import remediation as rem  # noqa: E402
import plugin_mgr as pm  # noqa: E402

router = APIRouter()

_HOOKS: Dict[str, Any] = {}


def bind_hooks(start_job_fn, jobs_dict, jobs_lock, jobs_to_disk_fn, legal_text: str, recover_fn=None):
    _HOOKS["start_job"] = start_job_fn
    _HOOKS["JOBS"] = jobs_dict
    _HOOKS["JOBS_LOCK"] = jobs_lock
    _HOOKS["jobs_to_disk"] = jobs_to_disk_fn
    _HOOKS["LEGAL"] = legal_text
    if recover_fn is not None:
        _HOOKS["recover_fn"] = recover_fn


def _all_jobs(project_id: Optional[str] = None, tenant_id: Optional[str] = None) -> List[dict]:
    jobs = _HOOKS.get("JOBS") or {}
    lock = _HOOKS.get("JOBS_LOCK")
    tid = tenant_id or edb.get_current_tenant()
    if lock:
        with lock:
            vals = [dict(j) for j in jobs.values()]
    else:
        vals = [dict(j) for j in jobs.values()]
    out = []
    for j in vals:
        jtid = j.get("tenant_id") or "default"
        if tid and tid != "default" and jtid != tid:
            continue
        if project_id and (j.get("project_id") or "default") != project_id:
            continue
        out.append(j)
    return out


def _all_project_findings(project_id: Optional[str] = None) -> List[dict]:
    items: List[dict] = []
    for j in _all_jobs(project_id=project_id):
        if j.get("status") not in ("done", "stopped"):
            continue
        res = j.get("result") or {}
        for f in (res.get("findings") or (res.get("report") or {}).get("findings") or []):
            items.append(f)
    return items


# ---------------------------------------------------------------------------
# Request Models
# ---------------------------------------------------------------------------
class CloudAuditReq(BaseModel):
    provider: str = "aws"
    content: str = ""
    target_path: Optional[str] = None
    project_id: str = "default"


class ContainerAuditReq(BaseModel):
    content: str = ""
    target_path: Optional[str] = None
    kind: str = "auto"
    project_id: str = "default"


class SastReq(BaseModel):
    code: str = ""
    target_path: Optional[str] = None
    language: str = "auto"
    project_id: str = "default"


class ApiAuditReq(BaseModel):
    url: str
    openapi_url: Optional[str] = None
    spec_json: Optional[str] = None
    auth_header: Optional[str] = None
    check_graphql: bool = True
    project_id: str = "default"


class ForensicsReq(BaseModel):
    log_text: str = ""
    log_type: str = "auto"
    custom_iocs: List[str] = []
    pcap_path: Optional[str] = None
    project_id: str = "default"


class AssetCreateReq(BaseModel):
    project_id: str = "default"
    kind: str = "domain"
    name: str
    criticality: str = "medium"
    internet_exposed: bool = True
    owner: str = ""
    tags: List[str] = []
    business_context: str = ""


class AssetPatchReq(BaseModel):
    criticality: Optional[str] = None
    internet_exposed: Optional[bool] = None
    owner: Optional[str] = None
    tags: Optional[List[str]] = None
    business_context: Optional[str] = None
    status: Optional[str] = None


class AssetRelReq(BaseModel):
    src_id: str
    dst_id: str
    relation: str = "connects_to"


class IntelSyncReq(BaseModel):
    fetch_cisa_kev: bool = True
    fetch_nvd_keyword: str = ""


class RiskWeightsReq(BaseModel):
    severity: float = 0.28
    confidence: float = 0.16
    exploitability: float = 0.24
    business_impact: float = 0.18
    exposure: float = 0.14


class VerifCreateReq(BaseModel):
    project_id: str = "default"
    job_id: str = ""
    finding: Dict[str, Any]
    status: Optional[str] = None
    note: str = ""
    manual_override: bool = False


class VerifRetestReq(BaseModel):
    allow_loopback: bool = True


class IocAddReq(BaseModel):
    value: str
    source: str = "manual-feed"
    ioc_type: Optional[str] = None
    confidence: float = 0.75
    severity: str = "Medium"
    context: str = ""
    ttl_days: int = 90


class IocMatchReq(BaseModel):
    observables: List[str]


class IntegrationCreateReq(BaseModel):
    kind: str
    name: str
    config: Dict[str, Any] = {}


class IntegrationDispatchReq(BaseModel):
    event_type: str = "finding.alert"
    payload: Dict[str, Any] = {}


class ReportTemplateReq(BaseModel):
    name: str
    sections: List[str]
    header_text: str = ""
    footer_text: str = ""


class RemCreateReq(BaseModel):
    project_id: str = "default"
    job_id: str = ""
    finding: Dict[str, Any]
    assignee: str = ""
    due_date: str = ""


class RemPatchReq(BaseModel):
    status: Optional[str] = None
    assignee: Optional[str] = None
    due_date: Optional[str] = None
    note: Optional[str] = None
    fix_evidence: Optional[str] = None


class RemRetestReq(BaseModel):
    still_vulnerable: bool = False
    detail: str = ""


class UserCreateReq(BaseModel):
    username: str
    password: str
    role: str = "analyst"
    tenant_id: str = "default"


class UserLoginReq(BaseModel):
    username: str
    password: str
    totp_code: str = ""


class TenantCreateReq(BaseModel):
    name: str
    plan: str = "enterprise"


class ApiKeyCreateReq(BaseModel):
    name: str
    role: str = "analyst"
    tenant_id: Optional[str] = None
    expires_days: int = 90


class VaultCreateReq(BaseModel):
    name: str
    kind: str = "api_token"
    secret_value: str


class ScopeRuleReq(BaseModel):
    pattern: str
    rule_type: str = "allow"
    note: str = ""


class ScheduleReq(BaseModel):
    project_id: str = "default"
    name: str
    kind: str = "web-scan"
    payload: Dict[str, Any]
    interval_minutes: int = 1440


# ---------------------------------------------------------------------------
# Phase 3 Scanners (Cloud, Container/SBOM, SAST, API Security, Forensics)
# ---------------------------------------------------------------------------
@router.post("/api/jobs/cloud-audit")
def job_cloud_audit(req: CloudAuditReq):
    jid = _HOOKS["start_job"](
        "cloud-audit", engine.run_cloud_audit,
        project_id=req.project_id, target_hint=req.target_path or f"{req.provider}-config",
        provider=req.provider, content=req.content, target_path=req.target_path,
    )
    edb.log_current_audit("scan:cloud-audit", req.provider)
    return {"job_id": jid, "legal": _HOOKS.get("LEGAL", "")}


@router.post("/api/jobs/container-audit")
def job_container_audit(req: ContainerAuditReq):
    jid = _HOOKS["start_job"](
        "container-audit", engine.run_container_audit,
        project_id=req.project_id, target_hint=req.target_path or "container-audit",
        content=req.content, target_path=req.target_path, manifest_kind=req.kind,
    )
    edb.log_current_audit("scan:container-audit", req.target_path or "inline")
    return {"job_id": jid, "legal": _HOOKS.get("LEGAL", "")}


@router.post("/api/jobs/sast-audit")
def job_sast_audit(req: SastReq):
    jid = _HOOKS["start_job"](
        "sast-audit", engine.run_sast_audit,
        project_id=req.project_id, target_hint=req.target_path or f"sast-{req.language}",
        code=req.code, target_path=req.target_path, language=req.language,
    )
    edb.log_current_audit("scan:sast-audit", req.target_path or req.language)
    return {"job_id": jid, "legal": _HOOKS.get("LEGAL", "")}


@router.post("/api/jobs/api-audit")
def job_api_audit(req: ApiAuditReq):
    jid = _HOOKS["start_job"](
        "api-audit", engine.run_api_audit,
        project_id=req.project_id, target_hint=req.url,
        url=req.url, openapi_url=req.openapi_url, spec_json=req.spec_json,
        auth_header=req.auth_header, check_graphql=req.check_graphql,
    )
    edb.log_current_audit("scan:api-audit", req.url)
    return {"job_id": jid, "legal": _HOOKS.get("LEGAL", "")}


@router.post("/api/jobs/forensics")
def job_forensics(req: ForensicsReq):
    jid = _HOOKS["start_job"](
        "forensics", engine.run_forensics_audit,
        project_id=req.project_id, target_hint=req.pcap_path or "forensics-logs",
        log_text=req.log_text, log_type=req.log_type,
        custom_iocs=req.custom_iocs, pcap_path=req.pcap_path,
    )
    edb.log_current_audit("scan:forensics", req.log_type)
    return {"job_id": jid, "legal": _HOOKS.get("LEGAL", "")}


# ---------------------------------------------------------------------------
# Advanced Attack Surface Management (Assets, Graph, Relations, History, Export)
# ---------------------------------------------------------------------------
@router.get("/api/assets")
def get_assets(
    project_id: Optional[str] = None,
    q: str = "",
    kind: Optional[str] = None,
    exposed: Optional[bool] = None,
    owner: Optional[str] = None,
    tag: Optional[str] = None,
    status: Optional[str] = None,
):
    return ai.list_assets(
        project_id=project_id, q=q, kind=kind,
        exposed=exposed, owner=owner, tag=tag, status=status,
    )


@router.get("/api/assets/graph")
def get_assets_graph(project_id: Optional[str] = None):
    return ai.build_attack_surface_graph(project_id=project_id)


@router.get("/api/assets/export.csv")
def export_assets_csv(project_id: Optional[str] = None):
    data = ai.list_assets(project_id=project_id)["assets"]
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["id", "tenant_id", "project_id", "kind", "name", "criticality",
                "internet_exposed", "owner", "tags", "business_context", "status", "risk_score"])
    for a in data:
        w.writerow([
            a["id"], a.get("tenant_id", "default"), a["project_id"], a["kind"], a["name"],
            a["criticality"], a["internet_exposed"], a.get("owner", ""),
            "|".join(a.get("tags") or []), a.get("business_context", ""),
            a.get("status", "active"), a.get("risk_score", 0.0),
        ])
    return Response(buf.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": 'attachment; filename="DARK-Assets.csv"'})


@router.post("/api/assets")
def post_asset(req: AssetCreateReq):
    a = ai.upsert_asset(
        req.project_id, req.kind, req.name, req.criticality, req.internet_exposed,
        owner=req.owner, tags=req.tags, business_context=req.business_context,
    )
    edb.log_current_audit("asset:upsert", f"{req.kind}:{req.name}")
    return {"asset": a}


@router.patch("/api/assets/{asset_id}")
def patch_asset(asset_id: str, req: AssetPatchReq):
    if not ai.update_asset_meta(
        asset_id, criticality=req.criticality, internet_exposed=req.internet_exposed,
        owner=req.owner, tags=req.tags, business_context=req.business_context, status=req.status,
    ):
        raise HTTPException(404, "Asset not found")
    edb.log_current_audit("asset:update", asset_id)
    return {"ok": True}


@router.post("/api/assets/relations")
def post_asset_relation(req: AssetRelReq):
    try:
        rel = ai.link_assets(req.src_id, req.dst_id, req.relation)
    except ValueError as e:
        raise HTTPException(400, str(e))
    edb.log_current_audit("asset:relation", f"{req.src_id} -[{req.relation}]-> {req.dst_id}")
    return {"relation": rel}


# ---------------------------------------------------------------------------
# Vulnerability Intelligence & Configurable 5-Axis Risk Prioritization
# ---------------------------------------------------------------------------
@router.get("/api/intel/feed")
def get_intel_feed(limit: int = 100, kev_only: bool = False):
    return {"cves": vi.list_vuln_feed(limit=limit, kev_only=kev_only)}


@router.get("/api/intel/history")
def get_intel_history(cve_id: Optional[str] = None, limit: int = 100):
    return {"history": vi.list_vuln_history(cve_id=cve_id, limit=limit)}


@router.post("/api/intel/sync")
def post_intel_sync(req: IntelSyncReq):
    res = vi.sync_live_feeds(fetch_cisa_kev=req.fetch_cisa_kev, fetch_nvd_keyword=req.fetch_nvd_keyword)
    edb.log_current_audit("intel:sync", f"synced={res['synced']}")
    return res


@router.get("/api/intel/risk")
def get_risk_prioritization(project_id: Optional[str] = None):
    fs = _all_project_findings(project_id=project_id)
    return vi.prioritize_findings(fs, project_id=project_id or "default")


@router.get("/api/intel/risk/weights")
def get_risk_weights():
    return {"weights": vi.get_risk_weights(), "formula": vi.formula_doc()}


@router.post("/api/intel/risk/weights")
def set_risk_weights(req: RiskWeightsReq):
    w = vi.set_risk_weights(req.model_dump())
    edb.log_current_audit("intel:weights", json.dumps(w))
    return {"weights": w, "formula": vi.formula_doc()}


# ---------------------------------------------------------------------------
# Vulnerability Verification Engine
# ---------------------------------------------------------------------------
@router.get("/api/verification")
def get_verifications(project_id: Optional[str] = None, status: Optional[str] = None):
    return vf.list_verifications(project_id=project_id, status=status)


@router.post("/api/verification")
def post_verification(req: VerifCreateReq):
    rec = vf.record_verification(
        req.project_id, req.job_id, req.finding,
        status=req.status, note=req.note, manual_override=req.manual_override,
    )
    edb.log_current_audit("verification:update", f"{rec['id']} -> {rec['status']}")
    return {"verification": rec}


@router.post("/api/verification/{verif_id}/retest")
def post_verification_retest(verif_id: str, req: VerifRetestReq = VerifRetestReq()):
    try:
        res = vf.retest_verification(verif_id, allow_loopback=req.allow_loopback)
    except ValueError as e:
        raise HTTPException(400, str(e))
    edb.log_current_audit("verification:retest", f"{verif_id} -> {res['verification']['status']}")
    return res


# ---------------------------------------------------------------------------
# Threat Intelligence Integration (IOCs & STIX 2.1)
# ---------------------------------------------------------------------------
@router.get("/api/threat-intel/iocs")
def get_threat_iocs(include_expired: bool = False):
    return ti.list_iocs(include_expired=include_expired)


@router.post("/api/threat-intel/iocs")
def post_threat_ioc(req: IocAddReq):
    try:
        ioc = ti.add_ioc(
            req.value, source=req.source, ioc_type=req.ioc_type,
            confidence=req.confidence, severity=req.severity,
            context=req.context, ttl_days=req.ttl_days,
        )
    except ValueError as e:
        raise HTTPException(400, str(e))
    edb.log_current_audit("threat_intel:add_ioc", ioc["value"])
    return {"ioc": ioc}


@router.post("/api/threat-intel/stix/import")
def post_stix_import(bundle: Dict[str, Any]):
    try:
        res = ti.import_stix_bundle(bundle)
    except ValueError as e:
        raise HTTPException(400, str(e))
    edb.log_current_audit("threat_intel:stix_import", f"imported={res['imported']}")
    return res


@router.get("/api/threat-intel/stix/export")
def get_stix_export():
    return ti.export_stix_bundle()


@router.post("/api/threat-intel/match")
def post_threat_match(req: IocMatchReq):
    return ti.match_observables(req.observables)


# ---------------------------------------------------------------------------
# Compliance Engine
# ---------------------------------------------------------------------------
@router.get("/api/compliance")
def get_compliance(project_id: Optional[str] = None, framework: Optional[str] = None):
    fs = _all_project_findings(project_id=project_id)
    return comp.evaluate_compliance(fs, framework=framework)


# ---------------------------------------------------------------------------
# Remediation Center
# ---------------------------------------------------------------------------
@router.get("/api/remediation")
def get_remediation(project_id: Optional[str] = None, status: Optional[str] = None):
    return {"tickets": rem.list_tickets(project_id=project_id, status=status)}


@router.post("/api/remediation")
def post_remediation(req: RemCreateReq):
    t = rem.create_or_sync_ticket(req.project_id, req.job_id, req.finding, req.assignee, req.due_date)
    edb.log_current_audit("remediation:create", t["id"])
    return {"ticket": t}


@router.patch("/api/remediation/{ticket_id}")
def patch_remediation(ticket_id: str, req: RemPatchReq):
    t = rem.update_ticket(ticket_id, status=req.status, assignee=req.assignee,
                          due_date=req.due_date, note=req.note, fix_evidence=req.fix_evidence)
    if not t:
        raise HTTPException(404, "Ticket not found")
    edb.log_current_audit("remediation:update", f"{ticket_id} -> {t['status']}")
    return {"ticket": t}


@router.post("/api/remediation/{ticket_id}/retest")
def post_remediation_retest(ticket_id: str, req: RemRetestReq):
    t = rem.record_retest(ticket_id, req.still_vulnerable, req.detail)
    if not t:
        raise HTTPException(404, "Ticket not found")
    edb.log_current_audit("remediation:retest", f"{ticket_id} -> {t['status']}")
    return {"ticket": t}


# ---------------------------------------------------------------------------
# Plugin Marketplace
# ---------------------------------------------------------------------------
@router.get("/api/plugins")
def get_plugins():
    return {"plugins": pm.list_plugins()}


@router.post("/api/plugins")
def post_plugin(manifest: Dict[str, Any]):
    try:
        res = pm.register_plugin(manifest)
    except ValueError as e:
        raise HTTPException(400, str(e))
    edb.log_current_audit("plugin:register", res["plugin_id"])
    return res


@router.post("/api/plugins/{plugin_id}/toggle")
def toggle_plugin_route(plugin_id: str, enabled: bool = True):
    if not pm.toggle_plugin(plugin_id, enabled):
        raise HTTPException(404, "Plugin not found")
    edb.log_current_audit("plugin:toggle", f"{plugin_id}={enabled}")
    return {"ok": True, "plugin_id": plugin_id, "enabled": enabled}


@router.post("/api/plugins/{plugin_id}/test")
def test_plugin_route(plugin_id: str):
    try:
        return pm.run_plugin_tests(plugin_id)
    except ValueError as e:
        raise HTTPException(404, str(e))


# ---------------------------------------------------------------------------
# Enterprise Integrations & SARIF v2.1.0
# ---------------------------------------------------------------------------
@router.get("/api/integrations")
def get_integrations():
    return integ.list_integrations()


@router.post("/api/integrations")
def post_integration(req: IntegrationCreateReq):
    try:
        rec = integ.register_integration(req.kind, req.name, req.config)
    except ValueError as e:
        raise HTTPException(400, str(e))
    edb.log_current_audit("integration:create", f"{rec['kind']}:{rec['name']}")
    return {"integration": rec}


@router.post("/api/integrations/{integration_id}/dispatch")
def post_integration_dispatch(integration_id: str, req: IntegrationDispatchReq):
    try:
        res = integ.dispatch_event(integration_id, req.event_type, req.payload)
    except ValueError as e:
        raise HTTPException(400, str(e))
    edb.log_current_audit("integration:dispatch", f"{integration_id} ({req.event_type})")
    return res


@router.get("/api/jobs/{job_id}/export.sarif")
def export_job_sarif(job_id: str):
    jobs = _HOOKS.get("JOBS") or {}
    lock = _HOOKS.get("JOBS_LOCK")
    with lock:
        j = jobs.get(job_id)
        if not j:
            raise HTTPException(404, "Job not found")
        snap = {k: v for k, v in j.items() if not k.startswith("_")}
    return integ.export_sarif(snap)


@router.get("/api/jobs/{job_id}/export.cyclonedx")
def export_job_cyclonedx(job_id: str):
    jobs = _HOOKS.get("JOBS") or {}
    lock = _HOOKS.get("JOBS_LOCK")
    with lock:
        j = jobs.get(job_id)
        if not j:
            raise HTTPException(404, "Job not found")
        snap = {k: v for k, v in j.items() if not k.startswith("_")}
    return integ.export_cyclonedx(snap)


@router.get("/api/jobs/{job_id}/report.pdf")
def export_job_pdf(job_id: str):
    jobs = _HOOKS.get("JOBS") or {}
    lock = _HOOKS.get("JOBS_LOCK")
    with lock:
        j = jobs.get(job_id)
        if not j:
            raise HTTPException(404, "Job not found")
        snap = {k: v for k, v in j.items() if not k.startswith("_")}
    res = snap.get("result") or {}
    role_now = edb.get_current_actor().get("role", "admin")
    raw_fs = res.get("findings") or (res.get("report") or {}).get("findings") or res.get("alerts") or []
    fs = [rpt.redact_finding_for_role(f, role_now) for f in raw_fs]
    pdf_bytes = rpt.render_pdf_bytes(f"Job {job_id} ({snap.get('target') or snap.get('kind')})", fs, res.get("stats"))
    return Response(
        pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="DARK-{job_id}.pdf"'},
    )


@router.get("/api/projects/{project_id}/report.pdf")
def export_project_pdf(project_id: str):
    role_now = edb.get_current_actor().get("role", "admin")
    jobs = [j for j in _all_jobs(project_id=project_id) if j.get("status") in ("done", "stopped")]
    fs: List[dict] = []
    seen = set()
    for j in jobs:
        res = j.get("result") or {}
        for f in (res.get("findings") or (res.get("report") or {}).get("findings") or []):
            fk = (str(f.get("vuln_type")), str(f.get("url")).rstrip("/"), str(f.get("parameter")))
            if fk in seen:
                continue
            seen.add(fk)
            fs.append(rpt.redact_finding_for_role(f, role_now))
    pdf_bytes = rpt.render_pdf_bytes(f"Project {project_id}", fs, {"modules_run": sorted({j.get("kind", "") for j in jobs})})
    return Response(
        pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="DARK-Project-{project_id}.pdf"'},
    )


@router.post("/api/integrations/sarif/import")
def import_sarif(sarif_doc: Dict[str, Any], project_id: str = "default"):
    try:
        findings = integ.parse_sarif_import(sarif_doc)
    except ValueError as e:
        raise HTTPException(400, str(e))
    for f in findings:
        vf.record_verification(project_id, "sarif-import", f)
    edb.log_current_audit("integration:sarif_import", f"count={len(findings)}")
    return {"imported": len(findings), "findings": findings}


# ---------------------------------------------------------------------------
# Benchmark & QA Lab + Executive Analytics + Metrics
# ---------------------------------------------------------------------------
@router.get("/api/benchmarks")
def get_benchmarks(limit: int = 20):
    return {"benchmarks": blab.list_benchmarks(limit=limit)}


@router.post("/api/benchmarks/run")
def run_benchmark_endpoint(lab_url: str = "http://127.0.0.1:8080"):
    res = blab.run_benchmark(lab_url=lab_url)
    edb.log_current_audit("benchmark:run", f"{res['id']} F1={res['f1_score']}")
    return {"benchmark": res}


@router.get("/api/analytics")
def get_analytics(project_id: Optional[str] = None):
    actor = edb.get_current_actor()
    jobs = _all_jobs(project_id=project_id, tenant_id=actor.get("tenant_id"))
    return rpt.build_executive_analytics(
        jobs, project_id=project_id,
        tenant_id=actor.get("tenant_id"), role=actor.get("role", "admin"),
    )


@router.get("/api/reports/templates")
def get_report_templates():
    return {"templates": rpt.list_report_templates()}


@router.post("/api/reports/templates")
def post_report_template(req: ReportTemplateReq):
    tpl = rpt.save_report_template(req.name, req.sections, req.header_text, req.footer_text)
    edb.log_current_audit("report:template", tpl["name"])
    return {"template": tpl}


@router.get("/api/metrics")
def get_metrics():
    jobs = _all_jobs()
    running = sum(1 for j in jobs if j.get("status") == "running")
    done = sum(1 for j in jobs if j.get("status") in ("done", "stopped"))
    cpu, ram = edb._sample_system_metrics()
    verif = vf.list_verifications()
    return {
        "jobs_total": len(jobs),
        "jobs_running": running,
        "jobs_completed": done,
        "cpu_pct": cpu,
        "ram_mb": ram,
        "false_positive_rate_pct": verif["false_positive_rate_pct"],
        "db_backend": edb.get_db_status(),
    }


# ---------------------------------------------------------------------------
# Administration: Multi-Tenant, Users/RBAC, 2FA, API Keys, Audit, Vault, Scope, Workers, Scheduler, Backup
# ---------------------------------------------------------------------------
@router.get("/api/admin/tenants")
def admin_list_tenants():
    return {"tenants": edb.list_tenants()}


@router.post("/api/admin/tenants")
def admin_create_tenant(req: TenantCreateReq):
    t = edb.create_tenant(req.name, req.plan)
    edb.log_current_audit("tenant:create", f"{t['id']}:{t['name']}")
    return {"tenant": t}


@router.get("/api/admin/api-keys")
def admin_list_api_keys(tenant_id: Optional[str] = None):
    return {"api_keys": edb.list_api_keys(tenant_id=tenant_id)}


@router.post("/api/admin/api-keys")
def admin_create_api_key(req: ApiKeyCreateReq):
    try:
        k = edb.create_api_key(req.name, req.role, tenant_id=req.tenant_id, expires_days=req.expires_days)
    except ValueError as e:
        raise HTTPException(400, str(e))
    edb.log_current_audit("api_key:create", f"{k['name']} ({k['role']})")
    return {"api_key": k}


@router.delete("/api/admin/api-keys/{key_id}")
def admin_revoke_api_key(key_id: str):
    if not edb.revoke_api_key(key_id):
        raise HTTPException(404, "API key not found")
    edb.log_current_audit("api_key:revoke", key_id)
    return {"ok": True}


@router.get("/api/admin/users")
def admin_list_users(tenant_id: Optional[str] = None):
    return {"users": edb.list_users(tenant_id=tenant_id), "roles": edb.ROLES}


@router.post("/api/admin/users")
def admin_create_user(req: UserCreateReq):
    try:
        u = edb.create_user(req.username, req.password, req.role, tenant_id=req.tenant_id)
    except Exception as e:
        raise HTTPException(400, str(e))
    edb.log_current_audit("user:create", f"{u['username']} ({u['role']}@{u['tenant_id']})")
    return {"user": u}


@router.post("/api/admin/users/login")
def admin_user_login(req: UserLoginReq, request: Request):
    ok, user, msg = edb.authenticate_user(req.username, req.password, req.totp_code)
    ip = request.client.host if request.client else ""
    edb.log_audit(
        req.username, (user or {}).get("role", "unknown"),
        "user:login_ok" if ok else "user:login_fail", req.username, msg, ip,
        tenant_id=(user or {}).get("tenant_id", "default"),
    )
    if not ok or not user:
        raise HTTPException(401, msg)
    tok = edb.create_rbac_session(user["username"], user["role"], tenant_id=user.get("tenant_id", "default"))
    csrf_tok = edb.secrets.token_urlsafe(24)
    resp = JSONResponse({"ok": True, "user": user, "token": tok, "csrf_token": csrf_tok})
    resp.set_cookie("dark_session", tok, httponly=True, samesite="lax", max_age=7 * 24 * 3600)
    resp.set_cookie("dark_csrf", csrf_tok, httponly=False, samesite="lax", max_age=7 * 24 * 3600)
    return resp


@router.post("/api/admin/users/{username}/revoke")
def admin_revoke_user_sessions(username: str):
    n = edb.revoke_user_sessions(username)
    edb.log_current_audit("user:revoke_sessions", f"{username} count={n}")
    return {"ok": True, "revoked": n}


@router.get("/api/admin/rbac")
def admin_rbac_status():
    return {"rbac_enforced": bool(edb.get_setting("rbac_enforced", False)), "roles": edb.ROLES}


@router.post("/api/admin/rbac/enforce")
def admin_rbac_enforce(enforced: bool = True):
    edb.set_setting("rbac_enforced", bool(enforced))
    edb.log_current_audit("rbac:enforce", str(enforced))
    return {"rbac_enforced": bool(enforced)}


@router.post("/api/admin/rate-limit")
def admin_set_rate_limit(max_requests_per_sec: int = 25, max_concurrent_jobs: int = 16):
    cfg = edb.set_rate_limit_config(max_requests_per_sec, max_concurrent_jobs)
    edb.log_current_audit("governance:rate_limit", json.dumps(cfg))
    return {"rate_limit": cfg}


@router.post("/api/admin/recovery/auto")
def admin_auto_recover():
    jobs = _HOOKS.get("JOBS") or {}
    lock = _HOOKS.get("JOBS_LOCK")
    recover_fn = _HOOKS.get("recover_fn")
    interrupted_ids: List[str] = []
    if lock:
        with lock:
            for jid, j in jobs.items():
                if j.get("status") == "interrupted" and j.get("repro_payload"):
                    interrupted_ids.append(jid)
    recovered: List[dict] = []
    if recover_fn:
        for jid in interrupted_ids[:10]:
            try:
                recovered.append(recover_fn(jid))
            except Exception:
                pass
    edb.log_current_audit("recovery:auto", f"recovered={len(recovered)}")
    return {"interrupted_found": len(interrupted_ids), "recovered": recovered}


@router.post("/api/admin/users/{username}/2fa")
def admin_setup_2fa(username: str, enable: bool = True):
    res = edb.setup_user_totp(username, enable=enable)
    edb.log_current_audit("user:2fa", f"{username} enabled={enable}")
    return res


@router.get("/api/admin/audit")
def admin_audit(limit: int = 100):
    return {"logs": edb.list_audit_logs(limit=limit)}


@router.get("/api/admin/audit/verify")
def admin_audit_verify():
    return edb.verify_audit_chain()


@router.get("/api/admin/vault")
def admin_vault_list():
    return {"secrets": edb.list_vault_secrets()}


@router.post("/api/admin/vault")
def admin_vault_store(req: VaultCreateReq):
    try:
        s = edb.store_vault_secret(req.name, req.kind, req.secret_value)
    except ValueError as e:
        raise HTTPException(400, str(e))
    edb.log_current_audit("vault:store", s["name"])
    return {"secret": s}


@router.delete("/api/admin/vault/{sid}")
def admin_vault_delete(sid: str):
    if not edb.delete_vault_secret(sid):
        raise HTTPException(404, "Secret not found")
    edb.log_current_audit("vault:delete", sid)
    return {"ok": True}


@router.get("/api/admin/scope")
def admin_scope_list():
    return {
        "enforced": bool(edb.get_setting("scope_enforced", False)),
        "rules": edb.list_scope_rules(),
        "rate_limit": edb.get_rate_limit_config(),
        "emergency_stop": edb.is_emergency_stopped(),
    }


@router.post("/api/admin/scope")
def admin_scope_add(req: ScopeRuleReq):
    try:
        r = edb.add_scope_rule(req.pattern, req.rule_type, req.note)
    except ValueError as e:
        raise HTTPException(400, str(e))
    edb.log_current_audit("scope:add", f"{r['rule_type']}:{r['pattern']}")
    return {"rule": r}


@router.delete("/api/admin/scope/{rule_id}")
def admin_scope_delete(rule_id: str):
    if not edb.delete_scope_rule(rule_id):
        raise HTTPException(404, "Rule not found")
    edb.log_current_audit("scope:delete", rule_id)
    return {"ok": True}


@router.post("/api/admin/scope/enforce")
def admin_scope_enforce(enforced: bool = True):
    edb.set_setting("scope_enforced", bool(enforced))
    edb.log_current_audit("scope:enforce", str(enforced))
    return {"enforced": bool(enforced)}


@router.post("/api/admin/emergency-stop")
def admin_emergency_stop(active: bool = True):
    edb.set_emergency_stop(active)
    stopped = []
    if active:
        jobs = _HOOKS.get("JOBS") or {}
        lock = _HOOKS.get("JOBS_LOCK")
        if lock:
            with lock:
                for jid, j in jobs.items():
                    if j.get("status") in ("running", "waiting"):
                        ev = j.get("_stop_event")
                        if ev is not None:
                            ev.set()
                        stopped.append(jid)
    edb.log_current_audit("governance:emergency_stop", f"active={active}, stopped={len(stopped)}")
    return {"emergency_stop": active, "stopped_jobs": stopped}


@router.get("/api/admin/workers")
def admin_workers():
    jobs = _HOOKS.get("JOBS") or {}
    active = sum(1 for j in jobs.values() if j.get("status") in ("running", "waiting"))
    edb.upsert_worker("local-primary", "DARK Primary Controller", active_jobs=active)
    return {"workers": edb.list_workers(), "db": edb.get_db_status()}


@router.get("/api/admin/schedules")
def admin_schedules_list():
    return {"schedules": edb.list_schedules()}


@router.post("/api/admin/schedules")
def admin_schedules_create(req: ScheduleReq):
    s = edb.create_schedule(req.project_id, req.name, req.kind, req.payload, req.interval_minutes)
    edb.log_current_audit("schedule:create", f"{s['name']} ({s['kind']})")
    return {"schedule": s}


@router.delete("/api/admin/schedules/{sid}")
def admin_schedules_delete(sid: str):
    if not edb.delete_schedule(sid):
        raise HTTPException(404, "Schedule not found")
    return {"ok": True}


@router.get("/api/admin/backup")
def admin_backup():
    edb.log_current_audit("backup:export", "full-db")
    return edb.export_backup()


@router.post("/api/admin/restore")
def admin_restore(payload: Dict[str, Any]):
    try:
        res = edb.restore_backup(payload)
    except ValueError as e:
        raise HTTPException(400, str(e))
    edb.log_current_audit("backup:restore", json.dumps(res.get("restored", {})))
    return res
