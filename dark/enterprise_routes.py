#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DARK Enterprise v3 REST Router — Assets, Vuln/Risk Intel, Cloud/Container/
SAST/API/Forensics scanners, Compliance, Remediation Center, Plugin Marketplace,
RBAC/2FA, Audit Trail, Vault, Scope Governance, Workers, Scheduler & Backup.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parent.parent
for _p in (str(ROOT / "dark"), str(ROOT / "modules")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import enterprise_db as edb  # noqa: E402
import engine  # noqa: E402
import asset_intel as ai  # noqa: E402
import vuln_intel as vi  # noqa: E402
import compliance as comp  # noqa: E402
import remediation as rem  # noqa: E402
import plugin_mgr as pm  # noqa: E402

router = APIRouter()

# References injected by dark/main.py at import time
_HOOKS: Dict[str, Any] = {}


def bind_hooks(start_job_fn, jobs_dict, jobs_lock, jobs_to_disk_fn, legal_text: str):
    _HOOKS["start_job"] = start_job_fn
    _HOOKS["JOBS"] = jobs_dict
    _HOOKS["JOBS_LOCK"] = jobs_lock
    _HOOKS["jobs_to_disk"] = jobs_to_disk_fn
    _HOOKS["LEGAL"] = legal_text


def _all_project_findings(project_id: Optional[str] = None) -> List[dict]:
    jobs = _HOOKS.get("JOBS") or {}
    lock = _HOOKS.get("JOBS_LOCK")
    items: List[dict] = []
    if lock:
        with lock:
            vals = list(jobs.values())
    else:
        vals = list(jobs.values())
    for j in vals:
        if project_id and (j.get("project_id") or "default") != project_id:
            continue
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


class AssetPatchReq(BaseModel):
    criticality: Optional[str] = None
    internet_exposed: Optional[bool] = None


class IntelSyncReq(BaseModel):
    fetch_cisa_kev: bool = True
    fetch_nvd_keyword: str = ""


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


class UserLoginReq(BaseModel):
    username: str
    password: str
    totp_code: str = ""


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
    edb.log_audit("operator", "analyst", "scan:cloud-audit", req.provider)
    return {"job_id": jid, "legal": _HOOKS.get("LEGAL", "")}


@router.post("/api/jobs/container-audit")
def job_container_audit(req: ContainerAuditReq):
    jid = _HOOKS["start_job"](
        "container-audit", engine.run_container_audit,
        project_id=req.project_id, target_hint=req.target_path or "container-audit",
        content=req.content, target_path=req.target_path, manifest_kind=req.kind,
    )
    edb.log_audit("operator", "analyst", "scan:container-audit", req.target_path or "inline")
    return {"job_id": jid, "legal": _HOOKS.get("LEGAL", "")}


@router.post("/api/jobs/sast-audit")
def job_sast_audit(req: SastReq):
    jid = _HOOKS["start_job"](
        "sast-audit", engine.run_sast_audit,
        project_id=req.project_id, target_hint=req.target_path or f"sast-{req.language}",
        code=req.code, target_path=req.target_path, language=req.language,
    )
    edb.log_audit("operator", "analyst", "scan:sast-audit", req.target_path or req.language)
    return {"job_id": jid, "legal": _HOOKS.get("LEGAL", "")}


@router.post("/api/jobs/api-audit")
def job_api_audit(req: ApiAuditReq):
    jid = _HOOKS["start_job"](
        "api-audit", engine.run_api_audit,
        project_id=req.project_id, target_hint=req.url,
        url=req.url, openapi_url=req.openapi_url, spec_json=req.spec_json,
        auth_header=req.auth_header, check_graphql=req.check_graphql,
    )
    edb.log_audit("operator", "analyst", "scan:api-audit", req.url)
    return {"job_id": jid, "legal": _HOOKS.get("LEGAL", "")}


@router.post("/api/jobs/forensics")
def job_forensics(req: ForensicsReq):
    jid = _HOOKS["start_job"](
        "forensics", engine.run_forensics_audit,
        project_id=req.project_id, target_hint=req.pcap_path or "forensics-logs",
        log_text=req.log_text, log_type=req.log_type,
        custom_iocs=req.custom_iocs, pcap_path=req.pcap_path,
    )
    edb.log_audit("operator", "analyst", "scan:forensics", req.log_type)
    return {"job_id": jid, "legal": _HOOKS.get("LEGAL", "")}


# ---------------------------------------------------------------------------
# Asset Intelligence
# ---------------------------------------------------------------------------
@router.get("/api/assets")
def get_assets(project_id: Optional[str] = None):
    return ai.list_assets(project_id=project_id)


@router.post("/api/assets")
def post_asset(req: AssetCreateReq):
    a = ai.upsert_asset(req.project_id, req.kind, req.name, req.criticality, req.internet_exposed)
    edb.log_audit("operator", "analyst", "asset:upsert", f"{req.kind}:{req.name}")
    return {"asset": a}


@router.patch("/api/assets/{asset_id}")
def patch_asset(asset_id: str, req: AssetPatchReq):
    if not ai.update_asset_meta(asset_id, req.criticality, req.internet_exposed):
        raise HTTPException(404, "Asset not found")
    return {"ok": True}


# ---------------------------------------------------------------------------
# Vulnerability Intelligence & Risk Prioritization
# ---------------------------------------------------------------------------
@router.get("/api/intel/feed")
def get_intel_feed(limit: int = 100, kev_only: bool = False):
    return {"cves": vi.list_vuln_feed(limit=limit, kev_only=kev_only)}


@router.post("/api/intel/sync")
def post_intel_sync(req: IntelSyncReq):
    res = vi.sync_live_feeds(fetch_cisa_kev=req.fetch_cisa_kev, fetch_nvd_keyword=req.fetch_nvd_keyword)
    edb.log_audit("operator", "analyst", "intel:sync", f"synced={res['synced']}")
    return res


@router.get("/api/intel/risk")
def get_risk_prioritization(project_id: Optional[str] = None):
    fs = _all_project_findings(project_id=project_id)
    return vi.prioritize_findings(fs, project_id=project_id or "default")


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
    edb.log_audit("operator", "analyst", "remediation:create", t["id"])
    return {"ticket": t}


@router.patch("/api/remediation/{ticket_id}")
def patch_remediation(ticket_id: str, req: RemPatchReq):
    t = rem.update_ticket(ticket_id, status=req.status, assignee=req.assignee,
                          due_date=req.due_date, note=req.note, fix_evidence=req.fix_evidence)
    if not t:
        raise HTTPException(404, "Ticket not found")
    edb.log_audit("operator", "analyst", "remediation:update", f"{ticket_id} -> {t['status']}")
    return {"ticket": t}


@router.post("/api/remediation/{ticket_id}/retest")
def post_remediation_retest(ticket_id: str, req: RemRetestReq):
    t = rem.record_retest(ticket_id, req.still_vulnerable, req.detail)
    if not t:
        raise HTTPException(404, "Ticket not found")
    edb.log_audit("operator", "analyst", "remediation:retest", f"{ticket_id} -> {t['status']}")
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
    edb.log_audit("operator", "admin", "plugin:register", res["plugin_id"])
    return res


@router.post("/api/plugins/{plugin_id}/toggle")
def toggle_plugin_route(plugin_id: str, enabled: bool = True):
    if not pm.toggle_plugin(plugin_id, enabled):
        raise HTTPException(404, "Plugin not found")
    edb.log_audit("operator", "admin", "plugin:toggle", f"{plugin_id}={enabled}")
    return {"ok": True, "plugin_id": plugin_id, "enabled": enabled}


@router.post("/api/plugins/{plugin_id}/test")
def test_plugin_route(plugin_id: str):
    try:
        return pm.run_plugin_tests(plugin_id)
    except ValueError as e:
        raise HTTPException(404, str(e))


# ---------------------------------------------------------------------------
# Administration: Users/RBAC, 2FA, Audit Trail, Vault, Scope, Workers, Scheduler, Backup
# ---------------------------------------------------------------------------
@router.get("/api/admin/users")
def admin_list_users():
    return {"users": edb.list_users(), "roles": edb.ROLES}


@router.post("/api/admin/users")
def admin_create_user(req: UserCreateReq):
    try:
        u = edb.create_user(req.username, req.password, req.role)
    except Exception as e:
        raise HTTPException(400, str(e))
    edb.log_audit("admin", "admin", "user:create", f"{u['username']} ({u['role']})")
    return {"user": u}


@router.post("/api/admin/users/login")
def admin_user_login(req: UserLoginReq, request: Request):
    ok, user, msg = edb.authenticate_user(req.username, req.password, req.totp_code)
    ip = request.client.host if request.client else ""
    edb.log_audit(req.username, (user or {}).get("role", "unknown"),
                  "user:login_ok" if ok else "user:login_fail", req.username, msg, ip)
    if not ok:
        raise HTTPException(401, msg)
    return {"ok": True, "user": user}


@router.post("/api/admin/users/{username}/2fa")
def admin_setup_2fa(username: str, enable: bool = True):
    res = edb.setup_user_totp(username, enable=enable)
    edb.log_audit("admin", "admin", "user:2fa", f"{username} enabled={enable}")
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
    edb.log_audit("admin", "admin", "vault:store", s["name"])
    return {"secret": s}


@router.delete("/api/admin/vault/{sid}")
def admin_vault_delete(sid: str):
    if not edb.delete_vault_secret(sid):
        raise HTTPException(404, "Secret not found")
    edb.log_audit("admin", "admin", "vault:delete", sid)
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
    edb.log_audit("admin", "admin", "scope:add", f"{r['rule_type']}:{r['pattern']}")
    return {"rule": r}


@router.delete("/api/admin/scope/{rule_id}")
def admin_scope_delete(rule_id: str):
    if not edb.delete_scope_rule(rule_id):
        raise HTTPException(404, "Rule not found")
    edb.log_audit("admin", "admin", "scope:delete", rule_id)
    return {"ok": True}


@router.post("/api/admin/scope/enforce")
def admin_scope_enforce(enforced: bool = True):
    edb.set_setting("scope_enforced", bool(enforced))
    edb.log_audit("admin", "admin", "scope:enforce", str(enforced))
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
    edb.log_audit("admin", "admin", "governance:emergency_stop", f"active={active}, stopped={len(stopped)}")
    return {"emergency_stop": active, "stopped_jobs": stopped}


@router.get("/api/admin/workers")
def admin_workers():
    jobs = _HOOKS.get("JOBS") or {}
    active = sum(1 for j in jobs.values() if j.get("status") in ("running", "waiting"))
    edb.upsert_worker("local-primary", "DARK Primary Controller", active_jobs=active)
    return {"workers": edb.list_workers()}


@router.get("/api/admin/schedules")
def admin_schedules_list():
    return {"schedules": edb.list_schedules()}


@router.post("/api/admin/schedules")
def admin_schedules_create(req: ScheduleReq):
    s = edb.create_schedule(req.project_id, req.name, req.kind, req.payload, req.interval_minutes)
    edb.log_audit("admin", "admin", "schedule:create", f"{s['name']} ({s['kind']})")
    return {"schedule": s}


@router.delete("/api/admin/schedules/{sid}")
def admin_schedules_delete(sid: str):
    if not edb.delete_schedule(sid):
        raise HTTPException(404, "Schedule not found")
    return {"ok": True}


@router.get("/api/admin/backup")
def admin_backup():
    edb.log_audit("admin", "admin", "backup:export", "full-db")
    return edb.export_backup()


@router.post("/api/admin/restore")
def admin_restore(payload: Dict[str, Any]):
    try:
        res = edb.restore_backup(payload)
    except ValueError as e:
        raise HTTPException(400, str(e))
    edb.log_audit("admin", "admin", "backup:restore", json.dumps(res.get("restored", {})))
    return res
