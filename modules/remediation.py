#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DARK Remediation Center — Vulnerability assignment, SLA due dates,
status tracking, operator notes, fix evidence, and verified retest closure.
"""
from __future__ import annotations

import hashlib
import json
import sys
import time
import uuid
from pathlib import Path
from typing import List, Optional

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT / "dark") not in sys.path:
    sys.path.insert(0, str(ROOT / "dark"))

import enterprise_db as edb  # noqa: E402

VALID_STATUSES = ("open", "in_progress", "fixed_pending_retest", "verified_closed", "accepted_risk")


def _fkey(f: dict) -> str:
    raw = f"{f.get('vuln_type','')}|{f.get('url','')}|{f.get('parameter','')}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _row_to_ticket(r) -> dict:
    d = dict(r)
    d["notes"] = json.loads(d.pop("notes_json") or "[]")
    d["evidence"] = json.loads(d.pop("evidence_json") or "[]")
    d["retest_history"] = json.loads(d.pop("retest_history_json") or "[]")
    return d


def create_or_sync_ticket(
    project_id: str,
    job_id: str,
    finding: dict,
    assignee: str = "",
    due_date: str = "",
) -> dict:
    fk = _fkey(finding)
    now = time.time()
    title = str(finding.get("vuln_type") or "Unnamed Finding")[:180]
    sev = str(finding.get("severity") or "Medium").title()
    tgt = str(finding.get("url") or "")[:300]

    with edb._DB_LOCK:
        c = edb._conn()
        try:
            existing = c.execute(
                "SELECT * FROM remediation_tickets WHERE project_id=? AND finding_key=?",
                (project_id or "default", fk),
            ).fetchone()
            if existing:
                return _row_to_ticket(existing)
            tid = "REM-" + uuid.uuid4().hex[:8].upper()
            c.execute(
                "INSERT INTO remediation_tickets(id, project_id, job_id, finding_key, title, severity, target, assignee, due_date, status, created_at, updated_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,'open',?,?)",
                (tid, project_id or "default", job_id or "", fk, title, sev, tgt, assignee, due_date, now, now),
            )
            c.commit()
            row = c.execute("SELECT * FROM remediation_tickets WHERE id=?", (tid,)).fetchone()
            return _row_to_ticket(row)
        finally:
            c.close()


def list_tickets(project_id: Optional[str] = None, status: Optional[str] = None) -> List[dict]:
    with edb._DB_LOCK:
        c = edb._conn()
        try:
            q = "SELECT * FROM remediation_tickets WHERE 1=1"
            args: list = []
            if project_id:
                q += " AND project_id=?"
                args.append(project_id)
            if status:
                q += " AND status=?"
                args.append(status)
            q += " ORDER BY updated_at DESC"
            return [_row_to_ticket(r) for r in c.execute(q, args).fetchall()]
        finally:
            c.close()


def update_ticket(
    ticket_id: str,
    status: Optional[str] = None,
    assignee: Optional[str] = None,
    due_date: Optional[str] = None,
    note: Optional[str] = None,
    fix_evidence: Optional[str] = None,
    actor: str = "operator",
) -> Optional[dict]:
    with edb._DB_LOCK:
        c = edb._conn()
        try:
            row = c.execute("SELECT * FROM remediation_tickets WHERE id=?", (ticket_id,)).fetchone()
            if not row:
                return None
            t = _row_to_ticket(row)
            now = time.time()
            if status and status in VALID_STATUSES:
                t["status"] = status
            if assignee is not None:
                t["assignee"] = assignee.strip()[:80]
            if due_date is not None:
                t["due_date"] = due_date.strip()[:40]
            if note and note.strip():
                t["notes"].append({"ts": now, "actor": actor, "text": note.strip()[:500]})
            if fix_evidence and fix_evidence.strip():
                t["evidence"].append({"ts": now, "actor": actor, "proof": fix_evidence.strip()[:500]})
            c.execute(
                "UPDATE remediation_tickets SET status=?, assignee=?, due_date=?, notes_json=?, evidence_json=?, updated_at=? WHERE id=?",
                (t["status"], t["assignee"], t["due_date"],
                 json.dumps(t["notes"]), json.dumps(t["evidence"]), now, ticket_id),
            )
            c.commit()
            return _row_to_ticket(c.execute("SELECT * FROM remediation_tickets WHERE id=?", (ticket_id,)).fetchone())
        finally:
            c.close()


def record_retest(ticket_id: str, still_vulnerable: bool, detail: str = "", actor: str = "retest-engine") -> Optional[dict]:
    with edb._DB_LOCK:
        c = edb._conn()
        try:
            row = c.execute("SELECT * FROM remediation_tickets WHERE id=?", (ticket_id,)).fetchone()
            if not row:
                return None
            t = _row_to_ticket(row)
            now = time.time()
            outcome = "failed_still_vulnerable" if still_vulnerable else "passed_verified_fixed"
            t["retest_history"].append({"ts": now, "actor": actor, "outcome": outcome, "detail": detail[:300]})
            new_status = "open" if still_vulnerable else "verified_closed"
            c.execute(
                "UPDATE remediation_tickets SET status=?, retest_history_json=?, updated_at=? WHERE id=?",
                (new_status, json.dumps(t["retest_history"]), now, ticket_id),
            )
            c.commit()
            return _row_to_ticket(c.execute("SELECT * FROM remediation_tickets WHERE id=?", (ticket_id,)).fetchone())
        finally:
            c.close()
