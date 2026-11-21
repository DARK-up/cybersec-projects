#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DARK Database Migration Manager & Multi-Engine Adapter (SQLite + PostgreSQL)."""
from __future__ import annotations

import os
import sqlite3
import time
from pathlib import Path
from typing import Callable, List, Tuple

APP_DIR = Path(__file__).resolve().parent
DATA_DIR = APP_DIR / "data"
DB_PATH = DATA_DIR / "dark_enterprise.db"

Migration = Tuple[int, str, List[str]]

MIGRATIONS: List[Migration] = [
    (
        1,
        "initial_enterprise_tables",
        [
            """CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                applied_at REAL NOT NULL
            )""",
            """CREATE TABLE IF NOT EXISTS tenants (
                id TEXT PRIMARY KEY,
                name TEXT UNIQUE NOT NULL,
                plan TEXT NOT NULL DEFAULT 'enterprise',
                active INTEGER NOT NULL DEFAULT 1,
                quota_jobs_per_day INTEGER NOT NULL DEFAULT 500,
                created_at REAL NOT NULL
            )""",
        ],
    ),
    (
        2,
        "multi_tenant_and_asm_history",
        [
            "ALTER TABLE users ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default'",
            "ALTER TABLE users ADD COLUMN failed_attempts INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE users ADD COLUMN locked_until REAL NOT NULL DEFAULT 0",
            "ALTER TABLE assets ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default'",
            "ALTER TABLE assets ADD COLUMN status TEXT NOT NULL DEFAULT 'active'",
            "ALTER TABLE assets ADD COLUMN owner TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE assets ADD COLUMN tags_json TEXT NOT NULL DEFAULT '[]'",
            "ALTER TABLE assets ADD COLUMN business_context TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE asset_relations ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default'",
            "ALTER TABLE remediation_tickets ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default'",
            "ALTER TABLE audit_logs ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default'",
            "ALTER TABLE scope_rules ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default'",
            """CREATE TABLE IF NOT EXISTS asset_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id TEXT NOT NULL DEFAULT 'default',
                project_id TEXT NOT NULL DEFAULT 'default',
                asset_id TEXT NOT NULL,
                asset_name TEXT NOT NULL,
                change_type TEXT NOT NULL,
                detail TEXT NOT NULL DEFAULT '',
                ts REAL NOT NULL
            )""",
        ],
    ),
    (
        3,
        "vuln_history_verification_threat_intel",
        [
            """CREATE TABLE IF NOT EXISTS vuln_feed_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT NOT NULL,
                cvss_v31 REAL NOT NULL,
                epss REAL NOT NULL,
                kev INTEGER NOT NULL,
                recorded_at REAL NOT NULL
            )""",
            """CREATE TABLE IF NOT EXISTS finding_verifications (
                id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL DEFAULT 'default',
                project_id TEXT NOT NULL DEFAULT 'default',
                job_id TEXT NOT NULL DEFAULT '',
                asset_name TEXT NOT NULL DEFAULT '',
                scanner TEXT NOT NULL DEFAULT '',
                plugin_id TEXT NOT NULL DEFAULT '',
                finding_key TEXT NOT NULL,
                vuln_type TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Unverified',
                confidence REAL NOT NULL DEFAULT 0.5,
                request_redacted TEXT NOT NULL DEFAULT '',
                response_redacted TEXT NOT NULL DEFAULT '',
                reproducibility_json TEXT NOT NULL DEFAULT '{}',
                verified_by TEXT NOT NULL DEFAULT 'system',
                notes TEXT NOT NULL DEFAULT '',
                updated_at REAL NOT NULL
            )""",
            """CREATE TABLE IF NOT EXISTS threat_iocs (
                id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL DEFAULT 'default',
                ioc_type TEXT NOT NULL,
                value TEXT NOT NULL,
                source TEXT NOT NULL,
                confidence REAL NOT NULL DEFAULT 0.6,
                severity TEXT NOT NULL DEFAULT 'Medium',
                context TEXT NOT NULL DEFAULT '',
                expires_at REAL NOT NULL DEFAULT 0,
                first_seen REAL NOT NULL,
                last_seen REAL NOT NULL,
                UNIQUE(tenant_id, ioc_type, value, source)
            )""",
            """CREATE TABLE IF NOT EXISTS threat_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id TEXT NOT NULL DEFAULT 'default',
                ioc_value TEXT NOT NULL,
                source TEXT NOT NULL,
                action TEXT NOT NULL,
                detail TEXT NOT NULL DEFAULT '',
                ts REAL NOT NULL
            )""",
        ],
    ),
    (
        4,
        "integrations_api_keys_benchmarks_jobs",
        [
            """CREATE TABLE IF NOT EXISTS api_keys (
                id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL DEFAULT 'default',
                name TEXT NOT NULL,
                key_prefix TEXT NOT NULL,
                key_hash TEXT UNIQUE NOT NULL,
                role TEXT NOT NULL DEFAULT 'analyst',
                active INTEGER NOT NULL DEFAULT 1,
                expires_at REAL NOT NULL DEFAULT 0,
                last_used REAL NOT NULL DEFAULT 0,
                created_at REAL NOT NULL
            )""",
            """CREATE TABLE IF NOT EXISTS integrations (
                id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL DEFAULT 'default',
                kind TEXT NOT NULL,
                name TEXT NOT NULL,
                config_enc_json TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                last_status TEXT NOT NULL DEFAULT 'configured',
                last_checked REAL NOT NULL DEFAULT 0,
                created_at REAL NOT NULL
            )""",
            """CREATE TABLE IF NOT EXISTS integration_deliveries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id TEXT NOT NULL DEFAULT 'default',
                integration_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                status TEXT NOT NULL,
                detail TEXT NOT NULL DEFAULT '',
                ts REAL NOT NULL
            )""",
            """CREATE TABLE IF NOT EXISTS benchmark_runs (
                id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                tp INTEGER NOT NULL,
                fp INTEGER NOT NULL,
                fn INTEGER NOT NULL,
                precision_score REAL NOT NULL,
                recall_score REAL NOT NULL,
                f1_score REAL NOT NULL,
                duration_s REAL NOT NULL,
                ram_mb REAL NOT NULL,
                cpu_pct REAL NOT NULL,
                details_json TEXT NOT NULL DEFAULT '{}',
                created_at REAL NOT NULL
            )""",
            """CREATE TABLE IF NOT EXISTS report_templates (
                id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL DEFAULT 'default',
                name TEXT NOT NULL,
                sections_json TEXT NOT NULL,
                header_text TEXT NOT NULL DEFAULT '',
                footer_text TEXT NOT NULL DEFAULT '',
                created_at REAL NOT NULL
            )""",
            """CREATE TABLE IF NOT EXISTS job_queue_meta (
                job_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL DEFAULT 'default',
                dedup_key TEXT NOT NULL DEFAULT '',
                priority INTEGER NOT NULL DEFAULT 5,
                retry_count INTEGER NOT NULL DEFAULT 0,
                max_retries INTEGER NOT NULL DEFAULT 1,
                worker_id TEXT NOT NULL DEFAULT 'local-primary',
                updated_at REAL NOT NULL
            )""",
        ],
    ),
    (
        5,
        "rbac_sessions_tenant_and_job_status",
        [
            "ALTER TABLE rbac_sessions ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default'",
            "ALTER TABLE job_queue_meta ADD COLUMN kind TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE job_queue_meta ADD COLUMN target TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE job_queue_meta ADD COLUMN status TEXT NOT NULL DEFAULT 'running'",
        ],
    ),
]


def get_backend_info() -> dict:
    pg_dsn = os.environ.get("DARK_POSTGRES_DSN", "").strip()
    pg_driver = False
    if pg_dsn:
        try:
            import psycopg  # type: ignore  # noqa: F401
            pg_driver = True
        except ImportError:
            pg_driver = False
    return {
        "active_engine": "postgresql" if (pg_dsn and pg_driver) else "sqlite",
        "sqlite_path": str(DB_PATH),
        "postgres_configured": bool(pg_dsn),
        "postgres_driver_available": pg_driver,
    }


def apply_sqlite_migrations(conn: sqlite3.Connection) -> List[int]:
    conn.execute(
        "CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at REAL NOT NULL)"
    )
    applied = {r[0] for r in conn.execute("SELECT version FROM schema_migrations").fetchall()}
    newly_applied: List[int] = []
    now = time.time()
    for ver, name, stmts in MIGRATIONS:
        if ver in applied:
            continue
        for sql in stmts:
            try:
                conn.execute(sql)
            except sqlite3.OperationalError as e:
                # Duplicate column on already-migrated DB is safe to ignore
                if "duplicate column name" not in str(e).lower():
                    raise
        conn.execute(
            "INSERT OR IGNORE INTO schema_migrations(version, name, applied_at) VALUES(?,?,?)",
            (ver, name, now),
        )
        newly_applied.append(ver)
    conn.execute(
        "INSERT OR IGNORE INTO tenants(id, name, plan, active, quota_jobs_per_day, created_at) "
        "VALUES('default', 'Default Organization', 'enterprise', 1, 1000, ?)",
        (now,),
    )
    conn.commit()
    return newly_applied


def list_applied_migrations(conn: sqlite3.Connection) -> List[dict]:
    rows = conn.execute("SELECT version, name, applied_at FROM schema_migrations ORDER BY version ASC").fetchall()
    return [{"version": r[0], "name": r[1], "applied_at": r[2]} for r in rows]
