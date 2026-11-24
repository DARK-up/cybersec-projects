#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DARK Database Migration Manager & Multi-Engine Adapter (SQLite + PostgreSQL)."""
from __future__ import annotations

import os
import re
import sqlite3
import time
from pathlib import Path
from typing import Any, List, Tuple

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
    (
        6,
        "session_activity_and_vault_key_rotation_tenants",
        [
            "ALTER TABLE rbac_sessions ADD COLUMN created_at REAL NOT NULL DEFAULT 0",
            "ALTER TABLE rbac_sessions ADD COLUMN last_activity REAL NOT NULL DEFAULT 0",
            "ALTER TABLE vault_secrets ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default'",
            "ALTER TABLE vault_secrets ADD COLUMN key_version INTEGER NOT NULL DEFAULT 1",
            "ALTER TABLE vault_secrets ADD COLUMN alg TEXT NOT NULL DEFAULT 'AES-256-GCM'",
            "ALTER TABLE vault_secrets ADD COLUMN updated_at REAL NOT NULL DEFAULT 0",
        ],
    ),
    (
        7,
        "vault_secrets_composite_tenant_unique",
        [
            """CREATE TABLE IF NOT EXISTS vault_secrets_v7 (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                kind TEXT NOT NULL,
                nonce_b64 TEXT NOT NULL,
                cipher_b64 TEXT NOT NULL,
                mac_b64 TEXT NOT NULL,
                created_by TEXT NOT NULL,
                created_at REAL NOT NULL,
                tenant_id TEXT NOT NULL DEFAULT 'default',
                key_version INTEGER NOT NULL DEFAULT 1,
                alg TEXT NOT NULL DEFAULT 'AES-256-GCM',
                updated_at REAL NOT NULL DEFAULT 0,
                UNIQUE(tenant_id, name)
            )""",
            """INSERT OR IGNORE INTO vault_secrets_v7(
                id, name, kind, nonce_b64, cipher_b64, mac_b64, created_by, created_at,
                tenant_id, key_version, alg, updated_at
            )
            SELECT id, name, kind, nonce_b64, cipher_b64, mac_b64, created_by, created_at,
                   COALESCE(NULLIF(tenant_id, ''), 'default'),
                   COALESCE(key_version, 1),
                   COALESCE(NULLIF(alg, ''), 'AES-256-GCM'),
                   COALESCE(updated_at, created_at)
            FROM vault_secrets""",
            "DROP TABLE vault_secrets",
            "ALTER TABLE vault_secrets_v7 RENAME TO vault_secrets",
        ],
    ),
    (
        8,
        "audit_logs_chain_version",
        [
            "ALTER TABLE audit_logs ADD COLUMN chain_version INTEGER NOT NULL DEFAULT 1",
        ],
    ),
]


def get_backend_info() -> dict:
    pg_dsn = os.environ.get("DARK_POSTGRES_DSN", "").strip()
    pg_driver = False
    pg_err = ""
    if pg_dsn:
        try:
            import psycopg  # type: ignore  # noqa: F401
            pg_driver = True
        except ImportError as e:
            pg_driver = False
            pg_err = f"psycopg driver missing: {e}"
    return {
        "active_engine": "postgresql" if pg_dsn else "sqlite",
        "sqlite_path": str(DB_PATH) if not pg_dsn else "",
        "postgres_configured": bool(pg_dsn),
        "postgres_driver_available": pg_driver,
        "postgres_error": pg_err,
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


def translate_sql_to_postgres(sql: str) -> str:
    """Translate SQLite SQL idioms (?, AUTOINCREMENT, INSERT OR IGNORE) to PostgreSQL."""
    out = re.sub(r"\bINTEGER\s+PRIMARY\s+KEY\s+AUTOINCREMENT\b", "SERIAL PRIMARY KEY", sql, flags=re.I)
    out = re.sub(r"\bREAL\b", "DOUBLE PRECISION", out)
    # Replace ? placeholders outside single-quoted literals
    parts = re.split(r"('(?:[^']|'')*')", out)
    for i in range(0, len(parts), 2):
        parts[i] = parts[i].replace("?", "%s")
    out = "".join(parts)
    if re.search(r"^\s*INSERT\s+OR\s+IGNORE\s+INTO\b", out, flags=re.I):
        out = re.sub(r"^\s*INSERT\s+OR\s+IGNORE\s+INTO\b", "INSERT INTO", out, flags=re.I)
        if "ON CONFLICT" not in out.upper():
            out = out.rstrip(" ;") + " ON CONFLICT DO NOTHING"
    return out


class PostgresCompatCursor:
    def __init__(self, pg_cur: Any):
        self._cur = pg_cur
        self.rowcount = 0

    def execute(self, sql: str, params: Tuple[Any, ...] = ()) -> "PostgresCompatCursor":
        self._cur.execute(translate_sql_to_postgres(sql), params)
        self.rowcount = getattr(self._cur, "rowcount", 0)
        return self

    def fetchone(self):
        return self._cur.fetchone()

    def fetchall(self):
        return self._cur.fetchall()


class PostgresCompatConnection:
    """Drop-in wrapper around psycopg connection matching sqlite3 usage in enterprise_db."""
    def __init__(self, pg_conn: Any):
        self._conn = pg_conn

    def execute(self, sql: str, params: Tuple[Any, ...] = ()) -> PostgresCompatCursor:
        cur = PostgresCompatCursor(self._conn.cursor())
        return cur.execute(sql, params)

    def executescript(self, script: str) -> None:
        for stmt in [s.strip() for s in script.split(";") if s.strip()]:
            self.execute(stmt)

    def commit(self) -> None:
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

