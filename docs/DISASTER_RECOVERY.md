# DARK Disaster Recovery & Backup Runbook (v4.0)

## 1. Authoritative Storage Paths
- **Primary SQLite Database (development / single-node):** `dark/data/dark_enterprise.db` (plus SQLite WAL files `-wal` / `-shm` when active).
- **PostgreSQL Database (distributed / production):** Configured via `DARK_POSTGRES_DSN` (`pg_dump` / `pg_restore`).
- **External Vault Keyring (NEVER stored inside DB):**
  - Environment mode: `DARK_VAULT_KEY` (+ optional `DARK_VAULT_KEY_V2..Vn`), **or**
  - Keyfile mode: `$DARK_VAULT_KEY_PATH` (default `~/.dark_keys/vault_keyring.json`, permissions `0600`).
- **External Audit Chain Checkpoint:** `~/.dark_keys/audit_checkpoint.json` (adjacent to keyring).
- **Redacted Job History State:** `dark/jobs_state.json` (permissions `0600`).

> **Important:** Backing up `dark/data/dark_enterprise.db` without backing up `vault_keyring.json` (or `DARK_VAULT_KEY`) makes encrypted `vault_secrets` unrecoverable. Always store DB snapshots and key backups in **separate** access-controlled locations.

## 2. Automated / On-Demand Export & Manifest
- **JSON Export:** `GET /api/admin/backup` (requires `backup:manage`).
- Exports `scope_rules`, `settings`, `assets`, `asset_relations`, `vuln_feed`, `remediation_tickets`, `schedules`, and `plugins`.
- **Full Physical Backup (SQLite + Vault + Audit Chain):**
  1. Stop writes or use `sqlite3 dark/data/dark_enterprise.db ".backup '/backup/dark_enterprise.db'"`.
  2. Separately archive `~/.dark_keys/vault_keyring.json` (`0600`) and `~/.dark_keys/audit_checkpoint.json`.

## 3. Clean-Environment Restore & Verification Procedure
1. Provision a clean target host/directory and restore `dark_enterprise.db` into `dark/data/dark_enterprise.db` (or `pg_restore` into `DARK_POSTGRES_DSN`).
2. Restore the external keyring to `$DARK_VAULT_KEY_PATH` (or export `DARK_VAULT_KEY`).
3. Start DARK and verify:
   - `GET /api/health` returns `"status": "online"` and expected `"db_engine"`.
   - `GET /api/admin/audit/verify` returns `{"valid": true}`.
   - Vault secret decryption succeeds (`reveal_vault_secret(...)` matches expected plaintext).
   - `POST /api/admin/recovery/auto` resumes any jobs marked `interrupted`.

## 4. Target Recovery Objectives (Measured in Local Restore Drill)
- **RPO (Recovery Point Objective):** `0` for committed DB/vault transactions (WAL / PostgreSQL synchronous commit); up to backup interval for physical snapshots.
- **RTO (Recovery Time Objective):** `< 60s` for full service restart; `2.15 ms` measured for SQLite DB + keyring clean encrypted restore verification in local drill (`tests/regression/test_review_26_closure.py`).

## 5. Emergency Stop
- Trigger `POST /api/admin/emergency-stop?active=true` to immediately halt all active scans and block new launches until cleared.
