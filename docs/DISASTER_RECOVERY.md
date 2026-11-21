# DARK Disaster Recovery & Backup Runbook

## 1. Automated / On-Demand Database Backup
- **Export**: `GET /api/admin/backup` (requires `backup:manage` permission when RBAC is enforced).
- Exports `assets`, `asset_relations`, `vuln_feed`, `remediation_tickets`, `scope_rules`, `schedules`, and `settings` as versioned JSON (`schema_version: "3.0"`).
- Note: Encrypted vault secrets and hashed user credentials are backed up via encrypted filesystem snapshot of `dark/dark_enterprise.db` and `dark/.dark_master_key`.

## 2. Restore Procedure
1. Verify service health at `GET /api/health` and audit log integrity at `GET /api/admin/audit/verify`.
2. Restore JSON configuration and findings via `POST /api/admin/restore` (or the Administration tab Restore form).
3. Run `POST /api/admin/recovery/auto` to resume any scans that were marked `interrupted` during an unexpected outage.

## 3. Emergency Stop
- Trigger `POST /api/admin/emergency-stop?active=true` to immediately halt all active scans and block new launches until cleared.
