# DARK Schema & Upgrade Migration Guide

## Schema Version History
Schema migrations are managed automatically at startup by `dark/db_migrations.py` (`apply_sqlite_migrations`):
- **v1**: Core enterprise baseline (`users`, `rbac_sessions`, `audit_logs`, `vault_secrets`, `assets`, `asset_relations`, `vuln_feed`, `remediation_tickets`, `plugins`, `scope_rules`, `schedules`, `workers`, `settings`).
- **v2**: Multi-tenant isolation (`tenants`, `tenant_id` columns on users/assets/tickets/audit/schedules/api_keys) and user account lockout columns (`failed_attempts`, `locked_until`).
- **v3**: Attack Surface Management metadata (`owner`, `tags_json`, `business_context`, `status` on `assets`), `asset_history`, `vuln_feed_history`, `finding_verifications`, `threat_iocs`, `threat_history`.
- **v4**: `api_keys`, `integrations`, `integration_deliveries`, `benchmark_runs`, `report_templates`, `job_queue_meta`.

## Password Hash Upgrade
Legacy PBKDF2-SHA256 user hashes continue to verify seamlessly and are automatically upgraded to **Argon2id** (`argon2-cffi`) upon next successful login.
