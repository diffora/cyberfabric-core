-- migration: 0005_running_audits
-- module: cf-account-management
-- feature: tenant-hierarchy-management (Phase 5 — single-flight gate for hierarchy-integrity audit)
-- owner: Account Management
-- reference: modules/system/account-management/docs/features/feature-tenant-hierarchy-management.md
--
-- Single-flight coordination row for the SQLite backend of
-- `audit_integrity_for_scope`. The Postgres backend uses
-- `pg_try_advisory_xact_lock(hashtext('am.integrity.' || scope))` at
-- runtime — no DDL needed there. SQLite has no advisory-lock primitive,
-- so the gate is a real row in this table held for the duration of an
-- in-flight audit transaction.
--
-- `scope_key` PRIMARY KEY enforces the per-scope mutual exclusion: an
-- `INSERT ... ON CONFLICT DO NOTHING` returns `rows_affected = 0` when
-- another worker already holds the slot. The row is removed by an
-- explicit `DELETE WHERE worker_id = ?` on the success path inside the
-- same transaction, or implicitly via transaction rollback on failure.
--
-- This file is the authoritative SQLite form. The matching Rust
-- migration in `src/infra/storage/migrations/m0005_running_audits.rs`
-- is the runtime mechanism actually executed against both backends.

CREATE TABLE running_audits (
    scope_key TEXT PRIMARY KEY,
    worker_id TEXT NOT NULL,
    started_at TIMESTAMP NOT NULL
);
