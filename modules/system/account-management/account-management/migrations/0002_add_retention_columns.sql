-- migration: 0002_add_retention_columns
-- module: cf-account-management
-- feature: tenant-hierarchy-management (Phase 3 — deletion pipeline)
-- owner: Account Management
-- reference: modules/system/account-management/docs/DESIGN.md §3.9
--
-- Adds the retention-scheduling columns used by the hard-delete pipeline
-- introduced in Phase 3 of the tenant-hierarchy-management plan. `deletion_scheduled_at`
-- is set at soft-delete time (`status = Deleted`); `retention_window_secs`
-- carries an optional per-tenant override of the module-default retention
-- window (`AccountManagementConfig.default_retention_secs`). Both columns
-- are nullable so Phase 1/2 rows continue to satisfy the schema without
-- backfill.
--
-- Two supporting indexes back the two background jobs:
--
--   * `idx_tenants_retention_scan`  — partial index on deleted + scheduled
--     rows, sorted leaf-first to match the hard-delete batch ordering
--     (depth DESC, id ASC).
--   * `idx_tenants_provisioning_stuck` — partial index on `status = 0`
--     rows for the provisioning reaper's `created_at + threshold <= now`
--     scan.

ALTER TABLE tenants
    ADD COLUMN deletion_scheduled_at TIMESTAMP WITH TIME ZONE NULL,
    ADD COLUMN retention_window_secs BIGINT NULL;

CREATE INDEX idx_tenants_retention_scan
    ON tenants (deletion_scheduled_at, depth DESC)
    WHERE status = 3 AND deletion_scheduled_at IS NOT NULL;

CREATE INDEX idx_tenants_provisioning_stuck
    ON tenants (created_at)
    WHERE status = 0;
