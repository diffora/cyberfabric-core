-- migration: 0003_add_retention_claim_column
-- module: cf-account-management
-- feature: tenant-hierarchy-management (Phase 5 — retention scan claiming)
-- owner: Account Management
-- reference: modules/system/account-management/docs/DESIGN.md §3.9
--
-- Adds the hard-delete scanner claim column. A retention scanner sets
-- `claimed_by` to a per-scan UUID while atomically claiming due rows; rows with
-- a non-NULL claim are excluded from subsequent scans.

ALTER TABLE tenants
    ADD COLUMN claimed_by UUID NULL;

CREATE INDEX idx_tenants_retention_claim
    ON tenants (claimed_by)
    WHERE claimed_by IS NOT NULL;
