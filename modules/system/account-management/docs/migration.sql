-- Created:  2026-04-19 by Virtuozzo
-- Updated:  2026-04-19 by Virtuozzo

-- Reference DDL for the Account Management source-of-truth schema.
-- This file is intentionally documentation-first: implementation migrations may
-- express the same logical schema through ModKit/SeaORM migration code.
-- Dialect: PostgreSQL reference DDL.
-- Retention policy overview:
--   conversion_requests: soft-deleted (`deleted_at` stamped) by the AM retention
--     job after `resolved_retention` (default 30d) elapses past the terminal
--     status transition; hard-deleted on AM's platform retention cadence.
--   tenants: soft-deleted via `tenants.deleted_at`; hard-deleted by the
--     background tenant-hard-delete job after the tenant retention window and
--     precondition checks (no non-deleted children, no RG ownership references).
--   tenant_closure: rows for a tenant are removed only on tenant hard-delete.
--     Provisioning tenants are never present (see comment on descendant_status).

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ── Tenants ──────────────────────────────────────────────────────────────────

CREATE TABLE tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    parent_id UUID NULL,
    name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 255),
    -- status domain is the FULL internal domain {0=provisioning, 1=active, 2=suspended, 3=deleted}.
    -- Code 0 (provisioning) is an AM-internal saga state that intentionally never appears in
    -- `tenant_closure.descendant_status` — closure rows are inserted in the provisioning→active
    -- transaction, so the closure contract exposes only the SDK-visible subset {1,2,3}
    -- (see ADR-0007 and the comment on tenant_closure.descendant_status below).
    -- Any reader that expects status=0 to be present in `tenant_closure` is querying the wrong
    -- table; use `tenants` for full-domain reads and `tenant_closure` for publication-contract reads.
    status SMALLINT NOT NULL CHECK (status IN (0, 1, 2, 3)),
    self_managed BOOLEAN NOT NULL DEFAULT FALSE,
    tenant_type_uuid UUID NOT NULL,
    depth INTEGER NOT NULL CHECK (depth >= 0),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE NULL,
    CONSTRAINT fk_tenants_parent
        FOREIGN KEY (parent_id)
        REFERENCES tenants(id)
        ON UPDATE CASCADE
        ON DELETE RESTRICT,
    CONSTRAINT ck_tenants_root_depth
        CHECK ((parent_id IS NULL AND depth = 0) OR (parent_id IS NOT NULL AND depth > 0))
);

CREATE UNIQUE INDEX ux_tenants_single_root
    ON tenants ((1))
    WHERE parent_id IS NULL;

CREATE INDEX idx_tenants_parent_status
    ON tenants (parent_id, status);

CREATE INDEX idx_tenants_status
    ON tenants (status);

CREATE INDEX idx_tenants_type
    ON tenants (tenant_type_uuid);

CREATE INDEX idx_tenants_deleted_at
    ON tenants (deleted_at)
    WHERE deleted_at IS NOT NULL;

COMMENT ON TABLE tenants
    IS 'Canonical tenant hierarchy owned by Account Management. Tenant Resolver consumes this as the source-of-truth contract.';
COMMENT ON COLUMN tenants.self_managed
    IS 'Binary v1 barrier contract. true = self-managed tenant that downstream resolver/authz layers treat as a visibility barrier.';
COMMENT ON COLUMN tenants.tenant_type_uuid
    IS 'Deterministic UUIDv5 derived from the public chained tenant_type GTS identifier using the GTS namespace constant; compact storage/index key for tenant type assignment.';
COMMENT ON COLUMN tenants.depth
    IS 'Denormalized hierarchy depth used for advisory threshold checks and leaf-first retention cleanup ordering.';
COMMENT ON COLUMN tenants.status
    IS 'Tenant lifecycle state, encoded as SMALLINT for MySQL/PostgreSQL parity. Mapping: 0=provisioning, 1=active, 2=suspended, 3=deleted. Int↔name translation is owned by the application layer; SQL authored outside the ORM MUST reference these codes, never string literals.';

-- ── Tenant closure ───────────────────────────────────────────────────────────

CREATE TABLE tenant_closure (
    ancestor_id UUID NOT NULL,
    descendant_id UUID NOT NULL,
    barrier SMALLINT NOT NULL DEFAULT 0,
    descendant_status SMALLINT NOT NULL CHECK (descendant_status IN (1, 2, 3)),
    CONSTRAINT pk_tenant_closure
        PRIMARY KEY (ancestor_id, descendant_id),
    CONSTRAINT fk_tenant_closure_ancestor
        FOREIGN KEY (ancestor_id)
        REFERENCES tenants(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,
    CONSTRAINT fk_tenant_closure_descendant
        FOREIGN KEY (descendant_id)
        REFERENCES tenants(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,
    CONSTRAINT ck_tenant_closure_self_row_barrier
        CHECK (ancestor_id <> descendant_id OR barrier = 0),
    CONSTRAINT ck_tenant_closure_barrier_nonnegative
        CHECK (barrier >= 0)
);

CREATE INDEX idx_tenant_closure_ancestor_barrier_status
    ON tenant_closure (ancestor_id, barrier, descendant_status);

CREATE INDEX idx_tenant_closure_descendant
    ON tenant_closure (descendant_id);

COMMENT ON TABLE tenant_closure
    IS 'AM-owned transitive ancestry table used by Tenant Resolver for barrier-aware hierarchy reads over source-of-truth storage.';
COMMENT ON COLUMN tenant_closure.barrier
    IS 'Bit-encoded barrier flags on path (ancestor, descendant] (ancestor excluded, descendant included). v1 uses bit 0 for self_managed; barrier = 0 means no respected barrier on the path, barrier != 0 means at least one is set. The column is SMALLINT (signed 2-byte int, -32768..32767 on both PostgreSQL and MySQL) and ck_tenant_closure_barrier_nonnegative enforces CHECK (barrier >= 0), so the usable non-negative domain is 0..32767. That yields 15 usable flag bits (bits 0..14); the sign bit (bit 15) is unavailable because a value with bit 15 set overflows the signed positive range and/or trips the CHECK. 15 flag bits remain ample for the multi-dimensional barrier types contemplated in TENANT_MODEL.md, and SMALLINT stays portable across PostgreSQL and MySQL without dialect-specific type mapping. Self-rows must remain 0.';
COMMENT ON COLUMN tenant_closure.descendant_status
    IS 'Denormalized SDK-visible lifecycle state for descendant_id. Domain is {1=active, 2=suspended, 3=deleted} — the internal provisioning state (tenants.status = 0) is excluded by construction: closure rows are inserted on the provisioning→active transition and removed on hard-delete, so tenant_closure never contains provisioning rows. This keeps the closure a clean publication contract for replication to business modules — consumers do not need provisioning-specific filtering.';

-- ── Tenant metadata ──────────────────────────────────────────────────────────

CREATE TABLE tenant_metadata (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    schema_uuid UUID NOT NULL,
    value JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_tenant_metadata_tenant
        FOREIGN KEY (tenant_id)
        REFERENCES tenants(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,
    CONSTRAINT uq_tenant_metadata_tenant_schema_uuid
        UNIQUE (tenant_id, schema_uuid)
);

CREATE INDEX idx_tenant_metadata_schema_uuid
    ON tenant_metadata (schema_uuid);

COMMENT ON TABLE tenant_metadata
    IS 'Extensible tenant-scoped metadata entries validated against GTS-registered schemas. Per-schema inheritance policy (ADR-0002 `cpt-cf-account-management-adr-metadata-inheritance`) is NOT enforced at the storage layer: each row stores only the value written directly on `tenant_id`. Inherited resolution is performed at READ time by the application-layer `MetadataService::resolve` (DESIGN §3.2 MetadataService), which walks the `parent_id` ancestor chain and stops at self-managed barriers for `inherit` schemas. Direct SQL readers that bypass `MetadataService` will therefore see only directly-written values — this is deliberate (ADR-0002: walk-up read resolution, no write amplification) and is the reason there is no CHECK/trigger/materialized inheritance on this table.';
COMMENT ON COLUMN tenant_metadata.schema_uuid
    IS 'Deterministic UUIDv5 derived from schema_id using the GTS namespace constant; primary storage and index key for metadata lookups.';
COMMENT ON COLUMN tenant_metadata.value
    IS 'Opaque JSON payload validated in AM against the registered schema identified by schema_id.';

-- ── Tenant IdP metadata ──────────────────────────────────────────────────────
--
-- AM-owned plugin-private per-tenant state isolated from the public
-- `tenant_metadata` table. AM persists the opaque blob returned by
-- `IdpPluginClient::provision_tenant` (`ProvisionResult::metadata`) keyed
-- by `tenant_id` (PK — at most one row per tenant) and replays it on every
-- subsequent IdP call via `TenantContext::metadata` /
-- `DeprovisionTenantRequest::tenant_context`. AM does NOT validate,
-- namespace, or interpret the JSON — the plugin owns the shape entirely.
-- No `plugin_id` column today: AM resolves at most one `IdpPluginClient`
-- per deployment; a multi-plugin disambiguator can land later together
-- with a backfill migration.

CREATE TABLE tenant_idp_metadata (
    tenant_id UUID PRIMARY KEY,
    metadata JSONB NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_tenant_idp_metadata_tenant
        FOREIGN KEY (tenant_id)
        REFERENCES tenants(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE
);

COMMENT ON TABLE tenant_idp_metadata
    IS 'Plugin-private per-tenant state owned by the resolved `IdpPluginClient`. AM persists the opaque `ProvisionResult::metadata` blob at provisioning finalization and replays it to the plugin on every subsequent IdP call via `TenantContext::metadata` / `DeprovisionTenantRequest::tenant_context`. AM never inspects, namespaces, or validates the JSON — the plugin owns the shape end-to-end. Size is capped at the AM service boundary by `MAX_IDP_METADATA_BYTES`. Lifecycle-bound to the owning tenant via `ON DELETE CASCADE` (Postgres); the SQLite migration variant relies on an explicit `delete_many` from `TenantRepoImpl::hard_delete_one` because `modkit-db` does not enable `PRAGMA foreign_keys`.';
COMMENT ON COLUMN tenant_idp_metadata.metadata
    IS 'Opaque JSON blob shaped by the IdP plugin. `NULL` means the plugin returned no per-tenant state.';

-- ── Conversion requests ──────────────────────────────────────────────────────

CREATE TABLE conversion_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    target_mode TEXT NOT NULL CHECK (target_mode IN ('managed', 'self_managed')),
    initiator_side TEXT NOT NULL CHECK (initiator_side IN ('child', 'parent')),
    requested_by UUID NOT NULL,
    approved_by UUID NULL,
    cancelled_by UUID NULL,
    rejected_by UUID NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'cancelled', 'rejected', 'expired')),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE NULL,
    CONSTRAINT fk_conversion_requests_tenant
        FOREIGN KEY (tenant_id)
        REFERENCES tenants(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,
    CONSTRAINT ck_conversion_actor_columns
        CHECK (
            (status = 'pending'   AND approved_by IS NULL AND cancelled_by IS NULL AND rejected_by IS NULL) OR
            (status = 'approved'  AND approved_by IS NOT NULL AND cancelled_by IS NULL AND rejected_by IS NULL) OR
            (status = 'cancelled' AND approved_by IS NULL AND cancelled_by IS NOT NULL AND rejected_by IS NULL) OR
            (status = 'rejected'  AND approved_by IS NULL AND cancelled_by IS NULL AND rejected_by IS NOT NULL) OR
            (status = 'expired'   AND approved_by IS NULL AND cancelled_by IS NULL AND rejected_by IS NULL)
        )
);

CREATE UNIQUE INDEX ux_conversion_pending_per_tenant
    ON conversion_requests (tenant_id)
    WHERE status = 'pending' AND deleted_at IS NULL;

CREATE INDEX idx_conversion_tenant_status
    ON conversion_requests (tenant_id, status)
    WHERE deleted_at IS NULL;

CREATE INDEX idx_conversion_expires
    ON conversion_requests (expires_at)
    WHERE status = 'pending' AND deleted_at IS NULL;

CREATE INDEX idx_conversion_deleted_at
    ON conversion_requests (deleted_at)
    WHERE deleted_at IS NOT NULL;

COMMENT ON TABLE conversion_requests
    IS 'Durable dual-consent mode transition records. Approved requests atomically change tenant barrier state; resolved history is soft-deleted after the configured retention window.';
COMMENT ON COLUMN conversion_requests.requested_by
    IS 'Canonical platform subject UUID from SecurityContext. Raw provider user identifiers are not stored here.';
COMMENT ON COLUMN conversion_requests.deleted_at
    IS 'Soft-delete tombstone. Stamped by the AM retention job when `resolved_retention` (default 30d) elapses past the row reaching a terminal status (`approved`, `cancelled`, `rejected`, `expired`). Default API reads filter `deleted_at IS NULL`. Hard-delete occurs on AM''s platform retention cadence.';
