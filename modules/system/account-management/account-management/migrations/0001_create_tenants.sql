-- migration: 0001_create_tenants
-- module: cf-account-management
-- feature: tenant-hierarchy-management
-- owner: Account Management
-- reference: modules/system/account-management/docs/DESIGN.md §3.9
--
-- Creates the AM-owned `tenants` and `tenant_closure` tables with their
-- constraints and indexes. This migration is the authoritative DDL for
-- the tenant hierarchy (Phase 1 of the feature-tenant-hierarchy-management
-- plan). `tenant_resolver` reads these tables via a read-only DB role;
-- AM owns write access and maintains the closure transactionally in
-- `TenantService`.

-- ── Tenants ──────────────────────────────────────────────────────────────────

CREATE TABLE tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    parent_id UUID NULL,
    name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 255),
    -- status: 0=provisioning, 1=active, 2=suspended, 3=deleted (tenants full domain)
    status SMALLINT NOT NULL CHECK (status IN (0, 1, 2, 3)),
    self_managed BOOLEAN NOT NULL DEFAULT FALSE,
    tenant_type_uuid UUID NOT NULL,
    depth INTEGER NOT NULL CHECK (depth >= 0),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE NULL,
    CONSTRAINT fk_tenants_parent
        FOREIGN KEY (parent_id) REFERENCES tenants(id)
        ON UPDATE CASCADE ON DELETE RESTRICT,
    CONSTRAINT ck_tenants_root_depth
        CHECK ((parent_id IS NULL AND depth = 0) OR (parent_id IS NOT NULL AND depth > 0))
);

CREATE UNIQUE INDEX ux_tenants_single_root
    ON tenants ((1)) WHERE parent_id IS NULL;
CREATE INDEX idx_tenants_parent_status ON tenants (parent_id, status);
CREATE INDEX idx_tenants_status        ON tenants (status);
CREATE INDEX idx_tenants_type          ON tenants (tenant_type_uuid);
CREATE INDEX idx_tenants_deleted_at    ON tenants (deleted_at) WHERE deleted_at IS NOT NULL;

-- ── Tenant closure ───────────────────────────────────────────────────────────

CREATE TABLE tenant_closure (
    ancestor_id UUID NOT NULL,
    descendant_id UUID NOT NULL,
    barrier SMALLINT NOT NULL DEFAULT 0,
    -- descendant_status: SDK-visible subset only {1=active,2=suspended,3=deleted}
    descendant_status SMALLINT NOT NULL CHECK (descendant_status IN (1, 2, 3)),
    CONSTRAINT pk_tenant_closure PRIMARY KEY (ancestor_id, descendant_id),
    CONSTRAINT fk_tenant_closure_ancestor
        FOREIGN KEY (ancestor_id) REFERENCES tenants(id)
        ON UPDATE CASCADE ON DELETE CASCADE,
    CONSTRAINT fk_tenant_closure_descendant
        FOREIGN KEY (descendant_id) REFERENCES tenants(id)
        ON UPDATE CASCADE ON DELETE CASCADE,
    CONSTRAINT ck_tenant_closure_self_row_barrier
        CHECK (ancestor_id <> descendant_id OR barrier = 0),
    CONSTRAINT ck_tenant_closure_barrier_nonnegative
        CHECK (barrier >= 0)
);

CREATE INDEX idx_tenant_closure_ancestor_barrier_status
    ON tenant_closure (ancestor_id, barrier, descendant_status);
CREATE INDEX idx_tenant_closure_descendant
    ON tenant_closure (descendant_id);
