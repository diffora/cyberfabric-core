-- migration: 0004_create_tenant_metadata
-- module: cf-account-management
-- feature: platform-bootstrap / tenant-metadata
-- owner: Account Management
-- reference: modules/system/account-management/docs/features/feature-platform-bootstrap.md
--
-- Stores provider-returned metadata entries during the same activation
-- transaction that finalizes a provisioning tenant.

CREATE TABLE tenant_metadata (
    tenant_id UUID NOT NULL,
    schema_uuid UUID NOT NULL,
    value JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT pk_tenant_metadata PRIMARY KEY (tenant_id, schema_uuid),
    CONSTRAINT fk_tenant_metadata_tenant
        FOREIGN KEY (tenant_id) REFERENCES tenants(id)
        ON UPDATE CASCADE ON DELETE CASCADE
);

CREATE INDEX idx_tenant_metadata_tenant
    ON tenant_metadata (tenant_id);
