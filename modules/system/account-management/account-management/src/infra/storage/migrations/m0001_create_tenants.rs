//! Phase 2 migration wrapper for Phase 1's `0001_create_tenants.sql`.
//!
//! The migration applies the AM-owned `tenants` + `tenant_closure` DDL.
//! We use per-backend raw SQL (not `SeaORM`'s schema-builder) so the
//! `CHECK` / partial unique / barrier invariants in Phase 1's
//! authoritative SQL are preserved byte-for-byte on Postgres. `SQLite`
//! receives a dialect-adjusted variant used by the in-tree integration
//! tests.
//!
//! `MySQL` is intentionally **not** supported by this migration — the
//! Postgres DDL relies on partial unique indexes (`WHERE parent_id IS
//! NULL`), `CHECK` constraints, and `FOREIGN KEY ... ON DELETE` modes
//! that need a `MySQL`-specific design pass before they can be reproduced
//! safely. A `MySQL` backend MUST ship its own migration set; running
//! the AM migrator against `MySQL` fails fast with an explicit
//! `DbErr::Custom`.

use sea_orm_migration::prelude::*;
use sea_orm_migration::sea_orm::ConnectionTrait;

const MYSQL_NOT_SUPPORTED: &str = "account-management migrations: MySQL is not supported \
    (this migration set targets PostgreSQL/SQLite); add a dedicated MySQL migration set \
    before running against MySQL";

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let backend = manager.get_database_backend();
        let conn = manager.get_connection();

        let statements: Vec<&str> = match backend {
            sea_orm::DatabaseBackend::Postgres => vec![
                r"
CREATE TABLE IF NOT EXISTS tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    parent_id UUID NULL,
    name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 255),
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
                ",
                "CREATE UNIQUE INDEX IF NOT EXISTS ux_tenants_single_root ON tenants ((1)) WHERE parent_id IS NULL;",
                "CREATE INDEX IF NOT EXISTS idx_tenants_parent_status ON tenants (parent_id, status);",
                "CREATE INDEX IF NOT EXISTS idx_tenants_status ON tenants (status);",
                "CREATE INDEX IF NOT EXISTS idx_tenants_type ON tenants (tenant_type_uuid);",
                "CREATE INDEX IF NOT EXISTS idx_tenants_deleted_at ON tenants (deleted_at) WHERE deleted_at IS NOT NULL;",
                r"
CREATE TABLE IF NOT EXISTS tenant_closure (
    ancestor_id UUID NOT NULL,
    descendant_id UUID NOT NULL,
    barrier SMALLINT NOT NULL DEFAULT 0,
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
                ",
                "CREATE INDEX IF NOT EXISTS idx_tenant_closure_ancestor_barrier_status ON tenant_closure (ancestor_id, barrier, descendant_status);",
                "CREATE INDEX IF NOT EXISTS idx_tenant_closure_descendant ON tenant_closure (descendant_id);",
            ],
            sea_orm::DatabaseBackend::Sqlite => vec![
                r"
CREATE TABLE IF NOT EXISTS tenants (
    id TEXT PRIMARY KEY NOT NULL,
    parent_id TEXT NULL,
    name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 255),
    status SMALLINT NOT NULL CHECK (status IN (0, 1, 2, 3)),
    self_managed INTEGER NOT NULL DEFAULT 0,
    tenant_type_uuid TEXT NOT NULL,
    depth INTEGER NOT NULL CHECK (depth >= 0),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TEXT NULL,
    CONSTRAINT ck_tenants_root_depth
        CHECK ((parent_id IS NULL AND depth = 0) OR (parent_id IS NOT NULL AND depth > 0))
);
                ",
                "CREATE UNIQUE INDEX IF NOT EXISTS ux_tenants_single_root ON tenants (parent_id) WHERE parent_id IS NULL;",
                "CREATE INDEX IF NOT EXISTS idx_tenants_parent_status ON tenants (parent_id, status);",
                "CREATE INDEX IF NOT EXISTS idx_tenants_status ON tenants (status);",
                "CREATE INDEX IF NOT EXISTS idx_tenants_type ON tenants (tenant_type_uuid);",
                r"
CREATE TABLE IF NOT EXISTS tenant_closure (
    ancestor_id TEXT NOT NULL,
    descendant_id TEXT NOT NULL,
    barrier SMALLINT NOT NULL DEFAULT 0,
    descendant_status SMALLINT NOT NULL CHECK (descendant_status IN (1, 2, 3)),
    PRIMARY KEY (ancestor_id, descendant_id),
    CONSTRAINT ck_tenant_closure_self_row_barrier
        CHECK (ancestor_id <> descendant_id OR barrier = 0),
    CONSTRAINT ck_tenant_closure_barrier_nonnegative
        CHECK (barrier >= 0)
);
                ",
                "CREATE INDEX IF NOT EXISTS idx_tenant_closure_ancestor_barrier_status ON tenant_closure (ancestor_id, barrier, descendant_status);",
                "CREATE INDEX IF NOT EXISTS idx_tenant_closure_descendant ON tenant_closure (descendant_id);",
            ],
            sea_orm::DatabaseBackend::MySql => {
                return Err(DbErr::Custom(MYSQL_NOT_SUPPORTED.to_owned()));
            }
        };

        for sql in statements {
            conn.execute_unprepared(sql).await?;
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let backend = manager.get_database_backend();
        if matches!(backend, sea_orm::DatabaseBackend::MySql) {
            return Err(DbErr::Custom(MYSQL_NOT_SUPPORTED.to_owned()));
        }
        let conn = manager.get_connection();
        // Drop in reverse order — closure first; CASCADEs into parents
        // via the FK on PG/SQLite.
        for sql in [
            "DROP TABLE IF EXISTS tenant_closure;",
            "DROP TABLE IF EXISTS tenants;",
        ] {
            conn.execute_unprepared(sql).await?;
        }
        Ok(())
    }
}
