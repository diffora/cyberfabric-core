//! Phase 6 migration — tenant metadata persistence for `IdP` results.
//!
//! The bootstrap and create-tenant sagas persist provider-returned
//! metadata entries as `(tenant_id, schema_uuid)` rows during activation.

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
CREATE TABLE IF NOT EXISTS tenant_metadata (
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
                ",
                "CREATE INDEX IF NOT EXISTS idx_tenant_metadata_tenant ON tenant_metadata (tenant_id);",
            ],
            sea_orm::DatabaseBackend::Sqlite => vec![
                r"
CREATE TABLE IF NOT EXISTS tenant_metadata (
    tenant_id TEXT NOT NULL,
    schema_uuid TEXT NOT NULL,
    value TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, schema_uuid),
    FOREIGN KEY (tenant_id) REFERENCES tenants(id)
        ON UPDATE CASCADE ON DELETE CASCADE
);
                ",
                "CREATE INDEX IF NOT EXISTS idx_tenant_metadata_tenant ON tenant_metadata (tenant_id);",
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
        for sql in [
            "DROP INDEX IF EXISTS idx_tenant_metadata_tenant;",
            "DROP TABLE IF EXISTS tenant_metadata;",
        ] {
            conn.execute_unprepared(sql).await?;
        }
        Ok(())
    }
}
