//! Migration `m0005` — add `idx_tenant_metadata_schema ON
//! tenant_metadata(schema_uuid)` for the FEATURE 2.7 (Tenant Metadata)
//! walk-up resolver.
//!
//! The `tenant_metadata` table itself was created by `m0001_initial_schema`
//! (composite PK `(tenant_id, schema_uuid)`, FK `ON DELETE CASCADE` on
//! Postgres, plus the lookup index `idx_tenant_metadata_tenant`). This
//! migration adds the secondary index on `schema_uuid` only — the
//! resolver and the future per-schema cross-tenant scans benefit from a
//! direct probe on the schema column without forcing a tenant-prefix
//! seek.
//!
//! Both supported backends use `CREATE INDEX IF NOT EXISTS` so the
//! migration is idempotent if the migrator re-runs against a database
//! that already holds the index. `MySQL` is unsupported and returns
//! `DbErr::Custom(MYSQL_NOT_SUPPORTED)` — same contract as `m0001` and
//! `m0004`. `down` drops only the index; the table itself is owned by
//! `m0001` and MUST NOT be dropped here.

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
            // @cpt-begin:cpt-cf-account-management-dbtable-tenant-metadata:p2:inst-dbtable-tenant-metadata-index-schema
            sea_orm::DatabaseBackend::Postgres | sea_orm::DatabaseBackend::Sqlite => vec![
                "CREATE INDEX IF NOT EXISTS idx_tenant_metadata_schema ON tenant_metadata (schema_uuid);",
            ],
            // @cpt-end:cpt-cf-account-management-dbtable-tenant-metadata:p2:inst-dbtable-tenant-metadata-index-schema
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
        manager
            .get_connection()
            .execute_unprepared("DROP INDEX IF EXISTS idx_tenant_metadata_schema;")
            .await?;
        Ok(())
    }
}
