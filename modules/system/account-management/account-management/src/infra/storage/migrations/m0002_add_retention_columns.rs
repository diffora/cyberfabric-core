//! Phase 3 migration — retention columns + supporting partial indexes.
//!
//! Mirrors `migrations/0002_add_retention_columns.sql` byte-for-byte on
//! Postgres and supplies a dialect-adjusted variant for `SQLite` (used
//! by the in-tree integration tests). Nullability is preserved on all
//! supported backends so Phase 1/2 rows need no backfill.
//!
//! `MySQL` is intentionally **not** supported — see
//! [`super::m0001_create_tenants`] for the full rationale. A `MySQL`
//! deployment MUST ship its own migration set.

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
                "ALTER TABLE tenants ADD COLUMN IF NOT EXISTS deletion_scheduled_at TIMESTAMP WITH TIME ZONE NULL;",
                "ALTER TABLE tenants ADD COLUMN IF NOT EXISTS retention_window_secs BIGINT NULL;",
                "CREATE INDEX IF NOT EXISTS idx_tenants_retention_scan ON tenants (deletion_scheduled_at, depth DESC) WHERE status = 3 AND deletion_scheduled_at IS NOT NULL;",
                "CREATE INDEX IF NOT EXISTS idx_tenants_provisioning_stuck ON tenants (created_at) WHERE status = 0;",
            ],
            sea_orm::DatabaseBackend::Sqlite => vec![
                "ALTER TABLE tenants ADD COLUMN deletion_scheduled_at TEXT NULL;",
                "ALTER TABLE tenants ADD COLUMN retention_window_secs INTEGER NULL;",
                "CREATE INDEX IF NOT EXISTS idx_tenants_retention_scan ON tenants (deletion_scheduled_at, depth DESC) WHERE status = 3 AND deletion_scheduled_at IS NOT NULL;",
                "CREATE INDEX IF NOT EXISTS idx_tenants_provisioning_stuck ON tenants (created_at) WHERE status = 0;",
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
            "DROP INDEX IF EXISTS idx_tenants_provisioning_stuck;",
            "DROP INDEX IF EXISTS idx_tenants_retention_scan;",
            "ALTER TABLE tenants DROP COLUMN retention_window_secs;",
            "ALTER TABLE tenants DROP COLUMN deletion_scheduled_at;",
        ] {
            conn.execute_unprepared(sql).await?;
        }
        Ok(())
    }
}
