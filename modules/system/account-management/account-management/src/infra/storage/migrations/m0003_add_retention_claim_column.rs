//! Phase 5 migration — retention scan worker claim columns.
//!
//! The hard-delete scanner claims due rows before returning them to the
//! service. Two nullable columns back the atomic claim update:
//!
//! * `claimed_by`  — scanner UUID; the row is "claimed by worker X".
//! * `claimed_at`  — when the claim was made; the stale-claim TTL is
//!   evaluated against this column rather than `updated_at`. Reusing
//!   `updated_at` would couple worker-liveness detection to ordinary
//!   tenant patches and break the moment a future code change starts
//!   touching `updated_at` on `Deleted`-status rows. Both `claimed_by`
//!   and `claimed_at` are cleared together when the scanner finishes
//!   the row (success or compensation).

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
                "ALTER TABLE tenants ADD COLUMN IF NOT EXISTS claimed_by UUID NULL;",
                "ALTER TABLE tenants ADD COLUMN IF NOT EXISTS claimed_at TIMESTAMPTZ NULL;",
                "CREATE INDEX IF NOT EXISTS idx_tenants_retention_claim ON tenants (claimed_by) WHERE claimed_by IS NOT NULL;",
            ],
            sea_orm::DatabaseBackend::Sqlite => vec![
                "ALTER TABLE tenants ADD COLUMN claimed_by TEXT NULL;",
                "ALTER TABLE tenants ADD COLUMN claimed_at TIMESTAMP NULL;",
                "CREATE INDEX IF NOT EXISTS idx_tenants_retention_claim ON tenants (claimed_by) WHERE claimed_by IS NOT NULL;",
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
            "DROP INDEX IF EXISTS idx_tenants_retention_claim;",
            "ALTER TABLE tenants DROP COLUMN claimed_at;",
            "ALTER TABLE tenants DROP COLUMN claimed_by;",
        ] {
            conn.execute_unprepared(sql).await?;
        }
        Ok(())
    }
}
