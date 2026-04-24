//! Phase 5 migration — single-flight gate for the hierarchy-integrity audit.
//!
//! Postgres uses `pg_try_advisory_xact_lock(hashtext(...))` at runtime,
//! so the Postgres branch performs no DDL. `SQLite` needs a real row-locked
//! table because there is no advisory-lock primitive; the
//! `running_audits` table holds at most one row per `IntegrityScope` for
//! the duration of an in-flight audit transaction. The gate is released
//! at txn commit (explicit `DELETE`) or at txn rollback (the uncommitted
//! `INSERT` row dies with the txn).
//!
//! See `migrations/0005_running_audits.sql` for the authoritative SQL
//! form consumed by external migration tooling; this Rust migration is
//! the runtime mechanism applied by `Migrator::up`.

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
            // Postgres uses `pg_try_advisory_xact_lock` at runtime; no
            // schema is required for the single-flight gate.
            sea_orm::DatabaseBackend::Postgres => vec![],
            sea_orm::DatabaseBackend::Sqlite => vec![
                "CREATE TABLE running_audits ( \
                    scope_key TEXT PRIMARY KEY, \
                    worker_id TEXT NOT NULL, \
                    started_at TIMESTAMP NOT NULL \
                );",
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
        if matches!(backend, sea_orm::DatabaseBackend::Sqlite) {
            manager
                .get_connection()
                .execute_unprepared("DROP TABLE IF EXISTS running_audits;")
                .await?;
        }
        // Postgres: nothing to drop — `up` was a no-op.
        Ok(())
    }
}
