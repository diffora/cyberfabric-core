//! `SeaORM` migrations for the Account Management module.
//!
//! * `m0001_initial_schema` — `tenants`, `tenant_closure`,
//!   `tenant_metadata` tables with every column and index needed by
//!   the storage-floor repository.
//! * `m0002_add_terminal_failure_columns` — `tenants.terminal_failure_at`
//!   column for provisioning-reaper terminal-failure handling
//!   (operator-action-required state that keeps the row out of the
//!   automatic reaper retry loop).
//! * `m0003_create_integrity_check_runs` —
//!   `integrity_check_runs` single-flight gate table for the
//!   Rust-side hierarchy-integrity check (singleton-row table with a
//!   `CHECK (id = 1)` PK so concurrent acquires collide on
//!   unique-violation, lifecycle-bound to the integrity-check
//!   transaction).

use sea_orm_migration::prelude::*;

pub mod m0001_initial_schema;
pub mod m0002_add_terminal_failure_columns;
pub mod m0003_create_integrity_check_runs;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m0001_initial_schema::Migration),
            Box::new(m0002_add_terminal_failure_columns::Migration),
            Box::new(m0003_create_integrity_check_runs::Migration),
        ]
    }
}
