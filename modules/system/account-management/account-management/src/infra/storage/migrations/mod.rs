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
//! * `m0004_create_conversion_requests` — `conversion_requests` and
//!   `tenant_idp_metadata` tables. The former backs the
//!   managed/self-managed dual-consent conversion state machine (with
//!   the partial unique index that enforces the at-most-one-pending
//!   invariant per tenant); the latter holds the plugin-private
//!   per-tenant state AM echoes through `TenantContext::metadata` on
//!   every `IdP` call, separated from public `tenant_metadata` so
//!   plugin internals do not leak through the public metadata REST
//!   surface. The two land in one migration because they belong to
//!   the same in-flight PR; the `m0005` slot is already claimed by
//!   the sibling `am/05-tenant-metadata` branch, and splitting after
//!   the fact would only add migration-history noise.

use sea_orm_migration::prelude::*;

pub mod m0001_initial_schema;
pub mod m0002_add_terminal_failure_columns;
pub mod m0003_create_integrity_check_runs;
pub mod m0004_create_conversion_requests;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m0001_initial_schema::Migration),
            Box::new(m0002_add_terminal_failure_columns::Migration),
            Box::new(m0003_create_integrity_check_runs::Migration),
            Box::new(m0004_create_conversion_requests::Migration),
        ]
    }
}
