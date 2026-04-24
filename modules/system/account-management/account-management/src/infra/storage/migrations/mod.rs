//! `SeaORM` migrations for the Account Management module.
//!
//! The migration body mirrors `migrations/0001_create_tenants.sql` — the
//! Rust wrapper lets modkit's `DatabaseCapability` register per-module
//! migrations (each module has its own history table).

use sea_orm_migration::prelude::*;

pub mod m0001_create_tenants;
pub mod m0002_add_retention_columns;
pub mod m0003_add_retention_claim_column;
pub mod m0004_create_tenant_metadata;
pub mod m0005_running_audits;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m0001_create_tenants::Migration),
            Box::new(m0002_add_retention_columns::Migration),
            Box::new(m0003_add_retention_claim_column::Migration),
            Box::new(m0004_create_tenant_metadata::Migration),
            Box::new(m0005_running_audits::Migration),
        ]
    }
}
