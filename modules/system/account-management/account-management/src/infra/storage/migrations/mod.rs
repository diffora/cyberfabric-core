//! `SeaORM` migrations for the Account Management module.
//!
//! Migration 0001 ships the initial schema (`tenants`, `tenant_closure`,
//! `tenant_metadata`) with every column and index needed by the
//! storage-floor repository. Audit-related tables (e.g. `running_audits`)
//! arrive in a later PR as 0002.

use sea_orm_migration::prelude::*;

pub mod m0001_initial_schema;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![Box::new(m0001_initial_schema::Migration)]
    }
}
