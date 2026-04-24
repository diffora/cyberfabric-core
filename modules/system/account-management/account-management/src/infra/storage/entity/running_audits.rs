//! `running_audits` `SeaORM` entity — single-flight gate row.
//!
//! Phase 5 single-flight coordination row for the `SQLite` backend of
//! `audit_integrity_for_scope`. The Postgres backend does not write here
//! (it uses `pg_try_advisory_xact_lock` at runtime); `SQLite` holds at
//! most one row per `IntegrityScope` for the lifetime of an in-flight
//! audit transaction. The PRIMARY KEY on `scope_key` provides the
//! mutual-exclusion semantics; `worker_id` lets the success-path
//! `DELETE` target the exact row this worker inserted (defensive: it
//! also disambiguates a hypothetical double-DELETE if the gate is ever
//! migrated to a non-PK shape).
//!
//! `Scopable(no_tenant, no_resource, no_owner, no_type)` because the
//! row is a process-coordination artifact, not a tenant resource. It is
//! never surfaced through the SDK; only the storage layer reads or
//! writes it.

use modkit_db_macros::Scopable;
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Scopable)]
#[sea_orm(table_name = "running_audits")]
#[secure(no_tenant, no_resource, no_owner, no_type)]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub scope_key: String,
    pub worker_id: String,
    pub started_at: ChronoDateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
