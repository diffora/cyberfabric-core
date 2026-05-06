//! `integrity_check_runs` `SeaORM` entity — single-flight gate row.
//!
//! Backing table for the uniform single-flight gate used by
//! `run_integrity_check_for_scope` on **both** `PostgreSQL` and
//! `SQLite`. The integrity-check transaction inserts one row per
//! in-flight check and deletes it before commit; concurrent callers
//! attempting the same `scope_key` collide on the PRIMARY KEY and
//! surface as [`crate::domain::error::DomainError::IntegrityCheckInProgress`].
//! The `pg_try_advisory_xact_lock` path used by the legacy raw-SQL
//! integrity check was removed in the Rust-side classifier refactor —
//! uniform behaviour across backends is the whole point of the new
//! gate. `worker_id` lets the success-path `DELETE` target the exact
//! row this worker inserted (defensive: it also disambiguates a
//! hypothetical double-DELETE if the gate is ever migrated to a
//! non-PK shape).
//!
//! `Scopable(no_tenant, no_resource, no_owner, no_type)` because the
//! row is a process-coordination artifact, not a tenant resource. It is
//! never surfaced through the SDK; only the storage layer reads or
//! writes it.

use modkit_db_macros::Scopable;
use sea_orm::entity::prelude::*;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Scopable)]
#[sea_orm(table_name = "integrity_check_runs")]
#[secure(no_tenant, no_resource, no_owner, no_type)]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub scope_key: String,
    pub worker_id: Uuid,
    pub started_at: OffsetDateTime,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
