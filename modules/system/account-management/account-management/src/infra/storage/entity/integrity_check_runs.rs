//! `integrity_check_runs` `SeaORM` entity — single-flight gate row.
//!
//! Backing table for the uniform single-flight gate used by
//! `run_integrity_check` on **both** `PostgreSQL` and `SQLite`. The
//! integrity-check transaction inserts one row per in-flight check and
//! deletes it before commit; concurrent callers collide on the
//! singleton PRIMARY KEY (`id = 1`, enforced by a `CHECK` constraint)
//! and surface as
//! [`crate::domain::error::DomainError::IntegrityCheckInProgress`].
//! The `pg_try_advisory_xact_lock` path used by the legacy raw-SQL
//! integrity check was removed in the Rust-side classifier refactor —
//! uniform behaviour across backends is the whole point of the new
//! gate. `worker_id` lets the success-path `DELETE` target the exact
//! row this worker inserted.
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
    /// Singleton PK pinned to `1` by a CHECK constraint at the DB
    /// layer — the table is a one-or-zero-row gate, the column exists
    /// only because both `PostgreSQL` and `SQLite` require a primary
    /// key to provide the unique-violation primitive `acquire` relies
    /// on.
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: i32,
    pub worker_id: Uuid,
    pub started_at: OffsetDateTime,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
