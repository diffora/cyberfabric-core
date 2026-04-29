//! `SeaORM` entity for the AM-owned `tenant_closure` table.
//!
//! Mirrors the `tenant_closure` schema declared by
//! `m0001_initial_schema` column-for-column and enforces the barrier +
//! SDK-visible `descendant_status` invariants through the DB-level
//! `CHECK` constraints in the migration. Closure maintenance helpers
//! that build the rows live in `domain/tenant/closure.rs`.
//!
//! DESIGN §3.1 / §3.7 closure invariants enforced in AM code:
//! - Self-row `(id, id)` with `barrier = 0` and `descendant_status =
//!   tenants.status` for every SDK-visible tenant.
//! - One `(ancestor_id, id)` row per strict ancestor along the `parent_id`
//!   chain; no gaps, no extras.
//! - `barrier = 1` on `(A, D)` iff any tenant on the strict `A → D` path
//!   (excluding `A`, including `D`) has `self_managed = true`; else `0`.
//! - `descendant_status ∈ {1, 2, 3}` — provisioning tenants have no closure
//!   rows at all.

use modkit_db_macros::Scopable;
use sea_orm::entity::prelude::*;
use uuid::Uuid;

// @cpt-begin:cpt-cf-account-management-dbtable-tenant-closure:p1:inst-dbtable-tenant-closure-entity
// `tenant_closure` is an auxiliary index used internally by AM + by the
// tenant-resolver read model. It does not carry a tenant-ownership column
// (each row references two tenants via `ancestor_id` + `descendant_id`),
// so it is declared with `no_tenant` / `no_resource`. Phase 2 addition:
// keeps the table writable from `TenantRepoImpl` via SecureConn without
// compromising the per-row scope contract enforced on `tenants` itself.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Scopable)]
#[sea_orm(table_name = "tenant_closure")]
#[secure(no_tenant, no_resource, no_owner, no_type)]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub ancestor_id: Uuid,
    #[sea_orm(primary_key, auto_increment = false)]
    pub descendant_id: Uuid,
    /// `0` for the self-row and for rows with no self-managed tenant on the
    /// strict `(ancestor, descendant]` path; `1` when such a tenant exists.
    /// v1 uses only bit 0; reserved as `SMALLINT` for future barrier bits.
    pub barrier: i16,
    /// `1=active, 2=suspended, 3=deleted` — the SDK-visible subset only.
    /// `provisioning` tenants never have closure rows.
    pub descendant_status: i16,
}
// @cpt-end:cpt-cf-account-management-dbtable-tenant-closure:p1:inst-dbtable-tenant-closure-entity

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
