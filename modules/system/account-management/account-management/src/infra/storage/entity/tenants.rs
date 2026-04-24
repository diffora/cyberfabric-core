//! `SeaORM` entity for the AM-owned `tenants` table.
//!
//! Mirrors `migrations/0001_create_tenants.sql` column-for-column and matches
//! DESIGN §3.9. The `status` and `depth` fields are stored as `SMALLINT` /
//! `INTEGER` at the DB level but surfaced through the domain layer via the
//! [`crate::domain::tenant::model::TenantStatus`] enum and a `u32` depth.
//!
//! Phase 1 scope: entity definition only. Repository implementation and
//! domain-to-entity mapping live in `infra/storage/repo_impl.rs`
//! (introduced in the REST-wiring phase).

use modkit_db_macros::Scopable;
use sea_orm::entity::prelude::*;
use time::OffsetDateTime;
use uuid::Uuid;

// @cpt-begin:cpt-cf-account-management-dbtable-tenants:p1:inst-dbtable-tenants-entity
// `tenants` is a tenant-scoped table where the row's own `id` is both the
// tenant id (for the purposes of AccessScope tenant checks) and the
// resource id. The `no_owner` + `no_type` markers are used because AM
// does not attach subject-owner / tenant-type relationships to tenants
// themselves. Phase 2 addition: consumed by SecureConn paths in
// `repo_impl.rs`.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Scopable)]
#[sea_orm(table_name = "tenants")]
#[secure(tenant_col = "id", resource_col = "id", no_owner, no_type)]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    #[sea_orm(nullable)]
    pub parent_id: Option<Uuid>,
    pub name: String,
    /// `0=provisioning, 1=active, 2=suspended, 3=deleted` — matches the
    /// `CHECK (status IN (0,1,2,3))` constraint in the migration DDL.
    pub status: i16,
    pub self_managed: bool,
    pub tenant_type_uuid: Uuid,
    pub depth: i32,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    #[sea_orm(nullable)]
    pub deleted_at: Option<OffsetDateTime>,
    /// Phase 3 — timestamp at which the hard-delete sweep first becomes
    /// eligible to reclaim this row. Populated at soft-delete time.
    #[sea_orm(nullable)]
    pub deletion_scheduled_at: Option<OffsetDateTime>,
    /// Phase 3 — optional per-tenant override of the module-default
    /// retention window. Stored as BIGINT seconds (not INTERVAL) so the
    /// shape is portable across `SQLite` / `MySQL` / Postgres.
    #[sea_orm(nullable)]
    pub retention_window_secs: Option<i64>,
    /// Phase 5 — hard-delete worker claim. A non-NULL value means a
    /// retention scanner atomically claimed the row before processing it.
    #[sea_orm(nullable)]
    pub claimed_by: Option<Uuid>,
}
// @cpt-end:cpt-cf-account-management-dbtable-tenants:p1:inst-dbtable-tenants-entity

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn root_model_has_no_parent_and_depth_zero() {
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("stable epoch");
        let m = Model {
            id: Uuid::from_u128(0x10),
            parent_id: None,
            name: "root".into(),
            status: 1,
            self_managed: false,
            tenant_type_uuid: Uuid::from_u128(0x3),
            depth: 0,
            created_at: now,
            updated_at: now,
            deleted_at: None,
            deletion_scheduled_at: None,
            retention_window_secs: None,
            claimed_by: None,
        };
        assert!(m.parent_id.is_none());
        assert_eq!(m.depth, 0);
    }
}
