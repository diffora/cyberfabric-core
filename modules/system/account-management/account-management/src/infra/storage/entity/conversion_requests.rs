//! `SeaORM` entity for the AM-owned `conversion_requests` table.
//!
//! Mirrors the schema declared by `m0004_create_conversion_requests`
//! column-for-column. The state-machine encodings (`status`,
//! `initiator_side`, `target_mode`) are stored as `SMALLINT` at the DB
//! layer and surfaced through the domain layer via
//! [`crate::domain::conversion::model::ConversionStatus`] /
//! [`crate::domain::conversion::model::ConversionSide`] /
//! [`crate::domain::conversion::model::TargetMode`].
//!
//! `Scopable(no_tenant, no_resource, no_owner, no_type)` mirrors
//! `tenants` / `tenant_closure`: until the `InTenantSubtree` predicate
//! lands, AM enforces cross-tenant authorization at the service layer
//! via the PDP gate; per-row auto-filtering is intentionally off here
//! and callers MUST pass [`modkit_security::AccessScope::allow_all`]
//! when invoking the repo methods that read or write this table.

use modkit_db_macros::Scopable;
use sea_orm::entity::prelude::*;
use time::OffsetDateTime;
use uuid::Uuid;

// @cpt-begin:cpt-cf-account-management-dbtable-conversion-requests:p1:inst-dbtable-conversion-requests-entity
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Scopable)]
#[sea_orm(table_name = "conversion_requests")]
#[secure(no_tenant, no_resource, no_owner, no_type)]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub tenant_id: Uuid,
    #[sea_orm(nullable)]
    pub parent_id: Option<Uuid>,
    pub child_tenant_name: String,
    /// `0=child, 1=parent` — encodes which side of the dual-consent
    /// pair initiated this request. Matches the
    /// `CHECK (initiator_side IN (0, 1))` constraint.
    pub initiator_side: i16,
    /// `0=managed, 1=self_managed` — the mode the tenant will move to
    /// if the request is approved. Matches the
    /// `CHECK (target_mode IN (0, 1))` constraint.
    pub target_mode: i16,
    /// `0=pending, 1=approved, 2=cancelled, 3=rejected, 4=expired` —
    /// matches the `CHECK (status IN (0, 1, 2, 3, 4))` constraint and
    /// the encoding pinned by
    /// [`crate::domain::conversion::model::ConversionStatus::as_smallint`].
    pub status: i16,
    pub requested_by: Uuid,
    #[sea_orm(nullable)]
    pub approved_by: Option<Uuid>,
    #[sea_orm(nullable)]
    pub cancelled_by: Option<Uuid>,
    #[sea_orm(nullable)]
    pub rejected_by: Option<Uuid>,
    pub requested_at: OffsetDateTime,
    #[sea_orm(nullable)]
    pub resolved_at: Option<OffsetDateTime>,
    pub expires_at: OffsetDateTime,
    #[sea_orm(nullable)]
    pub deleted_at: Option<OffsetDateTime>,
}
// @cpt-end:cpt-cf-account-management-dbtable-conversion-requests:p1:inst-dbtable-conversion-requests-entity

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
