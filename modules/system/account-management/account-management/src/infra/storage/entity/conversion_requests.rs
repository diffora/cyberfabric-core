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
//! `Scopable(tenant_col = "tenant_id", no_resource, no_owner, no_type)` —
//! the entity declares `tenant_id` as the resolvable
//! `pep_properties::OWNER_TENANT_ID` column so the
//! [`InTenantSubtree`](modkit_security::ScopeFilter::in_tenant_subtree)
//! predicate (cyberware-rust#1813) has a property to compile against.
//! A scope of shape `InTenantSubtree(OWNER_TENANT_ID, root)` would
//! materialise as
//! `tenant_id IN (SELECT descendant_id FROM tenant_closure
//!   WHERE ancestor_id = :root AND barrier = 0)`.
//!
//! **Service-side posture today (post-#1813, pre-REST-handler PR):**
//! `cancel` / `reject` / `approve` / `list_inbound_for_parent` still
//! pass [`modkit_security::AccessScope::allow_all`] to the repo
//! because the dual-consent flows need barrier-penetration:
//!
//! * Parent acts as counterparty (`reject` / `approve`) on a
//!   conversion initiated by a self-managed child whose parent
//!   barrier is `1`. A narrowed `InTenantSubtree(.., respect_barriers
//!   = true)` clamp would exclude the child's `tenant_id` from the
//!   subtree and turn an authorized counterparty action into a silent
//!   `NotFound`.
//! * Inbound listings surface conversions from self-managed children
//!   that sit behind the parent's barrier — clamping by subtree
//!   would drop them.
//!
//! The schema-side scope column is therefore declared today, and the
//! service layer's PEP gate plus the `verify_caller_scope` /
//! `require_caller_tenant_visible` fences carry authorization. When
//! the REST-handler PR ships, the request-bound caller side
//! (`Child` vs `Parent`) lets the PDP emit a barrier-penetrating
//! variant for the counterparty path, at which point the service can
//! plumb scope into the conversion repo verbatim. INSERT paths stay
//! `scope_unchecked` regardless — the Scopable INSERT-time clamp
//! isn't the right model for inserts.

use modkit_db_macros::Scopable;
use sea_orm::entity::prelude::*;
use time::OffsetDateTime;
use uuid::Uuid;

// @cpt-begin:cpt-cf-account-management-dbtable-conversion-requests:p1:inst-dbtable-conversion-requests-entity
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Scopable)]
#[sea_orm(table_name = "conversion_requests")]
#[secure(tenant_col = "tenant_id", no_resource, no_owner, no_type)]
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
