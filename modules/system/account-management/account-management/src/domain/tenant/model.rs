//! Tenant domain model types.
//!
//! Pure Rust value types that express tenant lifecycle concepts
//! independently of storage and transport. The `SeaORM` entities live in
//! `crate::infra::storage::entity::{tenants, tenant_closure}`; `OpenAPI`
//! DTOs are added in the REST-wiring phase. These domain types are the
//! shape that flows through `TenantService`.

use modkit_macros::domain_model;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::domain::error::AmError;

/// Full lifecycle status of a tenant.
///
/// Domain enum: includes the internal `Provisioning` state that is never
/// surfaced through the public SDK / REST API. The storage layer encodes
/// these as `SMALLINT` per `m0001_initial_schema` using the mapping:
/// `0=Provisioning, 1=Active, 2=Suspended, 3=Deleted`.
// @cpt-begin:cpt-cf-account-management-state-tenant-hierarchy-management-tenant-status:p1:inst-state-tenant-status-domain
#[domain_model]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum TenantStatus {
    Provisioning,
    Active,
    Suspended,
    Deleted,
}
// @cpt-end:cpt-cf-account-management-state-tenant-hierarchy-management-tenant-status:p1:inst-state-tenant-status-domain

impl TenantStatus {
    /// Numeric SMALLINT encoding used by the DB schema.
    #[must_use]
    pub const fn as_smallint(self) -> i16 {
        match self {
            Self::Provisioning => 0,
            Self::Active => 1,
            Self::Suspended => 2,
            Self::Deleted => 3,
        }
    }

    /// Whether the status is visible to the public API surface (`list`,
    /// `read`, status-filter). Provisioning tenants are SDK-invisible.
    #[must_use]
    pub const fn is_sdk_visible(self) -> bool {
        !matches!(self, Self::Provisioning)
    }

    /// Parse from SMALLINT. Returns `None` for any value outside the
    /// documented `{0, 1, 2, 3}` domain.
    #[must_use]
    pub const fn from_smallint(value: i16) -> Option<Self> {
        match value {
            0 => Some(Self::Provisioning),
            1 => Some(Self::Active),
            2 => Some(Self::Suspended),
            3 => Some(Self::Deleted),
            _ => None,
        }
    }
}

/// Snapshot of a tenant row as returned by `TenantRepo`.
///
/// Matches the column set declared by `m0001_initial_schema`,
/// including `deleted_at`.
#[domain_model]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantModel {
    pub id: Uuid,
    pub parent_id: Option<Uuid>,
    pub name: String,
    pub status: TenantStatus,
    pub self_managed: bool,
    pub tenant_type_uuid: Uuid,
    /// Depth from the root. Root has depth `0`; each step adds `1`.
    pub depth: u32,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    pub deleted_at: Option<OffsetDateTime>,
}

// NOTE: Phase 3 adds two retention columns (`deletion_scheduled_at`,
// `retention_window_secs`) to the `tenants` entity — see
// `src/infra/storage/entity/tenants.rs`. The domain layer surfaces them
// through the [`retention::TenantRetentionRow`] selection row rather than
// as free-floating `TenantModel` fields, so the happy-path surface used
// by every existing flow (read / list / update) keeps its Phase-1 shape.

/// Validated fields used to create a tenant's initial row (before the
/// `IdP` provisioning step of the create-tenant saga).
///
/// `parent_id` is `None` exclusively for the platform root tenant (the
/// row inserted by `BootstrapService`); every other tenant is a child
/// of an existing active tenant and carries `Some(parent_id)`. This
/// matches the migration's `ck_tenants_root_depth` invariant
/// (`(parent_id IS NULL AND depth = 0) OR (parent_id IS NOT NULL AND
/// depth > 0)`) and the FK on `tenants.parent_id`.
#[domain_model]
#[derive(Debug, Clone)]
pub struct NewTenant {
    pub id: Uuid,
    pub parent_id: Option<Uuid>,
    pub name: String,
    pub self_managed: bool,
    pub tenant_type_uuid: Uuid,
    pub depth: u32,
}

/// Patch passed to `TenantRepo::update_tenant_mutable`.
///
/// Only the two mutable fields from the `OpenAPI` contract
/// (`TenantUpdateRequest`) are representable. Immutable fields (`id`,
/// `parent_id`, `tenant_type`, `self_managed`, `depth`) are intentionally absent.
// @cpt-begin:cpt-cf-account-management-dod-tenant-hierarchy-management-update-mutable-only:p1:inst-dod-update-mutable-domain-patch
#[domain_model]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TenantUpdate {
    pub name: Option<String>,
    pub status: Option<TenantStatus>,
}
// @cpt-end:cpt-cf-account-management-dod-tenant-hierarchy-management-update-mutable-only:p1:inst-dod-update-mutable-domain-patch

impl TenantUpdate {
    /// Whether this patch is effectively empty. An empty patch is rejected
    /// per the `minProperties: 1` rule on `TenantUpdateRequest`.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.name.is_none() && self.status.is_none()
    }

    /// Reject status transitions that are not supported by the PATCH flow
    /// (DESIGN §3.3 update flow + FEATURE §2 `Update Tenant Mutable Fields`).
    ///
    /// Allowed transitions via PATCH (strict — only the cross-flip):
    /// - `Active → Suspended`
    /// - `Suspended → Active`
    ///
    /// Disallowed:
    /// - No-op transitions (`Active → Active`, `Suspended → Suspended`)
    ///   — the patch would still trigger a `tenant_closure.descendant_status`
    ///   rewrite per the closure-status invariant, costing a write for no
    ///   user-visible change. Surface them as `Conflict` so callers learn
    ///   the patch was a no-op rather than silently bumping `updated_at`.
    /// - Any target of `Deleted` (owned by the DELETE flow / `schedule_deletion`).
    /// - Any target of `Provisioning` (internal lifecycle state).
    /// - Any transition from `Deleted` or `Provisioning` (terminal /
    ///   internal — those tenants are not mutable through PATCH).
    ///
    /// Returns `Ok(())` only for the two cross-flip pairs above.
    ///
    /// # Errors
    ///
    /// Returns [`AmError::Conflict`] when the transition is rejected
    /// by one of the rules above. Matches the
    /// [`crate::domain::tenant::repo::TenantRepo::update_tenant_mutable`]
    /// contract — every failed transition is a state-precondition
    /// conflict (HTTP 409), not an input-schema validation error
    /// (HTTP 422).
    pub fn validate_status_transition(
        current: TenantStatus,
        target: TenantStatus,
    ) -> Result<(), AmError> {
        // @cpt-begin:cpt-cf-account-management-dod-tenant-hierarchy-management-status-change-non-cascading:p1:inst-dod-status-transition-guard
        if matches!(target, TenantStatus::Deleted) {
            return Err(AmError::Conflict {
                detail: "status=deleted must go through DELETE flow".into(),
            });
        }
        if matches!(target, TenantStatus::Provisioning) {
            return Err(AmError::Conflict {
                detail: "status=provisioning is internal; not patchable".into(),
            });
        }
        match (current, target) {
            (TenantStatus::Active, TenantStatus::Suspended)
            | (TenantStatus::Suspended, TenantStatus::Active) => Ok(()),
            _ => Err(AmError::Conflict {
                detail: format!(
                    "invalid status transition from {current:?} to {target:?}; \
                     PATCH only accepts the cross-flip Active↔Suspended"
                ),
            }),
        }
        // @cpt-end:cpt-cf-account-management-dod-tenant-hierarchy-management-status-change-non-cascading:p1:inst-dod-status-transition-guard
    }

    /// Validate that `name`, if present, falls within the `OpenAPI`
    /// `minLength: 1, maxLength: 255` bounds.
    ///
    /// # Errors
    ///
    /// Returns [`AmError::Validation`] when the name is shorter than 1
    /// or longer than 255 characters (by `char` count, not byte length).
    pub fn validate_name(name: &str) -> Result<(), AmError> {
        let len = name.chars().count();
        if !(1..=255).contains(&len) {
            return Err(AmError::Validation {
                detail: format!("name length {len} out of range [1,255]"),
            });
        }
        Ok(())
    }
}

/// Pagination and filter parameters for `TenantRepo::list_children`.
///
/// Matches the `top` / `skip` pagination used by the `OpenAPI`
/// `listChildren` endpoint. `status_filter`, when present, restricts the
/// result set to the listed SDK-visible statuses. `provisioning` is never
/// a legal filter value per FEATURE §2 `List Children`; the field is
/// private and the only way to set it is via [`ListChildrenQuery::new`],
/// which rejects [`TenantStatus::Provisioning`] at construction time.
#[domain_model]
#[derive(Debug, Clone)]
pub struct ListChildrenQuery {
    pub parent_id: Uuid,
    status_filter: Option<Vec<TenantStatus>>,
    /// Requested page size. Callers are expected to clamp to the platform
    /// cap before calling the repo; the repo does not enforce a cap.
    pub top: u32,
    pub skip: u32,
}

impl ListChildrenQuery {
    /// Construct a validated query. Rejects `status_filter` values
    /// containing [`TenantStatus::Provisioning`]: provisioning rows are
    /// SDK-invisible by FEATURE §2 `List Children`, and letting one
    /// reach the repo would surface rows the public contract promises
    /// will never appear.
    ///
    /// # Errors
    ///
    /// Returns [`AmError::Validation`] when `status_filter` contains
    /// `TenantStatus::Provisioning`, or when `top == 0` (the public
    /// contract sets `$top` minimum to `1`).
    pub fn new(
        parent_id: Uuid,
        status_filter: Option<Vec<TenantStatus>>,
        top: u32,
        skip: u32,
    ) -> Result<Self, AmError> {
        if top == 0 {
            return Err(AmError::Validation {
                detail: "top must be at least 1".into(),
            });
        }
        if let Some(ref filters) = status_filter
            && filters
                .iter()
                .any(|s| matches!(s, TenantStatus::Provisioning))
        {
            return Err(AmError::Validation {
                detail: "status_filter cannot contain `provisioning` (SDK-invisible)".into(),
            });
        }
        Ok(Self {
            parent_id,
            status_filter,
            top,
            skip,
        })
    }

    /// Read-only access to the validated `status_filter`. `None` means
    /// "default visibility set" — the repo applies its own SDK-visible
    /// default (`Active + Suspended`).
    ///
    /// An empty filter (`Some(vec![])` constructed via
    /// [`Self::new`]) is permitted and is treated identically to
    /// `None` by the repo: both fall through to the default
    /// SDK-visible set rather than producing an empty result. The
    /// only filter content [`Self::new`] rejects is a non-empty
    /// vector containing [`TenantStatus::Provisioning`].
    #[must_use]
    pub fn status_filter(&self) -> Option<&[TenantStatus]> {
        self.status_filter.as_deref()
    }
}

/// Page returned by `TenantRepo::list_children`.
#[domain_model]
#[derive(Debug, Clone)]
pub struct TenantPage {
    pub items: Vec<TenantModel>,
    pub top: u32,
    pub skip: u32,
    pub total: Option<u64>,
}

/// Filter consumed by `TenantRepo::count_children`.
///
/// `Provisioning` rows are *always* counted; the variants only differ in
/// how they treat `Deleted` rows. The split exists because the two
/// service-layer call sites have different semantics:
///
/// * Soft-delete preconditions ask "are there any **non-deleted**
///   children?" → [`ChildCountFilter::NonDeleted`].
/// * The hard-delete leaf-first guard asks "is *anything* still under
///   this tenant — even soft-deleted descendants the reaper hasn't
///   collected yet?" → [`ChildCountFilter::All`].
#[domain_model]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ChildCountFilter {
    /// Counts `Provisioning + Active + Suspended` (excludes `Deleted`
    /// only).
    NonDeleted,
    /// Counts every status, including `Deleted`.
    All,
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn smallint_round_trip_is_total_over_known_values() {
        for s in [
            TenantStatus::Provisioning,
            TenantStatus::Active,
            TenantStatus::Suspended,
            TenantStatus::Deleted,
        ] {
            let v = s.as_smallint();
            assert_eq!(TenantStatus::from_smallint(v), Some(s));
        }
    }

    #[test]
    fn from_smallint_rejects_unknown_values() {
        assert_eq!(TenantStatus::from_smallint(-1), None);
        assert_eq!(TenantStatus::from_smallint(4), None);
        assert_eq!(TenantStatus::from_smallint(42), None);
    }

    #[test]
    fn is_sdk_visible_excludes_provisioning_only() {
        assert!(!TenantStatus::Provisioning.is_sdk_visible());
        assert!(TenantStatus::Active.is_sdk_visible());
        assert!(TenantStatus::Suspended.is_sdk_visible());
        assert!(TenantStatus::Deleted.is_sdk_visible());
    }

    #[test]
    fn empty_update_is_empty() {
        assert!(TenantUpdate::default().is_empty());
        assert!(
            !TenantUpdate {
                name: Some("x".into()),
                ..Default::default()
            }
            .is_empty()
        );
        assert!(
            !TenantUpdate {
                status: Some(TenantStatus::Active),
                ..Default::default()
            }
            .is_empty()
        );
    }

    #[test]
    fn status_transition_active_suspended_allowed() {
        TenantUpdate::validate_status_transition(TenantStatus::Active, TenantStatus::Suspended)
            .expect("active -> suspended ok");
        TenantUpdate::validate_status_transition(TenantStatus::Suspended, TenantStatus::Active)
            .expect("suspended -> active ok");
    }

    #[test]
    fn status_transition_no_op_rejected() {
        // Strict contract: PATCH only permits the cross-flip; resending
        // the current status is a no-op that would still trigger a
        // wasted closure-rewrite, so it surfaces as `Conflict`.
        let active_active =
            TenantUpdate::validate_status_transition(TenantStatus::Active, TenantStatus::Active)
                .expect_err("A->A must reject");
        assert_eq!(active_active.code(), "conflict");
        let suspended_suspended = TenantUpdate::validate_status_transition(
            TenantStatus::Suspended,
            TenantStatus::Suspended,
        )
        .expect_err("S->S must reject");
        assert_eq!(suspended_suspended.code(), "conflict");
    }

    #[test]
    fn status_transition_to_deleted_rejected() {
        let err =
            TenantUpdate::validate_status_transition(TenantStatus::Active, TenantStatus::Deleted)
                .expect_err("reject");
        assert_eq!(err.code(), "conflict");
    }

    #[test]
    fn status_transition_from_provisioning_rejected() {
        let err = TenantUpdate::validate_status_transition(
            TenantStatus::Provisioning,
            TenantStatus::Active,
        )
        .expect_err("reject");
        assert_eq!(err.code(), "conflict");
    }

    #[test]
    fn status_transition_from_deleted_rejected() {
        let err =
            TenantUpdate::validate_status_transition(TenantStatus::Deleted, TenantStatus::Active)
                .expect_err("reject");
        assert_eq!(err.code(), "conflict");
    }

    #[test]
    fn name_length_validation_rejects_empty_and_oversized() {
        assert!(TenantUpdate::validate_name("a").is_ok());
        assert!(TenantUpdate::validate_name(&"x".repeat(255)).is_ok());
        assert_eq!(
            TenantUpdate::validate_name("")
                .expect_err("empty rejected")
                .code(),
            "validation"
        );
        assert_eq!(
            TenantUpdate::validate_name(&"x".repeat(256))
                .expect_err("too long rejected")
                .code(),
            "validation"
        );
    }

    #[test]
    fn list_children_query_rejects_provisioning_in_status_filter() {
        // Provisioning rows are SDK-invisible; the constructor must
        // reject any filter that names them so a bogus internal caller
        // cannot leak them via list_children.
        let err = ListChildrenQuery::new(
            Uuid::nil(),
            Some(vec![TenantStatus::Active, TenantStatus::Provisioning]),
            10,
            0,
        )
        .expect_err("provisioning must be rejected");
        assert_eq!(err.code(), "validation");
    }

    #[test]
    fn list_children_query_accepts_sdk_visible_filters() {
        let q = ListChildrenQuery::new(
            Uuid::nil(),
            Some(vec![
                TenantStatus::Active,
                TenantStatus::Suspended,
                TenantStatus::Deleted,
            ]),
            10,
            0,
        )
        .expect("sdk-visible filter accepted");
        assert_eq!(q.status_filter().expect("filter").len(), 3);
    }

    #[test]
    fn list_children_query_accepts_none_filter() {
        let q = ListChildrenQuery::new(Uuid::nil(), None, 10, 0).expect("none accepted");
        assert!(q.status_filter().is_none());
    }

    #[test]
    fn list_children_query_rejects_zero_top() {
        // The public OpenAPI contract sets `$top` minimum to 1.
        // Accepting 0 here would silently turn an invalid request
        // into an empty page rather than surfacing a validation
        // error to the caller.
        let err =
            ListChildrenQuery::new(Uuid::nil(), None, 0, 0).expect_err("top=0 must be rejected");
        assert_eq!(err.code(), "validation");
    }
}
