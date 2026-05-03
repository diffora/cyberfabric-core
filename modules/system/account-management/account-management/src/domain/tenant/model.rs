//! Tenant domain model types — internal storage / saga shapes.
//!
//! Pure Rust value types that express tenant lifecycle concepts
//! independently of storage and transport. The `SeaORM` entities live in
//! `crate::infra::storage::entity::{tenants, tenant_closure}`. Public
//! input / output DTOs (request bodies, query parameters, response
//! envelopes) live on [`account_management_sdk`] and reuse
//! [`account_management_sdk::TenantInfo`] / [`account_management_sdk::TenantStatus`]
//! (re-exported from `tenant-resolver-sdk`) on the public boundary —
//! no duplicated tenant DTOs across CF SDKs.
//!
//! What stays here:
//! * [`TenantStatus`] — internal 4-variant lifecycle (includes
//!   `Provisioning`, which is never surfaced through the public SDK).
//! * [`TenantModel`] — full storage row (with `tenant_type_uuid`,
//!   `depth`, lifecycle timestamps).
//! * [`NewTenant`] — repo-level insert input.
//! * [`ChildCountFilter`] — repo-level filter for `count_children`.
//! * `validate_*` free functions — domain validation reused by the
//!   service before mutating the DB through the SDK input shapes.

use modkit_macros::domain_model;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::domain::error::DomainError;

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

    /// Stable lowercase label used in audit payloads and structured
    /// logs. Pinned here (rather than as `Display` or via `serde`) so
    /// the wire shape is independent of any future derive changes.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Provisioning => "provisioning",
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::Deleted => "deleted",
        }
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
/// Returns [`DomainError::Conflict`] when the transition is rejected
/// by one of the rules above. Matches the
/// [`crate::domain::tenant::repo::TenantRepo::update_tenant_mutable`]
/// contract — every failed transition is a state-precondition
/// conflict, not an input-schema validation error. Both
/// [`DomainError::Conflict`] and [`DomainError::Validation`] surface
/// as HTTP 400 through the canonical error mapping in
/// [`crate::infra::canonical_mapping`] (`failed_precondition` and
/// `invalid_argument` AIP-193 statuses respectively); the public
/// SDK contract intentionally keeps both under 400 so clients
/// distinguish via the canonical reason rather than the HTTP code.
// @cpt-begin:cpt-cf-account-management-dod-tenant-hierarchy-management-status-change-non-cascading:p1:inst-dod-status-transition-guard
pub fn validate_status_transition(
    current: TenantStatus,
    target: TenantStatus,
) -> Result<(), DomainError> {
    if matches!(target, TenantStatus::Deleted) {
        return Err(DomainError::Conflict {
            detail: "status=deleted must go through DELETE flow".into(),
        });
    }
    if matches!(target, TenantStatus::Provisioning) {
        return Err(DomainError::Conflict {
            detail: "status=provisioning is internal; not patchable".into(),
        });
    }
    match (current, target) {
        (TenantStatus::Active, TenantStatus::Suspended)
        | (TenantStatus::Suspended, TenantStatus::Active) => Ok(()),
        _ => Err(DomainError::Conflict {
            detail: format!(
                "invalid status transition from {current:?} to {target:?}; \
                 PATCH only accepts the cross-flip Active<->Suspended"
            ),
        }),
    }
}
// @cpt-end:cpt-cf-account-management-dod-tenant-hierarchy-management-status-change-non-cascading:p1:inst-dod-status-transition-guard

/// Validate that `name`, if present, falls within the `OpenAPI`
/// `minLength: 1, maxLength: 255` bounds.
///
/// # Errors
///
/// Returns [`DomainError::Validation`] when the name is shorter than 1
/// or longer than 255 characters (by `char` count, not byte length).
pub fn validate_tenant_name(name: &str) -> Result<(), DomainError> {
    let len = name.chars().count();
    if !(1..=255).contains(&len) {
        return Err(DomainError::Validation {
            detail: format!("name length {len} out of range [1,255]"),
        });
    }
    Ok(())
}

/// Lift a SDK [`account_management_sdk::TenantStatus`] (3-variant,
/// public surface) into the AM-internal 4-variant
/// [`TenantStatus`]. Infallible because the SDK type cannot represent
/// `Provisioning`.
impl From<account_management_sdk::TenantStatus> for TenantStatus {
    fn from(s: account_management_sdk::TenantStatus) -> Self {
        match s {
            account_management_sdk::TenantStatus::Active => Self::Active,
            account_management_sdk::TenantStatus::Suspended => Self::Suspended,
            account_management_sdk::TenantStatus::Deleted => Self::Deleted,
        }
    }
}

/// Lower the AM-internal 4-variant [`TenantStatus`] into the SDK
/// 3-variant [`account_management_sdk::TenantStatus`].
///
/// # Panics
///
/// Panics on [`TenantStatus::Provisioning`]. Service-layer public
/// methods filter Provisioning rows out via
/// [`TenantStatus::is_sdk_visible`] **before** mapping a row to
/// [`account_management_sdk::TenantInfo`], so this arm is unreachable
/// in correct code; reaching it is a programmer error and
/// [`unreachable!`] surfaces the invariant violation loudly.
impl From<TenantStatus> for account_management_sdk::TenantStatus {
    fn from(s: TenantStatus) -> Self {
        match s {
            TenantStatus::Active => Self::Active,
            TenantStatus::Suspended => Self::Suspended,
            TenantStatus::Deleted => Self::Deleted,
            TenantStatus::Provisioning => unreachable!(
                "Provisioning rows must be filtered (is_sdk_visible) before lowering to SDK TenantStatus"
            ),
        }
    }
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
#[path = "model_tests.rs"]
mod model_tests;
