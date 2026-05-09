//! AM-row to SDK-type projection helpers and provisioning-invisibility
//! filter construction.
//!
//! Every projection here is a pure function: AM column values in,
//! SDK type out. Provisioning rows are filtered out structurally at
//! query time via [`tenants_visible_status_condition`] /
//! [`closure_visible_status_condition`]; the projection helpers
//! themselves trust that the caller has already excluded provisioning
//! rows from the row set they pass in.
//!
//! # `tenant_type` reverse hydration
//!
//! DESIGN §3.1 / FEATURE §3 require the public chained `tenant_type`
//! identifier to be resolved through `TypesRegistryClient`. The
//! resolution itself happens in [`super::queries`] (which owns the
//! registry handle and can batch lookups across a page); the
//! projection helpers here accept the already-resolved
//! `Option<String>` and place it onto the SDK type. Per DESIGN §3.4
//! / §5 the resolution layer fails closed with
//! `TenantResolverError::Internal` on any registry failure, so on
//! the hot path the projection helpers always receive `Some(...)`;
//! the SDK field type is `Option<String>` purely so the projection
//! layer can model "row hydration succeeded but `tenant_type` is
//! intentionally absent" — a state the plugin does not produce
//! today but the SDK contract leaves open.

use sea_orm::{ColumnTrait, Condition};
use tenant_resolver_sdk::{TenantId, TenantInfo, TenantRef, TenantStatus as SdkTenantStatus};

use crate::domain::tenant::model::TenantStatus as DomainTenantStatus;
use crate::infra::storage::entity::tenants;

/// Map AM's domain `TenantStatus` (4-variant, includes `Provisioning`)
/// onto the SDK-visible 3-variant enum. Returns `None` for
/// `Provisioning` so callers fail closed if a provisioning row ever
/// reaches projection — by design the query-time filter should prevent
/// that, but the `None` arm is the defense-in-depth catch.
#[must_use]
pub(super) fn map_status_to_sdk(status: DomainTenantStatus) -> Option<SdkTenantStatus> {
    match status {
        DomainTenantStatus::Active => Some(SdkTenantStatus::Active),
        DomainTenantStatus::Suspended => Some(SdkTenantStatus::Suspended),
        DomainTenantStatus::Deleted => Some(SdkTenantStatus::Deleted),
        DomainTenantStatus::Provisioning => None,
    }
}

/// Map an SDK-visible `TenantStatus` onto AM's `SMALLINT` encoding
/// (1=Active, 2=Suspended, 3=Deleted). Used when translating
/// caller-supplied `status` filters into closure / tenants predicates.
#[must_use]
pub(super) fn sdk_status_to_smallint(status: SdkTenantStatus) -> i16 {
    match status {
        SdkTenantStatus::Active => DomainTenantStatus::Active.as_smallint(),
        SdkTenantStatus::Suspended => DomainTenantStatus::Suspended.as_smallint(),
        SdkTenantStatus::Deleted => DomainTenantStatus::Deleted.as_smallint(),
    }
}

/// Project a `tenants::Model` row onto the SDK `TenantInfo`.
///
/// `tenant_type` is supplied by the caller — resolved via
/// `TypesRegistryClient::get_type_schema_by_uuid` (single) or
/// `get_type_schemas_by_uuid` (batched) in `super::queries`. Per
/// DESIGN §3.4, a registry failure causes the SDK call to fail with
/// `TenantResolverError::Internal` before this helper is reached, so
/// callers always pass `Some(...)` on the hot path.
///
/// Returns `None` when the row is provisioning (defense-in-depth —
/// the query layer should already have excluded it) or when its
/// `status` column carries an out-of-domain value.
#[must_use]
pub(super) fn row_to_tenant_info(
    row: tenants::Model,
    tenant_type: Option<String>,
) -> Option<TenantInfo> {
    let domain_status = DomainTenantStatus::from_smallint(row.status)?;
    let sdk_status = map_status_to_sdk(domain_status)?;
    Some(TenantInfo {
        id: TenantId(row.id),
        name: row.name,
        status: sdk_status,
        tenant_type,
        parent_id: row.parent_id.map(TenantId),
        self_managed: row.self_managed,
    })
}

/// Project a `tenants::Model` row onto the SDK `TenantRef` (no name).
///
/// `tenant_type` and error semantics identical to [`row_to_tenant_info`]:
/// callers pass `Some(...)` on the hot path (registry failures are
/// propagated as `Internal` before reaching here); `None` arm is the
/// defense-in-depth catch for provisioning / out-of-domain-status rows.
#[must_use]
pub(super) fn row_to_tenant_ref(
    row: &tenants::Model,
    tenant_type: Option<String>,
) -> Option<TenantRef> {
    let domain_status = DomainTenantStatus::from_smallint(row.status)?;
    let sdk_status = map_status_to_sdk(domain_status)?;
    Some(TenantRef {
        id: TenantId(row.id),
        status: sdk_status,
        tenant_type,
        parent_id: row.parent_id.map(TenantId),
        self_managed: row.self_managed,
    })
}

/// Build the unconditional provisioning-exclusion predicate on the
/// `tenants.status` column. Used on every `tenants` read on the SDK
/// path, regardless of caller-supplied status filter, to enforce
/// `cpt-cf-tr-plugin-fr-provisioning-invisibility` structurally.
#[must_use]
pub(super) fn tenants_visible_status_condition() -> Condition {
    Condition::all().add(tenants::Column::Status.ne(DomainTenantStatus::Provisioning.as_smallint()))
}

/// Build the SDK-visible status filter predicate for `tenants.status`.
/// An empty `statuses` slice means "all SDK-visible statuses" (the
/// caller still gets the structural provisioning exclusion combined in
/// at the call site).
#[must_use]
pub(super) fn tenants_status_in_condition(statuses: &[SdkTenantStatus]) -> Condition {
    if statuses.is_empty() {
        return tenants_visible_status_condition();
    }
    let mut any = Condition::any();
    for s in statuses {
        any = any.add(tenants::Column::Status.eq(sdk_status_to_smallint(*s)));
    }
    Condition::all()
        .add(any)
        .add(tenants_visible_status_condition())
}
