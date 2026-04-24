//! Tenant-type compatibility barrier — Feature 2.3 (`tenant-type-enforcement`).
//!
//! Pre-write barrier invoked by saga step 3 (`inst-algo-saga-type-check`) of
//! `algo-tenant-hierarchy-management-create-tenant-saga` before any
//! `tenants` or `tenant_closure` row is rewritten. Evaluates the parent
//! `tenant_type` against the child type's `allowed_parent_types` trait
//! resolved through the GTS Types Registry (`gts.x.core.am.tenant_type.v1~`).
//!
//! This module owns the **trait abstraction**. Two implementations exist:
//!
//! * [`InertTenantTypeChecker`] — admits everything. Used in dev / tests
//!   and as the production fallback when no GTS Types Registry client is
//!   resolved from `ClientHub`.
//! * `GtsTenantTypeChecker` (in `crate::infra::types_registry::checker`)
//!   — the real implementation that wraps `types_registry_sdk::TypesRegistryClient`.
//!
//! Failure mapping per FEATURE §6:
//!
//! * Child / parent type pairing not allowed → [`AmError::TypeNotAllowed`]
//!   (HTTP 409, `sub_code = type_not_allowed`).
//! * Same-type nesting not permitted → [`AmError::TypeNotAllowed`].
//! * Registry unreachable / trait-resolution failure →
//!   [`AmError::ServiceUnavailable`] (HTTP 503, `sub_code = service_unavailable`).
//! * Child type not registered / malformed trait → [`AmError::InvalidTenantType`]
//!   (HTTP 422, `sub_code = invalid_tenant_type`).

use std::sync::{Arc, Once};

use async_trait::async_trait;
use modkit_macros::domain_model;
use uuid::Uuid;

use crate::domain::error::AmError;

static STRICT_BARRIERS_NO_UUID_LOOKUP_WARN_ONCE: Once = Once::new();

/// Pre-write tenant-type compatibility barrier.
///
/// Implementations resolve the GTS `allowed_parent_types` trait for both
/// the child and parent tenant types and answer one yes/no question:
/// is this parent / child type pairing admitted by the registered
/// schema? Same-type nesting is admitted iff the type's
/// `allowed_parent_types` trait contains the type's own chained GTS
/// identifier (per `algo-same-type-nesting-admission`).
///
/// The barrier MUST NOT cache type definitions across calls
/// (`dod-tenant-type-enforcement-gts-availability-surface`); every
/// invocation re-resolves against GTS so trait updates and re-types
/// take effect immediately.
#[async_trait]
pub trait TenantTypeChecker: Send + Sync {
    /// Validate parent-child type compatibility.
    ///
    /// # Errors
    ///
    /// * [`AmError::TypeNotAllowed`] — the parent type is not a member of
    ///   the child type's effective `allowed_parent_types`, or same-type
    ///   nesting was requested but the trait does not include the child
    ///   type's own identifier.
    /// * [`AmError::InvalidTenantType`] — the child type is not
    ///   registered or its effective trait is malformed.
    /// * [`AmError::ServiceUnavailable`] — the GTS Types Registry is
    ///   unreachable, times out, or returns a trait-resolution failure.
    // @cpt-begin:cpt-cf-account-management-algo-tenant-type-enforcement-allowed-parent-types-evaluation:p1:inst-algo-apte-trait-contract
    // @cpt-begin:cpt-cf-account-management-algo-tenant-type-enforcement-same-type-nesting-admission:p1:inst-algo-stn-trait-contract
    async fn check_parent_child(&self, parent_type: Uuid, child_type: Uuid) -> Result<(), AmError>;
    // @cpt-end:cpt-cf-account-management-algo-tenant-type-enforcement-same-type-nesting-admission:p1:inst-algo-stn-trait-contract
    // @cpt-end:cpt-cf-account-management-algo-tenant-type-enforcement-allowed-parent-types-evaluation:p1:inst-algo-apte-trait-contract
}

/// No-op checker — admits every parent / child pairing. Used in dev,
/// tests, and as the production fallback when AM boots without a
/// `TypesRegistryClient` resolved from `ClientHub`. Mirrors the
/// `NoopProvisioner` fallback pattern used for the optional `IdP`
/// plugin.
#[domain_model]
#[derive(Debug, Default, Clone)]
pub struct InertTenantTypeChecker;

#[async_trait]
impl TenantTypeChecker for InertTenantTypeChecker {
    async fn check_parent_child(
        &self,
        _parent_type: Uuid,
        _child_type: Uuid,
    ) -> Result<(), AmError> {
        Ok(())
    }
}

/// Build an `Arc<dyn TenantTypeChecker>` over [`InertTenantTypeChecker`].
/// Used by tests and the `module.rs` dev-fallback wiring so callers
/// don't have to spell out the `Arc::new(InertTenantTypeChecker)` form
/// at every site.
#[must_use]
pub fn inert_tenant_type_checker() -> Arc<dyn TenantTypeChecker + Send + Sync> {
    Arc::new(InertTenantTypeChecker)
}

/// Emit the strict-barrier UUID-lookup gap warning at most once per
/// process. The production GTS checker calls this when
/// `strict_barriers=true` converts the current reachability-only probe
/// into a fail-closed result.
pub(crate) fn warn_strict_barriers_no_uuid_lookup_once() {
    STRICT_BARRIERS_NO_UUID_LOOKUP_WARN_ONCE.call_once(|| {
        tracing::warn!(
            target: "am::checkers::strict_barriers",
            "strict_barriers=true with no UUID-keyed get; failing closed"
        );
    });
}

/// Fail-closed error returned while the Types Registry SDK does not
/// expose UUID-keyed tenant-type lookups.
pub(crate) fn strict_barriers_no_uuid_lookup_error() -> AmError {
    AmError::ServiceUnavailable {
        detail:
            "tenant-type checker: no UUID-keyed lookup; failing closed under strict_barriers=true"
                .into(),
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn inert_checker_admits_every_pairing() {
        let c = InertTenantTypeChecker;
        let parent = Uuid::from_u128(0x1);
        let child = Uuid::from_u128(0x2);
        c.check_parent_child(parent, child)
            .await
            .expect("inert admits any pairing");
    }

    #[tokio::test]
    async fn inert_checker_admits_same_type_nesting() {
        let c = InertTenantTypeChecker;
        let same = Uuid::from_u128(0x3);
        c.check_parent_child(same, same)
            .await
            .expect("inert admits same-type nesting");
    }
}
