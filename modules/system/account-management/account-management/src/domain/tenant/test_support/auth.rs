//! Mock PDP plumbing for service-level `#[tokio::test]` blocks. Two
//! shapes are exposed:
//!
//! * [`mock_enforcer`] wires [`MockAuthZResolver`], a permissive PDP
//!   that emits a single
//!   [`InTenantSubtree`](modkit_security::ScopeFilter::in_tenant_subtree)
//!   constraint rooted at the caller's `subject_tenant_id`. Mirrors
//!   the production policy bundle's "permit + clamp to caller's
//!   subtree" shape. Account Management calls
//!   `access_scope_with(... require_constraints(true))`, so an
//!   empty-constraint PDP would surface as
//!   [`AccessRequest::require_constraints`]-fail; the
//!   subject-rooted subtree clamp keeps every existing test
//!   passing because tests act within their subject's own subtree.
//! * [`constraint_bearing_enforcer`] wires
//!   [`ConstraintBearingAuthZResolver`], which models a
//!   policy-bundle-style PDP that pins the subtree root explicitly
//!   to a caller-supplied tenant id. Used by the regression tests
//!   in `service_tests.rs` that pin the post-#1813 subtree-clamp
//!   contract: an authorized read / update / soft-delete on a
//!   tenant **inside** the root's subtree MUST succeed; an
//!   authorized action on a tenant **outside** the root's subtree
//!   MUST collapse to `NotFound` at the database via the secure-
//!   extension layer.

#![allow(dead_code, clippy::must_use_candidate, clippy::missing_panics_doc)]

use std::sync::Arc;

use async_trait::async_trait;
use authz_resolver_sdk::{
    AuthZResolverClient, AuthZResolverError, PolicyEnforcer,
    models::{Capability, EvaluationRequest, EvaluationResponse, EvaluationResponseContext},
};
use modkit_macros::domain_model;

/// Build a permit-with-subtree-clamp [`EvaluationResponse`] rooted at
/// `root_tenant_id`. Centralises the production-shape predicate
/// emission so both mocks below stay in sync.
fn permit_with_subtree(root_tenant_id: uuid::Uuid) -> EvaluationResponse {
    use authz_resolver_sdk::constraints::{Constraint, InTenantSubtreePredicate, Predicate};
    use modkit_security::pep_properties;

    EvaluationResponse {
        decision: true,
        context: EvaluationResponseContext {
            constraints: vec![Constraint {
                predicates: vec![Predicate::InTenantSubtree(InTenantSubtreePredicate::new(
                    pep_properties::RESOURCE_ID,
                    root_tenant_id,
                ))],
            }],
            deny_reason: None,
        },
    }
}

/// Permissive PDP fake for service / handler tests.
///
/// Reads the caller's `subject.properties["tenant_id"]` (populated by
/// the PEP per the `AuthZEN` spec) and emits a single
/// [`InTenantSubtree`](modkit_security::ScopeFilter::in_tenant_subtree)
/// constraint rooted at that tenant. Every existing service-level test
/// uses `ctx_for(root)`, so the compiled scope clamps to the root's
/// subtree — which transparently covers every tenant the test mutates.
/// Cross-tenant denial in production is owned by the real PDP behind a
/// `PolicyEnforcer` fed by the Tenant Resolver Plugin; the negative
/// path is regression-pinned by
/// [`ConstraintBearingAuthZResolver`] below.
#[domain_model]
pub struct MockAuthZResolver;

#[async_trait]
impl AuthZResolverClient for MockAuthZResolver {
    async fn evaluate(
        &self,
        request: EvaluationRequest,
    ) -> Result<EvaluationResponse, AuthZResolverError> {
        // Pluck the subject's tenant id out of the AuthZEN-spec
        // `subject.properties["tenant_id"]` slot the PEP builder
        // wrote. A missing / malformed slot is a test-wiring bug
        // (the production PEP at `authz-resolver-sdk::pep::enforcer`
        // always writes a stringified `Uuid`) — panic loudly so the
        // bug surfaces as a clear failure instead of as a confusing
        // empty-subtree `NotFound`.
        let root_str = request
            .subject
            .properties
            .get("tenant_id")
            .and_then(serde_json::Value::as_str)
            .expect(
                "MockAuthZResolver: subject.properties[\"tenant_id\"] is missing or not a string; \
                 build SecurityContext via SecurityContext::builder().subject_tenant_id(_) so \
                 the PEP enforcer populates the AuthZEN-spec slot",
            );
        let root = uuid::Uuid::parse_str(root_str).expect(
            "MockAuthZResolver: subject.properties[\"tenant_id\"] is not a valid UUID; \
             SecurityContext::builder takes a Uuid so this should be unreachable",
        );
        Ok(permit_with_subtree(root))
    }
}

/// Build a permissive [`PolicyEnforcer`] for tests. Pairs with
/// [`make_service`] and the inline `make_service` helpers used by the
/// service-level `#[tokio::test]` blocks.
#[must_use]
pub fn mock_enforcer() -> PolicyEnforcer {
    let authz: Arc<dyn AuthZResolverClient> = Arc::new(MockAuthZResolver);
    // Mirror the production wiring in `module.rs`: AM advertises
    // `TenantHierarchy` so the PDP returns the native
    // `InTenantSubtree` predicate. Without the capability the
    // production PDP would downgrade to a pre-resolved `In`, and
    // tests using this enforcer would diverge from the production
    // request shape.
    PolicyEnforcer::new(authz).with_capabilities(vec![Capability::TenantHierarchy])
}

/// PDP fake that pins the subtree root explicitly to a caller-supplied
/// tenant id, regardless of the request's subject tenant. Used by the
/// regression tests that exercise the cross-subtree denial contract:
/// caller scoped to root, target tenant outside root's subtree → the
/// compiled subtree-clamp at the database collapses the row to
/// `NotFound` even though the PDP-side `decision: true` lets the
/// service-layer gate through.
#[domain_model]
pub struct ConstraintBearingAuthZResolver {
    /// Root tenant id the synthetic
    /// [`InTenantSubtree`](modkit_security::ScopeFilter::in_tenant_subtree)
    /// predicate is rooted at. The compiled `AccessScope` clamps reads
    /// on `tenants.id` to that root's closure subtree via
    /// `tenant_closure`.
    pub root_tenant_id: uuid::Uuid,
}

#[async_trait]
impl AuthZResolverClient for ConstraintBearingAuthZResolver {
    async fn evaluate(
        &self,
        request: EvaluationRequest,
    ) -> Result<EvaluationResponse, AuthZResolverError> {
        let _ = request;
        Ok(permit_with_subtree(self.root_tenant_id))
    }
}

/// Build a [`PolicyEnforcer`] backed by [`ConstraintBearingAuthZResolver`].
/// The compiled scope clamps reads on the `tenants` entity (and any
/// other entity declaring an `OWNER_TENANT_ID` / `RESOURCE_ID` column
/// against the `InTenantSubtree` predicate) to the closure subtree
/// rooted at `root_tenant_id`.
#[must_use]
pub fn constraint_bearing_enforcer(root_tenant_id: uuid::Uuid) -> PolicyEnforcer {
    let authz: Arc<dyn AuthZResolverClient> =
        Arc::new(ConstraintBearingAuthZResolver { root_tenant_id });
    PolicyEnforcer::new(authz).with_capabilities(vec![Capability::TenantHierarchy])
}
