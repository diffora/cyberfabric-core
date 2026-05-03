//! Always-permit mock PDP + `PolicyEnforcer` factory used by the
//! service-level `#[tokio::test]` blocks. Account Management currently
//! calls the PDP with `require_constraints(false)`, so this mock returns
//! an unconstrained allow response and intentionally does not model
//! constraint-bearing PDP output.

#![allow(dead_code, clippy::must_use_candidate, clippy::missing_panics_doc)]

use std::sync::Arc;

use async_trait::async_trait;
use authz_resolver_sdk::{
    AuthZResolverClient, AuthZResolverError, PolicyEnforcer,
    models::{EvaluationRequest, EvaluationResponse, EvaluationResponseContext},
};
use modkit_macros::domain_model;

/// Always-permit mock PDP for service / handler tests.
///
/// Returns `decision: true` with no constraints (i.e. compiles to
/// [`AccessScope::allow_all`]). Cross-tenant denial in production is
/// owned by the PDP behind a real `PolicyEnforcer` fed by the Tenant
/// Resolver Plugin (separate PR in this stack); this mock therefore
/// stays minimal — tests that need cross-tenant behaviour land
/// alongside the resolver plugin, not here.
#[domain_model]
pub struct MockAuthZResolver;

#[async_trait]
impl AuthZResolverClient for MockAuthZResolver {
    async fn evaluate(
        &self,
        request: EvaluationRequest,
    ) -> Result<EvaluationResponse, AuthZResolverError> {
        // AM service tests exercise the current decision-only path:
        // `require_constraints(false)` compiles an empty constraint
        // set to `AccessScope::allow_all`.
        let _ = request;
        Ok(EvaluationResponse {
            decision: true,
            context: EvaluationResponseContext::default(),
        })
    }
}

/// Build a permissive [`PolicyEnforcer`] for tests. Pairs with
/// [`make_service`] and the inline `make_service` helpers used by the
/// service-level `#[tokio::test]` blocks.
#[must_use]
pub fn mock_enforcer() -> PolicyEnforcer {
    let authz: Arc<dyn AuthZResolverClient> = Arc::new(MockAuthZResolver);
    PolicyEnforcer::new(authz)
}
