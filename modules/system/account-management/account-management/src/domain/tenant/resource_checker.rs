//! Resource-ownership check trait used by `soft_delete`.
//!
//! AM has to reject soft-delete when the tenant still owns resource-group
//! rows (DESIGN §3.5). The check itself is owned by the `resource-group`
//! module, which exposes a typed client; AM holds a trait-object slot so
//! the production wiring can plug in the real client without threading a
//! third generic parameter through `TenantService<R, P>`.
//!
//! Dev deployments (and most unit tests) bind [`InertResourceOwnershipChecker`],
//! which always returns `0` — equivalent to "no RG module running".

use async_trait::async_trait;
use modkit_macros::domain_model;
use uuid::Uuid;

use crate::domain::error::AmError;

/// Contract for counting the number of resource-group rows that still
/// name `tenant_id` as their owner. A non-zero count rejects soft-delete
/// with [`AmError::TenantHasResources`].
#[async_trait]
pub trait ResourceOwnershipChecker: Send + Sync {
    /// Returns the number of RG rows owned by `tenant_id`. Any I/O
    /// failure MUST be funnelled through [`AmError`] so the service
    /// layer can surface it through the normal error taxonomy.
    async fn count_ownership_links(&self, tenant_id: Uuid) -> Result<u64, AmError>;
}

/// No-op checker — always reports zero ownership. Used when the AM
/// module boots without a resource-group client wired up.
#[domain_model]
#[derive(Debug, Default, Clone)]
pub struct InertResourceOwnershipChecker;

#[async_trait]
impl ResourceOwnershipChecker for InertResourceOwnershipChecker {
    async fn count_ownership_links(&self, _tenant_id: Uuid) -> Result<u64, AmError> {
        Ok(0)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn inert_checker_always_returns_zero() {
        let c = InertResourceOwnershipChecker;
        assert_eq!(
            c.count_ownership_links(Uuid::from_u128(0x1))
                .await
                .expect("ok"),
            0
        );
    }
}
