//! `RgResourceOwnershipChecker` — production
//! [`crate::domain::tenant::resource_checker::ResourceOwnershipChecker`]
//! wired against `resource_group_sdk::ResourceGroupClient` resolved
//! from `ClientHub`.
//!
//! Replaces the placeholder [`crate::domain::tenant::resource_checker::InertResourceOwnershipChecker`]
//! production wiring so the soft-delete ownership probe (DESIGN §3.5)
//! reflects real Resource Group memberships when the RG module is
//! deployed alongside AM.
//!
//! ## SDK gap (documented for FEATURE 2.3 / PR1 follow-up)
//!
//! The current `resource_group_sdk::ResourceGroupClient` exposes
//! `list_memberships(query)` filtered by `(group_id, resource_type,
//! resource_id)` — the membership row itself is not tenant-scoped; the
//! tenant scope lives on the owning `ResourceGroup`. A direct
//! `count_memberships_by_tenant(tenant_id)` method does not exist yet.
//!
//! Until the SDK adds a tenant-scoped count surface (or AM grows a
//! join-on-group lookup), this implementation:
//!
//! * Issues a bounded list-memberships probe with default pagination to
//!   confirm the RG service is reachable. Transport failure here
//!   propagates as [`AmError::ServiceUnavailable`].
//! * Returns `0` on success — semantically equivalent to "no
//!   memberships found for this tenant" — and emits a `tracing::debug`
//!   log so operators see that the wiring went live but the count is
//!   currently a stub.
//!
//! Once the SDK exposes a tenant-scoped count, only the body of
//! `count_ownership_links` changes — the [`crate::module`] wiring,
//! the production fallback to [`crate::domain::tenant::resource_checker::InertResourceOwnershipChecker`],
//! and the public trait contract all stay stable.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use modkit_odata::ODataQuery;
use modkit_security::SecurityContext;
use resource_group_sdk::ResourceGroupClient;
use tracing::warn;
use uuid::Uuid;

use crate::domain::error::AmError;
use crate::domain::tenant::resource_checker::ResourceOwnershipChecker;

/// Production resource-ownership checker backed by the Resource Group
/// SDK.
pub struct RgResourceOwnershipChecker {
    client: Arc<dyn ResourceGroupClient + Send + Sync>,
    probe_timeout: Duration,
}

impl RgResourceOwnershipChecker {
    /// Construct a new checker around an RG client resolved from
    /// `ClientHub`, using the backward-compatible default timeout.
    #[must_use]
    pub fn new(client: Arc<dyn ResourceGroupClient + Send + Sync>) -> Self {
        Self::with_timeout(client, 2_000)
    }

    /// Construct a checker with the configured probe timeout.
    #[must_use]
    pub fn with_timeout(
        client: Arc<dyn ResourceGroupClient + Send + Sync>,
        probe_timeout_ms: u64,
    ) -> Self {
        Self {
            client,
            probe_timeout: Duration::from_millis(probe_timeout_ms.max(1)),
        }
    }
}

#[async_trait]
impl ResourceOwnershipChecker for RgResourceOwnershipChecker {
    async fn count_ownership_links(&self, tenant_id: Uuid) -> Result<u64, AmError> {
        // Reachability probe. The anonymous security context is
        // appropriate here because the soft-delete ownership check
        // runs on behalf of AM itself, not the calling user; the
        // tenant identity is encoded in `tenant_id` rather than in the
        // caller's home tenant.
        let ctx = SecurityContext::anonymous();
        // Cap the probe at 1 row — we only need a "service is reachable"
        // signal, not the full membership page. Without `with_limit(1)`
        // every soft-delete would transfer the RG default page size.
        // @cpt-begin:cpt-cf-account-management-algo-tenant-hierarchy-management-soft-delete-preconditions:p1:inst-algo-sdelpc-rg-probe
        let query = ODataQuery::default().with_limit(1);
        match tokio::time::timeout(
            self.probe_timeout,
            self.client.list_memberships(&ctx, &query),
        )
        .await
        {
            Err(_elapsed) => Err(AmError::ServiceUnavailable {
                detail: "resource-group: timeout exceeded".into(),
            }),
            Ok(Err(err)) => Err(AmError::ServiceUnavailable {
                detail: format!("resource-group: {err}"),
            }),
            Ok(Ok(_page)) => {
                // Stub-admit: the SDK does not yet expose a tenant-scoped
                // count surface, so we always return 0 ownership links —
                // which means soft-delete will never block on resource
                // ownership. Logged at `warn!` (not `debug!`) so the gap
                // is visible to operators in production until the SDK
                // adds the real count primitive.
                warn!(
                    target: "am.resource_check",
                    tenant_id = %tenant_id,
                    "rg list_memberships probe succeeded; returning 0 (tenant-scoped count not yet exposed by resource-group-sdk; ownership check is a no-op)"
                );
                Ok(0)
            }
        }
        // @cpt-end:cpt-cf-account-management-algo-tenant-hierarchy-management-soft-delete-preconditions:p1:inst-algo-sdelpc-rg-probe
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[allow(clippy::expect_used, clippy::unwrap_used, reason = "test helpers")]
mod tests {
    use super::*;
    use modkit_odata::Page;
    use resource_group_sdk::{
        CreateGroupRequest, CreateTypeRequest, ResourceGroup, ResourceGroupError,
        ResourceGroupMembership, ResourceGroupType, ResourceGroupWithDepth, UpdateGroupRequest,
        UpdateTypeRequest,
    };
    use std::sync::Mutex;

    #[derive(Clone, Copy)]
    enum FakeBehaviour {
        ListOk,
        ListErr,
        ListDelay(Duration),
    }

    struct FakeRgClient {
        behaviour: Mutex<FakeBehaviour>,
        list_calls: Mutex<u32>,
    }

    impl FakeRgClient {
        fn ok() -> Self {
            Self {
                behaviour: Mutex::new(FakeBehaviour::ListOk),
                list_calls: Mutex::new(0),
            }
        }

        fn unavailable() -> Self {
            Self {
                behaviour: Mutex::new(FakeBehaviour::ListErr),
                list_calls: Mutex::new(0),
            }
        }

        fn slow(delay: Duration) -> Self {
            Self {
                behaviour: Mutex::new(FakeBehaviour::ListDelay(delay)),
                list_calls: Mutex::new(0),
            }
        }
    }

    #[async_trait]
    impl ResourceGroupClient for FakeRgClient {
        async fn create_type(
            &self,
            _ctx: &SecurityContext,
            _request: CreateTypeRequest,
        ) -> Result<ResourceGroupType, ResourceGroupError> {
            unreachable!("not used by RgResourceOwnershipChecker")
        }
        async fn get_type(
            &self,
            _ctx: &SecurityContext,
            _code: &str,
        ) -> Result<ResourceGroupType, ResourceGroupError> {
            unreachable!()
        }
        async fn list_types(
            &self,
            _ctx: &SecurityContext,
            _query: &ODataQuery,
        ) -> Result<Page<ResourceGroupType>, ResourceGroupError> {
            unreachable!()
        }
        async fn update_type(
            &self,
            _ctx: &SecurityContext,
            _code: &str,
            _request: UpdateTypeRequest,
        ) -> Result<ResourceGroupType, ResourceGroupError> {
            unreachable!()
        }
        async fn delete_type(
            &self,
            _ctx: &SecurityContext,
            _code: &str,
        ) -> Result<(), ResourceGroupError> {
            unreachable!()
        }
        async fn create_group(
            &self,
            _ctx: &SecurityContext,
            _request: CreateGroupRequest,
        ) -> Result<ResourceGroup, ResourceGroupError> {
            unreachable!()
        }
        async fn get_group(
            &self,
            _ctx: &SecurityContext,
            _id: Uuid,
        ) -> Result<ResourceGroup, ResourceGroupError> {
            unreachable!()
        }
        async fn list_groups(
            &self,
            _ctx: &SecurityContext,
            _query: &ODataQuery,
        ) -> Result<Page<ResourceGroup>, ResourceGroupError> {
            unreachable!()
        }
        async fn update_group(
            &self,
            _ctx: &SecurityContext,
            _id: Uuid,
            _request: UpdateGroupRequest,
        ) -> Result<ResourceGroup, ResourceGroupError> {
            unreachable!()
        }
        async fn delete_group(
            &self,
            _ctx: &SecurityContext,
            _id: Uuid,
        ) -> Result<(), ResourceGroupError> {
            unreachable!()
        }
        async fn get_group_descendants(
            &self,
            _ctx: &SecurityContext,
            _group_id: Uuid,
            _query: &ODataQuery,
        ) -> Result<Page<ResourceGroupWithDepth>, ResourceGroupError> {
            unreachable!()
        }
        async fn get_group_ancestors(
            &self,
            _ctx: &SecurityContext,
            _group_id: Uuid,
            _query: &ODataQuery,
        ) -> Result<Page<ResourceGroupWithDepth>, ResourceGroupError> {
            unreachable!()
        }
        async fn add_membership(
            &self,
            _ctx: &SecurityContext,
            _group_id: Uuid,
            _resource_type: &str,
            _resource_id: &str,
        ) -> Result<ResourceGroupMembership, ResourceGroupError> {
            unreachable!()
        }
        async fn remove_membership(
            &self,
            _ctx: &SecurityContext,
            _group_id: Uuid,
            _resource_type: &str,
            _resource_id: &str,
        ) -> Result<(), ResourceGroupError> {
            unreachable!()
        }
        async fn list_memberships(
            &self,
            _ctx: &SecurityContext,
            _query: &ODataQuery,
        ) -> Result<Page<ResourceGroupMembership>, ResourceGroupError> {
            *self.list_calls.lock().expect("lock") += 1;
            let behaviour = *self.behaviour.lock().expect("lock");
            match behaviour {
                FakeBehaviour::ListOk => Ok(Page::empty(0)),
                FakeBehaviour::ListErr => {
                    Err(ResourceGroupError::service_unavailable("rg backend down"))
                }
                FakeBehaviour::ListDelay(delay) => {
                    tokio::time::sleep(delay).await;
                    Ok(Page::empty(0))
                }
            }
        }
    }

    #[tokio::test]
    async fn rg_checker_returns_count_from_client() {
        let client = Arc::new(FakeRgClient::ok());
        let checker = RgResourceOwnershipChecker::new(client.clone());
        let count = checker
            .count_ownership_links(Uuid::from_u128(0xAB))
            .await
            .expect("rg up => count");
        // Stubbed count is 0 today (see SDK gap in module docs).
        assert_eq!(count, 0);
        assert_eq!(*client.list_calls.lock().expect("lock"), 1);
    }

    #[tokio::test]
    async fn rg_checker_propagates_client_failure_as_service_unavailable() {
        let client = Arc::new(FakeRgClient::unavailable());
        let checker = RgResourceOwnershipChecker::new(client);
        let err = checker
            .count_ownership_links(Uuid::from_u128(0xCD))
            .await
            .expect_err("rg down => err");
        assert!(matches!(err, AmError::ServiceUnavailable { .. }));
        assert_eq!(err.sub_code(), "service_unavailable");
        assert_eq!(err.http_status(), 503);
    }

    #[tokio::test(start_paused = true)]
    async fn rg_checker_times_out_client_probe() {
        let client = Arc::new(FakeRgClient::slow(Duration::from_millis(50)));
        let checker = RgResourceOwnershipChecker::with_timeout(client.clone(), 10);
        let err = checker
            .count_ownership_links(Uuid::from_u128(0xEF))
            .await
            .expect_err("slow rg => timeout");
        assert!(matches!(err, AmError::ServiceUnavailable { .. }));
        assert!(
            err.to_string().contains("resource-group: timeout exceeded"),
            "got: {err}"
        );
        assert_eq!(*client.list_calls.lock().expect("lock"), 1);
    }
}
