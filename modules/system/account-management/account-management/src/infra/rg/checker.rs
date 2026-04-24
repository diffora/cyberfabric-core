//! `RgResourceOwnershipChecker` — production
//! [`crate::domain::tenant::resource_checker::ResourceOwnershipChecker`]
//! wired against `resource_group_sdk::ResourceGroupClient` resolved
//! from `ClientHub`.
//!
//! Replaces the placeholder
//! [`crate::domain::tenant::resource_checker::InertResourceOwnershipChecker`]
//! production wiring so the soft-delete ownership probe (DESIGN §3.5)
//! reflects real Resource Group rows when the RG module is deployed
//! alongside AM.
//!
//! ## Probe shape
//!
//! `soft_delete` only needs a boolean ("does the child tenant own at
//! least one RG row?") to drive the [`AmError::TenantHasResources`]
//! rejection. The implementation issues:
//!
//! ```text
//! list_groups(ctx, $top=1, $filter=hierarchy/tenant_id eq <child>)
//! ```
//!
//! and reports `1` when the page has any items, `0` otherwise. The
//! caller's [`SecurityContext`] is propagated so RG-side `AuthZ` +
//! `SecureORM` apply the parent's `AccessScope` (which already covers
//! descendants per RG PRD §4); the `OData` filter narrows the answer to
//! the *specific* child tenant rather than the whole reachable subtree
//! — without that filter an unfiltered `list_groups($top=1)` would
//! return non-empty whenever any sibling owns RG rows, over-blocking
//! soft-delete.
//!
//! ## Coordination
//!
//! Depends on cyberfabric/cyberfabric-core#1626 (adding
//! `hierarchy/tenant_id` to the `GroupFilterField` whitelist). Until
//! that lands the `OData` filter is rejected at validation time and the
//! probe surfaces as [`AmError::ServiceUnavailable`]. AM-side code is
//! mergeable now because the existing checker is already a no-op stub
//! (returns `0` regardless), so the integration semantics do not
//! regress.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use modkit_odata::ODataQuery;
use modkit_odata::ast::{CompareOperator, Expr, Value};
use modkit_security::SecurityContext;
use resource_group_sdk::ResourceGroupClient;
use uuid::Uuid;

use crate::domain::error::AmError;
use crate::domain::tenant::resource_checker::ResourceOwnershipChecker;

/// `OData` identifier for the tenant-scope column on `ResourceGroup`.
///
/// Tracked in `GroupFilterField::HierarchyTenantId` once
/// cyberfabric/cyberfabric-core#1626 lands; using the literal here keeps
/// AM independent of the SDK's enum-variant rollout.
const HIERARCHY_TENANT_ID_FIELD: &str = "hierarchy/tenant_id";

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
    // @cpt-begin:cpt-cf-account-management-algo-tenant-hierarchy-management-soft-delete-preconditions:p1:inst-algo-sdelpc-rg-probe
    async fn count_ownership_links(
        &self,
        ctx: &SecurityContext,
        tenant_id: Uuid,
    ) -> Result<u64, AmError> {
        // `$top=1` — we only need a boolean answer; the actual count is
        // never read by `soft_delete`, which compares against zero.
        let query = ODataQuery::default()
            .with_limit(1)
            .with_filter(Expr::Compare(
                Box::new(Expr::Identifier(HIERARCHY_TENANT_ID_FIELD.to_owned())),
                CompareOperator::Eq,
                Box::new(Expr::Value(Value::Uuid(tenant_id))),
            ));
        match tokio::time::timeout(self.probe_timeout, self.client.list_groups(ctx, &query)).await {
            Err(_elapsed) => Err(AmError::ServiceUnavailable {
                detail: "resource-group: timeout exceeded".into(),
            }),
            Ok(Err(err)) => Err(AmError::ServiceUnavailable {
                detail: format!("resource-group: {err}"),
            }),
            Ok(Ok(page)) => Ok(u64::from(!page.items.is_empty())),
        }
    }
    // @cpt-end:cpt-cf-account-management-algo-tenant-hierarchy-management-soft-delete-preconditions:p1:inst-algo-sdelpc-rg-probe
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[allow(clippy::expect_used, clippy::unwrap_used, reason = "test helpers")]
mod tests {
    use super::*;
    use modkit_odata::Page;
    use resource_group_sdk::{
        CreateGroupRequest, CreateTypeRequest, GroupHierarchy, ResourceGroup, ResourceGroupError,
        ResourceGroupMembership, ResourceGroupType, ResourceGroupWithDepth, UpdateGroupRequest,
        UpdateTypeRequest,
    };
    use std::sync::Mutex;

    #[allow(
        clippy::enum_variant_names,
        reason = "test fake mirrors RG `list_*` operations under test; the `List` prefix names the operation, not the variant kind"
    )]
    #[derive(Clone)]
    enum FakeBehaviour {
        ListEmpty,
        ListNonEmpty,
        ListErr,
        ListDelay(Duration),
    }

    struct FakeRgClient {
        behaviour: Mutex<FakeBehaviour>,
        list_calls: Mutex<u32>,
        last_filter: Mutex<Option<Expr>>,
    }

    impl FakeRgClient {
        fn empty() -> Self {
            Self {
                behaviour: Mutex::new(FakeBehaviour::ListEmpty),
                list_calls: Mutex::new(0),
                last_filter: Mutex::new(None),
            }
        }

        fn non_empty() -> Self {
            Self {
                behaviour: Mutex::new(FakeBehaviour::ListNonEmpty),
                list_calls: Mutex::new(0),
                last_filter: Mutex::new(None),
            }
        }

        fn unavailable() -> Self {
            Self {
                behaviour: Mutex::new(FakeBehaviour::ListErr),
                list_calls: Mutex::new(0),
                last_filter: Mutex::new(None),
            }
        }

        fn slow(delay: Duration) -> Self {
            Self {
                behaviour: Mutex::new(FakeBehaviour::ListDelay(delay)),
                list_calls: Mutex::new(0),
                last_filter: Mutex::new(None),
            }
        }
    }

    fn sample_group(tenant_id: Uuid) -> ResourceGroup {
        ResourceGroup {
            id: Uuid::from_u128(0xDEAD),
            code: "gts.cf.core.rg.type.v1~example.v1~".into(),
            name: "sample".into(),
            hierarchy: GroupHierarchy {
                parent_id: None,
                tenant_id,
            },
            metadata: None,
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
            query: &ODataQuery,
        ) -> Result<Page<ResourceGroup>, ResourceGroupError> {
            *self.list_calls.lock().expect("lock") += 1;
            *self.last_filter.lock().expect("lock") = query.filter().cloned();
            let behaviour = self.behaviour.lock().expect("lock").clone();
            match behaviour {
                FakeBehaviour::ListEmpty => Ok(Page::empty(1)),
                FakeBehaviour::ListNonEmpty => Ok(Page::new(
                    vec![sample_group(Uuid::from_u128(0xAB))],
                    modkit_odata::page::PageInfo {
                        next_cursor: None,
                        prev_cursor: None,
                        limit: 1,
                    },
                )),
                FakeBehaviour::ListErr => {
                    Err(ResourceGroupError::service_unavailable("rg backend down"))
                }
                FakeBehaviour::ListDelay(delay) => {
                    tokio::time::sleep(delay).await;
                    Ok(Page::empty(1))
                }
            }
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
            unreachable!("not used by RgResourceOwnershipChecker")
        }
    }

    #[tokio::test]
    async fn rg_checker_returns_zero_on_empty_page() {
        let client = Arc::new(FakeRgClient::empty());
        let checker = RgResourceOwnershipChecker::new(client.clone());
        let count = checker
            .count_ownership_links(&SecurityContext::anonymous(), Uuid::from_u128(0xAB))
            .await
            .expect("rg up => count");
        assert_eq!(count, 0);
        assert_eq!(*client.list_calls.lock().expect("lock"), 1);
        // Filter must reference the typed `hierarchy/tenant_id` field —
        // mis-naming would silently match nothing on the RG side.
        let recorded = client.last_filter.lock().expect("lock").clone();
        let recorded = recorded.expect("filter recorded");
        match recorded {
            Expr::Compare(lhs, CompareOperator::Eq, rhs) => {
                assert!(matches!(*lhs, Expr::Identifier(ref s) if s == HIERARCHY_TENANT_ID_FIELD));
                assert!(matches!(*rhs, Expr::Value(Value::Uuid(u)) if u == Uuid::from_u128(0xAB)));
            }
            other => panic!("unexpected filter shape: {other:?}"),
        }
    }

    #[tokio::test]
    async fn rg_checker_returns_one_on_non_empty_page() {
        let client = Arc::new(FakeRgClient::non_empty());
        let checker = RgResourceOwnershipChecker::new(client.clone());
        let count = checker
            .count_ownership_links(&SecurityContext::anonymous(), Uuid::from_u128(0xAB))
            .await
            .expect("rg up => count");
        // Probe is `$top=1`; soft_delete only checks `> 0`, so reporting
        // `1` is sufficient — no need to drag back the full count.
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn rg_checker_propagates_client_failure_as_service_unavailable() {
        let client = Arc::new(FakeRgClient::unavailable());
        let checker = RgResourceOwnershipChecker::new(client);
        let err = checker
            .count_ownership_links(&SecurityContext::anonymous(), Uuid::from_u128(0xCD))
            .await
            .expect_err("rg down => err");
        assert!(matches!(err, AmError::ServiceUnavailable { .. }));
        assert_eq!(err.code(), "service_unavailable");
        assert_eq!(err.http_status(), 503);
    }

    #[tokio::test(start_paused = true)]
    async fn rg_checker_times_out_client_probe() {
        let client = Arc::new(FakeRgClient::slow(Duration::from_millis(50)));
        let checker = RgResourceOwnershipChecker::with_timeout(client.clone(), 10);
        let err = checker
            .count_ownership_links(&SecurityContext::anonymous(), Uuid::from_u128(0xEF))
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
