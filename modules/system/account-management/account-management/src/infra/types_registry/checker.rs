//! `GtsTenantTypeChecker` — the production [`TenantTypeChecker`] wired
//! against `types_registry_sdk::TypesRegistryClient` resolved from
//! `ClientHub`.
//!
//! Implements `algo-allowed-parent-types-evaluation`:
//!
//! 1. Probe the GTS Types Registry for both `child_tenant_type` and
//!    `parent_tenant_type`.
//! 2. Resolve each chained type's effective `allowed_parent_types` trait
//!    (via `x-gts-traits` resolution; the SDK exposes the resolved
//!    schema content directly so AM does not duplicate the resolution
//!    pipeline).
//! 3. Admit iff the parent's chained identifier is a member of the
//!    child's effective `allowed_parent_types`, with the same-type
//!    nesting rule applied per `algo-same-type-nesting-admission`.
//! 4. Map registry transport / trait-resolution failures onto
//!    [`AmError::ServiceUnavailable`].
//!
//! ## SDK gap (documented for FEATURE 2.3)
//!
//! `types_registry_sdk::TypesRegistryClient::get` takes a chained GTS
//! identifier (`&str`) and the AM trait surface speaks `Uuid` (the form
//! persisted on `TenantModel.tenant_type_uuid`). Until the registry SDK
//! adds a UUID-keyed lookup or the AM tenant model carries the chained
//! string alongside the UUID, this implementation:
//!
//! * Issues a [`TypesRegistryClient::list`] probe to verify the registry
//!   itself is reachable. Transport failure here propagates as
//!   [`AmError::ServiceUnavailable`].
//! * On success, admits the pairing and emits a `tracing` debug log
//!   recording the parent / child UUIDs that were checked. This
//!   preserves the barrier's invocation contract
//!   (`dod-tenant-type-enforcement-type-barrier-invocation-contract`)
//!   without falsely admitting when the registry is down.
//!
//! Once the SDK or domain model evolves, the inner `check_parent_child`
//! body is the only call site that needs to change — the wiring through
//! `module.rs` and the public `TenantTypeChecker` contract remain stable.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tracing::warn;
use types_registry_sdk::{ListQuery, TypesRegistryClient};
use uuid::Uuid;

use crate::domain::error::AmError;
use crate::domain::tenant_type::checker::{
    TenantTypeChecker, strict_barriers_no_uuid_lookup_error,
    warn_strict_barriers_no_uuid_lookup_once,
};

/// Production [`TenantTypeChecker`] backed by the GTS Types Registry.
pub struct GtsTenantTypeChecker {
    registry: Arc<dyn TypesRegistryClient + Send + Sync>,
    strict_barriers: bool,
    probe_timeout: Duration,
}

impl GtsTenantTypeChecker {
    /// Construct a new checker around a registry client resolved from
    /// `ClientHub`, using backward-compatible defaults.
    #[must_use]
    pub fn new(registry: Arc<dyn TypesRegistryClient + Send + Sync>) -> Self {
        Self::with_config(registry, false, 2_000)
    }

    /// Construct a checker with module configuration.
    #[must_use]
    pub fn with_config(
        registry: Arc<dyn TypesRegistryClient + Send + Sync>,
        strict_barriers: bool,
        probe_timeout_ms: u64,
    ) -> Self {
        Self {
            registry,
            strict_barriers,
            probe_timeout: Duration::from_millis(probe_timeout_ms.max(1)),
        }
    }
}

#[async_trait]
impl TenantTypeChecker for GtsTenantTypeChecker {
    async fn check_parent_child(&self, parent_type: Uuid, child_type: Uuid) -> Result<(), AmError> {
        // Probe the registry to verify it is reachable. A transport-layer
        // failure here MUST propagate as `service_unavailable` so the
        // calling saga returns 503 with no DB side effects
        // (`dod-tenant-type-enforcement-gts-availability-surface`).
        // @cpt-begin:cpt-cf-account-management-dod-tenant-type-enforcement-gts-availability-surface:p1:inst-dod-gts-availability-probe
        let probe = ListQuery::default()
            .with_is_type(true)
            .with_pattern("gts.x.core.am.tenant_type.v1~*");
        match tokio::time::timeout(self.probe_timeout, self.registry.list(probe)).await {
            Err(_elapsed) => Err(AmError::ServiceUnavailable {
                detail: "types-registry: timeout exceeded".into(),
            }),
            Ok(Err(err)) => Err(AmError::ServiceUnavailable {
                detail: format!("types-registry: {err}"),
            }),
            Ok(Ok(_entities)) => {
                if self.strict_barriers {
                    warn_strict_barriers_no_uuid_lookup_once();
                    return Err(strict_barriers_no_uuid_lookup_error());
                }
                // Stub-admit: the SDK does not yet expose a UUID-keyed
                // schema lookup, so we admit every (parent_type, child_type)
                // pair as long as the registry is reachable — the real
                // hierarchy enforcement is a no-op. Logged at `warn!`
                // (not `debug!`) so the gap is visible to operators in
                // production until the SDK adds the real lookup primitive.
                warn!(
                    target: "am.tenant_type",
                    parent_type = %parent_type,
                    child_type = %child_type,
                    "tenant_type compatibility probe succeeded; admitting (UUID-keyed schema lookup not yet exposed by types-registry-sdk; type-hierarchy enforcement is a no-op)"
                );
                Ok(())
            }
        }
        // @cpt-end:cpt-cf-account-management-dod-tenant-type-enforcement-gts-availability-surface:p1:inst-dod-gts-availability-probe
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[allow(clippy::expect_used, clippy::unwrap_used, reason = "test helpers")]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use types_registry_sdk::{GtsEntity, RegisterResult, TypesRegistryError};

    /// Toy in-memory client used by the wiring tests. Drives the two
    /// branches of `GtsTenantTypeChecker::check_parent_child`.
    #[allow(
        clippy::enum_variant_names,
        reason = "test fake mirrors the registry `list_*` operations under test; the `List` prefix names the operation, not the variant kind"
    )]
    #[derive(Clone)]
    enum FakeBehaviour {
        ListOk,
        ListErr(TypesRegistryError),
        ListDelay(Duration),
    }

    struct FakeRegistry {
        behaviour: Mutex<FakeBehaviour>,
        list_calls: Mutex<u32>,
    }

    impl FakeRegistry {
        fn ok() -> Self {
            Self {
                behaviour: Mutex::new(FakeBehaviour::ListOk),
                list_calls: Mutex::new(0),
            }
        }

        fn unavailable() -> Self {
            Self {
                behaviour: Mutex::new(FakeBehaviour::ListErr(TypesRegistryError::internal(
                    "registry down",
                ))),
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
    impl TypesRegistryClient for FakeRegistry {
        async fn register(
            &self,
            _entities: Vec<serde_json::Value>,
        ) -> Result<Vec<RegisterResult>, TypesRegistryError> {
            unreachable!("not used by GtsTenantTypeChecker")
        }

        async fn list(&self, _query: ListQuery) -> Result<Vec<GtsEntity>, TypesRegistryError> {
            *self.list_calls.lock().expect("lock") += 1;
            let behaviour = self.behaviour.lock().expect("lock").clone();
            match behaviour {
                FakeBehaviour::ListOk => Ok(Vec::new()),
                FakeBehaviour::ListErr(err) => Err(err),
                FakeBehaviour::ListDelay(delay) => {
                    tokio::time::sleep(delay).await;
                    Ok(Vec::new())
                }
            }
        }

        async fn get(&self, _gts_id: &str) -> Result<GtsEntity, TypesRegistryError> {
            unreachable!("not used by GtsTenantTypeChecker")
        }
    }

    #[tokio::test]
    async fn gts_checker_admits_when_registry_is_reachable() {
        let registry = Arc::new(FakeRegistry::ok());
        let checker = GtsTenantTypeChecker::new(registry.clone());
        let parent = Uuid::from_u128(0x10);
        let child = Uuid::from_u128(0x20);
        checker
            .check_parent_child(parent, child)
            .await
            .expect("registry up => admit");
        assert_eq!(*registry.list_calls.lock().expect("lock"), 1);
    }

    #[tokio::test]
    async fn gts_checker_propagates_registry_unavailable_as_service_unavailable() {
        let registry = Arc::new(FakeRegistry::unavailable());
        let checker = GtsTenantTypeChecker::new(registry);
        let parent = Uuid::from_u128(0x30);
        let child = Uuid::from_u128(0x40);
        let err = checker
            .check_parent_child(parent, child)
            .await
            .expect_err("registry down => err");
        assert!(matches!(err, AmError::ServiceUnavailable { .. }));
        assert_eq!(err.code(), "service_unavailable");
        assert_eq!(err.http_status(), 503);
    }

    #[tokio::test(start_paused = true)]
    async fn gts_checker_times_out_registry_probe() {
        let registry = Arc::new(FakeRegistry::slow(Duration::from_millis(50)));
        let checker = GtsTenantTypeChecker::with_config(registry.clone(), false, 10);
        let err = checker
            .check_parent_child(Uuid::from_u128(0x50), Uuid::from_u128(0x60))
            .await
            .expect_err("slow registry => timeout");
        assert!(matches!(err, AmError::ServiceUnavailable { .. }));
        assert!(
            err.to_string().contains("types-registry: timeout exceeded"),
            "got: {err}"
        );
        assert_eq!(*registry.list_calls.lock().expect("lock"), 1);
    }

    #[tokio::test]
    async fn gts_checker_strict_barriers_fail_closed_for_uuid_lookup_gap() {
        let registry = Arc::new(FakeRegistry::ok());
        let checker = GtsTenantTypeChecker::with_config(registry, true, 2_000);
        let err = checker
            .check_parent_child(Uuid::from_u128(0x70), Uuid::from_u128(0x80))
            .await
            .expect_err("strict barriers reject stub-admit path");
        assert!(matches!(err, AmError::ServiceUnavailable { .. }));
        assert!(
            err.to_string()
                .contains("no UUID-keyed lookup; failing closed"),
            "got: {err}"
        );
    }
}
