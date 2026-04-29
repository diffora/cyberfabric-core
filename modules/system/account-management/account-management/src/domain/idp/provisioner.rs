//! `IdP` tenant-provisioning contract.
//!
//! Defines [`IdpTenantProvisioner`] with three methods:
//! [`IdpTenantProvisioner::check_availability`],
//! [`IdpTenantProvisioner::provision_tenant`], and
//! [`IdpTenantProvisioner::deprovision_tenant`] (the last carries a
//! default impl returning [`DeprovisionFailure::UnsupportedOperation`]
//! so providers can opt into the deletion pipeline incrementally).
//!
//! The method is called during saga step 2 of the create-tenant flow
//! (DESIGN §3.3 `seq-create-child`). It runs **outside** any database
//! transaction — the provisioning step is an external side effect that
//! must not hold locks in `tenants`.
//!
//! # Failure model
//!
//! The Ok variant carries optional metadata produced by the provider,
//! which the service persists alongside the `active` status flip in
//! saga step 3. The Err variant is a [`ProvisionFailure`] discriminating
//! between:
//!
//! * [`ProvisionFailure::CleanFailure`] — AM can prove no `IdP`-side state
//!   was retained (connection refused before send, 4xx from the provider
//!   with a contract-defined "nothing retained" semantic). The service
//!   runs the compensating TX, deletes the `provisioning` row, and
//!   surfaces `idp_unavailable`. This is the only retry-safe failure mode.
//! * [`ProvisionFailure::Ambiguous`] — transport failure / timeout / 5xx
//!   where the provider may or may not have retained state. The service
//!   leaves the `provisioning` row for the provisioning reaper to
//!   compensate asynchronously and surfaces `internal`. Not retry-safe
//!   without reconciliation.
//! * [`ProvisionFailure::UnsupportedOperation`] — the provider signalled
//!   that the requested provisioning cannot be performed at all. The
//!   service surfaces `idp_unsupported_operation`; compensation rules
//!   match the `CleanFailure` path (nothing was ever written provider-side).

use async_trait::async_trait;
use modkit_macros::domain_model;
use serde_json::Value;
use uuid::Uuid;

use crate::domain::error::AmError;

/// Context passed to [`IdpTenantProvisioner::provision_tenant`].
///
/// Carries the identifiers and opaque provider metadata produced during
/// the pre-provisioning validation step. The `tenant_type` here is the
/// full chained GTS identifier (DESIGN §3.1 "Input and storage format");
/// the `parent_id` is always `Some` for child-tenant creation and
/// `None` during the root-bootstrap path (root bootstrap is owned by
/// `BootstrapService`, not in scope for Phase 1).
#[domain_model]
#[derive(Debug, Clone)]
pub struct ProvisionRequest {
    pub tenant_id: Uuid,
    pub parent_id: Option<Uuid>,
    pub name: String,
    pub tenant_type: String,
    /// Opaque provider-specific metadata from `TenantCreateRequest.provisioning_metadata`.
    pub metadata: Option<Value>,
}

/// Opaque result returned by the provider on success. The payload is
/// forwarded into `tenant_metadata` persistence during saga step 3
/// (ownership of that table is deferred to the `tenant-metadata`
/// feature); AM-only Phase 1 simply carries it through.
#[domain_model]
#[derive(Debug, Clone, Default)]
pub struct ProvisionResult {
    /// Optional provider-returned metadata entries. Empty vector means
    /// "provider performed the provisioning but produced no metadata" —
    /// this is the normal path for providers that establish the
    /// tenant-to-`IdP` binding through external configuration.
    pub metadata_entries: Vec<ProvisionMetadataEntry>,
}

/// Single metadata entry produced by the provider and persisted by AM.
#[domain_model]
#[derive(Debug, Clone)]
pub struct ProvisionMetadataEntry {
    pub schema_id: String,
    pub value: Value,
}

/// Failure discriminant for `provision_tenant`.
///
/// See module docs for compensation semantics.
#[domain_model]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProvisionFailure {
    /// AM can prove no `IdP`-side state was retained. Triggers the
    /// compensating TX that deletes the `provisioning` row.
    CleanFailure { detail: String },
    /// Outcome is uncertain; provider may have retained state. The
    /// provisioning reaper compensates asynchronously.
    Ambiguous { detail: String },
    /// Provider does not support the requested provisioning at all.
    /// Surfaces as `idp_unsupported_operation`.
    UnsupportedOperation { detail: String },
}

/// Failure discriminant for a non-mutating `IdP` availability probe.
///
/// Bootstrap uses this before starting the root-tenant saga so the
/// wait loop does not call [`IdpTenantProvisioner::provision_tenant`]
/// as a liveness check.
#[domain_model]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CheckAvailabilityFailure {
    /// No provider endpoint or plugin can be reached.
    Unreachable(String),
    /// Provider responded with a retryable health-check failure.
    TransientError(String),
}

impl CheckAvailabilityFailure {
    #[must_use]
    pub fn detail(&self) -> &str {
        match self {
            Self::Unreachable(detail) | Self::TransientError(detail) => detail,
        }
    }
}

impl ProvisionFailure {
    /// Map the failure onto the public [`AmError`] taxonomy:
    ///
    /// * `CleanFailure` → `idp_unavailable` (compensation already ran;
    ///   AM proved no provider state was retained).
    /// * `Ambiguous` → `internal` with a diagnostic carrying the
    ///   provider detail (provider may have retained state; the
    ///   provisioning reaper compensates asynchronously).
    /// * `UnsupportedOperation` → `idp_unsupported_operation`
    ///   (provider declined the entire operation; nothing was
    ///   written).
    #[must_use]
    pub fn into_am_error(self) -> AmError {
        match self {
            Self::CleanFailure { detail } => AmError::IdpUnavailable { detail },
            Self::Ambiguous { detail } => AmError::Internal {
                diagnostic: format!("idp provision ambiguous outcome: {detail}"),
                cause: None,
            },
            Self::UnsupportedOperation { detail } => AmError::IdpUnsupportedOperation { detail },
        }
    }

    /// Stable, snake-case metric-label form of this variant. Used as
    /// the `outcome` label on `AM_DEPENDENCY_HEALTH` counter samples
    /// emitted by the create-tenant saga; kept here so the producer
    /// (service layer) does not duplicate the variant → string mapping
    /// in match arms.
    #[must_use]
    pub const fn as_metric_label(&self) -> &'static str {
        match self {
            Self::CleanFailure { .. } => "clean_failure",
            Self::Ambiguous { .. } => "ambiguous",
            Self::UnsupportedOperation { .. } => "unsupported_operation",
        }
    }
}

/// Context passed to [`IdpTenantProvisioner::deprovision_tenant`] during
/// the hard-delete pipeline (Phase 3) or the provisioning reaper.
#[domain_model]
#[derive(Debug, Clone)]
pub struct DeprovisionRequest {
    pub tenant_id: Uuid,
}

/// Failure discriminant for `deprovision_tenant`.
///
/// See the hard-delete flow: a `Terminal` result means the tenant
/// cannot be deprovisioned by this provider and the operator must
/// intervene; `Retryable` defers to the next tick; `UnsupportedOperation`
/// is the default path that preserves Phase 1/2 behaviour when no
/// provider plugin is registered.
#[domain_model]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeprovisionFailure {
    /// Non-recoverable; logs/audits and skips the tenant this tick.
    Terminal { detail: String },
    /// Transient; defer the tenant to the next retention tick.
    Retryable { detail: String },
    /// Provider does not support deprovisioning at all.
    UnsupportedOperation { detail: String },
}

impl DeprovisionFailure {
    /// Map the failure onto the public [`AmError`] taxonomy. `Terminal`
    /// becomes [`AmError::Internal`] (non-leaky diagnostic), `Retryable`
    /// becomes [`AmError::IdpUnavailable`], `UnsupportedOperation`
    /// becomes [`AmError::IdpUnsupportedOperation`].
    #[must_use]
    pub fn into_am_error(self) -> AmError {
        match self {
            Self::Terminal { detail } => AmError::Internal {
                diagnostic: format!("idp deprovision terminal failure: {detail}"),
                cause: None,
            },
            Self::Retryable { detail } => AmError::IdpUnavailable { detail },
            Self::UnsupportedOperation { detail } => AmError::IdpUnsupportedOperation { detail },
        }
    }

    /// Stable, snake-case metric-label form of this variant. Used as
    /// the `outcome` label on `AM_DEPENDENCY_HEALTH` counter samples
    /// emitted by the hard-delete pipeline; kept here so the producer
    /// (service layer) does not duplicate the variant → string mapping
    /// in match arms.
    #[must_use]
    pub const fn as_metric_label(&self) -> &'static str {
        match self {
            Self::Terminal { .. } => "terminal",
            Self::Retryable { .. } => "retryable",
            Self::UnsupportedOperation { .. } => "unsupported_operation",
        }
    }
}

/// Trait implemented by the deployment-specific `IdP` provider plugin.
///
/// Phase 1 ships [`IdpTenantProvisioner::provision_tenant`]; Phase 3
/// adds the deprovisioning counterpart with a default implementation
/// that returns [`DeprovisionFailure::UnsupportedOperation`] — so
/// existing plugins written against the Phase 1/2 contract continue to
/// compile without modification.
#[async_trait]
pub trait IdpTenantProvisioner: Send + Sync + 'static {
    /// Lightweight, non-mutating provider health probe.
    ///
    /// Implementations should use a HEAD / ping / SDK health endpoint
    /// and MUST NOT create or mutate provider-side tenant state.
    async fn check_availability(&self) -> Result<(), CheckAvailabilityFailure>;

    /// Create any `IdP`-side resources for the new tenant.
    ///
    /// Invariants:
    /// * Runs outside any DB transaction.
    /// * MUST NOT silently no-op — provider implementations that cannot
    ///   perform the operation MUST return
    ///   [`ProvisionFailure::UnsupportedOperation`].
    /// * Any transport-layer uncertainty MUST be reported as
    ///   [`ProvisionFailure::Ambiguous`]; the provider MUST NOT pretend a
    ///   timed-out request succeeded.
    async fn provision_tenant(
        &self,
        req: &ProvisionRequest,
    ) -> Result<ProvisionResult, ProvisionFailure>;

    /// Tear down `IdP`-side resources attached to the tenant.
    ///
    /// Default impl returns [`DeprovisionFailure::UnsupportedOperation`]
    /// so Phase 1/2 provider plugins do not need to change. Providers
    /// that own teardown MUST override this method.
    async fn deprovision_tenant(&self, req: &DeprovisionRequest) -> Result<(), DeprovisionFailure> {
        let _ = req;
        Err(DeprovisionFailure::UnsupportedOperation {
            detail: "deprovision_tenant not implemented".to_owned(),
        })
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn clean_failure_maps_to_idp_unavailable() {
        let err = ProvisionFailure::CleanFailure {
            detail: "conn refused".into(),
        }
        .into_am_error();
        assert_eq!(err.code(), "idp_unavailable");
    }

    #[test]
    fn unsupported_operation_maps_to_code_idp_unsupported_operation() {
        let err = ProvisionFailure::UnsupportedOperation {
            detail: "not supported by provider".into(),
        }
        .into_am_error();
        assert_eq!(err.code(), "idp_unsupported_operation");
    }

    #[test]
    fn deprovision_failure_maps_to_am_error() {
        // Terminal -> internal
        let t = DeprovisionFailure::Terminal {
            detail: "torched".into(),
        }
        .into_am_error();
        assert_eq!(t.code(), "internal");

        // Retryable -> idp_unavailable
        let r = DeprovisionFailure::Retryable {
            detail: "try later".into(),
        }
        .into_am_error();
        assert_eq!(r.code(), "idp_unavailable");

        // UnsupportedOperation -> idp_unsupported_operation
        let u = DeprovisionFailure::UnsupportedOperation {
            detail: "nope".into(),
        }
        .into_am_error();
        assert_eq!(u.code(), "idp_unsupported_operation");
    }

    #[test]
    fn deprovision_default_impl_returns_unsupported_operation() {
        use async_trait::async_trait;

        struct Stub;
        #[async_trait]
        impl IdpTenantProvisioner for Stub {
            async fn check_availability(&self) -> Result<(), CheckAvailabilityFailure> {
                Ok(())
            }

            async fn provision_tenant(
                &self,
                _req: &ProvisionRequest,
            ) -> Result<ProvisionResult, ProvisionFailure> {
                Ok(ProvisionResult::default())
            }
        }

        let fut = async move {
            let s = Stub;
            let req = DeprovisionRequest {
                tenant_id: Uuid::nil(),
            };
            let err = s.deprovision_tenant(&req).await.expect_err("default");
            assert!(matches!(
                err,
                DeprovisionFailure::UnsupportedOperation { .. }
            ));
        };
        // No tokio runtime needed for the assertion itself; run on the
        // inline current-thread runtime via `futures::executor`.
        futures::executor::block_on(fut);
    }
}
