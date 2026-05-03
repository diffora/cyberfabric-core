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
//!   surfaces [`DomainError::ServiceUnavailable`] (HTTP 503). This is
//!   the only retry-safe failure mode.
//! * [`ProvisionFailure::Ambiguous`] — transport failure / timeout / 5xx
//!   where the provider may or may not have retained state. The service
//!   leaves the `provisioning` row for the provisioning reaper to
//!   compensate asynchronously and surfaces [`DomainError::Internal`]
//!   (HTTP 500). Not retry-safe without reconciliation.
//! * [`ProvisionFailure::UnsupportedOperation`] — the provider signalled
//!   that the requested provisioning cannot be performed at all. The
//!   service surfaces [`DomainError::UnsupportedOperation`] (HTTP 501);
//!   compensation rules match the `CleanFailure` path (nothing was ever
//!   written provider-side).

use std::hash::{Hash, Hasher};

use async_trait::async_trait;
use fnv::FnvHasher;
use modkit_macros::domain_model;
use serde_json::Value;
use uuid::Uuid;

use crate::domain::error::DomainError;

/// Stable, non-secret correlation handle for a provider-supplied error
/// detail. The raw text can carry vendor SDK strings, hostnames, or
/// token-bearing fragments — even into operator logs (which have a
/// longer retention horizon than the request envelope) those values
/// must not surface verbatim. Operators correlate the hash + length
/// across `am.idp` log events and audit rows; the inverse mapping
/// stays inside the audit-only `Internal::diagnostic` field where
/// access is governed by the audit-storage policy.
///
/// FNV-1a is chosen over [`std::hash::DefaultHasher`] precisely because
/// `DefaultHasher`'s output is **not guaranteed stable** between Rust
/// versions (stdlib doc: "the algorithms used … are not specified").
/// A toolchain upgrade would break correlation between audit records
/// emitted by older binaries and newer ones — the inverse of what a
/// forensic correlation handle is for. FNV-1a's spec is pinned, so
/// `digest=0x{...}` matches across upgrades. Collision resistance is
/// not a concern here: this is a non-cryptographic forensic handle,
/// not a security primitive (the inverse mapping is held in the
/// audit-only `diagnostic` field).
fn redact_provider_detail(detail: &str) -> (u64, usize) {
    let mut hasher = FnvHasher::default();
    detail.hash(&mut hasher);
    (hasher.finish(), detail.chars().count())
}

/// Context passed to [`IdpTenantProvisioner::provision_tenant`].
///
/// Carries the identifiers and opaque provider metadata produced during
/// the pre-provisioning validation step. The `tenant_type` here is the
/// full chained GTS identifier (DESIGN §3.1 "Input and storage format");
/// `parent_id` is `Some` for child-tenant creation and `None` during
/// the root-bootstrap path (`BootstrapService` saga step 2). Provider
/// implementations **MUST** handle both cases — `parent_id = None` is
/// not a degenerate placeholder, it is the canonical root-bootstrap
/// signal.
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
    /// Map the failure onto the public [`DomainError`] taxonomy:
    ///
    /// * `CleanFailure` → [`DomainError::ServiceUnavailable`] (HTTP 503;
    ///   compensation already ran; AM proved no provider state was
    ///   retained). Provider-supplied `detail` is **not** forwarded into
    ///   the public envelope: vendor SDK strings can carry endpoint
    ///   names, hostnames, or token-bearing fragments, and the
    ///   `with_detail` contract on `modkit-canonical-errors` mandates
    ///   pre-redacted public text. The raw detail is logged at
    ///   `am.idp` and reaches operators via trace correlation.
    /// * `Ambiguous` → [`DomainError::Internal`] (HTTP 500) with the
    ///   provider detail kept in the audit-only `diagnostic` field
    ///   (provider may have retained state; the provisioning reaper
    ///   compensates asynchronously).
    /// * `UnsupportedOperation` → [`DomainError::UnsupportedOperation`]
    ///   (HTTP 501); the boundary mapping further redacts the public
    ///   message (provider detail kept private — see
    ///   `infra::canonical_mapping`).
    #[allow(
        clippy::cognitive_complexity,
        reason = "flat 3-arm match with redact + warn! per arm; splitting fragments the variant→DomainError mapping reviewers must eyeball-check"
    )]
    #[must_use]
    pub fn into_am_error(self) -> DomainError {
        match self {
            Self::CleanFailure { detail } => {
                let (digest, len) = redact_provider_detail(&detail);
                tracing::warn!(
                    target: "am.idp",
                    provider_detail_digest = digest,
                    provider_detail_len = len,
                    "IdP provision CleanFailure; surfacing generic ServiceUnavailable, raw detail redacted (correlate via digest + audit-only diagnostic)"
                );
                DomainError::service_unavailable(
                    "identity provider unavailable; provisioning compensated",
                )
            }
            Self::Ambiguous { detail } => {
                // `DomainError::Internal::diagnostic` is forwarded
                // verbatim into the public `Problem.detail` by
                // `infra::canonical_mapping::From<DomainError> for
                // CanonicalError`, so the raw provider text MUST NOT
                // appear here even though the variant doc historically
                // described it as audit-only. Redact at construction
                // and correlate via digest.
                let (digest, len) = redact_provider_detail(&detail);
                tracing::warn!(
                    target: "am.idp",
                    provider_detail_digest = digest,
                    provider_detail_len = len,
                    "IdP provision Ambiguous outcome; surfacing generic Internal, raw detail redacted"
                );
                DomainError::Internal {
                    diagnostic: format!(
                        "idp provision ambiguous outcome (provider detail redacted; \
                         digest=0x{digest:016x} len={len})"
                    ),
                    cause: None,
                }
            }
            Self::UnsupportedOperation { detail } => {
                // The canonical-mapping boundary logs `detail` on a
                // `tracing::warn!` for operator correlation; that
                // makes the variant's `detail` field part of the
                // operator-log surface. Redact it at construction so
                // the long-lived log retains correlation without the
                // raw vendor text.
                let (digest, len) = redact_provider_detail(&detail);
                tracing::warn!(
                    target: "am.idp",
                    provider_detail_digest = digest,
                    provider_detail_len = len,
                    "IdP provision UnsupportedOperation; raw detail redacted"
                );
                DomainError::UnsupportedOperation {
                    detail: format!(
                        "provider declined the operation (detail redacted; \
                         digest=0x{digest:016x} len={len})"
                    ),
                }
            }
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
    /// Map the failure onto the public [`DomainError`] taxonomy:
    ///
    /// * `Terminal` → [`DomainError::Internal`] (HTTP 500). The raw
    ///   provider detail is **not** forwarded into the variant —
    ///   `Internal::diagnostic` is exposed as the public `Problem.detail`
    ///   by the canonical-mapping boundary, so the variant carries a
    ///   redacted summary and the raw text is logged at `am.idp` with
    ///   a digest for operator correlation.
    /// * `Retryable` → [`DomainError::ServiceUnavailable`] (HTTP 503).
    ///   Provider-supplied `detail` is **not** forwarded into the public
    ///   envelope (same vendor-text-leak rationale as
    ///   [`ProvisionFailure::CleanFailure`]); raw detail is logged at
    ///   `am.idp` for operator correlation via digest.
    /// * `UnsupportedOperation` → [`DomainError::UnsupportedOperation`]
    ///   (HTTP 501); the variant's `detail` field is logged verbatim by
    ///   the canonical-mapping boundary, so the raw provider text is
    ///   redacted at construction here.
    #[allow(
        clippy::cognitive_complexity,
        reason = "flat 3-arm match with redact + warn! per arm; splitting fragments the variant→DomainError mapping reviewers must eyeball-check"
    )]
    #[must_use]
    pub fn into_am_error(self) -> DomainError {
        match self {
            Self::Terminal { detail } => {
                let (digest, len) = redact_provider_detail(&detail);
                tracing::warn!(
                    target: "am.idp",
                    provider_detail_digest = digest,
                    provider_detail_len = len,
                    "IdP deprovision terminal failure; surfacing generic Internal, raw detail redacted"
                );
                DomainError::Internal {
                    diagnostic: format!(
                        "idp deprovision terminal failure (provider detail redacted; \
                         digest=0x{digest:016x} len={len})"
                    ),
                    cause: None,
                }
            }
            Self::Retryable { detail } => {
                let (digest, len) = redact_provider_detail(&detail);
                tracing::warn!(
                    target: "am.idp",
                    provider_detail_digest = digest,
                    provider_detail_len = len,
                    "IdP deprovision Retryable failure; surfacing generic ServiceUnavailable, raw detail redacted (correlate via digest)"
                );
                DomainError::service_unavailable(
                    "identity provider unavailable; deprovision will be retried",
                )
            }
            Self::UnsupportedOperation { detail } => {
                let (digest, len) = redact_provider_detail(&detail);
                tracing::warn!(
                    target: "am.idp",
                    provider_detail_digest = digest,
                    provider_detail_len = len,
                    "IdP deprovision UnsupportedOperation; raw detail redacted"
                );
                DomainError::UnsupportedOperation {
                    detail: format!(
                        "provider declined the operation (detail redacted; \
                         digest=0x{digest:016x} len={len})"
                    ),
                }
            }
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
    fn clean_failure_maps_to_service_unavailable() {
        let err = ProvisionFailure::CleanFailure {
            detail: "conn refused".into(),
        }
        .into_am_error();
        assert!(matches!(err, DomainError::ServiceUnavailable { .. }));
    }

    #[test]
    fn unsupported_operation_maps_to_unsupported_operation() {
        let err = ProvisionFailure::UnsupportedOperation {
            detail: "not supported by provider".into(),
        }
        .into_am_error();
        assert!(matches!(err, DomainError::UnsupportedOperation { .. }));
    }

    #[test]
    fn deprovision_failure_maps_to_am_error() {
        // Terminal -> internal
        let t = DeprovisionFailure::Terminal {
            detail: "torched".into(),
        }
        .into_am_error();
        assert!(matches!(t, DomainError::Internal { .. }));

        // Retryable -> service_unavailable
        let r = DeprovisionFailure::Retryable {
            detail: "try later".into(),
        }
        .into_am_error();
        assert!(matches!(r, DomainError::ServiceUnavailable { .. }));

        // UnsupportedOperation -> unsupported_operation
        let u = DeprovisionFailure::UnsupportedOperation {
            detail: "nope".into(),
        }
        .into_am_error();
        assert!(matches!(u, DomainError::UnsupportedOperation { .. }));
    }

    #[test]
    fn deprovision_default_impl_returns_unsupported_operation() {
        use async_trait::async_trait;

        #[allow(unknown_lints, de0309_must_have_domain_model)]
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
