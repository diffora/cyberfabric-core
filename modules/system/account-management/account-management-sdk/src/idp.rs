//! `IdP` tenant-provisioning contract.
//!
//! Public contract that deployment-specific `IdP` plugins implement and
//! that AM consumes through `ClientHub`. The trait carries three
//! methods — [`IdpTenantProvisionerClient::check_availability`],
//! [`IdpTenantProvisionerClient::provision_tenant`], and
//! [`IdpTenantProvisionerClient::deprovision_tenant`] (the last has a
//! default impl returning [`DeprovisionFailure::UnsupportedOperation`])
//! — together with the request / result / failure shapes they exchange.
//!
//! The trait runs **outside** any database transaction — the
//! provisioning step is an external side effect that must not hold
//! locks in `tenants`.
//!
//! # Failure model
//!
//! The `Ok` variant of `provision_tenant` carries optional metadata
//! produced by the provider, which AM persists alongside the `active`
//! status flip. The `Err` variant is a [`ProvisionFailure`]
//! discriminating between:
//!
//! * [`ProvisionFailure::CleanFailure`] — AM can prove no `IdP`-side
//!   state was retained (connection refused before send, 4xx from the
//!   provider with a contract-defined "nothing retained" semantic).
//!   AM runs the compensating TX, deletes the `provisioning` row, and
//!   surfaces an AIP-193 `ServiceUnavailable` (HTTP 503).
//! * [`ProvisionFailure::Ambiguous`] — transport failure / timeout /
//!   5xx where the provider may or may not have retained state. AM
//!   leaves the `provisioning` row for the provisioning reaper to
//!   compensate asynchronously and surfaces `Internal` (HTTP 500). Not
//!   retry-safe without reconciliation.
//! * [`ProvisionFailure::UnsupportedOperation`] — the provider
//!   signalled that the requested provisioning cannot be performed at
//!   all. AM surfaces `Unimplemented` (HTTP 501); compensation rules
//!   match the `CleanFailure` path (nothing was ever written
//!   provider-side).
//!
//! The `provider_detail` strings carried by the failure variants are
//! routed through AM's redaction pipeline before reaching public
//! envelopes (see the impl-side `From<ProvisionFailure>
//! for DomainError` boundary in `cf-account-management::domain::idp`).
//! Plugin authors do not need to redact themselves — they pass the
//! raw vendor text and AM owns the public-surface mapping.

use async_trait::async_trait;
use serde_json::Value;
use uuid::Uuid;

/// Context passed to [`IdpTenantProvisionerClient::provision_tenant`].
///
/// Carries the identifiers and opaque provider metadata produced during
/// the pre-provisioning validation step. The `tenant_type` here is the
/// full chained GTS identifier (DESIGN §3.1 "Input and storage
/// format"); `parent_id` is `Some` for child-tenant creation and
/// `None` during the root-bootstrap path. Provider implementations
/// **MUST** handle both cases — `parent_id = None` is not a degenerate
/// placeholder, it is the canonical root-bootstrap signal.
#[derive(Debug, Clone)]
pub struct ProvisionRequest {
    pub tenant_id: Uuid,
    pub parent_id: Option<Uuid>,
    pub name: String,
    pub tenant_type: String,
    /// Opaque provider-specific metadata from `TenantCreateRequest.provisioning_metadata`.
    pub metadata: Option<Value>,
}

/// Opaque result returned by the provider on success.
#[derive(Debug, Clone, Default)]
pub struct ProvisionResult {
    /// Optional provider-returned metadata entries. An empty vector
    /// means "provider performed the provisioning but produced no
    /// metadata" — the normal path for providers that establish the
    /// tenant-to-`IdP` binding through external configuration.
    pub metadata_entries: Vec<ProvisionMetadataEntry>,
}

/// Single metadata entry produced by the provider and persisted by AM.
#[derive(Debug, Clone)]
pub struct ProvisionMetadataEntry {
    pub schema_id: String,
    pub value: Value,
}

/// Failure discriminant for `provision_tenant`.
///
/// See module docs for compensation semantics.
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

impl ProvisionFailure {
    /// Stable, snake-case metric-label form of this variant. Used as
    /// the `outcome` label on `am.dependency_health` counter samples
    /// emitted by the create-tenant saga; kept on the SDK type so
    /// producers (impl-side service layer) do not duplicate the
    /// variant → string mapping in match arms.
    #[must_use]
    pub const fn as_metric_label(&self) -> &'static str {
        match self {
            Self::CleanFailure { .. } => "clean_failure",
            Self::Ambiguous { .. } => "ambiguous",
            Self::UnsupportedOperation { .. } => "unsupported_operation",
        }
    }
}

/// Failure discriminant for a non-mutating `IdP` availability probe.
///
/// Bootstrap uses this before starting the root-tenant saga so the
/// wait loop does not call [`IdpTenantProvisionerClient::provision_tenant`]
/// as a liveness check.
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

/// Context passed to [`IdpTenantProvisionerClient::deprovision_tenant`]
/// during the hard-delete pipeline or the provisioning reaper.
#[derive(Debug, Clone)]
pub struct DeprovisionRequest {
    pub tenant_id: Uuid,
}

/// Failure discriminant for `deprovision_tenant`.
///
/// `Terminal` means the tenant cannot be deprovisioned by this
/// provider and the operator must intervene; `Retryable` defers to the
/// next tick; `UnsupportedOperation` is the default path that
/// preserves Phase 1/2 behaviour when no provider plugin is
/// registered. `NotFound` is the "vendor-side already gone" path — AM
/// treats it as a success-equivalent and proceeds with the local DB
/// teardown (see the trait-level doc on idempotency vs typed errors).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeprovisionFailure {
    /// Non-recoverable; logs/audits and skips the tenant this tick.
    Terminal { detail: String },
    /// Transient; defer the tenant to the next retention tick.
    Retryable { detail: String },
    /// Provider does not support deprovisioning at all.
    UnsupportedOperation { detail: String },
    /// Provider reports the target tenant does not exist on its side
    /// (e.g. HTTP 404 / 410 from the vendor SDK). AM treats this as a
    /// success-equivalent — the local DB teardown still runs — and
    /// emits an `outcome=already_absent` metric so the operational
    /// signal is observable distinct from a fresh `compensated`.
    NotFound { detail: String },
}

impl DeprovisionFailure {
    /// Stable, snake-case metric-label form of this variant. Used as
    /// the `outcome` label on `am.dependency_health` counter samples
    /// emitted by the hard-delete pipeline; kept on the SDK type so
    /// producers (impl-side service layer) do not duplicate the
    /// variant → string mapping in match arms.
    #[must_use]
    pub const fn as_metric_label(&self) -> &'static str {
        match self {
            Self::Terminal { .. } => "terminal",
            Self::Retryable { .. } => "retryable",
            Self::UnsupportedOperation { .. } => "unsupported_operation",
            Self::NotFound { .. } => "already_absent",
        }
    }
}

/// Trait implemented by the deployment-specific `IdP` provider plugin.
///
/// Phase 1 ships [`IdpTenantProvisionerClient::provision_tenant`];
/// Phase 3 adds the deprovisioning counterpart with a default
/// implementation that returns
/// [`DeprovisionFailure::UnsupportedOperation`] — so existing plugins
/// written against the Phase 1/2 contract continue to compile without
/// modification.
///
/// # Retry, backoff, and rate-limiting are owned by the plugin
///
/// AM does NOT wrap calls into this trait in retry loops, exponential
/// backoff, jittered scheduling, or circuit-breakers. Each AM call
/// site issues exactly one invocation per logical attempt:
///
/// * `provision_tenant` — one call per `create_child` saga.
/// * `deprovision_tenant` — at most one call per claimed row per
///   tick (both `hard_delete_batch` and `reap_stuck_provisioning`
///   take a 600-second DB lease before invoking the plugin so two
///   replicas cannot simultaneously call for the same tenant).
///
/// Plugins MUST own their transport-level resilience: retries with
/// vendor-appropriate backoff, ratelimit handling, circuit breaking
/// after sustained failure, and any client-side dedup. A `Retryable`
/// return value signals that the plugin has exhausted its own retry
/// budget for this call; AM defers the row to the next reaper /
/// retention tick (default 30 s and 60 s respectively) and re-issues
/// from scratch. A misbehaving plugin that does not ratelimit will
/// see a steady periodic call rate (one per tick), not a thundering
/// herd — but the call frequency is the plugin's to manage.
///
/// # Idempotency by error-mapping
///
/// Plugins do NOT need to silently no-op on already-removed tenants.
/// Instead they MUST surface vendor-side "tenant does not exist"
/// responses as [`DeprovisionFailure::NotFound`] (typically HTTP 404
/// or 410 from the vendor SDK). AM's pipelines treat `NotFound` as
/// success-equivalent and proceed with the local DB teardown,
/// emitting an `outcome=already_absent` metric so the operational
/// signal stays observable. This shifts the "is this a re-call?"
/// interpretation from the plugin to AM — plugins map vendor errors
/// 1:1, AM business logic decides what each error means.
///
/// # `ClientHub` registration
///
/// Plugins register themselves in `ClientHub` as
/// `Arc<dyn IdpTenantProvisionerClient>`; AM's module entry-point
/// resolves the plugin via
/// `ctx.client_hub().get::<dyn IdpTenantProvisionerClient>()` and
/// falls back to a noop provisioner when no plugin is registered (dev
/// / test deployments).
#[async_trait]
pub trait IdpTenantProvisionerClient: Send + Sync + 'static {
    /// Lightweight, non-mutating provider health probe.
    ///
    /// Implementations should use a HEAD / ping / SDK health endpoint
    /// and MUST NOT create or mutate provider-side tenant state.
    async fn check_availability(&self) -> Result<(), CheckAvailabilityFailure>;

    /// Create any `IdP`-side resources for the new tenant.
    ///
    /// Invariants:
    /// * Runs outside any DB transaction.
    /// * MUST NOT silently no-op — provider implementations that
    ///   cannot perform the operation MUST return
    ///   [`ProvisionFailure::UnsupportedOperation`].
    /// * Any transport-layer uncertainty MUST be reported as
    ///   [`ProvisionFailure::Ambiguous`]; the provider MUST NOT
    ///   pretend a timed-out request succeeded.
    /// * MUST own retry / backoff / rate-limiting policy (see trait-
    ///   level doc). AM issues exactly one call per saga attempt.
    async fn provision_tenant(
        &self,
        req: &ProvisionRequest,
    ) -> Result<ProvisionResult, ProvisionFailure>;

    /// Tear down `IdP`-side resources attached to the tenant.
    ///
    /// Default impl returns
    /// [`DeprovisionFailure::UnsupportedOperation`] so Phase 1/2
    /// provider plugins do not need to change. Providers that own
    /// teardown MUST override this method.
    ///
    /// Invariants:
    /// * MUST map vendor-side "tenant does not exist" responses
    ///   (typically HTTP 404 / 410) to
    ///   [`DeprovisionFailure::NotFound`]. AM uses this signal as a
    ///   success-equivalent — the local DB teardown still proceeds —
    ///   so plugins do NOT need to magic-map "already gone" into
    ///   `Ok(())` themselves. Idempotency by error-mapping is the
    ///   contract.
    /// * MUST own retry / backoff / rate-limiting policy (see trait-
    ///   level doc). AM issues at most one call per reaper /
    ///   retention tick per row (rows are claimed via the same
    ///   600-second DB lease that the retention pipeline uses), so a
    ///   `Retryable` return defers the row to the next tick.
    async fn deprovision_tenant(&self, req: &DeprovisionRequest) -> Result<(), DeprovisionFailure> {
        let _ = req;
        Err(DeprovisionFailure::UnsupportedOperation {
            detail: "deprovision_tenant not implemented".to_owned(),
        })
    }
}

#[cfg(test)]
#[path = "idp_tests.rs"]
mod tests;
