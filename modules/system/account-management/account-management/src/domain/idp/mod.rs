//! AM-internal mapping from the SDK `IdP` failure shapes to
//! [`crate::domain::error::DomainError`].
//!
//! The trait + DTO are stable contract and live in
//! [`account_management_sdk::idp`] (see that module's docs for the
//! provisioner contract). This module owns the **mapping** from those
//! plugin-facing failure variants onto AM's internal error taxonomy
//! via the crate-private extension trait
//! [`ProvisionFailureExt::into_domain_error`].
//!
//! The method takes a `tenant_id: Uuid` so the per-conversion
//! `tracing::warn!` carries enough structured context for operator
//! grep — without that field a stack of identical `am.idp` warns from
//! different tenants becomes impossible to attribute. We deliberately
//! do NOT provide `From<ProvisionFailure> for DomainError`: the
//! conversion has a mandatory side effect (redaction + structured log
//! emit) and a mandatory context input (`tenant_id`). Forcing every
//! call site through `into_domain_error(tenant_id)` makes the
//! requirement locally visible and prevents an accidental
//! `?`-propagation that would emit a context-less log line.
//!
//! The symmetric `DeprovisionFailureExt` is intentionally NOT defined
//! at this revision — there are no production callers (the retention
//! and reaper pipelines and the saga step-3 compensator all
//! pattern-match on the variant manually). It will land together
//! with its first real consumer rather than as dead infrastructure;
//! the rationale is restated next to the trait's eventual home at
//! the bottom of this file.
//!
//! The mapping redacts provider-supplied detail strings (which can
//! carry vendor SDK error text, hostnames, or token-bearing fragments)
//! through [`redact_provider_detail`] and emits a `tracing::warn!` on
//! `am.idp` so operators can correlate the redacted public envelope
//! back to the raw provider response via the digest + length pair.

use std::hash::Hasher;

use account_management_sdk::{ProvisionFailure, UserOperationFailure};
use fnv::FnvHasher;
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
/// FNV-1a is chosen over [`std::hash::DefaultHasher`] because the
/// stdlib hasher's algorithm is explicitly unspecified and may change
/// between Rust toolchain versions — that would silently desync
/// digests emitted by older binaries from the same input hashed in a
/// newer one, breaking the cross-upgrade correlation a forensic
/// handle exists for. FNV-1a is spec-pinned, so a digest emitted
/// today still matches one emitted next year against the same input.
/// Collision resistance is not a concern here (non-cryptographic;
/// the inverse mapping lives in the audit-only `diagnostic` field).
///
/// We feed the bytes directly via [`Hasher::write`] rather than the
/// [`Hash`] trait because `Hash::hash` for `str` has no documented
/// stability guarantee across compiler versions (the std docs
/// explicitly warn that the byte stream `Hash` produces "should not
/// be considered stable between compiler versions"). FNV-1a being
/// spec-pinned only protects the *algorithm*; the cross-upgrade
/// digest stability we promise above also requires a spec-pinned
/// *encoding* of the input. UTF-8 bytes from `as_bytes()` are that
/// stable encoding. Length is reported in `chars` to keep the public
/// log field a Unicode-grapheme-aligned magnitude, while the digest
/// commits to the byte sequence one-to-one.
pub(crate) fn redact_provider_detail(detail: &str) -> (u64, usize) {
    let mut hasher = FnvHasher::default();
    hasher.write(detail.as_bytes());
    (hasher.finish(), detail.chars().count())
}

/// Map [`ProvisionFailure`] onto the [`DomainError`] taxonomy with
/// caller-supplied `tenant_id` context.
///
/// * `CleanFailure` → [`DomainError::ServiceUnavailable`] (HTTP 503;
///   compensation already ran; AM proved no provider state was
///   retained). Provider-supplied `detail` is **not** forwarded into
///   the public envelope: vendor SDK strings can carry endpoint
///   names, hostnames, or token-bearing fragments, and the
///   `with_detail` contract on `modkit-canonical-errors` mandates
///   pre-redacted public text. The raw detail is logged at `am.idp`
///   and reaches operators via trace correlation.
/// * `Ambiguous` → [`DomainError::Internal`] (HTTP 500). The provider
///   may have retained state; the provisioning reaper compensates
///   asynchronously. The raw detail is redacted and digested; the
///   diagnostic field carries only the digest + length.
/// * `UnsupportedOperation` → [`DomainError::UnsupportedOperation`]
///   (HTTP 501); the boundary mapping further redacts the public
///   message (provider detail kept private — see
///   `infra::canonical_mapping`).
pub(crate) trait ProvisionFailureExt {
    fn into_domain_error(self, tenant_id: Uuid) -> DomainError;
}

impl ProvisionFailureExt for ProvisionFailure {
    #[allow(
        clippy::cognitive_complexity,
        reason = "flat 3-arm match with redact + warn! per arm; splitting fragments the variant->DomainError mapping reviewers must eyeball-check"
    )]
    fn into_domain_error(self, tenant_id: Uuid) -> DomainError {
        match self {
            Self::CleanFailure { detail } => {
                let (digest, len) = redact_provider_detail(&detail);
                tracing::warn!(
                    target: "am.idp",
                    tenant_id = %tenant_id,
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
                    tenant_id = %tenant_id,
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
                    tenant_id = %tenant_id,
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
            // SDK enum is `#[non_exhaustive]`. A new variant added in a
            // future SDK release lands here until the AM-side mapping
            // is updated; surface as `Internal` with a loud `error!`
            // so the gap shows up in operator logs the moment the
            // new variant flows through.
            other => {
                let label = other.as_metric_label();
                tracing::error!(
                    target: "am.idp",
                    tenant_id = %tenant_id,
                    variant = label,
                    "unknown ProvisionFailure variant; mapping conservatively to Internal -- update ProvisionFailureExt::into_domain_error"
                );
                DomainError::Internal {
                    diagnostic: format!(
                        "idp provision unknown failure variant `{label}` (raw detail redacted; \
                         update ProvisionFailureExt::into_domain_error)"
                    ),
                    cause: None,
                }
            }
        }
    }
}

// `DeprovisionFailure → DomainError` has no production callers
// today: the retention pipeline ([`super::tenant::service::retention`])
// and the reaper ([`super::tenant::service::reaper`]) both
// pattern-match on the variant and decide per-arm; the saga
// step-3 compensator ([`super::tenant::service::TenantService::compensate_failed_activation`])
// likewise matches manually. The conversion shape (with the same
// redaction + per-variant `DomainError` mapping as the
// `ProvisionFailure` side) lands together with its first real
// caller — typically an admin endpoint that surfaces a deprovision
// outcome to a caller — rather than as dead infrastructure here.

/// Map [`UserOperationFailure`] onto the [`DomainError`] taxonomy with
/// caller-supplied `tenant_id` context.
///
/// * `Unavailable` → [`DomainError::IdpUnavailable`] (HTTP 503). The
///   provider was unreachable, the call timed out, or the transport
///   returned a retryable failure. AM holds no fallback projection
///   per `cpt-cf-account-management-constraint-no-user-storage`.
/// * `UnsupportedOperation` → [`DomainError::UnsupportedOperation`]
///   (HTTP 501). The provider declined a mutating operation in its
///   current implementation profile.
/// * `Rejected` → [`DomainError::Validation`] (HTTP 400). The
///   provider returned a payload-rejection category; the canonical
///   mapping refinement is owned by `feature-errors-observability`
///   and may diverge per provider in a follow-up. The Validation
///   surface is the most conservative public envelope today.
///
/// Provider-supplied detail strings are redacted via
/// [`redact_provider_detail`] before reaching public envelopes:
/// vendor SDK text can carry endpoint names, hostnames, or token-
/// bearing fragments. Operators correlate redacted public envelopes
/// to raw provider responses via the digest + length emitted on the
/// `am.idp` `tracing::warn!` line.
pub(crate) trait UserOperationFailureExt {
    fn into_domain_error(self, tenant_id: Uuid) -> DomainError;
}

impl UserOperationFailureExt for UserOperationFailure {
    #[allow(
        clippy::cognitive_complexity,
        reason = "flat 3-arm match with redact + warn! per arm; splitting fragments the variant->DomainError mapping reviewers must eyeball-check"
    )]
    fn into_domain_error(self, tenant_id: Uuid) -> DomainError {
        match self {
            // @cpt-begin:cpt-cf-account-management-dod-idp-user-operations-contract-idp-unavailability-contract:p1:inst-dod-idp-user-operations-contract-unavailability-mapping
            // @cpt-begin:cpt-cf-account-management-algo-idp-user-operations-contract-idp-contract-invocation:p1:inst-algo-ici-transport-failure
            // @cpt-begin:cpt-cf-account-management-algo-idp-user-operations-contract-idp-contract-invocation:p1:inst-algo-ici-transport-return
            Self::Unavailable { detail } => {
                let (digest, len) = redact_provider_detail(&detail);
                tracing::warn!(
                    target: "am.idp",
                    tenant_id = %tenant_id,
                    provider_detail_digest = digest,
                    provider_detail_len = len,
                    "IdP user operation Unavailable; surfacing IdpUnavailable, raw detail redacted (correlate via digest)"
                );
                DomainError::IdpUnavailable {
                    detail: format!(
                        "identity provider unavailable for user operation (detail redacted; \
                         digest=0x{digest:016x} len={len})"
                    ),
                }
            }
            // @cpt-end:cpt-cf-account-management-algo-idp-user-operations-contract-idp-contract-invocation:p1:inst-algo-ici-transport-return
            // @cpt-end:cpt-cf-account-management-algo-idp-user-operations-contract-idp-contract-invocation:p1:inst-algo-ici-transport-failure
            // @cpt-end:cpt-cf-account-management-dod-idp-user-operations-contract-idp-unavailability-contract:p1:inst-dod-idp-user-operations-contract-unavailability-mapping
            // @cpt-begin:cpt-cf-account-management-algo-idp-user-operations-contract-idp-contract-invocation:p1:inst-algo-ici-unsupported-branch
            // @cpt-begin:cpt-cf-account-management-algo-idp-user-operations-contract-idp-contract-invocation:p1:inst-algo-ici-unsupported-return
            Self::UnsupportedOperation { detail } => {
                let (digest, len) = redact_provider_detail(&detail);
                tracing::warn!(
                    target: "am.idp",
                    tenant_id = %tenant_id,
                    provider_detail_digest = digest,
                    provider_detail_len = len,
                    "IdP user operation UnsupportedOperation; raw detail redacted"
                );
                DomainError::UnsupportedOperation {
                    detail: format!(
                        "provider declined the user operation (detail redacted; \
                         digest=0x{digest:016x} len={len})"
                    ),
                }
            }
            // @cpt-end:cpt-cf-account-management-algo-idp-user-operations-contract-idp-contract-invocation:p1:inst-algo-ici-unsupported-return
            // @cpt-end:cpt-cf-account-management-algo-idp-user-operations-contract-idp-contract-invocation:p1:inst-algo-ici-unsupported-branch
            // @cpt-begin:cpt-cf-account-management-algo-idp-user-operations-contract-idp-contract-invocation:p1:inst-algo-ici-provider-error
            // @cpt-begin:cpt-cf-account-management-algo-idp-user-operations-contract-idp-contract-invocation:p1:inst-algo-ici-provider-error-return
            Self::Rejected { detail } => {
                let (digest, len) = redact_provider_detail(&detail);
                tracing::warn!(
                    target: "am.idp",
                    tenant_id = %tenant_id,
                    provider_detail_digest = digest,
                    provider_detail_len = len,
                    "IdP user operation Rejected; surfacing Validation, raw detail redacted"
                );
                DomainError::Validation {
                    detail: format!(
                        "identity provider rejected the user operation (detail redacted; \
                         digest=0x{digest:016x} len={len})"
                    ),
                }
            }
            // @cpt-end:cpt-cf-account-management-algo-idp-user-operations-contract-idp-contract-invocation:p1:inst-algo-ici-provider-error-return
            // @cpt-end:cpt-cf-account-management-algo-idp-user-operations-contract-idp-contract-invocation:p1:inst-algo-ici-provider-error
            // SDK enum is `#[non_exhaustive]`. A new variant added in
            // a future SDK release lands here until the AM-side
            // mapping is updated; surface as `Internal` with a loud
            // `error!` so the gap shows up in operator logs the
            // moment the new variant flows through.
            other => {
                let label = other.as_metric_label();
                tracing::error!(
                    target: "am.idp",
                    tenant_id = %tenant_id,
                    variant = label,
                    "unknown UserOperationFailure variant; mapping conservatively to Internal -- update UserOperationFailureExt::into_domain_error"
                );
                DomainError::Internal {
                    diagnostic: format!(
                        "idp user operation unknown failure variant `{label}` (raw detail redacted; \
                         update UserOperationFailureExt::into_domain_error)"
                    ),
                    cause: None,
                }
            }
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[path = "idp_tests.rs"]
mod tests;
