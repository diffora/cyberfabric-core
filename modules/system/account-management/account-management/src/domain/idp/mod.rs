//! AM-internal mapping from the SDK `IdP` failure shapes to
//! [`crate::domain::error::DomainError`].
//!
//! The trait + DTO are stable contract and live in
//! [`account_management_sdk::idp`] (see that module's docs for the
//! provisioner contract). This module owns the **mapping** from those
//! plugin-facing failure variants onto AM's internal error taxonomy:
//!
//! * [`From<account_management_sdk::ProvisionFailure>`] → [`DomainError`]
//! * [`From<account_management_sdk::DeprovisionFailure>`] → [`DomainError`]
//!
//! Both conversions redact provider-supplied detail strings (which can
//! carry vendor SDK error text, hostnames, or token-bearing fragments)
//! through [`redact_provider_detail`] and emit a `tracing::warn!` on
//! `am.idp` so operators can correlate the redacted public envelope
//! back to the raw provider response via the digest + length pair.

use std::hash::Hasher;

use account_management_sdk::{DeprovisionFailure, ProvisionFailure};
use fnv::FnvHasher;

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

/// Map [`ProvisionFailure`] onto the [`DomainError`] taxonomy.
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
impl From<ProvisionFailure> for DomainError {
    #[allow(
        clippy::cognitive_complexity,
        reason = "flat 3-arm match with redact + warn! per arm; splitting fragments the variant->DomainError mapping reviewers must eyeball-check"
    )]
    fn from(failure: ProvisionFailure) -> Self {
        match failure {
            ProvisionFailure::CleanFailure { detail } => {
                let (digest, len) = redact_provider_detail(&detail);
                tracing::warn!(
                    target: "am.idp",
                    provider_detail_digest = digest,
                    provider_detail_len = len,
                    "IdP provision CleanFailure; surfacing generic ServiceUnavailable, raw detail redacted (correlate via digest + audit-only diagnostic)"
                );
                Self::service_unavailable("identity provider unavailable; provisioning compensated")
            }
            ProvisionFailure::Ambiguous { detail } => {
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
                Self::Internal {
                    diagnostic: format!(
                        "idp provision ambiguous outcome (provider detail redacted; \
                         digest=0x{digest:016x} len={len})"
                    ),
                    cause: None,
                }
            }
            ProvisionFailure::UnsupportedOperation { detail } => {
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
                Self::UnsupportedOperation {
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
                    variant = label,
                    "unknown ProvisionFailure variant; mapping conservatively to Internal -- update From<ProvisionFailure> for DomainError"
                );
                Self::Internal {
                    diagnostic: format!(
                        "idp provision unknown failure variant `{label}` (raw detail redacted; \
                         update From<ProvisionFailure> for DomainError)"
                    ),
                    cause: None,
                }
            }
        }
    }
}

/// Map [`DeprovisionFailure`] onto the [`DomainError`] taxonomy.
///
/// * `Terminal` → [`DomainError::Internal`] (HTTP 500). The raw
///   provider detail is **not** forwarded into the variant —
///   `Internal::diagnostic` is exposed as the public `Problem.detail`
///   by the canonical-mapping boundary, so the variant carries a
///   redacted summary and the raw text is logged at `am.idp` with a
///   digest for operator correlation.
/// * `Retryable` → [`DomainError::ServiceUnavailable`] (HTTP 503).
///   Provider-supplied `detail` is **not** forwarded into the public
///   envelope (same vendor-text-leak rationale as
///   [`ProvisionFailure::CleanFailure`]); raw detail is logged at
///   `am.idp` for operator correlation via digest.
/// * `UnsupportedOperation` → [`DomainError::UnsupportedOperation`]
///   (HTTP 501); the variant's `detail` field is logged verbatim by
///   the canonical-mapping boundary, so the raw provider text is
///   redacted at construction here.
/// * `NotFound` should never reach this mapping in production — the
///   hard-delete and reaper pipelines both treat it as
///   success-equivalent and never propagate it as `DomainError`. The
///   arm exists only to keep the match exhaustive; it routes to
///   [`DomainError::Internal`] (with redacted diagnostic) so an
///   unexpected propagation is loud rather than silent.
impl From<DeprovisionFailure> for DomainError {
    #[allow(
        clippy::cognitive_complexity,
        reason = "flat 4-arm match with redact + warn! per arm; splitting fragments the variant->DomainError mapping reviewers must eyeball-check"
    )]
    fn from(failure: DeprovisionFailure) -> Self {
        match failure {
            DeprovisionFailure::Terminal { detail } => {
                let (digest, len) = redact_provider_detail(&detail);
                tracing::warn!(
                    target: "am.idp",
                    provider_detail_digest = digest,
                    provider_detail_len = len,
                    "IdP deprovision terminal failure; surfacing generic Internal, raw detail redacted"
                );
                Self::Internal {
                    diagnostic: format!(
                        "idp deprovision terminal failure (provider detail redacted; \
                         digest=0x{digest:016x} len={len})"
                    ),
                    cause: None,
                }
            }
            DeprovisionFailure::Retryable { detail } => {
                let (digest, len) = redact_provider_detail(&detail);
                tracing::warn!(
                    target: "am.idp",
                    provider_detail_digest = digest,
                    provider_detail_len = len,
                    "IdP deprovision Retryable failure; surfacing generic ServiceUnavailable, raw detail redacted (correlate via digest)"
                );
                Self::service_unavailable(
                    "identity provider unavailable; deprovision will be retried",
                )
            }
            DeprovisionFailure::UnsupportedOperation { detail } => {
                let (digest, len) = redact_provider_detail(&detail);
                tracing::warn!(
                    target: "am.idp",
                    provider_detail_digest = digest,
                    provider_detail_len = len,
                    "IdP deprovision UnsupportedOperation; raw detail redacted"
                );
                Self::UnsupportedOperation {
                    detail: format!(
                        "provider declined the operation (detail redacted; \
                         digest=0x{digest:016x} len={len})"
                    ),
                }
            }
            DeprovisionFailure::NotFound { detail } => {
                let (digest, len) = redact_provider_detail(&detail);
                tracing::warn!(
                    target: "am.idp",
                    provider_detail_digest = digest,
                    provider_detail_len = len,
                    "IdP deprovision NotFound reached DomainError mapping; pipelines should treat NotFound as success-equivalent. Surfacing Internal, raw detail redacted"
                );
                Self::Internal {
                    diagnostic: format!(
                        "idp deprovision NotFound reached DomainError mapping (provider detail redacted; \
                         digest=0x{digest:016x} len={len})"
                    ),
                    cause: None,
                }
            }
            // SDK enum is `#[non_exhaustive]`. A new variant added in a
            // future SDK release lands here until the AM-side mapping
            // is updated; surface as `Internal` with a loud `error!`.
            other => {
                let label = other.as_metric_label();
                tracing::error!(
                    target: "am.idp",
                    variant = label,
                    "unknown DeprovisionFailure variant; mapping conservatively to Internal -- update From<DeprovisionFailure> for DomainError"
                );
                Self::Internal {
                    diagnostic: format!(
                        "idp deprovision unknown failure variant `{label}` (raw detail redacted; \
                         update From<DeprovisionFailure> for DomainError)"
                    ),
                    cause: None,
                }
            }
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn clean_failure_maps_to_service_unavailable() {
        let err: DomainError = ProvisionFailure::CleanFailure {
            detail: "conn refused".into(),
        }
        .into();
        assert!(matches!(err, DomainError::ServiceUnavailable { .. }));
    }

    #[test]
    fn provision_unsupported_operation_maps_to_unsupported_operation() {
        let err: DomainError = ProvisionFailure::UnsupportedOperation {
            detail: "not supported by provider".into(),
        }
        .into();
        assert!(matches!(err, DomainError::UnsupportedOperation { .. }));
    }

    #[test]
    fn provision_ambiguous_maps_to_internal_with_redacted_diagnostic() {
        let err: DomainError = ProvisionFailure::Ambiguous {
            detail: "vendor stack trace with token=...".into(),
        }
        .into();
        let DomainError::Internal { diagnostic, .. } = err else {
            panic!("expected Internal");
        };
        assert!(diagnostic.contains("provider detail redacted"));
        assert!(!diagnostic.contains("token="));
    }

    #[test]
    fn deprovision_terminal_maps_to_internal() {
        let err: DomainError = DeprovisionFailure::Terminal {
            detail: "torched".into(),
        }
        .into();
        assert!(matches!(err, DomainError::Internal { .. }));
    }

    #[test]
    fn deprovision_retryable_maps_to_service_unavailable() {
        let err: DomainError = DeprovisionFailure::Retryable {
            detail: "try later".into(),
        }
        .into();
        assert!(matches!(err, DomainError::ServiceUnavailable { .. }));
    }

    #[test]
    fn deprovision_unsupported_maps_to_unsupported_operation() {
        let err: DomainError = DeprovisionFailure::UnsupportedOperation {
            detail: "nope".into(),
        }
        .into();
        assert!(matches!(err, DomainError::UnsupportedOperation { .. }));
    }

    #[test]
    fn deprovision_not_found_maps_to_internal_loudly() {
        // NotFound should be intercepted by the pipelines before reaching
        // the DomainError boundary; if it ever propagates, surface as
        // Internal with a redacted diagnostic so the propagation is
        // loud rather than silent.
        let err: DomainError = DeprovisionFailure::NotFound {
            detail: "absent".into(),
        }
        .into();
        let DomainError::Internal { diagnostic, .. } = err else {
            panic!("expected Internal");
        };
        assert!(diagnostic.contains("NotFound reached"));
    }
}
