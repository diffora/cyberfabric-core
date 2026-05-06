//! Boundary mapping between AM's domain error model and the public
//! [`modkit_canonical_errors::CanonicalError`] envelope.
//!
//! Lives in `infra/` because the classification ladder reads
//! `sea_orm::DbErr` SQLSTATE codes and `modkit_db::DbError` variant
//! discriminants — both forbidden inside `domain/` by the project-wide
//! Dylint rules (`DE0301`, `DE0309`). Keeping the mapping here lets
//! `domain::error::DomainError` stay pure (no `sea_orm`/`modkit_db`
//! imports, `#[domain_model]` enforced) while still routing DB
//! failures onto the AIP-193 canonical categories.
//!
//! # Resource markers
//!
//! `TenantResource`, `TenantMetadataResource`, `ConversionRequestResource`
//! are unit structs whose `#[resource_error]`-generated impls produce
//! [`modkit_canonical_errors::ResourceErrorBuilder`]s tagged with the
//! AM GTS resource types. The literal strings below MUST match the
//! corresponding constants in `account_management_sdk::gts`; the
//! `error_tests` module asserts equality at test time so a divergence
//! trips there, not in production.
//!
//! # Lift vs classify
//!
//! Two entry points convert raw DB errors into [`DomainError`]:
//!
//! - [`classify_db_err_to_domain`] — used by
//!   `with_serializable_retry` after the retry budget is exhausted, so
//!   the surviving SQLSTATE is final and not retryable.
//! - [`From<DbError> for DomainError`] — used by non-transactional code
//!   paths (`repo.db.conn()?`, `transaction_with_config` bodies that
//!   don't need retry); routes Sea variants through the same
//!   classifier, IO outages straight to `ServiceUnavailable`, and
//!   anything else to `Internal` with a redacted diagnostic.

use modkit_canonical_errors::{CanonicalError, resource_error};
use modkit_db::DbError;
use modkit_db::secure::is_unique_violation;
use sea_orm::DbErr;
use tracing::warn;

use crate::domain::error::DomainError;
use crate::infra::error_conv::{
    is_db_availability_error, is_serialization_failure, redacted_db_diagnostic,
};

// ---------------------------------------------------------------------------
// Resource markers — kept in sync with account_management_sdk::gts via
// `domain::error_tests::resource_error_strings_match_sdk_constants`.
// ---------------------------------------------------------------------------

#[resource_error("gts.cf.core.am.tenant.v1~")]
pub(crate) struct TenantResource;

#[resource_error("gts.cf.core.am.tenant_metadata.v1~")]
pub(crate) struct TenantMetadataResource;

#[resource_error("gts.cf.core.am.conversion_request.v1~")]
pub(crate) struct ConversionRequestResource;

// ---------------------------------------------------------------------------
// DbErr → DomainError classification.
// ---------------------------------------------------------------------------

/// Classify a raw [`DbErr`] into a typed [`DomainError`].
///
/// Used by the retry helper after every retryable contention has been
/// retried and the surviving error is final. The ladder mirrors the
/// AIP-193 mapping the boundary [`From<DomainError> for CanonicalError`]
/// applies, but expressed as typed `DomainError` variants so domain
/// code stays free of `sea_orm` references:
///
/// - SQLSTATE `40001` (post-retry) → [`DomainError::Aborted`] with
///   `reason = "SERIALIZATION_CONFLICT"`.
/// - Unique-violation (`23505` / `SQLite` `2067`) →
///   [`DomainError::AlreadyExists`].
/// - Typed availability signal (pool timeout, transport drop) →
///   [`DomainError::ServiceUnavailable`].
/// - Anything else → [`DomainError::Internal`] with a
///   [`redacted_db_diagnostic`] string (no DSN / driver text leaks).
#[allow(
    clippy::cognitive_complexity,
    reason = "flat classification ladder; branchy warn! paths only, no logic"
)]
pub(crate) fn classify_db_err_to_domain(db_err: DbErr) -> DomainError {
    if is_serialization_failure(&db_err) {
        warn!(
            target: "am.db",
            error = %db_err,
            "serialization failure (retry-exhausted) mapped to DomainError::Aborted"
        );
        return DomainError::Aborted {
            reason: "SERIALIZATION_CONFLICT".to_owned(),
            detail: "serialization conflict; retry budget exhausted".to_owned(),
        };
    }
    if is_unique_violation(&db_err) {
        warn!(
            target: "am.db",
            error = %db_err,
            "unique-constraint violation mapped to DomainError::AlreadyExists"
        );
        return DomainError::AlreadyExists {
            detail: "request conflicts with existing state".to_owned(),
        };
    }
    let wrapped = DbError::Sea(db_err);
    if is_db_availability_error(&wrapped) {
        warn!(
            target: "am.db",
            diagnostic = redacted_db_diagnostic(&wrapped),
            "DB availability failure mapped to DomainError::ServiceUnavailable"
        );
        return DomainError::ServiceUnavailable {
            detail: redacted_db_diagnostic(&wrapped).to_owned(),
            retry_after: None,
            cause: None,
        };
    }
    let redacted = redacted_db_diagnostic(&wrapped);
    warn!(
        target: "am.db",
        diagnostic = redacted,
        "unclassified DB error mapped to DomainError::Internal"
    );
    DomainError::Internal {
        diagnostic: format!("unclassified database error: {redacted}"),
        cause: None,
    }
}

// ---------------------------------------------------------------------------
// DbError → DomainError lift.
// ---------------------------------------------------------------------------

impl From<DbError> for DomainError {
    /// Lift a [`DbError`] into the appropriate domain-internal variant.
    ///
    /// Routing:
    ///
    /// * `DbError::Sea(_)` → [`classify_db_err_to_domain`]. Non-transactional
    ///   paths (`repo.db.conn()?`) classify eagerly because there is no
    ///   retry helper to consult the raw `DbErr`.
    /// * Non-Sea variants that satisfy [`is_db_availability_error`]
    ///   (currently `DbError::Io(_)`) → [`DomainError::ServiceUnavailable`]
    ///   directly. They don't carry a `DbErr` for retry to inspect,
    ///   but they signal a transient infra outage that must surface
    ///   as HTTP 503, not HTTP 500.
    /// * Everything else → [`DomainError::Internal`] with a
    ///   [`redacted_db_diagnostic`] string. The raw error is preserved
    ///   on the `cause` chain for the audit trail, but the
    ///   user-visible diagnostic carries only the variant kind so
    ///   DSN / env-var / driver text cannot leak.
    fn from(err: DbError) -> Self {
        match err {
            DbError::Sea(db) => classify_db_err_to_domain(db),
            other if is_db_availability_error(&other) => Self::ServiceUnavailable {
                detail: redacted_db_diagnostic(&other).to_owned(),
                retry_after: None,
                cause: Some(Box::new(other)),
            },
            other => Self::Internal {
                diagnostic: redacted_db_diagnostic(&other).to_owned(),
                cause: Some(Box::new(other)),
            },
        }
    }
}

// ---------------------------------------------------------------------------
// DomainError → CanonicalError boundary mapping.
// ---------------------------------------------------------------------------

// @cpt-begin:cpt-cf-account-management-algo-errors-observability-error-to-problem-mapping:p1:inst-algo-etp-domain-classification
impl From<DomainError> for CanonicalError {
    /// Map AM domain failures onto AIP-193 canonical categories.
    ///
    /// This is the single boundary where AM's internal `DomainError`
    /// vocabulary becomes the public canonical-error contract. REST
    /// handlers and inter-module SDK callers always receive a
    /// [`CanonicalError`] — never a `DomainError`.
    fn from(err: DomainError) -> Self {
        match err {
            // ---- InvalidArgument (HTTP 400) ----
            DomainError::InvalidTenantType { detail } => TenantResource::invalid_argument()
                .with_field_violation("tenant_type", detail, "INVALID_TENANT_TYPE")
                .create(),
            DomainError::Validation { detail } => TenantResource::invalid_argument()
                .with_field_violation("request", detail, "VALIDATION")
                .create(),
            DomainError::RootTenantCannotDelete => TenantResource::invalid_argument()
                .with_field_violation(
                    "tenant_id",
                    "root tenant cannot be deleted",
                    "ROOT_TENANT_CANNOT_DELETE",
                )
                .create(),
            DomainError::RootTenantCannotConvert => TenantResource::invalid_argument()
                .with_field_violation(
                    "tenant_id",
                    "root tenant cannot be converted",
                    "ROOT_TENANT_CANNOT_CONVERT",
                )
                .create(),

            // ---- NotFound (HTTP 404) ----
            // PR1 assumption: every `DomainError::NotFound` producer in
            // PR1 reports a missing tenant row. The metadata-specific
            // 404s (`MetadataSchemaNotRegistered`/`MetadataEntryNotFound`)
            // already use `TenantMetadataResource` below, and conversion-
            // request flows do not emit `NotFound` from PR1 code paths.
            // When conversion-request reads land (later PR) this arm
            // MUST grow a resource-kind discriminator (either by
            // splitting `NotFound` into per-resource variants or by
            // carrying a kind tag on the variant) so the public
            // `resource_type` matches the entity that actually went
            // missing.
            DomainError::NotFound { detail, resource } => TenantResource::not_found(detail)
                .with_resource(resource)
                .create(),
            DomainError::MetadataSchemaNotRegistered { detail, schema } => {
                TenantMetadataResource::not_found(detail)
                    .with_resource(schema)
                    .create()
            }
            DomainError::MetadataEntryNotFound { detail, entry } => {
                TenantMetadataResource::not_found(detail)
                    .with_resource(entry)
                    .create()
            }

            // ---- AlreadyExists (HTTP 409) ----
            // PR1 assumption: the only `DomainError::AlreadyExists`
            // producer is `classify_db_err_to_domain` mapping a unique-
            // violation `DbErr` from the `tenants` insert path
            // (`insert_provisioning`). Closure inserts use
            // `scope_unchecked` and the metadata insert pre-folds 23505
            // to `Internal` (provider-bug semantics, see
            // `lifecycle.rs::activate_tenant`), so neither reaches this
            // arm. If a future entity wires through the classifier, the
            // hard-coded `"tenant"` resource hint must be revisited.
            DomainError::AlreadyExists { detail } => TenantResource::already_exists(detail)
                .with_resource("tenant")
                .create(),

            // ---- Aborted (HTTP 409) ----
            DomainError::Aborted { reason, detail } => {
                TenantResource::aborted(detail).with_reason(reason).create()
            }

            // ---- FailedPrecondition (HTTP 400) ----
            DomainError::TypeNotAllowed { detail } => TenantResource::failed_precondition()
                .with_precondition_violation("tenant_type", detail, "TYPE_NOT_ALLOWED")
                .create(),
            DomainError::TenantDepthExceeded { detail } => TenantResource::failed_precondition()
                .with_precondition_violation("depth", detail, "TENANT_DEPTH_EXCEEDED")
                .create(),
            DomainError::TenantHasChildren => TenantResource::failed_precondition()
                .with_precondition_violation(
                    "tenant",
                    "tenant has child tenants",
                    "TENANT_HAS_CHILDREN",
                )
                .create(),
            DomainError::TenantHasResources => TenantResource::failed_precondition()
                .with_precondition_violation(
                    "tenant",
                    "tenant still owns resources",
                    "TENANT_HAS_RESOURCES",
                )
                .create(),
            DomainError::PendingExists { request_id } => {
                ConversionRequestResource::failed_precondition()
                    .with_precondition_violation(
                        "conversion_request",
                        format!("a pending conversion request already exists: {request_id}"),
                        "PENDING_EXISTS",
                    )
                    .create()
            }
            DomainError::InvalidActorForTransition {
                attempted_status,
                caller_side,
            } => ConversionRequestResource::failed_precondition()
                .with_precondition_violation(
                    "conversion_request",
                    format!(
                        "invalid actor for conversion transition: \
                         attempted={attempted_status} caller_side={caller_side}"
                    ),
                    "INVALID_ACTOR_FOR_TRANSITION",
                )
                .create(),
            DomainError::AlreadyResolved => ConversionRequestResource::failed_precondition()
                .with_precondition_violation(
                    "conversion_request",
                    "conversion request already resolved",
                    "ALREADY_RESOLVED",
                )
                .create(),
            DomainError::Conflict { detail } => TenantResource::failed_precondition()
                .with_precondition_violation("request", detail, "PRECONDITION_FAILED")
                .create(),

            // ---- PermissionDenied (HTTP 403) ----
            DomainError::CrossTenantDenied { .. } => TenantResource::permission_denied()
                .with_reason("CROSS_TENANT_DENIED")
                .create(),

            // ---- ServiceUnavailable (HTTP 503) ----
            //
            // `detail` is curated upstream by the adapter that
            // produced the variant — `From<EnforcerError::EvaluationFailed>`
            // emits `"authorization evaluation failed"`, IdP plugin
            // wrappers emit pre-redacted vendor-safe summaries, the
            // DB classifier runs `redacted_db_diagnostic`. Forward it
            // so callers see the specific outage cause instead of every
            // 503 collapsing to the generic `"Service temporarily
            // unavailable"` placeholder.
            DomainError::ServiceUnavailable {
                detail,
                retry_after,
                cause: _,
            } => {
                let mut builder = CanonicalError::service_unavailable().with_detail(detail);
                if let Some(after) = retry_after {
                    builder = builder.with_retry_after_seconds(after.as_secs());
                }
                builder.create()
            }

            // `IdpUnavailable` reuses the same AIP-193 `ServiceUnavailable`
            // envelope as the generic variant — the dedicated domain
            // variant exists solely so the bootstrap retry loop can
            // pattern-match on the IdP-availability source without
            // sniffing `detail` strings; at the boundary the public
            // shape collapses back to a single 503 family.
            //
            // Provider-supplied `detail` text (the constructor copies
            // `CheckAvailabilityFailure::detail()` and `ProvisionFailure::detail`
            // through verbatim) can carry vendor SDK strings, internal
            // endpoint names, or other operator-meaningful but
            // not-public-contract content. Mirror the
            // `UnsupportedOperation` redaction policy: emit a generic
            // public message and route the provider detail through the
            // structured `am.domain` log instead so operators correlate
            // by trace-id without exposing it through the public
            // Problem envelope.
            DomainError::IdpUnavailable { detail } => {
                // Log a redacted digest + length rather than the raw
                // provider detail: hostname / token / vendor SDK
                // strings can otherwise reach the `am.domain`
                // logfile even though the public envelope is
                // generic. Mirrors the redaction policy applied at
                // the saga layer in `domain::idp::redact_provider_detail`.
                let (digest, len) = crate::domain::idp::redact_provider_detail(&detail);
                warn!(
                    target: "am.domain",
                    detail_digest = digest,
                    detail_len_chars = len,
                    "IdpUnavailable surfaced; provider detail redacted for log/envelope safety"
                );
                CanonicalError::service_unavailable()
                    .with_detail("IdP plugin unavailable")
                    .create()
            }

            // ---- Unimplemented (HTTP 501) ----
            DomainError::UnsupportedOperation { detail } => {
                // Provider-supplied `detail` text can carry vendor
                // SDK strings, internal endpoint names, or other
                // operator-meaningful but not-public-contract
                // content. Unlike `Internal::diagnostic` (which the
                // canonical envelope hides from the public Problem)
                // `Unimplemented::message` is exposed verbatim, so
                // forwarding raw provider text would leak it into
                // every API response. Emit a generic public message
                // and route the provider detail through the
                // structured `am.domain` log instead — operators
                // correlate by trace-id.
                warn!(
                    target: "am.domain",
                    detail = %detail,
                    "UnsupportedOperation surfaced; provider detail kept private (canonical message is generic)"
                );
                TenantResource::unimplemented("operation not supported by the IdP provider")
                    .create()
            }

            // ---- ResourceExhausted (HTTP 429) ----
            DomainError::IntegrityCheckInProgress { scope } => {
                TenantResource::resource_exhausted("integrity check already in progress")
                    .with_quota_violation(
                        format!("integrity_check:{scope}"),
                        "another integrity check is already in progress for this scope",
                    )
                    .create()
            }

            // ---- Internal (HTTP 500) ----
            DomainError::Internal { diagnostic, .. } => {
                CanonicalError::internal(diagnostic).create()
            }
        }
    }
}
// @cpt-end:cpt-cf-account-management-algo-errors-observability-error-to-problem-mapping:p1:inst-algo-etp-domain-classification

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[path = "canonical_mapping_tests.rs"]
mod canonical_mapping_tests;
