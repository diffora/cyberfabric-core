//! `IdP` user-operations DTOs.
//!
//! Sibling of [`crate::idp`] (tenant-side) — hosts the request /
//! response / failure shapes consumed by the user-lifecycle half of
//! [`crate::idp::IdpPluginClient`]. The trait itself lives in
//! `crate::idp` so a single `Arc<dyn IdpPluginClient>` carries
//! both tenant and user methods.
//!
//! Users are NOT modelled in AM storage per
//! `cpt-cf-account-management-constraint-no-user-storage` -- every
//! user-side call is a live pass-through to the resolved provider
//! plugin.
//!
//! # User projection schema
//!
//! [`UserProjection`] mirrors the published GTS schema
//! `gts.cf.core.am.user.v1~` declared in
//! `modules/system/account-management/docs/schemas/user.v1.schema.json`.
//! The shape is intentionally tenant-minimal: no credentials, no
//! `IdP`-internal identifiers, no membership cache. Provider plugins
//! project only profile-like fields the `IdP` exposes.
//!
//! # Failure model
//!
//! [`UserOperationFailure`] discriminates between the categories AM's
//! service layer maps onto the public error envelope:
//!
//! * [`UserOperationFailure::Unavailable`] -- transport failure or
//!   timeout; AM surfaces `idp_unavailable` per
//!   `cpt-cf-account-management-dod-idp-user-operations-contract-idp-unavailability-contract`.
//!   AM holds NO fallback projection, so `list_users` during an outage
//!   returns the envelope-mapped error rather than a stale page.
//! * [`UserOperationFailure::UnsupportedOperation`] -- provider
//!   declines a mutating operation (read-only / legacy provider). AM
//!   surfaces `idp_unsupported_operation`. Providers MUST NOT silently
//!   no-op a mutating call; surface the variant explicitly.
//! * [`UserOperationFailure::Rejected`] -- provider returned a
//!   payload-rejection category (e.g. duplicate username, malformed
//!   email). AM surfaces a generic validation envelope; the canonical
//!   error catalog is owned by `feature-errors-observability` (sibling
//!   feature) and may refine the mapping in a follow-up.
//!
//! `provider_detail` strings carried by the failure variants are
//! routed through AM's redaction pipeline before reaching public
//! envelopes (see `cf-account-management::domain::idp` for the
//! `into_domain_error` boundary). Plugin authors do not need to redact
//! themselves -- they pass the raw vendor text and AM owns the public-
//! surface mapping.

use std::collections::BTreeMap;

use gts::GtsSchemaId;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

/// Provider-defined non-authoritative attributes carried on the
/// `gts.cf.core.am.user.v1~` projection. The published JSON Schema
/// declares the field as `{"type": "object",
/// "additionalProperties": true}`; using a typed map here makes a
/// non-object payload (integer / array / string) unrepresentable at
/// the SDK boundary so plugin authors cannot accidentally emit a
/// shape that violates the schema.
///
/// `BTreeMap` is chosen over `serde_json::Map` so the iteration
/// order is deterministic, which matters for golden-file tests and
/// stable digests on the redaction pipeline.
pub type UserAttributes = BTreeMap<String, Value>;

/// Resolved tenant context surfaced to provider plugins so they can
/// resolve `IdP`-specific identifiers (effective Keycloak realm, Zitadel
/// organization, etc.).
///
/// AM resolves the tenant via `TenantService` before invoking the
/// contract; the resolved fields are forwarded here so the plugin does
/// not have to round-trip back to AM for tenant metadata it could have
/// received inline.
///
/// # Field set
///
/// * `tenant_id` — the stable identifier the plugin keys vendor-side
///   state on.
/// * `tenant_name` — the human-readable label, useful for plugins
///   that derive provider-side identifiers from the slug (e.g. a
///   Keycloak realm whose name follows the tenant name).
/// * `tenant_type` — optional resolved chained GTS identifier
///   (e.g. `gts.cf.core.am.tenant_type.v1~cf.core.am.customer.v1~`).
///   AM populates it best-effort via the Types Registry; `None`
///   means either no registry is wired (dev / test) or the lookup
///   failed (registry blip on this tick). Plugins keying off
///   tenant type SHOULD treat `None` as "vendor-default" rather
///   than failing the call.
///
/// # Why these fields and not more
///
/// Because the unified [`crate::idp::IdpPluginClient`] owns
/// both tenant provisioning (`provision_tenant`, returning vendor-
/// specific [`crate::idp::ProvisionMetadataEntry`] values) **and**
/// the user-side calls, a plugin that needs richer per-tenant state
/// (resolved realm name, opaque vendor-side org id, etc.) caches it
/// from its own `provision_tenant` return value rather than
/// re-deriving it from `TenantContext` on every user call. Keeping
/// the wire shape narrow avoids forcing AM to fan out a tenant-
/// metadata lookup (and the registry round-trips behind it) on
/// every `provision_user` / `deprovision_user` / `list_users` call.
/// `tenant_type` is the cheap exception — it's already resolved
/// once for [`crate::tenant::TenantInfo.tenant_type`] on every CRUD
/// return, so reusing it on the user-ops boundary costs nothing.
///
/// # Adding fields
///
/// `#[non_exhaustive]` lets the SDK add fields (opaque tenant
/// metadata blob, `parent_id`, etc.) in a minor release without
/// breaking compilation. New fields default to `None` on
/// constructors that predate them.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
#[allow(
    clippy::struct_field_names,
    reason = "every field IS tenant-scoped (id / name / type) and stripping the prefix loses the public contract that the value comes from AM-resolved tenant state"
)]
pub struct TenantContext {
    /// Stable tenant identifier (the same UUID stored in AM's
    /// `tenants.id` column).
    pub tenant_id: Uuid,
    /// Human-readable tenant name, useful for plugins that derive
    /// provider-side identifiers from the tenant label (e.g. a
    /// Keycloak realm whose name follows the tenant slug).
    pub tenant_name: String,
    /// Optional resolved tenant type as a chained `GtsSchemaId`
    /// (e.g. `gts.cf.core.am.tenant_type.v1~cf.core.am.customer.v1~`).
    /// Populated by AM best-effort via the Types Registry; `None`
    /// when no registry is wired or the lookup failed. Plugins
    /// keying off the type (e.g. routing self-managed tenants to
    /// a different realm) SHOULD treat `None` as "use the
    /// provider's default behaviour" rather than failing the
    /// call.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_type: Option<GtsSchemaId>,
}

impl TenantContext {
    /// Build a [`TenantContext`] from the resolved tenant id, name,
    /// and optional chained tenant type.
    ///
    /// `tenant_type = None` is the always-available shape for test
    /// fakes and dev deployments without a Types Registry; production
    /// wiring resolves the chained id once via
    /// [`types_registry_sdk::TypesRegistryClient`] and passes it
    /// inline so plugin authors do not have to handle a partially-
    /// populated builder chain. With three fields total a single
    /// multi-arg constructor is more discoverable than the
    /// `new(...).with_tenant_type(...)` builder pattern.
    #[must_use]
    pub fn new(
        tenant_id: Uuid,
        tenant_name: impl Into<String>,
        tenant_type: Option<GtsSchemaId>,
    ) -> Self {
        Self {
            tenant_id,
            tenant_name: tenant_name.into(),
            tenant_type,
        }
    }
}

/// Profile-minimal payload accepted by
/// [`IdpPluginClient::provision_user`].
///
/// Shape mirrors the published `gts.cf.core.am.user.v1~` projection
/// minus the `IdP`-issued `id` (the provider assigns it on success) and
/// minus `attributes` flowing in the opposite direction (provider may
/// return them on the projection but AM does not synthesize them on
/// the create path). The structural contract (field shapes,
/// `minLength` / `maxLength`, `format`) is owned by the JSON Schema
/// referenced above; the AM service layer validates instances against
/// that schema at runtime via the GTS Types Registry — see
/// `cf-account-management::domain::gts_validation::validate_new_user_payload_via_gts`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct NewUserPayload {
    /// Login identifier (REQUIRED per the published schema).
    pub username: String,
    /// Optional contact email surfaced through the projection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Optional display name surfaced through the projection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Optional avatar URL surfaced through the projection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avatar_url: Option<String>,
    /// Optional provider-defined non-authoritative attributes
    /// forwarded verbatim into the `IdP` create call. AM does not
    /// inspect or transform these. Typed as a string-keyed map so
    /// non-object payloads are unrepresentable at the SDK boundary
    /// per the published schema's `{"type": "object"}` declaration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<UserAttributes>,
}

impl NewUserPayload {
    /// Construct a payload with only the required `username`. Use
    /// the `with_*` setters to populate optional profile fields.
    #[must_use]
    pub fn new(username: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            email: None,
            display_name: None,
            avatar_url: None,
            attributes: None,
        }
    }

    #[must_use]
    pub fn with_email(mut self, email: impl Into<String>) -> Self {
        self.email = Some(email.into());
        self
    }

    #[must_use]
    pub fn with_display_name(mut self, display_name: impl Into<String>) -> Self {
        self.display_name = Some(display_name.into());
        self
    }

    #[must_use]
    pub fn with_avatar_url(mut self, avatar_url: impl Into<String>) -> Self {
        self.avatar_url = Some(avatar_url.into());
        self
    }

    #[must_use]
    pub fn with_attributes(mut self, attributes: UserAttributes) -> Self {
        self.attributes = Some(attributes);
        self
    }
}

/// User projection matching the published GTS schema
/// `gts.cf.core.am.user.v1~`.
///
/// The shape is the contract for downstream consumers (e.g.
/// `feature-user-groups` membership existence checks, audit pipeline).
/// No `IdP`-internal identifier, credential, or membership cache is
/// included per `cpt-cf-account-management-adr-idp-user-identity-source-of-truth`
/// and `cpt-cf-account-management-adr-idp-user-tenant-binding`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct UserProjection {
    /// `IdP`-issued UUID user identifier. The provider owns the issuance
    /// and the value is stable across the user's lifetime in this
    /// tenant scope.
    pub id: Uuid,
    /// Login identifier (REQUIRED per the schema).
    pub username: String,
    /// Optional contact email.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Optional display name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Optional avatar URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avatar_url: Option<String>,
    /// Optional provider-defined non-authoritative attributes
    /// forwarded from the `IdP`. Opaque to AM. Typed as a string-keyed
    /// map so non-object payloads are unrepresentable at the SDK
    /// boundary per the published schema's `{"type": "object"}`
    /// declaration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<UserAttributes>,
}

impl UserProjection {
    /// Construct a projection with the two required schema fields.
    /// Use the `with_*` setters for optional profile fields.
    #[must_use]
    pub fn new(id: Uuid, username: impl Into<String>) -> Self {
        Self {
            id,
            username: username.into(),
            email: None,
            display_name: None,
            avatar_url: None,
            attributes: None,
        }
    }

    #[must_use]
    pub fn with_email(mut self, email: impl Into<String>) -> Self {
        self.email = Some(email.into());
        self
    }

    #[must_use]
    pub fn with_display_name(mut self, display_name: impl Into<String>) -> Self {
        self.display_name = Some(display_name.into());
        self
    }

    #[must_use]
    pub fn with_avatar_url(mut self, avatar_url: impl Into<String>) -> Self {
        self.avatar_url = Some(avatar_url.into());
        self
    }

    #[must_use]
    pub fn with_attributes(mut self, attributes: UserAttributes) -> Self {
        self.attributes = Some(attributes);
        self
    }
}

/// Pagination parameters for [`IdpPluginClient::list_users`].
///
/// Mirrors the `top`/`skip` convention used by
/// `account_management_sdk::ListChildrenQuery` so REST handlers can
/// translate the same query parameters without reshaping the values.
///
/// Both fields are private; construction goes through
/// [`UserPagination::new`] (which validates `top > 0` and accepts any
/// non-negative `skip`) or [`UserPagination::default`] (which returns
/// `top = DEFAULT_TOP, skip = 0`). Read via [`UserPagination::top`]
/// and [`UserPagination::skip`].
///
/// Private fields keep both values *set-once-at-construction* —
/// without this an external `let mut p = UserPagination::new(50,
/// 0).unwrap(); p.skip = 100;` could mutate `skip` after the
/// invariant check; while `top` cannot be similarly mutated (already
/// private), keeping `skip` `pub` left the two fields asymmetric for
/// no semantic gain.
///
/// `top = 0` would turn a tenant-scoped existence check
/// (`?user_id=<id>` -- `cpt-cf-account-management-flow-idp-user-operations-contract-list-users`)
/// into a false-negative empty page on providers that honor the
/// literal value, since AM cannot disambiguate "user absent" from
/// "page size was zero".
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(try_from = "RawUserPagination")]
#[non_exhaustive]
pub struct UserPagination {
    top: u32,
    skip: u32,
}

impl UserPagination {
    /// Default page size used by [`UserPagination::default`]. Chosen
    /// to match the AM tenant-CRUD listing default and stay below the
    /// `OpenAPI Top.maximum` typical value of 200.
    pub const DEFAULT_TOP: u32 = 50;

    /// Serde-attribute helper: returns [`Self::DEFAULT_TOP`]. Used by
    /// `RawUserPagination` so a wire payload that omits `top` still
    /// produces a non-zero page size when routed through
    /// [`UserPagination::new`]. Without this helper, omitting `top`
    /// would fail deserialization before `TryFrom` could substitute
    /// the default, contradicting the documented "default top = 50"
    /// contract.
    #[must_use]
    const fn default_top() -> u32 {
        Self::DEFAULT_TOP
    }

    /// Construct a validated pagination.
    ///
    /// # Errors
    ///
    /// Returns [`UserPaginationError::TopMustBePositive`] when `top`
    /// is zero.
    pub const fn new(top: u32, skip: u32) -> Result<Self, UserPaginationError> {
        if top == 0 {
            return Err(UserPaginationError::TopMustBePositive);
        }
        Ok(Self { top, skip })
    }

    /// Read-only access to the validated `top`. Always `>= 1` per the
    /// constructor invariant.
    #[must_use]
    pub const fn top(self) -> u32 {
        self.top
    }

    /// Read-only access to `skip`. Always set once at construction
    /// time so the value stays consistent with whatever validation
    /// the caller used to build the pagination.
    #[must_use]
    pub const fn skip(self) -> u32 {
        self.skip
    }
}

impl Default for UserPagination {
    fn default() -> Self {
        Self {
            top: Self::DEFAULT_TOP,
            skip: 0,
        }
    }
}

/// Wire shape for [`UserPagination`] deserialization. Mirrors the
/// public fields but skips the `top > 0` invariant -- the
/// [`TryFrom<RawUserPagination>`] impl below routes the value
/// through [`UserPagination::new`] so the invariant is enforced on
/// every serde input path, not just constructor calls.
///
/// `top` defaults to [`UserPagination::DEFAULT_TOP`] when absent in the
/// wire payload (matching the [`Default`] impl on `UserPagination`);
/// `skip` defaults to `0`. Without the `top` default, a wire payload
/// like `{"skip": 10}` would fail deserialization before the `TryFrom`
/// could substitute the configured default, contradicting the
/// documented "default top = 50" contract.
#[derive(Debug, Clone, Deserialize)]
struct RawUserPagination {
    #[serde(default = "UserPagination::default_top")]
    top: u32,
    #[serde(default)]
    skip: u32,
}

impl TryFrom<RawUserPagination> for UserPagination {
    type Error = UserPaginationError;

    fn try_from(raw: RawUserPagination) -> Result<Self, Self::Error> {
        Self::new(raw.top, raw.skip)
    }
}

/// Validation errors reported by [`UserPagination::new`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum UserPaginationError {
    /// `top` was zero; the user-list contract treats `top` as a
    /// strict positive page size so an existence-check filter cannot
    /// silently return an empty page.
    TopMustBePositive,
}

impl core::fmt::Display for UserPaginationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TopMustBePositive => f.write_str("top must be at least 1"),
        }
    }
}

impl core::error::Error for UserPaginationError {}

/// Page envelope returned by [`IdpPluginClient::list_users`].
///
/// Mirrors `account_management_sdk::TenantPage<T>` but is specialised
/// to [`UserProjection`] so plugin authors do not need to depend on
/// the tenant CRUD shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct UserPage {
    pub items: Vec<UserProjection>,
    pub top: u32,
    pub skip: u32,
    /// Total count of matching rows when the provider can return it
    /// cheaply; left `None` if the provider does not expose a total
    /// for the underlying directory query.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<u64>,
}

impl UserPage {
    /// Construct a fresh `UserPage`. The `#[non_exhaustive]` marker
    /// requires plugin authors to use this constructor so future
    /// field additions (e.g. `cursor`, `has_more`) are SemVer-safe.
    #[must_use]
    pub const fn new(items: Vec<UserProjection>, top: u32, skip: u32, total: Option<u64>) -> Self {
        Self {
            items,
            top,
            skip,
            total,
        }
    }
}

/// Request shape for [`IdpPluginClient::provision_user`].
///
/// `tenant_context.tenant_id` is the tenant the user is being
/// provisioned into; AM has already validated the scope is `Active`
/// before invoking the contract. There is intentionally no separate
/// `tenant_id` field on the request — carrying both a top-level
/// `tenant_id` and `tenant_context.tenant_id` previously made it
/// ambiguous which was authoritative; the context is the single
/// source of truth.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ProvisionUserRequest {
    /// Resolved tenant context (id, name, optional chained type).
    pub tenant_context: TenantContext,
    /// Profile-minimal payload to forward into the `IdP`.
    pub payload: NewUserPayload,
}

impl ProvisionUserRequest {
    #[must_use]
    pub const fn new(tenant_context: TenantContext, payload: NewUserPayload) -> Self {
        Self {
            tenant_context,
            payload,
        }
    }
}

/// Request shape for [`IdpPluginClient::deprovision_user`].
///
/// `tenant_context.tenant_id` is the tenant scope; see
/// [`ProvisionUserRequest`] for the duplication-removal rationale.
/// The resolved tenant context is forwarded on every contract method
/// per `cpt-cf-account-management-algo-idp-user-operations-contract-idp-contract-invocation`
/// step `package-request`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct DeprovisionUserRequest {
    pub tenant_context: TenantContext,
    pub user_id: Uuid,
}

impl DeprovisionUserRequest {
    #[must_use]
    pub const fn new(tenant_context: TenantContext, user_id: Uuid) -> Self {
        Self {
            tenant_context,
            user_id,
        }
    }
}

/// Request shape for [`IdpPluginClient::list_users`].
///
/// `tenant_context.tenant_id` is the tenant scope; see
/// [`ProvisionUserRequest`] for the duplication-removal rationale.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ListUsersRequest {
    pub tenant_context: TenantContext,
    /// Optional single-user filter. When `Some`, the provider returns
    /// either a one-element page (the user exists in this tenant
    /// scope) or an empty page (the user is absent). Both outcomes
    /// are success per
    /// `cpt-cf-account-management-flow-idp-user-operations-contract-list-users`.
    pub user_id_filter: Option<Uuid>,
    pub pagination: UserPagination,
}

impl ListUsersRequest {
    /// Construct a request with the two required fields.
    /// `user_id_filter` defaults to `None`; set it via
    /// [`Self::with_user_id_filter`] for the authoritative
    /// single-user existence-check shape.
    #[must_use]
    pub const fn new(tenant_context: TenantContext, pagination: UserPagination) -> Self {
        Self {
            tenant_context,
            user_id_filter: None,
            pagination,
        }
    }

    #[must_use]
    pub const fn with_user_id_filter(mut self, user_id: Uuid) -> Self {
        self.user_id_filter = Some(user_id);
        self
    }
}

/// Outcome of [`IdpPluginClient::deprovision_user`] on the success
/// path.
///
/// Splitting the success path into two variants (instead of folding
/// `NotFoundInTenant` into [`UserOperationFailure`]) keeps the trait
/// contract aligned with `algo-deprovision-idempotency-guard`: only
/// the absent outcome is an idempotent success, and an `Err(_)` from
/// the trait method is unambiguously a real failure (transport,
/// unsupported, rejected). AM's service layer maps
/// `Ok(NotFoundInTenant)` to `Ok(())` so `DELETE
/// /tenants/{tenant_id}/users/{user_id}` stays retry-safe per
/// `cpt-cf-account-management-fr-idp-user-deprovision`.
///
/// # Adding a variant
///
/// `#[non_exhaustive]` lets new outcomes ship in a minor SDK release
/// without breaking compilation, BUT every existing `AM`-side
/// mapping (`UserService::deprovision_user`) treats unknown
/// variants as a loud `DomainError::Internal` rather than silently
/// mapping to success or failure — the deprovision idempotency
/// guard cannot classify a new outcome's safety properties without
/// an explicit `AM`-side review. A new variant added here therefore
/// REQUIRES a matching `cf-account-management` patch landing in the
/// same release; deploying the SDK without the `AM` update will
/// surface HTTP 500 on the new path even when the `IdP` plugin
/// returns it as a success-shaped value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeprovisionUserOutcome {
    /// The user existed in this tenant scope and the `IdP` removed it.
    Removed,
    /// The user was already absent in this tenant scope. AM treats
    /// this as idempotent success (HTTP 204) per
    /// `cpt-cf-account-management-algo-idp-user-operations-contract-deprovision-idempotency-guard`.
    NotFoundInTenant,
}

impl DeprovisionUserOutcome {
    /// Stable, snake-case metric-label form of this variant. Mirrors
    /// [`UserOperationFailure::as_metric_label`] so AM-side
    /// observability emits a single, uniform discriminator on the
    /// `am.user.audit` channel — including the catch-all `Ok(_other)`
    /// branch in `UserService::deprovision_user`, which logs the
    /// variant label so a future SDK addition is grep-able the moment
    /// it lands. Takes `self` by value (this enum is `Copy`).
    ///
    /// `NotFoundInTenant` returns `"not_found_in_tenant"` (NOT
    /// `"already_absent"`, which is the label
    /// [`crate::idp::DeprovisionFailure::NotFound`] uses for the
    /// tenant-side already-absent outcome). The two pipelines emit
    /// on different `op` labels so the (op, outcome) tuple is unique,
    /// but operators alerting on `outcome=already_absent` alone would
    /// have seen both surfaces collide under one label. Disambiguating
    /// at the SDK keeps each pipeline's dashboard unambiguous.
    #[must_use]
    pub const fn as_metric_label(self) -> &'static str {
        match self {
            Self::Removed => "removed",
            Self::NotFoundInTenant => "not_found_in_tenant",
        }
    }
}

/// Failure discriminant shared by every user-operations contract
/// method.
///
/// AM's service layer maps each variant onto the canonical error
/// taxonomy via `cf-account-management::domain::idp` (the redaction +
/// public-envelope boundary). Plugin authors do not need to redact
/// `detail` themselves -- AM owns the public-surface mapping.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum UserOperationFailure {
    /// Provider was unreachable, the call timed out, or the transport
    /// returned a retryable failure. AM maps this to the public
    /// `idp_unavailable` code; no fallback projection is served per
    /// `cpt-cf-account-management-constraint-no-user-storage`.
    Unavailable { detail: String },
    /// Provider declined the operation in its current implementation
    /// profile (typically a read-only or legacy provider that does
    /// not support mutating user operations). AM maps this to
    /// `idp_unsupported_operation`. Providers MUST NOT silently no-op
    /// a mutating call.
    UnsupportedOperation { detail: String },
    /// Provider returned a payload-rejection category (e.g. duplicate
    /// username, validation failure on email format). AM maps this to
    /// the canonical validation envelope; the catalog refinement is
    /// owned by `feature-errors-observability`.
    Rejected { detail: String },
}

impl UserOperationFailure {
    /// Stable, snake-case metric-label form of this variant. Used by
    /// AM-side observability when emitting per-call outcome metrics
    /// (the metric catalog itself is owned by
    /// `feature-errors-observability`); kept on the SDK type so
    /// producers do not duplicate the variant -> string mapping in
    /// match arms.
    #[must_use]
    pub const fn as_metric_label(&self) -> &'static str {
        match self {
            Self::Unavailable { .. } => "unavailable",
            Self::UnsupportedOperation { .. } => "unsupported_operation",
            Self::Rejected { .. } => "rejected",
        }
    }

    /// Raw provider-supplied `detail` string carried by every variant.
    /// Mirrors [`crate::idp::CheckAvailabilityFailure::detail`],
    /// [`crate::idp::ProvisionFailure::detail`], and
    /// [`crate::idp::DeprovisionFailure::detail`] so consumers read
    /// the detail uniformly across all `IdP` failure enums.
    #[must_use]
    pub fn detail(&self) -> &str {
        match self {
            Self::Unavailable { detail }
            | Self::UnsupportedOperation { detail }
            | Self::Rejected { detail } => detail,
        }
    }
}

impl core::fmt::Display for UserOperationFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}: {}", self.as_metric_label(), self.detail())
    }
}

impl core::error::Error for UserOperationFailure {}

#[cfg(test)]
#[path = "idp_user_tests.rs"]
mod tests;
