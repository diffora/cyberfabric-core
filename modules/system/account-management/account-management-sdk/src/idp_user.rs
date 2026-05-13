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
//! [`User`] mirrors the published GTS schema
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

/// Resolved tenant snapshot surfaced to provider plugins so they can
/// route to `IdP`-specific identifiers (Keycloak realm, Zitadel
/// organization, vendor-side org id, etc.).
///
/// AM resolves the tenant via `TenantService` and loads any opaque
/// plugin-private state from `tenant_idp_metadata` before invoking
/// the contract; the resolved snapshot is forwarded here so the
/// plugin does not round-trip back to AM for data it could receive
/// inline.
///
/// # Field set
///
/// * `tenant_id` — the stable identifier the plugin keys vendor-side
///   state on.
/// * `tenant_name` — the current human-readable label. AM treats it
///   as mutable (tenant rename is allowed) so the value reflects
///   AM's source of truth at call time, not a snapshot from the
///   provisioning call.
/// * `tenant_type` — the resolved chained GTS identifier
///   (e.g. `gts.cf.core.am.tenant_type.v1~cf.core.am.customer.v1~`).
///   Mandatory: AM treats a Types Registry outage as a service-level
///   failure on user-ops (surfaces as `ServiceUnavailable`) rather
///   than leaking an `Option` into the plugin contract. Immutable
///   post-creation.
/// * `metadata` — opaque plugin-private blob persisted by AM in
///   `tenant_idp_metadata` and replayed on every subsequent `IdP` call
///   for this tenant. Returned by the plugin from
///   [`crate::idp::ProvisionResult::metadata`]; `None` when the
///   plugin owns no per-tenant state. AM does NOT interpret the
///   shape; the plugin is the sole owner.
///
/// # Why these fields and not more
///
/// The four fields are the minimum AM commits to surface uniformly
/// on every "operates on existing tenant" call (`provision_user`,
/// `deprovision_user`, `list_users`, `deprovision_tenant`). Anything
/// else the plugin needs it stashes inside `metadata` at
/// `provision_tenant` time and reads back from there.
///
/// # Adding fields
///
/// `#[non_exhaustive]` lets the SDK add fields (`parent_id`,
/// resolver-specific descriptors, etc.) in a minor release without
/// breaking compilation. New fields default to safe values on
/// constructors that predate them.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
#[allow(
    clippy::struct_field_names,
    reason = "every field IS tenant-scoped (id / name / type / metadata) and stripping the prefix loses the public contract that the value comes from AM-resolved tenant state"
)]
pub struct TenantContext {
    /// Stable tenant identifier (the same UUID stored in AM's
    /// `tenants.id` column).
    pub tenant_id: Uuid,
    /// Human-readable tenant name, useful for plugins that derive
    /// provider-side identifiers from the tenant label (e.g. a
    /// Keycloak realm whose name follows the tenant slug).
    pub tenant_name: String,
    /// Resolved tenant type as a chained `GtsSchemaId`
    /// (e.g. `gts.cf.core.am.tenant_type.v1~cf.core.am.customer.v1~`).
    /// Mandatory at the contract boundary — AM treats failures of
    /// the underlying Types Registry reverse-resolve as service-
    /// level errors rather than leaking an `Option` into the plugin.
    pub tenant_type: GtsSchemaId,
    /// Opaque plugin-private metadata persisted by AM in
    /// `tenant_idp_metadata`. AM replays whatever the plugin returned
    /// from [`crate::idp::ProvisionResult::metadata`] on every
    /// subsequent `IdP` call for this tenant. `None` when the plugin
    /// returned no metadata, or before the plugin has been called
    /// for this tenant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

impl TenantContext {
    /// Build a [`TenantContext`] from the resolved tenant snapshot.
    #[must_use]
    pub fn new(
        tenant_id: Uuid,
        tenant_name: impl Into<String>,
        tenant_type: GtsSchemaId,
        metadata: Option<Value>,
    ) -> Self {
        Self {
            tenant_id,
            tenant_name: tenant_name.into(),
            tenant_type,
            metadata,
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
pub struct NewUser {
    /// Login identifier (REQUIRED per the published schema).
    pub username: String,
    /// Optional contact email surfaced through the projection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Optional display name surfaced through the projection.
    /// Plugin authors derive this from vendor-specific shapes —
    /// Keycloak combines `firstName`/`lastName`; OIDC providers
    /// fold `given_name`/`family_name`/`name` claims.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Optional provider-defined non-authoritative attributes
    /// forwarded verbatim into the `IdP` create call. AM does not
    /// inspect or transform these. Typed as a string-keyed map so
    /// non-object payloads are unrepresentable at the SDK boundary
    /// per the published schema's `{"type": "object"}` declaration.
    /// Vendor-specific profile fields that AM does not model
    /// natively (avatar/picture URLs, federation hints, custom
    /// claims) live here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<UserAttributes>,
}

impl NewUser {
    /// Construct a payload with only the required `username`. Use
    /// the `with_*` setters to populate optional profile fields.
    #[must_use]
    pub fn new(username: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            email: None,
            display_name: None,
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
    pub fn with_attributes(mut self, attributes: UserAttributes) -> Self {
        self.attributes = Some(attributes);
        self
    }
}

/// Public projection of the `gts.cf.core.am.user.v1~` GTS schema.
///
/// The shape is the contract for downstream consumers (e.g.
/// `feature-user-groups` membership existence checks, audit pipeline).
/// No `IdP`-internal identifier, credential, or membership cache is
/// included per `cpt-cf-account-management-adr-idp-user-identity-source-of-truth`
/// and `cpt-cf-account-management-adr-idp-user-tenant-binding`.
///
/// The GTS schema identifier is exported as
/// [`crate::gts::USER_RESOURCE_TYPE`] for use in canonical-error
/// envelopes and PEP rules. The struct itself is not annotated with
/// `gts_macros::struct_to_gts_schema` because the macro's "base
/// type" contract requires the struct to carry either a
/// `GtsInstanceId`-typed `id` field or a `GtsSchemaId`-typed
/// `gts_type` field — `User.id` is the IdP-issued domain UUID
/// (Keycloak's user UUID, etc.), not a GTS instance identifier, so
/// the two semantics are intentionally distinct.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct User {
    /// `IdP`-issued UUID user identifier. The provider owns the issuance
    /// and the value is stable across the user's lifetime in this
    /// tenant scope.
    pub id: Uuid,
    /// Login identifier (REQUIRED per the schema).
    pub username: String,
    /// Optional contact email.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Optional display name. Plugin authors derive this from
    /// vendor-specific shapes (Keycloak `firstName`+`lastName`,
    /// OIDC `name`/`given_name`/`family_name` claims, etc.).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Optional provider-defined non-authoritative attributes
    /// forwarded from the `IdP`. Opaque to AM. Typed as a string-keyed
    /// map so non-object payloads are unrepresentable at the SDK
    /// boundary per the published schema's `{"type": "object"}`
    /// declaration. Vendor-specific profile fields AM does not model
    /// natively (avatar/picture URLs, federation hints, custom
    /// claims) live here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<UserAttributes>,
}

impl User {
    /// Construct a projection with the two required schema fields.
    /// Use the `with_*` setters for optional profile fields.
    #[must_use]
    pub fn new(id: Uuid, username: impl Into<String>) -> Self {
        Self {
            id,
            username: username.into(),
            email: None,
            display_name: None,
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
    pub fn with_attributes(mut self, attributes: UserAttributes) -> Self {
        self.attributes = Some(attributes);
        self
    }
}

/// Pagination parameters for [`IdpPluginClient::list_users`].
///
/// Cursor-based, wire-compatible with `modkit_odata::Page<T>` (same
/// envelope `cyberware-resource-group-sdk` and the AM REST surface
/// will use). The cursor itself is an **opaque token owned by the
/// `IdP` plugin** — AM never inspects, signs, or namespaces it. A
/// plugin backed by a SQL store SHOULD embed a filter hash and a
/// stable sort key in the cursor (see
/// [`modkit_odata::pagination`]) so that a client switching
/// `user_id_filter` mid-pagination receives a deterministic
/// invalid-cursor error instead of silently jumping pages; a plugin
/// wrapping a vendor SDK (e.g. Zitadel `next_token`) MAY forward the
/// native token unchanged.
///
/// `top` and `cursor` are private; construction goes through
/// [`UserPagination::new`] / [`UserPagination::default`]. Read via
/// [`UserPagination::top`] and [`UserPagination::cursor`].
///
/// `top = 0` would turn a tenant-scoped existence check
/// (`?user_id=<id>` --
/// `cpt-cf-account-management-flow-idp-user-operations-contract-list-users`)
/// into a false-negative empty page on providers that honor the
/// literal value, since AM cannot disambiguate "user absent" from
/// "page size was zero".
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(try_from = "RawUserPagination")]
#[non_exhaustive]
pub struct UserPagination {
    top: u32,
    cursor: Option<String>,
}

impl UserPagination {
    /// Default page size used by [`UserPagination::default`]. Chosen
    /// to match the AM tenant-CRUD listing default and stay below
    /// [`Self::MAX_TOP`].
    pub const DEFAULT_TOP: u32 = 50;

    /// Upper bound enforced by [`UserPagination::new`]. Matches the
    /// `OpenAPI Top.maximum` typical value referenced in the AM tenant-
    /// CRUD listing surface. Mirrors the DB-side row-count ceiling so a
    /// misbehaving (or compromised) `IdP` plugin asked to return
    /// `top = u32::MAX` users cannot exhaust the page-buffer allocation.
    pub const MAX_TOP: u32 = 200;

    /// Cap on the opaque cursor string AM is willing to forward. The
    /// cursor is plugin-shaped — AM never parses it — but caps the
    /// length so a hostile / buggy plugin cannot recycle a request
    /// into an unbounded heap allocation through the AM proxy. `4
    /// KiB` is generous for `modkit_odata`-shaped cursors
    /// (`{filter_hash, last_seen_id, limit}` base64) and for
    /// vendor-native tokens (Zitadel `next_token` is bytes; Keycloak
    /// plugin-encoded `(filter_hash, offset)` fits easily).
    pub const MAX_CURSOR_LEN: usize = 4096;

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
    /// * [`UserPaginationError::TopMustBePositive`] when `top` is zero.
    /// * [`UserPaginationError::TopExceedsMax`] when `top` exceeds
    ///   [`Self::MAX_TOP`] — guards against a caller forwarding
    ///   `top = u32::MAX` straight to the `IdP` plugin.
    /// * [`UserPaginationError::CursorTooLong`] when the supplied
    ///   cursor exceeds [`Self::MAX_CURSOR_LEN`] bytes.
    pub fn new(top: u32, cursor: Option<String>) -> Result<Self, UserPaginationError> {
        if top == 0 {
            return Err(UserPaginationError::TopMustBePositive);
        }
        if top > Self::MAX_TOP {
            return Err(UserPaginationError::TopExceedsMax {
                requested: top,
                max: Self::MAX_TOP,
            });
        }
        if let Some(ref c) = cursor
            && c.len() > Self::MAX_CURSOR_LEN
        {
            return Err(UserPaginationError::CursorTooLong {
                len: c.len(),
                max: Self::MAX_CURSOR_LEN,
            });
        }
        Ok(Self { top, cursor })
    }

    /// Read-only access to the validated `top`. Always `>= 1` per the
    /// constructor invariant.
    #[must_use]
    pub const fn top(&self) -> u32 {
        self.top
    }

    /// Read-only access to the opaque, plugin-shaped cursor (if any).
    /// The first page of a listing has `cursor = None`; subsequent
    /// pages echo back the `next_cursor` the plugin returned in the
    /// previous [`modkit_odata::Page::page_info`].
    #[must_use]
    pub fn cursor(&self) -> Option<&str> {
        self.cursor.as_deref()
    }
}

impl Default for UserPagination {
    fn default() -> Self {
        Self {
            top: Self::DEFAULT_TOP,
            cursor: None,
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
/// `cursor` defaults to `None`. Without the `top` default, a wire payload
/// like `{"cursor": "..."}` would fail deserialization before the `TryFrom`
/// could substitute the configured default, contradicting the
/// documented "default top = 50" contract.
#[derive(Debug, Clone, Deserialize)]
struct RawUserPagination {
    #[serde(default = "UserPagination::default_top")]
    top: u32,
    #[serde(default)]
    cursor: Option<String>,
}

impl TryFrom<RawUserPagination> for UserPagination {
    type Error = UserPaginationError;

    fn try_from(raw: RawUserPagination) -> Result<Self, Self::Error> {
        Self::new(raw.top, raw.cursor)
    }
}

/// Validation errors reported by [`UserPagination::new`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum UserPaginationError {
    /// `top` was zero; the user-list contract treats `top` as a
    /// strict positive page size so an existence-check filter cannot
    /// silently return an empty page.
    TopMustBePositive,
    /// `top` exceeded [`UserPagination::MAX_TOP`]. Caps the page size
    /// AM is willing to ask an `IdP` plugin for, so a literal
    /// `top = u32::MAX` cannot trigger an unbounded allocation in the
    /// provider.
    TopExceedsMax { requested: u32, max: u32 },
    /// The opaque cursor exceeded [`UserPagination::MAX_CURSOR_LEN`].
    /// AM forwards cursors as-is, so capping the length is the only
    /// defense against a hostile / buggy plugin trying to recycle a
    /// listing into an unbounded heap allocation through the AM
    /// proxy.
    CursorTooLong { len: usize, max: usize },
}

impl core::fmt::Display for UserPaginationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TopMustBePositive => f.write_str("top must be at least 1"),
            Self::TopExceedsMax { requested, max } => {
                write!(f, "top {requested} exceeds maximum {max}")
            }
            Self::CursorTooLong { len, max } => {
                write!(f, "cursor length {len} exceeds maximum {max}")
            }
        }
    }
}

impl core::error::Error for UserPaginationError {}

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
    pub payload: NewUser,
}

impl ProvisionUserRequest {
    #[must_use]
    pub const fn new(tenant_context: TenantContext, payload: NewUser) -> Self {
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
