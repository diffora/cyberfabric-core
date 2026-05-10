//! Public input/output contract for AM tenant CRUD.
//!
//! These are the shapes that pass through the AM REST boundary
//! (request bodies, query parameters, response envelopes) and through
//! any inter-module Rust callers wired through `ClientHub`. They are
//! deliberately slim and stable:
//!
//! * Inputs ([`CreateChildInput`], [`TenantUpdate`], [`ListChildrenQuery`])
//!   carry only what callers must supply. Internal storage details
//!   (`UUIDv5` derivations, hierarchy depth, lifecycle timestamps) live on
//!   AM-internal shapes in the impl crate and never appear here.
//! * Output reuses [`TenantInfo`] (re-exported from
//!   [`tenant_resolver_sdk`]) so the resolver subsystem and AM speak the
//!   same vocabulary on the public boundary — no duplicated tenant DTOs
//!   across CF SDKs.
//! * Status uses [`TenantStatus`] from `tenant-resolver-sdk` (3 public
//!   variants: `Active` / `Suspended` / `Deleted`). AM's internal
//!   4-variant `TenantStatus` (with `Provisioning`) is service-internal
//!   and is filtered out before any value crosses this boundary.

use gts::GtsSchemaId;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

pub use tenant_resolver_sdk::{TenantId, TenantInfo, TenantStatus};

/// Input for the create-child-tenant flow.
///
/// `tenant_type` is a chained GTS identifier (e.g.
/// `gts.cf.core.am.tenant_type.v1~cf.core.am.customer.v1~`); AM derives
/// the canonical `UUIDv5` via [`gts::GtsID`] internally so callers do not
/// supply two parallel identifiers (which used to drift). The field is
/// typed [`GtsSchemaId`] rather than `String` so callers (REST handler,
/// inter-module Rust consumers) get a self-documenting contract and
/// any generated JSON Schema annotates the field with
/// `format: gts-schema-id`. Wire shape stays a string.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct CreateChildInput {
    pub child_id: Uuid,
    pub parent_id: Uuid,
    pub name: String,
    #[serde(default)]
    pub self_managed: bool,
    pub tenant_type: GtsSchemaId,
    /// Opaque provider-specific metadata forwarded to the `IdP` plugin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provisioning_metadata: Option<Value>,
}

impl CreateChildInput {
    /// Construct the input with the four required fields.
    /// `self_managed` defaults to `false`; `provisioning_metadata`
    /// defaults to `None`. Use [`Self::with_self_managed`] and
    /// [`Self::with_provisioning_metadata`] when overriding.
    #[must_use]
    pub fn new(
        child_id: Uuid,
        parent_id: Uuid,
        name: impl Into<String>,
        tenant_type: GtsSchemaId,
    ) -> Self {
        Self {
            child_id,
            parent_id,
            name: name.into(),
            self_managed: false,
            tenant_type,
            provisioning_metadata: None,
        }
    }

    #[must_use]
    pub const fn with_self_managed(mut self, self_managed: bool) -> Self {
        self.self_managed = self_managed;
        self
    }

    #[must_use]
    pub fn with_provisioning_metadata(mut self, value: Value) -> Self {
        self.provisioning_metadata = Some(value);
        self
    }
}

/// Patch shape for the update-tenant flow. An empty patch (both fields
/// `None`) is rejected at the service boundary per the `OpenAPI`
/// `minProperties: 1` rule on `TenantUpdateRequest`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct TenantUpdate {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<TenantStatus>,
}

impl TenantUpdate {
    /// Construct an empty patch. Both fields default to `None` and
    /// are set via [`Self::with_name`] / [`Self::with_status`].
    /// An all-`None` patch is rejected at the service boundary.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            name: None,
            status: None,
        }
    }

    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    #[must_use]
    pub const fn with_status(mut self, status: TenantStatus) -> Self {
        self.status = Some(status);
        self
    }

    /// Whether this patch is effectively empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.name.is_none() && self.status.is_none()
    }
}

/// Pagination + filter query for `list_children`.
///
/// Construct via [`ListChildrenQuery::new`] (validates `top > 0`); the
/// serde path routes through [`RawListChildrenQuery`] + [`TryFrom`] so
/// the same invariant is enforced on every deserialization input.
///
/// Field visibility encodes invariants:
/// * `parent_id`, `skip` — public; no invariant (zero `skip` is fine).
/// * `top` — private. Read via [`ListChildrenQuery::top`]. Made private
///   because the contract requires `top > 0`, and a `pub` field would
///   let serde set it to `0` and bypass [`ListChildrenQuery::new`].
/// * `status_filter` — private. Read via
///   [`ListChildrenQuery::status_filter`]. Encapsulated to keep the
///   `None`/empty-vec equivalence rule (see the getter doc) consistent
///   across all callers. The `Provisioning` status is **not** part of
///   [`TenantStatus`] on the public boundary, so it cannot appear in
///   the filter by construction.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(try_from = "RawListChildrenQuery")]
pub struct ListChildrenQuery {
    pub parent_id: Uuid,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    status_filter: Option<Vec<TenantStatus>>,
    top: u32,
    #[serde(default)]
    pub skip: u32,
}

/// Wire shape for [`ListChildrenQuery`] deserialization. Mirrors the
/// public fields but skips the `top > 0` invariant — the
/// [`TryFrom<RawListChildrenQuery>`] impl below routes the value
/// through [`ListChildrenQuery::new`] so the invariant is enforced on
/// every serde input path, not just constructor calls.
#[derive(Debug, Clone, Deserialize)]
struct RawListChildrenQuery {
    parent_id: Uuid,
    #[serde(default)]
    status_filter: Option<Vec<TenantStatus>>,
    #[serde(default = "ListChildrenQuery::default_top")]
    top: u32,
    #[serde(default)]
    skip: u32,
}

impl TryFrom<RawListChildrenQuery> for ListChildrenQuery {
    type Error = ListChildrenQueryError;

    fn try_from(raw: RawListChildrenQuery) -> Result<Self, Self::Error> {
        Self::new(raw.parent_id, raw.status_filter, raw.top, raw.skip)
    }
}

/// Validation errors reported by [`ListChildrenQuery::new`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ListChildrenQueryError {
    /// `top` was zero; `OpenAPI` `Top.minimum = 1`.
    TopMustBePositive,
}

impl core::fmt::Display for ListChildrenQueryError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TopMustBePositive => f.write_str("top must be at least 1"),
        }
    }
}

impl core::error::Error for ListChildrenQueryError {}

impl ListChildrenQuery {
    /// Default page size used when serde input omits `top` (e.g.
    /// `GET /tenants/{id}/children?skip=10`). Mirrors
    /// [`crate::idp_user::UserPagination::DEFAULT_TOP`] so REST
    /// handlers apply the same fallback across tenant-CRUD and
    /// user-ops listings.
    pub const DEFAULT_TOP: u32 = 50;

    /// Serde-attribute helper: returns [`Self::DEFAULT_TOP`]. Used by
    /// [`RawListChildrenQuery`] so a wire payload that omits `top`
    /// still produces a non-zero page size when routed through
    /// [`ListChildrenQuery::new`]. Without this helper, omitting `top`
    /// would fail deserialization with "missing field `top`" —
    /// diverging from [`crate::idp_user::UserPagination`], which
    /// already defaults to its `DEFAULT_TOP`.
    #[must_use]
    const fn default_top() -> u32 {
        Self::DEFAULT_TOP
    }

    /// Construct a validated query.
    ///
    /// # Errors
    ///
    /// Returns [`ListChildrenQueryError::TopMustBePositive`] when `top`
    /// is zero.
    pub fn new(
        parent_id: Uuid,
        status_filter: Option<Vec<TenantStatus>>,
        top: u32,
        skip: u32,
    ) -> Result<Self, ListChildrenQueryError> {
        if top == 0 {
            return Err(ListChildrenQueryError::TopMustBePositive);
        }
        // Normalize `Some(vec![])` to `None` so the documented
        // contract on `status_filter()` ("empty vector is treated
        // identically to `None`") is enforced at construction time
        // rather than relying on every consumer to remember the
        // equivalence.
        let status_filter = status_filter.filter(|v| !v.is_empty());
        Ok(Self {
            parent_id,
            status_filter,
            top,
            skip,
        })
    }

    /// Read-only access to the validated `top`. Always `>= 1` per the
    /// constructor invariant.
    #[must_use]
    pub const fn top(&self) -> u32 {
        self.top
    }

    /// Read-only access to the validated `status_filter`. `None` means
    /// "default visibility set" — repo applies its own SDK-visible
    /// default. An empty vector is treated identically to `None`.
    #[must_use]
    pub fn status_filter(&self) -> Option<&[TenantStatus]> {
        self.status_filter.as_deref()
    }
}

/// Page envelope returned by list-children.
///
/// Generic over the item shape so AM-internal callers (repo trait) can
/// instantiate `TenantPage<TenantModel>` with the full storage row,
/// while the public service boundary returns `TenantPage<TenantInfo>`
/// with the slim shape consumers expect.
///
/// `total` is a best-effort snapshot — `list` and `count` are two
/// independent reads on the repo seam, so under concurrent writes
/// `total` may disagree with `items.len()` by one (READ COMMITTED
/// on Postgres; per-statement autocommit on `SQLite`). Consumers
/// driving `has_more` from `(total - skip) > top` should treat the
/// number as advisory rather than authoritative.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct TenantPage<T> {
    pub items: Vec<T>,
    pub top: u32,
    pub skip: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<u64>,
}

impl<T> TenantPage<T> {
    /// Construct a page envelope. `total = None` is the documented
    /// shape when the underlying source does not surface a total
    /// count cheaply.
    #[must_use]
    pub const fn new(items: Vec<T>, top: u32, skip: u32, total: Option<u64>) -> Self {
        Self {
            items,
            top,
            skip,
            total,
        }
    }
}

#[cfg(test)]
#[path = "tenant_tests.rs"]
mod tests;
