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

use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

pub use tenant_resolver_sdk::{TenantId, TenantInfo, TenantStatus};

/// Input for the create-child-tenant flow.
///
/// `tenant_type` is a chained GTS identifier (e.g.
/// `gts.cf.core.am.tenant_type.v1~x.core.am.customer.v1~`); AM derives
/// the canonical `UUIDv5` via [`gts::GtsID`] internally so callers do not
/// supply two parallel identifiers (which used to drift).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateChildInput {
    pub child_id: Uuid,
    pub parent_id: Uuid,
    pub name: String,
    #[serde(default)]
    pub self_managed: bool,
    pub tenant_type: String,
    /// Opaque provider-specific metadata forwarded to the `IdP` plugin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provisioning_metadata: Option<Value>,
}

/// Patch shape for the update-tenant flow. An empty patch (both fields
/// `None`) is rejected at the service boundary per the `OpenAPI`
/// `minProperties: 1` rule on `TenantUpdateRequest`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TenantUpdate {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<TenantStatus>,
}

impl TenantUpdate {
    /// Whether this patch is effectively empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.name.is_none() && self.status.is_none()
    }
}

/// Pagination + filter query for list-children.
///
/// `status_filter` is a private field — construct via
/// [`ListChildrenQuery::new`], which validates `top > 0`. The
/// `Provisioning` status is **not** part of [`TenantStatus`] on the
/// public boundary, so it cannot appear in the filter by construction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListChildrenQuery {
    pub parent_id: Uuid,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    status_filter: Option<Vec<TenantStatus>>,
    pub top: u32,
    #[serde(default)]
    pub skip: u32,
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
        Ok(Self {
            parent_id,
            status_filter,
            top,
            skip,
        })
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantPage<T> {
    pub items: Vec<T>,
    pub top: u32,
    pub skip: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<u64>,
}

#[cfg(test)]
#[path = "tenant_tests.rs"]
mod tests;
