//! Tenant-metadata domain module.
//!
//! Implements FEATURE `tenant-metadata` (see
//! `modules/system/account-management/docs/features/feature-tenant-metadata.md`).
//!
//! This module owns the storage seam ([`repo::MetadataRepo`]) and the
//! pure value types ([`MetadataRow`], [`UpsertOutcome`]) that the future
//! `MetadataService` (Phase 3) and `MetadataRepoImpl` (Phase 4) will
//! compose against.
//!
//! Layering (mirrors [`crate::domain::conversion`]):
//!
//! * [`MetadataRow`] / [`UpsertOutcome`] — pure value types projected by
//!   the repo trait. The row mirrors the `tenant_metadata` entity 1:1
//!   (`tenant_id`, `schema_uuid`, opaque `value`, `created_at`,
//!   `updated_at`); `UpsertOutcome` carries the discriminator the
//!   service layer maps to HTTP 200 / 201 in Phase 3.
//! * [`repo`] — the [`repo::MetadataRepo`] trait that the service layer
//!   talks to. The `SeaORM`-backed implementation lands in Phase 4
//!   under `crate::infra::storage::repo_impl::metadata`; an in-memory
//!   fake for unit tests lives under [`test_support`].
//!
//! No service / SDK / REST surface is wired in this module yet. Phase 3
//! introduces `MetadataService::{list, get, put, delete, resolve}`;
//! Phase 4 introduces `MetadataRepoImpl` and the cross-tenant cascade
//! hook used by `TenantRepoImpl::hard_delete_one` on `SQLite`.

use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use modkit_macros::domain_model;

pub mod registry;
pub mod repo;
pub mod service;

#[cfg(test)]
pub(crate) mod test_support;

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[path = "service_tests.rs"]
mod service_tests;

/// One direct-on-tenant metadata entry.
///
/// Mirrors [`crate::infra::storage::entity::tenant_metadata::Model`]
/// column-for-column. The `value` column carries an opaque
/// GTS-validated payload; the storage entity types it as `Json` while
/// this domain model uses [`serde_json::Value`] so the service layer
/// (Phase 3) can pass payloads from `account-management-sdk::metadata`
/// without dragging the `SeaORM` `Json` newtype into the public surface.
#[domain_model]
#[derive(Debug, Clone)]
pub struct MetadataRow {
    pub tenant_id: Uuid,
    pub schema_uuid: Uuid,
    pub value: Value,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

/// Discriminated upsert result returned by
/// [`repo::MetadataRepo::upsert_for_tenant`].
///
/// The service layer (Phase 3) maps the discriminator onto HTTP 201 vs
/// 200 per FEATURE §3.3 / §6 AC line 393. Both arms carry the
/// post-upsert row snapshot so the handler can build the response body
/// without a follow-up `SELECT`.
#[domain_model]
#[derive(Debug, Clone)]
pub enum UpsertOutcome {
    /// The row did not exist before this call — maps to HTTP 201.
    Inserted(MetadataRow),
    /// The row already existed and was updated — maps to HTTP 200.
    Updated(MetadataRow),
}

impl UpsertOutcome {
    /// Borrow the post-upsert row snapshot regardless of arm.
    #[must_use]
    pub fn row(&self) -> &MetadataRow {
        match self {
            Self::Inserted(row) | Self::Updated(row) => row,
        }
    }

    /// Convert into the post-upsert row, dropping the insert/update
    /// discriminator. Useful for unit tests that only need to assert on
    /// the column shape.
    #[must_use]
    pub fn into_row(self) -> MetadataRow {
        match self {
            Self::Inserted(row) | Self::Updated(row) => row,
        }
    }

    /// Returns `true` iff the upsert created a new row.
    #[must_use]
    pub const fn was_inserted(&self) -> bool {
        matches!(self, Self::Inserted(_))
    }
}

/// Repo-level pagination shape consumed by
/// [`repo::MetadataRepo::list_for_tenant`].
///
/// Lives in the domain module (rather than in [`service`]) so the repo
/// trait can reference it without an upward dependency on the service
/// layer. Mirrors `account-management-sdk::ListChildrenQuery` ergonomics
/// — `top` is a strict positive page size; `skip` is a non-negative
/// offset. The fields are `pub` for ergonomic struct-update / pattern
/// matching but the `top > 0` invariant is enforced at the
/// [`MetadataPagination::new`] constructor; the REST handler binds the
/// query-string + JSON path through `new` and the constructors
/// [`first_page`] / [`unlimited`] below. Tests that need to construct
/// the struct directly should also go through `new` so the invariant
/// stays a single source of truth.
///
/// [`first_page`]: Self::first_page
/// [`unlimited`]: Self::unlimited
#[domain_model]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetadataPagination {
    pub top: u32,
    pub skip: u32,
}

/// Validation errors reported by [`MetadataPagination::new`].
#[domain_model]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MetadataPaginationError {
    /// `top` was zero; `OpenAPI` binding pins `Top.minimum = 1`.
    TopMustBePositive,
}

impl core::fmt::Display for MetadataPaginationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TopMustBePositive => f.write_str("top must be at least 1"),
        }
    }
}

impl core::error::Error for MetadataPaginationError {}

impl MetadataPagination {
    /// Default page size used by [`Self::first_page`]. Matches
    /// `account-management-sdk::ListChildrenQuery`'s `DEFAULT_TOP`.
    pub const DEFAULT_TOP: u32 = 50;

    /// Construct a validated pagination cursor.
    ///
    /// # Errors
    ///
    /// Returns [`MetadataPaginationError::TopMustBePositive`] when
    /// `top` is zero -- `top = 0` would produce `LIMIT 0` SQL and
    /// silently return an empty page with the real `total` count,
    /// which the `OpenAPI` contract (`Top.minimum = 1`) does not
    /// permit. Mirrors `ListChildrenQuery::new` in the AM SDK.
    pub const fn new(top: u32, skip: u32) -> Result<Self, MetadataPaginationError> {
        if top == 0 {
            return Err(MetadataPaginationError::TopMustBePositive);
        }
        Ok(Self { top, skip })
    }

    /// Build a first-page query with [`Self::DEFAULT_TOP`] rows starting
    /// at offset 0. Useful for unit tests that don't care about cursor
    /// mechanics.
    #[must_use]
    pub const fn first_page() -> Self {
        Self {
            top: Self::DEFAULT_TOP,
            skip: 0,
        }
    }

    /// Build an "effectively unlimited" page (`top = u32::MAX, skip = 0`).
    /// Repo-direct callers in integration tests that assert on the full
    /// row set use this; production handlers always pass an explicit
    /// `top`.
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            top: u32::MAX,
            skip: 0,
        }
    }
}

/// Page envelope returned by [`repo::MetadataRepo::list_for_tenant`].
///
/// Carries the per-page rows plus the unfiltered `total` row count for
/// the tenant (independent of `top`/`skip`) so the service layer can
/// surface accurate pagination metadata to the public `ListMetadataPage`
/// without a second query.
#[domain_model]
#[derive(Debug, Clone)]
pub struct MetadataRowsPage {
    pub rows: Vec<MetadataRow>,
    pub total: u64,
}
