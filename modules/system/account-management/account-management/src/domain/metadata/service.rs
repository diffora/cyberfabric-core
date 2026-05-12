//! `MetadataService` — domain orchestrator for the tenant-metadata
//! subsystem.
//!
//! Implements FEATURE `tenant-metadata` (see
//! `modules/system/account-management/docs/features/feature-tenant-metadata.md`).
//!
//! Five operations:
//!
//! * [`MetadataService::list_for_tenant`] — paginated direct-on-tenant
//!   listing (NO ancestor walk per FEATURE §3.1).
//! * [`MetadataService::get_for_tenant`] — single-entry read; surfaces
//!   the distinct-404 split (`metadata_schema_not_registered` vs
//!   `metadata_entry_not_found`).
//! * [`MetadataService::put_for_tenant`] — upsert at
//!   `(tenant_id, schema_uuid)`; returns a [`PutMetadataOutcome`] that
//!   carries the insert-vs-update discriminator the future REST layer
//!   maps to HTTP 201 / 200 per FEATURE §6 AC line 393.
//! * [`MetadataService::delete_for_tenant`] — non-idempotent delete;
//!   missing rows surface as `MetadataEntryNotFound` per
//!   `dod-tenant-metadata-distinct-404-codes`.
//! * [`MetadataService::resolve_for_tenant`] — barrier-aware walk-up
//!   resolution per `algo-tenant-metadata-resolve-walk-up` and
//!   ADR-0002.
//!
//! # Layering invariant — application-only enforcement (ADR-0002)
//!
//! Inheritance semantics live exclusively in [`MetadataService`]. The
//! storage layer carries only directly-written rows; there is no DB
//! trigger, no materialized inheritance column, no walk-up SQL view.
//! Any SQL reader bypassing this service therefore sees only the
//! direct values for a given tenant — consumers that need inherited
//! values MUST go through this entry point or the future
//! `/api/.../resolved` REST endpoint.
//!
//! # Per-schema authorization (note-only)
//!
//! REST is deferred until cyberfabric-core#1813. The service has no
//! `PolicyEnforcer`-shaped dependency. To prepare for the eventual
//! REST drop-in, every per-schema operation emits the public chained
//! `schema_id` on its `am.events` tracing line so a future handler
//! can wire `PolicyEnforcer::enforce(action,
//! resource_attrs={schema_id})` per
//! `dod-tenant-metadata-per-schema-authz` without any change here.

use std::sync::Arc;

use account_management_sdk::{MetadataEntry, MetadataSchemaId, derive_schema_uuid};
use modkit_macros::domain_model;
use modkit_security::AccessScope;
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::domain::error::DomainError;
use crate::domain::metadata::registry::{InheritancePolicy, MetadataSchemaRegistry};
use crate::domain::metadata::repo::MetadataRepo;
use crate::domain::metadata::{MetadataRow, MetadataRowsPage, UpsertOutcome};
use crate::domain::tenant::model::{TenantModel, TenantStatus};
use crate::domain::tenant::repo::TenantRepo;

/// Shared clock seam. Produced by [`MetadataService::new`] from
/// `OffsetDateTime::now_utc` and overridable in tests via
/// [`MetadataService::with_now_fn`]. Mirrors the
/// [`crate::domain::conversion::service::ConversionService`] convention
/// so the unit tests can pin `created_at` / `updated_at` for repeatable
/// idempotency assertions.
type NowFn = Arc<dyn Fn() -> OffsetDateTime + Send + Sync>;

/// Re-export the domain-level pagination so callers and tests that
/// import via `domain::metadata::service::*` keep working.
pub use crate::domain::metadata::MetadataPagination;

/// Page envelope returned by [`MetadataService::list_for_tenant`].
///
/// Mirrors `account_management_sdk::TenantPage` field layout
/// (`items` + `top` + `skip` + `total`) so the REST handler in Phase 4
/// can re-use the same `Page<T>` projection without inventing a
/// metadata-only shape.
#[domain_model]
#[derive(Debug, Clone)]
pub struct ListMetadataPage {
    pub items: Vec<MetadataEntry>,
    pub top: u32,
    pub skip: u32,
    pub total: u64,
}

/// Discriminated outcome of [`MetadataService::put_for_tenant`].
///
/// Carries the projected [`MetadataEntry`] alongside the
/// insert-vs-update discriminator. The future REST handler
/// (Phase 4) maps `was_inserted == true` to HTTP 201 and
/// `was_inserted == false` to HTTP 200 per FEATURE §6 AC line 393.
#[domain_model]
#[derive(Debug, Clone)]
pub struct PutMetadataOutcome {
    pub entry: MetadataEntry,
    pub was_inserted: bool,
}

/// Central AM domain service for tenant metadata.
///
/// Construction mirrors
/// [`crate::domain::conversion::service::ConversionService`] — every
/// dependency is `Arc<dyn ...>` so production wiring (`module.rs`,
/// Phase 4) and tests (`FakeMetadataRepo` + `FakeTenantRepo` +
/// `StubMetadataSchemaRegistry`) share the same constructor surface.
#[domain_model]
pub struct MetadataService {
    metadata_repo: Arc<dyn MetadataRepo>,
    tenant_repo: Arc<dyn TenantRepo>,
    schema_registry: Arc<dyn MetadataSchemaRegistry>,
    now_fn: NowFn,
}

impl MetadataService {
    /// Construct a fully-wired service with the production clock
    /// (`OffsetDateTime::now_utc`).
    #[must_use]
    pub fn new(
        metadata_repo: Arc<dyn MetadataRepo>,
        tenant_repo: Arc<dyn TenantRepo>,
        schema_registry: Arc<dyn MetadataSchemaRegistry>,
    ) -> Self {
        Self {
            metadata_repo,
            tenant_repo,
            schema_registry,
            now_fn: Arc::new(OffsetDateTime::now_utc),
        }
    }

    /// Override the wall-clock function used to stamp `created_at`
    /// / `updated_at` on the upsert path. Mirrors
    /// [`crate::domain::conversion::service::ConversionService::with_now_fn`].
    #[must_use]
    pub fn with_now_fn(mut self, now_fn: NowFn) -> Self {
        self.now_fn = now_fn;
        self
    }

    /// Snapshot the current wall-clock through the configured
    /// `now_fn`.
    fn now(&self) -> OffsetDateTime {
        (self.now_fn)()
    }

    // ----------------------------------------------------------------
    // list_for_tenant
    // ----------------------------------------------------------------

    /// Paginated direct-on-tenant listing.
    ///
    /// Implements `cpt-cf-account-management-flow-tenant-metadata-list`.
    /// The query MUST NOT walk ancestors per FEATURE §3.1 — clients
    /// reading effective values use `/resolved`.
    ///
    /// The order is stable on `schema_uuid` per the
    /// [`MetadataRepo::list_for_tenant`] contract; cursor re-reads
    /// against the same fixture are deterministic.
    ///
    /// Each returned [`MetadataEntry`] carries the public chained
    /// `schema_id` re-hydrated from the registry per FEATURE §2 step
    /// 4 — `dbtable-tenant-metadata` MUST NOT retain the public id
    /// per `dod-tenant-metadata-schema-registration-and-uuid-derivation`.
    ///
    /// # Errors
    ///
    /// * [`DomainError::NotFound`] — `tenant_id` does not resolve
    ///   to a visible tenant.
    /// * [`DomainError::Validation`] — the resolved tenant is not in
    ///   [`TenantStatus::Active`].
    /// * [`DomainError::MetadataSchemaNotRegistered`] — a stored row
    ///   carries a `schema_uuid` whose chained id is missing from the
    ///   registry. This is a data-integrity signal; in practice
    ///   schemas are removed from the registry only after every
    ///   tenant has dropped its row, but the service surfaces the
    ///   condition rather than swallowing it.
    // @cpt-begin:cpt-cf-account-management-flow-tenant-metadata-list:p1:inst-flow-mdlist-service
    // @cpt-begin:cpt-cf-account-management-dod-tenant-metadata-crud-contract:p1:inst-dod-crud-list-service
    // @cpt-begin:cpt-cf-account-management-dod-tenant-metadata-application-only-enforcement:p1:inst-dod-app-only-list-service
    #[tracing::instrument(
        skip(self),
        fields(tenant_id = %tenant_id, top = pagination.top, skip = pagination.skip)
    )]
    pub async fn list_for_tenant(
        &self,
        scope: &AccessScope,
        tenant_id: Uuid,
        pagination: MetadataPagination,
    ) -> Result<ListMetadataPage, DomainError> {
        // Tenant existence + status guard runs BEFORE any DB read on
        // `tenant_metadata` per FEATURE §2 list error scenarios.
        let _tenant = self.resolve_active_tenant(scope, tenant_id).await?;

        // Direct-on-tenant only — NO ancestor walk per FEATURE §3.1.
        // The application-only-enforcement contract relies on this
        // method returning ONLY directly-written values. Pagination is
        // pushed into SQL `LIMIT`/`OFFSET` by the repo; `total` is the
        // unfiltered match-count for the tenant.
        let MetadataRowsPage { rows, total } = self
            .metadata_repo
            .list_for_tenant(scope, tenant_id, pagination)
            .await?;

        // Reverse-hydrate the chained `schema_id` for the page rows in
        // one batch call. The registry adapter resolves all uuids in a
        // single round-trip and the lookup below is a pure map read.
        // Rows whose `schema_uuid` is no longer registered are an
        // integrity-pipeline signal — operators get a precise
        // `MetadataSchemaNotRegistered` rather than a panic.
        let uuids: Vec<Uuid> = rows.iter().map(|r| r.schema_uuid).collect();
        let id_by_uuid = self.schema_registry.resolve_ids_by_uuid(&uuids).await?;
        let mut items: Vec<MetadataEntry> = Vec::with_capacity(rows.len());
        for row in rows {
            let schema_id = id_by_uuid.get(&row.schema_uuid).cloned().ok_or_else(|| {
                DomainError::MetadataSchemaNotRegistered {
                    detail: format!("schema_uuid {} not registered", row.schema_uuid),
                    schema: row.schema_uuid.to_string(),
                }
            })?;
            items.push(project_to_entry(row, schema_id));
        }

        Ok(ListMetadataPage {
            items,
            top: pagination.top,
            skip: pagination.skip,
            total,
        })
    }
    // @cpt-end:cpt-cf-account-management-dod-tenant-metadata-application-only-enforcement:p1:inst-dod-app-only-list-service
    // @cpt-end:cpt-cf-account-management-dod-tenant-metadata-crud-contract:p1:inst-dod-crud-list-service
    // @cpt-end:cpt-cf-account-management-flow-tenant-metadata-list:p1:inst-flow-mdlist-service

    // ----------------------------------------------------------------
    // get_for_tenant
    // ----------------------------------------------------------------

    /// Single-entry read keyed by `(tenant_id, schema_id)`.
    ///
    /// Implements `cpt-cf-account-management-flow-tenant-metadata-get`.
    ///
    /// Distinct-404 disambiguation per
    /// `dod-tenant-metadata-distinct-404-codes`:
    ///
    /// * Schema unknown to the registry →
    ///   [`DomainError::MetadataSchemaNotRegistered`] (HTTP 404,
    ///   `code=metadata_schema_not_registered`).
    /// * Schema known but no row at `(tenant_id, schema_uuid)` →
    ///   [`DomainError::MetadataEntryNotFound`] (HTTP 404,
    ///   `code=metadata_entry_not_found`).
    ///
    /// # Errors
    ///
    /// * [`DomainError::NotFound`] — `tenant_id` does not resolve.
    /// * [`DomainError::Validation`] — tenant is not `Active`.
    /// * [`DomainError::MetadataSchemaNotRegistered`] — see above.
    /// * [`DomainError::MetadataEntryNotFound`] — see above.
    // @cpt-begin:cpt-cf-account-management-flow-tenant-metadata-get:p1:inst-flow-mdget-service
    // @cpt-begin:cpt-cf-account-management-dod-tenant-metadata-crud-contract:p1:inst-dod-crud-get-service
    // @cpt-begin:cpt-cf-account-management-dod-tenant-metadata-distinct-404-codes:p1:inst-dod-distinct-404-get-service
    // @cpt-begin:cpt-cf-account-management-dod-tenant-metadata-schema-registration-and-uuid-derivation:p1:inst-dod-schema-registration-get-service
    pub async fn get_for_tenant(
        &self,
        scope: &AccessScope,
        tenant_id: Uuid,
        schema_id: MetadataSchemaId,
    ) -> Result<MetadataEntry, DomainError> {
        // Tenant existence + status guard runs BEFORE the registry call.
        let _tenant = self.resolve_active_tenant(scope, tenant_id).await?;

        // Existence gate: registry resolves the policy AND signals
        // unregistered. We don't need the policy on the GET path but
        // the same RPC is the cheapest existence check (one round-trip
        // serves both reads and writes). The error variant carries
        // `schema_id` verbatim so the canonical envelope can surface
        // the requested id without re-parsing the path.
        let _policy = self
            .schema_registry
            .resolve_inheritance_policy(&schema_id)
            .await?;

        // UUIDv5 derivation routes through the SDK helper per
        // `dod-tenant-metadata-schema-registration-and-uuid-derivation`.
        let schema_uuid = derive_schema_uuid(&schema_id);

        let row = self
            .metadata_repo
            .get_for_tenant(scope, tenant_id, schema_uuid)
            .await?
            .ok_or_else(|| DomainError::MetadataEntryNotFound {
                detail: format!("no metadata entry for tenant {tenant_id} at schema {schema_id}"),
                entry: format!("({tenant_id}, {schema_id})"),
            })?;

        Ok(project_to_entry(row, schema_id))
    }
    // @cpt-end:cpt-cf-account-management-dod-tenant-metadata-schema-registration-and-uuid-derivation:p1:inst-dod-schema-registration-get-service
    // @cpt-end:cpt-cf-account-management-dod-tenant-metadata-distinct-404-codes:p1:inst-dod-distinct-404-get-service
    // @cpt-end:cpt-cf-account-management-dod-tenant-metadata-crud-contract:p1:inst-dod-crud-get-service
    // @cpt-end:cpt-cf-account-management-flow-tenant-metadata-get:p1:inst-flow-mdget-service

    // ----------------------------------------------------------------
    // put_for_tenant
    // ----------------------------------------------------------------

    /// Upsert the row at `(tenant_id, schema_uuid)`.
    ///
    /// Implements `cpt-cf-account-management-flow-tenant-metadata-put`.
    /// The returned [`PutMetadataOutcome`] carries the
    /// insert-vs-update discriminator the future REST handler maps to
    /// HTTP 201 / 200 per FEATURE §6 AC line 393.
    ///
    /// Guard ordering (matches FEATURE §6 AC):
    /// 1. `resolve_active_tenant` — `NotFound` / non-`Active` collapses
    ///    BEFORE any registry lookup so tenant topology does not leak
    ///    through a schema-shape error.
    /// 2. `schema_registry.resolve_inheritance_policy` — the existence
    ///    gate. Unregistered schemas surface as
    ///    [`DomainError::MetadataSchemaNotRegistered`] without ever
    ///    touching the validator.
    /// 3. `schema_registry.validate_value` — GTS body validation against
    ///    the registered JSON Schema. Payload-fail surfaces as
    ///    [`DomainError::Validation`] BEFORE any DB write, fingerprinting
    ///    `dod-tenant-metadata-crud-contract` line 393.
    /// 4. `metadata_repo.upsert_for_tenant` — the actual write.
    ///
    /// `requested_by` is recorded on the success-side `am.events`
    /// line for audit correlation.
    ///
    /// # Errors
    ///
    /// * [`DomainError::NotFound`] — `tenant_id` does not resolve.
    /// * [`DomainError::Validation`] — tenant is not `Active`, or
    ///   `value` violates the registered JSON Schema body.
    /// * [`DomainError::MetadataSchemaNotRegistered`] — schema not
    ///   in the registry; no row written.
    /// * [`DomainError::ServiceUnavailable`] — types-registry transport
    ///   failure; no row written.
    /// * [`DomainError::Internal`] — registered schema is not a valid
    ///   JSON Schema (catalog drift); no row written.
    // @cpt-begin:cpt-cf-account-management-flow-tenant-metadata-put:p1:inst-flow-mdput-service
    // @cpt-begin:cpt-cf-account-management-dod-tenant-metadata-crud-contract:p1:inst-dod-crud-put-service
    // @cpt-begin:cpt-cf-account-management-dod-tenant-metadata-schema-registration-and-uuid-derivation:p1:inst-dod-schema-registration-put-service
    #[tracing::instrument(
        skip(self, value),
        fields(tenant_id = %tenant_id, schema_id = %schema_id, actor_uuid = %requested_by)
    )]
    pub async fn put_for_tenant(
        &self,
        scope: &AccessScope,
        tenant_id: Uuid,
        schema_id: MetadataSchemaId,
        value: Value,
        requested_by: Uuid,
    ) -> Result<PutMetadataOutcome, DomainError> {
        // Fail closed on `Uuid::nil()` for the actor field. `requested_by`
        // flows into `am.events` as `actor_uuid`; a default-constructed
        // nil would collapse every caller-side bug into one audit
        // bucket and hide it from `(event, actor_uuid)` aggregations.
        // Mirrors the user-service guard in
        // `crate::domain::user::service::UserService::provision_user`.
        if requested_by.is_nil() {
            return Err(DomainError::internal(
                "put_for_tenant: requested_by MUST NOT be Uuid::nil() (service-layer bug)",
            ));
        }
        let _tenant = self.resolve_active_tenant(scope, tenant_id).await?;

        let _policy = self
            .schema_registry
            .resolve_inheritance_policy(&schema_id)
            .await?;

        // GTS body validation. Runs AFTER the existence gate above so
        // an unregistered-schema PUT still surfaces 404, not 400, per
        // `dod-tenant-metadata-distinct-404-codes`. The registry's
        // local-client cache amortizes the second round-trip in the
        // steady state.
        self.schema_registry
            .validate_value(&schema_id, &value)
            .await?;

        let schema_uuid = derive_schema_uuid(&schema_id);
        let now = self.now();

        let outcome = self
            .metadata_repo
            .upsert_for_tenant(scope, tenant_id, schema_uuid, value, now)
            .await?;

        let was_inserted = outcome.was_inserted();
        let row = match outcome {
            UpsertOutcome::Inserted(row) | UpsertOutcome::Updated(row) => row,
        };
        let entry = project_to_entry(row, schema_id.clone());

        // Audit emission with `schema_id` on the structured log so a
        // future PolicyEnforcer wiring can correlate per-schema policy
        // decisions against the same field. `outcome` differentiates
        // insert vs update so an aggregator counting by
        // (event, outcome) gets the same shape REST will surface as
        // 201/200.
        tracing::info!(
            target: "am.events",
            event = "metadata_upserted",
            tenant_id = %tenant_id,
            schema_id = %schema_id,
            actor_uuid = %requested_by,
            outcome = if was_inserted { "inserted" } else { "updated" },
            "am tenant metadata upserted"
        );

        Ok(PutMetadataOutcome {
            entry,
            was_inserted,
        })
    }
    // @cpt-end:cpt-cf-account-management-dod-tenant-metadata-schema-registration-and-uuid-derivation:p1:inst-dod-schema-registration-put-service
    // @cpt-end:cpt-cf-account-management-dod-tenant-metadata-crud-contract:p1:inst-dod-crud-put-service
    // @cpt-end:cpt-cf-account-management-flow-tenant-metadata-put:p1:inst-flow-mdput-service

    // ----------------------------------------------------------------
    // delete_for_tenant
    // ----------------------------------------------------------------

    /// Delete the row at `(tenant_id, schema_uuid)`.
    ///
    /// Implements `cpt-cf-account-management-flow-tenant-metadata-delete`.
    ///
    /// DELETE is intentionally NOT idempotent-success on missing rows:
    /// the distinct-404 contract per
    /// `dod-tenant-metadata-distinct-404-codes` makes the signal
    /// observable to clients. Missing rows surface as
    /// [`DomainError::MetadataEntryNotFound`].
    ///
    /// # Errors
    ///
    /// * [`DomainError::NotFound`] — `tenant_id` does not resolve.
    /// * [`DomainError::Validation`] — tenant is not `Active`.
    /// * [`DomainError::MetadataSchemaNotRegistered`] — schema not
    ///   registered; no DB write issued.
    /// * [`DomainError::MetadataEntryNotFound`] — schema known but no
    ///   row at `(tenant_id, schema_uuid)`.
    // @cpt-begin:cpt-cf-account-management-flow-tenant-metadata-delete:p1:inst-flow-mddel-service
    // @cpt-begin:cpt-cf-account-management-dod-tenant-metadata-crud-contract:p1:inst-dod-crud-delete-service
    // @cpt-begin:cpt-cf-account-management-dod-tenant-metadata-distinct-404-codes:p1:inst-dod-distinct-404-delete-service
    // @cpt-begin:cpt-cf-account-management-dod-tenant-metadata-schema-registration-and-uuid-derivation:p1:inst-dod-schema-registration-delete-service
    #[tracing::instrument(
        skip(self),
        fields(tenant_id = %tenant_id, schema_id = %schema_id, actor_uuid = %requested_by)
    )]
    pub async fn delete_for_tenant(
        &self,
        scope: &AccessScope,
        tenant_id: Uuid,
        schema_id: MetadataSchemaId,
        requested_by: Uuid,
    ) -> Result<(), DomainError> {
        // Same `Uuid::nil()` audit guard as `put_for_tenant`. Both
        // service entry-points feed `requested_by` into `am.events`
        // and must reject nil actors consistently — otherwise a
        // mismapped caller would emit valid-looking audit records
        // under `00000000-0000-0000-0000-000000000000`.
        if requested_by.is_nil() {
            return Err(DomainError::internal(
                "delete_for_tenant: requested_by MUST NOT be Uuid::nil() (service-layer bug)",
            ));
        }
        let _tenant = self.resolve_active_tenant(scope, tenant_id).await?;

        let _policy = self
            .schema_registry
            .resolve_inheritance_policy(&schema_id)
            .await?;

        let schema_uuid = derive_schema_uuid(&schema_id);

        // The repo's `delete_for_tenant` returns
        // [`DomainError::MetadataEntryNotFound`] on missing rows,
        // satisfying the distinct-404 contract without an additional
        // service-side existence probe. Remap to use the public
        // `schema_id` in `detail` / `entry` so the wire shape matches
        // `get_for_tenant`'s NotFound projection (which the repo
        // cannot synthesise because it only sees the internal
        // `schema_uuid`). Without the remap, GET and DELETE on the
        // same missing entry would surface two different `entry`
        // payloads, breaking aggregators keyed on that field.
        self.metadata_repo
            .delete_for_tenant(scope, tenant_id, schema_uuid)
            .await
            .map_err(|e| match e {
                DomainError::MetadataEntryNotFound { .. } => DomainError::MetadataEntryNotFound {
                    detail: format!(
                        "no metadata entry for tenant {tenant_id} at schema {schema_id}"
                    ),
                    entry: format!("({tenant_id}, {schema_id})"),
                },
                other => other,
            })?;

        tracing::info!(
            target: "am.events",
            event = "metadata_deleted",
            tenant_id = %tenant_id,
            schema_id = %schema_id,
            actor_uuid = %requested_by,
            outcome = "ok",
            "am tenant metadata deleted"
        );

        Ok(())
    }
    // @cpt-end:cpt-cf-account-management-dod-tenant-metadata-schema-registration-and-uuid-derivation:p1:inst-dod-schema-registration-delete-service
    // @cpt-end:cpt-cf-account-management-dod-tenant-metadata-distinct-404-codes:p1:inst-dod-distinct-404-delete-service
    // @cpt-end:cpt-cf-account-management-dod-tenant-metadata-crud-contract:p1:inst-dod-crud-delete-service
    // @cpt-end:cpt-cf-account-management-flow-tenant-metadata-delete:p1:inst-flow-mddel-service

    // ----------------------------------------------------------------
    // resolve_for_tenant
    // ----------------------------------------------------------------

    /// Barrier-aware effective-value resolution.
    ///
    /// Implements `cpt-cf-account-management-flow-tenant-metadata-resolve`
    /// + `cpt-cf-account-management-algo-tenant-metadata-resolve-walk-up`.
    ///
    /// Empty resolution is `Ok(None)` — the normal terminal state of
    /// an unsuccessful walk per FEATURE §3 / DESIGN §3.2.3, NOT
    /// [`DomainError::MetadataEntryNotFound`]. Per
    /// `dod-tenant-metadata-distinct-404-codes` the future REST
    /// handler surfaces `Ok(None)` as HTTP 200 with an empty
    /// response.
    ///
    /// # Errors
    ///
    /// * [`DomainError::NotFound`] — `tenant_id` does not resolve.
    /// * [`DomainError::Validation`] — tenant is not `Active`.
    /// * [`DomainError::MetadataSchemaNotRegistered`] — schema not
    ///   registered; no walk performed.
    // @cpt-begin:cpt-cf-account-management-flow-tenant-metadata-resolve:p1:inst-flow-mdres-service
    // @cpt-begin:cpt-cf-account-management-dod-tenant-metadata-inheritance-resolution-contract:p1:inst-dod-inheritance-resolve-service
    // @cpt-begin:cpt-cf-account-management-dod-tenant-metadata-application-only-enforcement:p1:inst-dod-app-only-resolve-service
    pub async fn resolve_for_tenant(
        &self,
        scope: &AccessScope,
        tenant_id: Uuid,
        schema_id: MetadataSchemaId,
    ) -> Result<Option<MetadataEntry>, DomainError> {
        let start_tenant = self.resolve_active_tenant(scope, tenant_id).await?;

        // The walk-up algorithm consumes the resolved policy as its
        // sole controller per the DoD; unregistered schemas surface
        // here BEFORE any walk is attempted.
        let policy = self
            .schema_registry
            .resolve_inheritance_policy(&schema_id)
            .await?;

        let schema_uuid = derive_schema_uuid(&schema_id);

        let row = self
            .resolve_walk_up(scope, &start_tenant, schema_uuid, policy)
            .await?;

        Ok(row.map(|r| project_to_entry(r, schema_id)))
    }
    // @cpt-end:cpt-cf-account-management-dod-tenant-metadata-application-only-enforcement:p1:inst-dod-app-only-resolve-service
    // @cpt-end:cpt-cf-account-management-dod-tenant-metadata-inheritance-resolution-contract:p1:inst-dod-inheritance-resolve-service
    // @cpt-end:cpt-cf-account-management-flow-tenant-metadata-resolve:p1:inst-flow-mdres-service

    /// Barrier-aware ancestor walk-up per FEATURE §3
    /// `algo-tenant-metadata-resolve-walk-up`.
    ///
    /// Step ordering MUST match the FEATURE doc verbatim:
    ///
    /// 1. Read direct entry at `(start.id, schema_uuid)`. Hit ⇒ return.
    /// 2. `OverrideOnly` ⇒ return empty.
    /// 3. Start tenant `self_managed == true` ⇒ return empty
    ///    (start-tenant barrier).
    /// 4. Walk loop: advance to `parent_id`; null ⇒ root-empty;
    ///    self-managed ancestor ⇒ barrier-empty BEFORE reading;
    ///    suspended ancestor ⇒ skip-traverse; otherwise read and
    ///    return on hit, loop on miss.
    ///
    /// Application-only-enforcement contract: this is a pure
    /// service-layer computation. No DB trigger, no materialized
    /// inheritance column, no walk-up SQL view.
    // @cpt-begin:cpt-cf-account-management-algo-tenant-metadata-resolve-walk-up:p1:inst-algo-walk-up-service
    async fn resolve_walk_up(
        &self,
        scope: &AccessScope,
        start_tenant: &TenantModel,
        schema_uuid: Uuid,
        policy: InheritancePolicy,
    ) -> Result<Option<MetadataRow>, DomainError> {
        // Step 1 — own row first. Direct hit is returned regardless
        // of the start tenant's `self_managed` flag (the barrier only
        // blocks INHERITANCE from ancestors; own values are always
        // surfaced per `inst-algo-walk-own-return`).
        if let Some(row) = self
            .metadata_repo
            .get_for_tenant(scope, start_tenant.id, schema_uuid)
            .await?
        {
            return Ok(Some(row));
        }

        // Step 2 — override_only short-circuits before any tenant-row
        // load. `inst-algo-walk-override-return`.
        if matches!(policy, InheritancePolicy::OverrideOnly) {
            return Ok(None);
        }

        // Step 3 — start-tenant barrier. A self-managed tenant never
        // inherits from ancestors above its barrier per
        // `principle-barrier-as-data` /
        // `inst-algo-walk-start-barrier-return`.
        if start_tenant.self_managed {
            return Ok(None);
        }

        // Walk init (`inst-algo-walk-init`): `current = start`. We
        // already loaded the start row through `resolve_active_tenant`
        // so the loop body is structured around `current.parent_id`
        // null-check first per the FEATURE-doc step ordering (step 7
        // gates step 8).
        let mut current_parent = start_tenant.parent_id;

        // allow_all for the ancestor walk:
        //
        // The PEP gate above already authorised the caller on
        // `start_tenant` (the resource the caller actually named).
        // Once that gate has passed, walking up the ancestor chain
        // for `Inherit`-policy inheritance is a STRUCTURAL read --
        // the result is projected through the start tenant's
        // visibility, never disclosed directly. The
        // post-#1813 `tenants` entity declares `resource_col = "id"`
        // (and `tenant_metadata` declares `tenant_col = "tenant_id"`),
        // so reusing the caller's narrowed scope here would clamp
        // both reads to descendants of the start tenant -- and an
        // ancestor is by definition NOT in the start tenant's
        // descendant subtree. The narrowed scope would therefore
        // turn every ancestor lookup into a dangling-parent
        // `Internal` error (step 8) or a silent miss (step 11),
        // collapsing the FEATURE's inheritance semantics. Mirrors
        // the saga-internal `allow_all` reads in `TenantService`
        // (`create_child`, `update_tenant`, `soft_delete` parent /
        // structural-precondition reads).
        let walk_scope = AccessScope::allow_all();

        loop {
            // Step 7 — root reached without a value.
            // `inst-algo-walk-root-return`.
            let Some(parent_id) = current_parent else {
                return Ok(None);
            };

            // Step 8 — load the ancestor row.
            let ancestor = self
                .tenant_repo
                .find_by_id(&walk_scope, parent_id)
                .await?
                .ok_or_else(|| {
                    // A stored `parent_id` referencing a missing
                    // tenant row is a hierarchy-integrity violation.
                    // Surface it as `Internal` so the integrity-check
                    // pipeline can surface the dangling-parent
                    // signal; the walk does not silently terminate
                    // because that would mask the data-integrity
                    // signal under an empty-resolved response.
                    DomainError::internal(format!(
                        "metadata walk-up: parent tenant {parent_id} is missing (dangling parent_id reference)"
                    ))
                })?;

            // Step 9 — barrier-stop ancestor: return empty BEFORE
            // reading the ancestor's value per `inst-algo-walk-ancestor-barrier-return`.
            if ancestor.self_managed {
                return Ok(None);
            }

            // Step 10 — suspended ancestor: skip the read but
            // continue the walk to its parent. Suspension is a
            // lifecycle state, not a barrier per
            // `inst-algo-walk-suspended-continue`.
            if matches!(ancestor.status, TenantStatus::Suspended) {
                current_parent = ancestor.parent_id;
                continue;
            }

            // Step 11 — read ancestor's direct entry through
            // `walk_scope` (`allow_all`). Same structural-read
            // rationale as the ancestor `find_by_id` above: the
            // caller's narrowed `scope` was already enforced on the
            // start-tenant own-row read at the top of this function;
            // ancestors live outside that subtree by definition and
            // must be reached via `walk_scope` to honour the
            // `Inherit` policy.
            if let Some(row) = self
                .metadata_repo
                .get_for_tenant(&walk_scope, ancestor.id, schema_uuid)
                .await?
            {
                // Step 12 — return the ancestor's value.
                return Ok(Some(row));
            }

            // Step 13 — loop back to root-reached check with the new
            // `current`. `inst-algo-walk-loop`.
            current_parent = ancestor.parent_id;
        }
    }
    // @cpt-end:cpt-cf-account-management-algo-tenant-metadata-resolve-walk-up:p1:inst-algo-walk-up-service

    // ----------------------------------------------------------------
    // helpers
    // ----------------------------------------------------------------

    /// Resolve `tenant_id` to a visible [`TenantStatus::Active`]
    /// tenant. Mirrors
    /// [`crate::domain::user::service::UserService::resolve_active_tenant`]
    /// so every per-tenant flow shares one guard implementation and
    /// CPT review can verify the precondition once.
    async fn resolve_active_tenant(
        &self,
        scope: &AccessScope,
        tenant_id: Uuid,
    ) -> Result<TenantModel, DomainError> {
        let tenant = self
            .tenant_repo
            .find_by_id(scope, tenant_id)
            .await?
            .ok_or_else(|| DomainError::NotFound {
                detail: format!("tenant {tenant_id} not found"),
                resource: tenant_id.to_string(),
            })?;

        if !matches!(tenant.status, TenantStatus::Active) {
            return Err(DomainError::Validation {
                detail: format!(
                    "tenant {} is not active (status={})",
                    tenant.id,
                    tenant.status.as_str()
                ),
            });
        }

        Ok(tenant)
    }
}

/// Project a [`MetadataRow`] + its public chained `schema_id` into
/// the [`MetadataEntry`] surface returned by every read-flow.
fn project_to_entry(row: MetadataRow, schema_id: MetadataSchemaId) -> MetadataEntry {
    MetadataEntry::new(schema_id, row.value, row.updated_at)
}
