//! `SeaORM`-backed implementation of [`MetadataRepo`].
//!
//! Mirrors the conventions established by the sibling [`TenantRepoImpl`]
//! split (`reads`, `lifecycle`, `updates`, `retention`,
//! [`ConversionRepoImpl`]): every method on the [`MetadataRepo`] trait is
//! dispatched to a `pub(super)` free function in this module, every DB
//! call forwards the caller's [`AccessScope`] through `SecureORM` (the
//! `tenant_metadata` entity is declared `Scopable(tenant_col =
//! "tenant_id", no_resource, no_owner, no_type)` so a caller-built
//! `InTenantSubtree` scope clamps reads / writes to the caller's tenant
//! subtree via the secure-ORM closure subquery), and DB errors are
//! routed through the canonical-mapping classifier so domain code never
//! sees a raw `DbErr`.
//!
//! Two repo-specific behaviours are pinned here:
//!
//! * `upsert_for_tenant` runs a single SERIALIZABLE retry transaction
//!   that performs a SELECT-then-INSERT-or-UPDATE on the composite key
//!   `(tenant_id, schema_uuid)`. The path is engine-portable (`SeaORM`'s
//!   `OnConflict` builder is dialect-agnostic but UPSERT semantics
//!   require us to read back the post-write row anyway, so the SELECT-
//!   first form is simpler and matches the established
//!   `run_guarded_transition` shape used by `conversion.rs`). On insert
//!   `created_at == updated_at == now`; on update `created_at` is
//!   preserved and `updated_at` is bumped to `now`.
//! * `delete_for_tenant` is intentionally **non-idempotent** on missing
//!   rows. A `rows_affected == 0` UPDATE result surfaces
//!   [`DomainError::MetadataEntryNotFound`] per the trait contract — the
//!   distinct-404 contract (FEATURE §6 AC line 394) makes the signal
//!   observable to clients.
//!
//! Cascade-delete on tenant removal is owned by
//! `TenantRepoImpl::hard_delete_one`: that path issues a single in-TX
//! `delete_many` against `tenant_metadata` (dialect-portable; works on
//! PG and `SQLite` regardless of `PRAGMA foreign_keys`). The metadata
//! repo deliberately exposes no cascade-cleanup method.
//!
//! [`TenantRepoImpl`]: crate::infra::storage::repo_impl::TenantRepoImpl
//! [`ConversionRepoImpl`]: crate::infra::storage::repo_impl::ConversionRepoImpl
//! [`MetadataRepo`]: crate::domain::metadata::repo::MetadataRepo

use std::sync::Arc;

use async_trait::async_trait;
use modkit_db::secure::{DbTx, SecureDeleteExt, SecureEntityExt, SecureInsertExt, SecureUpdateExt};
use modkit_security::AccessScope;
use sea_orm::sea_query::Expr;
use sea_orm::{ActiveValue, ColumnTrait, Condition, EntityTrait, Order, QueryFilter};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::domain::error::DomainError;
use crate::domain::metadata::repo::MetadataRepo;
use crate::domain::metadata::{MetadataPagination, MetadataRow, MetadataRowsPage, UpsertOutcome};
use crate::domain::metrics::{AM_DEPENDENCY_HEALTH, MetricKind, emit_metric};
use crate::infra::storage::entity::tenant_metadata;

use super::AmDbProvider;
use super::helpers::{TxError, map_scope_err, map_scope_to_tx, with_serializable_retry};

/// Maximum extra attempts the upsert path will make after a
/// `DomainError::AlreadyExists` race on the first-write code path.
///
/// Two concurrent first-time PUTs for the same `(tenant_id, schema_uuid)`
/// can both observe `SELECT` returning `None` and both proceed to
/// `INSERT`. SERIALIZABLE/serialization-failure detection is engine-
/// dependent: `PostgreSQL` under SERIALIZABLE usually converts the
/// collision to a `40001` (handled by `with_serializable_retry`), but
/// `READ COMMITTED` and `SQLite` surface the raw `23505` / `2067`
/// unique violation which `with_serializable_retry` does NOT retry.
/// We retry here at the upsert boundary so the next attempt's `SELECT`
/// finds the row written by the peer and takes the UPDATE path. 3
/// retries (4 total attempts) is far above the realistic concurrency
/// for the same composite key.
const MAX_UPSERT_UNIQUE_VIOLATION_RETRIES: u8 = 3;

/// `SeaORM` repository adapter for [`MetadataRepo`].
///
/// Decision rule: a separate struct from [`super::TenantRepoImpl`] /
/// [`super::ConversionRepoImpl`] because `MetadataRepo` is a disjoint
/// trait — there is no shared state to factor and the storage layout is
/// independent (composite PK `(tenant_id, schema_uuid)`, no closure
/// touchpoints).
pub struct MetadataRepoImpl {
    db: Arc<AmDbProvider>,
}

impl MetadataRepoImpl {
    /// Build a new repo adapter over the shared AM DB provider.
    #[must_use]
    pub fn new(db: Arc<AmDbProvider>) -> Self {
        Self { db }
    }
}

// ---------------------------------------------------------------------------
// Mapping helpers
// ---------------------------------------------------------------------------

/// Lift a [`tenant_metadata::Model`] row into the domain
/// [`MetadataRow`]. Pure projection — every column is preserved
/// verbatim, the only translation is `Json` → [`serde_json::Value`].
fn entity_to_row(row: tenant_metadata::Model) -> MetadataRow {
    MetadataRow {
        tenant_id: row.tenant_id,
        schema_uuid: row.schema_uuid,
        value: row.value,
        created_at: row.created_at,
        updated_at: row.updated_at,
    }
}

/// Build a `Condition` matching a metadata row by composite key.
fn pk_eq(tenant_id: Uuid, schema_uuid: Uuid) -> Condition {
    Condition::all()
        .add(tenant_metadata::Column::TenantId.eq(tenant_id))
        .add(tenant_metadata::Column::SchemaUuid.eq(schema_uuid))
}

// ---------------------------------------------------------------------------
// Free functions implementing each MetadataRepo method.
// ---------------------------------------------------------------------------

async fn list_for_tenant(
    repo: &MetadataRepoImpl,
    scope: &AccessScope,
    tenant_id: Uuid,
    pagination: MetadataPagination,
) -> Result<MetadataRowsPage, DomainError> {
    let conn = repo.db.conn()?;

    // Unfiltered count (independent of `top`/`skip`) so the public list
    // envelope reports the true match-count, not just the page size.
    // `tenant_metadata` is `Scopable(tenant_col = "tenant_id", ...)` so
    // the count goes through the same scoped seam as the page query.
    let total = tenant_metadata::Entity::find()
        .secure()
        .scope_with(scope)
        .filter(Condition::all().add(tenant_metadata::Column::TenantId.eq(tenant_id)))
        .count(&conn)
        .await
        .map_err(map_scope_err)?;

    let rows = tenant_metadata::Entity::find()
        .secure()
        // `tenant_metadata` is `Scopable(tenant_col = "tenant_id", ...)`,
        // so passing a caller-built `InTenantSubtree` scope here narrows
        // the SQL to the caller's tenant subtree via the secure-ORM
        // closure clamp. The REST handler is responsible for building
        // the scope; the storage seam just forwards it.
        .scope_with(scope)
        .filter(Condition::all().add(tenant_metadata::Column::TenantId.eq(tenant_id)))
        // Stable ORDER BY schema_uuid ASC for deterministic pagination
        // — `LIMIT` / `OFFSET` are pushed into the SELECT so a tenant
        // with thousands of metadata rows does not transfer the whole
        // table per page.
        .order_by(tenant_metadata::Column::SchemaUuid, Order::Asc)
        .limit(u64::from(pagination.top))
        .offset(u64::from(pagination.skip))
        .all(&conn)
        .await
        .map_err(map_scope_err)?;

    Ok(MetadataRowsPage {
        rows: rows.into_iter().map(entity_to_row).collect(),
        total,
    })
}

async fn get_for_tenant(
    repo: &MetadataRepoImpl,
    scope: &AccessScope,
    tenant_id: Uuid,
    schema_uuid: Uuid,
) -> Result<Option<MetadataRow>, DomainError> {
    let conn = repo.db.conn()?;
    let row = tenant_metadata::Entity::find()
        .secure()
        // Same scope-forwarding posture as `list_for_tenant` — caller's
        // `InTenantSubtree` scope clamps the SELECT to the caller's
        // tenant subtree.
        .scope_with(scope)
        .filter(pk_eq(tenant_id, schema_uuid))
        .one(&conn)
        .await
        .map_err(map_scope_err)?;
    Ok(row.map(entity_to_row))
}

// @cpt-begin:cpt-cf-account-management-flow-tenant-metadata-put:p1:inst-storage-upsert-impl
// @cpt-begin:cpt-cf-account-management-dod-tenant-metadata-crud-contract:p1:inst-dod-crud-upsert-storage
async fn upsert_for_tenant(
    repo: &MetadataRepoImpl,
    scope: &AccessScope,
    tenant_id: Uuid,
    schema_uuid: Uuid,
    value: Value,
    now: OffsetDateTime,
) -> Result<UpsertOutcome, DomainError> {
    // Engine-portable upsert: SELECT under TX, INSERT or UPDATE based on
    // existence. The post-write `MetadataRow` is constructed in-memory
    // from the known inputs + the previously-loaded `created_at` — no
    // second SELECT round-trip per PUT.
    //
    // Two retry layers wrap this:
    //
    // 1. **Inner** — `with_serializable_retry` retries the closure on
    //    transient lock contention (PG 40001 / 40P01, MySQL deadlock,
    //    SQLite BUSY / BUSY_SNAPSHOT). Engine-specific contention
    //    signal lives there.
    //
    // 2. **Outer** — this function loops up to
    //    `MAX_UPSERT_UNIQUE_VIOLATION_RETRIES` times when the inner
    //    closure surfaces `DomainError::AlreadyExists`. That error
    //    means a peer transaction completed its first-write INSERT
    //    between our SELECT (which saw no row) and our INSERT (which
    //    hit the unique constraint). The remedy is to re-enter the
    //    closure: the next iteration's SELECT now finds the peer's
    //    row and dispatches to the UPDATE branch — turning the race
    //    into the idempotent "last write wins" semantics the PUT
    //    contract promises.
    //
    //    The reason we do this here and not inside
    //    `with_serializable_retry` is that the helper's classifier
    //    (`is_retryable_contention`) deliberately covers only lock
    //    contention, not constraint violations — every other repo
    //    method wants `AlreadyExists` propagated as a domain signal,
    //    not retried.
    let mut last_already_exists_detail: Option<String> = None;
    for attempt in 0..=MAX_UPSERT_UNIQUE_VIOLATION_RETRIES {
        match upsert_for_tenant_once(repo, scope, tenant_id, schema_uuid, value.clone(), now).await
        {
            Ok(outcome) => return Ok(outcome),
            Err(DomainError::AlreadyExists { detail }) => {
                last_already_exists_detail = Some(detail);
                if attempt < MAX_UPSERT_UNIQUE_VIOLATION_RETRIES {
                    // First-write race: peer landed INSERT between
                    // our SELECT and INSERT. Retry — the next SELECT
                    // sees the peer's row and takes the UPDATE
                    // branch. Observable so a misclassification (a
                    // non-race duplicate-key error wrongly routed
                    // here) shows up in the dependency-health
                    // counter rather than silently looping.
                    emit_metric(
                        AM_DEPENDENCY_HEALTH,
                        MetricKind::Counter,
                        &[
                            ("target", "metadata_upsert"),
                            ("op", "unique_violation_race"),
                            ("outcome", "retry"),
                        ],
                    );
                    tracing::debug!(
                        target: "am.metadata",
                        tenant_id = %tenant_id,
                        schema_uuid = %schema_uuid,
                        attempt = attempt + 1,
                        "metadata upsert: unique-violation race, retrying as UPDATE-path"
                    );
                    continue;
                }
                // Final attempt also raced: budget exhausted. Break
                // out so the post-loop counter + error get emitted.
                break;
            }
            Err(e) => return Err(e),
        }
    }

    // Exhausted retries: surface AlreadyExists as the last seen
    // signal. Reaching this branch implies sustained concurrent
    // first-writes for the same `(tenant_id, schema_uuid)` — the
    // operator-visible counter captures that the retry budget did
    // not absorb the race, which is itself the actionable signal.
    tracing::warn!(
        target: "am.metadata",
        tenant_id = %tenant_id,
        schema_uuid = %schema_uuid,
        attempts = u32::from(MAX_UPSERT_UNIQUE_VIOLATION_RETRIES) + 1,
        "metadata upsert retry budget exhausted on unique-violation race"
    );
    emit_metric(
        AM_DEPENDENCY_HEALTH,
        MetricKind::Counter,
        &[
            ("target", "metadata_upsert"),
            ("op", "unique_violation_race"),
            ("outcome", "retries_exhausted"),
        ],
    );
    let last_detail = last_already_exists_detail.unwrap_or_else(|| "<unknown>".to_owned());
    Err(DomainError::AlreadyExists {
        detail: format!(
            "metadata upsert for ({tenant_id}, {schema_uuid}) failed after \
             {MAX_UPSERT_UNIQUE_VIOLATION_RETRIES} retry attempts on unique-constraint race; \
             last inner detail: {last_detail}"
        ),
    })
}

/// Single SELECT-then-INSERT-or-UPDATE pass under one
/// `with_serializable_retry` envelope. Extracted so the outer
/// unique-violation retry loop in `upsert_for_tenant` can re-call it
/// with a fresh transaction.
async fn upsert_for_tenant_once(
    repo: &MetadataRepoImpl,
    scope: &AccessScope,
    tenant_id: Uuid,
    schema_uuid: Uuid,
    value: Value,
    now: OffsetDateTime,
) -> Result<UpsertOutcome, DomainError> {
    let scope_owned = scope.clone();
    let value_owned = value;
    with_serializable_retry(&repo.db, move || {
        let scope = scope_owned.clone();
        let value = value_owned.clone();
        Box::new(move |tx: &DbTx<'_>| {
            Box::pin(async move {
                let existing = tenant_metadata::Entity::find()
                    .secure()
                    // Caller's scope (typically `InTenantSubtree`)
                    // clamps the SELECT to the caller's subtree; the
                    // upsert TX inherits the same authz fence used by
                    // `list_for_tenant`.
                    .scope_with(&scope)
                    .filter(pk_eq(tenant_id, schema_uuid))
                    .one(tx)
                    .await
                    .map_err(map_scope_to_tx)?;

                if let Some(existing) = existing {
                    // UPDATE path: preserve `created_at`, stamp
                    // `updated_at = now`, rewrite the opaque value.
                    // Keep a clone of the value for the post-write row
                    // so the response can avoid a second SELECT.
                    let value_for_row = value.clone();
                    let res = tenant_metadata::Entity::update_many()
                        .col_expr(tenant_metadata::Column::Value, Expr::value(value))
                        .col_expr(tenant_metadata::Column::UpdatedAt, Expr::value(now))
                        .filter(pk_eq(tenant_id, schema_uuid))
                        .secure()
                        // Same caller-scope forwarding as the SELECT above.
                        .scope_with(&scope)
                        .exec(tx)
                        .await
                        .map_err(map_scope_to_tx)?;
                    if res.rows_affected == 0 {
                        // The row vanished between the SELECT and the
                        // UPDATE — only reachable on a concurrent
                        // hard-delete TX racing this upsert. Surface as
                        // `Internal` so the operator sees the timing
                        // collision; the caller's retry happens upstream.
                        tracing::warn!(
                            target: "am.metadata",
                            tenant_id = %tenant_id,
                            schema_uuid = %schema_uuid,
                            "metadata upsert UPDATE affected 0 rows; concurrent hard-delete suspected"
                        );
                        return Err(TxError::Domain(DomainError::Internal {
                            diagnostic: format!(
                                "metadata upsert UPDATE affected 0 rows for ({tenant_id}, \
                                 {schema_uuid}); concurrent hard-delete suspected"
                            ),
                            cause: None,
                        }));
                    }
                    Ok(UpsertOutcome::Updated(MetadataRow {
                        tenant_id,
                        schema_uuid,
                        value: value_for_row,
                        created_at: existing.created_at,
                        updated_at: now,
                    }))
                } else {
                    // INSERT path: stamp `created_at == updated_at == now`.
                    let am = tenant_metadata::ActiveModel {
                        tenant_id: ActiveValue::Set(tenant_id),
                        schema_uuid: ActiveValue::Set(schema_uuid),
                        value: ActiveValue::Set(value),
                        created_at: ActiveValue::Set(now),
                        updated_at: ActiveValue::Set(now),
                    };
                    // `scope_with_model` validates the AM's `tenant_id`
                    // column against the supplied scope per the
                    // `SecureInsertOne` Scopable contract — required
                    // for entities declared with `tenant_col`.
                    let model = tenant_metadata::Entity::insert(am.clone())
                        .secure()
                        // `scope_with_model` validates the AM's
                        // `tenant_id` against the caller scope per the
                        // `SecureInsertOne` Scopable contract; the
                        // caller's `InTenantSubtree` scope clamps the
                        // INSERT to the caller's subtree before any row
                        // hits the DB.
                        .scope_with_model(&scope, &am)
                        .map_err(map_scope_to_tx)?
                        .exec_with_returning(tx)
                        .await
                        .map_err(map_scope_to_tx)?;
                    Ok(UpsertOutcome::Inserted(entity_to_row(model)))
                }
            })
        })
    })
    .await
}
// @cpt-end:cpt-cf-account-management-dod-tenant-metadata-crud-contract:p1:inst-dod-crud-upsert-storage
// @cpt-end:cpt-cf-account-management-flow-tenant-metadata-put:p1:inst-storage-upsert-impl

// @cpt-begin:cpt-cf-account-management-flow-tenant-metadata-delete:p1:inst-storage-delete-impl
// @cpt-begin:cpt-cf-account-management-dod-tenant-metadata-distinct-404-codes:p1:inst-dod-distinct-404-delete-storage
async fn delete_for_tenant(
    repo: &MetadataRepoImpl,
    scope: &AccessScope,
    tenant_id: Uuid,
    schema_uuid: Uuid,
) -> Result<(), DomainError> {
    let conn = repo.db.conn()?;
    let res = tenant_metadata::Entity::delete_many()
        .filter(pk_eq(tenant_id, schema_uuid))
        .secure()
        // Same caller-scope forwarding as the rest of the file —
        // `InTenantSubtree` clamps the DELETE to the caller's subtree.
        .scope_with(scope)
        .exec(&conn)
        .await
        .map_err(map_scope_err)?;
    if res.rows_affected == 0 {
        // Distinct-404 contract: missing rows MUST surface
        // `MetadataEntryNotFound`, not `Ok(())`. The service layer
        // forwards this verbatim per
        // `dod-tenant-metadata-distinct-404-codes`.
        return Err(DomainError::MetadataEntryNotFound {
            detail: format!("no metadata entry for tenant {tenant_id} at schema {schema_uuid}"),
            entry: format!("({tenant_id}, {schema_uuid})"),
        });
    }
    Ok(())
}
// @cpt-end:cpt-cf-account-management-dod-tenant-metadata-distinct-404-codes:p1:inst-dod-distinct-404-delete-storage
// @cpt-end:cpt-cf-account-management-flow-tenant-metadata-delete:p1:inst-storage-delete-impl

// ---------------------------------------------------------------------------
// Trait dispatch.
// ---------------------------------------------------------------------------

#[async_trait]
impl MetadataRepo for MetadataRepoImpl {
    async fn list_for_tenant(
        &self,
        scope: &AccessScope,
        tenant_id: Uuid,
        pagination: MetadataPagination,
    ) -> Result<MetadataRowsPage, DomainError> {
        list_for_tenant(self, scope, tenant_id, pagination).await
    }

    async fn get_for_tenant(
        &self,
        scope: &AccessScope,
        tenant_id: Uuid,
        schema_uuid: Uuid,
    ) -> Result<Option<MetadataRow>, DomainError> {
        get_for_tenant(self, scope, tenant_id, schema_uuid).await
    }

    async fn upsert_for_tenant(
        &self,
        scope: &AccessScope,
        tenant_id: Uuid,
        schema_uuid: Uuid,
        value: Value,
        now: OffsetDateTime,
    ) -> Result<UpsertOutcome, DomainError> {
        upsert_for_tenant(self, scope, tenant_id, schema_uuid, value, now).await
    }

    async fn delete_for_tenant(
        &self,
        scope: &AccessScope,
        tenant_id: Uuid,
        schema_uuid: Uuid,
    ) -> Result<(), DomainError> {
        delete_for_tenant(self, scope, tenant_id, schema_uuid).await
    }
}
