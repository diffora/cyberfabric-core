//! `SeaORM`-backed implementation of [`TenantRepo`].
//!
//! AM is the authoritative owner of the `tenants` + `tenant_closure`
//! tables (DESIGN §4.2). Every public repo method takes an explicit
//! [`AccessScope`] parameter that is forwarded verbatim to the secure
//! `modkit_db` query builders. The service layer derives the scope from
//! the caller's [`SecurityContext`] (per-caller tenant scope, with a
//! platform-admin override anchored on the platform-root tenant id) and
//! also performs an explicit ancestry check against `tenant_closure`
//! before each call — the storage-level scope is defence-in-depth
//! against a missing service-level check. Background-task entry points
//! (retention sweep, provisioning reaper, integrity audit) are the only
//! callers that pass [`AccessScope::allow_all`] — they have no
//! per-request caller context and are explicitly allowed by DESIGN §4.2
//! to operate over the whole tree.
//!
//! The `Scopable` derives on the entities additionally enforce:
//!
//! * tenant-immutability on updates (the secure `UpdateMany` wrapper
//!   rejects any attempt to update `tenants.id` since `tenant_col = "id"`),
//! * type-safe executor selection (`DBRunner` trait is sealed so the repo
//!   cannot reach through to a raw `SeaORM` connection).
//!
//! Transactional writes (`activate_tenant`, `update_tenant_mutable`,
//! `compensate_provisioning`, `schedule_deletion`, `hard_delete_one`) go
//! through [`DBProvider::transaction_with_config`] under
//! [`TxIsolationLevel::Serializable`] via the [`with_serializable_retry`]
//! helper, which closes `DoD` `concurrency-serializability` and AC#15: the
//! tenants tree + closure invariants must be preserved under concurrent
//! mutators. Serialization conflicts (Postgres SQLSTATE `40001`,
//! `MySQL`/`MariaDB` `InnoDB` deadlocks, `PostgreSQL`
//! `could not serialize access` message) are bounded-retried up to
//! 5 attempts with exponential 1-2-4-8 ms backoff before propagating to
//! the caller as the original `AmError::Internal`. All commit / rollback
//! failures continue to flow through the `impl From<DbError> for AmError`
//! in `infra/error_conv.rs`.
//!
//! Background-task scans (`scan_retention_due`, `scan_stuck_provisioning`,
//! `load_tree_and_closure_for_scope`) are read-only and stay on the
//! engine default isolation — they do not need SERIALIZABLE.

use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use async_trait::async_trait;
use modkit_db::DBProvider;
use modkit_db::secure::{
    DbTx, SecureDeleteExt, SecureEntityExt, SecureInsertExt, SecureUpdateExt, TxAccessMode,
    TxConfig, TxIsolationLevel, is_unique_violation,
};
use modkit_security::AccessScope;
use sea_orm::sea_query::{Expr, LockBehavior, LockType};
use sea_orm::{ColumnTrait, Condition, EntityTrait, Order, QueryFilter};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::domain::error::AmError;
use crate::domain::idp::ProvisionMetadataEntry;
use crate::domain::metrics::{AM_SERIALIZABLE_RETRY, MetricKind, emit_metric};
use crate::domain::tenant::closure::ClosureRow;
use crate::domain::tenant::integrity::IntegrityScope;
use crate::domain::tenant::model::{
    ListChildrenQuery, NewTenant, TenantModel, TenantPage, TenantStatus, TenantUpdate,
};
use crate::domain::tenant::repo::TenantRepo;
use crate::domain::tenant::retention::{
    HardDeleteOutcome, TenantProvisioningRow, TenantRetentionRow,
};
use crate::infra::storage::entity::{tenant_closure, tenant_metadata, tenants};

/// Shared alias used by `module.rs` + tests.
pub type AmDbProvider = DBProvider<AmError>;

/// `SeaORM` repository adapter for [`TenantRepo`].
///
/// Holds a shared [`DBProvider`] parameterized over [`AmError`] so every
/// infra failure funnels through the single `From<DbError> for AmError`
/// boundary in `infra/error_conv.rs`.
pub struct TenantRepoImpl {
    db: Arc<AmDbProvider>,
}

impl TenantRepoImpl {
    #[must_use]
    pub fn new(db: Arc<AmDbProvider>) -> Self {
        Self { db }
    }
}

// ---- private helpers ------------------------------------------------------

fn map_scope_err(err: modkit_db::secure::ScopeError) -> AmError {
    use modkit_db::secure::ScopeError;
    match err {
        // Route the underlying `sea_orm::DbErr` through the canonical
        // `From<DbError> for AmError` ladder in `infra/error_conv.rs`
        // so SQLSTATE `40001` becomes `AmError::SerializationConflict`
        // and `with_serializable_retry` actually retries it. Earlier
        // this arm flattened directly to `AmError::Internal`,
        // discarding the SQLSTATE / unique-violation classification —
        // a SERIALIZABLE conflict surfacing through a SecureORM
        // statement (the common path) was silently demoted to a 500
        // and never retried. Same routing also catches Postgres
        // `23505` / SQLite `2067` / MySQL `1062` and maps them to
        // `AmError::Conflict` (HTTP 409) per AC §15 line 711.
        ScopeError::Db(db) => AmError::from(modkit_db::DbError::Sea(db)),
        ScopeError::Invalid(msg) => AmError::Internal {
            diagnostic: format!("scope invalid: {msg}"),
        },
        ScopeError::TenantNotInScope { .. } => AmError::CrossTenantDenied,
        ScopeError::Denied(msg) => AmError::Internal {
            diagnostic: format!("unexpected access denied in AM repo: {msg}"),
        },
    }
}

fn entity_to_model(row: tenants::Model) -> Result<TenantModel, AmError> {
    let status = TenantStatus::from_smallint(row.status).ok_or_else(|| AmError::Internal {
        diagnostic: format!("tenants.status out-of-domain value: {}", row.status),
    })?;
    let depth = u32::try_from(row.depth).map_err(|_| AmError::Internal {
        diagnostic: format!("tenants.depth negative: {}", row.depth),
    })?;
    Ok(TenantModel {
        id: row.id,
        parent_id: row.parent_id,
        name: row.name,
        status,
        self_managed: row.self_managed,
        tenant_type_uuid: row.tenant_type_uuid,
        depth,
        created_at: row.created_at,
        updated_at: row.updated_at,
        deleted_at: row.deleted_at,
    })
}

/// Build a simple `Condition` that matches a tenant id. Used everywhere
/// to bridge the `SimpleExpr` returned by `Column::eq` with the
/// `Condition` parameter accepted by `SecureSelect::filter`.
fn id_eq(id: Uuid) -> Condition {
    Condition::all().add(tenants::Column::Id.eq(id))
}

static GTS_NAMESPACE: LazyLock<Uuid> = LazyLock::new(|| Uuid::new_v5(&Uuid::NAMESPACE_URL, b"gts"));

fn schema_uuid_from_gts_id(gts_id: &str) -> Uuid {
    Uuid::new_v5(&GTS_NAMESPACE, gts_id.as_bytes())
}

/// Maximum number of attempts for a SERIALIZABLE transaction before the
/// retry helper gives up and returns the underlying error to the caller.
const MAX_SERIALIZABLE_ATTEMPTS: u32 = 5;

/// TTL after which a hard-delete scan claim is considered stale and may
/// be stolen by another worker. Bounds the worst-case stuck-row latency
/// when [`TenantRepo::clear_retention_claim`] fails after a non-Cleaned
/// outcome (network blip, pool exhaustion): without this, the row would
/// be permanently invisible to future scans because `claimed_by` would
/// never return to NULL. A `Deleted` row's `updated_at` is frozen by
/// `schedule_deletion` and only touched by the scan UPDATE below, so it
/// is a reliable claim-age marker for retention rows.
// `from_mins` is unstable on the workspace MSRV; keep `from_secs` form.
#[allow(clippy::duration_suboptimal_units)]
const RETENTION_CLAIM_TTL: Duration = Duration::from_secs(600);

/// Run a SERIALIZABLE transaction with bounded retry on serialization
/// failure.
///
/// SERIALIZABLE isolation can produce SQLSTATE `40001` whenever the
/// engine detects a read/write dependency cycle. These errors are
/// always safe to retry. The retry trigger is the typed
/// [`AmError::SerializationConflict`] variant routed by
/// `From<DbError>` in [`crate::infra::error_conv`]; underneath it
/// uses `modkit_db::deadlock::is_serialization_failure(&DbErr)` so
/// detection stays in sync with the workspace primitive.
///
/// Retries up to [`MAX_SERIALIZABLE_ATTEMPTS`] times with exponential
/// 1-2-4-8 ms backoff. On exhaustion the final `SerializationConflict`
/// propagates to the caller; it sits in the [`AmError`] `Conflict`
/// category (HTTP 409) with `sub_code = serialization_conflict` per
/// `domain/error.rs` — losing concurrent mutators receive a
/// deterministic `conflict` envelope per
/// `feature-tenant-hierarchy-management §6 / AC line 711`, not a 500.
///
/// The closure may be invoked multiple times — it must be idempotent.
/// All AM mutating transactions in this file are written so that
/// re-execution from a clean transaction state produces the same end
/// state (re-read row, re-check status, re-issue the same updates).
// @cpt-begin:cpt-cf-account-management-dod-tenant-hierarchy-management-concurrency-serializability:p1:inst-dod-concurrency-serializable-retry
async fn with_serializable_retry<F, T>(db: &AmDbProvider, op: F) -> Result<T, AmError>
where
    F: Fn() -> Box<
            dyn for<'a> FnOnce(
                    &'a DbTx<'a>,
                )
                    -> Pin<Box<dyn Future<Output = Result<T, AmError>> + Send + 'a>>
                + Send,
        > + Send
        + Sync,
    T: Send + 'static,
{
    let mut attempt: u32 = 0;
    loop {
        attempt += 1;
        let closure = op();
        let res = db
            .transaction_with_config(TxConfig::serializable(), |tx| closure(tx))
            .await;
        match res {
            Ok(v) => {
                // Telemetry — only emit when at least one retry was
                // needed. `attempts` is bounded by
                // `MAX_SERIALIZABLE_ATTEMPTS` so cardinality stays
                // small.
                if attempt > 1 {
                    let attempts = attempt.to_string();
                    emit_metric(
                        AM_SERIALIZABLE_RETRY,
                        MetricKind::Counter,
                        &[("outcome", "recovered"), ("attempts", attempts.as_str())],
                    );
                }
                return Ok(v);
            }
            Err(AmError::SerializationConflict { .. }) if attempt < MAX_SERIALIZABLE_ATTEMPTS => {
                // Exponential backoff: 1ms, 2ms, 4ms, 8ms.
                let backoff_ms = 1u64 << (attempt - 1);
                tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
            }
            Err(e @ AmError::SerializationConflict { .. }) => {
                // attempt == MAX_SERIALIZABLE_ATTEMPTS — retry budget
                // exhausted. Emit `outcome=exhausted` so platform
                // monitoring can alert on sustained DB contention,
                // then surface the typed error to the caller (mapped
                // to `conflict` / HTTP 409 by `AmError::category`).
                let attempts = attempt.to_string();
                emit_metric(
                    AM_SERIALIZABLE_RETRY,
                    MetricKind::Counter,
                    &[("outcome", "exhausted"), ("attempts", attempts.as_str())],
                );
                return Err(e);
            }
            Err(e) => return Err(e),
        }
    }
}
// @cpt-end:cpt-cf-account-management-dod-tenant-hierarchy-management-concurrency-serializability:p1:inst-dod-concurrency-serializable-retry

#[async_trait]
impl TenantRepo for TenantRepoImpl {
    async fn find_by_id(
        &self,
        scope: &AccessScope,
        id: Uuid,
    ) -> Result<Option<TenantModel>, AmError> {
        let conn = self.db.conn()?;
        let row = tenants::Entity::find()
            .secure()
            .scope_with(scope)
            .filter(id_eq(id))
            .one(&conn)
            .await
            .map_err(map_scope_err)?;
        match row {
            Some(r) => Ok(Some(entity_to_model(r)?)),
            None => Ok(None),
        }
    }

    async fn list_children(
        &self,
        scope: &AccessScope,
        query: &ListChildrenQuery,
    ) -> Result<TenantPage, AmError> {
        let conn = self.db.conn()?;

        // Base filter: parent_id = query.parent_id AND status filter.
        let status_filter_cond = if let Some(statuses) = query.status_filter() {
            let mut any_of = Condition::any();
            for s in statuses {
                any_of = any_of.add(tenants::Column::Status.eq(s.as_smallint()));
            }
            any_of
        } else {
            // Default: active and suspended only. Callers must explicitly
            // request status=deleted to see soft-deleted tenants.
            Condition::any()
                .add(tenants::Column::Status.eq(TenantStatus::Active.as_smallint()))
                .add(tenants::Column::Status.eq(TenantStatus::Suspended.as_smallint()))
        };

        let base = Condition::all()
            .add(tenants::Column::ParentId.eq(query.parent_id))
            .add(status_filter_cond);

        // Stable ordering: (created_at ASC, id ASC) per DESIGN §3.3.
        let items_rows = tenants::Entity::find()
            .secure()
            .scope_with(scope)
            .filter(base.clone())
            .order_by(tenants::Column::CreatedAt, Order::Asc)
            .order_by(tenants::Column::Id, Order::Asc)
            .limit(u64::from(query.top))
            .offset(u64::from(query.skip))
            .all(&conn)
            .await
            .map_err(map_scope_err)?;

        let total: u64 = tenants::Entity::find()
            .secure()
            .scope_with(scope)
            .filter(base)
            .count(&conn)
            .await
            .map_err(map_scope_err)?;

        let mut items = Vec::with_capacity(items_rows.len());
        for r in items_rows {
            items.push(entity_to_model(r)?);
        }

        Ok(TenantPage {
            items,
            top: query.top,
            skip: query.skip,
            total: Some(total),
        })
    }

    async fn insert_provisioning(
        &self,
        scope: &AccessScope,
        tenant: &NewTenant,
    ) -> Result<TenantModel, AmError> {
        use sea_orm::ActiveValue;
        let conn = self.db.conn()?;
        let now = OffsetDateTime::now_utc();
        let am = tenants::ActiveModel {
            id: ActiveValue::Set(tenant.id),
            parent_id: ActiveValue::Set(tenant.parent_id),
            name: ActiveValue::Set(tenant.name.clone()),
            status: ActiveValue::Set(TenantStatus::Provisioning.as_smallint()),
            self_managed: ActiveValue::Set(tenant.self_managed),
            tenant_type_uuid: ActiveValue::Set(tenant.tenant_type_uuid),
            depth: ActiveValue::Set(i32::try_from(tenant.depth).map_err(|_| {
                AmError::Internal {
                    diagnostic: format!("depth overflow: {}", tenant.depth),
                }
            })?),
            created_at: ActiveValue::Set(now),
            updated_at: ActiveValue::Set(now),
            deleted_at: ActiveValue::Set(None),
            deletion_scheduled_at: ActiveValue::Set(None),
            retention_window_secs: ActiveValue::Set(None),
            claimed_by: ActiveValue::Set(None),
        };
        // scope_unchecked: `tenants.tenant_col = "id"` so `scope_with` would
        // require an existing row with that id — there is none yet on INSERT.
        // The caller always passes `allow_all` (PEP gate is the real guard).
        let model: tenants::Model = tenants::Entity::insert(am)
            .secure()
            .scope_unchecked(scope)
            .map_err(map_scope_err)?
            .exec_with_returning(&conn)
            .await
            .map_err(|e| match e {
                modkit_db::secure::ScopeError::Db(ref db) if is_unique_violation(db) => {
                    AmError::Conflict {
                        detail: format!("tenant {} already exists", tenant.id),
                    }
                }
                other => map_scope_err(other),
            })?;
        entity_to_model(model)
    }

    async fn activate_tenant(
        &self,
        scope: &AccessScope,
        tenant_id: Uuid,
        closure_rows: &[ClosureRow],
        metadata_entries: &[ProvisionMetadataEntry],
    ) -> Result<TenantModel, AmError> {
        let rows = closure_rows.to_vec();
        let metadata_entries = metadata_entries.to_vec();
        let scope = scope.clone();
        let result = with_serializable_retry(&self.db, move || {
            let scope = scope.clone();
            let rows = rows.clone();
            let metadata_entries = metadata_entries.clone();
            Box::new(move |tx: &DbTx<'_>| {
                Box::pin(async move {
                    use sea_orm::ActiveValue;

                    let existing = tenants::Entity::find()
                        .secure()
                        .scope_with(&scope)
                        .filter(id_eq(tenant_id))
                        .one(tx)
                        .await
                        .map_err(map_scope_err)?
                        .ok_or_else(|| AmError::NotFound {
                            detail: format!("tenant {tenant_id} not found for activation"),
                        })?;

                    if existing.status != TenantStatus::Provisioning.as_smallint() {
                        return Err(AmError::Conflict {
                            detail: format!("tenant {tenant_id} not in provisioning state"),
                        });
                    }

                    // Flip status -> Active + bump updated_at via SecureUpdateMany.
                    let now = OffsetDateTime::now_utc();
                    let rows_affected = tenants::Entity::update_many()
                        .col_expr(
                            tenants::Column::Status,
                            Expr::value(TenantStatus::Active.as_smallint()),
                        )
                        .col_expr(tenants::Column::UpdatedAt, Expr::value(now))
                        .filter(id_eq(tenant_id))
                        .secure()
                        .scope_with(&scope)
                        .exec(tx)
                        .await
                        .map_err(map_scope_err)?
                        .rows_affected;
                    if rows_affected == 0 {
                        return Err(AmError::NotFound {
                            detail: format!("tenant {tenant_id} missing during activation"),
                        });
                    }

                    // Insert closure rows in a single multi-row INSERT.
                    // SeaORM `Entity::insert_many` returns the same
                    // `Insert<A>` builder the secure wrapper extends,
                    // so we keep the secure-execution path while
                    // collapsing depth-N RT into one. The closure
                    // entity is declared with `no_tenant, no_resource,
                    // no_owner, no_type` — closure rows are
                    // cross-tenant by definition — so `scope_unchecked`
                    // is the appropriate scope mode (matches the
                    // single-row insert path immediately above the
                    // refactor).
                    if !rows.is_empty() {
                        // @cpt-begin:cpt-cf-account-management-algo-tenant-hierarchy-management-closure-maintenance:p1:inst-algo-closmnt-repo-activation-insert
                        let active_models = rows.iter().map(|row| tenant_closure::ActiveModel {
                            ancestor_id: ActiveValue::Set(row.ancestor_id),
                            descendant_id: ActiveValue::Set(row.descendant_id),
                            barrier: ActiveValue::Set(row.barrier),
                            descendant_status: ActiveValue::Set(row.descendant_status),
                        });
                        tenant_closure::Entity::insert_many(active_models)
                            .secure()
                            .scope_unchecked(&scope)
                            .map_err(map_scope_err)?
                            .exec(tx)
                            .await
                            .map_err(map_scope_err)?;
                        // @cpt-end:cpt-cf-account-management-algo-tenant-hierarchy-management-closure-maintenance:p1:inst-algo-closmnt-repo-activation-insert
                    }

                    if !metadata_entries.is_empty() {
                        let metadata_rows =
                            metadata_entries.iter().map(|entry| tenant_metadata::ActiveModel {
                                tenant_id: ActiveValue::Set(tenant_id),
                                schema_uuid: ActiveValue::Set(schema_uuid_from_gts_id(
                                    &entry.schema_id,
                                )),
                                value: ActiveValue::Set(entry.value.clone()),
                                created_at: ActiveValue::Set(now),
                                updated_at: ActiveValue::Set(now),
                            });
                        tenant_metadata::Entity::insert_many(metadata_rows)
                            .secure()
                            .scope_unchecked(&scope)
                            .map_err(map_scope_err)?
                            .exec(tx)
                            .await
                            .map_err(|e| match e {
                                modkit_db::secure::ScopeError::Db(ref db)
                                    if is_unique_violation(db) =>
                                {
                                    AmError::Conflict {
                                        detail: format!(
                                            "tenant {tenant_id} metadata contains duplicate schema entries"
                                        ),
                                    }
                                }
                                other => map_scope_err(other),
                            })?;
                    }

                    // Re-read so the caller gets a fresh model with the new status.
                    let fresh = tenants::Entity::find()
                        .secure()
                        .scope_with(&scope)
                        .filter(id_eq(tenant_id))
                        .one(tx)
                        .await
                        .map_err(map_scope_err)?
                        .ok_or_else(|| AmError::Internal {
                            diagnostic: format!("tenant {tenant_id} disappeared after activation"),
                        })?;
                    entity_to_model(fresh)
                })
            })
        })
        .await?;
        Ok(result)
    }

    async fn compensate_provisioning(
        &self,
        scope: &AccessScope,
        tenant_id: Uuid,
    ) -> Result<(), AmError> {
        let scope = scope.clone();
        with_serializable_retry(&self.db, move || {
            let scope = scope.clone();
            Box::new(move |tx: &DbTx<'_>| {
                Box::pin(async move {
                    let existing = tenants::Entity::find()
                        .secure()
                        .scope_with(&scope)
                        .filter(id_eq(tenant_id))
                        .one(tx)
                        .await
                        .map_err(map_scope_err)?;
                    match existing {
                        Some(row)
                            if row.status == TenantStatus::Provisioning.as_smallint() =>
                        {
                            tenants::Entity::delete_many()
                                .filter(
                                    Condition::all()
                                        .add(tenants::Column::Id.eq(tenant_id))
                                        .add(
                                            tenants::Column::Status
                                                .eq(TenantStatus::Provisioning.as_smallint()),
                                        ),
                                )
                                .secure()
                                .scope_with(&scope)
                                .exec(tx)
                                .await
                                .map_err(map_scope_err)?;
                            Ok(())
                        }
                        Some(_) => Err(AmError::Conflict {
                            detail: format!(
                                "refusing to compensate: tenant {tenant_id} not in provisioning state"
                            ),
                        }),
                        None => Ok(()),
                    }
                })
            })
        })
        .await
    }

    async fn update_tenant_mutable(
        &self,
        scope: &AccessScope,
        tenant_id: Uuid,
        patch: &TenantUpdate,
    ) -> Result<TenantModel, AmError> {
        let patch_owned = patch.clone();
        let scope = scope.clone();
        with_serializable_retry(&self.db, move || {
            let patch_owned = patch_owned.clone();
            let scope = scope.clone();
            Box::new(move |tx: &DbTx<'_>| {
                Box::pin(async move {
                    // SERIALIZABLE anti-dependency anchor: the SELECT
                    // forces this transaction to see the row in its
                    // pre-update state, so a concurrent PATCH on the
                    // same row triggers a `40001` serialization
                    // failure instead of a lost update. The row value
                    // itself is unused — discarded with `let _row`
                    // rather than removed entirely so the read isn't
                    // optimised away. Also gates the path on row
                    // existence, mapping a missing tenant to
                    // `NotFound` before any write SQL is sent.
                    let _row = tenants::Entity::find()
                        .secure()
                        .scope_with(&scope)
                        .filter(id_eq(tenant_id))
                        .one(tx)
                        .await
                        .map_err(map_scope_err)?
                        .ok_or_else(|| AmError::NotFound {
                            detail: format!("tenant {tenant_id} not found"),
                        })?;

                    let now = OffsetDateTime::now_utc();
                    let mut upd = tenants::Entity::update_many()
                        .col_expr(tenants::Column::UpdatedAt, Expr::value(now));
                    if let Some(ref new_name) = patch_owned.name {
                        upd = upd.col_expr(tenants::Column::Name, Expr::value(new_name.clone()));
                    }
                    if let Some(new_status) = patch_owned.status {
                        upd = upd.col_expr(
                            tenants::Column::Status,
                            Expr::value(new_status.as_smallint()),
                        );
                    }
                    upd.filter(id_eq(tenant_id))
                        .secure()
                        .scope_with(&scope)
                        .exec(tx)
                        .await
                        .map_err(map_scope_err)?;

                    // Rewrite tenant_closure.descendant_status atomically on status change.
                    if let Some(new_status) = patch_owned.status {
                        // @cpt-begin:cpt-cf-account-management-algo-tenant-hierarchy-management-closure-maintenance:p1:inst-algo-closmnt-repo-status-update
                        tenant_closure::Entity::update_many()
                            .col_expr(
                                tenant_closure::Column::DescendantStatus,
                                Expr::value(new_status.as_smallint()),
                            )
                            .filter(
                                Condition::all()
                                    .add(tenant_closure::Column::DescendantId.eq(tenant_id)),
                            )
                            .secure()
                            .scope_with(&scope)
                            .exec(tx)
                            .await
                            .map_err(map_scope_err)?;
                        // @cpt-end:cpt-cf-account-management-algo-tenant-hierarchy-management-closure-maintenance:p1:inst-algo-closmnt-repo-status-update
                    }

                    let fresh = tenants::Entity::find()
                        .secure()
                        .scope_with(&scope)
                        .filter(id_eq(tenant_id))
                        .one(tx)
                        .await
                        .map_err(map_scope_err)?
                        .ok_or_else(|| AmError::Internal {
                            diagnostic: format!("tenant {tenant_id} disappeared after update"),
                        })?;
                    entity_to_model(fresh)
                })
            })
        })
        .await
    }

    async fn load_strict_ancestors_of_parent(
        &self,
        scope: &AccessScope,
        parent_id: Uuid,
    ) -> Result<Vec<TenantModel>, AmError> {
        let conn = self.db.conn()?;

        // Resolve the strict ancestors via `parent`'s closure rows:
        // every `descendant_id = parent_id` row in `tenant_closure`
        // names a tenant on the chain `[parent, parent's parent, …,
        // root]`. One RT into closure → one RT into `tenants` for the
        // strict-ancestor set, regardless of depth.
        //
        // `tenant_closure` carries no per-row tenant ownership column
        // (`no_tenant`, `no_resource`) — closure rows are cross-tenant
        // by definition — so the scoped read is the subsequent
        // `tenants` query.
        let closure_rows = tenant_closure::Entity::find()
            .secure()
            .scope_with(&AccessScope::allow_all())
            .filter(Condition::all().add(tenant_closure::Column::DescendantId.eq(parent_id)))
            .all(&conn)
            .await
            .map_err(map_scope_err)?;

        if closure_rows.is_empty() {
            // Defensive fallback: parent has no closure rows yet (e.g.
            // diagnostic call against an in-flight provisioning parent).
            // Walk via `parent_id` like the legacy implementation; this
            // path is rare and bounded by the depth invariant.
            //
            // The walk is hard-capped at `MAX_ANCESTOR_WALK_HOPS` so a
            // corrupt `parent_id` cycle (or a depth value that disagrees
            // with the actual chain length) can't loop indefinitely
            // issuing one DB round-trip per hop. The cap is well above
            // any realistic depth_threshold; overrun returns
            // `AmError::Internal` so ops sees the corruption.
            const MAX_ANCESTOR_WALK_HOPS: usize = 64;
            // Emit a WARN whenever we land here so a closure-table gap
            // developing in production (the only non-bootstrap reason
            // this branch fires) is surfaced rather than silently
            // absorbing the per-hop round-trips.
            tracing::warn!(
                target: "am.tenant_repo",
                parent_id = %parent_id,
                "load_strict_ancestors_of_parent: closure rows empty; falling back to parent_id walk (one query per hop)"
            );
            let mut chain = Vec::new();
            let mut cursor_id = Some(parent_id);
            let mut hops = 0usize;
            while let Some(pid) = cursor_id {
                if hops >= MAX_ANCESTOR_WALK_HOPS {
                    return Err(AmError::Internal {
                        diagnostic: format!(
                            "ancestor walk exceeded {MAX_ANCESTOR_WALK_HOPS} hops from parent {parent_id}; possible parent_id cycle"
                        ),
                    });
                }
                let parent = tenants::Entity::find()
                    .secure()
                    .scope_with(scope)
                    .filter(id_eq(pid))
                    .one(&conn)
                    .await
                    .map_err(map_scope_err)?
                    .ok_or_else(|| AmError::NotFound {
                        detail: format!("ancestor {pid} missing while walking chain"),
                    })?;
                cursor_id = parent.parent_id;
                chain.push(entity_to_model(parent)?);
                hops += 1;
            }
            return Ok(chain);
        }

        let ancestor_ids: Vec<Uuid> = closure_rows.iter().map(|r| r.ancestor_id).collect();
        let rows = tenants::Entity::find()
            .secure()
            .scope_with(scope)
            .filter(Condition::all().add(tenants::Column::Id.is_in(ancestor_ids.clone())))
            .order_by(tenants::Column::Depth, Order::Desc)
            .all(&conn)
            .await
            .map_err(map_scope_err)?;
        if rows.len() != ancestor_ids.len() {
            let found: HashSet<Uuid> = rows.iter().map(|r| r.id).collect();
            let mut missing_ids: Vec<Uuid> = ancestor_ids
                .iter()
                .copied()
                .filter(|id| !found.contains(id))
                .collect();
            missing_ids.sort_unstable();
            return Err(AmError::NotFound {
                detail: format!("ancestor ids missing: {missing_ids:?}"),
            });
        }

        let mut chain = Vec::with_capacity(rows.len());
        for r in rows {
            chain.push(entity_to_model(r)?);
        }
        Ok(chain)
    }

    // -----------------------------------------------------------------
    // Phase 3 — retention scan, reaper scan, hard-delete, integrity load
    // -----------------------------------------------------------------

    async fn scan_retention_due(
        &self,
        scope: &AccessScope,
        now: OffsetDateTime,
        default_retention: Duration,
        limit: usize,
    ) -> Result<Vec<TenantRetentionRow>, AmError> {
        // Push the per-row due-check into SQL so the `LIMIT` applies to
        // *due* rows only. The earlier implementation over-fetched
        // `4 × batch` rows ordered by `scheduled_at ASC` and applied
        // `is_due` in Rust afterwards — but a backlog of older
        // not-yet-due rows (typical case: NULL `retention_window_secs`
        // → default 90 days) could fill the over-fetch window and
        // starve newer due rows (e.g. soft-deleted with explicit
        // `retention_window_secs = 0`). The reviewer flagged this as
        // an indefinite-delay class of bug; by filtering at the DB the
        // due-set is exact and starvation is impossible.
        //
        // The effective due predicate is
        //   `scheduled_at + COALESCE(retention_window_secs, default) seconds <= now`.
        // Both supported backends express this as a single comparison
        // against `now`; no engine-specific INTERVAL arithmetic is
        // exposed to Rust. The MySQL backend is unsupported by AM
        // migrations (see `m0001_create_tenants`) so it errors here
        // for symmetry with the migration-set rejection.
        let engine = self.db.db().db_engine();
        let default_secs = i64::try_from(default_retention.as_secs()).unwrap_or(i64::MAX);
        let due_check = match engine {
            "postgres" => Expr::cust_with_values(
                "deletion_scheduled_at + make_interval(secs => COALESCE(retention_window_secs, $1)) <= $2",
                vec![
                    sea_orm::Value::from(default_secs),
                    sea_orm::Value::from(now),
                ],
            ),
            "sqlite" => Expr::cust_with_values(
                // SQLite stores TIMESTAMP as TEXT (ISO-8601);
                // `julianday()` returns a numeric so the comparison
                // is monotonic regardless of the textual format
                // SeaORM uses for the bound `now`.
                "julianday(deletion_scheduled_at) + COALESCE(retention_window_secs, $1) / 86400.0 <= julianday($2)",
                vec![
                    sea_orm::Value::from(default_secs),
                    sea_orm::Value::from(now),
                ],
            ),
            other => {
                return Err(AmError::Internal {
                    diagnostic: format!(
                        "scan_retention_due: backend '{other}' is not a supported AM backend"
                    ),
                });
            }
        };

        let cap = u64::try_from(limit).unwrap_or(u64::MAX);
        let worker_id = Uuid::new_v4();
        // Stale-claim cutoff: a row claimed before this instant whose
        // `clear_retention_claim` evidently never landed (else
        // `claimed_by` would be NULL) is up for re-claim by another
        // worker. Computed in Rust so the SQL stays portable across
        // the two supported engines.
        let stale_cutoff = match time::Duration::try_from(RETENTION_CLAIM_TTL) {
            Ok(d) => now - d,
            Err(_) => now,
        };
        let scope = scope.clone();
        let rows = self
            .db
            .transaction_with_config(
                TxConfig {
                    isolation: Some(TxIsolationLevel::ReadCommitted),
                    access_mode: Some(TxAccessMode::ReadWrite),
                },
                move |tx| {
                    Box::pin(async move {
                        // Claimable iff unclaimed OR the previous claim
                        // is older than `RETENTION_CLAIM_TTL`. The
                        // `updated_at` column is the claim-age marker
                        // (see comment on `RETENTION_CLAIM_TTL`).
                        let claimable = Condition::any()
                            .add(tenants::Column::ClaimedBy.is_null())
                            .add(tenants::Column::UpdatedAt.lte(stale_cutoff));
                        let scan_filter = Condition::all()
                            .add(tenants::Column::Status.eq(TenantStatus::Deleted.as_smallint()))
                            .add(tenants::Column::DeletionScheduledAt.is_not_null())
                            .add(claimable.clone())
                            .add(due_check);

                        let mut query = tenants::Entity::find()
                            .secure()
                            .scope_with(&scope)
                            .filter(scan_filter)
                            .order_by(tenants::Column::DeletionScheduledAt, Order::Asc)
                            .order_by(tenants::Column::Depth, Order::Desc)
                            .order_by(tenants::Column::Id, Order::Asc)
                            .limit(cap);
                        if engine == "postgres" {
                            query = query
                                .lock_with_behavior(LockType::Update, LockBehavior::SkipLocked);
                        }

                        let candidates = query.all(tx).await.map_err(map_scope_err)?;
                        let candidate_ids: Vec<Uuid> =
                            candidates.iter().map(|row| row.id).collect();
                        if candidate_ids.is_empty() {
                            return Ok(Vec::new());
                        }

                        // Bump `updated_at` so the new claim's age can
                        // be aged out by the same TTL predicate above
                        // if `clear_retention_claim` later fails.
                        tenants::Entity::update_many()
                            .col_expr(tenants::Column::ClaimedBy, Expr::value(worker_id))
                            .col_expr(tenants::Column::UpdatedAt, Expr::value(now))
                            .filter(
                                Condition::all()
                                    .add(tenants::Column::Id.is_in(candidate_ids))
                                    .add(claimable),
                            )
                            .secure()
                            .scope_with(&scope)
                            .exec_with_returning(tx)
                            .await
                            .map_err(map_scope_err)
                    })
                },
            )
            .await?;

        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let Some(scheduled_at) = r.deletion_scheduled_at else {
                continue;
            };
            let retention = match r.retention_window_secs {
                Some(secs) if secs >= 0 => Duration::from_secs(u64::try_from(secs).unwrap_or(0)),
                _ => default_retention,
            };
            // Defense-in-depth: the SQL filter is the source of truth;
            // we re-verify in Rust to catch any semantic drift between
            // backend date math and the domain `is_due` contract
            // (e.g. timezone normalisation differences). A mismatch is
            // logged but does not surface a hard error — the row is
            // simply skipped this tick and re-evaluated next one.
            if !crate::domain::tenant::retention::is_due(now, scheduled_at, retention) {
                tracing::warn!(
                    target: "am.tenant_retention",
                    tenant_id = %r.id,
                    "row matched SQL due-check but failed Rust is_due; skipping for this tick"
                );
                continue;
            }
            out.push(TenantRetentionRow {
                id: r.id,
                depth: u32::try_from(r.depth).map_err(|_| AmError::Internal {
                    diagnostic: format!(
                        "tenants.depth negative for retention row {}: {}",
                        r.id, r.depth
                    ),
                })?,
                deletion_scheduled_at: scheduled_at,
                retention_window: retention,
            });
        }
        // The SQL ordering is by `scheduled_at ASC` for index locality;
        // re-sort to the leaf-first order the batch processor expects
        // (`depth DESC, id ASC`).
        out.sort_by(|a, b| b.depth.cmp(&a.depth).then_with(|| a.id.cmp(&b.id)));
        Ok(out)
    }

    async fn clear_retention_claim(
        &self,
        scope: &AccessScope,
        tenant_id: Uuid,
    ) -> Result<(), AmError> {
        let conn = self.db.conn()?;
        tenants::Entity::update_many()
            .col_expr(
                tenants::Column::ClaimedBy,
                Expr::value(Option::<Uuid>::None),
            )
            .filter(id_eq(tenant_id))
            .secure()
            .scope_with(scope)
            .exec(&conn)
            .await
            .map_err(map_scope_err)?;
        Ok(())
    }

    async fn scan_stuck_provisioning(
        &self,
        scope: &AccessScope,
        older_than: OffsetDateTime,
        limit: usize,
    ) -> Result<Vec<TenantProvisioningRow>, AmError> {
        let conn = self.db.conn()?;
        // Bound the query at the SQL layer so a large stuck-provisioning
        // backlog cannot load every row into memory in one round-trip.
        // Mirrors `scan_retention_due`'s capped fetch pattern.
        //
        // Unlike `scan_retention_due` this method does NOT take a row
        // lock or atomic claim. Two reaper instances scanning the same
        // window may both pick up the same `Provisioning` row and both
        // call `IdpTenantProvisioner::deprovision_tenant` for it. That
        // is acceptable because:
        // 1. `deprovision_tenant` is idempotent per the
        //    `idp-tenant-deprovision` DoD — a second invocation on an
        //    already-removed tenant returns Ok or `UnsupportedOperation`,
        //    not a hard error.
        // 2. The follow-up DB teardown flows through
        //    `schedule_deletion(retention = 0)` which itself errors with
        //    `Conflict` if the row is already `Deleted`, so the second
        //    worker's branch lands on `NotEligible` at hard-delete time.
        // The cost is a wasted IdP call window equal to one
        // `reaper_tick_secs`, traded against the schema cost of adding a
        // claim column purely for liveness.
        let cap = u64::try_from(limit).unwrap_or(u64::MAX);
        let rows = tenants::Entity::find()
            .secure()
            .scope_with(scope)
            .filter(
                Condition::all()
                    .add(tenants::Column::Status.eq(TenantStatus::Provisioning.as_smallint()))
                    .add(tenants::Column::CreatedAt.lte(older_than)),
            )
            .order_by(tenants::Column::CreatedAt, Order::Asc)
            .order_by(tenants::Column::Id, Order::Asc)
            .limit(cap)
            .all(&conn)
            .await
            .map_err(map_scope_err)?;
        Ok(rows
            .into_iter()
            .map(|r| TenantProvisioningRow {
                id: r.id,
                created_at: r.created_at,
            })
            .collect())
    }

    async fn count_children(
        &self,
        scope: &AccessScope,
        parent_id: Uuid,
        include_deleted: bool,
    ) -> Result<u64, AmError> {
        let connection = self.db.conn()?;
        let mut filter = Condition::all().add(tenants::Column::ParentId.eq(parent_id));
        if !include_deleted {
            filter = filter.add(tenants::Column::Status.ne(TenantStatus::Deleted.as_smallint()));
        }
        tenants::Entity::find()
            .secure()
            .scope_with(scope)
            .filter(filter)
            .count(&connection)
            .await
            .map_err(map_scope_err)
    }

    async fn schedule_deletion(
        &self,
        scope: &AccessScope,
        id: Uuid,
        now: OffsetDateTime,
        retention: Option<Duration>,
    ) -> Result<TenantModel, AmError> {
        // Fail-fast on overflow. Silently clamping a misconfigured
        // duration of e.g. `Duration::MAX` to ~292 billion years would
        // mask the misconfig and produce rows that never become
        // retention-due. Returning `Internal` surfaces the bug to ops
        // immediately.
        let retention_secs: Option<i64> = match retention {
            None => None,
            Some(d) => Some(i64::try_from(d.as_secs()).map_err(|_| AmError::Internal {
                diagnostic: format!(
                    "retention duration {} secs overflows i64; misconfiguration",
                    d.as_secs()
                ),
            })?),
        };
        let scope = scope.clone();
        with_serializable_retry(&self.db, move || {
            let scope = scope.clone();
            Box::new(move |tx: &DbTx<'_>| {
                Box::pin(async move {
                    let existing = tenants::Entity::find()
                        .secure()
                        .scope_with(&scope)
                        .filter(id_eq(id))
                        .one(tx)
                        .await
                        .map_err(map_scope_err)?
                        .ok_or_else(|| AmError::NotFound {
                            detail: format!("tenant {id} not found"),
                        })?;
                    if existing.status == TenantStatus::Deleted.as_smallint() {
                        return Err(AmError::Conflict {
                            detail: format!("tenant {id} already deleted"),
                        });
                    }

                    let mut upd = tenants::Entity::update_many()
                        .col_expr(
                            tenants::Column::Status,
                            Expr::value(TenantStatus::Deleted.as_smallint()),
                        )
                        .col_expr(tenants::Column::UpdatedAt, Expr::value(now))
                        // `deleted_at` is the public-contract tombstone
                        // exposed through the `Tenant` schema
                        // (`account-management-v1.yaml:591`) and the
                        // partial index `idx_tenants_deleted_at`
                        // declared by `m0001_create_tenants`. The
                        // earlier implementation only stamped
                        // `deletion_scheduled_at` and left this column
                        // permanently NULL — which both made the
                        // dedicated partial index empty and surfaced
                        // soft-deleted rows to the API with
                        // `status=deleted, deleted_at=null`, violating
                        // the OpenAPI contract.
                        .col_expr(tenants::Column::DeletedAt, Expr::value(now))
                        .col_expr(tenants::Column::DeletionScheduledAt, Expr::value(now));
                    if let Some(secs) = retention_secs {
                        upd = upd.col_expr(tenants::Column::RetentionWindowSecs, Expr::value(secs));
                    }
                    upd.filter(id_eq(id))
                        .secure()
                        .scope_with(&scope)
                        .exec(tx)
                        .await
                        .map_err(map_scope_err)?;

                    // Rewrite descendant_status on every closure row that
                    // points at this tenant (same invariant as update).
                    // @cpt-begin:cpt-cf-account-management-algo-tenant-hierarchy-management-closure-maintenance:p1:inst-algo-closmnt-repo-soft-delete-status
                    tenant_closure::Entity::update_many()
                        .col_expr(
                            tenant_closure::Column::DescendantStatus,
                            Expr::value(TenantStatus::Deleted.as_smallint()),
                        )
                        .filter(Condition::all().add(tenant_closure::Column::DescendantId.eq(id)))
                        .secure()
                        .scope_with(&scope)
                        .exec(tx)
                        .await
                        .map_err(map_scope_err)?;
                    // @cpt-end:cpt-cf-account-management-algo-tenant-hierarchy-management-closure-maintenance:p1:inst-algo-closmnt-repo-soft-delete-status

                    let fresh = tenants::Entity::find()
                        .secure()
                        .scope_with(&scope)
                        .filter(id_eq(id))
                        .one(tx)
                        .await
                        .map_err(map_scope_err)?
                        .ok_or_else(|| AmError::Internal {
                            diagnostic: format!("tenant {id} disappeared after schedule_deletion"),
                        })?;
                    entity_to_model(fresh)
                })
            })
        })
        .await
    }

    async fn hard_delete_one(
        &self,
        scope: &AccessScope,
        id: Uuid,
    ) -> Result<HardDeleteOutcome, AmError> {
        let scope = scope.clone();
        with_serializable_retry(&self.db, move || {
            let scope = scope.clone();
            Box::new(move |tx: &DbTx<'_>| {
                Box::pin(async move {
                    let existing = tenants::Entity::find()
                        .secure()
                        .scope_with(&scope)
                        .filter(id_eq(id))
                        .one(tx)
                        .await
                        .map_err(map_scope_err)?;
                    let Some(row) = existing else {
                        // Row already gone — treat as cleaned for idempotency.
                        return Ok(HardDeleteOutcome::Cleaned);
                    };
                    if row.status != TenantStatus::Deleted.as_smallint()
                        || row.deletion_scheduled_at.is_none()
                    {
                        return Ok(HardDeleteOutcome::NotEligible);
                    }

                    // In-tx child-existence guard. If any row (including
                    // Deleted children that haven't been reclaimed yet)
                    // still names this tenant as parent, defer.
                    let children = tenants::Entity::find()
                        .secure()
                        .scope_with(&scope)
                        .filter(Condition::all().add(tenants::Column::ParentId.eq(id)))
                        .count(tx)
                        .await
                        .map_err(map_scope_err)?;
                    if children > 0 {
                        return Ok(HardDeleteOutcome::DeferredChildPresent);
                    }

                    // Closure rows first (FK cascades would do this on
                    // Postgres, but we clear explicitly to remain
                    // dialect-portable).
                    // @cpt-begin:cpt-cf-account-management-algo-tenant-hierarchy-management-closure-maintenance:p1:inst-algo-closmnt-repo-hard-delete
                    tenant_closure::Entity::delete_many()
                        .filter(
                            Condition::any()
                                .add(tenant_closure::Column::AncestorId.eq(id))
                                .add(tenant_closure::Column::DescendantId.eq(id)),
                        )
                        .secure()
                        .scope_with(&scope)
                        .exec(tx)
                        .await
                        .map_err(map_scope_err)?;
                    // @cpt-end:cpt-cf-account-management-algo-tenant-hierarchy-management-closure-maintenance:p1:inst-algo-closmnt-repo-hard-delete

                    // Tenant row.
                    tenants::Entity::delete_many()
                        .filter(id_eq(id))
                        .secure()
                        .scope_with(&scope)
                        .exec(tx)
                        .await
                        .map_err(map_scope_err)?;
                    Ok(HardDeleteOutcome::Cleaned)
                })
            })
        })
        .await
    }

    async fn load_tree_and_closure_for_scope(
        &self,
        scope: &AccessScope,
        integrity_scope: IntegrityScope,
        tenants_cap: Option<usize>,
    ) -> Result<(Vec<TenantModel>, Vec<ClosureRow>), AmError> {
        let scope = scope.clone();
        self.db
            .transaction_with_config(
                TxConfig {
                    isolation: Some(TxIsolationLevel::RepeatableRead),
                    access_mode: Some(TxAccessMode::ReadOnly),
                },
                move |tx| {
                    Box::pin(async move {
                        let (tenant_filter, closure_filter): (Condition, Condition) =
                            match integrity_scope {
                                IntegrityScope::Whole => (Condition::all(), Condition::all()),
                                IntegrityScope::Subtree(root) => {
                                    // Subtree membership is the set of `descendant_id`s in
                                    // closure rows with `ancestor_id = root`. Reuse that
                                    // set to filter both tables inside the same snapshot.
                                    let closure_rows_for_root = tenant_closure::Entity::find()
                                        .secure()
                                        .scope_with(&scope)
                                        .filter(
                                            Condition::all()
                                                .add(tenant_closure::Column::AncestorId.eq(root)),
                                        )
                                        .all(tx)
                                        .await
                                        .map_err(map_scope_err)?;
                                    let ids: Vec<Uuid> = closure_rows_for_root
                                        .iter()
                                        .map(|r| r.descendant_id)
                                        .collect();
                                    if ids.is_empty() {
                                        return Ok((Vec::new(), Vec::new()));
                                    }
                                    let tenant_cond =
                                        Condition::all().add(tenants::Column::Id.is_in(ids.clone()));
                                    let closure_cond = Condition::all()
                                        .add(tenant_closure::Column::DescendantId.is_in(ids));
                                    (tenant_cond, closure_cond)
                                }
                            };

                        // Apply the cap at the SQL layer when set: load `cap + 1` rows
                        // so an overrun is detectable, then fail-fast before loading
                        // any closure rows. This prevents a Whole-scope audit on a
                        // 100k-tenant deployment from streaming ~1M closure rows just
                        // to be rejected by an in-memory check.
                        let mut tenant_query = tenants::Entity::find()
                            .secure()
                            .scope_with(&scope)
                            .filter(tenant_filter);
                        if let Some(cap) = tenants_cap {
                            let probe = u64::try_from(cap.saturating_add(1)).unwrap_or(u64::MAX);
                            tenant_query = tenant_query.limit(probe);
                        }
                        let tenant_rows = tenant_query.all(tx).await.map_err(map_scope_err)?;
                        if let Some(cap) = tenants_cap
                            && tenant_rows.len() > cap
                        {
                            return Err(AmError::Internal {
                                diagnostic: format!(
                                    "integrity scope too large; use Subtree (live tenants > cap, cap={cap})"
                                ),
                            });
                        }
                        let mut tenants_out = Vec::with_capacity(tenant_rows.len());
                        for r in tenant_rows {
                            tenants_out.push(entity_to_model(r)?);
                        }

                        let closure_rows = tenant_closure::Entity::find()
                            .secure()
                            .scope_with(&scope)
                            .filter(closure_filter)
                            .all(tx)
                            .await
                            .map_err(map_scope_err)?;
                        let closure_out = closure_rows
                            .into_iter()
                            .map(|r| ClosureRow {
                                ancestor_id: r.ancestor_id,
                                descendant_id: r.descendant_id,
                                barrier: r.barrier,
                                descendant_status: r.descendant_status,
                            })
                            .collect();

                        Ok((tenants_out, closure_out))
                    })
                },
            )
            .await
    }

    async fn is_descendant(
        &self,
        scope: &AccessScope,
        ancestor: Uuid,
        descendant: Uuid,
    ) -> Result<bool, AmError> {
        let conn = self.db.conn()?;
        let count = tenant_closure::Entity::find()
            .secure()
            .scope_with(scope)
            .filter(
                Condition::all()
                    .add(tenant_closure::Column::AncestorId.eq(ancestor))
                    .add(tenant_closure::Column::DescendantId.eq(descendant)),
            )
            .count(&conn)
            .await
            .map_err(map_scope_err)?;
        Ok(count > 0)
    }

    async fn find_root(&self, scope: &AccessScope) -> Result<Option<TenantModel>, AmError> {
        let conn = self.db.conn()?;
        let row = tenants::Entity::find()
            .secure()
            .scope_with(scope)
            .filter(
                Condition::all()
                    .add(tenants::Column::ParentId.is_null())
                    .add(tenants::Column::Status.ne(TenantStatus::Provisioning.as_smallint())),
            )
            .order_by(tenants::Column::CreatedAt, Order::Asc)
            .order_by(tenants::Column::Id, Order::Asc)
            .one(&conn)
            .await
            .map_err(map_scope_err)?;
        match row {
            Some(r) => Ok(Some(entity_to_model(r)?)),
            None => Ok(None),
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    // Most of the repo_impl logic is exercised through integration tests
    // against a real DB (Phase 3 owns cross-backend coverage). These unit
    // tests cover the pure helpers only.
    use super::*;

    #[test]
    fn entity_to_model_rejects_unknown_status() {
        let row = tenants::Model {
            id: Uuid::nil(),
            parent_id: None,
            name: "x".into(),
            status: 42,
            self_managed: false,
            tenant_type_uuid: Uuid::nil(),
            depth: 0,
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
            deleted_at: None,
            deletion_scheduled_at: None,
            retention_window_secs: None,
            claimed_by: None,
        };
        let err = entity_to_model(row).expect_err("unknown status");
        assert_eq!(err.sub_code(), "internal");
    }

    #[test]
    fn entity_to_model_rejects_negative_depth() {
        let row = tenants::Model {
            id: Uuid::nil(),
            parent_id: None,
            name: "x".into(),
            status: 1,
            self_managed: false,
            tenant_type_uuid: Uuid::nil(),
            depth: -1,
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
            deleted_at: None,
            deletion_scheduled_at: None,
            retention_window_secs: None,
            claimed_by: None,
        };
        let err = entity_to_model(row).expect_err("negative depth");
        assert_eq!(err.sub_code(), "internal");
    }

    /// Pin the SQLSTATE 40001 → `SerializationConflict` routing through
    /// `map_scope_err`. The previous implementation flattened
    /// `ScopeError::Db` directly into `AmError::Internal`, which made
    /// the `with_serializable_retry` loop unable to recognise the
    /// retry trigger — a SERIALIZABLE conflict surfaced through a
    /// `SecureORM` statement was silently demoted to HTTP 500 and never
    /// retried.
    #[test]
    fn map_scope_err_routes_sqlstate_40001_to_serialization_conflict() {
        use modkit_db::secure::ScopeError;
        use sea_orm::{DbErr, RuntimeErr};
        let scope_err = ScopeError::Db(DbErr::Exec(RuntimeErr::Internal(
            "error returned from database: 40001: could not serialize access".to_owned(),
        )));
        let am_err = map_scope_err(scope_err);
        assert_eq!(am_err.sub_code(), "serialization_conflict");
        assert!(matches!(am_err, AmError::SerializationConflict { .. }));
    }

    /// Same routing also catches unique-violation SQLSTATE values
    /// (`Postgres` `23505`, `SQLite` `2067`, `MySQL` `1062`) and maps them
    /// to `AmError::Conflict` (HTTP 409) per
    /// `feature-tenant-hierarchy-management §6` AC line 711. Without
    /// this, racing inserts that hit `ScopeError::Db` would surface
    /// as 500.
    #[test]
    fn map_scope_err_routes_unique_violation_to_conflict() {
        use modkit_db::secure::ScopeError;
        use sea_orm::{DbErr, RuntimeErr};
        let scope_err = ScopeError::Db(DbErr::Exec(RuntimeErr::Internal(
            "duplicate key value violates unique constraint".to_owned(),
        )));
        let am_err = map_scope_err(scope_err);
        assert_eq!(am_err.sub_code(), "conflict");
        assert_eq!(am_err.http_status(), 409);
    }

    /// `ScopeError::TenantNotInScope` MUST always map to
    /// `cross_tenant_denied` regardless of the routing change.
    #[test]
    fn map_scope_err_preserves_tenant_not_in_scope_routing() {
        use modkit_db::secure::ScopeError;
        let scope_err = ScopeError::TenantNotInScope {
            tenant_id: Uuid::nil(),
        };
        let am_err = map_scope_err(scope_err);
        assert_eq!(am_err.sub_code(), "cross_tenant_denied");
    }
}
