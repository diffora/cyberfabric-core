//! Pure helpers shared across the `SeaORM` repo split.
//!
//! Visibility: `pub(super)` — these helpers are private to the
//! `repo_impl` module tree (siblings: `reads`, `lifecycle`,
//! `updates`, `retention`).

use std::future::Future;
use std::pin::Pin;
use std::sync::LazyLock;
use std::time::Duration;

use modkit_db::secure::{DbTx, TxConfig};
use sea_orm::{ColumnTrait, Condition};
use uuid::Uuid;

use crate::domain::error::AmError;
use crate::domain::metrics::{AM_SERIALIZABLE_RETRY, MetricKind, emit_metric};
use crate::domain::tenant::model::{TenantModel, TenantStatus};
use crate::infra::storage::entity::tenants;

use super::AmDbProvider;

pub(super) fn map_scope_err(err: modkit_db::secure::ScopeError) -> AmError {
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
            cause: None,
        },
        ScopeError::TenantNotInScope { .. } => AmError::CrossTenantDenied { cause: None },
        ScopeError::Denied(msg) => AmError::Internal {
            diagnostic: format!("unexpected access denied in AM repo: {msg}"),
            cause: None,
        },
    }
}

pub(super) fn entity_to_model(row: tenants::Model) -> Result<TenantModel, AmError> {
    let status = TenantStatus::from_smallint(row.status).ok_or_else(|| AmError::Internal {
        diagnostic: format!("tenants.status out-of-domain value: {}", row.status),
        cause: None,
    })?;
    let depth = u32::try_from(row.depth).map_err(|_| AmError::Internal {
        diagnostic: format!("tenants.depth negative: {}", row.depth),
        cause: None,
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
pub(super) fn id_eq(id: Uuid) -> Condition {
    Condition::all().add(tenants::Column::Id.eq(id))
}

static GTS_NAMESPACE: LazyLock<Uuid> = LazyLock::new(|| Uuid::new_v5(&Uuid::NAMESPACE_URL, b"gts"));

pub(super) fn schema_uuid_from_gts_id(gts_id: &str) -> Uuid {
    Uuid::new_v5(&GTS_NAMESPACE, gts_id.as_bytes())
}

/// Maximum number of attempts for a SERIALIZABLE transaction before the
/// retry helper gives up and returns the underlying error to the caller.
const MAX_SERIALIZABLE_ATTEMPTS: u32 = 5;

/// TTL after which a hard-delete scan claim is considered stale and may
/// be stolen by another worker. Bounds the worst-case stuck-row latency
/// when [`crate::domain::tenant::repo::TenantRepo::clear_retention_claim`]
/// fails after a non-Cleaned outcome (network blip, pool exhaustion):
/// without this, the row would be permanently invisible to future scans
/// because `claimed_by` would never return to NULL. A `Deleted` row's
/// `updated_at` is frozen by `schedule_deletion` and only touched by the
/// scan UPDATE below, so it is a reliable claim-age marker for retention
/// rows.
// `from_mins` is unstable on the workspace MSRV; keep `from_secs` form.
#[allow(clippy::duration_suboptimal_units)]
pub(super) const RETENTION_CLAIM_TTL: Duration = Duration::from_secs(600);

/// Run a SERIALIZABLE transaction with bounded retry on serialization
/// failure.
///
/// SERIALIZABLE isolation can produce SQLSTATE `40001` whenever the
/// engine detects a read/write dependency cycle. These errors are
/// always safe to retry. The retry trigger is the typed
/// [`AmError::SerializationConflict`] variant routed by
/// `From<DbError>` in [`crate::infra::error_conv`]; underneath it
/// uses `modkit_db::contention::is_retryable_contention(backend, &DbErr)`
/// (probed for both AM-supported backends) so detection stays in sync
/// with the workspace primitive.
///
/// Retries up to [`MAX_SERIALIZABLE_ATTEMPTS`] times with exponential
/// 1-2-4-8 ms backoff. On exhaustion the final `SerializationConflict`
/// propagates to the caller; it sits in the [`AmError`] `Conflict`
/// category (HTTP 409) with `code = serialization_conflict` per
/// `domain/error.rs` — losing concurrent mutators receive a
/// deterministic `conflict` envelope per
/// `feature-tenant-hierarchy-management §6 / AC line 711`, not a 500.
///
/// The closure may be invoked multiple times — it must be idempotent.
/// All AM mutating transactions in this file are written so that
/// re-execution from a clean transaction state produces the same end
/// state (re-read row, re-check status, re-issue the same updates).
// @cpt-begin:cpt-cf-account-management-dod-tenant-hierarchy-management-concurrency-serializability:p1:inst-dod-concurrency-serializable-retry
pub(super) async fn with_serializable_retry<F, T>(db: &AmDbProvider, op: F) -> Result<T, AmError>
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

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    // Most of the repo_impl logic is exercised through integration tests
    // against a real DB (Phase 3 owns cross-backend coverage). These unit
    // tests cover the pure helpers only.
    use super::*;
    use time::OffsetDateTime;

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
            claimed_at: None,
        };
        let err = entity_to_model(row).expect_err("unknown status");
        assert_eq!(err.code(), "internal");
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
            claimed_at: None,
        };
        let err = entity_to_model(row).expect_err("negative depth");
        assert_eq!(err.code(), "internal");
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
        assert_eq!(am_err.code(), "serialization_conflict");
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
        assert_eq!(am_err.code(), "conflict");
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
        assert_eq!(am_err.code(), "cross_tenant_denied");
    }
}
