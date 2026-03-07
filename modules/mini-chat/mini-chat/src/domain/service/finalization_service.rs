use std::sync::Arc;

use modkit_macros::domain_model;
use tracing::{debug, error, warn};

use crate::domain::error::DomainError;
use crate::domain::model::billing_outcome::{
    BillingDerivation, BillingDerivationInput, BillingOutcome, derive_billing_outcome,
};
use crate::domain::model::finalization::{
    FinalizationInput, FinalizationOutcome, has_known_usage, settlement_path_from_billing,
};
use crate::domain::model::quota::SettlementInput;
use crate::domain::repos::{
    CasTerminalParams, InsertAssistantMessageParams, MessageRepository, TurnRepository,
};
use crate::domain::service::quota_settler::QuotaSettler;
use crate::infra::db::entity::chat_turn::TurnState;

use super::DbProvider;

fn to_db(e: DomainError) -> modkit_db::DbError {
    modkit_db::DbError::Other(anyhow::anyhow!(e))
}

/// Service encapsulating the atomic finalization transaction.
///
/// Generic over `TR` and `MR` (repository traits are not dyn-compatible
/// due to `&impl DBRunner` methods). The `QuotaService<QR>` generic is
/// erased via the `QuotaSettler` trait (see D2).
///
/// Created once in `AppServices::new()` and shared with spawned tasks
/// via `Arc<FinalizationService<TR, MR>>`.
#[domain_model]
pub struct FinalizationService<TR: TurnRepository + 'static, MR: MessageRepository + 'static> {
    db: Arc<DbProvider>,
    turn_repo: Arc<TR>,
    message_repo: Arc<MR>,
    quota_settler: Arc<dyn QuotaSettler>,
    // TODO(P4): add Arc<dyn OutboxEnqueuer> once UsageEvent type is real (task 6.1)
}

impl<TR: TurnRepository + 'static, MR: MessageRepository + 'static> FinalizationService<TR, MR> {
    pub(crate) fn new(
        db: Arc<DbProvider>,
        turn_repo: Arc<TR>,
        message_repo: Arc<MR>,
        quota_settler: Arc<dyn QuotaSettler>,
    ) -> Self {
        Self {
            db,
            turn_repo,
            message_repo,
            quota_settler,
        }
    }

    /// Single universal finalization function for all terminal paths.
    ///
    /// Executes CAS guard + billing derivation + quota settlement +
    /// message persistence + outbox enqueue in one atomic DB transaction.
    ///
    /// Returns `FinalizationOutcome { won_cas: false, .. }` if another
    /// finalizer already committed (CAS loser — no-op).
    ///
    /// If message persistence fails on a completed turn, rolls back and
    /// retries as `Failed` with `error_code = "message_persistence_failed"`
    /// (content durability invariant, DESIGN.md §5.7).
    pub(crate) async fn finalize_turn_cas(
        &self,
        input: FinalizationInput,
    ) -> Result<FinalizationOutcome, DomainError> {
        let result = self.try_finalize(&input).await;

        match result {
            Ok(outcome) => {
                // Emit side effects after transaction commit.
                if let Some(billing) = outcome.billing_outcome {
                    Self::emit_post_commit_side_effects(&input, billing);
                }
                Ok(outcome)
            }
            Err(FinalizationError::MessagePersistenceFailed(e)) => {
                // Content durability invariant: downgrade completed → failed.
                // The transaction rolled back, so the turn is still 'running'.
                // Retry with Failed state.
                error!(
                    error = %e,
                    turn_id = %input.turn_id,
                    "message persistence failed, downgrading completed to failed"
                );
                let mut retry_input = input;
                retry_input.terminal_state = TurnState::Failed;
                retry_input.error_code = Some("message_persistence_failed".to_owned());
                let retry_outcome =
                    self.try_finalize(&retry_input)
                        .await
                        .map_err(|fe| match fe {
                            FinalizationError::Domain(de) => de,
                            FinalizationError::MessagePersistenceFailed(e2) => {
                                // Should not happen on Failed path (no message INSERT).
                                DomainError::internal(format!("unexpected retry failure: {e2}"))
                            }
                        })?;
                if let Some(billing) = retry_outcome.billing_outcome {
                    Self::emit_post_commit_side_effects(&retry_input, billing);
                }
                Ok(retry_outcome)
            }
            Err(FinalizationError::Domain(e)) => Err(e),
        }
    }

    /// Core finalization logic inside a transaction.
    async fn try_finalize(
        &self,
        input: &FinalizationInput,
    ) -> Result<FinalizationOutcome, FinalizationError> {
        let turn_repo = Arc::clone(&self.turn_repo);
        let message_repo = Arc::clone(&self.message_repo);
        let quota_settler = Arc::clone(&self.quota_settler);
        let input = input.clone();

        let tx_result = self
            .db
            .transaction(|tx| {
                Box::pin(async move {
                    let scope = input.scope.clone();

                    // 1. CAS guard — state transition only.
                    //    assistant_message_id and provider_response_id are set
                    //    AFTER the message INSERT (step 4) to avoid FK violation
                    //    (assistant_message_id REFERENCES messages(id)).
                    let rows = turn_repo
                        .cas_update_state(
                            tx,
                            &scope,
                            CasTerminalParams {
                                turn_id: input.turn_id,
                                state: input.terminal_state.clone(),
                                error_code: input.error_code.clone(),
                                error_detail: input.error_detail.clone(),
                                assistant_message_id: None,
                                provider_response_id: input.provider_response_id.clone(),
                            },
                        )
                        .await
                        .map_err(to_db)?;

                    if rows == 0 {
                        debug!(turn_id = %input.turn_id, "CAS loser: another finalizer won");
                        return Ok(FinalizationOutcome {
                            won_cas: false,
                            billing_outcome: None,
                            settlement_outcome: None,
                        });
                    }

                    // 2. Derive billing outcome (pure function, no DB)
                    let billing = derive_billing_outcome(&BillingDerivationInput {
                        terminal_state: input.terminal_state.clone(),
                        error_code: input.error_code.clone(),
                        has_usage: has_known_usage(input.usage),
                    });

                    // 3. Build SettlementInput and settle quota
                    let settlement_path =
                        settlement_path_from_billing(billing.settlement_method, input.usage);
                    let settlement_input = SettlementInput {
                        tenant_id: input.tenant_id,
                        user_id: input.user_id,
                        effective_model: input.effective_model.clone(),
                        policy_version_applied: input.policy_version_applied,
                        reserve_tokens: input.reserve_tokens,
                        max_output_tokens_applied: input.max_output_tokens_applied,
                        reserved_credits_micro: input.reserved_credits_micro,
                        minimal_generation_floor_applied: input.minimal_generation_floor_applied,
                        settlement_path,
                        period_starts: input.period_starts.clone(),
                    };
                    let settlement_outcome = quota_settler
                        .settle_in_tx(tx, &scope, settlement_input)
                        .await
                        .map_err(to_db)?;

                    // 4. Persist assistant message (completed turns only)
                    //    Content durability invariant (DESIGN.md §5.7):
                    //    "completed ⟹ full assistant content is durably persisted"
                    if input.terminal_state == TurnState::Completed {
                        message_repo
                            .insert_assistant_message(
                                tx,
                                &scope,
                                InsertAssistantMessageParams {
                                    id: input.message_id,
                                    tenant_id: input.tenant_id,
                                    chat_id: input.chat_id,
                                    request_id: input.request_id,
                                    content: input.accumulated_text.clone(),
                                    input_tokens: input.usage.map(|u| u.input_tokens),
                                    output_tokens: input.usage.map(|u| u.output_tokens),
                                    model: Some(input.effective_model.clone()),
                                    provider_response_id: input.provider_response_id.clone(),
                                },
                            )
                            .await
                            .map_err(|e| {
                                // Signal message persistence failure for retry logic.
                                modkit_db::DbError::Other(anyhow::anyhow!("MSG_PERSIST_FAILED:{e}"))
                            })?;

                        // 4b. Link assistant_message_id on the turn row.
                        //     Done as a separate UPDATE (not in the CAS step) because
                        //     assistant_message_id has a FK to messages(id), so the
                        //     message row must exist first.
                        turn_repo
                            .set_assistant_message_id(tx, &scope, input.turn_id, input.message_id)
                            .await
                            .map_err(to_db)?;
                    }

                    // 5. Enqueue outbox event via domain trait
                    // TODO(P4): enqueue UsageEvent once real type exists (task 6.1)
                    // let event = build_usage_event(&input, &billing, &settlement_outcome);
                    // outbox_enqueuer.enqueue_usage_event(tx, event).await.map_err(to_db)?;

                    // 6. Return outcome
                    Ok(FinalizationOutcome {
                        won_cas: true,
                        billing_outcome: Some(billing),
                        settlement_outcome: Some(settlement_outcome),
                    })
                })
            })
            .await;

        match tx_result {
            Ok(outcome) => Ok(outcome),
            Err(e) => {
                // Check if this was a message persistence failure (sentinel).
                let err_str = e.to_string();
                if err_str.contains("MSG_PERSIST_FAILED:") {
                    let inner = err_str
                        .strip_prefix("MSG_PERSIST_FAILED:")
                        .unwrap_or(&err_str);
                    Err(FinalizationError::MessagePersistenceFailed(
                        inner.to_owned(),
                    ))
                } else {
                    Err(FinalizationError::Domain(DomainError::from(e)))
                }
            }
        }
    }

    /// Emit metrics and logs after the transaction commits.
    /// These MUST NOT run inside the transaction.
    fn emit_post_commit_side_effects(input: &FinalizationInput, billing: BillingDerivation) {
        // Unknown error code → critical log + metric
        if billing.unknown_error_code {
            error!(
                error_code = ?input.error_code,
                turn_id = %input.turn_id,
                "CRITICAL: unknown error code in billing derivation"
            );
            // TODO(P4): increment mini_chat_unknown_error_code_total{code} (task 8.4)
        }

        // Aborted billing outcome → streams_aborted metric
        if billing.outcome == BillingOutcome::Aborted {
            let trigger = match input.error_code.as_deref() {
                Some("orphan_timeout") => "orphan_timeout",
                _ if input.terminal_state == TurnState::Cancelled => "client_disconnect",
                _ => "internal_abort",
            };
            warn!(
                turn_id = %input.turn_id,
                trigger = trigger,
                "stream aborted"
            );
            // TODO(P4): increment mini_chat_streams_aborted_total{trigger} (task 8.3)
        }
    }
}

/// Internal error type to distinguish message persistence failure
/// from other domain errors, enabling the retry-as-failed logic.
#[domain_model]
enum FinalizationError {
    Domain(DomainError),
    MessagePersistenceFailed(String),
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::domain::model::finalization::FinalizationInput;
    use crate::domain::model::quota::{SettlementMethod, SettlementOutcome};
    use crate::domain::repos::{CreateTurnParams, TurnRepository as TurnRepoTrait};
    use crate::domain::service::test_helpers::{inmem_db, mock_db_provider};
    use crate::infra::db::entity::chat_turn::TurnState;
    use crate::infra::db::entity::quota_usage::PeriodType;
    use crate::infra::db::repo::message_repo::MessageRepository as MsgRepo;
    use crate::infra::db::repo::turn_repo::TurnRepository as TurnRepo;
    use crate::infra::llm::Usage;
    use modkit_security::AccessScope;
    use uuid::Uuid;

    // ── Mock QuotaSettler ──

    #[domain_model]
    struct MockQuotaSettler;

    #[async_trait::async_trait]
    impl QuotaSettler for MockQuotaSettler {
        async fn settle_in_tx(
            &self,
            _tx: &modkit_db::secure::DbTx<'_>,
            _scope: &AccessScope,
            _input: crate::domain::model::quota::SettlementInput,
        ) -> Result<SettlementOutcome, DomainError> {
            Ok(SettlementOutcome {
                settlement_method: SettlementMethod::Actual,
                actual_credits_micro: 500,
                charged_tokens: 15,
                overshoot_capped: false,
            })
        }
    }

    fn build_finalization_service(db: Arc<DbProvider>) -> FinalizationService<TurnRepo, MsgRepo> {
        FinalizationService::new(
            db,
            Arc::new(TurnRepo),
            Arc::new(MsgRepo::new(modkit_db::odata::LimitCfg {
                default: 20,
                max: 100,
            })),
            Arc::new(MockQuotaSettler),
        )
    }

    /// Insert a parent chat row (FK constraint).
    async fn insert_test_chat(db: &Arc<DbProvider>, tenant_id: Uuid, chat_id: Uuid, user_id: Uuid) {
        use crate::infra::db::entity::chat::{ActiveModel, Entity as ChatEntity};
        use modkit_db::secure::secure_insert;
        use sea_orm::Set;
        use time::OffsetDateTime;

        let now = OffsetDateTime::now_utc();
        let am = ActiveModel {
            id: Set(chat_id),
            tenant_id: Set(tenant_id),
            user_id: Set(user_id),
            model: Set("gpt-5.2".to_owned()),
            title: Set(Some("test".to_owned())),
            is_temporary: Set(false),
            created_at: Set(now),
            updated_at: Set(now),
            deleted_at: Set(None),
        };
        let conn = db.conn().unwrap();
        secure_insert::<ChatEntity>(am, &AccessScope::allow_all(), &conn)
            .await
            .expect("insert chat");
    }

    /// Insert a turn in `running` state.
    async fn insert_running_turn(
        db: &Arc<DbProvider>,
        tenant_id: Uuid,
        chat_id: Uuid,
        turn_id: Uuid,
        request_id: Uuid,
    ) {
        let conn = db.conn().unwrap();
        let scope = AccessScope::allow_all();
        let turn_repo = TurnRepo;
        turn_repo
            .create_turn(
                &conn,
                &scope,
                CreateTurnParams {
                    id: turn_id,
                    tenant_id,
                    chat_id,
                    request_id,
                    requester_type: "user".to_owned(),
                    requester_user_id: None,
                    reserve_tokens: Some(100),
                    max_output_tokens_applied: Some(4096),
                    reserved_credits_micro: Some(1000),
                    policy_version_applied: Some(1),
                    effective_model: Some("gpt-5.2".to_owned()),
                    minimal_generation_floor_applied: Some(10),
                },
            )
            .await
            .expect("create turn");
    }

    fn make_input(
        tenant_id: Uuid,
        chat_id: Uuid,
        turn_id: Uuid,
        request_id: Uuid,
        user_id: Uuid,
        terminal_state: TurnState,
    ) -> FinalizationInput {
        let today = time::OffsetDateTime::now_utc().date();
        let month_start = today.replace_day(1).unwrap();
        FinalizationInput {
            turn_id,
            tenant_id,
            chat_id,
            request_id,
            user_id,
            scope: AccessScope::allow_all(),
            message_id: Uuid::new_v4(),
            terminal_state,
            error_code: None,
            error_detail: None,
            accumulated_text: "Hello, world!".to_owned(),
            usage: Some(Usage {
                input_tokens: 10,
                output_tokens: 5,
            }),
            provider_response_id: Some("resp-123".to_owned()),
            effective_model: "gpt-5.2".to_owned(),
            selected_model: "gpt-5.2".to_owned(),
            reserve_tokens: 100,
            max_output_tokens_applied: 4096,
            reserved_credits_micro: 1000,
            policy_version_applied: 1,
            minimal_generation_floor_applied: 10,
            quota_decision: "allow".to_owned(),
            downgrade_from: None,
            downgrade_reason: None,
            period_starts: vec![
                (PeriodType::Daily, today),
                (PeriodType::Monthly, month_start),
            ],
        }
    }

    // ── 3.6: CAS winner executes full atomic finalization ──

    #[tokio::test]
    async fn cas_winner_completes_finalization() {
        let db = mock_db_provider(inmem_db().await);
        let svc = build_finalization_service(Arc::clone(&db));

        let tenant_id = Uuid::new_v4();
        let chat_id = Uuid::new_v4();
        let turn_id = Uuid::new_v4();
        let request_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();

        insert_test_chat(&db, tenant_id, chat_id, user_id).await;
        insert_running_turn(&db, tenant_id, chat_id, turn_id, request_id).await;

        let input = make_input(
            tenant_id,
            chat_id,
            turn_id,
            request_id,
            user_id,
            TurnState::Completed,
        );
        let outcome = svc
            .finalize_turn_cas(input)
            .await
            .expect("finalization should succeed");

        assert!(outcome.won_cas, "should be CAS winner");
        assert!(outcome.billing_outcome.is_some());
        assert!(outcome.settlement_outcome.is_some());

        // Verify turn is now in completed state
        let conn = db.conn().unwrap();
        let scope = AccessScope::allow_all();
        let turn_repo = TurnRepo;
        let turn = turn_repo
            .find_by_chat_and_request_id(&conn, &scope, chat_id, request_id)
            .await
            .expect("find turn")
            .expect("turn should exist");
        assert_eq!(turn.state, TurnState::Completed);
    }

    // ── 3.7: CAS loser returns won_cas = false ──

    #[tokio::test]
    async fn cas_loser_returns_no_side_effects() {
        let db = mock_db_provider(inmem_db().await);
        let svc = build_finalization_service(Arc::clone(&db));

        let tenant_id = Uuid::new_v4();
        let chat_id = Uuid::new_v4();
        let turn_id = Uuid::new_v4();
        let request_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();

        insert_test_chat(&db, tenant_id, chat_id, user_id).await;
        insert_running_turn(&db, tenant_id, chat_id, turn_id, request_id).await;

        // First finalization — wins CAS
        let input = make_input(
            tenant_id,
            chat_id,
            turn_id,
            request_id,
            user_id,
            TurnState::Completed,
        );
        let outcome1 = svc
            .finalize_turn_cas(input)
            .await
            .expect("first finalization");
        assert!(outcome1.won_cas);

        // Second finalization — loses CAS (turn already completed)
        let input2 = make_input(
            tenant_id,
            chat_id,
            turn_id,
            request_id,
            user_id,
            TurnState::Failed,
        );
        let outcome2 = svc
            .finalize_turn_cas(input2)
            .await
            .expect("second finalization");
        assert!(!outcome2.won_cas, "second finalizer should lose CAS");
        assert!(outcome2.billing_outcome.is_none());
        assert!(outcome2.settlement_outcome.is_none());
    }

    // ── 3.8: Transaction rollback on failure leaves turn in running state ──

    #[tokio::test]
    async fn failed_settlement_leaves_turn_running() {
        // Use a QuotaSettler that always fails
        #[domain_model]
        struct FailingQuotaSettler;

        #[async_trait::async_trait]
        impl QuotaSettler for FailingQuotaSettler {
            async fn settle_in_tx(
                &self,
                _tx: &modkit_db::secure::DbTx<'_>,
                _scope: &AccessScope,
                _input: crate::domain::model::quota::SettlementInput,
            ) -> Result<SettlementOutcome, DomainError> {
                Err(DomainError::internal("settlement exploded"))
            }
        }

        let db = mock_db_provider(inmem_db().await);
        let svc = FinalizationService::new(
            Arc::clone(&db),
            Arc::new(TurnRepo),
            Arc::new(MsgRepo::new(modkit_db::odata::LimitCfg {
                default: 20,
                max: 100,
            })),
            Arc::new(FailingQuotaSettler),
        );

        let tenant_id = Uuid::new_v4();
        let chat_id = Uuid::new_v4();
        let turn_id = Uuid::new_v4();
        let request_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();

        insert_test_chat(&db, tenant_id, chat_id, user_id).await;
        insert_running_turn(&db, tenant_id, chat_id, turn_id, request_id).await;

        let input = make_input(
            tenant_id,
            chat_id,
            turn_id,
            request_id,
            user_id,
            TurnState::Completed,
        );
        let result = svc.finalize_turn_cas(input).await;

        // Should fail due to settlement error
        assert!(
            result.is_err(),
            "finalization should fail when settlement fails"
        );

        // Verify turn is still running (transaction rolled back)
        let conn = db.conn().unwrap();
        let scope = AccessScope::allow_all();
        let turn_repo = TurnRepo;
        let running = turn_repo
            .find_running_by_chat_id(&conn, &scope, chat_id)
            .await
            .expect("find running turn")
            .expect("turn should still be running");
        assert_eq!(running.id, turn_id);
        assert_eq!(running.state, TurnState::Running);
    }
}
