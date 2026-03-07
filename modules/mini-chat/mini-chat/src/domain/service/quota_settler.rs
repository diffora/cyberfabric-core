use async_trait::async_trait;
use modkit_db::secure::DbTx;
use modkit_security::AccessScope;

use crate::domain::error::DomainError;
use crate::domain::model::quota::{SettlementInput, SettlementOutcome};
use crate::domain::repos::QuotaUsageRepository;
use crate::domain::service::QuotaService;

/// Type-erased settlement interface for `FinalizationService`.
///
/// Erases the `QuotaService<QR>` generic so that `FinalizationService` is
/// non-generic and can be shared via `Arc` into spawned task closures
/// without propagating repository type parameters.
///
/// Takes `&DbTx` (transaction) rather than generic `&impl DBRunner` because
/// finalization always runs within a transaction. This avoids the `Sized`
/// constraint issue with `&dyn DBRunner`.
///
/// See design D2: "Generic erasure via `QuotaSettler` trait".
#[async_trait]
pub trait QuotaSettler: Send + Sync {
    async fn settle_in_tx(
        &self,
        tx: &DbTx<'_>,
        scope: &AccessScope,
        input: SettlementInput,
    ) -> Result<SettlementOutcome, DomainError>;
}

#[async_trait]
impl<QR: QuotaUsageRepository + 'static> QuotaSettler for QuotaService<QR> {
    async fn settle_in_tx(
        &self,
        tx: &DbTx<'_>,
        scope: &AccessScope,
        input: SettlementInput,
    ) -> Result<SettlementOutcome, DomainError> {
        // DbTx implements DBRunner, so we can pass it to the generic settle().
        self.settle(tx, scope, input).await
    }
}
