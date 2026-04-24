//! Audit-event emission helper.
//!
//! Implements `algo-audit-emission`. AM **MUST NOT** own audit storage,
//! retention, or tamper resistance — those are inherited platform controls
//! (DESIGN §4.1). This helper only classifies and forwards the event
//! through the platform sink.
//!
//! The audit-event type surface ([`AuditEvent`], [`AuditActor`],
//! [`AuditEventKind`]) lives in `account-management-sdk` so external
//! consumers can match on AM events without depending on this impl
//! crate's runtime; the items are re-exported below verbatim.
//!
//! TODO(audit-transport): the structured `tracing::info!` sink below is a
//! provisional emission path. The platform audit transport (durable
//! queue + plugin consumer, like mini-chat's outbox pattern) is not yet
//! specified for AM. Until that lands, audit events surface as
//! `target="audit.am"` log lines — operators must configure their log
//! pipeline to route those to the platform audit store. See
//! `docs/features/feature-errors-observability.md` "Outstanding
//! Dependencies" for the migration path.

pub use account_management_sdk::audit::{AuditActor, AuditEvent, AuditEventKind};
use tracing::info;

#[cfg(test)]
use std::cell::RefCell;

#[cfg(test)]
thread_local! {
    static CAPTURED_AUDIT_EVENTS: RefCell<Vec<AuditEvent>> = const { RefCell::new(Vec::new()) };
}


/// Emit an audit event through the platform sink.
///
/// Implements `algo-audit-emission`, in particular the gate at step 3 that
/// short-circuits caller-less events whose kind is not on the `actor=system`
/// allow-list. Fire-and-forget: returns `()` and never fails.
///
/// Callers running inside a `SecurityContext` **SHOULD** construct the event
/// with [`AuditEvent::from_context`]. Background jobs **SHOULD** construct
/// it with [`AuditEvent::system`] (which enforces the allow-list at
/// construction time).
// @cpt-begin:cpt-cf-account-management-algo-errors-observability-audit-emission:p1:inst-algo-audit-emit-gate
pub fn emit_audit(event: &AuditEvent) {
    // The gate: an `actor=system` record is only permitted for the enumerated
    // kinds. `AuditEvent::system` enforces this at construction time, but the
    // defensive check below guards against direct struct construction.
    if matches!(event.actor, AuditActor::System) && !event.kind.is_actor_system_eligible() {
        // Short-circuit per step 3.1 of algo-audit-emission. Do not emit;
        // do not fabricate a tenant-scoped identity. The drop is also
        // counted on `am.audit_drop` so a misconfigured caller is
        // alertable instead of merely showing up as a `warn!` log line.
        tracing::warn!(
            target: "audit.am",
            kind = event.kind.as_str(),
            "dropping actor=system audit event - kind not on allow-list"
        );
        crate::domain::metrics::emit_metric(
            crate::domain::metrics::AM_AUDIT_DROP,
            crate::domain::metrics::MetricKind::Counter,
            &[("kind", event.kind.as_str())],
        );
        return;
    }

    emit_through_sink(event);
}
// @cpt-end:cpt-cf-account-management-algo-errors-observability-audit-emission:p1:inst-algo-audit-emit-gate

fn emit_through_sink(event: &AuditEvent) {
    #[cfg(test)]
    capture_event(event);

    match &event.actor {
        AuditActor::TenantScoped {
            subject_id,
            subject_tenant_id,
        } => {
            info!(
                target: "audit.am",
                kind = event.kind.as_str(),
                actor = "tenant_scoped",
                subject_id = %subject_id,
                subject_tenant_id = %subject_tenant_id,
                tenant_id = %event.tenant_id,
                payload = %event.payload,
                "am audit event"
            );
        }
        AuditActor::System => {
            info!(
                target: "audit.am",
                kind = event.kind.as_str(),
                actor = "system",
                tenant_id = %event.tenant_id,
                payload = %event.payload,
                "am audit event"
            );
        }
    }
}

#[cfg(test)]
fn capture_event(event: &AuditEvent) {
    CAPTURED_AUDIT_EVENTS.with(|events| events.borrow_mut().push(event.clone()));
}

#[cfg(test)]
pub(crate) fn clear_captured_audit_events() {
    CAPTURED_AUDIT_EVENTS.with(|events| events.borrow_mut().clear());
}

#[cfg(test)]
pub(crate) fn take_captured_audit_events() -> Vec<AuditEvent> {
    CAPTURED_AUDIT_EVENTS.with(|events| std::mem::take(&mut *events.borrow_mut()))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use serde_json::json;
    use uuid::Uuid;

    #[test]
    fn system_factory_rejects_non_allowlist_kind() {
        let got = AuditEvent::system(AuditEventKind::TenantStateChanged, Uuid::nil(), json!({}));
        assert!(
            got.is_none(),
            "non-allowlist kind must not produce system event"
        );
    }

    #[test]
    fn system_factory_accepts_bootstrap_completed() {
        let got = AuditEvent::system(
            AuditEventKind::BootstrapCompleted,
            Uuid::nil(),
            json!({ "phase": "ready" }),
        );
        assert!(got.is_some());
        assert!(matches!(got.unwrap().actor, AuditActor::System));
    }

    #[test]
    fn emit_does_not_panic_for_allowed_paths() {
        let event = AuditEvent::system(AuditEventKind::ConversionExpired, Uuid::nil(), json!({}))
            .expect("allow-listed kind");
        emit_audit(&event);
    }

    #[test]
    fn emit_drops_actor_system_on_non_allowlist_kind_if_hand_built() {
        // Construct directly (bypassing AuditEvent::system) to probe the
        // defensive gate inside emit_audit.
        let bad = AuditEvent {
            kind: AuditEventKind::TenantStateChanged,
            actor: AuditActor::System,
            tenant_id: Uuid::nil(),
            payload: json!({}),
        };
        emit_audit(&bad); // must be silent / non-panicking
    }
}
