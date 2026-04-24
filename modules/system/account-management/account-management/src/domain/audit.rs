//! Audit-event emission helper.
//!
//! Implements `algo-audit-emission`. AM **MUST NOT** own audit storage,
//! retention, or tamper resistance — those are inherited platform controls
//! (DESIGN §4.1). This helper only classifies and forwards the event
//! through the platform sink.

// TODO(errors-observability): wire to the platform audit sink once ModKit
// exposes an audit-handle on `ModuleCtx`; until then the structured
// `tracing::info!` sink is scraped by the platform log-to-audit pipeline.

use modkit_macros::domain_model;
use modkit_security::SecurityContext;
use serde_json::Value;
use tracing::info;
use uuid::Uuid;

#[cfg(test)]
use std::cell::RefCell;

#[cfg(test)]
thread_local! {
    static CAPTURED_AUDIT_EVENTS: RefCell<Vec<AuditEvent>> = const { RefCell::new(Vec::new()) };
}

/// Actor attribution on an audit record.
///
/// Either a tenant-scoped caller (derived from [`SecurityContext`]) or the
/// reserved `system` actor used by AM-owned background transitions.
#[domain_model]
#[derive(Debug, Clone)]
pub enum AuditActor {
    /// Actor derived from a validated [`SecurityContext`]. Carries the
    /// subject and its home tenant.
    TenantScoped {
        subject_id: Uuid,
        subject_tenant_id: Uuid,
    },
    /// AM-owned background transition. Only events enumerated in
    /// [`AuditEventKind::is_actor_system_eligible`] may use this.
    System,
}

/// Kinds of AM audit events emitted by this module.
///
/// The variants listed in the FEATURE §3 algorithm `audit-emission` step 2
/// as "AM-owned background transitions" are the **only** ones permitted to
/// use [`AuditActor::System`]; all other kinds **MUST** carry a
/// [`AuditActor::TenantScoped`] actor or be dropped by the gate.
#[domain_model]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AuditEventKind {
    // ---- actor=system eligible (AM-owned background transitions) ----
    /// Root-tenant bootstrap completed successfully.
    BootstrapCompleted,
    /// Root-tenant bootstrap found a provisioning row and deferred cleanup
    /// to the provisioning reaper.
    BootstrapDeferredToReaper,
    /// Conversion request expired without resolution.
    ConversionExpired,
    /// Provisioning reaper compensated an orphaned provisioning.
    ProvisioningReaperCompensated,
    /// Hard-delete cleanup job finished sweeping a tenant's residue.
    HardDeleteCleanupCompleted,
    /// Tenant-deprovision cleanup job finished.
    TenantDeprovisionCompleted,

    // ---- tenant-scoped state-changing transitions ----
    /// Tenant create / status change / mode conversion / metadata write.
    TenantStateChanged,
    /// Conversion request status change driven by a tenant-scoped actor.
    ConversionStateChanged,
    /// Metadata entry written or deleted.
    MetadataWritten,
    /// Hard-delete initiated by a tenant-scoped actor.
    HardDeleteRequested,

    // ---- failure-trail events (per algo-audit-emission step 5) ----
    /// A `cross_tenant_denied` surfacing from the error surface flow.
    CrossTenantDenialRecorded,
    /// An `idp_unavailable` surfacing from the error surface flow.
    IdpUnavailableRecorded,
}

impl AuditEventKind {
    /// Whether this event kind may be emitted with [`AuditActor::System`].
    ///
    /// Matches the authoritative allow-list in `algo-audit-emission`
    /// step 2 — anything outside this set that reaches the gate without a
    /// `SecurityContext` is dropped.
    #[must_use]
    pub const fn is_actor_system_eligible(self) -> bool {
        matches!(
            self,
            Self::BootstrapCompleted
                | Self::BootstrapDeferredToReaper
                | Self::ConversionExpired
                | Self::ProvisioningReaperCompensated
                | Self::HardDeleteCleanupCompleted
                | Self::TenantDeprovisionCompleted
        )
    }

    /// Stable kind tag used on the `tracing` target and in the emitted
    /// payload. Must remain forward-compatible — renaming requires a
    /// contract-version review.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BootstrapCompleted => "bootstrap_completed",
            Self::BootstrapDeferredToReaper => "bootstrap_deferred_to_reaper",
            Self::ConversionExpired => "conversion_expired",
            Self::ProvisioningReaperCompensated => "provisioning_reaper_compensated",
            Self::HardDeleteCleanupCompleted => "hard_delete_cleanup_completed",
            Self::TenantDeprovisionCompleted => "tenant_deprovision_completed",
            Self::TenantStateChanged => "tenant_state_changed",
            Self::ConversionStateChanged => "conversion_state_changed",
            Self::MetadataWritten => "metadata_written",
            Self::HardDeleteRequested => "hard_delete_requested",
            Self::CrossTenantDenialRecorded => "cross_tenant_denial_recorded",
            Self::IdpUnavailableRecorded => "idp_unavailable_recorded",
        }
    }
}

/// A fully-prepared audit record waiting for the gate in [`emit_audit`].
// @cpt-begin:cpt-cf-account-management-dod-errors-observability-audit-contract:p1:inst-dod-audit-contract-event-shape
#[domain_model]
#[derive(Debug, Clone)]
pub struct AuditEvent {
    pub kind: AuditEventKind,
    pub actor: AuditActor,
    /// The tenant the event describes (not necessarily the actor's home
    /// tenant — e.g. a platform-admin operating on a child tenant).
    pub tenant_id: Uuid,
    /// Free-form structured payload (change diff, diagnostic, request id).
    pub payload: Value,
}
// @cpt-end:cpt-cf-account-management-dod-errors-observability-audit-contract:p1:inst-dod-audit-contract-event-shape

impl AuditEvent {
    /// Build a tenant-scoped event from a validated [`SecurityContext`].
    /// This is the happy-path constructor every AM feature will call.
    #[must_use]
    pub fn from_context(
        kind: AuditEventKind,
        ctx: &SecurityContext,
        tenant_id: Uuid,
        payload: Value,
    ) -> Self {
        Self {
            kind,
            actor: AuditActor::TenantScoped {
                subject_id: ctx.subject_id(),
                subject_tenant_id: ctx.subject_tenant_id(),
            },
            tenant_id,
            payload,
        }
    }

    /// Build an `actor=system` event for an AM-owned background transition.
    ///
    /// Returns `None` if `kind` is not on the allow-list — callers
    /// **MUST NOT** fabricate `actor=system` events for unauthorized kinds.
    #[must_use]
    pub fn system(kind: AuditEventKind, tenant_id: Uuid, payload: Value) -> Option<Self> {
        if !kind.is_actor_system_eligible() {
            return None;
        }
        Some(Self {
            kind,
            actor: AuditActor::System,
            tenant_id,
            payload,
        })
    }
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
