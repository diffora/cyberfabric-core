//! Account Management audit-event shapes.
//!
//! Carries the [`AuditEvent`] / [`AuditActor`] / [`AuditEventKind`]
//! types that the AM impl crate emits via `emit_audit`. External
//! consumers (e.g. an audit-bus plugin once the platform contract
//! lands) match on these types to route AM events without depending
//! on the impl runtime.
//!
use modkit_macros::domain_model;
use modkit_security::SecurityContext;
use serde_json::Value;
use uuid::Uuid;

/// Actor attribution on an audit record.
///
/// Either a tenant-scoped caller (derived from `SecurityContext` by
/// the impl-side helper) or the reserved `system` actor used by
/// AM-owned background transitions.
#[domain_model]
#[derive(Debug, Clone)]
pub enum AuditActor {
    /// Actor derived from a validated security context. Carries the
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

/// A fully-prepared audit record waiting for the gate in `emit_audit`.
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
