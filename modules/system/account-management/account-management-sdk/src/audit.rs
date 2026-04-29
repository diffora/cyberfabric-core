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
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

/// Actor attribution on an audit record.
///
/// Either a tenant-scoped caller (derived from `SecurityContext` by
/// the impl-side helper) or the reserved `system` actor used by
/// AM-owned background transitions.
///
/// Wire format is internally-tagged JSON with `camelCase` discriminant
/// and field names — e.g. `{"type":"system"}` /
/// `{"type":"tenantScoped","subjectId":"…","subjectTenantId":"…"}`.
#[domain_model]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
#[non_exhaustive]
pub enum AuditActor {
    /// Actor derived from a validated security context. Carries the
    /// subject and its home tenant.
    #[serde(rename_all = "camelCase")]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum AuditEventKind {
    // ---- actor=system eligible (AM-owned background transitions) ----
    /// Root-tenant bootstrap completed successfully.
    BootstrapCompleted,
    /// Root-tenant bootstrap detected a pre-existing active root and
    /// returned without re-running the saga.
    BootstrapSkipped,
    /// Root-tenant bootstrap found a `provisioning` row and deferred
    /// cleanup to the provisioning reaper.
    BootstrapDeferredToReaper,
    /// Bootstrap exceeded `idp_retry_timeout` while waiting for
    /// `IdpProviderPluginClient::check_availability` and aborted with
    /// `idp_unavailable`.
    BootstrapIdpTimeout,
    /// Bootstrap observed an illegal pre-existing root state
    /// (e.g. suspended or deleted root) and refused to proceed.
    BootstrapInvariantViolation,
    /// Bootstrap finalization step failed after a successful
    /// `provision_tenant`; the row was left in `provisioning` for the
    /// reaper to compensate.
    BootstrapFinalizationFailed,
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
                | Self::BootstrapSkipped
                | Self::BootstrapDeferredToReaper
                | Self::BootstrapIdpTimeout
                | Self::BootstrapInvariantViolation
                | Self::BootstrapFinalizationFailed
                | Self::ConversionExpired
                | Self::ProvisioningReaperCompensated
                | Self::HardDeleteCleanupCompleted
                | Self::TenantDeprovisionCompleted
        )
    }

    /// Stable kind tag used on the `tracing` target and in the emitted
    /// payload. Matches the `Serialize`/`Deserialize` representation of
    /// `Self` byte-for-byte; renaming requires a contract-version review.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BootstrapCompleted => "bootstrapCompleted",
            Self::BootstrapSkipped => "bootstrapSkipped",
            Self::BootstrapDeferredToReaper => "bootstrapDeferredToReaper",
            Self::BootstrapIdpTimeout => "bootstrapIdpTimeout",
            Self::BootstrapInvariantViolation => "bootstrapInvariantViolation",
            Self::BootstrapFinalizationFailed => "bootstrapFinalizationFailed",
            Self::ConversionExpired => "conversionExpired",
            Self::ProvisioningReaperCompensated => "provisioningReaperCompensated",
            Self::HardDeleteCleanupCompleted => "hardDeleteCleanupCompleted",
            Self::TenantDeprovisionCompleted => "tenantDeprovisionCompleted",
            Self::TenantStateChanged => "tenantStateChanged",
            Self::ConversionStateChanged => "conversionStateChanged",
            Self::MetadataWritten => "metadataWritten",
            Self::HardDeleteRequested => "hardDeleteRequested",
            Self::CrossTenantDenialRecorded => "crossTenantDenialRecorded",
            Self::IdpUnavailableRecorded => "idpUnavailableRecorded",
        }
    }
}

/// A fully-prepared audit record waiting for the gate in `emit_audit`.
///
/// Wire format is `camelCase` JSON, consistent with peer SDK conventions
/// (`resource-group-sdk`, `tenant-resolver-sdk`).
// @cpt-begin:cpt-cf-account-management-dod-errors-observability-audit-contract:p1:inst-dod-audit-contract-event-shape
#[domain_model]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
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
    /// # Errors
    ///
    /// Returns [`SystemActorNotEligible`] if `kind` is not on the
    /// allow-list — callers **MUST NOT** fabricate `actor=system`
    /// events for unauthorized kinds, and the failure must be loud
    /// rather than silently dropped.
    pub fn system(
        kind: AuditEventKind,
        tenant_id: Uuid,
        payload: Value,
    ) -> Result<Self, SystemActorNotEligible> {
        if !kind.is_actor_system_eligible() {
            return Err(SystemActorNotEligible { kind });
        }
        Ok(Self {
            kind,
            actor: AuditActor::System,
            tenant_id,
            payload,
        })
    }
}

/// Returned by [`AuditEvent::system`] when the requested kind is not on
/// the `actor=system` allow-list defined by
/// [`AuditEventKind::is_actor_system_eligible`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemActorNotEligible {
    pub kind: AuditEventKind,
}

impl std::fmt::Display for SystemActorNotEligible {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "audit event kind '{}' is not eligible for actor=system; \
             only AM-owned background transitions may use it",
            self.kind.as_str()
        )
    }
}

impl std::error::Error for SystemActorNotEligible {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Locks `AuditEventKind::as_str` to the serde wire form so the two
    /// representations cannot drift silently.
    #[test]
    fn audit_event_kind_as_str_matches_serde() {
        let all = [
            AuditEventKind::BootstrapCompleted,
            AuditEventKind::BootstrapSkipped,
            AuditEventKind::BootstrapDeferredToReaper,
            AuditEventKind::BootstrapIdpTimeout,
            AuditEventKind::BootstrapInvariantViolation,
            AuditEventKind::BootstrapFinalizationFailed,
            AuditEventKind::ConversionExpired,
            AuditEventKind::ProvisioningReaperCompensated,
            AuditEventKind::HardDeleteCleanupCompleted,
            AuditEventKind::TenantDeprovisionCompleted,
            AuditEventKind::TenantStateChanged,
            AuditEventKind::ConversionStateChanged,
            AuditEventKind::MetadataWritten,
            AuditEventKind::HardDeleteRequested,
            AuditEventKind::CrossTenantDenialRecorded,
            AuditEventKind::IdpUnavailableRecorded,
        ];
        for kind in all {
            let json = serde_json::to_string(&kind).expect("serialize");
            let unquoted = json.trim_matches('"');
            assert_eq!(unquoted, kind.as_str(), "drift on {kind:?}");
        }
    }

    #[test]
    fn audit_actor_serde_round_trip() {
        let cases = [
            AuditActor::System,
            AuditActor::TenantScoped {
                subject_id: Uuid::nil(),
                subject_tenant_id: Uuid::nil(),
            },
        ];
        for actor in cases {
            let json = serde_json::to_string(&actor).expect("serialize");
            let back: AuditActor = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(format!("{actor:?}"), format!("{back:?}"));
        }
    }

    #[test]
    fn audit_actor_tenant_scoped_wire_format() {
        let actor = AuditActor::TenantScoped {
            subject_id: Uuid::nil(),
            subject_tenant_id: Uuid::nil(),
        };
        let json = serde_json::to_value(&actor).expect("serialize");
        assert_eq!(json["type"], "tenantScoped");
        assert!(json.get("subjectId").is_some(), "expected camelCase field");
        assert!(json.get("subjectTenantId").is_some());
    }
}
