//! Service implementation for the TR `AuthZ` resolver plugin.
//!
//! Implements the 8 access-check rules (R1–R8) from the tenant-based access
//! algorithm: each evaluation maps to exactly one rule, depending on three
//! axes read from the request:
//!
//! - **single-resource vs list** — decided by `resource.id`.
//!   `Some(_)` → single (GET/UPDATE/DELETE); `None` → list/create.
//! - **explicit target tenant** — `context.tenant_context.root_id`
//!   (`Some` / `None`).
//! - **scope mode** — `context.tenant_context.mode`
//!   (`RootOnly` / `Subtree`; default `Subtree`).
//!
//! See `docs/arch/authorization/AUTHZ_USAGE_SCENARIOS.md` for the full matrix
//! and per-rule HTTP examples.

use std::sync::Arc;

use authz_resolver_sdk::{
    BarrierMode as AuthzBarrierMode, Constraint, EvaluationRequest, EvaluationResponse,
    EvaluationResponseContext, InGroupPredicate, InGroupSubtreePredicate, InPredicate, Predicate,
    TenantMode,
};
use modkit_security::{SecurityContext, pep_properties};
use tenant_resolver_sdk::{
    BarrierMode, GetDescendantsOptions, IsAncestorOptions, TenantId, TenantResolverClient,
    TenantResolverError, TenantStatus,
};
use tracing::{debug, info, warn};
use uuid::Uuid;

/// TR-based `AuthZ` resolver service.
///
/// Resolves tenant hierarchy via `TenantResolverClient`.
#[modkit_macros::domain_model]
pub struct Service {
    tr: Arc<dyn TenantResolverClient>,
}

impl Service {
    pub fn new(tr: Arc<dyn TenantResolverClient>) -> Self {
        Self { tr }
    }

    /// Evaluate an authorization request.
    ///
    /// Branches the request into one of 8 rules (R1–R8) by
    /// `resource.id.is_some()` × `tenant_context.root_id.is_some()` × `mode`.
    /// On any failed access check, resolver call failure, or missing required
    /// field — returns `deny` (fail-closed).
    #[allow(clippy::cognitive_complexity)]
    pub async fn evaluate(&self, request: &EvaluationRequest) -> EvaluationResponse {
        info!(
            action = %request.action.name,
            resource_type = %request.resource.resource_type,
            "tr-authz: evaluate called"
        );

        // Subject tenant is required in every rule (R3/R4/R7/R8 use it directly;
        // R1/R2/R5/R6 use it inside `is_in_subtree`).
        let Some(subject_tid) = Self::read_uuid(&request.subject.properties, "tenant_id") else {
            warn!("tr-authz: subject tenant_id missing or unparseable -- deny");
            return Self::deny();
        };
        if subject_tid == Uuid::nil() {
            warn!("tr-authz: subject tenant_id is nil -- deny");
            return Self::deny();
        }

        let tc = request.context.tenant_context.as_ref();
        let root_id = tc.and_then(|t| t.root_id);
        let mode = tc.map(|t| t.mode.clone()).unwrap_or_default();
        let barrier_mode =
            Self::tr_barrier_mode(tc.map_or(AuthzBarrierMode::default(), |t| t.barrier_mode));

        // Parse caller-supplied tenant_status filter once, up-front. Any
        // unknown status string fails closed (deny) — silently dropping it
        // would widen the visible-subtree set in R6/R8.
        let tenant_statuses = match tc.and_then(|t| t.tenant_status.as_deref()) {
            None => Vec::new(),
            Some(strs) => match Self::parse_tenant_statuses(strs) {
                Ok(v) => v,
                Err(bad) => {
                    warn!(%bad, "tr-authz: unknown tenant_status value -- deny");
                    return Self::deny();
                }
            },
        };

        // tr-authz is a trusted plugin by design and MUST NOT propagate caller
        // scope into TR calls: the access-check rules (R1/R2/R5/R6) walk from
        // `subject` toward `root_id`, which routinely lies outside the caller's
        // visibility — a scope-limited view would hide legitimate ancestors and
        // yield wrong allow/deny decisions. The plugin must keep its full-tree
        // visibility either way.
        //
        // EXTRACTION BLOCKER — resolve issue #1597 before moving this plugin
        // out of the modkit in-process trust boundary. `SecurityContext::anonymous()`
        // is safe only when the TR client is an in-process implementation
        // (no network hop, no mTLS). Extracting this plugin to a separate
        // service without replacing the anonymous context with a valid S2S
        // service identity would allow any caller to impersonate this plugin
        // over the wire.
        //
        // TODO(https://github.com/cyberfabric/cyberfabric-core/issues/1597):
        // once the platform S2S authentication subsystem and the gRPC + mTLS
        // transport land, replace `SecurityContext::anonymous()` here with the
        // S2S-issued service context identifying this caller as `tr-authz-plugin`.
        let ctx = SecurityContext::anonymous();

        let mut response = if request.resource.id.is_some() {
            // Single-resource: owner_tenant_id is mandatory (PEP must prefetch it).
            let Some(owner_tid) = Self::read_uuid(
                &request.resource.properties,
                pep_properties::OWNER_TENANT_ID,
            ) else {
                warn!(
                    "tr-authz: single-resource request missing owner_tenant_id in properties -- deny"
                );
                return Self::deny();
            };
            self.evaluate_single(&ctx, subject_tid, owner_tid, root_id, &mode, barrier_mode)
                .await
        } else {
            self.evaluate_list(
                &ctx,
                subject_tid,
                root_id,
                &mode,
                barrier_mode,
                &tenant_statuses,
            )
            .await
        };

        // Group predicates are orthogonal to tenant scoping — append only on
        // allow. If the group property is present but any of its UUIDs are
        // malformed, the group predicate cannot be compiled; fail-closed to
        // avoid silently widening scope to tenant-wide access.
        if response.decision
            && Self::append_group_predicates(&mut response, &request.resource.properties).is_err()
        {
            warn!("tr-authz: malformed group scoping properties -- deny");
            return Self::deny();
        }

        response
    }

    // ── Single-resource branches (R1–R4) ──────────────────────────────────

    #[allow(clippy::cognitive_complexity)]
    async fn evaluate_single(
        &self,
        ctx: &SecurityContext,
        subject: Uuid,
        owner: Uuid,
        root_id: Option<Uuid>,
        mode: &TenantMode,
        barrier_mode: BarrierMode,
    ) -> EvaluationResponse {
        match (root_id, mode) {
            (Some(root), TenantMode::RootOnly) => {
                // R1: GET /tasks/{id}?tenant=t2&tenant_mode=root_only
                if owner != root {
                    warn!(%owner, %root, "R1: owner_tenant_id != root_id -- deny");
                    return Self::deny();
                }
                if !self.is_in_subtree(ctx, subject, root, barrier_mode).await {
                    warn!(%subject, %root, "R1: subject is not an ancestor of root_id -- deny");
                    return Self::deny();
                }
                debug!(rule = "R1", %owner, "tr-authz: allow");
                Self::allow_eq(owner)
            }
            (Some(root), TenantMode::Subtree) => {
                // R2: GET /tasks/{id}?tenant=t2
                if !self.is_in_subtree(ctx, root, owner, barrier_mode).await {
                    warn!(%owner, %root, "R2: owner is not in root_id subtree -- deny");
                    return Self::deny();
                }
                if !self.is_in_subtree(ctx, subject, root, barrier_mode).await {
                    warn!(%subject, %root, "R2: subject is not an ancestor of root_id -- deny");
                    return Self::deny();
                }
                debug!(rule = "R2", %owner, "tr-authz: allow");
                Self::allow_eq(owner)
            }
            (None, TenantMode::RootOnly) => {
                // R3: GET /tasks/{id}?tenant_mode=root_only
                if owner != subject {
                    warn!(%owner, %subject, "R3: owner_tenant_id != subject tenant -- deny");
                    return Self::deny();
                }
                debug!(rule = "R3", %owner, "tr-authz: allow");
                Self::allow_eq(owner)
            }
            (None, TenantMode::Subtree) => {
                // R4: GET /tasks/{id}
                if !self.is_in_subtree(ctx, subject, owner, barrier_mode).await {
                    warn!(%owner, %subject, "R4: owner is not in subject subtree -- deny");
                    return Self::deny();
                }
                debug!(rule = "R4", %owner, "tr-authz: allow");
                Self::allow_eq(owner)
            }
        }
    }

    // ── List / CREATE branches (R5–R8) ────────────────────────────────────

    #[allow(clippy::cognitive_complexity)]
    async fn evaluate_list(
        &self,
        ctx: &SecurityContext,
        subject: Uuid,
        root_id: Option<Uuid>,
        mode: &TenantMode,
        barrier_mode: BarrierMode,
        tenant_statuses: &[TenantStatus],
    ) -> EvaluationResponse {
        match (root_id, mode) {
            (Some(root), TenantMode::RootOnly) => {
                // R5: GET /tasks?tenant=t2&tenant_mode=root_only
                // Subject must be (reflexive) ancestor of root_id.
                if !self.is_in_subtree(ctx, subject, root, barrier_mode).await {
                    warn!(%subject, %root, "R5: subject is not an ancestor of root_id -- deny");
                    return Self::deny();
                }
                debug!(rule = "R5", %root, "tr-authz: allow");
                Self::allow_eq(root)
            }
            (Some(root), TenantMode::Subtree) => {
                // R6: GET /tasks?tenant=t2
                // Subject must be (reflexive) ancestor of root_id.
                if !self.is_in_subtree(ctx, subject, root, barrier_mode).await {
                    warn!(%subject, %root, "R6: subject is not an ancestor of root_id -- deny");
                    return Self::deny();
                }
                match self
                    .resolve_subtree(ctx, root, barrier_mode, tenant_statuses)
                    .await
                {
                    Ok(ids) if !ids.is_empty() => {
                        debug!(rule = "R6", %root, visible = ids.len(), "tr-authz: allow");
                        Self::allow_in(ids)
                    }
                    Ok(_) => {
                        warn!(%root, "R6: empty descendants -- deny");
                        Self::deny()
                    }
                    Err(e) => {
                        warn!(error = %e, %root, "R6: TR failure -- deny");
                        Self::deny()
                    }
                }
            }
            (None, TenantMode::RootOnly) => {
                // R7: GET /tasks?tenant_mode=root_only
                debug!(rule = "R7", %subject, "tr-authz: allow");
                Self::allow_eq(subject)
            }
            (None, TenantMode::Subtree) => {
                // R8: GET /tasks
                match self
                    .resolve_subtree(ctx, subject, barrier_mode, tenant_statuses)
                    .await
                {
                    Ok(ids) if !ids.is_empty() => {
                        debug!(rule = "R8", %subject, visible = ids.len(), "tr-authz: allow");
                        Self::allow_in(ids)
                    }
                    Ok(_) => {
                        warn!(%subject, "R8: empty descendants -- deny");
                        Self::deny()
                    }
                    Err(e) => {
                        warn!(error = %e, %subject, "R8: TR failure -- deny");
                        Self::deny()
                    }
                }
            }
        }
    }

    // ── TR helpers ────────────────────────────────────────────────────────

    /// Reflexive "candidate is in the closed subtree rooted at `anchor`".
    /// Returns `false` on any TR error (fail-closed).
    async fn is_in_subtree(
        &self,
        ctx: &SecurityContext,
        anchor: Uuid,
        candidate: Uuid,
        barrier_mode: BarrierMode,
    ) -> bool {
        if anchor == candidate {
            return true;
        }
        match self
            .tr
            .is_ancestor(
                ctx,
                TenantId(anchor),
                TenantId(candidate),
                &IsAncestorOptions { barrier_mode },
            )
            .await
        {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, %anchor, %candidate, "is_ancestor failed -- treat as false");
                false
            }
        }
    }

    /// Resolve the closed subtree (root + descendants) as UUIDs.
    ///
    /// `tenant_statuses` filters descendants by status (empty = all). Per the
    /// TR SDK contract (`GetDescendantsOptions::status`), the filter does not
    /// apply to the starting tenant itself.
    async fn resolve_subtree(
        &self,
        ctx: &SecurityContext,
        tenant_id: Uuid,
        barrier_mode: BarrierMode,
        tenant_statuses: &[TenantStatus],
    ) -> Result<Vec<Uuid>, String> {
        let response = self
            .tr
            .get_descendants(
                ctx,
                TenantId(tenant_id),
                &GetDescendantsOptions {
                    status: tenant_statuses.to_vec(),
                    barrier_mode,
                    max_depth: None,
                },
            )
            .await
            .map_err(|e| match e {
                TenantResolverError::TenantNotFound { .. } => {
                    format!("Tenant {tenant_id} not found")
                }
                other => format!("TR error: {other}"),
            })?;

        let mut visible = Vec::with_capacity(response.descendants.len() + 1);
        visible.push(response.tenant.id.0);
        visible.extend(response.descendants.iter().map(|t| t.id.0));
        Ok(visible)
    }

    // ── Response builders ────────────────────────────────────────────────

    fn allow_eq(tenant_id: Uuid) -> EvaluationResponse {
        Self::allow(vec![Predicate::In(InPredicate::new(
            pep_properties::OWNER_TENANT_ID,
            [tenant_id],
        ))])
    }

    fn allow_in(tenant_ids: Vec<Uuid>) -> EvaluationResponse {
        Self::allow(vec![Predicate::In(InPredicate::new(
            pep_properties::OWNER_TENANT_ID,
            tenant_ids,
        ))])
    }

    fn allow(predicates: Vec<Predicate>) -> EvaluationResponse {
        EvaluationResponse {
            decision: true,
            context: EvaluationResponseContext {
                constraints: vec![Constraint { predicates }],
                ..Default::default()
            },
        }
    }

    fn deny() -> EvaluationResponse {
        EvaluationResponse {
            decision: false,
            context: EvaluationResponseContext::default(),
        }
    }

    // ── Group predicates (orthogonal to tenant) ──────────────────────────

    /// Returns `Err(())` when a group scoping property is present but cannot
    /// be parsed as a full `Vec<Uuid>` (e.g. not an array, or contains a
    /// non-UUID string). Caller maps that to `deny` (fail-closed). Missing
    /// properties and legitimately empty arrays are `Ok(())`.
    fn append_group_predicates(
        response: &mut EvaluationResponse,
        props: &std::collections::HashMap<String, serde_json::Value>,
    ) -> Result<(), ()> {
        let Some(Constraint { predicates }) = response.context.constraints.get_mut(0) else {
            return Ok(());
        };
        if let Some(group_ids) = props.get("group_ids") {
            let ids = Self::parse_uuid_array(group_ids).ok_or(())?;
            if !ids.is_empty() {
                predicates.push(Predicate::InGroup(InGroupPredicate::new("id", ids)));
            }
        }
        if let Some(ancestor_ids) = props.get("ancestor_group_ids") {
            let ids = Self::parse_uuid_array(ancestor_ids).ok_or(())?;
            if !ids.is_empty() {
                predicates.push(Predicate::InGroupSubtree(InGroupSubtreePredicate::new(
                    "id", ids,
                )));
            }
        }
        Ok(())
    }

    // ── Parsing helpers ──────────────────────────────────────────────────

    fn read_uuid(
        props: &std::collections::HashMap<String, serde_json::Value>,
        key: &str,
    ) -> Option<Uuid> {
        props
            .get(key)
            .and_then(|v| v.as_str())
            .and_then(|s| Uuid::parse_str(s).ok())
    }

    /// Strict array-of-UUID parse: returns `None` when the JSON value is not
    /// an array, OR when any element is not a valid UUID string. Callers treat
    /// `None` as a hard error (fail-closed) rather than silently dropping the
    /// bad entries, which would widen the resulting access scope.
    fn parse_uuid_array(value: &serde_json::Value) -> Option<Vec<Uuid>> {
        let arr = value.as_array()?;
        arr.iter()
            .map(|v| v.as_str().and_then(|s| Uuid::parse_str(s).ok()))
            .collect()
    }

    /// Map caller-supplied `tenant_status` strings to TR SDK `TenantStatus`.
    /// Returns the first unrecognized value on failure so the caller can
    /// fail-closed with a diagnostic — silently dropping unknowns would widen
    /// the status filter to "all statuses" and leak suspended/deleted tenants.
    ///
    /// Accepted values match the SDK's `#[serde(rename_all = "snake_case")]`
    /// representation of `TenantStatus`: `active`, `suspended`, `deleted`.
    fn parse_tenant_statuses(statuses: &[String]) -> Result<Vec<TenantStatus>, String> {
        statuses
            .iter()
            .map(|s| match s.as_str() {
                "active" => Ok(TenantStatus::Active),
                "suspended" => Ok(TenantStatus::Suspended),
                "deleted" => Ok(TenantStatus::Deleted),
                other => Err(other.to_owned()),
            })
            .collect()
    }

    fn tr_barrier_mode(mode: AuthzBarrierMode) -> BarrierMode {
        match mode {
            AuthzBarrierMode::Respect => BarrierMode::Respect,
            AuthzBarrierMode::Ignore => BarrierMode::Ignore,
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use std::collections::HashMap;

    use async_trait::async_trait;
    use authz_resolver_sdk::{Action, EvaluationRequestContext, Resource, Subject, TenantContext};
    use serde_json::json;
    use tenant_resolver_sdk::{
        GetAncestorsOptions, GetAncestorsResponse, GetTenantsOptions, TenantInfo, TenantRef,
    };

    #[derive(Debug, Clone, Default)]
    struct FakeTenantResolver {
        tenants: HashMap<Uuid, TenantRef>,
    }

    impl FakeTenantResolver {
        fn standard() -> Self {
            let mut fake = Self::default();
            fake.insert(root(), None, TenantStatus::Active);
            fake.insert(child(), Some(root()), TenantStatus::Active);
            fake.insert(grandchild(), Some(child()), TenantStatus::Active);
            fake.insert(sibling(), Some(root()), TenantStatus::Active);
            fake.insert(suspended_child(), Some(child()), TenantStatus::Suspended);
            fake
        }

        fn insert(&mut self, id: Uuid, parent_id: Option<Uuid>, status: TenantStatus) {
            self.tenants.insert(
                id,
                TenantRef {
                    id: TenantId(id),
                    status,
                    tenant_type: None,
                    parent_id: parent_id.map(TenantId),
                    self_managed: false,
                },
            );
        }

        fn tenant_ref(&self, id: TenantId) -> Result<TenantRef, TenantResolverError> {
            self.tenants
                .get(&id.0)
                .cloned()
                .ok_or(TenantResolverError::TenantNotFound { tenant_id: id })
        }

        fn tenant_info(reference: &TenantRef) -> TenantInfo {
            TenantInfo {
                id: reference.id,
                name: reference.id.to_string(),
                status: reference.status,
                tenant_type: reference.tenant_type.clone(),
                parent_id: reference.parent_id,
                self_managed: reference.self_managed,
            }
        }

        fn is_descendant_of(
            &self,
            ancestor: Uuid,
            candidate: Uuid,
        ) -> Result<bool, TenantResolverError> {
            let _ = self.tenant_ref(TenantId(ancestor))?;
            let mut current = self.tenant_ref(TenantId(candidate))?;
            while let Some(parent_id) = current.parent_id {
                if parent_id.0 == ancestor {
                    return Ok(true);
                }
                current = self.tenant_ref(parent_id)?;
            }
            Ok(false)
        }

        fn descendants(
            &self,
            tenant_id: Uuid,
            statuses: &[TenantStatus],
        ) -> Result<Vec<TenantRef>, TenantResolverError> {
            let _ = self.tenant_ref(TenantId(tenant_id))?;
            let mut descendants = self
                .tenants
                .values()
                .filter(|tenant| tenant.id.0 != tenant_id)
                .filter(|tenant| statuses.is_empty() || statuses.contains(&tenant.status))
                .filter(|tenant| {
                    self.is_descendant_of(tenant_id, tenant.id.0)
                        .unwrap_or(false)
                })
                .cloned()
                .collect::<Vec<_>>();
            descendants.sort_by_key(|tenant| tenant.id.0.as_u128());
            Ok(descendants)
        }
    }

    #[async_trait]
    impl TenantResolverClient for FakeTenantResolver {
        async fn get_tenant(
            &self,
            _ctx: &SecurityContext,
            id: TenantId,
        ) -> Result<TenantInfo, TenantResolverError> {
            Ok(Self::tenant_info(&self.tenant_ref(id)?))
        }

        async fn get_root_tenant(
            &self,
            _ctx: &SecurityContext,
        ) -> Result<TenantInfo, TenantResolverError> {
            let root = self
                .tenants
                .values()
                .find(|tenant| tenant.parent_id.is_none())
                .ok_or_else(|| TenantResolverError::Internal("root tenant missing".to_owned()))?;
            Ok(Self::tenant_info(root))
        }

        async fn get_tenants(
            &self,
            _ctx: &SecurityContext,
            ids: &[TenantId],
            options: &GetTenantsOptions,
        ) -> Result<Vec<TenantInfo>, TenantResolverError> {
            Ok(ids
                .iter()
                .filter_map(|id| self.tenants.get(&id.0))
                .filter(|tenant| {
                    options.status.is_empty() || options.status.contains(&tenant.status)
                })
                .map(Self::tenant_info)
                .collect())
        }

        async fn get_ancestors(
            &self,
            _ctx: &SecurityContext,
            id: TenantId,
            _options: &GetAncestorsOptions,
        ) -> Result<GetAncestorsResponse, TenantResolverError> {
            let tenant = self.tenant_ref(id)?;
            let mut ancestors = Vec::new();
            let mut current = tenant.clone();
            while let Some(parent_id) = current.parent_id {
                current = self.tenant_ref(parent_id)?;
                ancestors.push(current.clone());
            }
            Ok(GetAncestorsResponse { tenant, ancestors })
        }

        async fn get_descendants(
            &self,
            _ctx: &SecurityContext,
            id: TenantId,
            options: &GetDescendantsOptions,
        ) -> Result<tenant_resolver_sdk::GetDescendantsResponse, TenantResolverError> {
            Ok(tenant_resolver_sdk::GetDescendantsResponse {
                tenant: self.tenant_ref(id)?,
                descendants: self.descendants(id.0, &options.status)?,
            })
        }

        async fn is_ancestor(
            &self,
            _ctx: &SecurityContext,
            ancestor_id: TenantId,
            descendant_id: TenantId,
            _options: &IsAncestorOptions,
        ) -> Result<bool, TenantResolverError> {
            // Strictly non-reflexive: a tenant is NOT its own ancestor.
            // Callers that need reflexive containment (e.g. `is_in_subtree`)
            // must add the self-equality short-circuit before calling this.
            if ancestor_id == descendant_id {
                return Ok(false);
            }
            self.is_descendant_of(ancestor_id.0, descendant_id.0)
        }
    }

    #[derive(Debug, Clone)]
    struct RuleCase {
        single_resource: bool,
        subject: Uuid,
        owner: Option<Uuid>,
        root_id: Option<Uuid>,
        mode: TenantMode,
        expected_decision: bool,
    }

    #[tokio::test]
    async fn r1_to_r8_allow_deny_matrix() {
        use TenantMode::{RootOnly, Subtree};

        let cases = vec![
            (
                "R1 allow",
                rule(true, root(), Some(child()), Some(child()), RootOnly, true),
            ),
            (
                "R1 deny owner != root",
                rule(
                    true,
                    root(),
                    Some(grandchild()),
                    Some(child()),
                    RootOnly,
                    false,
                ),
            ),
            (
                "R2 allow",
                rule(
                    true,
                    root(),
                    Some(grandchild()),
                    Some(child()),
                    Subtree,
                    true,
                ),
            ),
            (
                "R2 deny owner outside root subtree",
                rule(true, root(), Some(sibling()), Some(child()), Subtree, false),
            ),
            (
                "R3 allow",
                rule(true, child(), Some(child()), None, RootOnly, true),
            ),
            (
                "R3 deny owner differs",
                rule(true, child(), Some(grandchild()), None, RootOnly, false),
            ),
            (
                "R4 allow",
                rule(true, child(), Some(grandchild()), None, Subtree, true),
            ),
            (
                "R4 deny owner outside subject subtree",
                rule(true, child(), Some(sibling()), None, Subtree, false),
            ),
            (
                "R5 allow",
                rule(false, root(), None, Some(child()), RootOnly, true),
            ),
            (
                "R5 deny subject not ancestor",
                rule(false, sibling(), None, Some(child()), RootOnly, false),
            ),
            (
                "R6 allow",
                rule(false, root(), None, Some(child()), Subtree, true),
            ),
            (
                "R6 deny subject not ancestor",
                rule(false, sibling(), None, Some(child()), Subtree, false),
            ),
            ("R7 allow", rule(false, child(), None, None, RootOnly, true)),
            (
                "R7 deny nil subject",
                rule(false, Uuid::nil(), None, None, RootOnly, false),
            ),
            ("R8 allow", rule(false, child(), None, None, Subtree, true)),
            (
                "R8 deny unknown subject",
                rule(false, unknown(), None, None, Subtree, false),
            ),
        ];

        for (name, case) in cases {
            assert_rule_case(name, case).await;
        }
    }

    fn rule(
        single_resource: bool,
        subject: Uuid,
        owner: Option<Uuid>,
        root_id: Option<Uuid>,
        mode: TenantMode,
        expected_decision: bool,
    ) -> RuleCase {
        RuleCase {
            single_resource,
            subject,
            owner,
            root_id,
            mode,
            expected_decision,
        }
    }

    async fn assert_rule_case(name: &str, case: RuleCase) {
        let service = Service::new(Arc::new(FakeTenantResolver::standard()));
        let request = request_for(&case, None, HashMap::new());
        let response = service.evaluate(&request).await;

        assert_eq!(
            response.decision, case.expected_decision,
            "{name} should have decision {}: {case:?}",
            case.expected_decision
        );
        if case.expected_decision {
            assert!(
                !response.context.constraints.is_empty(),
                "{name} should carry tenant constraints: {case:?}"
            );
        } else {
            assert!(
                response.context.constraints.is_empty(),
                "{name} should not carry constraints: {case:?}"
            );
        }
    }

    #[test]
    fn parse_tenant_statuses_accepts_active_suspended_deleted() {
        let input = vec![
            "active".to_owned(),
            "suspended".to_owned(),
            "deleted".to_owned(),
        ];

        let statuses = Service::parse_tenant_statuses(&input).expect("valid statuses parse");

        assert_eq!(
            statuses,
            vec![
                TenantStatus::Active,
                TenantStatus::Suspended,
                TenantStatus::Deleted
            ]
        );
    }

    #[test]
    fn parse_tenant_statuses_rejects_unknown_archived() {
        let input = vec!["active".to_owned(), "archived".to_owned()];

        let err = Service::parse_tenant_statuses(&input).expect_err("unknown status rejects");

        assert_eq!(err, "archived");
    }

    #[test]
    fn parse_tenant_statuses_accepts_missing_empty_input() {
        let input = Vec::<String>::new();

        let statuses = Service::parse_tenant_statuses(&input).expect("empty status filter parses");

        assert!(statuses.is_empty());
    }

    #[tokio::test]
    async fn evaluate_denies_unknown_tenant_status_before_resolving_subtree() {
        let service = Service::new(Arc::new(FakeTenantResolver::standard()));
        let case = RuleCase {
            single_resource: false,
            subject: child(),
            owner: None,
            root_id: None,
            mode: TenantMode::Subtree,
            expected_decision: false,
        };
        let request = request_for(&case, Some(vec!["archived"]), HashMap::new());

        let response = service.evaluate(&request).await;

        assert!(!response.decision);
        assert!(response.context.constraints.is_empty());
    }

    #[tokio::test]
    async fn evaluate_applies_tenant_status_filter_to_descendants() {
        let service = Service::new(Arc::new(FakeTenantResolver::standard()));
        let case = RuleCase {
            single_resource: false,
            subject: root(),
            owner: None,
            root_id: Some(child()),
            mode: TenantMode::Subtree,
            expected_decision: true,
        };
        let request = request_for(&case, Some(vec!["suspended"]), HashMap::new());

        let response = service.evaluate(&request).await;

        assert!(response.decision);
        let Predicate::In(predicate) = &response.context.constraints[0].predicates[0] else {
            panic!("tenant scope should be an In predicate");
        };
        let mut actual = predicate.values.clone();
        actual.sort_by(|a, b| a.to_string().cmp(&b.to_string()));
        let mut expected = vec![
            json!(child().to_string()),
            json!(suspended_child().to_string()),
        ];
        expected.sort_by(|a, b| a.to_string().cmp(&b.to_string()));
        assert_eq!(actual, expected);
    }

    #[tokio::test]
    async fn is_in_subtree_is_reflexive() {
        // `is_ancestor` in the fake is strictly non-reflexive; `is_in_subtree`
        // must add the self-equality short-circuit so a tenant is always
        // considered inside its own subtree.
        let service = Service::new(Arc::new(FakeTenantResolver::standard()));
        let ctx = SecurityContext::anonymous();
        assert!(
            service
                .is_in_subtree(&ctx, child(), child(), BarrierMode::default())
                .await,
            "is_in_subtree should be reflexive"
        );
    }

    #[test]
    fn group_predicates_append_valid_membership_and_subtree() {
        let group_id = Uuid::from_u128(101);
        let ancestor_group_id = Uuid::from_u128(102);
        let mut response = Service::allow_eq(child());
        let mut props = HashMap::new();
        props.insert("group_ids".to_owned(), json!([group_id.to_string()]));
        props.insert(
            "ancestor_group_ids".to_owned(),
            json!([ancestor_group_id.to_string()]),
        );

        Service::append_group_predicates(&mut response, &props).expect("valid group props append");

        let predicates = &response.context.constraints[0].predicates;
        assert_eq!(predicates.len(), 3);
        assert!(matches!(predicates[1], Predicate::InGroup(_)));
        assert!(matches!(predicates[2], Predicate::InGroupSubtree(_)));
        let Predicate::InGroup(predicate) = &predicates[1] else {
            panic!("expected InGroup predicate");
        };
        assert_eq!(predicate.property, "id");
        assert_eq!(predicate.group_ids, vec![json!(group_id.to_string())]);
        let Predicate::InGroupSubtree(predicate) = &predicates[2] else {
            panic!("expected InGroupSubtree predicate");
        };
        assert_eq!(predicate.property, "id");
        assert_eq!(
            predicate.ancestor_ids,
            vec![json!(ancestor_group_id.to_string())]
        );
    }

    #[test]
    fn group_predicates_reject_invalid_group_id_shapes() {
        let cases = vec![
            ("group_ids_not_array", "group_ids", json!("not-an-array")),
            ("group_ids_invalid_uuid", "group_ids", json!(["not-a-uuid"])),
            (
                "ancestor_group_ids_invalid_uuid",
                "ancestor_group_ids",
                json!(["not-a-uuid"]),
            ),
        ];

        for (name, key, value) in cases {
            let mut response = Service::allow_eq(child());
            let mut props = HashMap::new();
            props.insert(key.to_owned(), value);

            let result = Service::append_group_predicates(&mut response, &props);

            assert!(result.is_err(), "{name} should fail closed");
        }
    }

    #[test]
    fn group_predicates_ignore_missing_and_empty_arrays() {
        let mut response = Service::allow_eq(child());
        let mut props = HashMap::new();
        props.insert("group_ids".to_owned(), json!([]));
        props.insert("ancestor_group_ids".to_owned(), json!([]));

        Service::append_group_predicates(&mut response, &props).expect("empty arrays are valid");

        assert_eq!(response.context.constraints[0].predicates.len(), 1);
    }

    #[tokio::test]
    async fn evaluate_denies_when_allowed_rule_has_malformed_group_scope() {
        let service = Service::new(Arc::new(FakeTenantResolver::standard()));
        let case = RuleCase {
            single_resource: false,
            subject: child(),
            owner: None,
            root_id: None,
            mode: TenantMode::RootOnly,
            expected_decision: false,
        };
        let mut props = HashMap::new();
        props.insert("group_ids".to_owned(), json!(["not-a-uuid"]));
        let request = request_for(&case, None, props);

        let response = service.evaluate(&request).await;

        assert!(!response.decision);
        assert!(response.context.constraints.is_empty());
    }

    fn request_for(
        case: &RuleCase,
        tenant_status: Option<Vec<&str>>,
        extra_resource_props: HashMap<String, serde_json::Value>,
    ) -> EvaluationRequest {
        let mut subject_props = HashMap::new();
        subject_props.insert("tenant_id".to_owned(), json!(case.subject.to_string()));

        let mut resource_props = HashMap::new();
        if let Some(owner) = case.owner {
            resource_props.insert(
                pep_properties::OWNER_TENANT_ID.to_owned(),
                json!(owner.to_string()),
            );
        }
        resource_props.extend(extra_resource_props);

        EvaluationRequest {
            subject: Subject {
                id: Uuid::from_u128(1_000),
                subject_type: Some("user".to_owned()),
                properties: subject_props,
            },
            action: Action {
                name: if case.single_resource {
                    "get".to_owned()
                } else {
                    "list".to_owned()
                },
            },
            resource: Resource {
                resource_type: "task".to_owned(),
                id: case.single_resource.then(|| Uuid::from_u128(2_000)),
                properties: resource_props,
            },
            context: EvaluationRequestContext {
                tenant_context: Some(TenantContext {
                    mode: case.mode.clone(),
                    root_id: case.root_id,
                    barrier_mode: AuthzBarrierMode::Respect,
                    tenant_status: tenant_status
                        .map(|statuses| statuses.into_iter().map(str::to_owned).collect()),
                }),
                token_scopes: Vec::new(),
                require_constraints: true,
                capabilities: Vec::new(),
                supported_properties: vec![pep_properties::OWNER_TENANT_ID.to_owned()],
                bearer_token: None,
            },
        }
    }

    fn root() -> Uuid {
        Uuid::from_u128(1)
    }

    fn child() -> Uuid {
        Uuid::from_u128(2)
    }

    fn grandchild() -> Uuid {
        Uuid::from_u128(3)
    }

    fn sibling() -> Uuid {
        Uuid::from_u128(4)
    }

    fn suspended_child() -> Uuid {
        Uuid::from_u128(5)
    }

    fn unknown() -> Uuid {
        Uuid::from_u128(99)
    }
}
