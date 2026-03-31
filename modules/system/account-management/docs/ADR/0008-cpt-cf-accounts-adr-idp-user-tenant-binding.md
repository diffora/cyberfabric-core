---
status: accepted
date: 2026-04-09
decision-makers: Virtuozzo
---

# ADR-0008: IdP as the Canonical Store for User-Tenant Binding


<!-- toc -->

- [Context and Problem Statement](#context-and-problem-statement)
- [Decision Drivers](#decision-drivers)
- [Considered Options](#considered-options)
- [Decision Outcome](#decision-outcome)
  - [Consequences](#consequences)
  - [Confirmation](#confirmation)
- [Pros and Cons of the Options](#pros-and-cons-of-the-options)
  - [Option 1: IdP stores user-tenant binding as a tenant identity attribute](#option-1-idp-stores-user-tenant-binding-as-a-tenant-identity-attribute)
  - [Option 2: AM stores user-tenant binding in a local join table](#option-2-am-stores-user-tenant-binding-in-a-local-join-table)
  - [Option 3: Dual-write — both AM and IdP store the binding](#option-3-dual-write--both-am-and-idp-store-the-binding)
- [More Information](#more-information)
- [Traceability](#traceability)

<!-- /toc -->

**ID**: `cpt-cf-accounts-adr-idp-user-tenant-binding`

## Context and Problem Statement

Every user in the Cyber Fabric platform belongs to exactly one tenant. This user-tenant binding is foundational to the authorization model: the AuthN Resolver extracts the tenant identity from the bearer token to establish the caller's `SecurityContext`, and the AuthZ Resolver uses that tenant identity for policy evaluation and tenant-scoped access control. The platform must decide where the canonical user-tenant binding is stored: in the IdP (as a tenant identity attribute on the user record), in AM's database (as a local association table), or in both systems.

This decision is closely related to but distinct from ADR-0007 (`cpt-cf-accounts-adr-idp-user-identity-source-of-truth`), which addresses user identity data broadly. This ADR focuses specifically on the user-tenant relationship — a piece of data that sits at the intersection of identity management and tenant hierarchy administration.

## Decision Drivers

* **Token-based authorization flow**: The platform's AuthN Resolver reads the tenant identity from the bearer token at request time. For this to work, the IdP must know which tenant a user belongs to — the binding must be present in the IdP so it can be embedded in tokens without an extra lookup to AM on every request.
* **Single source of truth**: If both AM and the IdP store the user-tenant binding, any desynchronization creates a split-brain scenario where the token claims (from IdP) disagree with AM's local record, leading to authorization inconsistencies.
* **Consistency with ADR-0007**: ADR-0007 establishes that AM does not maintain a local user table. Storing user-tenant binding locally would reintroduce user-related state in AM's database, contradicting the no-local-user-storage constraint.
* **IdP-agnostic portability**: The binding storage mechanism must work across all conforming IdP implementations (Keycloak, Azure AD, Okta, custom). The `IdpProviderPluginClient` contract defines `create_user` with tenant scope binding — the provider sets the attribute using its native mechanism.
* **Operational correctness of user-tenant queries**: AM's `GET /tenants/{id}/users` endpoint must return the authoritative list of users belonging to a tenant. If the binding is stored locally, AM can query its own database; if stored in the IdP, AM must delegate the query to the IdP.

## Considered Options

1. **IdP stores user-tenant binding as a tenant identity attribute**: The `IdpProviderPluginClient::create_user` contract sets a tenant identity attribute on the user record in the IdP. AM queries tenant-scoped users via `IdpProviderPluginClient::list_users`. AM does not store any local user-tenant association.
2. **AM stores user-tenant binding in a local join table**: AM maintains a `user_tenant_bindings` table mapping user IDs to tenant IDs. The IdP stores credentials and profile; AM stores the organizational relationship. User provisioning writes to both AM's table and the IdP.
3. **Dual-write — both AM and IdP store the binding**: AM writes the binding to its local table and to the IdP simultaneously. Either can serve as a query source. Consistency is maintained by saga or compensating transactions.

## Decision Outcome

Chosen option: **Option 1 — IdP stores user-tenant binding as a tenant identity attribute**, because the authorization hot path already requires the IdP to know the user's tenant (for token claims), making the IdP the natural canonical store. Storing the binding exclusively in the IdP eliminates split-brain risk between two systems, maintains consistency with the no-local-user-storage constraint (ADR-0007), and avoids synchronization complexity across pluggable IdP implementations.

The `IdpProviderPluginClient::create_user` contract requires the provider to set the tenant identity attribute on the user record. AM coordinates the binding by calling the IdP contract at the right lifecycle moment (provisioning, deprovisioning) but does not independently assert or cache the user-tenant relationship.

### Consequences

* The IdP is the single authoritative source for "user X belongs to tenant Y." The AuthN Resolver reads the tenant identity from the bearer token issued by the IdP — no additional AM lookup is required on the request hot path.
* AM's `GET /tenants/{id}/users` delegates to `IdpProviderPluginClient::list_users` with a tenant filter. Query performance and capabilities (pagination, filtering, search) depend on the IdP implementation, not on AM's database schema.
* AM has no `user_tenant_bindings` table or equivalent local state. This maintains the no-local-user-storage constraint from ADR-0007 and avoids introducing user-related database entities.
* User-tenant reassignment (moving a user between tenants) is out of scope for v1 (per PRD §4.2). When implemented, it will be coordinated through the IdP contract — AM will call the IdP to update the tenant identity attribute, and downstream effects (Resource Group membership migration, AuthZ cache invalidation, session revocation) will require cross-platform coordination.
* If the IdP is unreachable, AM cannot query which users belong to a tenant. The platform accepts this: tenant hierarchy operations remain available, but user-related operations fail with `idp_unavailable`.
* The `IdpProviderPluginClient` contract must be expressive enough for each provider to implement tenant identity attribute storage using its native mechanism (Keycloak: user attribute, Azure AD: custom claim, custom IdP: provider-defined). The contract specifies the semantic requirement (bind user to tenant) without prescribing the storage mechanism.

### Confirmation

* DESIGN and code review verify that AM's database schema contains no user-tenant association tables.
* Integration tests confirm that `create_user` results in the tenant identity attribute being set on the IdP user record (verified via `list_users` with tenant filter).
* Integration tests confirm that bearer tokens issued for provisioned users contain the correct tenant identity claim.
* Code review verifies that AM never independently asserts user-tenant membership — all membership checks go through the IdP contract.

## Pros and Cons of the Options

### Option 1: IdP stores user-tenant binding as a tenant identity attribute

* Good, because the authorization hot path (token validation) already requires the IdP to know the user's tenant, so the IdP is the natural canonical store — no redundant data path.
* Good, because it maintains a single source of truth — the token claims and the binding storage are the same system, eliminating split-brain scenarios.
* Good, because it is consistent with ADR-0007's no-local-user-storage constraint, keeping AM's schema focused on tenant hierarchy.
* Good, because it avoids synchronization protocols between AM and the IdP for binding state.
* Neutral, because user-tenant query performance depends on the IdP's query capabilities rather than AM's database indexes.
* Bad, because AM cannot answer "which users belong to this tenant" without calling the IdP, creating an availability dependency for user-related operations.
* Bad, because IdP implementations must support tenant-scoped user queries with acceptable performance — this is a contract requirement that not all off-the-shelf IdPs may satisfy without customization.

### Option 2: AM stores user-tenant binding in a local join table

* Good, because AM can query user-tenant relationships locally with predictable performance and SQL capabilities.
* Good, because user-tenant queries remain available during IdP outages.
* Bad, because it creates a second source of truth for user-tenant binding — the IdP must also know the binding for token claims, producing a dual-write scenario with split-brain risk.
* Bad, because it contradicts ADR-0007's no-local-user-storage constraint by reintroducing user-related state in AM's database.
* Bad, because provisioning requires writes to both AM's table and the IdP, requiring saga/compensation logic and adding a failure mode class.
* Bad, because each pluggable IdP implementation must synchronize its tenant identity attribute with AM's local table, coupling AM to provider-specific sync behavior.

### Option 3: Dual-write — both AM and IdP store the binding

* Good, because AM can serve user-tenant queries locally while the IdP handles token claims — read path optimization for both systems.
* Bad, because dual-write requires transactional coordination or eventual consistency between two independent systems, with complex compensation on partial failures.
* Bad, because desynchronization between the two stores means the IdP token claims may disagree with AM's local record, causing authorization inconsistencies that are difficult to diagnose.
* Bad, because it doubles the operational burden for user-tenant reassignment, deprovisioning cascades, and data lifecycle management.
* Bad, because it violates the single-source-of-truth principle for a critical security-relevant piece of data (tenant identity).

## More Information

The user-tenant binding is a security-critical data point: it determines the caller's tenant context for authorization. The CyberFabric authorization flow is:
1. User authenticates → IdP issues a bearer token containing the tenant identity claim.
2. AuthN Resolver validates the token and extracts the tenant identity → establishes `SecurityContext`.
3. AuthZ Resolver evaluates policies using the tenant context from `SecurityContext`.

Because the token issuance path (step 1) requires the IdP to know the user's tenant, the IdP is inherently the system that must store the binding. Duplicating this data in AM would create a consistency obligation with no authorization-path benefit.

PRD Section 3.4 (User Data Ownership) explicitly states: "IdP is the single source of truth for 'user X exists and belongs to tenant Y.'"

## Traceability

- **PRD**: [PRD.md](../PRD.md)
- **DESIGN**: [DESIGN.md](../DESIGN.md)

This decision directly addresses the following requirements and design elements:

* `cpt-cf-accounts-fr-idp-user-provision` — The `create_user` contract sets the tenant identity attribute on the user record in the IdP, establishing the binding at provisioning time.
* `cpt-cf-accounts-fr-idp-user-query` — User-tenant queries delegate to `IdpProviderPluginClient::list_users` with tenant filter because the IdP is the canonical store for the binding.
* `cpt-cf-accounts-fr-idp-user-deprovision` — User deprovisioning removes the user (and its tenant binding) from the IdP; no local binding cleanup needed.
* `cpt-cf-accounts-principle-idp-agnostic` — The binding is stored via the IdP contract's native mechanism, maintaining provider portability.
* `cpt-cf-accounts-constraint-no-user-storage` — No local user-tenant association table exists, consistent with the no-direct-user-data-storage constraint.
* `cpt-cf-accounts-adr-idp-user-identity-source-of-truth` — This ADR is a companion decision; ADR-0007 establishes no local user table, this ADR specifically addresses where the user-tenant relationship lives.
* `cpt-cf-accounts-nfr-context-validation-latency` — Tenant context validation on the hot path reads the tenant identity from the bearer token (IdP-issued), avoiding an AM database lookup.
