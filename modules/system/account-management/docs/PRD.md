Created:  2026-03-30 by Virtuozzo

# PRD - Account Management (AM)


<!-- toc -->

- [1. Overview](#1-overview)
  - [1.1 Purpose](#11-purpose)
  - [1.2 Background / Problem Statement](#12-background--problem-statement)
  - [1.3 Goals (Business Outcomes)](#13-goals-business-outcomes)
  - [1.4 Non-goals](#14-non-goals)
  - [1.5 Glossary](#15-glossary)
- [2. Actors](#2-actors)
  - [2.1 Human Actors](#21-human-actors)
  - [2.2 System Actors](#22-system-actors)
- [3. Operational Concept & Environment](#3-operational-concept--environment)
  - [3.1 Core Boundary](#31-core-boundary)
  - [3.2 IdP Integration Boundary](#32-idp-integration-boundary)
  - [3.3 Barrier Tenant Isolation](#33-barrier-tenant-isolation)
  - [3.4 User Data Ownership](#34-user-data-ownership)
- [4. Scope](#4-scope)
  - [4.1 In Scope](#41-in-scope)
  - [4.2 Out of Scope](#42-out-of-scope)
- [5. Functional Requirements](#5-functional-requirements)
  - [5.1 Platform Bootstrap](#51-platform-bootstrap)
  - [5.2 Tenant Hierarchy Management](#52-tenant-hierarchy-management)
  - [5.3 Tenant Type Enforcement](#53-tenant-type-enforcement)
  - [5.4 Managed/Self-Managed Tenant Modes](#54-managedself-managed-tenant-modes)
  - [5.5 IdP Tenant & User Operations Contract](#55-idp-tenant--user-operations-contract)
  - [5.6 User Groups Management](#56-user-groups-management)
  - [5.7 Extensible Tenant Metadata](#57-extensible-tenant-metadata)
  - [5.8 Deterministic Error Semantics](#58-deterministic-error-semantics)
  - [5.9 Observability Metrics](#59-observability-metrics)
- [6. Non-Functional Requirements](#6-non-functional-requirements)
  - [6.1 Tenant Context Validation Latency](#61-tenant-context-validation-latency)
  - [6.2 Authentication Context](#62-authentication-context)
  - [6.3 Tenant Isolation Integrity](#63-tenant-isolation-integrity)
  - [6.4 Audit Trail Completeness](#64-audit-trail-completeness)
  - [6.5 Barrier Enforcement](#65-barrier-enforcement)
  - [6.6 Tenant Model Versatility](#66-tenant-model-versatility)
  - [6.7 API and SDK Compatibility](#67-api-and-sdk-compatibility)
  - [6.8 Expected Production Scale](#68-expected-production-scale)
  - [6.9 Data Classification](#69-data-classification)
  - [6.10 Reliability](#610-reliability)
  - [6.11 Data Lifecycle](#611-data-lifecycle)
  - [6.12 Data Quality](#612-data-quality)
  - [NFR Exclusions](#nfr-exclusions)
- [7. Public Library Interfaces](#7-public-library-interfaces)
  - [7.1 Public API Surface](#71-public-api-surface)
  - [7.2 External Integration Contracts](#72-external-integration-contracts)
- [8. Use Cases](#8-use-cases)
  - [8.1 Bootstrap](#81-bootstrap)
  - [8.2 Tenant Lifecycle](#82-tenant-lifecycle)
  - [8.3 Managed/Self-Managed Modes](#83-managedself-managed-modes)
  - [8.4 User Groups](#84-user-groups)
  - [8.5 IdP User Operations](#85-idp-user-operations)
  - [8.6 Extensible Tenant Metadata](#86-extensible-tenant-metadata)
- [9. Acceptance Criteria](#9-acceptance-criteria)
- [10. Dependencies](#10-dependencies)
- [11. Assumptions](#11-assumptions)
- [12. Risks](#12-risks)
- [13. Question Log (Resolved / Deferred)](#13-question-log-resolved--deferred)
- [14. Traceability](#14-traceability)

<!-- /toc -->

> **Abbreviations**: Account Management = **AM**; Global Type System = **GTS**. Used throughout this document.

## 1. Overview

### 1.1 Purpose

AM is the foundational multi-tenancy source-of-truth module for the Cyber Fabric platform. It provides hierarchical tenant management, tenant isolation metadata, delegated administration, and a pluggable Identity Provider (IdP) integration contract for administrative user lifecycle operations.

AM enables diverse organizational models — from cloud hosting (Provider / Reseller / Customer) to enterprise divisions and managed-service providers — within a single deployment, supporting both managed (delegated administration) and self-managed (barrier-isolated) tenant modes in the same hierarchy.

### 1.2 Background / Problem Statement

Cyber Fabric needs a unified multi-tenancy model that supports diverse organizational structures and business models within a single deployment. Without a shared tenant hierarchy, each organizational model requires separate infrastructure or custom integration, increasing operational cost and limiting platform scalability.

The platform needs a tenant model with unlimited hierarchy depth (configurable advisory threshold), visibility barriers for self-managed tenants, and consistent tenant context propagation across all services.

**Representative use-cases the module is designed for:**

| Domain | Use-case | How AM is used |
|--------|----------|-----------------|
| **Cloud hosting** | Model a service-provider channel: *Provider → Reseller → Customer*. Provider onboards resellers who sell to end-customers. | Each level is a GTS-registered tenant type; individual organizations are tenant entities forming a tree. Provider manages resellers and customers through a single hierarchy view. |
| **Education** | Model a university consortium: *Consortium → University → College*. Consortium provides shared infrastructure; each university operates independently. | Consortium is root tenant; universities are child tenants with their own billing, security policy, and data isolation. A college (e.g., School of Medicine) may be self-managed to enforce stricter data-access rules than the parent university. |
| **Enterprise** | Model a corporation with divisions: *HQ → Region → Business Unit*. Each unit manages its own users and resources while HQ retains oversight. | HQ is root tenant; regions and business units are child tenants. `BarrierMode` controls whether HQ can traverse into a self-managed unit; a self-managed unit's metadata is independent (no inheritance from HQ). |
| **MSP / Managed Services** | A managed service provider operates customer environments on their behalf. | Parent-child managed relationship (no barrier). Parent admin impersonates child tenant for support operations with time-bounded sessions and full audit trail. |
| **Distributor / Reseller** | A distributor resells platform capacity but does not access customer data. | Self-managed child tenants create visibility barriers. Distributor sees billing metadata (`BarrierMode::Ignore`) but cannot access customer APIs or resources. |

### 1.3 Goals (Business Outcomes)

- Provide one stable contract for tenant hierarchy, type enforcement, barrier semantics, and user group coordination (via [Resource Group](../../resource-group/docs/PRD.md)).
- Support both managed (no barrier — delegated administration) and self-managed (with barrier — independent operation) tenant modes within the same tenant tree, covering use-cases from MSP service delivery to autonomous subsidiaries.
- Enable unlimited hierarchy depth with a configurable advisory threshold (default: 10 levels) for diverse organizational models.
- Enable end-to-end tenant-context validation to achieve p95 ≤ 5ms on every API call.
- Maintain zero cross-tenant data leaks, verified by automated security tests.
- Provide a pluggable IdP integration contract for user lifecycle operations.

**Success criteria:**

| Metric | Baseline | Target | Timeframe |
|--------|----------|--------|-----------|
| Tenant onboarding effort | 5+ API calls and manual IdP configuration per tenant | Single API call — tenant create with type and mode | Module GA |
| Separate deployments per tenant model | 2 separate deployment configurations required today (one per managed/self-managed pattern) | Both modes in one tenant tree — zero per-model deployments (pass/fail) | Module GA |
| End-to-end tenant context validation latency (p95) | N/A (no unified solution) | ≤ 5ms with caching in the resolver path | Pre-GA load test gate |
| Cross-tenant data leaks | N/A | Zero — verified by automated security test suite; secondary metric: number of cross-tenant isolation test scenarios passing (target: 100%) | Pre-GA security gate |
| Hierarchy depth coverage | Fixed shallow hierarchies (2–3 levels) | Unlimited depth with configurable advisory threshold (default: 10); validated with at least 3 distinct type topologies including hierarchies beyond the default threshold | Pre-GA integration test gate |

### 1.4 Non-goals

- User authentication flows (covered by IAM PRD).
- Authorization policy evaluation or SQL predicate generation (covered by AuthZ Resolver).
- Resource provisioning and lifecycle (covered by Resource Management System PRD).
- Being an IdP implementation — AM consumes IdP, not replaces it.
- User-tenant reassignment (moving a user between tenants) — deferred from v1; requires cross-platform coordination (Resource Group membership migration, resource ownership transfer, AuthZ cache invalidation, session revocation).

### 1.5 Glossary

> Platform-wide terms (Tenant, Subject Tenant, Context Tenant, Resource Tenant) are defined canonically in the [Authorization Core Terms](../../../../docs/arch/authorization/DESIGN.md#core-terms) and the [Tenant Model](../../../../docs/arch/authorization/TENANT_MODEL.md). This glossary re-states them briefly for self-containedness and adds AM-specific terms.

| Term | Definition |
|------|------------|
| GTS (Global Type System) | Platform registry for runtime-extensible type definitions, validation rules, and schema-based constraints. AM uses GTS to register and validate tenant types and metadata schemas. |
| Tenant | Logical organizational entity representing a company, division, team, or individual. The fundamental unit of multi-tenancy isolation. |
| Subject Tenant | Tenant the subject (user or API client) belongs to. Used for authorization context. |
| Context Tenant | Tenant scope root for an operation. May differ from Subject Tenant in cross-tenant scenarios (e.g., managed tenant access via impersonation). |
| Resource Tenant | Actual tenant owning a specific resource. |
| Self-Managed Tenant | Child tenant that creates a visibility barrier. The parent cannot see or access resources below this tenant in the hierarchy. |
| Managed Tenant | Child tenant where the parent is eligible for controlled access to child tenant APIs and resources per policy. No visibility barrier exists. |
| Tenant Barrier | Visibility and access boundary created by self-managed tenants. When a tenant is self-managed, it blocks ancestor visibility into the subtree below it. |
| Barrier Mode | Authorization parameter controlling barrier handling: `Respect` (default) stops traversal at self-managed boundaries; `Ignore` traverses through barriers for operations like billing queries. Values align with the `BarrierMode` SDK enum. Tenant metadata resolution does not use `BarrierMode::Ignore` — inheritance stops at self-managed boundaries instead (see §5.7). |
| Tenant Forest | Collection of independent tenant trees with no single global root. Each tree is fully isolated. Matches the platform tenant model topology. |
| Tenant Tree | Single rooted hierarchy of tenants within the forest. Each tree has exactly one root tenant (`parent_id = NULL`). |
| Root Tenant | Top-level tenant in a tree (`parent_id = NULL`). Multiple root tenants can exist in the forest, each heading an independent tree. Created by Platform Administrator. |
| Tenant Context | Tenant scope carried in the authorization request's `tenant_context` (separate from `SecurityContext`) to enforce isolation and scoping. |
| Tenant Status | Lifecycle state of a tenant: `active`, `suspended`, or `deleted`. |
| Conversion Request Status | Lifecycle state of a mode conversion request: `pending` (awaiting counterparty approval), `approved` (conversion completed), `expired` (72h window elapsed without approval), or `cancelled` (explicitly withdrawn). |
| Tenant Type | Classification of a tenant node. Types are extensible at runtime via the GTS types registry. Deployments define their own type topology. |
| User | A human subject managed by AM via the IdP contract (provisioning, tenant binding, group membership). Corresponds to the platform-level [Subject](../../../../docs/arch/authorization/DESIGN.md#core-terms) term narrowed to human identities; API clients and service accounts are not AM-managed users. |
| IdP Contract | Abstract pluggable interface for Identity Provider operations (user provisioning, deprovisioning, tenant binding, impersonation tokens). |
| Impersonation | Authorized action by parent tenant admin to act as a managed child tenant admin, with time-bounded sessions and full audit trail. |
| User Group | A [Resource Group](../../resource-group/docs/PRD.md) entity with a Resource Group type configured for user membership (`allowed_memberships` includes the user resource type). AM delegates group hierarchy, membership management, and cycle detection to the Resource Group module. |
| Tenant Metadata Schema | A GTS-registered schema that defines a kind of extensible tenant data (e.g., `branding`, `contacts`), its validation rules, and its inheritance policy. |
| Inheritance Policy | Per-schema setting that controls parent-to-child metadata propagation: `inherit` (child inherits parent value unless overridden) or `override-only` (no inheritance; each tenant sets its own value). |

## 2. Actors

### 2.1 Human Actors

#### Platform Administrator

**ID**: `cpt-cf-accounts-actor-platform-admin`

- **Role**: Operator of the platform with full access to the tenant forest, platform configuration, and bootstrap operations. Only actor authorized to create new root tenants (new trees in the forest).
- **Needs**: View and manage the full tenant forest, perform platform bootstrap, create additional root tenants, override barriers for billing and administrative operations, monitor tenant health and isolation integrity.

#### Tenant Administrator

**ID**: `cpt-cf-accounts-actor-tenant-admin`

- **Role**: Administrator of a specific tenant who manages sub-tenants, users, groups, extensible tenant metadata, and tenant configuration within their scope.
- **Needs**: Create and manage child tenants, configure tenant metadata (branding, contacts, etc.) via GTS-registered schemas, manage user groups and memberships (via Resource Group), control tenant mode (managed/self-managed), access managed child tenant resources via impersonation when available.

### 2.2 System Actors

#### Tenant Resolver Plugin

**ID**: `cpt-cf-accounts-actor-tenant-resolver`

- **Role**: Maintains a denormalized projection of the tenant hierarchy for efficient subtree queries on the authorization hot path. Periodically synchronizes with the Account Service source of truth.

#### AuthZ Resolver Plugin

**ID**: `cpt-cf-accounts-actor-authz-resolver`

- **Role**: Evaluates authorization decisions using tenant context, barrier semantics, and subtree scoping constraints. Consumes the tenant hierarchy projection via [Tenant Resolver](../../tenant-resolver) for query-level tenant isolation.

#### IdP Provider

**ID**: `cpt-cf-accounts-actor-idp`

- **Role**: Pluggable identity provider that manages user authentication, token issuance, and user-tenant binding. Provides tenant identity via user attributes in tokens. Conforms to the AM IdP contract for user lifecycle operations.

#### Billing System

**ID**: `cpt-cf-accounts-actor-billing`

- **Role**: Consumes tenant hierarchy metadata with barrier bypass (`BarrierMode::Ignore`) for billing aggregation and reporting across the tenant forest.

#### GTS Registry

**ID**: `cpt-cf-accounts-actor-gts-registry`

- **Role**: Provides runtime-extensible type definitions for tenant types, enabling new tenant classifications without code changes. Validates parent-child type constraints at tenant creation time.

**Downstream consumer resilience**: Billing System and AuthZ Resolver Plugin are downstream consumers of AM data. Their resilience to AM unavailability is their own concern, consistent with the Tenant Resolver pattern where projection staleness is a Tenant Resolver responsibility.

## 3. Operational Concept & Environment

**IdP integration convention.** AM defines an abstract IdP contract for user lifecycle operations (provision, deprovision). The contract is pluggable — deployments can use any conforming IdP implementation (Keycloak, Azure AD, Okta, custom). AM owns the tenant model; IdP owns user authentication and token issuance. AM calls IdP via the pluggable contract for user-tenant binding operations.

**Tenant isolation convention.** Tenants form a forest of independent trees (per the [platform tenant model](../../../../docs/arch/authorization/TENANT_MODEL.md)). Every tenant exists in exactly one tree. Barrier semantics (managed vs self-managed) control cross-tenant visibility within a tree; trees are fully isolated from each other. The platform enforces tenant context on every API request via the authorization path. AM provides the tenant metadata, hierarchy state, and barrier flags consumed by [Tenant Resolver](../../tenant-resolver) and [AuthZ Resolver](../../authz-resolver); AM is not itself the per-request authorization enforcement point.

### 3.1 Core Boundary

AM:

- owns the tenant hierarchy and tenant metadata (source of truth).
- validates structural invariants (type compatibility, forest shape — multiple independent trees, no cross-tree references) and enforces depth advisory threshold.
- exposes tenant data consumed by Tenant Resolver, AuthZ Resolver, Billing, and other platform components.
- calls IdP via pluggable contract for user lifecycle operations.

AM does not:

- evaluate allow/deny decisions.
- interpret authorization policies.
- validate bearer tokens or construct `SecurityContext` on the per-request path.
- implement user authentication flows.
- manage resource provisioning.

### 3.2 IdP Integration Boundary

AM defines an abstract **IdP Contract** for tenant and user lifecycle operations. The contract covers:

- **Tenant provisioning**: set up IdP-side resources for a newly created tenant (e.g., a Keycloak realm, an Azure AD directory, or a no-op for providers that do not require per-tenant resources). Called on every tenant creation (root and child). Receives tenant metadata parameters so the provider can configure the IdP resource to match tenant properties.
- **Tenant deprovisioning**: tear down IdP-side resources for a deleted tenant (e.g., remove a Keycloak realm). Called during tenant hard deletion. Default implementation is a no-op.
- **User provisioning**: create a user record bound to a specific tenant.
- **User deprovisioning**: remove a user record from a tenant.
- **Impersonation token issuance**: obtain a time-bounded token for parent-to-child managed access.
- **User query by tenant**: list users belonging to a tenant scope.

Cyber Fabric ships a ready-to-use IdP provider implementation. Deployments can either:

- use this built-in provider directly, or
- use a vendor-specific IdP provider behind the same contract (plugin pattern), analogous to Tenant Resolver extensibility.

The IdP contract is one-directional: AM calls IdP. IdP does not call AM. AM tolerates IdP unavailability during bootstrap with retry/backoff.

The IdP integration contract is intentionally separate from the AuthN Resolver contract. The two categories have fundamentally different performance profiles (hot-path token validation vs infrequent admin operations), protocols (OIDC vs SCIM/admin REST), and deployment requirements.

### 3.3 Barrier Tenant Isolation

#### Responsibility Split: AM stores, Tenant Resolver + AuthZ enforce

**AM does not enforce access-control barriers.** AM stores and returns the `self_managed` flag in API responses. AM domain logic does not filter or restrict API results based on barrier values — barrier enforcement is applied by the platform's tenant-scoping and authorization layers, which exclude self-managed tenants and their subtrees from the caller's access scope before AM domain logic executes. AM's domain services do read hierarchy data that may include barrier-hidden tenants for two internal purposes: (1) **metadata inheritance boundary** — the ancestor walk stops at self-managed boundaries so that a self-managed tenant never inherits metadata from ancestors above its barrier (see `cpt-cf-accounts-fr-tenant-metadata-api`); (2) **structural invariant validation** — hierarchy-owner operations (parent-child type validation during creation, child-count pre-checks during deletion, child-state validation for the parent-scoped conversion endpoint) require full hierarchy visibility regardless of barrier state. Neither purpose constitutes access-control filtering — the results are used for internal precondition checks and are not exposed to API callers.

**The platform's tenant resolver enforces barriers during hierarchy traversal.** Barrier logic is applied when collecting ancestors and descendants.

**The platform's authorization layer integrates barriers into access constraints.** Authorization supports a barrier mode parameter (respect / ignore). When respecting barriers, self-managed tenants and their subtrees are excluded from access scope.

**Each layer is vendor-replaceable.** Vendors can implement custom tenant resolver plugins and authorization plugins with different barrier semantics.

#### Barrier Semantics Summary

The following rules describe the default barrier behavior (barrier mode = respect). AM does not enforce them.

1. **Self-managed tenant and its subtree invisible to parent**: self-managed tenant and its descendants are skipped during parent's hierarchy traversal.
2. **Self-managed tenant cannot see parent chain**: upward traversal from self-managed tenant returns empty.
3. **Visible to self**: self-managed tenant sees itself and its own children normally.
4. **Nested barriers allowed**: barriers compose — each barrier hides its subtree from the parent above. No depth limit.
5. **Barrier bypass mode**: bypasses all barriers. Used for platform-admin provisioning and billing.

#### Scenarios

**Scenario 1: Parent reads hierarchy (`BarrierMode::Respect`)**
```
Root (root) → T2 (self-managed) → T3 → T4
Caller: Root
```
- Root's visible scope includes only Root — T2 is excluded by barrier enforcement.
- Root sees direct children minus self-managed tenants. Does NOT see T2, T3, or T4.

**Scenario 2: Self-managed tenant reads own data**
```
Caller: T2
```
- T2's visible scope includes only T2 and its subtree.
- T2 sees T3.
- Does NOT see Root (parent chain blocked by barrier).

**Scenario 3: Nested barriers**
```
Root → A (self-managed) → B (self-managed) → D1
```
- Caller Root: visible scope is Root only — does NOT see A, B, or D1.
- Caller A: visible scope is A only — does NOT see B or D1.
- Caller B: visible scope is B and its subtree — sees B, D1.

**Scenario 4: Platform admin (`BarrierMode::Ignore`)**
```
Caller: platform-admin, barrier_mode: Ignore
```
- Full traversal: Root, A, B, D1 — all tenants visible.
- Used for tenant provisioning, billing, migration, support tooling.

### 3.4 User Data Ownership

AM coordinates user lifecycle operations but **does not own user data**. The ownership boundaries are:

| Data | System of record | AM role |
|------|-----------------|----------|
| User identity (credentials, profile, authentication state) | IdP | Not stored. AM never receives or persists credentials. |
| User-tenant binding (which tenant a user belongs to) | IdP (tenant identity attribute on user record) | Coordinator — AM calls IdP contract to set/query the binding, but IdP is the canonical store. |
| User existence | IdP | AM verifies user existence against IdP at operation time. AM does not maintain a local user table or projection. |
| User identifiers in group memberships | Resource Group (stores opaque `resource_id`) | AM passes the IdP-issued user identifier to Resource Group when managing group membership. Resource Group stores the identifier as an opaque reference. |
| User identifiers in audit logs | AM audit log | AM records IdP-issued user identifiers in audit entries as opaque references for traceability. |

**Key invariant**: IdP is the single source of truth for "user X exists and belongs to tenant Y." AM references users exclusively by opaque IdP-issued identifiers and does not cache, project, or independently assert user-tenant membership. If the IdP is unavailable, user operations fail with `idp_unavailable` — AM does not fall back to locally cached user state.

**Implication for group membership**: When a user is added to a group (via Resource Group), the membership link references the user by opaque identifier. If the user is later deprovisioned from the IdP, the membership link becomes orphaned. Orphan detection and cleanup require cross-module coordination (AM, Resource Group, and potentially an event bus) that does not yet exist; this is deferred to a future lifecycle management feature.

## 4. Scope

### 4.1 In Scope

- Platform bootstrap: initial root tenant auto-creation during install, idempotent (p1).
- Root tenant creation: Platform Administrator can create additional root tenants post-bootstrap, establishing new trees in the forest (p1).
- Tenant type classification via GTS registry with configurable parent-child constraints (p1).
- Tenant forest: multiple independent trees, each with parent-child relationships and unlimited depth with a configurable advisory threshold (p1).
- Managed tenant model: parent eligible for delegated child access with no barrier; impersonation when IdP contract supports it (p1).
- Self-managed tenant model: strict isolation via barrier; metadata inheritance stops at self-managed boundaries (p1).
- Tenant CRUD operations: create, read, update, soft-delete with configurable retention (p1).
- Root tenant listing: Platform Administrator can discover all root tenants in the forest (p1).
- IdP user operations contract: pluggable contract for user provisioning, deprovisioning, impersonation (p1).
- User groups management (via Resource Group): create groups, manage membership, nested groups with cycle detection delegated to Resource Group (p1).
- Observability metrics: domain-specific metrics exported via platform observability conventions (OpenTelemetry) (p1).
- Extensible tenant metadata: GTS-registered schemas for tenant-specific data kinds (e.g., branding, contacts) with per-schema inheritance policy and validation (p2).
- Tenant mode conversion: managed to self-managed (unilateral), self-managed to managed (dual approval with 72h expiry), inbound conversion request discovery for parent admins (p3).

### 4.2 Out of Scope

- User self-registration: users are provisioned via API within tenant security context (invite model only).
- User authentication flows: covered by IAM PRD.
- Tenant context propagation (SecurityContext population, cross-tenant rejection, service-to-service forwarding): framework and AuthZ Resolver responsibility.
- Barrier-aware tenant tree traversal (ancestor chains, descendant queries with `BarrierMode`): Tenant Resolver Plugin responsibility. AM provides source-of-truth data and direct children queries.
- AuthZ Resolver (PDP) implementation: covered by Cyber Fabric DESIGN; this module covers the tenant model consumed by PDP.
- Resource provisioning and lifecycle: covered by Resource Management System PRD.
- Tenant lifecycle events (CloudEvents): deferred until EVT (Events and Audit Bus) is introduced.

## 5. Functional Requirements

> **Testing strategy**: All requirements verified via automated tests (unit, integration, e2e) targeting 90%+ code coverage unless otherwise specified. Document verification method only for non-test approaches (analysis, inspection, demonstration).

### 5.1 Platform Bootstrap

#### Root Tenant Auto-Creation

- [ ] `p1` - **ID**: `cpt-cf-accounts-fr-root-tenant-creation`

**Actors**: `cpt-cf-accounts-actor-platform-admin`, `cpt-cf-accounts-actor-idp`

The system **MUST** automatically create the initial root tenant with status `active` when the AM service starts for the first time during platform installation. The root tenant type is determined by deployment configuration (typically the top-level type in the GTS tenant type hierarchy, e.g., `provider` or `root`). Additional root tenants (new trees in the forest) are created post-bootstrap via the Root Tenant Creation API.

- **Rationale**: The initial root tenant is the foundation of the first tenant tree; without it, no other tenants or operations can exist. The forest may grow with additional root tenants created by Platform Administrators.

#### Root Tenant IdP Linking

- [ ] `p1` - **ID**: `cpt-cf-accounts-fr-root-tenant-idp-link`

**Actors**: `cpt-cf-accounts-actor-platform-admin`, `cpt-cf-accounts-actor-idp`

During bootstrap, the system **MUST** invoke the tenant-provisioning operation for the root tenant — the same IdP integration contract used for every tenant creation — forwarding deployer-configured metadata so the IdP provider plugin can establish the tenant-to-IdP binding. The provider determines the appropriate action: adopting an existing IdP context (e.g., Keycloak master realm), creating a new one, or any other provider-specific behavior. If the provider returns provisioning metadata, AM persists it as tenant metadata; if the provider returns no metadata (binding established through external configuration or convention), AM proceeds normally. AM does not require identifier equality between its tenant UUID and the IdP's internal identifiers, nor does it validate binding sufficiency — that is the provider's responsibility. The initial Platform Administrator user identity is pre-provisioned in the IdP during infrastructure setup; AM does not create this user.

- **Rationale**: AM's obligation is to invoke the IdP contract at the right lifecycle moment and persist whatever the provider returns. Whether the binding is established through returned metadata, external IdP configuration, or convention is deployment-specific and provider-owned. AM owns the tenant model, not user identities — the IdP is the source of truth for admin credentials and authentication. The metadata pass-through keeps AM IdP-agnostic while giving the provider plugin enough context to determine deployment-specific behavior.

#### Bootstrap Idempotency

- [ ] `p1` - **ID**: `cpt-cf-accounts-fr-bootstrap-idempotency`

**Actors**: `cpt-cf-accounts-actor-platform-admin`

The system **MUST** detect an existing initial root tenant during platform upgrade or AM restart and preserve it without duplication; bootstrap **MUST** be a no-op when the initial root tenant already exists. Post-bootstrap root tenants created via the API are unaffected.

- **Rationale**: Platform upgrades and service restarts must not corrupt the tenant forest by creating duplicate root tenants.

#### Bootstrap Ordering

- [ ] `p1` - **ID**: `cpt-cf-accounts-fr-bootstrap-ordering`

**Actors**: `cpt-cf-accounts-actor-platform-admin`, `cpt-cf-accounts-actor-idp`

The system **MUST** wait for the IdP to be available before completing bootstrap, retrying with backoff, and failing after a configurable timeout if the IdP is not ready.

- **Rationale**: The root tenant cannot be fully operational without its associated IdP; proceeding without it would leave the platform in an inconsistent state.

### 5.2 Tenant Hierarchy Management

**Cross-cutting: Concurrency semantics** — Hierarchy-mutating operations (create, delete, status change, mode conversion) on overlapping tenant scopes **MUST** produce deterministic, serializable outcomes. Concurrent mutations on the same tenant **MUST** resolve without data corruption; conflicting operations **MUST** fail with the appropriate deterministic error category rather than producing partial state.

#### Create Root Tenant

- [ ] `p1` - **ID**: `cpt-cf-accounts-fr-create-root-tenant`

**Actors**: `cpt-cf-accounts-actor-platform-admin`

The system **MUST** allow a Platform Administrator to create a new root tenant (`parent_id = NULL`) with status `active`, establishing a new independent tree in the tenant forest. The root tenant type **MUST** be validated against GTS allowed root types. The operation **MUST** link the new root tenant to the IdP via the IdP integration contract. Only the Platform Administrator role is authorized to perform this operation; Tenant Administrators **MUST NOT** be able to create root tenants.

- **Rationale**: The forest model requires the ability to create multiple independent trees post-bootstrap for onboarding new organizations, vendors, or business units that operate independently.

#### Create Child Tenant

- [ ] `p1` - **ID**: `cpt-cf-accounts-fr-create-child-tenant`

**Actors**: `cpt-cf-accounts-actor-tenant-admin`

The system **MUST** allow an authenticated parent tenant administrator to create a new child tenant with a parent reference and status `active`, establishing the parent-child relationship immediately.

- **Rationale**: Creating sub-tenants is the core operation that builds the organizational hierarchy for all tenant models.

#### Tenant Hierarchy Depth Limit

- [ ] `p1` - **ID**: `cpt-cf-accounts-fr-hierarchy-depth-limit`

**Actors**: `cpt-cf-accounts-actor-tenant-admin`

The system **MUST** support a configurable hierarchy depth advisory threshold (default: 10 levels). When a child tenant creation would exceed the threshold, the system **MUST** emit an operator-visible warning signal and **MUST NOT** reject the operation. In v1, this warning signal MUST be observable by operators via platform monitoring infrastructure (metric increment and structured log entry); it is not a tenant lifecycle CloudEvent. Operators **MUST** be able to configure a strict mode that rejects creation above the threshold with a `tenant_depth_exceeded` error. The platform data model supports unlimited depth per the platform tenant model specification.

- **Rationale**: The platform architecture defines hierarchy depth as unlimited, but deep hierarchies impact query performance and operational complexity. A configurable advisory threshold provides operational visibility while preserving flexibility; strict mode is opt-in for deployments that need a hard cap.

#### Tenant Status Change

- [ ] `p1` - **ID**: `cpt-cf-accounts-fr-tenant-status-change`

**Actors**: `cpt-cf-accounts-actor-tenant-admin`

The system **MUST** allow an administrator to change a tenant's status between `active` and `suspended` and **MUST NOT** cascade suspension to child tenants; child tenants **MUST** remain active and fully operational when a parent is suspended. Transitioning to `deleted` is not permitted via status change — deletion **MUST** go through the dedicated soft-delete operation (`cpt-cf-accounts-fr-tenant-soft-delete`) which enforces child/resource preconditions.

**Operations on a suspended tenant:**

- Child tenant creation under a suspended parent **MUST** be rejected with a `validation` error.
- User provisioning within a suspended tenant **MUST** be rejected with a `validation` error.
- Metadata writes to a suspended tenant **MUST** be rejected with a `validation` error.
- Read operations (tenant details, children query, metadata resolution, user query) **MUST** remain available.
- Status change to `active` (unsuspend) and soft-delete **MUST** remain available.
- Mode conversion initiation from a suspended tenant **MUST** be rejected with a `validation` error.

- **Rationale**: Cascading suspension would disrupt downstream tenants (e.g., suspending a parent must not suspend its children). Each tenant's operational state must be independently controllable. Separating deletion from status updates ensures the child/resource guards cannot be bypassed. Blocking mutating operations on suspended tenants prevents inconsistent state while preserving read access and the ability to unsuspend or delete.

#### Tenant Soft Delete

- [ ] `p1` - **ID**: `cpt-cf-accounts-fr-tenant-soft-delete`

**Actors**: `cpt-cf-accounts-actor-tenant-admin`, `cpt-cf-accounts-actor-platform-admin`

The system **MUST** allow deletion of a tenant only when it has no non-deleted child tenants and no active resources, transitioning the tenant to `deleted` status (soft delete). If non-deleted children exist, deletion **MUST** be rejected with a `tenant_has_children` error. If active resources exist (validated via Resource Management System query), deletion **MUST** be rejected with a `tenant_has_resources` error. If RMS is unavailable, deletion **MUST** fail with `service_unavailable` rather than proceeding without the resource pre-check. Hard deletion **MUST** occur after a configurable retention period (default: 90 days). The hard-deletion process **MUST NOT** leave orphaned child tenant records. When a parent and child tenant share the same retention window, the hard-deletion background job **MUST** process leaf tenants before their parents (leaf-first ordering).

- **Rationale**: Preventing deletion of tenants with active children or resources protects organizational integrity and prevents orphaned data. Soft delete with retention enables recovery and compliance. Ensuring no orphaned child records prevents referential integrity violations during retention cleanup.

#### Children Query with Pagination

- [ ] `p1` - **ID**: `cpt-cf-accounts-fr-children-query`

**Actors**: `cpt-cf-accounts-actor-tenant-admin`

The system **MUST** return direct children of a given tenant with pagination support and optional status filtering.

- **Rationale**: Tenant administrators need a predictable way to browse and manage immediate children; deeper barrier-aware traversal is handled by Tenant Resolver.

#### Root Tenant Listing

- [ ] `p1` - **ID**: `cpt-cf-accounts-fr-root-tenant-listing`

**Actors**: `cpt-cf-accounts-actor-platform-admin`

The system **MUST** allow a Platform Administrator to list all root tenants in the forest with pagination support and optional status filtering. This is the only forest-level tenant discovery mechanism provided by AM.

- **Rationale**: Platform Administrators need to discover and manage root tenants without prior knowledge of specific tenant identifiers. Without this endpoint, there is no entry point for forest-level administrative workflows such as auditing, onboarding verification, or capacity planning.

#### Read Tenant Details

- [ ] `p1` - **ID**: `cpt-cf-accounts-fr-tenant-read`

**Actors**: `cpt-cf-accounts-actor-tenant-admin`, `cpt-cf-accounts-actor-platform-admin`

The system **MUST** return tenant details for a requested tenant identifier when the caller is authorized for that tenant scope. The response **MUST** include the tenant's identifier, parent reference, type, status, mode, and the timestamps required for administrative workflows and auditing.

- **Rationale**: Administrators need a reliable way to inspect current tenant state before making lifecycle, support, billing, and policy decisions.

#### Update Tenant Mutable Fields

- [ ] `p1` - **ID**: `cpt-cf-accounts-fr-tenant-update`

**Actors**: `cpt-cf-accounts-actor-tenant-admin`, `cpt-cf-accounts-actor-platform-admin`

The system **MUST** allow an authorized administrator to update only mutable tenant attributes through the general update operation: `name` and `status` (limited to `active` ↔ `suspended` transitions; `deleted` is handled exclusively by the soft-delete operation). The system **MUST** reject attempts to modify immutable hierarchy-defining fields such as `id`, `parent_id`, `tenant_type`, `self_managed`, and `depth`; mode changes remain handled by the dedicated conversion flow.

- **Rationale**: Administrative workflows require controlled edits to tenant presentation and lifecycle state without allowing accidental hierarchy or mode mutations through a generic update path. Restricting the update path to non-terminal status transitions ensures deletion guards (child/resource checks) cannot be bypassed.

### 5.3 Tenant Type Enforcement

#### Tenant Type Validation via GTS

- [ ] `p1` - **ID**: `cpt-cf-accounts-fr-tenant-type-enforcement`

**Actors**: `cpt-cf-accounts-actor-tenant-admin`, `cpt-cf-accounts-actor-gts-registry`

The system **MUST** enforce parent-child type constraints at creation time using the GTS types registry. Each tenant type defines `allowed_parent_types` and `can_be_root`. The system **MUST** reject creation when the child type is not permitted under the parent's type.

- **Rationale**: Enforcing type-based parent constraints ensures the business hierarchy remains well-formed and prevents invalid organizational structures.

Type topology is deployment-specific. Examples:

| Deployment model | Tenant types | Type rules |
|------------------|-------------|------------|
| **Flat** | `tenant` | `can_be_root: true, allowed_parent_types: []` — root placement only, no nesting |
| **Cloud hosting** | `provider`, `reseller`, `customer` | provider can parent reseller and customer; reseller can parent customer; customer is leaf |
| **Education** | `consortium`, `university`, `college` | consortium is root; university under consortium; college under university |
| **Enterprise** | `hq`, `region`, `unit` | hq is root; region under hq; unit under region |

#### Tenant Type Nesting

- [ ] `p1` - **ID**: `cpt-cf-accounts-fr-tenant-type-nesting`

**Actors**: `cpt-cf-accounts-actor-tenant-admin`

The system **MUST** allow same-type nesting when the GTS type definition permits it (e.g., `region` under `region` for multi-level structures) while maintaining an acyclic hierarchy.

- **Rationale**: Some real tenant topologies require repeated organizational tiers, and forbidding valid same-type nesting would force artificial type taxonomies.

### 5.4 Managed/Self-Managed Tenant Modes

#### Managed Tenant Creation

- [ ] `p1` - **ID**: `cpt-cf-accounts-fr-managed-tenant-creation`

**Actors**: `cpt-cf-accounts-actor-tenant-admin`

The system **MUST** allow creation of a managed child tenant (`self_managed=false`) that establishes no visibility barrier between parent and child, making the parent eligible for controlled access to the child's APIs and resources per policy.

- **Rationale**: The managed tenant model enables delegated administration where parent tenants directly manage child tenant environments.

#### Self-Managed Tenant Creation

- [ ] `p1` - **ID**: `cpt-cf-accounts-fr-self-managed-tenant-creation`

**Actors**: `cpt-cf-accounts-actor-tenant-admin`

The system **MUST** allow creation of a self-managed child tenant (`self_managed=true`) that establishes a visibility barrier; the parent **MUST** have no access to the child's APIs or resources by default.

- **Rationale**: The self-managed model enables autonomous operation where the child tenant operates independently with full isolation from the parent.

#### Managed to Self-Managed Conversion

- [ ] `p3` - **ID**: `cpt-cf-accounts-fr-managed-to-self-managed`

**Actors**: `cpt-cf-accounts-actor-tenant-admin`

The system **MUST** allow a managed tenant to convert to self-managed status unilaterally (no parent approval required); the barrier **MUST** be created synchronously with the conversion operation and the parent **MUST** lose all child resource access once the platform's enforcement layer (Tenant Resolver) reflects the updated barrier state. Propagation latency from AM's committed state to enforcement is a platform-level concern, not an AM requirement.

- **Rationale**: A child tenant must be able to become autonomous without depending on parent cooperation once the business relationship changes. The barrier is authoritative the moment AM commits it; downstream enforcement converges independently.

#### Self-Managed to Managed Conversion

- [ ] `p3` - **ID**: `cpt-cf-accounts-fr-self-managed-to-managed`

**Actors**: `cpt-cf-accounts-actor-tenant-admin`, `cpt-cf-accounts-actor-platform-admin`

The system **MUST** require both parent and child administrator consent to convert a self-managed tenant to managed status. Each side **MUST** be able to express consent from their own tenant scope — the child admin acts within the child tenant, and the parent admin acts within the parent tenant — so that no authorization-level barrier bypass is required. The domain service validates child state (exists, is a direct child, is self-managed, is active) through hierarchy-owner structural reads on AM's own data, consistent with the two-purpose pattern described in §3.3. The pending conversion **MUST** expire after 72 hours if the counterparty has not approved, with background cleanup cancelling expired requests. The pending conversion state **MUST** be durable (persisted before acknowledgment), and the approval-plus-barrier-removal step **MUST** be atomic or idempotently retriable so that a crash between approval and barrier removal does not leave the system in an inconsistent state. Concurrent conversion requests targeting the same tenant **MUST** produce deterministic outcomes: duplicate initiation from the same side **MUST** fail with `mode_change_pending`, while an opposite-side race either completes approval or returns `mode_change_pending` without violating the single-pending-request invariant.

- **Rationale**: Removing a barrier expands parent visibility and access, so the change requires bilateral consent and a bounded approval window. The authorization pipeline evaluates the parent admin's permissions within the parent scope only — no platform-level barrier bypass mode is invoked. Child-state validation is a hierarchy-owner structural read (the same pattern AM uses for deletion pre-checks and type validation), not an access-control decision.

#### Inbound Conversion Requests Query

- [ ] `p3` - **ID**: `cpt-cf-accounts-fr-conversion-requests-query`

**Actors**: `cpt-cf-accounts-actor-tenant-admin`

The system **MUST** allow a parent Tenant Admin to list pending inbound conversion requests targeting direct children of their tenant, with optional status filtering and pagination. The query **MUST** be scoped to the parent tenant (no barrier bypass required) and **MUST** return only conversion-request metadata (request identifier, child tenant identifier, child tenant name, initiating side, creation timestamp, expiry timestamp, status) — not the child tenant's full hierarchy, metadata, or resources. This endpoint is the discovery mechanism that enables the parent admin to learn about and act on pending self-managed-to-managed conversion requests that would otherwise be invisible due to the barrier.

- **Rationale**: Without a dedicated query endpoint, the parent admin has no way to discover pending conversion requests from self-managed children — the barrier blocks normal child visibility, creating a functional gap in the dual-consent flow. Exposing only conversion-request metadata (not child tenant data) preserves barrier semantics while enabling the approval workflow.

#### Conversion Request Cancellation

- [ ] `p3` - **ID**: `cpt-cf-accounts-fr-conversion-cancel`

**Actors**: `cpt-cf-accounts-actor-tenant-admin`

The system **MUST** allow either side of a pending conversion request to cancel it from their own tenant scope. The initiator cancels to withdraw the request; the counterparty cancels to reject it. Cancellation **MUST** transition the request to `cancelled` status and **MUST NOT** alter the tenant's current mode. If no pending conversion request exists for the target tenant, cancellation **MUST** fail with `not_found`.

- **Rationale**: Without explicit cancellation, the only way to dismiss an unwanted conversion request is to wait for the 72-hour expiry. Both sides need the ability to withdraw or reject promptly — the initiator may change their mind, and the counterparty may want to decline without waiting.

#### Managed Tenant Impersonation

- [ ] `p1` - **ID**: `cpt-cf-accounts-fr-managed-tenant-impersonation`

**Actors**: `cpt-cf-accounts-actor-tenant-admin`, `cpt-cf-accounts-actor-idp`

The system **MUST** support parent tenant administrator impersonation of managed child tenant administrators via a time-bounded impersonation token (configurable, default: 1 hour, maximum: 4 hours), obtained through the IdP integration contract. The platform authorization context **MUST** preserve both the caller's home tenant and the impersonated operating tenant so downstream authorization and auditing can distinguish them. Both identities **MUST** be recorded in the audit trail. This capability **MUST** remain feature-gated if the IdP implementation does not support impersonation tokens.

- **Rationale**: Impersonation is the primary mechanism for delegated administration, enabling parent tenant administrators to perform support and management actions in managed child tenant environments.

### 5.5 IdP Tenant & User Operations Contract

> All IdP operations remain subject to the platform's standard authentication and authorization pipeline, which enforces tenant barriers and cross-tenant visibility rules. AM does not implement an additional AM-specific barrier enforcement layer.

#### Tenant IdP Provisioning

- [ ] `p1` - **ID**: `cpt-cf-accounts-fr-idp-tenant-provision`

**Actors**: `cpt-cf-accounts-actor-tenant-admin`, `cpt-cf-accounts-actor-platform-admin`, `cpt-cf-accounts-actor-idp`

The system **MUST** invoke the tenant-provisioning operation of the IdP integration contract after every successful tenant creation (both root and child tenants). The call **MUST** pass the new tenant's identifier, name, type, parent identifier (if any), and any provider-specific provisioning metadata parameters from the creation request. The active IdP provider implementation decides whether to adopt an existing tenant context, create a new tenant-scoped context, or perform no tenant-specific provisioning. If the IdP call fails, the tenant creation **MUST** be rolled back and the caller **MUST** receive one of the deterministic AM error categories defined in §5.8. Provider-specific diagnostics MAY appear in error detail or audit logs, but **MUST NOT** change the public error code.

- **Rationale**: Different IdP implementations require different per-tenant resources (Keycloak uses realms, Azure AD uses directories, some providers need nothing). A pluggable tenant-provisioning hook keeps AM IdP-agnostic while allowing each provider to set up whatever tenant-scoped resources it needs at the right lifecycle moment.

#### Tenant IdP Deprovisioning

- [ ] `p1` - **ID**: `cpt-cf-accounts-fr-idp-tenant-deprovision`

**Actors**: `cpt-cf-accounts-actor-platform-admin`, `cpt-cf-accounts-actor-idp`

The system **MUST** invoke the tenant-deprovisioning operation of the IdP integration contract during tenant hard deletion (after the retention period expires). The call **MUST** pass the tenant's identifier and metadata so the provider can clean up any IdP-side resources created during provisioning. If the IdP call fails, the hard deletion **MUST** be retried rather than skipped, to prevent orphaned IdP resources.

- **Rationale**: Symmetric to tenant provisioning — providers that create per-tenant IdP resources need a lifecycle hook to clean them up. Running at hard-deletion time (not soft-delete) ensures the IdP resources remain available during the retention window in case the tenant is restored.

#### User Provisioning

- [ ] `p1` - **ID**: `cpt-cf-accounts-fr-idp-user-provision`

**Actors**: `cpt-cf-accounts-actor-tenant-admin`, `cpt-cf-accounts-actor-idp`

The system **MUST** provision a new user within a tenant scope by invoking the user-provisioning operation of the IdP integration contract, binding the user to the specified tenant. The IdP contract **MUST** set the tenant identity attribute on the user record. The caller **MUST** provide at least one unique user identifier; additional user attributes are provider-defined and passed through from the caller to the IdP contract. AM validates only tenant scope and status (the target tenant **MUST** be `active`); attribute validation is the IdP provider's responsibility.

- **Rationale**: Tenant-scoped provisioning is the primary administrative bridge between AM and a pluggable IdP implementation.

#### User Deprovisioning

- [ ] `p1` - **ID**: `cpt-cf-accounts-fr-idp-user-deprovision`

**Actors**: `cpt-cf-accounts-actor-tenant-admin`, `cpt-cf-accounts-actor-idp`

The system **MUST** deprovision a user by invoking the user-deprovisioning operation of the IdP integration contract, removing the user from the IdP and revoking active sessions.

- **Rationale**: Deprovisioning through the shared contract keeps AM intent and IdP identity state aligned while closing access promptly.

#### User Tenant Query

- [ ] `p1` - **ID**: `cpt-cf-accounts-fr-idp-user-query`

**Actors**: `cpt-cf-accounts-actor-tenant-admin`, `cpt-cf-accounts-actor-idp`

The system **MUST** support querying users belonging to a tenant scope by invoking the tenant-scoped user-query operation of the IdP integration contract with tenant filtering. The contract **MUST** support an optional user-ID filter to narrow results to a single user by their opaque IdP-issued identifier, enabling point-existence checks without a dedicated lookup operation.

- **Rationale**: Tenant-scoped user queries are required for administration and support. User-ID filtering enables callers to verify user existence before adding them to a Resource Group.

### 5.6 User Groups Management

> User groups are implemented as [Resource Group](../../resource-group/docs/PRD.md) entities. AM ensures the required Resource Group type exists; consumers use Resource Group's own group-management interfaces directly for all group operations. Resource Group owns hierarchy, membership lifecycle, cycle detection, and tenant-scoped isolation.

#### User Group Resource Group Type Registration

- [ ] `p1` - **ID**: `cpt-cf-accounts-fr-user-group-rg-type`

**Actors**: `cpt-cf-accounts-actor-platform-admin`

AM **MUST** register (or require via seeding) a Resource Group type for user groups with `allowed_memberships` including the platform user resource type. The type **MUST** support nesting (`allowed_parents` includes itself) and tenant-scoped placement. Registration happens during AM module initialization.

- **Rationale**: A dedicated Resource Group type ensures user group operations are governed by the same typed hierarchy, forest invariants, and tenant isolation rules as all other Resource Group entities, without reimplementing group infrastructure in AM.

#### User Group Lifecycle via Resource Group

- [ ] `p1` - **ID**: `cpt-cf-accounts-fr-user-group-lifecycle`

**Actors**: `cpt-cf-accounts-actor-tenant-admin`

The system **MUST** allow a tenant administrator to create, update, and delete user groups within their tenant scope. Group identifiers **MUST** be unique within the tenant scope (enforced by Resource Group). Consumers interact with Resource Group directly — AM does not proxy group CRUD.

- **Rationale**: Resource Group already provides typed hierarchy, tenant scoping, and forest invariants. A separate AM proxy layer would add no domain logic beyond pass-through. AM's tenant-scoped user-query capability provides the valid user set that callers combine with Resource Group membership operations.

#### User Group Membership via Resource Group

- [ ] `p1` - **ID**: `cpt-cf-accounts-fr-user-group-membership`

**Actors**: `cpt-cf-accounts-actor-tenant-admin`

The system **MUST** allow a tenant administrator to add and remove users from a group via Resource Group membership operations using the platform user resource identity. Resource Group enforces tenant compatibility and duplicate detection. Callers verify user existence via AM's tenant-scoped user-query capability before adding membership; Resource Group treats the user identifier as opaque.

- **Rationale**: Administrators need direct control of membership; Resource Group's existing membership contract (composite key, tenant-scoping, conflict detection) satisfies this without duplication. User existence validation is a caller responsibility, not a structural invariant.

#### Nested User Groups

- [ ] `p1` - **ID**: `cpt-cf-accounts-fr-nested-user-groups`

**Actors**: `cpt-cf-accounts-actor-tenant-admin`

The system **MUST** support nested user groups via Resource Group's parent-child hierarchy so that members of an inner group inherit the outer group's permissions. Cycle detection is enforced by Resource Group's forest invariants.

- **Rationale**: Resource Group already provides strict forest enforcement (single parent, no cycles) and closure-table traversal — reusing it avoids duplicating cycle detection and hierarchy query logic.

### 5.7 Extensible Tenant Metadata

#### Tenant Metadata Schema Registration

- [ ] `p2` - **ID**: `cpt-cf-accounts-fr-tenant-metadata-schema`

**Actors**: `cpt-cf-accounts-actor-platform-admin`, `cpt-cf-accounts-actor-gts-registry`

The system **MUST** support extensible tenant metadata via GTS-registered schemas. Each schema defines a metadata kind (e.g., `branding`, `contacts`, `billing-address`), validation rules, and an inheritance policy (`inherit` — child inherits parent value unless overridden, or `override-only` — no inheritance). New metadata kinds **MUST** be registerable at runtime via GTS without code changes, consistent with tenant type extensibility.

- **Rationale**: A generic metadata mechanism avoids feature-specific APIs for each new tenant data kind. Branding, company contacts, billing addresses, and future tenant attributes all share the same storage, validation, and inheritance contract.

#### Tenant Metadata CRUD

- [ ] `p2` - **ID**: `cpt-cf-accounts-fr-tenant-metadata-crud`

**Actors**: `cpt-cf-accounts-actor-tenant-admin`

The system **MUST** allow a tenant administrator to create, read, update, and delete metadata entries of any registered kind within their tenant scope. Writes **MUST** be validated against the GTS schema for the metadata kind. Child tenants **MUST** be able to override inherited metadata when the schema's inheritance policy is `inherit`.

- **Rationale**: Tenant administrators need self-service control over tenant-specific data without platform-level intervention for each new metadata kind.

#### Tenant Metadata Resolution API

- [ ] `p2` - **ID**: `cpt-cf-accounts-fr-tenant-metadata-api`

**Actors**: `cpt-cf-accounts-actor-tenant-admin`

The system **MUST** provide a metadata resolution API that returns the effective metadata value for a given tenant and metadata kind, applying the schema's inheritance policy (walking up the hierarchy for `inherit` schemas, returning the tenant's own value or empty for `override-only` schemas). For `inherit` schemas, the ancestor walk **MUST** stop at self-managed boundaries: a self-managed tenant's resolved value considers only its own metadata entries (and its own descendants' overrides), never inheriting from ancestors above the barrier. This means a self-managed tenant with no own value resolves to `empty`, the same as a root tenant. Consuming components (portals, billing, etc.) use the resolved metadata for rendering or processing; AM does not interpret metadata content.

- **Rationale**: A single resolution API with per-schema inheritance gives consumers one consistent contract instead of re-implementing resolution per metadata kind. Stopping inheritance at self-managed boundaries preserves the core isolation invariant — a self-managed tenant is fully independent, including its metadata — without requiring `BarrierMode::Ignore` for metadata operations.

### 5.8 Deterministic Error Semantics

- [ ] `p1` - **ID**: `cpt-cf-accounts-fr-deterministic-errors`

**Actors**: `cpt-cf-accounts-actor-tenant-admin`, `cpt-cf-accounts-actor-platform-admin`

The module **MUST** map all failures to deterministic categories:

- `validation` (invalid input, missing required fields)
- `not_found` (tenant, group, or user not found)
- `conflict` (`tenant_has_children`, `tenant_has_resources`, `tenant_depth_exceeded`, `type_not_allowed`, `mode_change_pending`)
- `cross_tenant_denied` (barrier violation, unauthorized cross-tenant access, non-platform-admin attempting root-tenant-scoped operations)
- `idp_unavailable` (IdP contract call failed or timed out)
- `idp_unsupported_operation` (IdP implementation does not support the requested operation, e.g., impersonation)
- `service_unavailable`
- `internal`

- **Rationale**: Deterministic error categories let API clients, automation, and operators react consistently across tenant models and IdP providers.

Provider-specific diagnostics MAY be included in RFC 9457 `detail` fields and audit logs, but the public `code` value **MUST** remain one of the deterministic categories above.

**Integration failure behavior:**

- If GTS Registry is unavailable during tenant creation (type validation), the operation MUST fail with `service_unavailable`.
- If Resource Group is unavailable during module initialization (user group type registration), AM MUST retry with backoff.
- Tenant Resolver sync failure is owned by Tenant Resolver — AM ensures data consistency at the source; projection staleness is a Tenant Resolver concern.

### 5.9 Observability Metrics

#### Domain-Specific Metrics Export

- [ ] `p1` - **ID**: `cpt-cf-accounts-fr-observability-metrics`

**Actors**: `cpt-cf-accounts-actor-platform-admin`

The module **MUST** export domain-specific metrics that the platform HTTP middleware and database cannot provide. Observable concerns include: IdP contract call latency and error rates (by operation), GTS type validation latency, metadata resolution latency (by inheritance policy), bootstrap duration, hard-deletion job throughput, conversion request expiration counts, hierarchy-depth advisory threshold exceedance counts, and security-relevant counters (impersonation outcomes, cross-tenant denials). Metric names and labels **MUST** follow platform observability conventions. The DESIGN specifies which metrics are module-internal versus already captured by the platform middleware, and the concrete metric names, labels, and instrumentation strategy.

- **Rationale**: Operators need visibility into AM-specific domain operations (external dependency health, internal sub-operation latencies, security event counts) that platform-level middleware cannot provide. The boundary between platform-provided and module-internal metrics is an implementation concern owned by the DESIGN.

## 6. Non-Functional Requirements

> **Global baselines**: Project-wide NFRs (performance, security, reliability, scalability) defined in root PRD. Document only module-specific NFRs here: **exclusions** from defaults or **standalone** requirements.
>
> **Testing strategy**: NFRs verified via automated benchmarks, security scans, and monitoring unless otherwise specified.

### 6.1 Tenant Context Validation Latency

- [ ] `p1` - **ID**: `cpt-cf-accounts-nfr-context-validation-latency`

AM data access and source-of-truth lookups **MUST** enable end-to-end tenant-context validation to complete in p95 ≤ 5ms under normal load when resolver-side caching is enabled.

- **Threshold**: 5ms at p95 under normal load, measured end-to-end across the tenant-context validation path
- **Rationale**: Tenant context is validated on every API call in the AuthN/AuthZ path. AM is not the enforcement point, but its data model and lookup behavior must not prevent the platform from meeting this request-path SLO.

**Response time expectations for AM operations:**

- Tenant CRUD operations (create, read, update, delete): p95 ≤ 200 ms under normal load (excluding IdP-dependent operations)
- IdP-delegated user operations (provision, deprovision, query): p95 ≤ 500 ms (dominated by external IdP latency)
- Metadata resolution API: p95 ≤ 50 ms for cached schemas, ≤ 200 ms for uncached
- Children query with pagination: p95 ≤ 100 ms

### 6.2 Authentication Context

- [ ] `p1` - **ID**: `cpt-cf-accounts-nfr-authentication-context`

AM API endpoints require authenticated requests via platform SecurityContext (reference IAM PRD for mechanism).

- **MFA**: Required for administrative operations (tenant creation, mode conversion, impersonation) — deferred to platform AuthN policy.
- **SSO/federation**: The IdP contract supports any conforming provider (Keycloak, Azure AD, Okta) — SSO expectations are IdP-owned.
- **Session management**: Impersonation sessions have explicit time bounds (default 1h, max 4h); general API session management follows platform defaults.

### 6.3 Tenant Isolation Integrity

- [ ] `p1` - **ID**: `cpt-cf-accounts-nfr-tenant-isolation`

Tenant A **MUST NOT** be able to access Tenant B data through any API or data access path, verified by automated security tests.

- **Threshold**: Zero cross-tenant data leaks in automated security test suite
- **Verification Method**: Automated security tests with cross-tenant access attempts in multi-tenant test environments

### 6.4 Audit Trail Completeness

- [ ] `p1` - **ID**: `cpt-cf-accounts-nfr-audit-completeness`

Every tenant configuration change **MUST** be recorded in the local audit log with actor identity, tenant identity, and change details. Audit logs **MUST** be append-only.

- **Threshold**: 100% of tenant configuration changes recorded; zero audit gaps

**Compliance reporting**: AM audit data MUST be available to platform-level compliance reporting tools. Report format and generation are platform concerns.

**Forensic support**: Audit logs MUST include correlation identifiers (request ID, trace ID) to support incident investigation. Log tamper-evidence is a platform audit infrastructure concern.

**Non-repudiation**: All administrative actions MUST be attributable to a specific authenticated identity via the SecurityContext audit trail.

### 6.5 Barrier Enforcement

- [ ] `p1` - **ID**: `cpt-cf-accounts-nfr-barrier-enforcement`

AM barrier state and tenant metadata **MUST** be sufficient for Tenant Resolver and AuthZ Resolver to enforce managed and self-managed access controls at the query level. AM **MUST** audit all barrier-state-changing operations it owns (mode conversions, `self_managed` flag writes) per `cpt-cf-accounts-nfr-audit-completeness`. Cross-tenant access auditing (barrier traversals, `BarrierMode::Ignore` usage) is a platform AuthZ concern — AM does not observe or audit downstream enforcement decisions.

- **Threshold**: Zero unauthorized cross-barrier accesses attributable to missing or stale AM source data; 100% of AM-owned barrier-state changes audited
- **Rationale**: AM owns the source data for barrier semantics; missing or ambiguous barrier state would undermine downstream authorization behavior. Audit of cross-tenant access events belongs to the enforcement layer (AuthZ Resolver) that evaluates the access decisions, not the data layer (AM) that supplies the inputs.

### 6.6 Tenant Model Versatility

- [ ] `p2` - **ID**: `cpt-cf-accounts-nfr-tenant-model-versatility`

The tenant model **MUST** support both managed (no barrier) and self-managed (with barriers) patterns within the same tenant tree, with `BarrierMode` enabling selective barrier bypass for downstream billing and administrative operations.

- **Threshold**: Both managed and self-managed tenant creation, resolver-side traversal, and access patterns function correctly in the same hierarchy
- **Rationale**: Supporting both tenant models in one hierarchy is the core product differentiator that lets Cyber Fabric serve MSP and autonomous-customer deployments without separate control planes.

### 6.7 API and SDK Compatibility

- [ ] `p1` - **ID**: `cpt-cf-accounts-nfr-compatibility`

Published REST APIs **MUST** follow path-based versioning. SDK client and IdP integration contracts are stable interfaces — breaking changes **MUST** follow platform versioning policy and require a new contract version with a migration path for consumers.

- **Threshold**: No breaking API or contract changes within a published minor release; any break requires a new major API or contract version plus a documented migration path
- **Rationale**: AM is a foundational dependency for portals, automation, and resolver integrations, so compatibility policy must be explicit.

### 6.8 Expected Production Scale

- [ ] `p1` - **ID**: `cpt-cf-accounts-nfr-production-scale`

The platform team **MUST** define and approve a canonical AM deployment profile before DESIGN sign-off. At minimum, the profile **MUST** specify target values for the following dimensions and keep them within, or explicitly revise, the current planning envelope.

| Dimension | Current Planning Envelope |
|-----------|---------------------------|
| Tenants (hierarchy nodes) | 1K–100K |
| Typical hierarchy depth | 3–10 levels (unlimited supported; advisory threshold default: 10) |
| Users (across all tenants) | 10K–1M |
| User groups (Resource Group entities) | 1K–50K (stored in Resource Group) |
| Group memberships (Resource Group membership links) | 10K–500K (stored in Resource Group) |
| Concurrent API requests (peak) | 100–10K rps |

- **Threshold**: 100% of the listed dimensions have an approved target before DESIGN sign-off
- **Rationale**: AM indexing, partitioning, cache sizing, and projection freshness budgets depend on explicit scale inputs rather than implicit assumptions.

Tenant-context validation (NFR 6.1) must hold against the approved deployment profile. DESIGN.md must document how the chosen profile drives indexing, partitioning, and memory sizing.

**Growth expectation**: The platform team expects to reach the upper end of the planning envelope (100K tenants, 1M users) within 2-3 years of GA. The DESIGN SHOULD plan indexing and partitioning strategies to accommodate this trajectory.

**Burst and seasonal traffic patterns**: Burst and seasonal traffic patterns are deployment-specific and are captured in the deployment profile approved by the platform team.

### 6.9 Data Classification

AM stores tenant hierarchy structure, tenant metadata (names, types, modes, status), extensible metadata entries (GTS-schema-validated, e.g., branding, contacts), and user identifiers used as opaque references. User group hierarchy and membership data are stored by the Resource Group module. Tenant hierarchy may reveal commercial relationships between organizations. During administrative lifecycle operations, AM also exchanges identity-linked payloads with the IdP for provisioning, deprovisioning, and tenant-scoped user queries. AM is not the system of record for authentication credentials or user profile PII, but it does process identity-related data in transit and may record identity references in audit logs.

**Classification levels**: Tenant hierarchy metadata (names, types, modes, parent-child relationships) = Internal/Confidential. Identity references recorded in audit logs = PII-adjacent. Extensible metadata = classification varies by GTS schema (determined at schema registration time).

**Cross-border data transfer**: Deferred to platform-level data residency controls. AM does not independently transfer data across jurisdictions.

**PII handling in transit**: Identity-linked payloads processed in transit MUST be encrypted via platform TLS and MUST NOT be persistently cached by AM.

**Anonymization**: User identifiers in audit logs: Anonymization requirements after user deprovisioning are deferred to platform audit retention policy.

**Privacy by Design (SEC-PRD-005)**: Covered by platform privacy defaults rather than a standalone AM-only NFR. AM must minimize persisted user attributes, treat IdP-managed identity payloads as transient administrative data, and avoid storing profile data returned by IdP unless a downstream contract explicitly requires it. Tenant hierarchy metadata remains commercially sensitive and must be protected by barrier-aware visibility controls. Hierarchy queries with barrier bypass (`BarrierMode::Ignore`) are restricted to authorized platform-level operations and are audited by the platform AuthZ layer (AuthZ Resolver) — not by AM, consistent with NFR 6.5.

- **Purpose limitation**: AM-stored identity references MUST only be used for tenant-scoped administrative operations and audit traceability.
- **Storage limitation**: Retention of user identifiers in audit logs follows platform audit retention policy. AM-specific retention is limited to the soft-delete retention period (default 90 days).
- **Privacy-by-default**: New tenant creation defaults to the mode specified by the creating administrator. AM does not impose a default management mode — the choice is explicit per-creation.
- **Pseudonymization**: Pseudonymization of user identifiers in audit logs after user deprovisioning is deferred to platform audit policy.

### 6.10 Reliability

- **Availability**: AM inherits the platform core infrastructure SLA (target: 99.9% uptime). As a foundational module consumed by Tenant Resolver and AuthZ Resolver, AM availability directly impacts platform-wide authorization. Degraded mode: When IdP is unavailable, AM MUST continue serving tenant hierarchy reads and non-IdP-dependent admin operations (for example tenant reads, children queries, metadata resolution, and status changes). Bootstrap, tenant creation, and IdP-delegated user or impersonation operations fail or retry per their contracts, typically surfacing `idp_unavailable`. Maintenance windows follow platform scheduling.
- **Recovery**: RPO/RTO follow platform defaults for stateful services (target: RPO ≤ 1 hour, RTO ≤ 15 minutes). AM's tenant hierarchy table is the authoritative source of truth — backup and point-in-time recovery are provided by the platform database infrastructure. No module-specific disaster recovery requirements beyond platform defaults.

### 6.11 Data Lifecycle

- [ ] `p1` - **ID**: `cpt-cf-accounts-nfr-data-lifecycle`

Data lifecycle follows platform defaults. Tenant deprovisioning **MUST** cascade-delete associated extensible metadata entries and trigger Resource Group cleanup for user groups and memberships scoped to the deprovisioned tenant. Soft-deleted tenants are hard-deleted after the configured retention period (default: 90 days). Data archival and purging are handled at platform infrastructure level. No module-specific retention policy beyond platform defaults.

- **Threshold**: 100% of tenant-scoped group and metadata records are removed during tenant deprovisioning; hard deletion occurs after the configured retention period
- **Rationale**: AM owns tenant-scoped administrative metadata that must not outlive its tenant beyond the configured retention window.

### 6.12 Data Quality

- [ ] `p2` - **ID**: `cpt-cf-accounts-nfr-data-quality`

- **Data freshness**: AM hierarchy changes **MUST** be committed transactionally and immediately visible in the source-of-truth `tenants` table. The end-to-end SLO that Tenant Resolver projections reflect these changes within 30 seconds under normal load is a **platform-level target** requiring Tenant Resolver's sync mechanism; AM's contribution is transactional commit visibility and schema stability (see `cpt-cf-accounts-nfr-compatibility`). DESIGN must document AM's freshness contribution and the interface contract that enables Tenant Resolver to meet the platform SLO.
- **Data consistency**: AM **MUST** support hierarchy integrity checks (orphaned children, broken parent references, depth mismatches) as a diagnostic capability. DESIGN must specify the verification mechanism and test plan.
- **Data completeness**: Mandatory fields (name, type, status) **MUST** be non-null and validated at creation.

### NFR Exclusions

- **Offline support**: Not applicable. AM is a server-side platform service and does not operate in offline mode.
- **Usability (UX)**: Not applicable at module level — AM exposes REST API and SDK traits. Portal UI is a separate concern.
- **Compliance (COMPL)**: AM acts as a data processor for identity-linked payloads during user lifecycle operations. Applicable data protection regulations (e.g., GDPR processor obligations) are enforced at the platform level. AM's data minimization and transient-data handling requirements (6.9) satisfy module-level processor obligations. Data sovereignty requirements for tenant hierarchy metadata follow platform-level data residency controls. Compliance certification requirements (SOC 2, ISO 27001, etc.) are platform-level obligations. AM follows platform security and audit standards that contribute to these certifications.
- **Safety (SAFE)**: Not applicable — AM is a pure information system with no physical interaction or safety-critical operations.
- **Operations (OPS)**: Not applicable — AM follows standard CyberFabric deployment and monitoring patterns. No module-specific operational requirements beyond platform defaults.
- **Maintainability / Documentation (MAINT)**: Not applicable at PRD level — SDK trait documentation and REST API OpenAPI specification follow platform documentation standards. No module-specific documentation requirements beyond platform defaults.
- **Geographic distribution**: Not applicable at module level — AM follows platform deployment topology. Data residency and cross-region replication are platform infrastructure concerns.
- **Rate limiting**: Not applicable at module level — API rate limiting is enforced by the platform API gateway. AM does not implement module-specific throttling.

## 7. Public Library Interfaces

### 7.1 Public API Surface

#### Tenant Management API

- [ ] `p1` - **ID**: `cpt-cf-accounts-interface-tenant-mgmt-api`

- **Type**: REST API
- **Stability**: stable
- **Description**: API for tenant CRUD operations (including root tenant creation and root tenant listing — Platform Administrator only), hierarchy management (including direct children queries), status changes, mode configuration (managed/self-managed), and conversion request discovery.
- **Breaking Change Policy**: Major version bump required for endpoint removal or incompatible request/response schema changes.

#### Tenant Metadata API

- [ ] `p2` - **ID**: `cpt-cf-accounts-interface-tenant-metadata-api`

- **Type**: REST API
- **Stability**: stable
- **Description**: API for CRUD and resolution of extensible tenant metadata. Metadata kinds (e.g., branding, contacts, billing-address) are defined by GTS-registered schemas with per-schema inheritance policy and validation.
- **Breaking Change Policy**: Major version bump required for endpoint removal or incompatible request/response schema changes.

#### User Operations API

- [ ] `p1` - **ID**: `cpt-cf-accounts-interface-user-ops-api`

- **Type**: REST API
- **Stability**: stable
- **Description**: API for tenant-scoped user provisioning, deprovisioning, and query operations delegated to the configured IdP provider contract.
- **Breaking Change Policy**: Major version bump required for endpoint removal or incompatible request/response schema changes.

### 7.2 External Integration Contracts

IdP contract implementations are expected to align with SCIM 2.0 for user provisioning and OIDC for authentication where applicable.

#### IdP Provider Contract

- [ ] `p1` - **ID**: `cpt-cf-accounts-contract-idp-provider`

- **Direction**: required from client (IdP implementation via pluggable IdP integration contract)
- **Protocol/Format**: Pluggable contract (in-process or remote)
- **Compatibility**: AM depends on IdP for user provisioning, deprovisioning, tenant binding, and optional impersonation token issuance. AM must tolerate IdP unavailability during bootstrap with retry/backoff. Provider implementations are vendor-replaceable.

#### Tenant Resolver Plugin Data Contract

- [ ] `p1` - **ID**: `cpt-cf-accounts-contract-tenant-resolver`

- **Direction**: provided by library (tenant hierarchy data for Resolver consumption)
- **Protocol/Format**: Database-level data contract (source-of-truth tenant tables consumed by Resolver sync)
- **Compatibility**: Schema changes to source-of-truth tenant tables require coordinated update with Tenant Resolver Plugin. Schema migrations to source-of-truth tenant tables MUST be backward-compatible within a minor release to support rolling upgrades where AM and Tenant Resolver may temporarily run different versions.

#### AuthZ Resolver Integration

- [ ] `p1` - **ID**: `cpt-cf-accounts-contract-authz-resolver`

- **Direction**: provided by library (tenant context and hierarchy data for authorization decisions)
- **Protocol/Format**: SecurityContext propagation via Cyber Fabric framework
- **Compatibility**: Changes to SecurityContext tenant fields require coordinated update with AuthZ Resolver Plugin.

## 8. Use Cases

### 8.1 Bootstrap

#### Scenario: Root Tenant Auto-Created on First Start

- [ ] `p1` - **ID**: `cpt-cf-accounts-usecase-root-bootstrap`

**Actor**: `cpt-cf-accounts-actor-platform-admin`, `cpt-cf-accounts-actor-idp`

**Preconditions**:
- AM starts for the first time during platform installation
- IdP is available

**Main Flow**:
1. AM starts the bootstrap procedure.
2. System creates the initial root tenant with status `active` and the configured root type.
3. System invokes the tenant-provisioning operation with the deployer-configured bootstrap metadata (e.g., `{ "adopt_realm": "master" }`), enabling the IdP provider plugin to adopt the pre-existing IdP context and configure tenant identity claim mapping.
4. System records the bootstrap operation in the audit log.

**Postconditions**:
- Initial root tenant exists and is linked to IdP
- Tenant provisioning completed without error; any provider-returned metadata is persisted as tenant metadata
- Bootstrap completion state is persisted for subsequent restarts

**Alternative Flows**:
- **IdP unavailable**: See `cpt-cf-accounts-usecase-bootstrap-waits-idp`

#### Scenario: Bootstrap Is Idempotent

- [ ] `p1` - **ID**: `cpt-cf-accounts-usecase-bootstrap-idempotent`

**Actor**: `cpt-cf-accounts-actor-platform-admin`

**Preconditions**:
- Initial root tenant already exists from a previous bootstrap

**Main Flow**:
1. AM restarts or the platform runs an upgrade.
2. Bootstrap checks whether the initial root tenant already exists.
3. System detects the existing tenant and performs no additional create operation.

**Postconditions**:
- No duplicate root tenant is created
- Existing root tenant remains unchanged

**Alternative Flows**:
- **None**: No additional alternative flows beyond standard restart handling

#### Scenario: Bootstrap Waits for IdP

- [ ] `p1` - **ID**: `cpt-cf-accounts-usecase-bootstrap-waits-idp`

**Actor**: `cpt-cf-accounts-actor-platform-admin`, `cpt-cf-accounts-actor-idp`

**Preconditions**:
- AM bootstrap begins
- IdP is not yet available

**Main Flow**:
1. System starts bootstrap and checks IdP availability.
2. System detects that the IdP is unavailable.
3. System retries with backoff until the IdP becomes available or the configured timeout is reached.
4. If the IdP becomes available before the timeout, bootstrap continues.

**Postconditions**:
- Bootstrap resumes only after IdP availability is confirmed, or stops at the timeout boundary

**Alternative Flows**:
- **Timeout expires**: Bootstrap fails with `idp_unavailable`

### 8.2 Tenant Lifecycle

#### Scenario: Create Root Tenant (New Tree in Forest)

- [ ] `p1` - **ID**: `cpt-cf-accounts-usecase-create-root-tenant`

**Actor**: `cpt-cf-accounts-actor-platform-admin`

**Preconditions**:
- Caller is Platform Administrator
- GTS registry defines `vendor` as an allowed root type

**Main Flow**:
1. Platform Administrator submits a root tenant create request with type `vendor` and name `"Acme Corp"`.
2. System validates that `vendor` is allowed as a root tenant type.
3. System creates the root tenant with `parent_id = NULL`, status `active`, and type `vendor`.
4. System links the root tenant to the IdP via the IdP integration contract.
5. System records the operation in the audit log.

**Postconditions**:
- A new independent tree is established in the tenant forest
- The new root tenant exists and is linked to IdP

**Alternative Flows**:
- **Root type not allowed**: Request is rejected by GTS validation before tenant creation

#### Scenario: Reject Root Tenant Creation — Insufficient Privileges

- [ ] `p2` - **ID**: `cpt-cf-accounts-usecase-reject-root-tenant-no-privilege`

**Actor**: `cpt-cf-accounts-actor-tenant-admin`

**Preconditions**:
- Caller is Tenant Administrator and not Platform Administrator

**Main Flow**:
1. Caller submits a request to create a root tenant with `parent_id = NULL`.
2. System evaluates the caller's privileges for root tenant creation.
3. System rejects the request.

**Postconditions**:
- No root tenant is created
- Caller receives `cross_tenant_denied`

**Alternative Flows**:
- **None**: No additional alternative flows beyond the authorization failure

#### Scenario: Create Child Tenant

- [ ] `p1` - **ID**: `cpt-cf-accounts-usecase-create-child-tenant`

**Actor**: `cpt-cf-accounts-actor-tenant-admin`

**Preconditions**:
- Parent tenant `T1` exists with status `active` and type `org`
- GTS registry allows type `division` under `org`
- Hierarchy depth is below the advisory threshold

**Main Flow**:
1. Tenant admin of `T1` submits a child tenant create request with type `division`, name `"East Division"`, and mode `self_managed=false`.
2. System validates parent status, type constraints, and current hierarchy depth.
3. System creates the child tenant with status `active`, parent `T1`, and managed mode.
4. Hierarchy projection converges on the next sync cycle.

**Postconditions**:
- Child tenant exists under `T1`
- Hierarchy projection reflects the new child after synchronization

**Alternative Flows**:
- **Type not allowed under parent**: See `cpt-cf-accounts-usecase-reject-type-not-allowed`
- **Depth threshold exceeded**: See `cpt-cf-accounts-usecase-warn-depth-exceeded`
- **Strict depth limit exceeded**: See `cpt-cf-accounts-usecase-reject-depth-exceeded`

#### Scenario: Read Tenant Details

- [ ] `p1` - **ID**: `cpt-cf-accounts-usecase-read-tenant`

**Actor**: `cpt-cf-accounts-actor-tenant-admin`

**Preconditions**:
- Tenant `T2` exists
- Caller is authorized to read `T2`

**Main Flow**:
1. Tenant administrator requests tenant details for `T2`.
2. System validates read access for the requested tenant scope.
3. System returns the current tenant details, including status, type, mode, parent reference, and audit timestamps.

**Postconditions**:
- Caller receives the current state of `T2`
- No tenant state is modified

**Alternative Flows**:
- **Tenant not found**: Request fails with `not_found`
- **Caller lacks access**: Request fails with `cross_tenant_denied`

#### Scenario: Update Tenant Mutable Fields

- [ ] `p1` - **ID**: `cpt-cf-accounts-usecase-update-tenant`

**Actor**: `cpt-cf-accounts-actor-tenant-admin`

**Preconditions**:
- Tenant `T2` exists and is not deleted
- Caller is authorized to update `T2`

**Main Flow**:
1. Tenant administrator submits an update request for `T2` with a new `name` and/or `status`.
2. System validates that only mutable fields are present in the request.
3. System applies the permitted changes.
4. System records the change in the audit log.

**Postconditions**:
- `T2` reflects the updated mutable fields
- Audit trail records the update operation

**Alternative Flows**:
- **Immutable field included**: Request fails with `validation`
- **Deleted tenant targeted**: Request fails because deleted tenants are immutable

#### Scenario: Reject Create — Type Not Allowed Under Parent

- [ ] `p2` - **ID**: `cpt-cf-accounts-usecase-reject-type-not-allowed`

**Actor**: `cpt-cf-accounts-actor-tenant-admin`

**Preconditions**:
- Parent tenant `T1` has type `team`
- GTS registry defines `team` as a leaf type with no children allowed

**Main Flow**:
1. Tenant admin submits a child tenant create request under `T1`.
2. System validates the requested parent-child type relationship against GTS rules.
3. System rejects the request.

**Postconditions**:
- No child tenant is created under `T1`
- Caller receives `type_not_allowed`

**Alternative Flows**:
- **None**: No additional alternative flows beyond the validation failure

#### Scenario: Warn — Depth Advisory Threshold Exceeded

- [ ] `p2` - **ID**: `cpt-cf-accounts-usecase-warn-depth-exceeded`

**Actor**: `cpt-cf-accounts-actor-tenant-admin`

**Preconditions**:
- Hierarchy depth is at the advisory threshold, for example 10 levels

**Main Flow**:
1. Tenant admin submits a request to create a child at depth 11.
2. System detects that the advisory threshold would be exceeded.
3. System creates the child tenant successfully.
4. System increments the `am_depth_threshold_exceeded_total` metric and writes a structured warning log entry for operators.

**Postconditions**:
- Child tenant exists beyond the advisory threshold
- Operator-visible warning signal is emitted for operators

**Alternative Flows**:
- **Strict mode enabled**: See `cpt-cf-accounts-usecase-reject-depth-exceeded`

#### Scenario: Reject Create — Depth Hard Limit (Strict Mode)

- [ ] `p2` - **ID**: `cpt-cf-accounts-usecase-reject-depth-exceeded`

**Actor**: `cpt-cf-accounts-actor-tenant-admin`

**Preconditions**:
- Strict depth mode is enabled with a hard limit, for example 10 levels
- Hierarchy depth is already at the hard limit

**Main Flow**:
1. Tenant admin submits a request to create a child at depth 11.
2. System evaluates the request against the strict depth limit.
3. System rejects the request.

**Postconditions**:
- No child tenant is created
- Caller receives `tenant_depth_exceeded`

**Alternative Flows**:
- **None**: No additional alternative flows beyond the limit rejection

#### Scenario: Suspend Tenant Without Cascading

- [ ] `p1` - **ID**: `cpt-cf-accounts-usecase-suspend-no-cascade`

**Actor**: `cpt-cf-accounts-actor-tenant-admin`, `cpt-cf-accounts-actor-platform-admin`

**Preconditions**:
- Tenant `T2` has child tenants `[T3, T4]` in `active` status

**Main Flow**:
1. Administrator submits a request to suspend `T2`.
2. System updates `T2` status to `suspended`.
3. System leaves child tenants `T3` and `T4` unchanged.

**Postconditions**:
- `T2` is `suspended`
- `T3` and `T4` remain `active` and fully operational

**Alternative Flows**:
- **None**: No additional alternative flows beyond the status update

#### Scenario: Reject Delete — Tenant Has Children

- [ ] `p2` - **ID**: `cpt-cf-accounts-usecase-reject-delete-has-children`

**Actor**: `cpt-cf-accounts-actor-tenant-admin`, `cpt-cf-accounts-actor-platform-admin`

**Preconditions**:
- Tenant `T2` has non-deleted child `T3`

**Main Flow**:
1. Administrator submits a request to delete `T2`.
2. System checks for non-deleted child tenants.
3. System rejects the delete operation.

**Postconditions**:
- `T2` remains unchanged
- Caller receives `tenant_has_children`

**Alternative Flows**:
- **None**: No additional alternative flows beyond the child-presence check

#### Scenario: Soft Delete Leaf Tenant

- [ ] `p1` - **ID**: `cpt-cf-accounts-usecase-soft-delete-leaf`

**Actor**: `cpt-cf-accounts-actor-tenant-admin`, `cpt-cf-accounts-actor-platform-admin`

**Preconditions**:
- Tenant `T5` has no children
- Tenant `T5` has no active resources

**Main Flow**:
1. Administrator submits a delete request for `T5`.
2. System validates that `T5` has no children and no active resources.
3. System transitions `T5` to `deleted` status as a soft delete.
4. System schedules hard deletion after the configured retention period, by default 90 days.

**Postconditions**:
- `T5` is soft-deleted immediately
- Hard deletion is deferred until the retention period expires

**Alternative Flows**:
- **Active resources exist**: Delete request is rejected until resources are removed

#### Scenario: List Root Tenants

- [ ] `p1` - **ID**: `cpt-cf-accounts-usecase-list-root-tenants`

**Actor**: `cpt-cf-accounts-actor-platform-admin`

**Preconditions**:
- Caller is authenticated as a Platform Administrator
- At least one root tenant exists in the forest

**Main Flow**:
1. Platform Administrator requests a list of root tenants with optional status filter.
2. System returns a paginated list of root tenants matching the filter criteria.
3. Each entry includes tenant identifier, name, type, status, mode, and timestamps.

**Postconditions**:
- Caller receives a paginated result set of root tenants

**Alternative Flows**:
- **No root tenants match filter**: Empty result set is returned
- **Non-Platform-Admin caller**: Request is rejected with `cross_tenant_denied`

### 8.3 Managed/Self-Managed Modes

#### Scenario: Create Managed Child Tenant

- [ ] `p1` - **ID**: `cpt-cf-accounts-usecase-create-managed-child`

**Actor**: `cpt-cf-accounts-actor-tenant-admin`

**Preconditions**:
- Parent tenant `T1` is allowed to create child tenants
- Requested child is created with `self_managed=false`

**Main Flow**:
1. Tenant admin creates child tenant `T2` with `self_managed=false`.
2. System persists `T2` as a managed child tenant.
3. System exposes the parent-child relationship without a visibility barrier.

**Postconditions**:
- No visibility barrier exists between `T1` and `T2`
- `T1` is eligible for delegated access to `T2` per policy

**Alternative Flows**:
- **None**: No additional alternative flows beyond standard policy evaluation

#### Scenario: Create Self-Managed Child Tenant

- [ ] `p1` - **ID**: `cpt-cf-accounts-usecase-create-self-managed-child`

**Actor**: `cpt-cf-accounts-actor-tenant-admin`

**Preconditions**:
- Parent tenant `T1` is allowed to create child tenants
- Requested child is created with `self_managed=true`

**Main Flow**:
1. Tenant admin creates child tenant `T2` with `self_managed=true`.
2. System persists `T2` as a self-managed child tenant.
3. System establishes the visibility barrier for the new subtree.

**Postconditions**:
- Visibility barrier exists between `T1` and `T2`
- `T1` has no access to `T2` APIs or resources by default

**Alternative Flows**:
- **None**: No additional alternative flows beyond standard authorization behavior

#### Scenario: Impersonate Managed Child

- [ ] `p1` - **ID**: `cpt-cf-accounts-usecase-impersonate-managed-child`

**Actor**: `cpt-cf-accounts-actor-tenant-admin`, `cpt-cf-accounts-actor-idp`

**Preconditions**:
- Managed relationship exists between parent `T1` and child `T2`
- `T2` is not self-managed
- IdP contract supports impersonation tokens

**Main Flow**:
1. Admin of `T1` requests impersonation of `T2`.
2. System validates the managed relationship and impersonation capability.
3. System obtains a time-bounded impersonation token from the IdP contract.
4. The platform carries both the caller's tenant identity and the impersonated operating tenant in the authorization context for downstream enforcement.
5. System records all impersonation activity in the audit log with both identities.

**Postconditions**:
- A time-bounded impersonation session is available for managed-child operations
- Audit trail records both Subject Tenant and Context Tenant identities

**Alternative Flows**:
- **Child is self-managed**: See `cpt-cf-accounts-usecase-reject-impersonate-self-managed`
- **IdP lacks impersonation support**: See `cpt-cf-accounts-usecase-reject-impersonate-unsupported`

#### Scenario: Reject Impersonation — Self-Managed Child

- [ ] `p2` - **ID**: `cpt-cf-accounts-usecase-reject-impersonate-self-managed`

**Actor**: `cpt-cf-accounts-actor-tenant-admin`

**Preconditions**:
- Relationship between `T1` and `T2` is self-managed with `self_managed=true`

**Main Flow**:
1. Admin of `T1` requests impersonation of `T2`.
2. System evaluates the tenant relationship mode.
3. System rejects the impersonation request because the barrier is active.

**Postconditions**:
- No impersonation token is issued
- Caller receives `cross_tenant_denied`

**Alternative Flows**:
- **None**: No additional alternative flows beyond the barrier check

#### Scenario: Reject Impersonation — IdP Does Not Support It

- [ ] `p2` - **ID**: `cpt-cf-accounts-usecase-reject-impersonate-unsupported`

**Actor**: `cpt-cf-accounts-actor-tenant-admin`, `cpt-cf-accounts-actor-idp`

**Preconditions**:
- Managed relationship exists between `T1` and `T2`
- IdP contract implementation does not support impersonation tokens

**Main Flow**:
1. Admin of `T1` requests impersonation of `T2`.
2. System checks the capabilities of the active IdP provider.
3. System rejects the request because impersonation is feature-gated for this provider.

**Postconditions**:
- No impersonation token is issued
- Caller is informed that impersonation is unavailable

**Alternative Flows**:
- **None**: No additional alternative flows beyond the provider capability check

#### Scenario: Convert Managed to Self-Managed (Unilateral)

- [ ] `p3` - **ID**: `cpt-cf-accounts-usecase-convert-to-self-managed`

**Actor**: `cpt-cf-accounts-actor-tenant-admin`

**Preconditions**:
- Tenant `T2` is currently managed under parent `T1`

**Main Flow**:
1. Admin of `T2` submits a request to convert `T2` to self-managed mode.
2. System updates the tenant mode and creates the barrier synchronously within the same operation.
3. System records the mode change in the audit log.

**Postconditions**:
- `T2` has `self_managed=true` committed in AM's source-of-truth
- `T1` loses access to `T2` resources once Tenant Resolver's projection reflects the updated barrier state (propagation latency is a platform concern, not AM's)
- `T2` operates as a self-managed tenant

**Alternative Flows**:
- **None**: No additional alternative flows beyond the immediate conversion

#### Scenario: Convert Self-Managed to Managed (Dual Consent)

- [ ] `p3` - **ID**: `cpt-cf-accounts-usecase-convert-to-managed`

**Actor**: `cpt-cf-accounts-actor-tenant-admin`

**Preconditions**:
- Tenant `T2` is self-managed under parent `T1`

**Main Flow**:
1. Admin of one side (e.g., `T2`) requests conversion to managed mode via their own tenant scope.
2. System creates a pending conversion record with the initiating side recorded and a 72-hour expiry.
3. Admin of the counterparty (e.g., `T1`) approves the conversion via their own tenant scope within 72 hours.
4. System removes the barrier and establishes the managed relationship.
5. System records the completed mode change in the audit log with initiator and approver identity.

**Postconditions**:
- `T2` becomes a managed child of `T1`
- Conversion history shows both parent and child approval, including which side initiated

**Alternative Flows**:
- **Approval not received within 72 hours**: See `cpt-cf-accounts-usecase-conversion-expires`

#### Scenario: Conversion Approval Expires

- [ ] `p3` - **ID**: `cpt-cf-accounts-usecase-conversion-expires`

**Actor**: `cpt-cf-accounts-actor-tenant-admin`

**Preconditions**:
- Pending conversion request exists for `T2`
- Required approval has not yet been received

**Main Flow**:
1. System tracks the approval window for the pending conversion request.
2. Seventy-two hours pass without the required approval.
3. Background cleanup cancels the pending request.
4. System preserves the existing tenant mode.

**Postconditions**:
- Pending conversion request is cancelled
- Existing tenant mode remains unchanged

**Alternative Flows**:
- **None**: No additional alternative flows beyond expiration handling

#### Scenario: Parent Discovers Pending Conversion Request

- [ ] `p3` - **ID**: `cpt-cf-accounts-usecase-discover-conversion-request`

**Actor**: `cpt-cf-accounts-actor-tenant-admin`

**Preconditions**:
- Parent tenant `T1` exists with status `active`
- Self-managed child tenant `T2` exists under `T1` with a visibility barrier
- Child admin of `T2` has initiated a self-managed-to-managed conversion (pending request exists)

**Main Flow**:
1. Parent admin of `T1` queries inbound conversion requests for their tenant.
2. System returns a paginated list of pending conversion requests targeting direct children of `T1`.
3. Each entry includes the request identifier, child tenant identifier, child tenant name, initiating side, status, creation timestamp, and expiry timestamp.
4. Parent admin reviews the pending request and decides to approve via `cpt-cf-accounts-usecase-convert-to-managed`.

**Postconditions**:
- Parent admin has visibility into the pending conversion request without the barrier being bypassed
- No child tenant data beyond conversion-request metadata is exposed

**Alternative Flows**:
- **No pending requests**: Empty result set is returned
- **Request has expired**: Expired requests are included only if the status filter includes non-pending statuses; otherwise they are excluded

#### Scenario: Cancel Pending Conversion Request

- [ ] `p3` - **ID**: `cpt-cf-accounts-usecase-cancel-conversion`

**Actor**: `cpt-cf-accounts-actor-tenant-admin`

**Preconditions**:
- A pending conversion request exists for self-managed tenant `T2` under parent `T1`

**Main Flow**:
1. Admin of either side (initiator to withdraw, or counterparty to reject) submits a cancellation from their own tenant scope.
2. System validates that a pending conversion request exists for the target tenant.
3. System transitions the request to `cancelled` status.
4. System records the cancellation in the audit log with the cancelling actor's identity.

**Postconditions**:
- Conversion request status is `cancelled`
- Tenant mode remains unchanged (`T2` stays self-managed)
- A new conversion request can be initiated after cancellation

**Alternative Flows**:
- **No pending request**: Cancellation fails with `not_found`

### 8.4 User Groups

> User group operations are performed by consumers directly via the [Resource Group module](../../resource-group/docs/PRD.md). AM's role is limited to registering the user-group RG type at module initialization and triggering tenant-scoped group cleanup during hard-deletion. Structural invariants (cycle detection, forest enforcement, tenant scoping) are enforced by Resource Group; see [Resource Group use cases](../../resource-group/docs/PRD.md#8-use-cases).

#### Scenario: Create User Group via Resource Group

- [ ] `p1` - **ID**: `cpt-cf-accounts-usecase-create-user-group`

**Actor**: `cpt-cf-accounts-actor-tenant-admin`

**Preconditions**:
- Tenant `T1` exists with status `active`
- User-group Resource Group type is registered with `allowed_memberships` including the user resource type

**Main Flow**:
1. Tenant admin calls the Resource Group API directly to create a Resource Group entity of the user-group type within tenant scope `T1`.
2. Resource Group validates type compatibility, tenant scope, and forest invariants; persists the group.

**Postconditions**:
- Group exists as a Resource Group entity within tenant `T1`
- Group identifier is unique within the tenant scope (enforced by Resource Group)

> AM is not in the call path — the consumer interacts with Resource Group directly.

#### Scenario: Manage Group Membership via Resource Group

- [ ] `p1` - **ID**: `cpt-cf-accounts-usecase-manage-group-membership`

**Actor**: `cpt-cf-accounts-actor-tenant-admin`

**Preconditions**:
- User-group Resource Group entity `G1` exists in tenant `T1`
- User `U1` belongs to tenant `T1` (verified via AM's tenant-scoped user-query capability)

**Main Flow**:
1. Admin adds `U1` to `G1` through the Resource Group membership API.
2. Resource Group validates tenant compatibility and stores the membership link.
3. Admin removes `U1` from `G1` through the same Resource Group membership API.
4. Resource Group removes the membership link.

**Postconditions**:
- Group membership reflects the most recent update
- `U1` is no longer a member of `G1`

> AM is not in the call path — the consumer interacts with Resource Group directly. User existence verification is the caller's responsibility (via AM's tenant-scoped user-query capability).

#### Scenario: Reject Circular Group Nesting (Resource Group Invariant)

- [ ] `p2` - **ID**: `cpt-cf-accounts-usecase-reject-circular-nesting`

**Actor**: `cpt-cf-accounts-actor-tenant-admin`

**Preconditions**:
- Nested user-group Resource Group entities `G1 → G2 → G3` already exist

**Main Flow**:
1. Admin requests Resource Group to move `G1` under `G3`.
2. Resource Group evaluates forest invariants and detects a cycle.
3. Resource Group rejects the operation with `CycleDetected`.

**Postconditions**:
- Existing nesting structure is preserved
- Caller receives `CycleDetected` error directly from Resource Group

> AM is not in the call path — cycle detection is a Resource Group invariant. `CycleDetected` is an RG-owned error, not part of AM's error contract.

### 8.5 IdP User Operations

#### Scenario: Provision User in Tenant

- [ ] `p1` - **ID**: `cpt-cf-accounts-usecase-provision-user`

**Actor**: `cpt-cf-accounts-actor-tenant-admin`, `cpt-cf-accounts-actor-idp`

**Preconditions**:
- Tenant `T1` exists with status `active`

**Main Flow**:
1. Tenant admin submits a request to provision user `U1` via the AM API.
2. AM invokes the IdP integration contract's user-provisioning operation with tenant scope `T1`.
3. IdP creates user `U1` and binds the user to tenant `T1`.

**Postconditions**:
- User `U1` exists in the IdP
- User `U1` is bound to tenant `T1` via the tenant identity attribute

**Alternative Flows**:
- **IdP unavailable**: IdP contract call fails or times out. AM returns `idp_unavailable` error to the caller. No user record is created or modified. (See `cpt-cf-accounts-fr-deterministic-errors`.)

#### Scenario: Deprovision User

- [ ] `p1` - **ID**: `cpt-cf-accounts-usecase-deprovision-user`

**Actor**: `cpt-cf-accounts-actor-tenant-admin`, `cpt-cf-accounts-actor-idp`

**Preconditions**:
- User `U1` exists in tenant `T1`

**Main Flow**:
1. Tenant admin submits a request to deprovision `U1`.
2. AM invokes the IdP integration contract's user-deprovisioning operation.
3. System revokes active sessions for `U1`.

**Postconditions**:
- User `U1` is removed or deactivated according to IdP behavior
- Active sessions for `U1` are revoked

**Alternative Flows**:
- **IdP unavailable**: IdP contract call fails or times out. AM returns `idp_unavailable` error to the caller. User `U1` remains in its current state. (See `cpt-cf-accounts-fr-deterministic-errors`.)

#### Scenario: Query Users by Tenant

- [ ] `p1` - **ID**: `cpt-cf-accounts-usecase-query-users-by-tenant`

**Actor**: `cpt-cf-accounts-actor-tenant-admin`, `cpt-cf-accounts-actor-idp`

**Preconditions**:
- Tenant `T1` has users `[U1, U2, U3]`

**Main Flow**:
1. Tenant admin queries users of `T1`.
2. AM invokes the IdP integration contract's tenant-scoped user-query operation with a tenant filter for `T1`.
3. IdP returns the matching users.

**Postconditions**:
- Response contains `[U1, U2, U3]`
- Returned users are scoped to tenant `T1`

**Alternative Flows**:
- **IdP unavailable**: IdP contract call fails or times out. AM returns `idp_unavailable` error to the caller. (See `cpt-cf-accounts-fr-deterministic-errors`.)

### 8.6 Extensible Tenant Metadata

#### Scenario: Register and Write Tenant Metadata

- [ ] `p2` - **ID**: `cpt-cf-accounts-usecase-write-tenant-metadata`

**Actor**: `cpt-cf-accounts-actor-tenant-admin`, `cpt-cf-accounts-actor-gts-registry`

**Preconditions**:
- Tenant `T1` exists with status `active`
- GTS schema `branding` is registered with inheritance policy `inherit`

**Main Flow**:
1. Tenant admin submits a metadata write for kind `branding` with logo URL and color scheme for tenant `T1`.
2. System validates the payload against the GTS `branding` schema.
3. System stores the metadata entry scoped to `T1`.

**Postconditions**:
- Metadata entry of kind `branding` is stored for `T1`
- Child tenants without overrides inherit `T1` branding via the resolution API (inheritance policy `inherit`)

**Alternative Flows**:
- **Schema validation fails**: Write is rejected with `validation` error
- **Metadata kind not registered**: Write is rejected with `not_found` error

#### Scenario: Resolve Inherited Metadata

- [ ] `p2` - **ID**: `cpt-cf-accounts-usecase-resolve-inherited-metadata`

**Actor**: `cpt-cf-accounts-actor-tenant-admin`

**Preconditions**:
- Tenant `T1` has metadata of kind `branding` with inheritance policy `inherit`
- Child tenant `T2` has no `branding` metadata of its own

**Main Flow**:
1. Consumer requests resolved `branding` metadata for tenant `T2`.
2. System finds no `T2`-level entry for `branding`.
3. System walks up the hierarchy and finds `T1`'s entry.
4. System returns `T1`'s branding as the effective value for `T2`.

**Postconditions**:
- `T2` receives `T1`'s branding metadata via inheritance
- No metadata entry is created for `T2`

**Alternative Flows**:
- **`T2` has its own entry**: `T2`'s value takes precedence (override)
- **`override-only` schema**: Resolution returns empty — no hierarchy walk

#### Scenario: Write Override-Only Metadata

- [ ] `p2` - **ID**: `cpt-cf-accounts-usecase-write-override-only-metadata`

**Actor**: `cpt-cf-accounts-actor-tenant-admin`

**Preconditions**:
- GTS schema `billing-address` is registered with inheritance policy `override-only`
- Tenant `T2` exists with status `active`

**Main Flow**:
1. Tenant admin writes `billing-address` metadata for `T2`.
2. System validates the payload against the GTS `billing-address` schema.
3. System stores the entry scoped to `T2`.

**Postconditions**:
- `T2` has its own `billing-address` metadata
- Child tenants of `T2` do not inherit this value (override-only policy)

**Alternative Flows**:
- **None**: No additional alternative flows beyond standard validation

#### Scenario: Resolve Metadata Across Multiple Self-Managed Boundaries

- [ ] `p2` - **ID**: `cpt-cf-accounts-usecase-resolve-metadata-multi-barrier`

**Actor**: `cpt-cf-accounts-actor-tenant-admin`

**Preconditions**:
- Hierarchy: `Root → T1 (self-managed) → T2 → T3 (self-managed) → T4`
- `Root` has metadata of kind `branding` with inheritance policy `inherit`
- `T3` has metadata of kind `branding` with inheritance policy `inherit`
- `T4` has no `branding` metadata of its own

**Main Flow**:
1. Consumer requests resolved `branding` metadata for tenant `T4`.
2. System walks up the hierarchy from `T4` and encounters `T3`'s self-managed barrier.
3. System stops the walk at `T3` (barrier boundary) and returns `T3`'s branding as the effective value.

**Postconditions**:
- `T4` receives `T3`'s branding metadata (nearest ancestor within the same barrier boundary)
- `Root`'s branding is not considered because `T3`'s self-managed barrier stops traversal

**Alternative Flows**:
- **`T3` has no metadata either**: Resolution returns empty — the walk stops at the barrier and does not cross into `T1`'s scope

## 9. Acceptance Criteria

- [ ] Initial root tenant is automatically created during platform installation and linked to IdP; bootstrap is idempotent.
- [ ] Platform Administrator can create additional root tenants post-bootstrap; Tenant Administrators cannot.
- [ ] Child tenants can be created with GTS-enforced type constraints; depth advisory threshold emits an operator-visible warning signal, strict mode rejects when enabled.
- [ ] Authorized administrators can read tenant details and update mutable tenant fields; immutable hierarchy-defining fields are rejected by the general update operation.
- [ ] Managed tenants allow parent access via impersonation (when IdP contract supports it); self-managed tenants block parent access via visibility barriers.
- [ ] Managed to self-managed conversion is unilateral; self-managed to managed uses an explicit `target_mode` contract where either side may initiate and the counterparty must approve within 72 hours.
- [ ] Direct children queries return paginated results with status filtering.
- [ ] IdP user operations (provision, deprovision, query) work through pluggable IdP integration contract.
- [ ] User groups (delegated to Resource Group) support creation, membership management, and nested groups with cycle detection via Resource Group forest invariants.
- [ ] Extensible tenant metadata (e.g., branding, contacts, billing-address) is configurable per tenant via GTS-registered schemas, with per-schema inheritance policy, exposed via tenant metadata resolution API.
- [ ] Tenant isolation is verified by automated security tests: Tenant A cannot access Tenant B data through any path.
- [ ] Tenant context validation completes in p95 ≤ 5ms.
- [ ] All tenant configuration changes are recorded in append-only audit logs with actor and tenant identity.
- [ ] All failures map to deterministic error categories.
- [ ] Concurrent mode conversion requests targeting the same tenant produce deterministic outcomes: duplicate initiation from the same side fails with `mode_change_pending`, while opposite-side races either complete approval or return `mode_change_pending` without violating the single-pending-request invariant.
- [ ] Metadata resolution returns the correct value when multiple self-managed boundaries exist in the ancestor chain.
- [ ] Hard-deletion background job correctly processes leaf-first ordering when parent and child share the same retention window.
- [ ] IdP timeout during user provisioning results in deterministic rollback with `idp_unavailable` error.
- [ ] Platform Administrator can list all root tenants in the forest with pagination and status filtering; non-Platform-Admin callers are rejected with `cross_tenant_denied`.
- [ ] Parent Tenant Administrator can discover pending inbound conversion requests from self-managed children without barrier bypass; only conversion-request metadata (request ID, child tenant ID, child tenant name, initiating side, timestamps, status) is exposed.
- [ ] Either side of a pending conversion request can cancel it from their own tenant scope; cancellation transitions the request to `cancelled` status without altering the tenant's mode.

## 10. Dependencies

**AM depends on:**

| Dependency | Description | Criticality |
|------------|-------------|-------------|
| IdP Provider (via IdP integration contract) | User authentication, token issuance, user-tenant binding. IdP must be available before AM bootstrap completes. | p1 |
| GTS Types Registry | Provides runtime-extensible tenant type definitions and parent-child constraint validation at tenant creation time. | p1 |
| [Resource Group](../../resource-group/docs/PRD.md) | User group hierarchy, membership storage, cycle detection, and tenant-scoped isolation. AM registers a Resource Group type for user groups and delegates all group operations to Resource Group itself. | p1 |
| Resource Management System | Provides resource existence check for tenant deletion validation (AM must verify no active resources before soft-deleting a tenant). | p2 |

**Depend on AM (consumers):**

| Consumer | What it consumes |
|----------|-----------------|
| Tenant Resolver Plugin | Syncs denormalized hierarchy projection from AM source-of-truth tenant tables. |
| AuthZ Resolver Plugin | Consumes tenant hierarchy and barrier state for authorization decisions. |
| RBAC Engine | Consumes user group structure and membership data (stored in Resource Group) for group-to-role binding. |
| Billing System | Consumes tenant hierarchy metadata with barrier bypass for billing aggregation. |

## 11. Assumptions

- IdP is a pluggable component accessed via the IdP integration contract. The platform ships a default implementation; deployments can substitute vendor-specific providers behind the same contract.
- Initial root tenant is created during platform install; IdP is bootstrapped by infrastructure before AM starts. The initial Platform Administrator identity is provisioned in the IdP as part of infrastructure setup — AM links the root tenant to this pre-existing identity but does not create the admin user itself. Additional root tenants are created by Platform Administrators via the API.
- User provisioning follows an API-only invite model; no self-registration is supported.
- Parent-child tenant creation is governed by GTS type constraints (allowed-parents rules); extensible by registering new GTS type schemas without code changes.
- RBAC Engine handles role definitions, role assignments, and group-to-role binding; AM provides group structure and membership data consumed by RBAC.
- Resource Management System is the source of record for resource scopes; tenant hierarchy is reflected in the RMS scope model.
- Authorization enforcement (AuthZ Resolver) and barrier-aware traversal (Tenant Resolver) are external consumers of AM source-of-truth data; their projection consistency and query performance are their own responsibility.

## 12. Risks

| Risk | Likelihood | Severity | Impact | Mitigation |
|------|-----------|----------|--------|------------|
| IdP impersonation not supported by chosen provider | Medium | Medium | Managed tenant access (impersonation) would be unavailable, reducing delegated administration value | Feature-gate impersonation so it can be enabled per-provider without blocking other multi-tenancy functionality |
| Cross-tenant data leak due to query-level isolation bypass | Low | High | Tenant data exposure, contractual and legal liability | Automated security test suite with cross-tenant access attempts; barrier enforcement at query level; continuous monitoring |
| Tenant hierarchy depth exceeding practical limits at scale | Low | Medium | Performance degradation of hierarchy queries and projections | Configurable advisory threshold (default: 10) with opt-in strict mode; monitoring of hierarchy depth distribution; design for scalability beyond 10,000 tenants |
| Circular nesting in user groups | Low | Low | Infinite loops in permission resolution | Enforced by Resource Group forest invariants — cycle detection at group move/create time; consumers receive `CycleDetected` directly from Resource Group before persistence. AM is not in the call path. |
| IdP provider unavailability during operations | Medium | High | Tenant creation, impersonation, and user lifecycle operations become temporarily unavailable | Clear deterministic error mapping (`idp_unavailable`), bootstrap retry/backoff, and operator alerting via observability metrics |

## 13. Question Log (Resolved / Deferred)

No open questions remain for the v1 sign-off baseline as of 2026-04-03. The items below are kept as a decision log so deferred topics stay visible without presenting them as unresolved blockers.

- ~~Will multiple barrier types be needed beyond the current binary (barrier/no barrier) model after v1?~~ **Resolved — Deferred** (Owner: Platform Architecture; revisit at v2 planning): v1 standardizes a binary `self_managed` barrier contract across AM, Tenant Resolver, and AuthZ Resolver (see §5.4). Any richer barrier model would require coordinated contract changes across those modules. No concrete post-v1 use case has been identified; revisit only if one emerges. See also Non-goals §1.4.
- ~~User-tenant reassignment (moving a user between tenants).~~ **Resolved — Deferred** (Owner: Platform Architecture; revisit when organizational restructuring use case is validated): explicitly listed in Non-goals §1.4. Requires cross-platform coordination beyond IdP (Resource Group membership migration, resource ownership transfer, AuthZ cache invalidation, session revocation, audit trail continuity).
- ~~Which initial GA deployment profile within the NFR 6.8 planning envelope will the platform team commit to before DESIGN sign-off?~~ **Resolved**: platform team approved 100K tenants, 300K users (IdP-stored), 30K user groups / 300K memberships (RG-stored), 1K rps peak. See DESIGN Section 4, Production Scale for schema impact assessment.

## 14. Traceability

- **Upstream requirements**: No UPSTREAM_REQS document exists for account-management. AM requirements are derived directly from platform architecture needs and business use cases documented in this PRD.
- **Downstream artifacts**: AM-specific [DESIGN](./DESIGN.md) exists; DECOMPOSITION and FEATURE artifacts are not created yet
- **Canonical platform references**:
  - [Authorization DESIGN](../../../../docs/arch/authorization/DESIGN.md) — authoritative source for `SecurityContext`, AuthN/AuthZ separation, and request-path enforcement
  - [Tenant Model](../../../../docs/arch/authorization/TENANT_MODEL.md) — platform-wide tenant terminology and ownership semantics
  - [Tenant Resolver README](../../tenant-resolver/README.md) — current resolver traversal and barrier behavior consumed by downstream authorization components
