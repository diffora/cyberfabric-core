---
status: accepted
date: 2026-04-18
decision-makers: Virtuozzo
---

# ADR-0003: Symmetric Dual-Consent Conversion via a First-Class `ConversionRequest` Resource


<!-- toc -->

- [Context and Problem Statement](#context-and-problem-statement)
- [Decision Drivers](#decision-drivers)
- [Considered Options](#considered-options)
  - [Approval State](#approval-state)
  - [API Surface](#api-surface)
- [Decision Outcome](#decision-outcome)
  - [Consequences](#consequences)
  - [Confirmation](#confirmation)
- [Pros and Cons of the Options](#pros-and-cons-of-the-options)
  - [Approval State](#approval-state-1)
  - [API Surface](#api-surface-1)
- [Traceability](#traceability)

<!-- /toc -->

**ID**: `cpt-cf-account-management-adr-conversion-approval`

## Context and Problem Statement

Flipping `tenants.self_managed` after creation changes a visibility barrier that splits parent and child AuthZ scopes. Either direction of the toggle (`managed → self_managed`, `self_managed → managed`) permanently shifts the control surface between the two parties, so AM treats every post-creation mode change as a mutual-consent operation requiring explicit agreement from both sides. The only unilateral path is the creation-time form `self_managed=true` on `POST /tenants`, where the parent's call to create the child is itself the consent.

Two coupled design questions must be answered:

1. **Approval state model.** How is a pending two-party agreement represented across sessions — a dedicated entity, inline columns on `tenants`, or an event-driven saga — given that the initiator and counterparty act in different HTTP sessions, possibly hours apart, and the approval window is bounded?
2. **API surface.** What REST shape drives the lifecycle (create, approve, cancel, reject) — a singular stateful sub-resource, or a collection of first-class request resources?

The two questions compose: the chosen state model determines what the API can or should expose; the chosen API shape determines which transitions need to be first-class operations.

## Decision Drivers

* **Symmetry of the toggle.** Both `managed → self_managed` and `self_managed → managed` shift AuthZ scope permanently; treating them asymmetrically (one-sided) invites a future change request to unify them.
* **Two-party agreement across sessions.** Initiator and counterparty act in separate HTTP sessions. The approval state must be durable across requests and service restarts.
* **Bounded approval window.** Pending agreements must expire automatically after a configurable TTL so they do not accumulate.
* **At most one pending request per tenant.** Concurrent or duplicate conversion requests on the same tenant must be prevented deterministically.
* **Audit trail and history.** Who initiated, who approved / cancelled / rejected, and when, must be recoverable after the fact. Resolved requests stay queryable for a bounded retention window before they are soft-deleted.
* **AuthZ scope correctness.** Parent and child administrators act from their own tenant scopes. The barrier must not be bypassed by a generic approval endpoint; the parent-side path is a narrow hierarchy-owner read on AM-owned data.
* **No new infrastructure.** The platform has no event bus or workflow engine yet (EVT is deferred — see PRD §4.2 Out of Scope). The solution should not introduce one.
* **Future-extensibility of the API.** The request entity already has an `id`, `status`, `expires_at`, and will grow audit-visible fields (initiator comment, counterparty reason, filtering). The API surface should anticipate that without retroactive re-shaping.
* **Simplicity of policy authoring.** The AuthZ vocabulary should distinguish "manage tenant hierarchy" from "manage mode-conversion requests" so the two can be granted independently.

## Considered Options

### Approval State

1. **Stateful `ConversionRequest` entity** — a dedicated table stores a durable request row per pending agreement, with TTL, actor columns, and soft-delete retention for resolved history.
2. **Inline columns on the `tenants` table** — store pending-agreement state (`mode_change_pending`, `initiated_by`, `initiated_at`) as nullable columns on the tenant row; a background job clears expired state.
3. **Event-driven saga** — an event bus coordinates initiation and approval as two separate events wired by a saga/process manager.

### API Surface

A. **Singular stateful sub-resource** — one `/tenants/{id}/conversion` sub-resource whose handlers (`PUT`/`DELETE`) mean different things depending on caller side and current server state (create / approve / cancel / no-op).

B. **Collection of first-class request resources** — `POST` creates a new request, `PATCH` drives its lifecycle (`approved`, `cancelled`, `rejected`), `GET` lists and fetches by `request_id`. Own-scope and parent-scope are exposed as two parallel collections (`/tenants/{id}/conversions`, `/tenants/{id}/child-conversions`).

C. **Sibling approval endpoint** — `POST /tenants/{id}/conversions` to create plus `POST /tenants/{id}/conversions/{request_id}/approve`, `/cancel`, `/reject` action verbs.

## Decision Outcome

* **Approval state model: Option 1 (Stateful `ConversionRequest` entity).** A dedicated `conversion_requests` table carries the dual-consent lifecycle with five statuses — `pending`, `approved`, `cancelled` (initiator withdraws), `rejected` (counterparty declines), `expired` (background sweep) — plus `deleted_at` for soft-delete retention. A partial unique index on `(tenant_id) WHERE status = 'pending' AND deleted_at IS NULL` enforces the at-most-one invariant at the DB level. A per-status `CHECK` constraint binds each terminal status to the correct actor column (`approved_by` / `cancelled_by` / `rejected_by`) with mutual exclusion. Approval atomically flips `tenants.self_managed` and the request status in a single transaction.
* **API surface: Option B (collection of first-class request resources).** Two parallel collections expose the same entity from each side's AuthZ scope:
  * Child-scope: `GET/POST /tenants/{id}/conversions`, `GET/PATCH /tenants/{id}/conversions/{request_id}`.
  * Parent-scope: `GET /tenants/{id}/child-conversions`, `GET/PATCH /tenants/{id}/child-conversions/{request_id}`.
  * `POST` always creates a new request (`initiator_side` derived from the URL collection). `PATCH` drives status only — body whitelist `{"status": "approved" | "cancelled" | "rejected"}`. `caller_side` is derived from the URL collection.
* **AuthZ vocabulary: ConversionRequest is a distinct GTS ResourceType** (`gts.cf.core.am.conversion_request.v1~`, identifier-only — no validation body) with two actions: `read` and `write`, as defined in [DESIGN.md](../DESIGN.md#authorization-model). `write` covers both `POST` (create) and `PATCH` (drive lifecycle); the `caller_side` / `initiator_side` role check that distinguishes legal transitions lives in `ConversionService`, not in the AuthZ action.
* **Role-per-transition (enforced by `ConversionService`, not by AuthZ):** `cancelled` requires `caller_side == initiator_side`; `approved` and `rejected` require `caller_side != initiator_side`. Mismatches surface as `409 conflict` with sub-code `invalid_actor_for_transition`.
* **Configurable lifecycle windows (AM module config, validated at `AccountManagementModule::init`):** `approval_ttl` (default 72h, range `[1h, 30d]`), `resolved_retention` (default 30d, range `[1d, 365d]`), `cleanup_interval` (default 60s, range `[10s, 10m]`). The module fails fast on out-of-range values.

### Consequences

* The `conversion_requests` table becomes a stable contract: five-value status enum, three mutually-exclusive actor columns guarded by a `CHECK` constraint, a partial unique index on `(tenant_id) WHERE status = 'pending' AND deleted_at IS NULL`, and a `deleted_at` tombstone column. The approval flip on `tenants.self_managed` and the request status change always happen in the same transaction.
* Two parallel URL collections (`/conversions`, `/child-conversions`) back one entity; the handler derives `caller_side` from the URL collection, not from the caller's identity, so the two sides cannot spoof each other even inside a shared AuthZ grant.
* `PATCH` semantics are limited to driving the state machine. Editable request metadata (initiator comment, counterparty reason) can be added later as additional whitelisted `PATCH` keys without changing URLs or action semantics.
* `ConversionRequest.write` is a single PEP check for both create and status transitions; role-per-transition rules are a service-layer concern. This lets policy authors grant "manage mode-conversion requests in my scope" without re-modeling each transition in the policy language. `ConversionRequest.read` gates both the list endpoints and the single-request `GET`s.
* The parent-scope `/child-conversions` list performs an authorized parent-scope structural read that joins `conversion_requests` with `tenants` on `parent_id` and exposes only the conversion-request metadata fields defined in DESIGN §3.3 — not full child tenant data. This is the same hierarchy-owner carve-out AM uses for deletion pre-checks and child-count validation; it is not an AuthZ barrier bypass.
* Resolved requests are retained for `resolved_retention` and then soft-deleted by a background job (`am_conversion_soft_deleted_total`); hard-deletion follows AM's existing tombstone retention cadence on `deleted_at`. Historical pending rows with `deleted_at IS NOT NULL` do not block new `pending` inserts, because the partial unique index excludes them.
* Conversion background job metrics: `am_conversion_approved_total`, `am_conversion_cancelled_total`, `am_conversion_rejected_total` (labeled by `initiator_side`), `am_conversion_expired_total`, `am_conversion_soft_deleted_total`.
* If an event bus is introduced later, conversion events can be emitted as a notification layer on top of this entity — the entity remains the source of truth.

### Confirmation

* Integration tests cover: create (`POST`) in both child-scope and parent-scope; `PATCH` transitions to `approved`, `cancelled`, `rejected`; the `409 conflict` + `invalid_actor_for_transition` pair for each invalid `(caller_side, attempted_status)` pair; `409 conflict` + `pending_exists` on concurrent `POST` collisions; `422 validation` + `root_tenant_cannot_convert` for the root tenant; URL-smuggling guards (mismatched `{id}` / `{request_id}`) returning `404`.
* DB-integrity tests cover the partial unique index, the actor-column `CHECK` constraint (each terminal status requires exactly one actor column populated), and the retention soft-delete job (soft-deleted rows are excluded from default list queries and from the partial unique index).
* Approval flip atomicity is verified by a transaction-boundary test that asserts `tenants.self_managed` and `conversion_requests.status = 'approved'` either both commit or both roll back.
* Metric sanity tests verify that each terminal transition increments the corresponding counter exactly once per transition.
* `AccountManagementModule::init` tests verify fail-fast behavior on out-of-range `approval_ttl`, `resolved_retention`, and `cleanup_interval` values.
* No artifact defines an `/{id}/conversion` singular sub-resource, `/approve`, `/cancel`, or `/reject` action verbs. The only state-driving verb is `PATCH` on `{request_id}`.

## Pros and Cons of the Options

### Approval State

#### Option 1: Stateful `ConversionRequest` entity

* Good — no new infrastructure; uses the existing database and background-job pattern AM already runs for retention cleanup.
* Good — partial unique index gives DB-level at-most-one enforcement; no application-level race conditions.
* Good — the entity has a natural audit trail (`requested_by`, `approved_by` / `cancelled_by` / `rejected_by`, `status` transitions, timestamps) and a natural home for soft-delete history.
* Good — durable across service restarts.
* Good — separates conversion lifecycle cleanly from tenant data; the `tenants` table stays single-purpose.
* Neutral — the counterparty must be notified out of band (email, UI poll) until an event bus exists.
* Bad — a background cleanup/retention job is one more component that must run and be monitored.

#### Option 2: Inline columns on the `tenants` table

* Good — no extra table; approval state is a single-row read on the tenant itself.
* Bad — mixes conversion lifecycle with tenant data; the `tenants` table grows multiple nullable columns that are `NULL` for the vast majority of rows.
* Bad — the at-most-one invariant is awkward to express with a partial unique index on nullable state columns, compared to a clean `WHERE status = 'pending'` predicate on a dedicated table.
* Bad — historical audit trail (prior approvals, rejections, cancellations) has nowhere to live without adding a shadow history table anyway.
* Bad — future conversion fields (initiator comment, counterparty reason, filtering) pile nullable columns onto `tenants`.
* Bad — soft-delete/retention of resolved history does not compose with "the tenant row is the state" — a tenant cannot be soft-deleted independently of its mode-change history.

#### Option 3: Event-driven saga

* Good — would support real-time notification once an event bus exists.
* Bad — hard dependency on infrastructure that does not exist (EVT deferred per PRD §4.2). This option introduces a blocking prerequisite.
* Bad — saga/process manager is disproportionate complexity for a two-step human-approval flow.
* Bad — the approval state still needs durable storage; the event bus is not a state store. This option becomes Option 1 + a bus, not a replacement.
* Bad — event ordering, delivery guarantees, and dead-letter handling must be designed for a single use case before the platform has a general-purpose model for them.

### API Surface

#### Option A: Singular stateful sub-resource (`/tenants/{id}/conversion`)

* Good — minimal transport surface.
* Bad — handler semantics are state-driven: the same `PUT` may create a request, approve an existing one, or be a same-side idempotent no-op depending on which side is calling and what the current status is. The verb-to-intent mapping is non-obvious.
* Bad — does not model history; a resolved or expired request has no URL to reference.
* Bad — does not compose with future per-request fields (initiator comment, counterparty reason, filtering) — those would force a retroactive re-shape toward a collection later.
* Bad — does not separate "manage tenant hierarchy" from "manage mode-conversion requests" in the AuthZ vocabulary, because the sub-resource is an attribute of `Tenant`.

#### Option B: Collection of first-class request resources

* Good — matches the underlying model: a first-class request entity with its own `id`, `status`, TTL, and actor columns is exposed as a first-class REST resource.
* Good — `POST` always creates; `PATCH` always drives lifecycle; `GET` always reads. Handler semantics are deterministic per verb.
* Good — historical rows are first-class and queryable by `request_id`; list endpoints support filtering by `status`.
* Good — extensibility is cheap: editable metadata (initiator comment, counterparty reason) can be added as additional `PATCH` keys without new URLs or new actions.
* Good — `ConversionRequest` becomes a distinct AuthZ ResourceType with its own `read` / `write` actions, independent of `Tenant` grants.
* Good — parent-scope and child-scope are two parallel collections, which makes the `caller_side` derivation explicit at the URL layer and prevents a shared grant from being used to spoof the other side.
* Neutral — slightly more surface than Option A; every endpoint is symmetric, so the added surface is regular and does not branch in the handler.

#### Option C: Sibling approval endpoint (`/approve`, `/cancel`, `/reject` action verbs)

* Good — each lifecycle step is its own URL with obvious intent.
* Bad — duplicates state-machine knowledge in route registration and policy bindings; every future status addition requires a new URL and a new PEP entry.
* Bad — grows the `ConversionRequest` action surface from `{read, write}` to one action per transition, which the AuthZ layer does not need to distinguish (the service layer already enforces role-per-transition).
* Bad — editable request metadata has no natural home; would add a fourth verb (`/update`) that re-creates `PATCH` under a different name.
* Bad — asymmetric: `POST` for create sits next to action-verb endpoints, so the resource stops being a uniformly-modeled collection.

## Traceability

- **PRD**: [PRD.md](../PRD.md)
- **DESIGN**: [DESIGN.md](../DESIGN.md)

This decision directly addresses the following requirements:

* `cpt-cf-account-management-fr-mode-conversion-approval` — Symmetric dual consent for any post-creation toggle of `tenants.self_managed`.
* `cpt-cf-account-management-fr-conversion-creation-time-self-managed` — Creation-time `self_managed=true` bypasses the request flow; parent's creation call is the consent.
* `cpt-cf-account-management-fr-child-conversions-query` — Parent-scope listing of inbound conversion requests on direct children via the `/child-conversions` collection.
* `cpt-cf-account-management-fr-conversion-cancel` — Initiator withdraws a pending request via `PATCH status=cancelled`.
* `cpt-cf-account-management-fr-conversion-reject` — Counterparty declines a pending request via `PATCH status=rejected`.
* `cpt-cf-account-management-fr-conversion-retention` — Resolved requests are soft-deleted after `resolved_retention`; hard-delete follows AM's existing tombstone retention cadence.
* `cpt-cf-account-management-usecase-convert-dual-consent` — Either side initiates; the counterparty approves from its own scope.
* `cpt-cf-account-management-usecase-conversion-expires` — Background cleanup expires pending requests past `approval_ttl`.
* `cpt-cf-account-management-usecase-discover-child-conversions` — Parent admin discovers pending inbound requests on direct children.
* `cpt-cf-account-management-usecase-cancel-conversion-by-initiator` — Initiator withdraws their own pending request.
* `cpt-cf-account-management-usecase-reject-conversion-by-counterparty` — Counterparty declines a pending request.
* `cpt-cf-account-management-usecase-invalid-actor-for-transition` — Role-per-transition mismatch surfaces as `409 conflict` with sub-code `invalid_actor_for_transition`.
* `cpt-cf-account-management-usecase-retention-of-resolved-conversion` — Resolved rows are soft-deleted after the retention window.
* `cpt-cf-account-management-nfr-audit-completeness` — Initiation, approval, cancellation, rejection, and expiry are all recorded in the platform audit log.
* `cpt-cf-account-management-interface-tenant-mgmt-rest` — The tenant management API surface exposes the `/conversions` and `/child-conversions` collections and no action-verb or singular-sub-resource routes.
