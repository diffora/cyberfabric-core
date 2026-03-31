---
status: superseded
date: 2026-04-02
decision-makers: Virtuozzo
superseded_by: cpt-cf-accounts-adr-dual-scope-conversion-endpoints
---

# ADR-0003: Stateful Entity for Mode Conversion Approval


<!-- toc -->

- [Context and Problem Statement](#context-and-problem-statement)
- [Decision Drivers](#decision-drivers)
- [Considered Options](#considered-options)
- [Decision Outcome](#decision-outcome)
  - [Consequences](#consequences)
  - [Confirmation](#confirmation)
- [Pros and Cons of the Options](#pros-and-cons-of-the-options)
  - [Option 1: Stateful `ConversionRequest` entity](#option-1-stateful-conversionrequest-entity)
  - [Option 2: Event-driven approval flow](#option-2-event-driven-approval-flow)
  - [Option 3: Inline columns on the `tenants` table](#option-3-inline-columns-on-the-tenants-table)
- [Traceability](#traceability)

<!-- /toc -->

**ID**: `cpt-cf-accounts-adr-conversion-approval`

**Superseded By**: `cpt-cf-accounts-adr-dual-scope-conversion-endpoints` — [ADR-0005](./0005-cpt-cf-accounts-adr-dual-scope-conversion-endpoints.md). This ADR remains the historical record for choosing the `ConversionRequest` entity and TTL cleanup pattern; the canonical REST endpoint shape was corrected in ADR-0005 on 2026-04-03.

## Context and Problem Statement

Converting a self-managed tenant to managed mode removes a visibility barrier and grants the parent delegated access to the child's resources. The PRD requires both parent and child administrator approval before the barrier is removed (`cpt-cf-accounts-fr-self-managed-to-managed`), with a 72-hour approval window and automatic expiry of unconfirmed requests. How should AM implement this two-party approval flow?

The reverse direction (managed → self-managed) is unilateral and applies immediately — no approval mechanism is needed. This ADR addresses only the self-managed → managed direction.

## Decision Drivers

* **Two-party agreement across separate sessions**: The initiator and confirmer act in different HTTP sessions, potentially hours apart. The approval state must be durable across requests and service restarts.
* **Bounded approval window**: PRD requires a 72-hour expiry. The mechanism must support time-bounded pending state with automatic cleanup.
* **At most one pending request per tenant**: Concurrent or duplicate conversion requests for the same tenant must be prevented.
* **Audit trail**: Both initiation and approval (or expiry) must be recorded with actor identity.
* **Infrastructure dependencies**: The platform does not yet have an event bus or workflow engine. The solution should not introduce a new infrastructure dependency.
* **Simplicity**: Mode conversion is a p3 feature. The implementation complexity should be proportional to its priority.

## Considered Options

1. **Stateful `ConversionRequest` entity** — a dedicated DB table stores pending conversion requests with TTL. Background cleanup job expires stale requests.
2. **Event-driven approval flow** — an event bus (e.g., CloudEvents via EVT) publishes a conversion-requested event; the confirmer's approval triggers a conversion-confirmed event; a saga or process manager coordinates the two.
3. **Inline columns on the `tenants` table** — store `mode_change_pending`, `mode_change_initiated_by`, `mode_change_initiated_at` directly on the tenant row. Background job clears expired rows.

## Decision Outcome

Chosen option: **Stateful `ConversionRequest` entity** (Option 1), because it cleanly separates conversion lifecycle from tenant data, supports the required constraints (TTL, at-most-one, audit), and requires no infrastructure beyond the existing database and a background cleanup job.

### Consequences

* A dedicated `conversion_requests` table stores pending requests with `tenant_id`, `initiator_tenant_id`, `requested_by`, `approved_by`, `status`, `expires_at`, and audit timestamps.
* A partial unique index (`UNIQUE (tenant_id) WHERE status = 'pending'`) enforces at-most-one active request per tenant at the database level.
* A background job runs periodically (configurable, default: every 60 seconds) to expire requests where `expires_at < now() AND status = 'pending'`. Each expired request generates an audit entry with `system` as the actor.
* The conversion flow is two REST calls: `POST /convert` (initiate) → `POST /convert/approve` (confirm). The initiator can be either the parent or child admin; the confirmer must be the other party.
* The `tenants.self_managed` flag is updated only after both parties have acted and the request is marked `approved`. The update and the request status change happen in a single DB transaction.
* If the platform introduces an event bus in the future, conversion events can be emitted as a notification layer on top of the stateful entity — the entity remains the source of truth, and events become an optimization for real-time notification rather than a replacement for the approval state.

### Confirmation

* `am_conversion_expired_total` counter tracks background cleanup activity.
* Integration tests verify: (1) initiation creates a pending request, (2) confirmation by the other party completes the conversion, (3) duplicate initiation returns `mode_change_pending`, (4) expired requests are cleaned up and do not complete, (5) the `self_managed` flag changes only after both approvals.
* The `conversion_requests` table has no FK to an event bus or external workflow system.

## Pros and Cons of the Options

### Option 1: Stateful `ConversionRequest` entity

* Good, because no new infrastructure dependency — uses the existing database and background job pattern already used by retention cleanup.
* Good, because the partial unique index (`WHERE status = 'pending'`) enforces at-most-one at the DB level — no application-level race conditions.
* Good, because the entity provides a natural audit trail: `requested_by`, `approved_by`, `status` transitions, and timestamps.
* Good, because the approval state survives service restarts — it's durable in the database.
* Good, because complexity is proportional to the feature's p3 priority — a single table and a background job.
* Neutral, because the confirmer must poll or be notified out-of-band (e.g., email, UI notification) — no push notification built into this model.
* Bad, because the background cleanup job adds a small operational concern (must run, must be monitored).

### Option 2: Event-driven approval flow

* Good, because real-time notification — the confirmer can be notified immediately via event subscription.
* Good, because the saga pattern provides a well-understood coordination model for multi-party workflows.
* Bad, because the platform does not have an event bus yet (EVT is deferred — see PRD §4.2 Out of Scope). This option introduces a hard infrastructure dependency that does not exist.
* Bad, because saga/process manager adds significant implementation complexity for a two-step flow.
* Bad, because event ordering, delivery guarantees, and dead-letter handling must be designed for a single use case.
* Bad, because the approval state must still be persisted somewhere for durability — the event bus alone is not a durable state store.

### Option 3: Inline columns on the `tenants` table

* Good, because no additional table — the pending state lives on the tenant row.
* Good, because the approval check is a single-row read (the tenant itself).
* Bad, because it mixes conversion lifecycle with tenant data — the `tenants` table gains three nullable columns that are `NULL` 99% of the time.
* Bad, because the partial unique constraint for at-most-one is harder to express on a boolean column (vs a separate table with a clean partial unique index on `status`).
* Bad, because the audit trail (who initiated, who approved) must be reconstructed from column values rather than being a natural property of a request entity.
* Bad, because future conversion requirements (e.g., multiple approval types, cancellation reasons, retry tracking) would add more nullable columns to the tenant row.

## Traceability

- **PRD**: [PRD.md](../PRD.md)
- **DESIGN**: [DESIGN.md](../DESIGN.md)

This decision directly addresses the following requirements:

* `cpt-cf-accounts-fr-self-managed-to-managed` — Dual-approval conversion with 72-hour expiry window.
* `cpt-cf-accounts-usecase-convert-to-managed` — Parent initiates, child confirms (or vice versa).
* `cpt-cf-accounts-usecase-conversion-expires` — Background cleanup cancels expired pending requests.
* `cpt-cf-accounts-nfr-audit-completeness` — Conversion initiation, approval, and expiry are all recorded in the audit log.
