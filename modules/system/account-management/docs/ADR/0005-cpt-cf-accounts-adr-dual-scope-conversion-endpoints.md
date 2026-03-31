---
status: accepted
date: 2026-04-03
decision-makers: Virtuozzo
---

# ADR-0005: Use Dual-Scope `/convert` Endpoints for Mode Conversion Approval


<!-- toc -->

- [Context and Problem Statement](#context-and-problem-statement)
- [Decision Drivers](#decision-drivers)
- [Considered Options](#considered-options)
- [Decision Outcome](#decision-outcome)
  - [Consequences](#consequences)
  - [Confirmation](#confirmation)
- [Pros and Cons of the Options](#pros-and-cons-of-the-options)
  - [Dual-scope `/convert` endpoints with state-driven initiate/approve behavior](#dual-scope-convert-endpoints-with-state-driven-initiateapprove-behavior)
  - [Separate `POST /convert/approve` confirmation endpoint](#separate-post-convertapprove-confirmation-endpoint)
  - [Single parent-controlled endpoint with barrier-bypass semantics](#single-parent-controlled-endpoint-with-barrier-bypass-semantics)
- [More Information](#more-information)
- [Traceability](#traceability)

<!-- /toc -->

**ID**: `cpt-cf-accounts-adr-dual-scope-conversion-endpoints`

## Context and Problem Statement

AM already chose a stateful `ConversionRequest` entity for self-managed to managed approval, but the historical ADR described the confirmation API as `POST /convert/approve`. The canonical PRD and DESIGN instead use two tenant-scoped `/convert` endpoints, one in the child scope and one in the parent scope, with the request state determining whether a call initiates or approves the conversion.

We need one canonical endpoint model for this approval flow so API contracts, tests, and implementation all describe the same interaction.

## Decision Drivers

* **AuthZ scope correctness**: Parent and child administrators must act from their own tenant scopes, without an artificial approval endpoint that obscures which side is acting.
* **Barrier compatibility**: The parent-side approval path must work without a generic barrier-bypass contract.
* **Stateful entity retention**: The endpoint design should preserve the already chosen `ConversionRequest` table, TTL, and audit semantics.
* **API clarity**: Consumers need a single, stable initiation and approval contract with no ambiguous duplicate routes.
* **Operational simplicity**: The approval flow should avoid extra endpoint surface when the request state already distinguishes initiation from confirmation.

## Considered Options

* Dual-scope `/convert` endpoints with state-driven initiate/approve behavior
* Separate `POST /convert/approve` confirmation endpoint
* Single parent-controlled endpoint with barrier-bypass semantics

## Decision Outcome

Chosen option: "Dual-scope `/convert` endpoints with state-driven initiate/approve behavior", because it lets each party act within its own tenant scope, keeps the API surface minimal, and preserves the stateful `ConversionRequest` design without introducing a separate confirmation route.

### Consequences

* The child-side endpoint remains `POST /api/accounts/v1/tenants/{id}/convert`; the parent-side endpoint remains `POST /api/accounts/v1/tenants/{parent_id}/children/{child_id}/convert`.
* For self-managed to managed conversion, either side may initiate by calling its own endpoint with `target_mode = managed`; the counterparty completes approval by calling its own endpoint while a pending request from the opposite side exists.
* There is no `POST /convert/approve` endpoint in the canonical API surface.
* The `ConversionRequest` entity, partial unique index, TTL expiry, and audit model from ADR-0003 remain valid and unchanged.
* Parent-side approval continues to require explicit domain validation of the barrier-hidden child tenant after AuthZ passes on the parent scope; this is a narrow hierarchy-owner lookup, not a generalized barrier bypass.

### Confirmation

* PRD and DESIGN expose only the two `/convert` endpoints and describe initiation/approval as state-driven behavior.
* API and integration tests verify four paths: child initiates, parent approves, parent initiates, child approves.
* No OpenAPI, DESIGN, or implementation artifact defines a `POST /convert/approve` route.

## Pros and Cons of the Options

### Dual-scope `/convert` endpoints with state-driven initiate/approve behavior

Each party calls its own tenant-scoped `/convert` endpoint; the `ConversionRequest` state determines whether the call creates or completes the approval request.

* Good, because each actor stays inside its own AuthZ scope.
* Good, because the API surface is smaller and more symmetric.
* Good, because the stateful entity remains the single source of truth for initiation, approval, and expiry.
* Bad, because clients must understand that the same route can either initiate or approve depending on current request state.

### Separate `POST /convert/approve` confirmation endpoint

Use one route for initiation and a second explicit route for confirmation.

* Good, because initiation and approval are visually distinct in the API.
* Good, because some clients may find the intent easier to read at first glance.
* Bad, because it introduces an endpoint shape that is not used by the reviewed PRD or DESIGN.
* Bad, because it adds surface area without replacing the need for a stateful `ConversionRequest`.

### Single parent-controlled endpoint with barrier-bypass semantics

Route all approval through one parent-side endpoint and let the system bypass the child barrier during approval.

* Good, because the route inventory is minimal.
* Good, because parent-side integrations have one entry point.
* Bad, because it centralizes a dual-consent flow in one actor scope.
* Bad, because it relies on a broader barrier-bypass exception that the current design explicitly avoids.

## More Information

Supersedes `cpt-cf-accounts-adr-conversion-approval` — [ADR-0003](./0003-cpt-cf-accounts-adr-conversion-approval.md). ADR-0003 remains the historical record for choosing the `ConversionRequest` entity and expiry model, while ADR-0005 is the canonical source for the REST endpoint shape that drives that state machine.

## Traceability

- **PRD**: [PRD.md](../PRD.md)
- **DESIGN**: [DESIGN.md](../DESIGN.md)

This decision directly addresses the following requirements or design elements:

* `cpt-cf-accounts-fr-managed-to-self-managed` — The child-scoped `/convert` endpoint remains the unilateral path for managed to self-managed conversion.
* `cpt-cf-accounts-fr-self-managed-to-managed` — Dual-consent approval is executed through the two tenant-scoped `/convert` endpoints.
* `cpt-cf-accounts-usecase-convert-to-managed` — Either side can initiate; the counterparty approves from its own scope.
* `cpt-cf-accounts-usecase-conversion-expires` — The `ConversionRequest` expiry model remains unchanged under the chosen endpoint shape.
* `cpt-cf-accounts-interface-tenant-mgmt-rest` — The tenant management API surface exposes the two `/convert` routes and no separate approval route.
