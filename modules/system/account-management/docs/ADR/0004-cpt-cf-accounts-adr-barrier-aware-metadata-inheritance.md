---
status: accepted
date: 2026-04-03
decision-makers: Virtuozzo
---

# ADR-0004: Stop Metadata Inheritance at Self-Managed Barriers


<!-- toc -->

- [Context and Problem Statement](#context-and-problem-statement)
- [Decision Drivers](#decision-drivers)
- [Considered Options](#considered-options)
- [Decision Outcome](#decision-outcome)
  - [Consequences](#consequences)
  - [Confirmation](#confirmation)
- [Pros and Cons of the Options](#pros-and-cons-of-the-options)
  - [Stop the walk-up resolution at the first self-managed barrier](#stop-the-walk-up-resolution-at-the-first-self-managed-barrier)
  - [Ignore self-managed barriers during metadata resolution](#ignore-self-managed-barriers-during-metadata-resolution)
  - [Materialize barrier-truncated effective metadata per tenant](#materialize-barrier-truncated-effective-metadata-per-tenant)
- [More Information](#more-information)
- [Traceability](#traceability)

<!-- /toc -->

**ID**: `cpt-cf-accounts-adr-barrier-aware-metadata-inheritance`

## Context and Problem Statement

AM already chose read-time walk-up resolution for inherited tenant metadata, but the historical ADR left one consequence stated incorrectly: whether the `/resolved` walk may cross a self-managed barrier. The canonical PRD and DESIGN both require a self-managed tenant to be metadata-independent from ancestors above its barrier, so we need an explicit decision for barrier semantics within the walk-up algorithm.

## Decision Drivers

* **Isolation consistency**: Self-managed tenants are defined as independent administrative boundaries, not merely hidden nodes in UI traversal.
* **Artifact consistency**: PRD, DESIGN, ADR, and downstream tests must describe one resolution rule.
* **No hidden barrier bypass**: AM metadata resolution must not introduce an AM-local equivalent of `BarrierMode::Ignore`.
* **Consumer predictability**: Portals and integrations need one stable rule for when inherited metadata resolves to an ancestor value versus `empty`.
* **Preserve walk-up simplicity**: The solution should keep single-row metadata writes and avoid materialized effective-value state.

## Considered Options

* Stop the walk-up resolution at the first self-managed barrier
* Ignore self-managed barriers during metadata resolution
* Materialize barrier-truncated effective metadata per tenant

## Decision Outcome

Chosen option: "Stop the walk-up resolution at the first self-managed barrier", because it preserves the self-managed independence contract already adopted by the PRD and DESIGN while retaining the simplicity and consistency benefits of read-time walk-up resolution.

### Consequences

* For `inherit` schemas, the `/resolved` endpoint walks ancestors only until it encounters the first self-managed boundary; ancestors above that boundary are not consulted.
* A self-managed tenant with no own value for a metadata kind resolves to `empty`, just like a root tenant with no value.
* For hierarchies with no self-managed barrier on the path, the walk continues to the root exactly as in the original read-time walk-up model.
* This decision preserves the operational benefits of ADR-0002 that remain valid: no write amplification, no cascade infrastructure, and source-of-truth consistency at read time.
* ADR-0002 is superseded because its stated barrier-crossing consequence conflicted with the adopted product and design contract.

### Confirmation

* PRD and DESIGN both state that metadata inheritance stops at self-managed boundaries and reference this ADR.
* Integration tests verify three cases: own value, inherited ancestor value below any barrier, and `empty` when the nearest ancestor value is above a self-managed boundary.
* No AM path performing metadata resolution requires or simulates `BarrierMode::Ignore`.

## Pros and Cons of the Options

### Stop the walk-up resolution at the first self-managed barrier

Keep read-time walk-up resolution, but treat a self-managed tenant as the upper bound of the accessible inheritance chain.

* Good, because it matches the platform definition of self-managed tenant independence.
* Good, because it keeps PRD, DESIGN, and runtime behavior aligned.
* Good, because it preserves the low-complexity read-time walk-up model.
* Bad, because tenants below a barrier cannot inherit useful shared metadata from ancestors above the barrier unless it is re-authored below the barrier.

### Ignore self-managed barriers during metadata resolution

Walk to the root even when the path crosses a self-managed tenant boundary.

* Good, because it maximizes reuse of ancestor metadata.
* Good, because it keeps the walk algorithm uniformly root-seeking.
* Bad, because it contradicts the documented self-managed isolation contract.
* Bad, because it creates an implicit barrier-bypass rule inside AM.

### Materialize barrier-truncated effective metadata per tenant

Pre-compute effective values after each metadata or hierarchy change, with barrier rules applied during propagation.

* Good, because resolved reads are O(1).
* Good, because the barrier rule can be encoded once at write time.
* Bad, because it re-introduces write amplification and propagation complexity that ADR-0002 intentionally avoided.
* Bad, because partial propagation failures create consistency repair work that read-time resolution avoids.

## More Information

Supersedes `cpt-cf-accounts-adr-metadata-inheritance` — [ADR-0002](./0002-cpt-cf-accounts-adr-metadata-inheritance.md). ADR-0002 remains useful as background for why AM prefers walk-up resolution over materialization, but ADR-0004 is the canonical source for barrier semantics within that walk.

## Traceability

- **PRD**: [PRD.md](../PRD.md)
- **DESIGN**: [DESIGN.md](../DESIGN.md)

This decision directly addresses the following requirements or design elements:

* `cpt-cf-accounts-fr-tenant-metadata-schema` — Per-schema inheritance remains part of the metadata model.
* `cpt-cf-accounts-fr-tenant-metadata-crud` — Child tenants can still override inherited values locally without propagation jobs.
* `cpt-cf-accounts-fr-tenant-metadata-api` — The resolution API stops the ancestor walk at self-managed boundaries.
* `cpt-cf-accounts-nfr-barrier-enforcement` — Metadata resolution no longer contradicts the barrier independence contract.
* `cpt-cf-accounts-principle-barrier-as-data` — AM stores the barrier flag and uses it only for metadata inheritance termination, not for generalized access-control bypass.
