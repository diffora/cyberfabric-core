---
status: rejected
date: 2026-04-04
decision-makers: Virtuozzo
---

# ADR-0006: Reject Resource Group as the Canonical Tenant Hierarchy Store for AM


<!-- toc -->

- [Context and Problem Statement](#context-and-problem-statement)
- [Decision Drivers](#decision-drivers)
- [Considered Options](#considered-options)
- [Decision Outcome](#decision-outcome)
  - [Consequences](#consequences)
  - [Confirmation](#confirmation)
- [Pros and Cons of the Options](#pros-and-cons-of-the-options)
  - [Make RG the canonical tenant hierarchy source and remove dedicated hierarchy ownership from AM](#make-rg-the-canonical-tenant-hierarchy-source-and-remove-dedicated-hierarchy-ownership-from-am)
  - [Keep the dedicated AM `tenants` table and continue using RG only for user groups](#keep-the-dedicated-am-tenants-table-and-continue-using-rg-only-for-user-groups)
  - [Extract shared hierarchy/storage primitives while keeping AM as the tenant source of truth](#extract-shared-hierarchystorage-primitives-while-keeping-am-as-the-tenant-source-of-truth)
  - [Keep both stores and synchronize tenant hierarchy between AM and RG](#keep-both-stores-and-synchronize-tenant-hierarchy-between-am-and-rg)
- [More Information](#more-information)
- [Traceability](#traceability)

<!-- /toc -->

**ID**: `cpt-cf-accounts-adr-resource-group-tenant-hierarchy-source`

## Context and Problem Statement

AM currently owns tenant lifecycle, bootstrap, mode conversion, IdP orchestration, tenant-specific authorization semantics, and the source-of-truth `tenants` table consumed by downstream hierarchy readers. RG already provides a generic hierarchy engine for groups, with parent-child storage, type-driven placement, closure-table traversal, and barrier-as-data semantics for tenant-like nodes. We considered replacing the AM `tenants` table with RG as the canonical tenant hierarchy store in order to reduce duplicated tree machinery, but we needed to determine whether that produces a cleaner ownership model or only moves complexity across module boundaries.

## Decision Drivers

* **Clean ownership boundary**: Tenant hierarchy, lifecycle, and public tenant API semantics should belong to one clear domain owner.
* **Avoid cross-module invariants**: Deletion, bootstrap, conversion, and barrier updates should not require fragile AM↔RG coordination for every write.
* **Authorization clarity**: Tenants must remain governed by AM tenant permissions, not become indistinguishable from generic RG groups.
* **Lifecycle completeness**: Soft delete, hard delete ordering, root bootstrap, and subtree checks must stay coherent without introducing parallel state models.
* **Consumer stability**: Tenant Resolver and other hierarchy readers should not absorb a large migration unless the new ownership model is demonstrably cleaner.
* **Reuse without leakage**: Reusing hierarchy mechanics is desirable, but not if it forces tenant-specific semantics into a generic RG abstraction.

## Considered Options

* Make RG the canonical tenant hierarchy source and remove dedicated hierarchy ownership from AM
* Keep the dedicated AM `tenants` table and continue using RG only for user groups
* Extract shared hierarchy/storage primitives while keeping AM as the tenant source of truth
* Keep both stores and synchronize tenant hierarchy between AM and RG

## Decision Outcome

Chosen option: "Keep the dedicated AM `tenants` table and continue using RG only for user groups", because making RG the canonical tenant hierarchy store does not create a cleaner architecture. It splits one domain concept across two modules, forces tenant-specific lifecycle and permission semantics through a generic group subsystem, and introduces cross-module coordination on the critical path of every important tenant operation.

The RG-backed hierarchy idea remains a prospective exploration only if the platform later decides to move tenant ownership into RG end-to-end. That would be a larger redesign where RG becomes the true tenant owner and AM becomes a thin facade or is reduced in scope. This ADR rejects the partial middle-ground design.

### Consequences

* AM remains the canonical owner of tenant hierarchy structure, tenant lifecycle state, and the database contract exposed to downstream tenant-hierarchy consumers.
* RG remains delegated to user groups and other generic group hierarchies; it does not become the persistence owner for AM tenants.
* Tree-logic duplication is accepted for now as the lower-risk trade-off compared with cross-module ownership splitting.
* Any future reuse effort should target extracted hierarchy primitives, shared libraries, or storage helpers rather than moving tenant source-of-truth ownership into RG.
* The current AM PRD and DESIGN remain directionally correct and do not require a tenant-storage migration to RG.

### Confirmation

* AM DESIGN continues to center tenant lifecycle and hierarchy on `cpt-cf-accounts-dbtable-tenants`.
* No follow-up design migrates Tenant Resolver or other hierarchy consumers from the AM `tenants` table to RG.
* RG continues to expose generic group APIs without tenant-only CRUD restrictions, special tenant-group write bans, or AM-owned lifecycle fields.

## Pros and Cons of the Options

### Make RG the canonical tenant hierarchy source and remove dedicated hierarchy ownership from AM

Use RG as the authoritative store for tenant nodes, parent-child relationships, tenant typing, and barrier state, while AM keeps the tenant-facing API and business logic.

* Good, because it would reuse RG's existing parent-child, type, and closure-table capabilities for tenant-like entities.
* Good, because it would remove one dedicated hierarchy table from AM.
* Bad, because one domain concept would have two owners: structure in RG, lifecycle and semantics in AM.
* Bad, because soft delete would become awkward: RG has hierarchy data, while AM would still need tenant-only lifecycle state such as `status` and `deleted_at`.
* Bad, because hard delete would require cross-module orchestration to verify subtree emptiness, retention eligibility, IdP cleanup, and physical RG-node deletion.
* Bad, because bootstrap of the first tenant would invert ownership: AM would need to create and manage canonical RG state before AM itself is fully established.
* Bad, because tenant-specific authorization would need tenant-only exceptions inside RG so that tenant groups are not editable like ordinary groups.
* Bad, because direct RG CRUD for tenant-typed groups would need to be blocked or special-cased, which weakens RG's generic abstraction.
* Bad, because barrier updates and mode-conversion semantics would span modules: AM decides, RG stores, Tenant Resolver consumes.
* Bad, because recovery, auditing, and debugging become more complex when the canonical tenant write path crosses AM, RG, IdP, and downstream readers.
* Bad, because downstream consumers currently built around the AM `tenants` contract would face a large migration without gaining a cleaner domain boundary.
* Bad, because AM availability and correctness for tenant lifecycle would become operationally coupled to RG's persistence contract and write-path behavior.
* Bad, because the design encourages a "generic group with tenant exceptions" model instead of a crisp tenant domain model.

### Keep the dedicated AM `tenants` table and continue using RG only for user groups

Retain the current AM design where tenant hierarchy is AM-owned, while RG remains limited to user-group hierarchy and membership use cases.

* Good, because hierarchy structure, lifecycle state, bootstrap, deletion, and tenant-specific permissions stay under one domain owner.
* Good, because the public AM tenant API maps directly to AM-owned persistence and invariants.
* Good, because downstream consumers keep a stable tenant-hierarchy source of truth.
* Good, because RG stays generic and does not need tenant-only write restrictions or lifecycle fields.
* Bad, because AM and RG both continue to contain hierarchy-related logic.
* Bad, because future reuse of closure-table or type-placement mechanics may still require refactoring or shared infrastructure extraction.

### Extract shared hierarchy/storage primitives while keeping AM as the tenant source of truth

Factor reusable tree mechanics into shared libraries, helpers, or lower-level storage components, but keep tenant source-of-truth ownership in AM.

* Good, because it targets the real duplication problem without splitting tenant ownership across modules.
* Good, because AM can reuse hierarchy mechanics while keeping tenant lifecycle, deletion, and bootstrap coherent.
* Good, because RG remains generic and AM remains the tenant domain owner.
* Bad, because it requires deliberate engineering work to identify and extract the right reusable substrate.
* Bad, because it does not immediately remove the existing AM `tenants` table.

### Keep both stores and synchronize tenant hierarchy between AM and RG

Maintain the AM `tenants` table while also creating corresponding RG tenant nodes through projection or dual-write synchronization.

* Good, because it offers a staged migration path.
* Good, because it can support experiments without immediately cutting consumers over.
* Bad, because it introduces split-brain risk between the two hierarchy stores.
* Bad, because reconciliation, dual-write ordering, and failure recovery become first-class architectural problems.
* Bad, because it preserves the current duplication while adding synchronization complexity on top.

## More Information

This ADR records a rejected prospective direction, not an adopted design. The rejected idea was attractive from a tree-mechanics reuse perspective, but it failed the more important test of domain cleanliness.

The specific design concerns that led to rejection were:

* tenant hierarchy structure would move to RG while tenant lifecycle would remain in AM
* soft delete and hard delete would become cross-module workflows instead of AM-local invariants
* first-tenant bootstrap would require AM to initialize canonical RG state before its own domain is fully materialized
* tenant permissions would need to remain AM-specific, forcing RG to special-case tenant-typed groups
* generic RG CRUD would no longer be valid for tenant-typed nodes, which would make the RG abstraction less consistent
* migration of current AM-hierarchy consumers would be large and high-risk relative to the architectural gain

If the platform later wants a single hierarchy owner, the cleaner path is a larger redesign that makes RG the true tenant owner end-to-end, or a smaller refactor that extracts shared hierarchy primitives while keeping AM as source of truth.

## Traceability

- **PRD**: [PRD.md](../PRD.md)
- **DESIGN**: [DESIGN.md](../DESIGN.md)

This decision directly addresses the following requirements or design elements:

* `cpt-cf-accounts-fr-create-root-tenant` — Root tenant creation remains an AM-owned operation against AM-owned tenant storage.
* `cpt-cf-accounts-fr-create-child-tenant` — Child tenant creation keeps parent/type/depth validation inside AM rather than splitting write ownership across AM and RG.
* `cpt-cf-accounts-fr-tenant-soft-delete` — Soft-delete remains a tenant-domain invariant enforced by AM without RG-backed lifecycle coordination.
* `cpt-cf-accounts-nfr-barrier-enforcement` — Barrier state remains part of the AM tenant source-of-truth contract consumed by downstream resolvers.
* `cpt-cf-accounts-nfr-data-quality` — Transactional hierarchy visibility continues to rely on the AM `tenants` table contract.
* `cpt-cf-accounts-principle-source-of-truth` — Reaffirms AM as the canonical owner of tenant hierarchy and lifecycle semantics.
* `cpt-cf-accounts-principle-delegation-to-rg` — Confirms that RG delegation stops at user-group use cases and does not expand to canonical tenant storage.
* `cpt-cf-accounts-dbtable-tenants` — Keeps the dedicated AM tenant table as the active long-term design baseline.
