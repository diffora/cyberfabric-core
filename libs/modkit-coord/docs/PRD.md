# PRD - modkit-coord

Created: 2026-05-07 by Diffora

<!-- toc -->

- [1. Overview](#1-overview)
  - [1.1 Purpose](#11-purpose)
  - [1.2 Background / Problem Statement](#12-background--problem-statement)
  - [1.3 Goals (Business Outcomes)](#13-goals-business-outcomes)
  - [1.4 Non-Goals](#14-non-goals)
  - [1.5 Glossary](#15-glossary)
- [2. Actors](#2-actors)
  - [2.1 Human Actors](#21-human-actors)
  - [2.2 System Actors](#22-system-actors)
- [3. Operational Concept & Environment](#3-operational-concept--environment)
  - [3.1 Module-Specific Environment Constraints](#31-module-specific-environment-constraints)
- [4. Scope](#4-scope)
  - [4.1 In Scope](#41-in-scope)
  - [4.2 Out of Scope](#42-out-of-scope)
- [5. Functional Requirements](#5-functional-requirements)
  - [5.1 Lease Lifecycle](#51-lease-lifecycle)
  - [5.2 Lease-Guarded Writes](#52-lease-guarded-writes)
  - [5.3 Crash Recovery & Diagnostics](#53-crash-recovery--diagnostics)
  - [5.4 Schema Provisioning](#54-schema-provisioning)
- [6. Non-Functional Requirements](#6-non-functional-requirements)
  - [6.1 Module-Specific NFRs](#61-module-specific-nfrs)
  - [6.2 NFR Exclusions](#62-nfr-exclusions)
- [7. Public Library Interfaces](#7-public-library-interfaces)
  - [7.1 Public API Surface](#71-public-api-surface)
  - [7.2 External Integration Contracts](#72-external-integration-contracts)
- [8. Use Cases](#8-use-cases)
  - [8.1 Acquire-Renew-Release Cycle](#81-acquire-renew-release-cycle)
  - [8.2 Crash Recovery After TTL Expiry](#82-crash-recovery-after-ttl-expiry)
  - [8.3 Lease-Guarded Write Loses Race](#83-lease-guarded-write-loses-race)
  - [8.4 Cursor-Based Consumer With Co-Located State](#84-cursor-based-consumer-with-co-located-state)
  - [8.5 Per-Acquire Worker Label Override](#85-per-acquire-worker-label-override)
- [9. Acceptance Criteria](#9-acceptance-criteria)
- [10. Dependencies](#10-dependencies)
- [11. Assumptions](#11-assumptions)
- [12. Risks](#12-risks)
- [13. Open Questions](#13-open-questions)
- [14. Traceability](#14-traceability)

<!-- /toc -->

## 1. Overview

### 1.1 Purpose

`modkit-coord` is the Cyber Fabric platform's crate for distributed coordination primitives. v1 ships a single primitive — an exclusive distributed lease for background-job consumers — as the crate's first member, with TTL-based crash recovery and lease-guarded write semantics so the holder's data writes commit only when the lease is still valid. The crate is structured as a multi-module home so that additional coordination primitives can be added as opt-in cargo features in future versions (for example, `features = ["semaphore"]`) without breaking the lease surface or forcing consumers to depend on functionality they do not need.

The library targets module authors building background jobs that must remain singleton across a multi-replica deployment — for example, outbox dispatchers, integrity reconcilers, and similar long-running consumers. It generalises the lease pattern that `modkit-db::outbox` already ships in-line, and provides a primitive that future consumers — such as a planned `account-management/integrity_check_runs` reconciler — can adopt without rolling their own DB-table-backed lease.

### 1.2 Background / Problem Statement

The Cyber Fabric platform expects modules to be deployed as multi-replica services. The "exactly one holder per cluster with crash-recovery" pattern is already shipped once: `modkit-db::outbox` carries its own per-partition lease implementation. Concretely, the lease-specific SQL templates `lease_acquire` / `lease_ack_advance` / `lease_record_retry` / `lease_release` live in `libs/modkit-db/src/outbox/dialect.rs:683-810` (~110 LOC of SQL template emission), plus the strategy-side lease lifecycle (`acquire_lease_and_read`, `lease_guarded_ack`, and surrounding orchestration) in `libs/modkit-db/src/outbox/strategy.rs:314-620` (a couple of hundred LOC of lifecycle code). The exact figure depends on whether you count the surrounding dispatch helpers, but it is several hundred lines of dialect-aware SQL plus async lifecycle per consumer that adopts this pattern. Other consumers — most concretely a planned `account-management/integrity_check_runs` reconciler that needs to run safely under multi-replica deployment — would have to copy that implementation or write a parallel one from scratch.

The duplication is not just developer toil. Each implementation has to independently solve the same subtle problems: atomic acquire-with-stale-sweep, fence-token semantics so a crashed-and-replaced holder cannot ack stale work, cross-backend SQL parity for PostgreSQL / SQLite / MySQL, renewal heartbeats for long-running holders, and forensic counters that surface crashed cycles. Without a shared primitive, every new consumer that needs exclusive background-job semantics must either re-derive the outbox approach or invent its own variant; either path creates a real risk of subtle behavioural drift between modules and increases the platform-wide audit cost as more modules adopt the pattern.

The platform needs a single library that captures the pattern once, supports the same relational backends as `modkit-db`, and exposes a high-level Rust API that no longer leaks raw SQL into consumers.

**Representative consumers the library is designed for:**

| Consumer | Status | Why a shared primitive helps |
|---|---|---|
| `modkit-db::outbox` | Existing in-tree implementation: per-partition lease with `locked_by` / `locked_until` / `attempts`, fence-protected ack-tx; lease-specific subset spread across `libs/modkit-db/src/outbox/dialect.rs:683-810` (~110 LOC of SQL templates) and `libs/modkit-db/src/outbox/strategy.rs:314-620` (~300 LOC of lifecycle orchestration). | Lifts the lease pattern out of the outbox crate so future consumers do not depend on `modkit-db::outbox` internals. Migration is owned by the outbox team in a follow-up PR. |
| `account-management/integrity_check_runs` | Planned consumer; no Rust source exists yet — only `docs/`. The reconciler is the canonical singleton-tenant use case the library is sized to absorb on first implementation. | Lands as a fence-protected lease from day one rather than re-deriving the outbox approach in-house. |
| Future module needing exclusive background-job semantics | Would otherwise have to copy `modkit-db::outbox`. | Adopts `modkit-coord` directly without rolling a third implementation. |

### 1.3 Goals (Business Outcomes)

- Reduce per-consumer lease implementation cost from several hundred lines of dialect-aware SQL plus async lifecycle code (the current `modkit-db::outbox` baseline; the lease-specific subset spans `dialect.rs:683-810` plus `strategy.rs:314-620`) to a one-line migration helper call plus a small typed API surface.
- Cover all relational backends supported by `modkit-db` — PostgreSQL, SQLite, MySQL — with semantically equivalent behaviour on every operation, validated by integration tests on each backend.
- Provide a public API surface where the only consumer-supplied SQL touches consumer-owned columns, never the lease columns: zero raw lease-state SQL on the `modkit-coord` public surface, enforced by a `cargo public-api` audit at release time. The corresponding zero-occurrences-in-consumer-crates outcome is owned by each consumer's migration PR (outbox migration, `account-management` first implementation), not by this PRD.
- Land an API surface that is sized to absorb both shapes the platform already has on the roadmap: a partitioned consumer (the outbox migration target) and a singleton consumer (the planned `account-management/integrity_check_runs` reconciler). Validation is the appearance of those two consumers in their own follow-up PRs; this PRD's acceptance is met when the surface is demonstrably sufficient for them.
- Provide forensic visibility for crashed holders via a per-key `attempts` counter that increments on every acquire and resets on clean release, so post-incident analysis can attribute crash cycles to specific keys without bespoke instrumentation.

### 1.4 Non-Goals

- The library MUST NOT provide distributed semaphores, counters, or barriers in v1. Those are different coordination primitives; if and when consumer demand emerges, they land in `modkit-coord` itself as additional modules behind opt-in cargo features (for example, `features = ["semaphore"]`), not as separate crates. v1 implementation effort is scoped to the lease primitive only — see §1.1 for the multi-primitive crate structure.
- The library MUST NOT support external coordination backends such as Redis, etcd, Consul, or ZooKeeper in v1; the lease and the work-data are required to live in the same relational database so that lease-guarded writes can be atomic.
- The library MUST NOT support cross-database-cluster coordination (for example, multi-region active-active) in v1; the same single-database assumption applies.
- The library MUST NOT ship a platform-managed shared schema. Each consumer module owns its own per-module database with its own coordination table; `modkit-coord` provides a migration helper that consumers call from their own migrator (one-line invocation), not a centrally-managed schema.

### 1.5 Glossary

| Term | Definition |
|---|---|
| Lease | Time-bounded exclusive ownership of a key in the coordination table. Acquired by a worker, renewed periodically, released when work completes, and reclaimable by another worker after expiry. |
| Lease key | The string identifier under which a lease is held. Singleton consumers (such as `integrity_check_runs`) use a fixed key; partitioned consumers (such as `outbox`) use the partition identifier as the key. |
| Worker identity | A UUIDv4 generated at acquire time. Stored in `locked_by` and used as the fence token: a contender takeover changes `locked_by`, which causes any later operation guarded by the previous worker's identity to fail atomically. The fence-token role is reserved exclusively for `locked_by`; no human-readable string carries lease-correctness semantics. |
| Worker label | An opaque, human-readable string the consumer optionally attaches at `LeaseManager` construction (or per-acquire override) for diagnostic logging and forensic queries (for example, `"outbox-partition-7-replica-A12F3B"`). Stored in the `worker_label` column. The label is **not** a fence token — `modkit-coord` neither parses nor validates it beyond a length bound, and contender takeover is decided solely by `locked_by`. |
| TTL | Time-to-live of a lease, supplied at `acquire`. The lease is considered expired and reclaimable once `locked_until` is in the past relative to the database clock. The acquire-time TTL is captured by the returned `LeaseGuard` and reused by every subsequent `renew` and `with_ack_in_tx` call against that guard; consumers MAY override the TTL on a specific call via the `*_with` variant when they need to extend or shorten a single cycle. |
| Stale-sweep acquire | An atomic INSERT-or-UPDATE that succeeds when no current holder exists or when the existing holder's TTL has expired. |
| Lease-guarded write | A database transaction that performs the holder's work writes and atomically validates `locked_by` against the holder's worker identity inside the same transaction; if validation fails, the entire transaction rolls back (which requires the consumer to propagate the `LeaseLost` error rather than swallow it — see `cpt-modkit-coord-fr-ack-in-tx`). |
| Renewal task | A background heartbeat task that periodically refreshes `locked_until` for a long-running holder so the lease does not expire mid-work. |
| Coordination table | The per-consumer table that holds the five `modkit-coord`-owned columns (`lease_key`, `locked_by`, `locked_until`, `attempts`, `worker_label`). Consumers MAY add their own state columns to the same table (for cursor-based progress, error diagnostics, etc.) or place that state in a separate table — `modkit-coord` operates only on its own five columns and does not interfere with consumer-added columns. |
| Consumer state columns | Additional columns a consumer chooses to place in the coordination table for their own work-state (e.g., `processed_seq`, `last_error`). These are owned and managed entirely by the consumer; `modkit-coord` neither creates nor reads them. |
| Consumer | A module crate that depends on `modkit-coord` to implement an exclusive background job. |

## 2. Actors

> **Note**: Stakeholder needs are managed at the project/task level by the steering committee. This section documents actors that interact with the `modkit-coord` library directly.

### 2.1 Human Actors

#### Module Author

**ID**: `cpt-modkit-coord-actor-module-author`

- **Role**: Rust developer building a Cyber Fabric module that includes a background job requiring exclusive single-holder semantics across a multi-replica deployment. Integrates `modkit-coord` into the module by calling the migration helper from the module's migrator stack and using the `LeaseManager` API from the module's worker code.
- **Needs**: A typed Rust API that hides dialect-aware SQL; a one-line migration helper that provisions the coordination table; clear semantics for lease loss, crash recovery, and lease-guarded writes; cross-backend behaviour parity so module tests pass on every supported backend.

#### Platform Maintainer

**ID**: `cpt-modkit-coord-actor-platform-maintainer`

- **Role**: Engineer responsible for the shared `modkit-*` library set. Maintains `modkit-coord` itself, reviews consumer integrations, and adjudicates open questions about lease semantics, schema shape, and backend coverage.
- **Needs**: A small, well-tested surface area; cross-backend integration tests; explicit invariants and non-goals so consumers cannot misuse the library in ways that break its guarantees.

### 2.2 System Actors

#### Consumer Migrator

**ID**: `cpt-modkit-coord-actor-consumer-migrator`

- **Role**: The migrator stack of a consumer module (for example, `account-management`'s migrator). Calls `modkit-coord`'s migration helper at module startup to provision or upgrade the per-consumer coordination table in the consumer's database.

#### Consumer Worker

**ID**: `cpt-modkit-coord-actor-consumer-worker`

- **Role**: A background-job task owned by a consumer module. Acquires a lease via `LeaseManager`, performs the consumer's work, optionally runs a renewal heartbeat for long-running cycles, and either commits work via a lease-guarded transaction or releases the lease cleanly when work completes.

#### Relational Database

**ID**: `cpt-modkit-coord-actor-database`

- **Role**: The PostgreSQL, SQLite, or MySQL backend in which the consumer's coordination table and work data both live. Provides atomic transaction semantics that `modkit-coord` relies on for stale-sweep acquire and lease-guarded writes. The same database instance MUST host both the coordination table and the work data so that lease-guarded writes can commit or roll back atomically.

## 3. Operational Concept & Environment

### 3.1 Module-Specific Environment Constraints

- The library targets the same relational backends as `modkit-db`: PostgreSQL, SQLite, and MySQL. No other backends are supported in v1.
- The coordination table and the consumer's work data MUST live in the same database instance. Cross-database coordination is explicitly out of scope; consumers that violate this constraint forfeit lease-guarded write atomicity.
- The library MUST NOT depend on the host filesystem (unlike the existing `modkit-db::advisory_locks` primitive, which is file-based and per-host). All coordination state lives in the database.
- The library targets the multi-replica deployment topology that the Cyber Fabric platform expects for module deployments. Single-replica deployments still work but do not exercise contention paths.
- TTL is supplied by the consumer per acquire call. The library does not impose a minimum or maximum TTL bound; selecting an appropriate value (and an appropriate renewal cadence relative to it) is a consumer concern documented in `DESIGN.md`.
- The library operates against the coordination table via dialect-aware SQL statements without binding the table to a `SeaORM` `Entity`. Consumers MAY define their own `Entity` types over the same table for their own state columns; `modkit-coord` and the consumer's `Entity` interact only by sharing the same database transaction when the lease-guarded transactional ack operation (`cpt-modkit-coord-fr-ack-in-tx`) is in use.
- The coordination table name is supplied by the consumer at `LeaseManager` construction time and at migration-helper invocation. The library validates the supplied name against a strict identifier format (`[A-Za-z_][A-Za-z0-9_]*`, length-bounded) at construction; consumers SHOULD follow the recommended naming convention `<module-slug>_coord_leases` documented in the crate `README`.
- The lease key is bounded to 255 bytes (UTF-8) by the library at `acquire` time; this is the intersection of the cross-backend column types defined in `DESIGN.md` (`TEXT` on PG / SQLite, `VARCHAR(255)` on MySQL). Keys longer than the bound are rejected with a typed error; the limit is documented at the API level rather than left to surface as a backend-specific failure.

## 4. Scope

### 4.1 In Scope

- Distributed lease primitive backed by any relational database supported by `modkit-db` (PostgreSQL, SQLite, MySQL), with semantically equivalent behaviour across backends.
- High-level Rust API consisting of a `LeaseManager` and an RAII `LeaseGuard`. No raw SQL exposed to consumers.
- Lease-guarded write semantics: the holder can perform work writes inside a transaction that atomically validates lease ownership; if the lease was lost to a contender, the transaction rolls back atomically together with the data writes.
- TTL-based stale-lease auto-recovery: a crashed holder's lease becomes reclaimable by the next contender after TTL expiry, without any manual intervention.
- Renewal-task lifecycle for long-running holders: a heartbeat keeps the lease alive past TTL while work is in progress.
- Crash-detection telemetry: a per-key `attempts` counter that increments on each acquire and resets on clean release, providing a forensic trace for crashed holders.
- A migration helper that consumers call from their own migrator stack to provision the per-consumer coordination table with the fixed shape.
- Cross-backend integration tests for concurrent acquire, lease-loss-during-write, renewal cancellation, and migration idempotency.

### 4.2 Out of Scope

- Distributed semaphores, counters, or barriers as v1 implementation. These are different coordination primitives; if needed later they land in this crate as additional opt-in modules (`features = ["semaphore"]`, etc.), not as separate crates. See §1.1 for the multi-primitive crate structure.
- External coordination backends (Redis, etcd, Consul, ZooKeeper). The single-database assumption is a hard architectural constraint of v1.
- Cross-database-cluster coordination (for example, multi-region active-active). Same single-database assumption.
- A platform-managed shared coordination schema. Each consumer owns its own per-module database with its own coordination table; the library only ships a migration helper.
- Concrete API signatures, SQL strings, and dialect mechanics. Those land in `DESIGN.md`. This PRD captures intent, not implementation detail.
- Per-consumer migration / first-implementation plans for the existing `modkit-db::outbox` lease and the planned `account-management/integrity_check_runs` reconciler. The outbox migration is owned by the outbox team in a follow-up PR (including the `locked_by` format-rollover plan documented in §12); the AM reconciler is a fresh implementation owned by the AM team and will adopt `modkit-coord` directly without a port.
- Replacement of the existing `modkit-db::advisory_locks` primitive. That primitive is a file-based per-host lock with different semantics; `modkit-coord` lives alongside it, not as a substitute.

## 5. Functional Requirements

> **Testing strategy**: All requirements verified via automated tests (unit, integration, e2e) targeting 90%+ code coverage unless otherwise specified. Integration tests run on PostgreSQL, SQLite, and MySQL.

### 5.1 Lease Lifecycle

#### Acquire Lease

- [ ] `p1` - **ID**: `cpt-modkit-coord-fr-acquire`

The system **MUST** provide an atomic acquire operation that either inserts a new lease row or sweeps a stale lease (one whose `locked_until` is in the past relative to the database clock) and returns an RAII handle on success. The acquire operation **MUST** accept the lease key, a TTL, and an optional per-call worker label override; the TTL supplied at acquire is captured by the returned handle and reused as the default for subsequent renew / lease-guarded-write operations against that handle. When another worker currently holds a non-expired lease for the same key, acquire **MUST** fail with a distinct lease-held error. Acquire **MUST** also reject lease keys longer than 255 bytes (UTF-8) with a distinct typed error before any database round-trip. Underlying database errors **MUST** surface via the platform's canonical error mapping so callers can distinguish contention from infrastructure failure.

- **Rationale**: Atomicity is the core correctness invariant of the primitive: any non-atomic acquire path admits two-holder windows that defeat the purpose of the lease. Capturing the TTL on the handle removes a class of consumer bugs where a renewal cadence and the original acquire TTL drift apart by accident; consumers that genuinely need a per-call TTL still have an explicit override path. The 255-byte key bound is the intersection of cross-backend column types and is enforced at the library boundary so consumers see a uniform error rather than a backend-specific truncation or insert failure.
- **Actors**: `cpt-modkit-coord-actor-consumer-worker`, `cpt-modkit-coord-actor-database`

#### Renew Lease

- [ ] `p1` - **ID**: `cpt-modkit-coord-fr-renew`

The system **MUST** provide a renew operation that extends `locked_until` for the current holder identified by their worker identity, using the TTL captured by the lease handle at acquire time. The renew operation **MUST** also expose an explicit-TTL variant that accepts a per-call TTL override for consumers that need to extend a single cycle differently from the acquire-time default. When a contender has already taken over the lease (zero rows updated because `locked_by` no longer matches), renew **MUST** return a distinct lease-lost error so the caller can abort cleanly without retrying.

- **Rationale**: Long-running holders need to extend their lease past TTL; a missing or weak renew path forces consumers to choose between unsafely long TTLs and frequent re-acquires that race contenders. Defaulting renew to the acquire-time TTL is the ergonomic path for the common case (one TTL per lease lifetime) while keeping the explicit-override path available so consumers retain full control when they need it.
- **Actors**: `cpt-modkit-coord-actor-consumer-worker`, `cpt-modkit-coord-actor-database`

#### Clean Release

- [ ] `p1` - **ID**: `cpt-modkit-coord-fr-release`

The system **MUST** provide a deterministic clean-release operation on the lease handle that frees the lease for the next contender and resets the per-key `attempts` counter to zero **when the holder still owns the row at release time**. The release statement is fenced by the worker identity (`WHERE locked_by = ?`); if a contender has already reclaimed the lease, the release statement matches zero rows and **MUST** be treated as already-evicted (success returned to the caller, `attempts` left untouched — the contender's reclaim already counted it). The handle's `Drop` implementation **MUST** also attempt a best-effort clean release so that panics or early returns from holder code do not leak the lease past TTL. `Drop` **MUST** always perform clean release (never retry release): consumers that need failure-streak preservation across an unwinding panic are required to call `cpt-modkit-coord-fr-release-with-retry` explicitly **before** any fallible code path that they expect might panic.

- **Rationale**: Deterministic release minimises hand-off latency between holders; best-effort drop keeps the system live even when consumer code does not call release explicitly. Clean release resets `attempts` so a successfully completed cycle does not pollute the failure-streak signal observed by the next contender — but only on the path where this holder is the row's current owner; a holder that already lost the lease cannot "reset" a counter that semantically belongs to the contender. Pinning `Drop` to always-clean removes ambiguity for consumers and for the `DESIGN.md` agent — the alternative (configurable Drop policy or auto-retry-on-panic) would require panic-payload introspection that is brittle in async runtimes; consumers needing deterministic retry semantics own that contract by making the explicit call.
- **Actors**: `cpt-modkit-coord-actor-consumer-worker`, `cpt-modkit-coord-actor-database`

#### Retry Release

- [ ] `p2` - **ID**: `cpt-modkit-coord-fr-release-with-retry`

The system **MUST** provide a retry-release operation on the lease handle that frees the lease for the next contender **without** resetting the per-key `attempts` counter. Holders that finish a cycle with a recoverable error (and intend the next holder to retry the same key) call this instead of clean release so the failure-streak signal accumulates across cycles.

- **Rationale**: Cursor-based consumers (such as `modkit-db::outbox`) treat `attempts` as a failure-streak counter, not a crash-detection-only counter; without retry release, every release would reset the streak and consumers would have to roll their own counter. With both forms, `attempts` cleanly distinguishes "recovered successfully" (clean release → 0) from "still failing across cycles" (retry release → preserved). Retry release does not record an error message: any consumer-specific diagnostic text (the equivalent of `last_error`) lives in a consumer state column and is written by the consumer inside `cpt-modkit-coord-fr-ack-in-tx`. Consumers using retry release for failure-streak preservation **MUST** call this method explicitly on the failure path; the lease handle's `Drop` performs clean release (see `cpt-modkit-coord-fr-release` rationale), so an unwinding panic that bypasses the explicit call resets `attempts` to zero by design.
- **Actors**: `cpt-modkit-coord-actor-consumer-worker`, `cpt-modkit-coord-actor-database`

#### Renewal Task Lifecycle

- [ ] `p2` - **ID**: `cpt-modkit-coord-fr-renewal-task`

The system **MUST** provide a managed renewal task lifecycle so consumers can keep a lease alive past TTL while long-running work is in progress. The lifecycle **MUST** support clean cancellation when the holder finishes, and **MUST** propagate lease-lost outcomes from the renewal loop to the holder so the holder can abort without committing stale work.

- **Rationale**: Without a managed renewal task, consumers either pick unsafely long TTLs (slow recovery from crashed holders) or implement their own heartbeat loops (the duplication this library exists to remove).
- **Actors**: `cpt-modkit-coord-actor-consumer-worker`

### 5.2 Lease-Guarded Writes

#### Lease-Guarded Transactional Ack

- [ ] `p1` - **ID**: `cpt-modkit-coord-fr-ack-in-tx`

The system **MUST** provide an operation that runs a caller-supplied work closure inside a consumer-owned database transaction and atomically validates lease ownership inside the same transaction before the transaction commits. When the lease has been lost to a contender (the in-tx ownership check finds `locked_by` no longer matches the holder's worker identity), the operation **MUST** return a distinct lease-lost error. The operation **MUST NOT** itself commit or roll back the transaction; the rollback path is realised structurally by the consumer's call shape — the consumer invokes the operation from inside `Db::transaction_ref(|tx| async { ... })` (or `transaction_ref_mapped`) and propagates the lease-lost error via `?` out of that closure, at which point `transaction_ref` observes the error and rolls back the underlying `DatabaseTransaction` it owns. The operation **MUST NOT** require the caller to write or inspect any lease-related SQL. The API documentation **MUST** spell out this consumer-owned rollback contract so a consumer that swallows the lease-lost error and returns `Ok` from the outer closure cannot accidentally trigger a commit-on-lost-lease.

- **Rationale**: Lease-guarded write atomicity is the second core correctness invariant: without it, a holder that lost the lease mid-cycle could still commit stale work concurrently with the new holder, defeating exclusive semantics. Pushing the ownership check into the same transaction as the work writes is the property that makes the lease useful for "exactly one consumer commits per cycle". The library cannot itself force a rollback because `modkit-db`'s `DbTx<'_>` is a borrow-only wrapper over `&DatabaseTransaction`; the actual `DatabaseTransaction` is owned by `Db::transaction_ref`, and only the closure-returns-`Err` path triggers the rollback. Anchoring the contract on `transaction_ref` (rather than telling consumers "drop the tx") ties correctness to a structural API boundary the consumer cannot trivially bypass.
- **Actors**: `cpt-modkit-coord-actor-consumer-worker`, `cpt-modkit-coord-actor-database`

### 5.3 Crash Recovery & Diagnostics

#### Stale Lease Reclaim

- [ ] `p1` - **ID**: `cpt-modkit-coord-fr-stale-reclaim`

The system **MUST** allow a contender to reclaim a lease whose `locked_until` is in the past relative to the database clock without requiring any manual intervention or operator action. Stale-reclaim **MUST** be performed atomically inside the same statement as the acquire path so two contenders cannot both reclaim the same stale lease.

- **Rationale**: TTL-based recovery is what makes the primitive resilient to crashed holders; without it, a single crash freezes the consumer until an operator intervenes.
- **Actors**: `cpt-modkit-coord-actor-consumer-worker`, `cpt-modkit-coord-actor-database`

#### Crash Forensics Counter

- [ ] `p2` - **ID**: `cpt-modkit-coord-fr-attempts-counter`

The system **MUST** maintain a per-key `attempts` counter that is incremented atomically by every acquire (including stale reclaims). The counter **MUST** be reset to zero on clean release (`cpt-modkit-coord-fr-release`) when the releasing holder still owns the row (the release statement's fence predicate matches), **MUST** be left untouched on clean release when the holder has already lost the lease to a contender (zero rows affected — see `cpt-modkit-coord-fr-release` for the conditionality), and **MUST** be preserved across retry release (`cpt-modkit-coord-fr-release-with-retry`) so that a non-zero value on the next acquire signals either a crashed-and-replaced previous holder, an in-progress failure-streak the consumer is intentionally tracking, or a Drop-after-loss path. The counter **MUST** be observable by consumers via the lease handle so they can emit telemetry or logs based on its value at acquire time.

- **Rationale**: Forensic visibility into crash cycles is currently bespoke per consumer; surfacing a uniform counter lets platform-wide dashboards and alerts treat crashed-holder events consistently.
- **Actors**: `cpt-modkit-coord-actor-consumer-worker`, `cpt-modkit-coord-actor-platform-maintainer`

### 5.4 Schema Provisioning

#### Migration Helper

- [ ] `p1` - **ID**: `cpt-modkit-coord-fr-migration-helper`

The system **MUST** provide a migration helper that consumers call from their own migrator stack to install the five `modkit-coord`-owned columns (`lease_key`, `locked_by`, `locked_until`, `attempts`, `worker_label`) in the per-consumer coordination table. The helper **MUST** accept the table name as the only consumer-controlled parameter; the five library-owned columns and their types are fixed by the library and not configurable. Consumers MAY add their own state columns (such as cursor position or last-error text) to the same table via their own migrator entries, or place that state in a separate table — the helper neither requires nor forbids consumer-added columns and is **idempotent** so consumers can safely include it in repeated migrator runs alongside their own column additions.

- **Rationale**: Migration ownership stays with the consumer (the consumer owns its database and its migrator), but the five `modkit-coord`-owned columns are fixed by the library so every coordination table across the platform remains compatible with `modkit-coord`'s SQL. The `worker_label` column is included in the library-owned set because the SQL emitted by the library writes to it during acquire (so consumers cannot opt out of the column without breaking acquire); see `cpt-modkit-coord-fr-attempts-counter` and the Glossary entry for "Worker label" for the role it plays. Allowing consumers to co-locate their own state columns matches the existing `modkit-db::outbox` topology (`processed_seq` + `last_error` alongside the lease columns) and avoids forcing consumers into a two-table topology when one suffices.
- **Actors**: `cpt-modkit-coord-actor-consumer-migrator`, `cpt-modkit-coord-actor-database`

#### Per-Consumer Table Naming

- [ ] `p2` - **ID**: `cpt-modkit-coord-fr-table-naming`

The system **MUST** require each consumer to declare its own coordination table name (for example, `am_coord_leases`, `outbox_coord_leases`) rather than sharing a single fixed table name across consumers. Two consumers that happen to share a database **MUST NOT** collide on a fixed table name.

- **Rationale**: Two modules can legitimately share a database, and a shared fixed table name would either force coordination-key namespacing across modules or cause silent collisions; per-consumer tables avoid both failure modes. The supplied name is also format-validated at construction time per the constraint documented in §3.1 (`[A-Za-z_][A-Za-z0-9_]*`, length-bounded), so a typo or injected fragment is rejected before any SQL emission.
- **Actors**: `cpt-modkit-coord-actor-module-author`, `cpt-modkit-coord-actor-consumer-migrator`

## 6. Non-Functional Requirements

> **Global baselines**: Project-wide NFRs (performance, security, reliability) defined in root PRD and platform guidelines. This section documents only library-specific NFRs.
>
> **Testing strategy**: NFRs verified via automated benchmarks, security scans, and concurrent integration tests unless otherwise specified.

### 6.1 Module-Specific NFRs

#### Cross-Backend Behavioural Parity

- [ ] `p1` - **ID**: `cpt-modkit-coord-nfr-cross-backend-parity`

The library **MUST** provide semantically equivalent behaviour for every public operation across PostgreSQL, SQLite, and MySQL.

- **Threshold**: Every public operation has an integration test that runs on all three backends; behavioural divergence (different observable outcomes for the same inputs) is treated as a defect, not a documented platform difference.
- **Rationale**: Consumers are expected to be portable across the same backends `modkit-db` supports; behavioural divergence at the lease layer would push backend-specific workarounds back into consumers.
- **Architecture Allocation**: See `DESIGN.md` § NFR Allocation for how cross-backend parity is realised.

#### SQL Encapsulation

- [ ] `p1` - **ID**: `cpt-modkit-coord-nfr-sql-encapsulation`

The library **MUST NOT** expose raw SQL to consumers. All lease-related SQL is internal to the crate's private modules.

- **Threshold**: Zero raw lease-state SQL exposed on the `modkit-coord` public API surface, enforced by a `cargo public-api` audit at release time. The downstream zero-occurrences-in-consumer-crates outcome is the responsibility of each consumer's migration / first-implementation PR (outbox migration; `account-management` first implementation); any consumer-side workaround that requires raw lease SQL is treated as a missing feature in `modkit-coord` rather than an acceptable consumer-side patch.
- **Rationale**: Mirrors the policy of `modkit-db::advisory_locks`, which forbids plain SQL outside migrations. Encapsulation is what lets the library evolve dialect emission without breaking consumers.
- **Architecture Allocation**: See `DESIGN.md` § Component Model for the internal layering that enforces encapsulation.

#### No Filesystem Dependency

- [ ] `p1` - **ID**: `cpt-modkit-coord-nfr-no-fs-dep`

The library **MUST NOT** depend on the host filesystem for lease state. All coordination state lives in the database.

- **Threshold**: 0 filesystem reads or writes from `modkit-coord` runtime code; static-analysis review during PR enforces this constraint.
- **Rationale**: The existing `modkit-db::advisory_locks` primitive is file-based and per-host, which makes it unsuitable for distributed coordination. `modkit-coord` exists precisely to fill the no-filesystem gap; reintroducing a filesystem dependency would defeat the primitive's purpose.

#### `modkit-db` Compatibility

- [ ] `p2` - **ID**: `cpt-modkit-coord-nfr-modkit-db-compat`

The library **MUST** integrate with the `modkit-db` secure-builder layer where applicable, so consumers configure their database connection through the same mechanisms they use for the rest of their data access.

- **Threshold**: Consumers configure connection setup through `modkit-db` builders; `modkit-coord` does not introduce a parallel connection-configuration surface.
- **Rationale**: A second connection-configuration path would split observability, security policy, and operational tooling between the lease layer and the rest of the consumer's data access; reusing `modkit-db` keeps consumer infrastructure uniform.
- **Architecture Allocation**: See `DESIGN.md` § External Dependencies for how `modkit-db` is consumed.

#### Test Coverage

- [ ] `p2` - **ID**: `cpt-modkit-coord-nfr-test-coverage`

The library **MUST** ship with the following automated test categories at a minimum: concurrent-acquire integration tests on each supported backend; a lease-loss-during-write integration test that exercises the rollback path (including a negative variant that confirms a consumer who swallows `LeaseLost` and commits anyway *does* corrupt state, so the rollback contract is not silently violated by future API changes); a renewal-cancellation unit test; a migration-idempotency test; a retry-release-preserves-attempts test that confirms the failure-streak counter survives across retry-release cycles and resets only on clean release; a co-located-consumer-columns test confirming that consumer-added columns in the coordination table do not interfere with `modkit-coord` operations and remain accessible to consumer SQL inside `with_ack_in_tx` closures; and a worker-label-survives-acquire test that confirms the `worker_label` column round-trips through acquire and is observable on the lease handle after both fresh-insert and stale-reclaim paths.

- **Threshold**: All seven test categories present in the test suite; concurrent-acquire, lease-loss-during-write, retry-release, co-located-columns, and worker-label tests run on PostgreSQL, SQLite, and MySQL.
- **Rationale**: Concurrent-acquire and lease-loss-during-write are the two paths where correctness regressions are most damaging and least likely to be caught by unit tests; renewal-cancellation and migration-idempotency are the lifecycle paths most prone to silent regressions; the retry-release and co-located-columns tests pin the two release flavours and the table-topology contract so consumer-state co-location is not silently broken by future internal refactors; the worker-label test pins the diagnostic-only role of `worker_label` so a future SQL refactor cannot accidentally drop the column from acquire and break operator-side log queries.

### 6.2 NFR Exclusions

- **Cross-region active-active replication**: Not applicable. The library's single-database assumption excludes cross-region active-active topologies by design. See `cpt-modkit-coord-fr-ack-in-tx` for why same-database co-location is required for atomic lease-guarded writes.
- **External-backend latency targets** (Redis, etcd, ZooKeeper): Not applicable. The library does not support external coordination backends in v1.
- **Filesystem-IO performance targets**: Not applicable. The library has no filesystem dependency (see `cpt-modkit-coord-nfr-no-fs-dep`).
- **Acquire / renew latency budgets**: Not applicable at the library level. `modkit-coord` is a thin DB-backed primitive whose per-operation latency is dominated by the underlying database round-trip and bounded by the consumer's TTL choice. Concrete latency targets are owned by each consumer's NFRs against their own use case.
- **Authentication and authorization (SEC)**: Not applicable. `modkit-coord` is consumed in-process by trusted module code; AuthN and AuthZ are owned by the host application's HTTP / AuthZ layer and are not part of this library's contract. The library does not expose a network surface and does not handle credentials.
- **Functional safety (SAFE)**: Not applicable. The library is a pure information system with no physical actuation, no real-time control loops, and no safety-critical decision paths.
- **Regulatory and standards compliance (COMPL)**: Not applicable. `modkit-coord` stores no personally identifying information, no payment data, and no regulated content; coordination state is limited to the five library-owned columns (`lease_key`, `locked_by`, `locked_until`, `attempts`, `worker_label`), and the consumer-supplied `worker_label` is documented as opaque deployment-identifier text rather than user data. Compliance posture for any consumer-added state columns is owned by the consumer module's data plane.

## 7. Public Library Interfaces

### 7.1 Public API Surface

#### Rust API: `LeaseManager` + `LeaseGuard`

- [ ] `p1` - **ID**: `cpt-modkit-coord-interface-rust-api`

- **Type**: Rust crate API (public modules within `modkit-coord`).
- **Stability**: experimental in v1; promoted to stable once the outbox migration and the AM reconciler first-implementation land and validate the surface.
- **Description**: High-level Rust interface for acquiring, renewing, lease-guarded-writing, and releasing leases. Concrete signatures are defined in the follow-up `DESIGN.md`; this PRD only commits to the surface area existing and to the operations described in section 5.
- **Breaking Change Policy**: Major version bump required for any breaking change to public types or method signatures. While the surface is `experimental`, breaking changes are permitted between minor versions with explicit changelog entries; once promoted to `stable`, semver applies in full.

#### Migration Helper Surface

- [ ] `p1` - **ID**: `cpt-modkit-coord-interface-migration-helper`

- **Type**: Rust function exposed for consumer migrator integration.
- **Stability**: experimental in v1, aligned with the main API surface.
- **Description**: Single entry point that consumers call from their own migrator to install the five `modkit-coord`-owned columns in the per-consumer coordination table. Accepts the table name as the only consumer-controlled parameter; the five library-owned columns and their types are fixed. Consumers MAY add their own state columns to the same table via separate migrator entries; the helper does not require those columns and does not interact with them.
- **Breaking Change Policy**: The five library-owned columns `(lease_key, locked_by, locked_until, attempts, worker_label)` and their types are part of the contract and cannot change without a major version bump and a documented upgrade path; consumer-added columns are not part of `modkit-coord`'s contract and are managed entirely by the consumer. The function signature follows the same policy as the main API surface.

### 7.2 External Integration Contracts

#### `modkit-db` Connection Backend

- [ ] `p1` - **ID**: `cpt-modkit-coord-contract-modkit-db`

- **Direction**: required from client (consumer-supplied database connection).
- **Protocol/Format**: `modkit-db` connection types and secure-builder layer.
- **Compatibility**: `modkit-coord` is compatible with the `modkit-db` major version current at the time of release; consumers using a divergent `modkit-db` major must upgrade to consume `modkit-coord`.

#### Coordination Table Schema

- [ ] `p1` - **ID**: `cpt-modkit-coord-contract-table-schema`

- **Direction**: provided by library (the migration helper installs `modkit-coord`-owned columns in the consumer's database).
- **Protocol/Format**: Five `modkit-coord`-owned columns `(lease_key, locked_by, locked_until, attempts, worker_label)` with library-defined column types compatible across PostgreSQL, SQLite, and MySQL. The library guarantees behaviour for these columns only; consumer-added columns in the same coordination table are outside the contract and managed entirely by the consumer.
- **Compatibility**: Changes to the five library-owned columns are major-version events with documented migration steps. Consumer table names and consumer-added columns are independent and do not affect compatibility.

## 8. Use Cases

### 8.1 Acquire-Renew-Release Cycle

#### Singleton Background Job Holder Cycle

- [ ] `p1` - **ID**: `cpt-modkit-coord-usecase-singleton-cycle`

**Actor**: `cpt-modkit-coord-actor-consumer-worker`

**Preconditions**:

- The consumer's coordination table has been installed by `cpt-modkit-coord-fr-migration-helper`.
- No other replica currently holds the lease for the consumer's key, or any prior lease has expired.

**Main Flow**:

1. Worker calls acquire on the lease key with a chosen TTL (and optionally a per-call worker label override).
2. Library performs atomic stale-sweep acquire, writing a freshly generated UUIDv4 to `locked_by` and the configured `worker_label` to its column, and returns an RAII lease handle that captures the acquire-time TTL.
3. Worker starts a renewal task that periodically calls renew before TTL elapses; renew uses the captured TTL by default.
4. Worker performs its background work; on each work-commit boundary it opens a transaction via `Db::transaction_ref(|tx| async { ... })` and from inside that closure invokes the lease-guarded transactional ack (`cpt-modkit-coord-fr-ack-in-tx`). The worker propagates any `LeaseLost` error from `with_ack_in_tx` via `?` out of the `transaction_ref` closure, so `transaction_ref` rolls back; otherwise the closure returns `Ok` and `transaction_ref` commits.
5. When the cycle completes, worker cancels the renewal task and calls release on the lease handle.

**Postconditions**:

- The lease has been released cleanly; `attempts` is reset to zero for the key.
- All work writes performed by the holder were committed inside lease-guarded transactions; no stale work was committed under a lost lease.

**Alternative Flows**:

- **Acquire fails because another worker holds the lease**: Worker returns lease-held without further side effects.

### 8.2 Crash Recovery After TTL Expiry

#### Reclaim Stale Lease From Crashed Holder

- [ ] `p1` - **ID**: `cpt-modkit-coord-usecase-stale-reclaim`

**Actor**: `cpt-modkit-coord-actor-consumer-worker`

**Preconditions**:

- A previous holder acquired the lease and crashed without releasing it.
- The lease's `locked_until` is now in the past relative to the database clock.

**Main Flow**:

1. New worker calls acquire on the same key.
2. Library detects the existing row's stale TTL and atomically rewrites `locked_by` to the new worker's UUIDv4, overwrites `worker_label` with the new worker's configured label, increments `attempts`, and extends `locked_until`.
3. Library returns a new RAII lease handle to the new worker.
4. Worker observes a non-zero `attempts` counter on the handle and emits forensic telemetry attributing the crash cycle to the previous holder. The previous holder's `worker_label` value is no longer in the row (it has been overwritten); operators relying on label history need to consult logs / tracing rather than the live row.
5. Worker proceeds with the standard acquire-renew-release cycle (`cpt-modkit-coord-usecase-singleton-cycle`).

**Postconditions**:

- The lease is held by the new worker.
- Forensic telemetry records the crash-recovery event without operator intervention.

**Alternative Flows**:

- **Two contenders race for the stale lease**: Atomic stale-sweep ensures only one contender succeeds; the other receives lease-held and retries on its own schedule.

### 8.3 Lease-Guarded Write Loses Race

#### Holder Loses Lease Mid-Cycle

- [ ] `p1` - **ID**: `cpt-modkit-coord-usecase-lease-loss-during-write`

**Actor**: `cpt-modkit-coord-actor-consumer-worker`

**Preconditions**:

- Worker A holds the lease and is performing work writes inside a lease-guarded transaction.
- Worker A's renewal task has fallen behind (for example, due to GC pause, scheduler delay, or network partition); meanwhile Worker B has observed TTL expiry and reclaimed the lease.

**Main Flow**:

1. Worker A opens a transaction by entering a `Db::transaction_ref(|tx| async { ... })` scope; the closure receives a borrow-only `DbTx<'_>`.
2. From inside that closure, Worker A calls `with_ack_in_tx(&guard, tx, work)`. The work closure performs Worker A's writes inside the same transaction.
3. The library validates ownership by checking `locked_by` against Worker A's worker identity inside the same transaction.
4. The check fails because Worker B's reclaim has changed `locked_by`. The library returns `LeaseLost`.
5. Worker A propagates `LeaseLost` via `?` out of the `transaction_ref` closure. `transaction_ref` observes `Err` from its closure and issues `ROLLBACK` against the underlying `DatabaseTransaction`, atomically discarding both the ownership-validation UPDATE and Worker A's work writes. Worker A does not retry.

**Postconditions**:

- No stale work writes from Worker A were committed.
- Worker B holds the lease and proceeds with its own cycle.

**Alternative Flows**:

- **Worker A's renewal task detects lease-lost first**: Worker A aborts the work closure before reaching the ownership check; the transaction is rolled back without ever attempting the writes.

### 8.4 Cursor-Based Consumer With Co-Located State

#### Cursor-Based Consumer With Retry Release

- [ ] `p1` - **ID**: `cpt-modkit-coord-usecase-cursor-with-retry`

**Actor**: `cpt-modkit-coord-actor-consumer-worker`

**Preconditions**:

- The consumer's coordination table has been installed by `cpt-modkit-coord-fr-migration-helper` and additionally has consumer-owned state columns (e.g., `processed_seq` cursor and `last_error` diagnostic) added via the consumer's own migrator entries.
- The lease key (e.g., a partition identifier) is available for the consumer to acquire.

**Main Flow**:

1. Worker calls acquire on the partition's lease key. The lease handle exposes the current `attempts` value, which the worker observes as a failure-streak signal.
2. Worker reads its own `processed_seq` cursor for the partition (via consumer-owned SQL or `Entity`) and selects the next batch of work past that cursor.
3. Worker processes the batch and computes the new cursor value plus any error diagnostic to record.
4. Worker enters a `Db::transaction_ref(|tx| async { ... })` scope and from inside the closure calls `cpt-modkit-coord-fr-ack-in-tx` with a work closure that updates `processed_seq` (and optionally `last_error`) on the same coordination row using its own SQL or `Entity`. `modkit-coord` validates lease ownership inside the same transaction; if validation succeeds the work closure returns `Ok`, the outer `transaction_ref` closure returns `Ok`, and `transaction_ref` commits both the consumer's column updates and the lease validation atomically. If validation fails (`LeaseLost`), the consumer's `?` propagates the error out of the `transaction_ref` closure and `transaction_ref` rolls back.
5. On a successfully completed batch, worker calls clean release (`cpt-modkit-coord-fr-release`); `attempts` is reset to zero.
6. On a recoverable error mid-cycle, worker calls retry release (`cpt-modkit-coord-fr-release-with-retry`) so the failure-streak counter on `attempts` survives to the next holder for diagnostic purposes.

**Postconditions**:

- The consumer's `processed_seq` cursor advanced atomically with the lease validation, or did not advance at all if the lease was lost.
- `attempts` reflects the consumer's chosen failure-streak semantics: zero after a clean cycle, monotonically non-decreasing across error cycles.
- Both the lease columns and the consumer's state columns live in the same coordination table; no two-table topology was required.

**Alternative Flows**:

- **Consumer prefers a separate state table**: Instead of co-locating `processed_seq` / `last_error` on the coordination table, the consumer places those columns in a dedicated table and updates that table inside the lease-guarded ack closure (`cpt-modkit-coord-fr-ack-in-tx`). `modkit-coord` operates identically — it cares only about its own five columns on the coordination table.

### 8.5 Per-Acquire Worker Label Override

#### Sharded Worker Pool With Per-Shard Labels

- [ ] `p2` - **ID**: `cpt-modkit-coord-usecase-per-acquire-label`

**Actor**: `cpt-modkit-coord-actor-consumer-worker`

**Preconditions**:

- The consumer has a single `Arc<LeaseManager>` shared across N tokio worker tasks (the recommended pattern from `DESIGN.md` §4.2). The manager was constructed with a deployment-level default `worker_label` such as `"outbox-replica-A12F3B"`.
- Each worker task owns a distinct shard / partition identifier and wants its own per-shard label appended to the deployment label, so operators querying logs by shard can filter on the row-level value directly.

**Main Flow**:

1. Worker task `i` builds its per-acquire label by composing the manager's default with its shard identifier — for example, `"outbox-replica-A12F3B/shard-{i}"`.
2. Worker task calls `acquire_with_label(key=shard_key, ttl, label=composed_label)` instead of bare `acquire`.
3. Library performs the standard atomic acquire and writes the composed label into `worker_label` on the row, alongside the freshly generated `locked_by` UUIDv4.
4. The lease handle returned to worker `i` exposes the resolved label via `LeaseGuard::worker_label()`; the worker emits `tracing` events that include the same value, so log queries and a SELECT on the row's `worker_label` column return matching strings.
5. Worker proceeds with the standard acquire-renew-release cycle.

**Postconditions**:

- The row's `worker_label` carries the per-acquire composed label (overwrites any previous holder's label, as documented in §1.5 Glossary and `cpt-modkit-coord-fr-acquire`).
- Multiple worker tasks under the same `Arc<LeaseManager>` produce row-level labels that distinguish them at the operator level without requiring per-task `LeaseManager` construction.

**Alternative Flows**:

- **Worker is fine with the default label**: Bare `acquire(key, ttl)` is used; the manager's default `worker_label` is written verbatim. The override is purely opt-in.

## 9. Acceptance Criteria

- [ ] The library provides the `LeaseManager` + `LeaseGuard` Rust API described in `cpt-modkit-coord-interface-rust-api`, with no raw SQL exposed to consumers.
- [ ] All public operations have integration tests that pass on PostgreSQL, SQLite, and MySQL with semantically equivalent outcomes.
- [ ] A concurrent-acquire integration test demonstrates that exactly one of N concurrent contenders succeeds in acquiring an unheld or stale lease.
- [ ] A lease-loss-during-write integration test demonstrates that a holder whose lease was reclaimed mid-cycle, when it propagates `LeaseLost` and drops its transaction, has its work writes rolled back atomically; the same test fixture's negative variant confirms that a consumer who swallows `LeaseLost` and commits anyway *does* see corruption, pinning the rollback contract as consumer-side.
- [ ] A renewal-cancellation unit test demonstrates clean shutdown of the renewal task and propagation of lease-lost outcomes.
- [ ] A migration-idempotency test demonstrates that re-running the migration helper on an already-installed coordination table is a no-op.
- [ ] The migration helper installs the five `modkit-coord`-owned columns `(lease_key, locked_by, locked_until, attempts, worker_label)` in a consumer-supplied coordination table and is callable from a consumer's existing migrator stack in one line; consumer-added columns in the same table are accepted without interference.
- [ ] The `attempts` counter is observable by consumers and resets to zero on clean release; retry release preserves the counter so cursor-based consumers can use it as a failure-streak signal.
- [ ] A retry-release-preserves-attempts integration test demonstrates that `attempts` survives across retry releases and resets only on clean release, on every supported backend.
- [ ] A co-located-consumer-columns integration test demonstrates that consumer-added columns in the coordination table coexist with `modkit-coord`'s columns and remain accessible to consumer SQL inside `with_ack_in_tx` closures.
- [ ] A worker-label round-trip integration test demonstrates that the configured `worker_label` is written to the row on both fresh-insert and stale-reclaim acquire paths and is observable on the lease handle, on every supported backend.
- [ ] An acquire-time TTL is captured by the returned `LeaseGuard` and reused by default for `renew` / `with_ack_in_tx`; an explicit per-call TTL override variant is available for both operations and exercised by a unit test.
- [ ] Lease keys longer than 255 bytes (UTF-8) are rejected at `acquire` with a typed error before any database round-trip, exercised by a unit test.
- [ ] The library API surface and developer documentation are sufficient for a future third consumer to adopt `modkit-coord` without coordinating with the platform team — covered by the README quickstart, the public API rustdoc, and one worked-example test in the repository.

## 10. Dependencies

| Dependency | Description | Criticality |
|---|---|---|
| `modkit-db` | Connection types (`Db`, `DbConn`, `DbTx`), secure-builder layer, and dialect coverage for PostgreSQL / SQLite / MySQL. | p1 |
| Tokio async runtime (workspace default) | Hosts the renewal task lifecycle and the `Drop`-time best-effort release task. | p1 |
| `uuid` (workspace dependency) | Generates per-acquire worker identities (UUIDv4 fence tokens). | p1 |
| `time` (workspace dependency) | Computes `locked_until` from the configured TTL via `time::OffsetDateTime` and `time::Duration` — the workspace timestamp standard already used by sibling `modkit-*` crates. | p2 |
| `tracing` (workspace dependency) | Library-internal observability for acquire / renew / release / lease-loss events. | p2 |

## 11. Assumptions

- Consumers deploy with `modkit-db`-supported relational backends and configure their database connection through `modkit-db`'s builder layer.
- Consumers' background-job consumers and their work data live in the same database instance; cross-database coordination is explicitly out of scope.
- The platform's multi-replica deployment topology applies, so contention paths are exercised in real deployments rather than only in tests.
- Consumers control their own migrator stack and can include `modkit-coord`'s migration helper alongside their existing migrations.
- Database clocks are reasonably synchronised within each backend's transaction-visibility model; severe clock skew across the cluster is treated as an operational fault, not a `modkit-coord` concern.
- MySQL consumers run their work transactions at the default `REPEATABLE READ` isolation level (or stricter). The MySQL acquire path's atomicity (`cpt-modkit-coord-fr-acquire`) relies on row-level locks taken by the conditional `UPDATE` inside the explicit transaction; running consumers under `READ UNCOMMITTED` invalidates the acquire-atomicity invariant and forfeits the contention guarantee. PostgreSQL's and SQLite's defaults satisfy the same invariant without an explicit constraint.

## 12. Risks

| Risk | Impact | Mitigation |
|---|---|---|
| Consumers misuse the library by storing work data in a different database than the coordination table, defeating lease-guarded write atomicity. | Stale work commits under a lost lease; correctness regression for the consumer. | Document the same-database constraint prominently in the README and the API docs; cover it explicitly in the migration helper's documentation; surface it as a hard architectural assumption in `DESIGN.md`. |
| Per-consumer table naming creates inconsistent operational tooling (dashboards, queries) across modules. | Increased operational cost for platform maintainers. | Recommend a naming convention (`<module>_coord_leases`) in documentation; provide example queries that work against any consumer's table given the fixed shape. |
| Cross-backend SQL parity drifts as backends evolve, producing subtle behavioural differences between PostgreSQL, SQLite, and MySQL. | Consumers see backend-dependent regressions; trust in the abstraction erodes. | Cross-backend behavioural-parity NFR (`cpt-modkit-coord-nfr-cross-backend-parity`) gates every release; integration tests run on all three backends in CI. |
| Renewal task lifecycle complexity (cancellation propagation, lease-lost notification) introduces subtle bugs that consumers cannot diagnose. | Hidden lease-lost events; silent stale work commits in the worst case. | Mandatory renewal-cancellation unit test (`cpt-modkit-coord-nfr-test-coverage`); explicit lease-lost propagation contract in the API; library-internal `tracing` events for every lifecycle transition. |
| The fixed schema shape proves insufficient for a future consumer's needs (for example, consumers wanting a richer state column). | Library cannot serve the new consumer; pressure to either bloat the schema or fork the library. | Treat the fixed shape as a hard contract; if a future consumer needs richer state, that is a v2 conversation with an explicit migration story rather than an ad-hoc schema extension. |
| `modkit-db::outbox` migration changes the on-disk `locked_by` format. The outbox today writes `"{queue_name}-{6-char}"` strings into `locked_by`; `modkit-coord` writes UUIDv4. The migration cycle (rolling deploy → both formats coexist briefly → fully on `modkit-coord`) admits brief windows where two replicas use different fence-token shapes. | Possible spurious lease-lost or false-acquire during the rollover if the migration code does not handle both formats simultaneously. | The outbox-side migration PR owns the rollover plan: drain in-flight leases before swap, or run a brief compatibility shim that accepts both formats in `WHERE locked_by = ?`. `modkit-coord` itself sees only UUIDv4 and is not responsible for the bridge; this risk is documented here so the outbox migration PR cannot start without addressing it. |

## 13. Open Questions

- ~~Should the renewal-task lifecycle be opt-in or opt-out?~~ **Resolved (DESIGN §3.3, §4.4 line `cpt-modkit-coord-design-open-question-renewal-task`)**: opt-in via `LeaseManager::spawn_renewal`. Reverting to opt-out is additive and non-breaking; the v1 surface commits to opt-in to keep the construction surface minimal and the cancellation-token contract explicit.
- Should `attempts` be capped (saturating after a configurable limit) to protect against pathological crash loops bloating the counter, or left uncapped because the value carries forensic information? Owner: Platform Maintainer; target resolution: before v1 GA.
- Should `modkit-coord` provide a built-in metric exporter (counters for acquires, renews, lease-losses) on top of `tracing`, or leave that responsibility to consumers via existing platform observability layers? Owner: Platform Maintainer; target resolution: before v1 GA.

## 14. Traceability

Links to related specification artifacts.

- **Design**: [DESIGN.md](./DESIGN.md)
- **ADRs**: [ADR/](./ADR/) (none yet; created as architecture decisions arise)
- **Reference implementation the library generalises**:
  - `modkit-db::outbox` lease-with-fence pattern (`libs/modkit-db/src/outbox/dialect.rs`, `libs/modkit-db/src/outbox/strategy.rs`) — the only existing in-tree implementation; informs the dialect-module pattern, the fence-token shape, and the cross-backend SQL split (PG/SQLite single statement, MySQL multi-statement).
- **Adjacent primitive (not generalised by this library)**:
  - `modkit-db::advisory_locks` file-based per-host primitive (`libs/modkit-db/src/advisory_locks.rs`); `modkit-coord` lives alongside it, not as a substitute. The advisory-locks module documents in its header that it forbids raw SQL outside migrations; `modkit-coord` inherits that policy.
- **Planned consumer (no in-tree implementation yet)**:
  - `account-management/integrity_check_runs` reconciler — the canonical singleton-tenant use case the library is sized to absorb. The `account-management` module currently ships only `docs/`; the reconciler lands as a `modkit-coord` consumer in its own follow-up PR rather than as a port of an existing implementation.
