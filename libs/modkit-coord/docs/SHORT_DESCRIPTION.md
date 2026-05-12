# How modkit-coord works — explanation

We will use a real consumer — `account-management`'s **hierarchy integrity reconciler** — as the running example. Every concept below is illustrated against it.

---

## Why do we even need this?

Account-management ships a background job that periodically:
1. **Snapshots** the tenant hierarchy (closure table — for 100k tenants at depth 10 that's ~1M rows).
2. **Classifies** anomalies (orphans, cycles, depth violations, stale parent pointers).
3. **Repairs** what it can repair, writing UPDATE/DELETE corrections back to the same tables.

Two facts collide:

- **AM deploys multi-replica** for HA. Without coordination, every replica runs its own integrity check on the same tenants at the same time.
- **The repair phase writes correction SQL.** If two replicas repair the same anomaly concurrently with different snapshots, you get **double-corrections** — corrupted closures, lost parent pointers, broken counters.

So: **only one replica is allowed to run the integrity check at a time across the cluster.** That's the whole job of `modkit-coord`.

It's NOT just "exclusive access" — it's exclusive access **that survives crashes, GC pauses, VM suspends, and slow runs without operator intervention.** That last part is what's hard, and it's what the rest of this doc explains.

---

## The four columns we live in

In a DB table named by the consumer (recommended convention: `am_coord_leases` for AM), `modkit-coord` owns four columns:

| Column | Meaning | For the integrity reconciler |
|---|---|---|
| `key` | The lease's identifier — different consumers can use different keys in the same table | A fixed string `"hierarchy_integrity"` (singleton job — one key forever) |
| `locked_by` | UUID of the worker currently holding the lease | The UUID of the AM replica's reconciler task |
| `locked_until` | When the lease expires (DB clock) | `now() + 15 minutes` per the planned `LEASE_TTL` |
| `attempts` | Forensic counter — increments on every acquire, resets on clean release | How many times somebody crashed mid-check on this key |

The consumer **may add their own columns** to the same table (cursor positions, last error, etc.) and `modkit-coord` will not touch them. The reconciler currently does NOT need extra columns — its work-state lives in `integrity_check_runs` already.

---

## Basic scenario: "acquire → renew → release"

### Step 1. Acquire

Replica A's reconciler task wakes up on its 30-minute schedule and asks the DB:
> "Give me the lease on key `hierarchy_integrity` for 15 minutes."

The DB does it atomically — in a single SQL statement:

- if there's no row — INSERT it with `locked_by = uuid_A`, `locked_until = now() + 15min`
- if there's a row but `locked_until < now()` (the previous holder is dead by TTL) — UPDATE it with `uuid_A`
- otherwise — return "already held"

Replica B was about to start its own reconciler at the same moment? It gets "already held" and the AM service maps that to `DomainError::IntegrityCheckInProgress` — its scheduler logs "skipped, another replica is running" and tries again on the next tick. **No spinning, no waiting** — singleton background jobs don't queue, they skip.

### Step 2. Renew

The actual integrity check on a big hierarchy can easily take **5-8 minutes**. The lease was granted for 15. What if the snapshot+classify+repair takes 20?

Solution: replica A spawns a tiny background "heartbeat":
> Every 5 minutes: "Extend my lease by another 15 minutes, I'm still working."

The SQL:

```sql
UPDATE am_coord_leases
   SET locked_until = now() + 15min
 WHERE key = 'hierarchy_integrity'
   AND locked_by = uuid_A
```

Notice the `AND locked_by = uuid_A`. **This is the safety net.** If somebody else has taken over (their `uuid_B` is now in `locked_by`), the UPDATE affects **zero rows**, and the renewal task immediately knows "I lost the lease." It signals the holder, the holder aborts cleanly (more on that below).

### Step 3. Release

The reconciler finished its check + repair successfully. It calls `release` — a `DELETE` (or in some implementations an UPDATE that clears the row). The lease is now free; the next replica's scheduled tick will pick it up.

`release` ALSO resets `attempts` to zero. A clean release means "the previous run finished normally" — no forensic noise.

---

## Trick #1: fence token (the killer feature for integrity reconciler)

This is where the integrity reconciler **really** needs `modkit-coord` versus a naive lock.

### The scenario that breaks naive locks

1. Replica A acquires the lease, starts the integrity check.
2. Replica A is in the middle of writing repair UPDATEs — say, it's rewriting `parent_id` on 50 stale tenant rows.
3. Replica A's host gets **VM-suspended** (live migration, hypervisor freeze, OS swap-in stall — pick any cause). The whole runtime, including the renewal heartbeat, is frozen.
4. While A is frozen, the lease's `locked_until` passes. Replica B's reconciler ticks, sees the expired row, atomically takes over (`locked_by` now = `uuid_B`).
5. Replica B starts its own check + repair on the same tenants.
6. Replica A's host **resumes**. From A's point of view, no time has passed. Its half-written repair transaction continues. It commits.

**Result without a fence**: both A and B repaired the same anomalies with different snapshots. The closure table is now in an inconsistent state. The reconciler — the thing whose job is to fix integrity — just broke integrity.

### How the fence token fixes it

The worker's UUID (`locked_by`) **is** the fence token. When A commits its repair, it doesn't just write — it writes inside a transaction that **also** validates the lease in the same SQL transaction:

```sql
BEGIN TRANSACTION;

  -- repair work
  UPDATE tenant_closure SET ... WHERE ...;
  DELETE FROM tenant_closure WHERE depth > max_depth;
  UPDATE tenants SET parent_id = ... WHERE ...;

  -- the fence check, IN THE SAME TRANSACTION:
  SELECT 1
    FROM am_coord_leases
   WHERE key = 'hierarchy_integrity'
     AND locked_by = uuid_A;
  -- if zero rows → return error; the whole transaction rolls back

COMMIT;
```

When A "thaws" and tries to commit, the `SELECT` returns zero rows because B has rewritten `locked_by` to `uuid_B`. A's transaction rolls back **atomically** — the repair UPDATEs and the fence check are undone together. A returns `LeaseLost` to its caller; the reconciler aborts cleanly without committing anything.

This is `with_ack_in_tx(closure)` in the public API. You hand `modkit-coord` a closure that does the repair work, and the library wraps it with the fence-validating transaction around it. **The integrity reconciler's repair phase calls exactly one method**: `guard.with_ack_in_tx(|tx| async move { run_repair(tx).await })`.

### Why this is impossible with Redis-locks or cluster's `DistributedLockV1`

Both alternatives store the lease in a **different system** from the data the reconciler is repairing. There's no cross-system atomic transaction — Redis-lock + Postgres-data cannot commit-or-rollback together. `modkit-coord` mandates the same DB for the lease and the work precisely because that's the only way the fence-in-tx pattern is correct.

---

## Trick #2: the `attempts` counter — for crash forensics

Every `acquire` (including stale-takeover) does `attempts += 1`.

- **Clean release** (success path) → `attempts = 0`
- **Retry release** (consumer says "I didn't crash, but my work didn't finish — keep the streak") → `attempts` preserved

Why does this matter for integrity?

Imagine the reconciler keeps failing midway on the same hierarchy. Crash → TTL expires → next replica picks up → `attempts` is now 1. Crashes again → 2. And so on.

When the next replica acquires and sees `attempts = 7` on the handle, it can:
- Emit `tracing::warn!(target="am.integrity", attempts=7, "previous_runs_crashed_in_a_row")`.
- The platform's alerting layer fires a page: "AM integrity reconciler has failed 7 times in a row — somebody is crashing mid-classification on this hierarchy."

Without the counter, every crash would look isolated. The pattern would be invisible.

The reconciler today uses **clean release on success** (so `attempts` resets to 0 after a healthy run) and would use **retry release on a recoverable error** (e.g. classifier returned `IntegrityViolationsTooLargeForOneRun` — we'll come back next tick, please remember we already tried).

---

## Full lifecycle: integrity reconciler service flow

```
AM scheduler tick (every 30 minutes per hierarchy):

  1. let manager = LeaseManager::new(db, "am_coord_leases");
  2. let guard = manager.acquire("hierarchy_integrity", LEASE_TTL).await
       ?error_path: LeaseHeld → log "skipped, another replica running"; return;

  3. let renewal = guard.spawn_renewal(RENEW_INTERVAL);  // 5-min heartbeat
       // renewal sends RenewalState::Lost on the watch channel if the
       // lease is taken over before we get a chance to renew.

  4. let snapshot = take_hierarchy_snapshot(db).await?;        // read-only
     let anomalies = classify(snapshot);                         // pure compute
     let repairs   = decide_repairs(anomalies);                  // pure compute

  5. // The actual write phase — the only place that needs the fence:
     guard.with_ack_in_tx(|tx| async move {
         apply_repairs(tx, repairs).await
     }).await
       ?error_path: AckError::LeaseLost → log "lease lost mid-repair, aborting";
                                          DO NOT release (TTL handles it).
                                          return;

  6. renewal.cancel().await?;
  7. guard.release().await?;     // attempts = 0; next tick is a clean run
```

If replica A crashes anywhere between step 2 and step 7:
- The renewal task stops sending heartbeats.
- `locked_until` expires after at most one TTL window.
- Replica B's next tick acquires the stale lease, increments `attempts`, and proceeds.
- A's repair (if any was in flight) was either already committed (clean) or rolled back at the fence check (no harm done).

---

## Key invariants (what the library guarantees for the reconciler)

1. **Exclusivity** — at any moment, exactly one AM replica holds a valid lease on `"hierarchy_integrity"`. No double-runs.
2. **Atomic acquire** — two replicas reclaiming the same expired lease cannot both win; one gets the row, the other gets `LeaseHeld`.
3. **Atomic write** — if A loses the lease while in `with_ack_in_tx`, **A's repair is rolled back atomically** with the fence check. The reconciler cannot corrupt data after losing its lease.
4. **Auto-recovery** — a crashed reconciler does not freeze the platform. After at most one TTL (15 min in our case), the next replica takes over without operator action.

---

## What the reconciler actually writes

```rust
// Once, at AM module migrator setup:
modkit_coord::install_migration(&mut migrator, "am_coord_leases");

// Every scheduler tick, in domain/integrity_check/service.rs:
let manager = LeaseManager::new(db.clone(), "am_coord_leases");
let guard = match manager.acquire("hierarchy_integrity", LEASE_TTL).await {
    Ok(g) => g,
    Err(CoordError::LeaseHeld) => {
        // expected on multi-replica deployments — another replica is running
        return Ok(IntegrityCheckOutcome::SkippedInProgress);
    }
    Err(e) => return Err(e.into()),
};

let renewal = guard.spawn_renewal(RENEW_INTERVAL);

let snapshot  = take_hierarchy_snapshot(&db).await?;
let anomalies = classify(snapshot);
let repairs   = decide_repairs(anomalies);

let outcome = guard.with_ack_in_tx(|tx| async move {
    apply_repairs(tx, repairs).await
}).await;

renewal.cancel().await?;

match outcome {
    Ok(repair_summary) => {
        guard.release().await?;          // attempts → 0
        Ok(IntegrityCheckOutcome::Completed(repair_summary))
    }
    Err(AckError::LeaseLost) => {
        // do NOT release — TTL handles this
        Ok(IntegrityCheckOutcome::AbortedLeaseLost)
    }
    Err(AckError::Work(domain_err)) => {
        guard.release_with_retry().await?;  // attempts preserved → forensic signal
        Err(domain_err)
    }
    Err(AckError::Db(db_err)) => Err(db_err.into()),
}
```

**Total lease-related SQL written by AM**: zero. That's the point of the library — the reconciler used to ship ~150 lines of dialect-aware lease SQL inline. With `modkit-coord`, the reconciler talks to a typed Rust API and the SQL stays inside the library.

---

## What changes if a future consumer arrives

A future module that needs the same pattern (e.g. a per-partition outbox dispatcher) calls `install_migration` with its own table name (`outbox_coord_leases`), uses partition IDs as keys (`"partition-7"` instead of singleton `"hierarchy_integrity"`), and gets the same correctness guarantees for free. The library does not change; the consumer picks its key shape and table name.

The integrity reconciler is the **first** consumer because it has the most painful form of the problem (long-running repair under multi-replica deployment with same-DB writes). Once it works for the reconciler, smaller use cases inherit the same primitive.
