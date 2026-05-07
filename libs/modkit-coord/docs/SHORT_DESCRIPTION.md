# How modkit-coord works — explanation

## Why do we even need this?

Imagine: you have a background job (e.g. an outbox dispatcher that sends emails from a queue). You deploy your app in **3 replicas** for reliability. But if all 3 replicas start sending the same emails at the same time — you get spam. **You need a mechanism that says: "only one replica works, the others wait."**

That's a **distributed lease**.

---

## The main characters

In a DB table (let's call it `outbox_coord_leases`) we store 4 columns:

| Column | Meaning |
|---|---|
| `key` | Job identifier (e.g. `"outbox"` or `"partition-7"`) |
| `locked_by` | UUID of the worker currently holding the lease |
| `locked_until` | Until what time the lease is considered alive |
| `attempts` | Counter of attempts (for crash diagnostics) |

---

## Basic scenario: "acquire → renew → release"

### Step 1. Acquire
Worker A comes and says to the DB:
> "Give me a lease on key `outbox` for 30 seconds"

The DB atomically (in a single SQL statement) does:
- if no row exists — inserts one with `locked_by = uuid_A`, `locked_until = now() + 30s`
- if a row exists but `locked_until < now()` (expired) — overwrites it with uuid_A
- otherwise — returns "already held"

Worker B that arrived at the same moment gets "held" and goes to drink tea.

### Step 2. Renew
Work can take more than 30 seconds. So worker A spawns a background "heartbeat":
> Every ~10 seconds: "Extend my lease by another 30 seconds, I'm still working"

SQL: `UPDATE ... SET locked_until = now() + 30s WHERE key='outbox' AND locked_by = uuid_A`

Key detail: `WHERE locked_by = uuid_A`. If somebody has already taken the lease over — `locked_by` is different, the update affects **0 rows**, and we know "I lost the lease."

### Step 3. Release
Done with the work — release the lease so others don't have to wait for TTL.

---

## Trick #1: fence token

**Problem:** worker A "froze" (e.g. a 40-second GC pause). Meanwhile:
1. TTL expired
2. Worker B acquired the lease
3. Worker B already wrote something to the DB
4. Worker A "thawed" and thinks: "I still hold the lease, let me commit my work now"

If A commits — you get **double writes**. Disaster.

**Solution:** the worker's UUID (`locked_by`) is the **fence token**. When A wants to commit work, it does it like this (simplified):

```sql
BEGIN TRANSACTION;
  -- worker's work: UPDATE my_data SET ...
  -- ownership check: am I still the holder?
  SELECT 1 FROM outbox_coord_leases
    WHERE key='outbox' AND locked_by = uuid_A;
  -- if 0 rows — ROLLBACK the whole transaction
COMMIT;
```

This is the **lease-guarded write** — a write protected by the lease. The ownership check and the work itself live in the **same transaction**. Either everything commits, or everything rolls back.

In the API this will be a method like `with_ack_in_tx(closure)` — you pass a closure with your work, the library wraps it in a transaction + ownership check.

---

## Trick #2: the `attempts` counter

Every `acquire` (including reclaiming an expired lease) does `attempts += 1`.
- **Clean release** (`release`) → `attempts = 0`
- **Retry release** (`release_with_retry`) → `attempts` is preserved

**Why?** If a new worker acquires the lease and sees `attempts = 7` — that means somebody crashed 7 times on this key. You can fire an alert.

`retry_release` is for scenarios like "I didn't crash, but processing didn't succeed — let the next one retry, and let's keep the failure-streak counter."

---

## Full lifecycle (use case 8.1)

```
Worker A:
  1. acquire("outbox", ttl=30s)        → got a LeaseGuard
  2. spawn renewal_task (renews every 10s)
  3. in a loop:
       with_ack_in_tx(|tx| {
         // reads its work
         // writes the result
         // library checks locked_by == uuid_A inside
       })
  4. cancel(renewal_task)
  5. release()                          → attempts = 0, lease is free
```

If worker A crashes: the renewal_task no longer runs → `locked_until` expires → worker B does `acquire` and atomically takes over (`attempts += 1`).

---

## Key invariants (what the library guarantees)

1. **Exclusivity**: at any moment in time, only one worker holds a valid (non-expired) lease on a key.
2. **Atomic acquire**: two workers cannot simultaneously reclaim an expired lease — atomic SQL.
3. **Atomic write**: if you lose the lease in the middle of your work — your work will NOT be committed (rollback of the whole transaction).
4. **Auto-recovery**: a crashed worker does not block the system — TTL expires, the next one takes over.

---

## What you as a consumer write

```rust
// in the module's migrator — once
modkit_coord::install_migration(&mut migrator, "outbox_coord_leases");

// in the worker
let manager = LeaseManager::new(db, "outbox_coord_leases");
let guard = manager.acquire("outbox", Duration::from_secs(30)).await?;
let _renewal = guard.spawn_renewal(Duration::from_secs(10));

guard.with_ack_in_tx(|tx| async move {
    // your work here — plain SeaORM/SQL
    Ok(())
}).await?;

guard.release().await?;  // or just drop — best-effort release will run
```

**You write zero SQL related to the lease.** That's the whole point of the library — to replace ~150 lines of duplicated SQL in every module with a single typed API.
