//! Integration tests for the retention pipeline against a real `SQLite` / Postgres
//! database.
//!
//! These tests are **ignored by default** until the AM integration-test scaffold
//! (real DB connection, migration runner, module initialisation) is in place.
//! See `feature-tenant-hierarchy-management.md` retention § for the test
//! requirements and tracking issue for the scaffold.
//!
//! ## What these tests must cover once the scaffold lands
//!
//! 1. **`scan_retention_due` ordering** — seed rows at multiple depths with
//!    `deletion_scheduled_at` values that straddle the retention window boundary.
//!    Assert the returned Vec is sorted `depth DESC, id ASC` and that rows whose
//!    `scheduled_at + retention_window > now` are excluded.
//!
//! 2. **`is_due` SQL vs Rust parity** — insert a row whose `scheduled_at` is
//!    exactly `now - retention_window`. The SQL predicate and the Rust
//!    `is_due(now, scheduled_at, retention)` check must both return `true`.
//!
//! 3. **Claim-lock atomicity** — start two concurrent `scan_retention_due` calls
//!    on the same batch. Assert each row appears in exactly one of the two result
//!    sets (no double-processing).
//!
//! 4. **Default vs per-row retention window** — insert one row with
//!    `retention_window_secs = NULL` (uses module default) and one with an
//!    explicit override. Assert each row becomes due at the correct wall-clock
//!    time.
//!
//! 5. **Leaf-first FK guard** — insert a parent and a child both past their
//!    retention window. Run `hard_delete_batch`. Assert the child row is removed
//!    first and the parent succeeds in the same tick without a FK violation.

// Remove this attribute and add the DB setup once the scaffold is ready.
#[allow(unused_imports)]
use std::marker::PhantomData;

/// Placeholder — replace with real integration tests once the scaffold is ready.
///
/// Running `cargo test --ignored` will fail here as a reminder that this
/// scaffold is not yet complete.
#[test]
#[ignore = "AM integration-test scaffold not yet in place; see feature-tenant-hierarchy-management.md retention § and tracking issue for scan_retention_due SQL coverage"]
fn scan_retention_due_integration_scaffold_pending() {
    panic!("scaffold not implemented");
}
