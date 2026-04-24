//! Account Management SDK — public contract surface.
//!
//! This crate carries the AM module's most stable public contract:
//! the error taxonomy, audit-event shapes, and observability
//! metric-name constants. External consumers — plugin authors,
//! dashboards, integration tests — depend on **this** crate, never on
//! the impl crate (`cf-account-management`), so impl-side churn
//! (sea-orm migrations, axum wiring, tokio runtime) does not
//! propagate as a contract break.
//!
//! Pattern mirrors `resource-group-sdk` and `tenant-resolver-sdk`:
//! the impl crate re-exports the SDK types verbatim so internal
//! `use crate::domain::*` paths stay stable across the boundary.
//!
//! # Scope (current)
//!
//! Carried by this SDK today:
//!
//! * [`audit`] — [`AuditActor`] / [`AuditEvent`] / [`AuditEventKind`]
//!   shapes (the *types*; emission is impl-side)
//! * [`metric_names`] — `AM_*` family-name constants and
//!   [`MetricKind`] (the *names*; emission is impl-side)
//!
//! Deliberately **not** in this SDK yet:
//!
//! * `AmError` / `ErrorCategory` — the impl crate has a
//!   `From<modkit_db::DbError> for AmError` that ties error
//!   construction to a heavy infra dep (`sea-orm`). Moving the
//!   taxonomy here would either leak that dep into every consumer or
//!   force a `From`→free-function refactor across the impl. Deferred
//!   until that refactor is scheduled.
//! * Trait-level surface (`TenantRepo`, `IdpTenantProvisioner`,
//!   `ResourceOwnershipChecker`, `TenantTypeChecker`) and their
//!   argument types — pending the integrity-audit refactor that
//!   stabilises trait method shapes.
#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]

pub mod audit;
pub mod metric_names;

pub use audit::{AuditActor, AuditEvent, AuditEventKind};
pub use metric_names::MetricKind;
