//! Account Management SDK — public contract surface.
//!
//! This crate carries the AM module's stable public surface: audit-event
//! shapes ([`AuditActor`] / [`AuditEvent`] / [`AuditEventKind`]) plus their
//! `serde` wire format, and the inter-module error type
//! [`AccountManagementError`]. External consumers — plugin authors,
//! dashboards, integration tests, sibling modules calling AM via
//! `ClientHub` — depend on **this** crate, never on the impl crate
//! (`cf-account-management`), so impl-side churn (sea-orm migrations,
//! axum wiring, tokio runtime) does not propagate as a contract break.
//!
//! Pattern mirrors `resource-group-sdk` and `tenant-resolver-sdk`: the
//! impl crate re-exports the SDK types verbatim so internal
//! `use crate::domain::*` paths stay stable across the boundary, and
//! the JSON wire format for audit events is `camelCase` to match peer
//! SDKs. The runtime crate carries
//! `impl From<AmError> for AccountManagementError` that flattens the
//! finer-grained internal taxonomy onto the 9 stable categories.
//!
//! # Scope (current)
//!
//! Carried by this SDK today:
//!
//! * [`audit`] — [`AuditActor`] / [`AuditEvent`] / [`AuditEventKind`]
//!   shapes plus `Serialize` / `Deserialize` for the on-the-wire format
//!   (emission is impl-side)
//! * [`error`] — [`AccountManagementError`], the lossy-flatten
//!   inter-module error type. The runtime crate's richer `AmError`
//!   stays internal; REST handlers convert `AmError` directly to the
//!   platform `Problem` envelope so finer-grained `code` tokens
//!   survive on the wire.
//!
//! Deliberately **not** in this SDK yet:
//!
//! * The runtime taxonomy [`AmError`](../cf_account_management/domain/error/enum.AmError.html)
//!   itself stays internal — it carries `From<modkit_db::DbError>` which
//!   would otherwise leak `sea-orm` into every consumer.
//!   [`AccountManagementError`] is the public, infra-free flatten that
//!   downstream modules consume.
//! * Metric-name constants — re-homed inside the runtime crate at
//!   `cf-account-management::domain::metrics`. Peer SDKs
//!   (`resource-group-sdk`, `tenant-resolver-sdk`) do not carry metric
//!   constants either.
//! * Trait-level surface (`TenantRepo`, `IdpTenantProvisioner`,
//!   `ResourceOwnershipChecker`, `TenantTypeChecker`) and their
//!   argument types — pending the integrity-audit refactor that
//!   stabilises trait method shapes.
#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]

pub mod audit;
pub mod error;

pub use audit::{AuditActor, AuditEvent, AuditEventKind, SystemActorNotEligible};
pub use error::AccountManagementError;
