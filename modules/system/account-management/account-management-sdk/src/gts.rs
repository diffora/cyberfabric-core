//! GTS resource type identifiers for Account Management.
//!
//! Single source of truth for the AM resource-type strings used in:
//!
//! * PEP `ResourceType.name` for authorization decisions (consumed by
//!   `service::pep::TENANT` and friends in the impl crate).
//! * `resource_type` field on the canonical-error envelope produced
//!   when an AM domain failure converts to
//!   [`modkit_canonical_errors::CanonicalError`] at the module
//!   boundary.
//! * Future cross-module event consumers and sibling modules that
//!   pattern-match on AM-emitted events (event-bus contract TBD) —
//!   depending on this SDK instead of the impl crate keeps consumer
//!   build graphs slim.
//!
//! Strings follow the AM-specific GTS namespace convention from
//! `modules/system/account-management/docs/DESIGN.md` (PEP table):
//! `gts.cf.core.am.{resource}.v1~`. The trailing `~` is the GTS
//! terminator and is part of the identifier.
//!
//! Mirrors the `gts` module layout used by `resource-group-sdk` —
//! see `account_management_sdk::lib` rationale for the SDK split.
//!
//! # Note on `#[resource_error]` macro arguments
//!
//! The `modkit_canonical_errors::resource_error` proc-macro takes a
//! literal string at expansion time and cannot resolve constants —
//! the impl-crate sites that call the macro therefore duplicate
//! these literals. The `domain::error_tests` module asserts the
//! impl-crate strings match the constants below, so a divergence
//! trips at test time, not in production.

/// AM Tenant resource. Used for PEP authorization on the `tenants`
/// table and as the `resource_type` field on tenant-scoped canonical
/// errors (e.g. `tenant {id} not found` → 404).
pub const TENANT_RESOURCE_TYPE: &str = "gts.cf.core.am.tenant.v1~";

/// AM `TenantMetadata` resource. Used for canonical errors raised
/// by the metadata feature (e.g. `MetadataSchemaNotRegistered`,
/// `MetadataEntryNotFound`) and for the future PEP gate on
/// metadata reads / writes.
pub const TENANT_METADATA_RESOURCE_TYPE: &str = "gts.cf.core.am.tenant_metadata.v1~";

/// AM `ConversionRequest` resource. Used for canonical errors raised
/// by the conversion-request feature and for the future PEP gate on
/// conversion read / approve / reject endpoints.
pub const CONVERSION_REQUEST_RESOURCE_TYPE: &str = "gts.cf.core.am.conversion_request.v1~";

// ---------------------------------------------------------------------------
// User-groups feature -- two flavours of identifiers
// ---------------------------------------------------------------------------
//
// The user-groups feature delegates storage to the Resource Group module
// (see DECOMPOSITION §2.6: "consumers call `ResourceGroupClient` directly
// per the Delegation-to-RG principle"). That delegation produces TWO
// related-but-distinct strings per resource:
//
// * The **AM resource-type identifier** (`gts.cf.core.am.*`) -- the
//   semantic AM type used by PEP / canonical-error envelopes / future
//   event-bus consumers. Mirrors the pattern of `TENANT_RESOURCE_TYPE`
//   et al above.
//
// * The **RG-prefixed type code** (`gts.cf.core.rg.type.v1~cf.core.am.*`)
//   -- the form RG's `validate_type_code` requires for entries in
//   `gts_type` (the type-registry namespace). AM registers these codes
//   at module init via `register_user_group_types`; sibling modules
//   (RBAC, UI gateways, batch jobs) that interact with RG directly
//   need the RG-prefixed strings to filter `list_groups` /
//   `add_membership` / `remove_membership` calls.
//
// Sibling modules MUST import these constants instead of hard-coding
// the strings; the impl crate re-exports them so the AM-internal call
// sites stay aligned with the public SDK contract.

/// AM `UserGroup` resource (AM-typed, no RG prefix).
///
/// Use as `resource_type` on PEP / canonical-error / event-bus
/// envelopes that authorise actions performed **on** a user group
/// (e.g. "tenant admin can rename user-group G"). Distinct from
/// [`USER_GROUP_RG_TYPE_CODE`] below, which is the type-registry
/// handle RG accepts in its `gts_type` table.
///
/// **Status:** currently unused; reserved for the future PEP gate on
/// user-group write endpoints. Lives alongside the actively-used
/// RG-prefixed constants so the AM ↔ sibling-module contract is
/// declared in one place rather than scattered as string literals.
pub const USER_GROUP_RESOURCE_TYPE: &str = "gts.cf.core.am.user_group.v1~";

/// AM `User` resource (AM-typed, no RG prefix).
///
/// Use as `resource_type` on PEP / canonical-error / event-bus
/// envelopes referring to an AM user identity. Distinct from
/// [`USER_RG_TYPE_CODE`] which is the RG type-registry handle used
/// inside membership rows.
///
/// **Status:** currently unused; reserved for the future PEP gate on
/// user-write endpoints (the existing user-write paths gate on
/// tenant scope, not on a user resource identifier).
pub const USER_RESOURCE_TYPE: &str = "gts.cf.core.am.user.v1~";

/// RG type-registry code for the AM user-group **container** type.
///
/// Used by:
///
/// * `ResourceGroupClient::list_groups($filter=type eq <this>)` -- to
///   list user-groups (optionally combined with `tenant_id eq <t>`).
/// * `ResourceGroupClient::create_group({code: <this>, ...})` -- to
///   create a new user-group instance.
/// * AM's `register_user_group_types` at module init.
///
/// Wraps [`USER_GROUP_RESOURCE_TYPE`] in the RG type-registry namespace
/// so RG's `validate_type_code` (`gts.cf.core.rg.type.v1~` prefix
/// requirement) accepts it.
pub const USER_GROUP_RG_TYPE_CODE: &str = "gts.cf.core.rg.type.v1~cf.core.am.user_group.v1~";

/// RG type-registry code for the AM user **member-handle** type.
///
/// Used by:
///
/// * `ResourceGroupClient::add_membership(group_id, <this>, user_uuid)`
///   -- to add an AM user as a member of a user-group.
/// * `ResourceGroupClient::remove_membership(group_id, <this>, user_uuid)`
///   -- to remove a user from a group.
/// * `ResourceGroupClient::list_memberships($filter=resource_type eq <this>)`
///   -- to enumerate user→group links (e.g. "what groups is user X in").
///
/// This is a type-registry-only entry; AM users themselves live in
/// AM's tables + `IdP`, never as RG groups. Wraps
/// [`USER_RESOURCE_TYPE`] in the RG type-registry namespace.
pub const USER_RG_TYPE_CODE: &str = "gts.cf.core.rg.type.v1~cf.core.am.user.v1~";
