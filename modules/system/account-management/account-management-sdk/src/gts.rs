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

/// AM `User` resource projection. Mirror of the
/// `gts.cf.core.am.user.v1~` JSON Schema declared in
/// `modules/system/account-management/docs/schemas/user.v1.schema.json`
/// and produced by [`crate::User`]. Surfaces as the `resource_type`
/// on user-scoped canonical errors raised by the user-operations
/// feature (`feature-idp-user-operations-contract`).
pub const USER_RESOURCE_TYPE: &str = "gts.cf.core.am.user.v1~";

// ---------------------------------------------------------------------------
// IdP provider plugin spec
// ---------------------------------------------------------------------------

use gts_macros::struct_to_gts_schema;
use modkit::gts::BaseModkitPluginV1;

/// GTS type definition for `IdP` provider plugin instances.
///
/// Each `IdP` plugin registers an instance of this type with its
/// vendor-specific instance ID. AM resolves the active plugin
/// through `ClientHub` keyed by the schema id below per
/// `cpt-cf-account-management-adr-idp-contract-separation` (ADR-0001).
///
/// Mirrors the established `AuthNResolverPluginSpecV1` pattern from
/// `cyberware-authn-resolver-sdk::gts` so plugin discovery is
/// uniform across the Cyber Ware plugin contracts (`IdpPluginClient`,
/// `AuthNResolverPluginClient`, `TenantResolverPluginClient`, …).
///
/// # Instance ID Format
///
/// ```text
/// gts.cf.core.modkit.plugin.v1~<vendor>.<package>.idp.plugin.v1~
/// ```
///
/// # Example
///
/// ```ignore
/// use account_management_sdk::IdpPluginSpecV1;
/// use modkit::gts::BaseModkitPluginV1;
///
/// // Plugin generates its instance ID
/// let instance_id = IdpPluginSpecV1::gts_make_instance_id(
///     "cf.builtin.keycloak_idp.plugin.v1",
/// );
///
/// // Plugin builds the registration record
/// let instance = BaseModkitPluginV1::<IdpPluginSpecV1> {
///     id: instance_id.clone(),
///     vendor: "cyberfabric".to_owned(),
///     priority: 100,
///     properties: IdpPluginSpecV1,
/// };
///
/// // Register with types-registry
/// // registry.register(vec![serde_json::to_value(&instance)?]).await?;
/// ```
#[struct_to_gts_schema(
    dir_path = "../docs/schemas",
    base = BaseModkitPluginV1,
    schema_id = "gts.cf.core.modkit.plugin.v1~cf.core.idp.plugin.v1~",
    description = "IdP provider plugin specification",
    properties = ""
)]
pub struct IdpPluginSpecV1;
