//! Request / response DTOs for the `tenants` REST resource.
//!
//! Matches `account-management-v1.yaml` schemas field-for-field. DTOs
//! serialize with `serde`'s `snake_case` default already established by
//! `modkit_macros::api_dto`.
//!
//! Conversions into domain types perform the small amount of boundary
//! validation that does not belong in the domain service (length bounds,
//! `minProperties: 1` enforcement, UUID parse). The domain service
//! performs the transitional validation (allowed PATCH status moves,
//! SDK-visibility, saga invariants).

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::domain::error::AmError;
use crate::domain::tenant::model::{
    ListChildrenQuery, TenantModel, TenantPage, TenantStatus as DomainTenantStatus, TenantUpdate,
};
use crate::domain::tenant::service::CreateChildInput;

/// Public tenant lifecycle status used on the REST wire.
///
/// The domain enum also has an internal `provisioning` state. That state
/// is intentionally absent here because provisioning rows are not part
/// of the SDK-visible tenant surface.
// @cpt-begin:cpt-cf-account-management-state-tenant-hierarchy-management-tenant-status:p1:inst-state-api-public-status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum TenantStatus {
    Active,
    Suspended,
    Deleted,
}
// @cpt-end:cpt-cf-account-management-state-tenant-hierarchy-management-tenant-status:p1:inst-state-api-public-status

// ======================================================================
// Tenant DTO (response) — matches OpenAPI `Tenant`
// ======================================================================

/// Public projection of a tenant row.
///
/// `tenant_type` is the full chained GTS schema id per `OpenAPI`. In
/// Phase 2 AM does not yet resolve the chain from `tenant_type_uuid`
/// (GTS-registry integration is a later feature), so the DTO carries
/// the UUID rendered as a string - callers get a stable, serialized
/// identifier they can round-trip back into a future `POST` payload.
/// This is documented in `out/phase-02-rest-surface.md`.
///
/// # `Provisioning` children — visibility asymmetry
///
/// Tenants in the internal `Provisioning` state are deliberately
/// asymmetric across the public surface:
///
/// * `listChildren` filters them out — the create-tenant saga is still
///   in flight, and surfacing a half-built tenant would leak transient
///   state through a paginated read API that callers expect to be
///   stable.
/// * `deleteTenant` (soft-delete) DOES count them as live children and
///   rejects the parent's deletion with `tenant_has_children`. Letting
///   the parent move to `Deleted` mid-saga would either strand the
///   in-flight provisioning child (orphaning IdP-side state when the
///   saga completes) or force a complex compensation across two
///   tenants. Counting them is the simpler correct behaviour.
///
/// Operators reaping stuck `Provisioning` rows is the path to clearing
/// this rejection — see the provisioning-reaper feature.
#[derive(Debug)]
#[modkit_macros::api_dto(response)]
pub struct TenantDto {
    #[schema(value_type = String)]
    pub id: Uuid,
    pub name: String,
    #[schema(value_type = Option<String>)]
    pub parent_id: Option<Uuid>,
    pub tenant_type: String,
    pub status: TenantStatus,
    pub self_managed: bool,
    pub depth: u32,
    #[schema(value_type = String)]
    pub created_at: OffsetDateTime,
    #[schema(value_type = String)]
    pub updated_at: OffsetDateTime,
    #[schema(value_type = Option<String>)]
    pub deleted_at: Option<OffsetDateTime>,
}

fn status_to_public_status(s: DomainTenantStatus) -> TenantStatus {
    match s {
        DomainTenantStatus::Active => TenantStatus::Active,
        DomainTenantStatus::Suspended => TenantStatus::Suspended,
        // `provisioning` is SDK-invisible and never reaches the wire. The
        // domain service filters it out - but if it slipped through the
        // safest thing is to coerce to "deleted" so we don't leak the
        // internal token. In practice this branch is unreachable.
        DomainTenantStatus::Deleted | DomainTenantStatus::Provisioning => TenantStatus::Deleted,
    }
}

impl From<TenantModel> for TenantDto {
    fn from(m: TenantModel) -> Self {
        Self {
            id: m.id,
            name: m.name,
            parent_id: m.parent_id,
            // GTS-registry chain resolution is deferred — surface the
            // UUID so the public shape is still a `string`.
            tenant_type: m.tenant_type_uuid.to_string(),
            status: status_to_public_status(m.status),
            self_managed: m.self_managed,
            depth: m.depth,
            created_at: m.created_at,
            updated_at: m.updated_at,
            deleted_at: m.deleted_at,
        }
    }
}

// ======================================================================
// Page DTO (response) — matches OpenAPI `TenantPage`
// ======================================================================

#[derive(Debug)]
#[modkit_macros::api_dto(response)]
pub struct PageInfoDto {
    pub top: u32,
    pub skip: u32,
    pub total: Option<i64>,
}

#[derive(Debug)]
#[modkit_macros::api_dto(response)]
pub struct TenantPageDto {
    pub items: Vec<TenantDto>,
    pub page_info: PageInfoDto,
}

impl From<TenantPage> for TenantPageDto {
    fn from(page: TenantPage) -> Self {
        Self {
            items: page.items.into_iter().map(Into::into).collect(),
            page_info: PageInfoDto {
                top: page.top,
                skip: page.skip,
                total: page
                    .total
                    .map(|total| i64::try_from(total).unwrap_or(i64::MAX)),
            },
        }
    }
}

// ======================================================================
// Create request — matches OpenAPI `TenantCreateRequest`
// ======================================================================

#[derive(Debug)]
#[modkit_macros::api_dto(request)]
// Reject payloads carrying fields the contract does not list. Without
// this, a typo (`parent` for `parent_id`, `metadata` for
// `provisioning_metadata`) deserialises silently and the request goes
// through with the misnamed value dropped — surfacing as a confusing
// downstream failure or, worse, a successful create with the wrong
// shape. `additionalProperties: false` is also propagated to the
// `OpenAPI` schema by `utoipa`, so SDK consumers see the contract.
#[serde(deny_unknown_fields)]
pub struct TenantCreateRequest {
    pub name: String,
    #[schema(value_type = String)]
    pub parent_id: Uuid,
    /// Full chained GTS schema id. For Phase 2 AM accepts a UUID string;
    /// see `out/phase-02-rest-surface.md` for the deviation note.
    pub tenant_type: String,
    #[serde(default)]
    pub self_managed: bool,
    #[serde(default)]
    pub provisioning_metadata: Option<serde_json::Value>,
}

impl TenantCreateRequest {
    /// Convert into the domain saga input after validating `OpenAPI`
    /// field-level constraints.
    ///
    /// # Errors
    ///
    /// * [`AmError::Validation`] when `name` is empty, longer than 255
    ///   chars, or `tenant_type` cannot be parsed into a UUID (Phase 2
    ///   placeholder until GTS chain resolution is wired).
    pub fn into_create_child_input(self, child_id: Uuid) -> Result<CreateChildInput, AmError> {
        TenantUpdate::validate_name(&self.name)?;
        let tenant_type_uuid =
            Uuid::parse_str(self.tenant_type.trim()).map_err(|e| AmError::Validation {
                detail: format!("tenant_type is not a valid UUID: {e}"),
            })?;
        Ok(CreateChildInput {
            child_id,
            parent_id: self.parent_id,
            name: self.name,
            self_managed: self.self_managed,
            tenant_type: self.tenant_type,
            tenant_type_uuid,
            provisioning_metadata: self.provisioning_metadata,
        })
    }
}

// ======================================================================
// Update request — matches OpenAPI `TenantUpdateRequest`
// ======================================================================

#[derive(Debug)]
#[modkit_macros::api_dto(request)]
// Reject PATCH bodies carrying immutable fields. Only `name` and
// `status` are mutable per `OpenAPI` `TenantUpdateRequest`; payloads
// containing `parent_id`, `tenant_type`, `self_managed`, etc. must
// surface as a validation error rather than silently applying the
// known fields and dropping the rest. `additionalProperties: false`
// is also propagated to the `OpenAPI` schema by `utoipa`.
#[serde(deny_unknown_fields)]
pub struct TenantUpdateRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub status: Option<TenantStatus>,
}

impl TenantUpdateRequest {
    /// Enforce `minProperties: 1`, parse the public `status` string, and
    /// validate `name` length.
    ///
    /// # Errors
    ///
    /// * [`AmError::Validation`] for empty patches, out-of-range names,
    ///   or unsupported public status tokens.
    pub fn into_domain_patch(self) -> Result<TenantUpdate, AmError> {
        let status = match self.status {
            Some(s) => Some(patch_status_to_domain(s)?),
            None => None,
        };
        let name = self.name;
        if name.is_none() && status.is_none() {
            return Err(AmError::Validation {
                detail: "patch is empty; at least one field required".into(),
            });
        }
        if let Some(ref n) = name {
            TenantUpdate::validate_name(n)?;
        }
        Ok(TenantUpdate { name, status })
    }
}

fn patch_status_to_domain(s: TenantStatus) -> Result<DomainTenantStatus, AmError> {
    match s {
        TenantStatus::Active => Ok(DomainTenantStatus::Active),
        TenantStatus::Suspended => Ok(DomainTenantStatus::Suspended),
        // `deleted` goes through the DELETE flow; accepting it here is
        // rejected by the domain service but we fail early with a
        // matching message.
        TenantStatus::Deleted => Err(AmError::Validation {
            detail: "status=deleted must go through DELETE flow".into(),
        }),
    }
}

fn public_status_str_to_domain(s: &str) -> Result<DomainTenantStatus, AmError> {
    match s {
        "active" => Ok(DomainTenantStatus::Active),
        "suspended" => Ok(DomainTenantStatus::Suspended),
        "deleted" => Ok(DomainTenantStatus::Deleted),
        other => Err(AmError::Validation {
            detail: format!("unsupported status token: {other}"),
        }),
    }
}

// ======================================================================
// Child-list query — matches OpenAPI `Top` / `Skip` / `StatusFilter`
// ======================================================================

/// Query parameters accepted by `GET /tenants/{id}/children`.
///
/// Field names match the `OpenAPI` `$top` / `$skip` using `serde` rename
/// hints. `status` may appear multiple times; serde parses a single
/// string (comma-separated is handled by splitting on commas inside
/// [`ChildListQuery::into_domain_query`]).
#[derive(Debug, Deserialize, Serialize)]
pub struct ChildListQuery {
    #[serde(default, rename = "$top")]
    pub top: Option<u32>,
    #[serde(default, rename = "$skip")]
    pub skip: Option<u32>,
    /// Comma-separated list of SDK-visible statuses, e.g. `active,suspended`.
    /// Missing → no status filter (all SDK-visible rows).
    #[serde(default)]
    pub status: Option<String>,
}

impl ChildListQuery {
    /// Clamp `$top` to `max_top`, default `$skip` to `0`, and convert
    /// the status token list. Emits [`AmError::Validation`] for:
    ///
    /// * `$top == 0`
    /// * `$skip == u32::MAX` (treated as caller error)
    /// * any unsupported status token
    ///
    /// # Errors
    ///
    /// Returns [`AmError::Validation`] in the three cases listed above.
    // @cpt-begin:cpt-cf-account-management-dod-tenant-hierarchy-management-children-query-paginated:p1:inst-dod-children-query-api-clamp
    pub fn into_domain_query(
        self,
        parent_id: Uuid,
        max_top: u32,
    ) -> Result<ListChildrenQuery, AmError> {
        let top = match self.top {
            Some(0) => {
                return Err(AmError::Validation {
                    detail: "$top must be >= 1".into(),
                });
            }
            Some(t) => t.min(max_top),
            None => 50_u32.min(max_top),
        };
        let skip = match self.skip {
            Some(u32::MAX) => {
                return Err(AmError::Validation {
                    detail: "$skip must be < u32::MAX".into(),
                });
            }
            Some(s) => s,
            None => 0,
        };
        let status_filter = match self.status.as_deref() {
            None | Some("") => None,
            Some(raw) => {
                let mut out = Vec::new();
                for tok in raw.split(',').map(str::trim).filter(|t| !t.is_empty()) {
                    out.push(public_status_str_to_domain(tok)?);
                }
                if out.is_empty() { None } else { Some(out) }
            }
        };
        Ok(ListChildrenQuery {
            parent_id,
            status_filter,
            top,
            skip,
        })
    }
    // @cpt-end:cpt-cf-account-management-dod-tenant-hierarchy-management-children-query-paginated:p1:inst-dod-children-query-api-clamp
}

// ======================================================================
// Tests
// ======================================================================

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn update_request_empty_is_rejected() {
        let req = TenantUpdateRequest {
            name: None,
            status: None,
        };
        let err = req.into_domain_patch().expect_err("empty reject");
        assert_eq!(err.sub_code(), "validation");
    }

    #[test]
    fn tenant_status_wire_tokens_round_trip() {
        for (status, token) in [
            (TenantStatus::Active, "active"),
            (TenantStatus::Suspended, "suspended"),
            (TenantStatus::Deleted, "deleted"),
        ] {
            let encoded = serde_json::to_string(&status).expect("serialize");
            assert_eq!(encoded, format!("\"{token}\""));
            let decoded: TenantStatus = serde_json::from_str(&encoded).expect("deserialize");
            assert_eq!(decoded, status);
        }
    }

    #[test]
    fn tenant_update_request_status_uses_typed_enum() {
        let req: TenantUpdateRequest =
            serde_json::from_str(r#"{"status":"suspended"}"#).expect("deserialize");
        assert_eq!(req.status, Some(TenantStatus::Suspended));
        let patch = req.into_domain_patch().expect("domain patch");
        assert_eq!(patch.status, Some(DomainTenantStatus::Suspended));
    }

    #[test]
    fn tenant_dto_status_and_page_total_match_wire_contract() {
        let dto = TenantDto {
            id: Uuid::from_u128(0x10),
            name: "tenant".into(),
            parent_id: None,
            tenant_type: Uuid::from_u128(0xAA).to_string(),
            status: TenantStatus::Active,
            self_managed: false,
            depth: 0,
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
            deleted_at: None,
        };
        let page = TenantPageDto {
            items: vec![dto],
            page_info: PageInfoDto {
                top: 50,
                skip: 0,
                total: Some(123_i64),
            },
        };
        let encoded = serde_json::to_value(&page).expect("serialize");
        assert_eq!(encoded["items"][0]["status"], "active");
        assert_eq!(encoded["page_info"]["total"], 123);
    }

    #[test]
    fn status_to_public_status_coerces_provisioning_to_deleted() {
        // Provisioning is SDK-invisible and is never expected to reach
        // the public wire; the coercion to "deleted" is a defensive
        // last-resort that avoids leaking the internal token. Test
        // pins the branch so a future refactor cannot regress it.
        assert_eq!(
            status_to_public_status(DomainTenantStatus::Provisioning),
            TenantStatus::Deleted
        );
        assert_eq!(
            status_to_public_status(DomainTenantStatus::Deleted),
            TenantStatus::Deleted
        );
        assert_eq!(
            status_to_public_status(DomainTenantStatus::Active),
            TenantStatus::Active
        );
        assert_eq!(
            status_to_public_status(DomainTenantStatus::Suspended),
            TenantStatus::Suspended
        );
    }

    #[test]
    fn list_query_rejects_skip_at_u32_max() {
        let q = ChildListQuery {
            top: None,
            skip: Some(u32::MAX),
            status: None,
        };
        let err = q
            .into_domain_query(Uuid::nil(), 200)
            .expect_err("skip == u32::MAX must be rejected");
        assert_eq!(err.sub_code(), "validation");
    }

    #[test]
    fn update_request_oversized_name_is_rejected() {
        let req = TenantUpdateRequest {
            name: Some("x".repeat(256)),
            status: None,
        };
        let err = req.into_domain_patch().expect_err("oversized reject");
        assert_eq!(err.sub_code(), "validation");
    }

    #[test]
    fn update_request_unknown_status_is_rejected() {
        let err = serde_json::from_str::<TenantUpdateRequest>(r#"{"status":"unknown"}"#)
            .expect_err("bad status token");
        assert!(err.to_string().contains("unknown variant"), "got: {err}");
    }

    #[test]
    fn update_request_deleted_status_is_rejected() {
        let req = TenantUpdateRequest {
            name: None,
            status: Some(TenantStatus::Deleted),
        };
        let err = req.into_domain_patch().expect_err("deleted via PATCH");
        assert_eq!(err.sub_code(), "validation");
    }

    #[test]
    fn update_request_happy_path_active() {
        let req = TenantUpdateRequest {
            name: Some("new".into()),
            status: Some(TenantStatus::Active),
        };
        let patch = req.into_domain_patch().expect("ok");
        assert_eq!(patch.name.as_deref(), Some("new"));
        assert_eq!(patch.status, Some(DomainTenantStatus::Active));
    }

    /// PATCH bodies containing immutable fields (`parent_id`,
    /// `tenant_type`, `self_managed`, …) **must** be rejected at
    /// deserialisation rather than silently dropped — see the
    /// `#[serde(deny_unknown_fields)]` doc-comment on
    /// [`TenantUpdateRequest`].
    #[test]
    fn update_request_rejects_immutable_field_parent_id() {
        let body = r#"{"name":"x","parent_id":"00000000-0000-0000-0000-000000000001"}"#;
        let err = serde_json::from_str::<TenantUpdateRequest>(body)
            .expect_err("parent_id must be rejected");
        assert!(
            err.to_string().contains("parent_id"),
            "expected serde to surface the offending field, got: {err}"
        );
    }

    #[test]
    fn update_request_rejects_immutable_field_tenant_type() {
        let body = r#"{"status":"suspended","tenant_type":"x.core.am.customer.v1~"}"#;
        let err = serde_json::from_str::<TenantUpdateRequest>(body)
            .expect_err("tenant_type must be rejected");
        assert!(
            err.to_string().contains("tenant_type"),
            "expected serde to surface the offending field, got: {err}"
        );
    }

    #[test]
    fn update_request_rejects_immutable_field_self_managed() {
        let body = r#"{"name":"x","self_managed":true}"#;
        let err = serde_json::from_str::<TenantUpdateRequest>(body)
            .expect_err("self_managed must be rejected");
        assert!(
            err.to_string().contains("self_managed"),
            "expected serde to surface the offending field, got: {err}"
        );
    }

    /// Same posture for `TenantCreateRequest` — typos in field names
    /// (`parentId`, `metdata`, ...) **must** fail loud rather than
    /// silently produce a tenant with the misnamed value dropped.
    #[test]
    fn create_request_rejects_unknown_field() {
        let body = r#"{
            "name":"t",
            "parent_id":"00000000-0000-0000-0000-000000000001",
            "tenant_type":"00000000-0000-0000-0000-000000000002",
            "metdata":{}
        }"#;
        let err = serde_json::from_str::<TenantCreateRequest>(body)
            .expect_err("unknown 'metdata' must be rejected");
        assert!(
            err.to_string().contains("metdata"),
            "expected serde to surface the offending field, got: {err}"
        );
    }

    #[test]
    fn create_request_rejects_bad_tenant_type_uuid() {
        let req = TenantCreateRequest {
            name: "t".into(),
            parent_id: Uuid::nil(),
            tenant_type: "not-a-uuid".into(),
            self_managed: false,
            provisioning_metadata: None,
        };
        let err = req
            .into_create_child_input(Uuid::nil())
            .expect_err("bad uuid");
        assert_eq!(err.sub_code(), "validation");
    }

    #[test]
    fn create_request_happy_path_builds_input() {
        let req = TenantCreateRequest {
            name: "t".into(),
            parent_id: Uuid::from_u128(0x10),
            tenant_type: Uuid::from_u128(0xAA).to_string(),
            self_managed: true,
            provisioning_metadata: None,
        };
        let input = req
            .into_create_child_input(Uuid::from_u128(0x20))
            .expect("ok");
        assert_eq!(input.parent_id, Uuid::from_u128(0x10));
        assert_eq!(input.child_id, Uuid::from_u128(0x20));
        assert!(input.self_managed);
    }

    #[test]
    fn child_list_query_clamps_top_to_max() {
        let q = ChildListQuery {
            top: Some(500),
            skip: None,
            status: None,
        };
        let dq = q.into_domain_query(Uuid::nil(), 200).expect("ok");
        assert_eq!(dq.top, 200);
    }

    #[test]
    fn child_list_query_rejects_top_zero() {
        let q = ChildListQuery {
            top: Some(0),
            skip: None,
            status: None,
        };
        let err = q.into_domain_query(Uuid::nil(), 200).expect_err("top zero");
        assert_eq!(err.sub_code(), "validation");
    }

    #[test]
    fn child_list_query_parses_comma_separated_status() {
        let q = ChildListQuery {
            top: None,
            skip: None,
            status: Some("active,suspended".into()),
        };
        let dq = q.into_domain_query(Uuid::nil(), 200).expect("ok");
        let filters = dq.status_filter.expect("filter");
        assert_eq!(filters.len(), 2);
        assert!(filters.contains(&DomainTenantStatus::Active));
        assert!(filters.contains(&DomainTenantStatus::Suspended));
    }
}
