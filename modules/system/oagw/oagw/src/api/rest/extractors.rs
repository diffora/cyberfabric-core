use modkit::api::problem::Problem;
use uuid::Uuid;

use crate::domain::gts_helpers;
use crate::domain::model::ListQuery;

/// Parse a GTS identifier, verifying that its schema prefix matches
/// `expected_schema` (e.g. `UPSTREAM_SCHEMA`). Returns a validation
/// `Problem` if the prefix does not match.
#[allow(clippy::result_large_err)]
pub fn parse_gts_id(gts_str: &str, expected_schema: &str, instance: &str) -> Result<Uuid, Problem> {
    let (schema, uuid) = gts_helpers::parse_resource_gts(gts_str).map_err(Problem::from)?;
    let expected_prefix = expected_schema.trim_end_matches('~');
    if schema != expected_prefix {
        return Err(Problem::new(
            http::StatusCode::BAD_REQUEST,
            "Validation Error",
            format!("expected GTS schema '{expected_schema}' but got '{schema}~'"),
        )
        .with_type("gts.cf.core.errors.err.v1~cf.oagw.validation.error.v1")
        .with_instance(instance));
    }
    Ok(uuid)
}

/// Pagination query parameters.
#[derive(Debug, serde::Deserialize)]
pub struct PaginationQuery {
    #[serde(default = "default_top")]
    pub limit: u32,
    #[serde(default)]
    pub offset: u32,
}

fn default_top() -> u32 {
    50
}

impl PaginationQuery {
    pub fn to_list_query(&self) -> ListQuery {
        ListQuery {
            top: self.limit.min(100),
            skip: self.offset,
        }
    }
}
