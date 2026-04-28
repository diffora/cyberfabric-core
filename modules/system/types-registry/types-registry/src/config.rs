//! Configuration for the Types Registry module.

use serde::Deserialize;
use uuid::Uuid;

/// Configuration for the Types Registry module.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct TypesRegistryConfig {
    /// Fields to check for GTS entity ID (in order of priority).
    /// Default: `["$id", "gtsId", "id"]`
    pub entity_id_fields: Vec<String>,

    /// Fields to check for schema ID reference (in order of priority).
    /// Default: `["$schema", "gtsTid", "type"]`
    pub schema_id_fields: Vec<String>,

    /// Default tenant ID injected into static entities that don't specify one.
    ///
    /// When a static entity in `entities` has no `tenant_id` field, this value
    /// is automatically inserted before registration. Defaults to
    /// `modkit_security::constants::DEFAULT_TENANT_ID`.
    #[serde(default = "default_tenant_id")]
    pub default_tenant_id: Uuid,

    /// Raw GTS entity JSON values to register at startup.
    ///
    /// Each entry must be a valid GTS entity with at least an `$id` (or
    /// `gtsId`/`id`) field. Entities are registered in order.
    #[serde(default)]
    pub entities: Vec<serde_json::Value>,
}

fn default_tenant_id() -> Uuid {
    modkit_security::constants::DEFAULT_TENANT_ID
}

impl Default for TypesRegistryConfig {
    fn default() -> Self {
        Self {
            entity_id_fields: vec!["$id".to_owned(), "gtsId".to_owned(), "id".to_owned()],
            schema_id_fields: vec!["$schema".to_owned(), "gtsTid".to_owned(), "type".to_owned()],
            default_tenant_id: default_tenant_id(),
            entities: Vec::new(),
        }
    }
}

impl TypesRegistryConfig {
    /// Converts this config to a `gts::GtsConfig`.
    #[must_use]
    pub fn to_gts_config(&self) -> gts::GtsConfig {
        gts::GtsConfig {
            entity_id_fields: self.entity_id_fields.clone(),
            schema_id_fields: self.schema_id_fields.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let cfg = TypesRegistryConfig::default();
        assert_eq!(cfg.entity_id_fields, vec!["$id", "gtsId", "id"]);
        assert_eq!(cfg.schema_id_fields, vec!["$schema", "gtsTid", "type"]);
        assert!(cfg.entities.is_empty());
        assert_eq!(
            cfg.default_tenant_id,
            modkit_security::constants::DEFAULT_TENANT_ID
        );
    }

    #[test]
    fn test_to_gts_config() {
        let cfg = TypesRegistryConfig::default();
        let gts_cfg = cfg.to_gts_config();
        assert_eq!(gts_cfg.entity_id_fields, cfg.entity_id_fields);
        assert_eq!(gts_cfg.schema_id_fields, cfg.schema_id_fields);
    }
}
