use std::sync::Arc;

use authz_resolver_sdk::PolicyEnforcer;
use modkit_macros::domain_model;
use uuid::Uuid;

use crate::domain::error::DomainError;
use crate::domain::repos::model_resolver::ResolvedModel;
use crate::domain::repos::{ModelPrefRepository, ModelResolver};

use super::DbProvider;

/// Service handling model listing and selection.
#[domain_model]
pub struct ModelService {
    _db: Arc<DbProvider>,
    _model_pref_repo: Arc<dyn ModelPrefRepository>,
    _enforcer: PolicyEnforcer,
    model_resolver: Arc<dyn ModelResolver>,
}

impl ModelService {
    pub(crate) fn new(
        db: Arc<DbProvider>,
        model_pref_repo: Arc<dyn ModelPrefRepository>,
        enforcer: PolicyEnforcer,
        model_resolver: Arc<dyn ModelResolver>,
    ) -> Self {
        Self {
            _db: db,
            _model_pref_repo: model_pref_repo,
            _enforcer: enforcer,
            model_resolver,
        }
    }

    /// Resolve a model ID + provider from the policy catalog.
    pub(crate) async fn resolve_model(
        &self,
        user_id: Uuid,
        model: Option<String>,
    ) -> Result<ResolvedModel, DomainError> {
        self.model_resolver.resolve_model(user_id, model).await
    }
}
