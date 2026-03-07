use std::sync::Arc;

use async_trait::async_trait;
use authz_resolver_sdk::{
    AuthZResolverClient, AuthZResolverError, PolicyEnforcer,
    constraints::{Constraint, EqPredicate, Predicate},
    models::{DenyReason, EvaluationRequest, EvaluationResponse, EvaluationResponseContext},
};
use modkit_db::{
    ConnectOpts, DBProvider, Db, connect_db, migration_runner::run_migrations_for_testing,
};
use modkit_security::{SecurityContext, pep_properties};
use sea_orm_migration::MigratorTrait;
use uuid::Uuid;

use crate::domain::error::DomainError;
use crate::domain::repos::model_resolver::ResolvedModel;
use crate::domain::repos::{
    ModelResolver, PolicySnapshotProvider, ThreadSummaryRepository, UserLimitsProvider,
};

// ── Mock AuthZ Resolver ──

pub struct MockAuthZResolver;

#[async_trait]
impl AuthZResolverClient for MockAuthZResolver {
    async fn evaluate(
        &self,
        request: EvaluationRequest,
    ) -> Result<EvaluationResponse, AuthZResolverError> {
        let subject_tenant_id = request
            .subject
            .properties
            .get("tenant_id")
            .and_then(|v| v.as_str())
            .and_then(|s| Uuid::parse_str(s).ok());

        let subject_id = request.subject.id;

        // Deny when resource tenant_id differs from subject tenant_id
        if let Some(res_tenant) = request
            .resource
            .properties
            .get(pep_properties::OWNER_TENANT_ID)
            .and_then(|v| v.as_str())
            .and_then(|s| Uuid::parse_str(s).ok())
            && subject_tenant_id.is_some_and(|st| st != res_tenant)
        {
            return Ok(EvaluationResponse {
                decision: false,
                context: EvaluationResponseContext {
                    deny_reason: Some(DenyReason {
                        error_code: "tenant_mismatch".to_owned(),
                        details: Some("subject tenant does not match resource tenant".to_owned()),
                    }),
                    ..Default::default()
                },
            });
        }

        // Deny when resource owner_id differs from subject id
        if let Some(res_owner) = request
            .resource
            .properties
            .get(pep_properties::OWNER_ID)
            .and_then(|v| v.as_str())
            .and_then(|s| Uuid::parse_str(s).ok())
            && res_owner != subject_id
        {
            return Ok(EvaluationResponse {
                decision: false,
                context: EvaluationResponseContext {
                    deny_reason: Some(DenyReason {
                        error_code: "owner_mismatch".to_owned(),
                        details: Some("subject id does not match resource owner".to_owned()),
                    }),
                    ..Default::default()
                },
            });
        }

        // Build constraints from subject identity
        if request.context.require_constraints {
            let mut predicates = Vec::new();

            if let Some(tid) = subject_tenant_id {
                predicates.push(Predicate::Eq(EqPredicate::new(
                    pep_properties::OWNER_TENANT_ID,
                    tid,
                )));
            }

            predicates.push(Predicate::Eq(EqPredicate::new(
                pep_properties::OWNER_ID,
                subject_id,
            )));

            let constraints = vec![Constraint { predicates }];

            Ok(EvaluationResponse {
                decision: true,
                context: EvaluationResponseContext {
                    constraints,
                    ..Default::default()
                },
            })
        } else {
            Ok(EvaluationResponse {
                decision: true,
                context: EvaluationResponseContext::default(),
            })
        }
    }
}

// ── Mock Model Resolver ──

pub struct MockModelResolver;

#[async_trait]
impl ModelResolver for MockModelResolver {
    async fn resolve_model(
        &self,
        _user_id: Uuid,
        model: Option<String>,
    ) -> Result<ResolvedModel, DomainError> {
        let catalog = [("gpt-5.2", "openai", true), ("gpt-5-mini", "openai", false)];

        match model {
            None => Ok(ResolvedModel {
                model_id: "gpt-5.2".to_owned(),
                provider_id: "openai".to_owned(),
            }),
            Some(m) if m.is_empty() => Err(DomainError::invalid_model("model must not be empty")),
            Some(m) => {
                if let Some((_, provider_id, _)) =
                    catalog.iter().find(|(id, _, enabled)| *id == m && *enabled)
                {
                    Ok(ResolvedModel {
                        model_id: m,
                        provider_id: provider_id.to_string(),
                    })
                } else {
                    Err(DomainError::invalid_model(&m))
                }
            }
        }
    }
}

// ── Test Helpers ──

pub async fn inmem_db() -> Db {
    let opts = ConnectOpts {
        max_conns: Some(1),
        min_conns: Some(1),
        ..Default::default()
    };
    let db = connect_db("sqlite::memory:", opts)
        .await
        .expect("Failed to connect to in-memory database");

    run_migrations_for_testing(&db, crate::infra::db::migrations::Migrator::migrations())
        .await
        .expect("Failed to run migrations");

    db
}

pub fn test_security_ctx(tenant_id: Uuid) -> SecurityContext {
    SecurityContext::builder()
        .subject_id(Uuid::new_v4())
        .subject_tenant_id(tenant_id)
        .build()
        .expect("failed to build SecurityContext")
}

pub fn test_security_ctx_with_id(tenant_id: Uuid, subject_id: Uuid) -> SecurityContext {
    SecurityContext::builder()
        .subject_id(subject_id)
        .subject_tenant_id(tenant_id)
        .build()
        .expect("failed to build SecurityContext")
}

pub fn mock_enforcer() -> PolicyEnforcer {
    let authz: Arc<dyn AuthZResolverClient> = Arc::new(MockAuthZResolver);
    PolicyEnforcer::new(authz)
}

pub fn mock_model_resolver() -> Arc<dyn ModelResolver> {
    Arc::new(MockModelResolver)
}

pub fn mock_thread_summary_repo() -> Arc<dyn ThreadSummaryRepository> {
    struct MockThreadSummaryRepo;
    impl ThreadSummaryRepository for MockThreadSummaryRepo {}
    Arc::new(MockThreadSummaryRepo)
}

pub fn mock_db_provider(db: Db) -> Arc<DBProvider<modkit_db::DbError>> {
    Arc::new(DBProvider::new(db))
}

// ── Mock Policy Snapshot Provider ──

use mini_chat_sdk::{PolicySnapshot, UserLimits};
use std::sync::Mutex;

pub struct MockPolicySnapshotProvider {
    snapshot: Mutex<PolicySnapshot>,
}

impl MockPolicySnapshotProvider {
    pub fn new(snapshot: PolicySnapshot) -> Self {
        Self {
            snapshot: Mutex::new(snapshot),
        }
    }
}

#[async_trait]
impl PolicySnapshotProvider for MockPolicySnapshotProvider {
    async fn get_snapshot(
        &self,
        _user_id: Uuid,
        _policy_version: u64,
    ) -> Result<PolicySnapshot, DomainError> {
        Ok(self.snapshot.lock().unwrap().clone())
    }

    async fn get_current_version(&self, _user_id: Uuid) -> Result<u64, DomainError> {
        Ok(self.snapshot.lock().unwrap().policy_version)
    }
}

// ── Mock User Limits Provider ──

pub struct MockUserLimitsProvider {
    limits: Mutex<UserLimits>,
}

impl MockUserLimitsProvider {
    pub fn new(limits: UserLimits) -> Self {
        Self {
            limits: Mutex::new(limits),
        }
    }
}

#[async_trait]
impl UserLimitsProvider for MockUserLimitsProvider {
    async fn get_limits(
        &self,
        _user_id: Uuid,
        _policy_version: u64,
    ) -> Result<UserLimits, DomainError> {
        Ok(self.limits.lock().unwrap().clone())
    }
}
