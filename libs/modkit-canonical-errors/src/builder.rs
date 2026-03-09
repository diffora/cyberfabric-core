use crate::context::{
    Aborted, AlreadyExists, Cancelled, DataLoss, DeadlineExceeded, FailedPrecondition,
    FieldViolation, Internal, InvalidArgument, NotFound, OutOfRange, PermissionDenied,
    PreconditionViolation, QuotaViolation, ResourceExhausted, ServiceUnavailable, Unauthenticated,
    Unimplemented, Unknown,
};
use crate::error::CanonicalError;

// ---------------------------------------------------------------------------
// Resource markers
// ---------------------------------------------------------------------------

pub struct ResourceAbsent;
pub struct ResourceOptional;
pub struct ResourceMissing;
pub struct ResourceSet(String);

// ---------------------------------------------------------------------------
// Context markers
// ---------------------------------------------------------------------------

pub struct NoContext;
pub struct NeedsFieldViolation;
pub struct HasFieldViolations(Vec<FieldViolation>);
pub struct NeedsPreconditionViolation;
pub struct HasPreconditionViolations(Vec<PreconditionViolation>);
pub struct NeedsQuotaViolation;
pub struct HasQuotaViolations(Vec<QuotaViolation>);
pub struct HasFormatMessage(String);
pub struct HasConstraintMessage(String);
pub struct NeedsReason;
pub struct HasReason;

// ---------------------------------------------------------------------------
// Traits gating build()
// ---------------------------------------------------------------------------

pub trait ResourceResolved {
    fn resolve(self) -> Option<String>;
}

impl ResourceResolved for ResourceAbsent {
    fn resolve(self) -> Option<String> {
        None
    }
}

impl ResourceResolved for ResourceOptional {
    fn resolve(self) -> Option<String> {
        None
    }
}

impl ResourceResolved for ResourceSet {
    fn resolve(self) -> Option<String> {
        Some(self.0)
    }
}

pub struct ContextData {
    pub field_violations: Vec<FieldViolation>,
    pub precondition_violations: Vec<PreconditionViolation>,
    pub quota_violations: Vec<QuotaViolation>,
    pub format_message: Option<String>,
    pub constraint_message: Option<String>,
}

pub trait ContextResolved {
    fn into_context_data(self) -> ContextData;
}

impl ContextResolved for NoContext {
    fn into_context_data(self) -> ContextData {
        ContextData {
            field_violations: Vec::new(),
            precondition_violations: Vec::new(),
            quota_violations: Vec::new(),
            format_message: None,
            constraint_message: None,
        }
    }
}

impl ContextResolved for HasFieldViolations {
    fn into_context_data(self) -> ContextData {
        ContextData {
            field_violations: self.0,
            precondition_violations: Vec::new(),
            quota_violations: Vec::new(),
            format_message: None,
            constraint_message: None,
        }
    }
}

impl ContextResolved for HasFormatMessage {
    fn into_context_data(self) -> ContextData {
        ContextData {
            field_violations: Vec::new(),
            precondition_violations: Vec::new(),
            quota_violations: Vec::new(),
            format_message: Some(self.0),
            constraint_message: None,
        }
    }
}

impl ContextResolved for HasConstraintMessage {
    fn into_context_data(self) -> ContextData {
        ContextData {
            field_violations: Vec::new(),
            precondition_violations: Vec::new(),
            quota_violations: Vec::new(),
            format_message: None,
            constraint_message: Some(self.0),
        }
    }
}

impl ContextResolved for HasPreconditionViolations {
    fn into_context_data(self) -> ContextData {
        ContextData {
            field_violations: Vec::new(),
            precondition_violations: self.0,
            quota_violations: Vec::new(),
            format_message: None,
            constraint_message: None,
        }
    }
}

impl ContextResolved for HasQuotaViolations {
    fn into_context_data(self) -> ContextData {
        ContextData {
            field_violations: Vec::new(),
            precondition_violations: Vec::new(),
            quota_violations: self.0,
            format_message: None,
            constraint_message: None,
        }
    }
}

impl ContextResolved for HasReason {
    fn into_context_data(self) -> ContextData {
        ContextData {
            field_violations: Vec::new(),
            precondition_violations: Vec::new(),
            quota_violations: Vec::new(),
            format_message: None,
            constraint_message: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Error variant discriminant
// ---------------------------------------------------------------------------

#[doc(hidden)]
#[derive(Debug, Clone, Copy)]
pub enum ErrorVariant {
    Cancelled,
    Unknown,
    InvalidArgument,
    DeadlineExceeded,
    NotFound,
    AlreadyExists,
    PermissionDenied,
    ResourceExhausted,
    FailedPrecondition,
    Aborted,
    OutOfRange,
    Unimplemented,
    Internal,
    DataLoss,
    Unauthenticated,
}

// ---------------------------------------------------------------------------
// ResourceErrorBuilder
// ---------------------------------------------------------------------------

pub struct ResourceErrorBuilder<Resource, Context> {
    resource_type: Option<&'static str>,
    detail: String,
    variant: ErrorVariant,
    resource: Resource,
    context: Context,
    reason: Option<String>,
}

// ---------------------------------------------------------------------------
// #[doc(hidden)] constructors — called by the macro
// ---------------------------------------------------------------------------

impl ResourceErrorBuilder<ResourceMissing, NoContext> {
    #[doc(hidden)]
    pub fn __not_found(resource_type: &'static str, detail: impl Into<String>) -> Self {
        ResourceErrorBuilder {
            resource_type: Some(resource_type),
            detail: detail.into(),
            variant: ErrorVariant::NotFound,
            resource: ResourceMissing,
            context: NoContext,
            reason: None,
        }
    }

    #[doc(hidden)]
    pub fn __already_exists(resource_type: &'static str, detail: impl Into<String>) -> Self {
        ResourceErrorBuilder {
            resource_type: Some(resource_type),
            detail: detail.into(),
            variant: ErrorVariant::AlreadyExists,
            resource: ResourceMissing,
            context: NoContext,
            reason: None,
        }
    }

    #[doc(hidden)]
    pub fn __data_loss(resource_type: &'static str, detail: impl Into<String>) -> Self {
        ResourceErrorBuilder {
            resource_type: Some(resource_type),
            detail: detail.into(),
            variant: ErrorVariant::DataLoss,
            resource: ResourceMissing,
            context: NoContext,
            reason: None,
        }
    }
}

impl ResourceErrorBuilder<ResourceOptional, NeedsReason> {
    #[doc(hidden)]
    pub fn __aborted(resource_type: &'static str, detail: impl Into<String>) -> Self {
        ResourceErrorBuilder {
            resource_type: Some(resource_type),
            detail: detail.into(),
            variant: ErrorVariant::Aborted,
            resource: ResourceOptional,
            context: NeedsReason,
            reason: None,
        }
    }
}

impl ResourceErrorBuilder<ResourceOptional, NoContext> {
    #[doc(hidden)]
    pub fn __unknown(resource_type: &'static str, detail: impl Into<String>) -> Self {
        ResourceErrorBuilder {
            resource_type: Some(resource_type),
            detail: detail.into(),
            variant: ErrorVariant::Unknown,
            resource: ResourceOptional,
            context: NoContext,
            reason: None,
        }
    }

    #[doc(hidden)]
    pub fn __deadline_exceeded(resource_type: &'static str, detail: impl Into<String>) -> Self {
        ResourceErrorBuilder {
            resource_type: Some(resource_type),
            detail: detail.into(),
            variant: ErrorVariant::DeadlineExceeded,
            resource: ResourceOptional,
            context: NoContext,
            reason: None,
        }
    }

    #[doc(hidden)]
    pub fn __unimplemented(resource_type: &'static str, detail: impl Into<String>) -> Self {
        ResourceErrorBuilder {
            resource_type: Some(resource_type),
            detail: detail.into(),
            variant: ErrorVariant::Unimplemented,
            resource: ResourceOptional,
            context: NoContext,
            reason: None,
        }
    }
}

impl ResourceErrorBuilder<ResourceAbsent, NoContext> {
    #[doc(hidden)]
    pub fn __permission_denied(resource_type: &'static str, detail: impl Into<String>) -> Self {
        ResourceErrorBuilder {
            resource_type: Some(resource_type),
            detail: detail.into(),
            variant: ErrorVariant::PermissionDenied,
            resource: ResourceAbsent,
            context: NoContext,
            reason: None,
        }
    }

    #[doc(hidden)]
    pub fn __cancelled(resource_type: &'static str, detail: impl Into<String>) -> Self {
        ResourceErrorBuilder {
            resource_type: Some(resource_type),
            detail: detail.into(),
            variant: ErrorVariant::Cancelled,
            resource: ResourceAbsent,
            context: NoContext,
            reason: None,
        }
    }
}

impl ResourceErrorBuilder<ResourceOptional, NeedsFieldViolation> {
    #[doc(hidden)]
    pub fn __invalid_argument(resource_type: &'static str, detail: impl Into<String>) -> Self {
        ResourceErrorBuilder {
            resource_type: Some(resource_type),
            detail: detail.into(),
            variant: ErrorVariant::InvalidArgument,
            resource: ResourceOptional,
            context: NeedsFieldViolation,
            reason: None,
        }
    }

    #[doc(hidden)]
    pub fn __out_of_range(resource_type: &'static str, detail: impl Into<String>) -> Self {
        ResourceErrorBuilder {
            resource_type: Some(resource_type),
            detail: detail.into(),
            variant: ErrorVariant::OutOfRange,
            resource: ResourceOptional,
            context: NeedsFieldViolation,
            reason: None,
        }
    }
}

impl ResourceErrorBuilder<ResourceOptional, NeedsQuotaViolation> {
    #[doc(hidden)]
    pub fn __resource_exhausted(resource_type: &'static str, detail: impl Into<String>) -> Self {
        ResourceErrorBuilder {
            resource_type: Some(resource_type),
            detail: detail.into(),
            variant: ErrorVariant::ResourceExhausted,
            resource: ResourceOptional,
            context: NeedsQuotaViolation,
            reason: None,
        }
    }
}

impl ResourceErrorBuilder<ResourceOptional, NeedsPreconditionViolation> {
    #[doc(hidden)]
    pub fn __failed_precondition(resource_type: &'static str, detail: impl Into<String>) -> Self {
        ResourceErrorBuilder {
            resource_type: Some(resource_type),
            detail: detail.into(),
            variant: ErrorVariant::FailedPrecondition,
            resource: ResourceOptional,
            context: NeedsPreconditionViolation,
            reason: None,
        }
    }
}

// ---------------------------------------------------------------------------
// with_resource() — available for ResourceMissing and ResourceOptional
// ---------------------------------------------------------------------------

impl<Context> ResourceErrorBuilder<ResourceMissing, Context> {
    #[must_use]
    pub fn with_resource(
        self,
        resource: impl Into<String>,
    ) -> ResourceErrorBuilder<ResourceSet, Context> {
        ResourceErrorBuilder {
            resource_type: self.resource_type,
            detail: self.detail,
            variant: self.variant,
            resource: ResourceSet(resource.into()),
            context: self.context,
            reason: self.reason,
        }
    }
}

impl<Context> ResourceErrorBuilder<ResourceOptional, Context> {
    #[must_use]
    pub fn with_resource(
        self,
        resource: impl Into<String>,
    ) -> ResourceErrorBuilder<ResourceSet, Context> {
        ResourceErrorBuilder {
            resource_type: self.resource_type,
            detail: self.detail,
            variant: self.variant,
            resource: ResourceSet(resource.into()),
            context: self.context,
            reason: self.reason,
        }
    }
}

// ---------------------------------------------------------------------------
// with_field_violation() — NeedsFieldViolation → HasFieldViolations, then self
// ---------------------------------------------------------------------------

impl<Resource> ResourceErrorBuilder<Resource, NeedsFieldViolation> {
    #[must_use]
    pub fn with_field_violation(
        self,
        field: impl Into<String>,
        description: impl Into<String>,
        reason: impl Into<String>,
    ) -> ResourceErrorBuilder<Resource, HasFieldViolations> {
        ResourceErrorBuilder {
            resource_type: self.resource_type,
            detail: self.detail,
            variant: self.variant,
            resource: self.resource,
            context: HasFieldViolations(vec![FieldViolation::new(field, description, reason)]),
            reason: self.reason,
        }
    }

    #[must_use]
    pub fn with_format(
        self,
        message: impl Into<String>,
    ) -> ResourceErrorBuilder<Resource, HasFormatMessage> {
        let msg = message.into();
        ResourceErrorBuilder {
            resource_type: self.resource_type,
            detail: msg.clone(),
            variant: self.variant,
            resource: self.resource,
            context: HasFormatMessage(msg),
            reason: self.reason,
        }
    }

    #[must_use]
    pub fn with_constraint(
        self,
        message: impl Into<String>,
    ) -> ResourceErrorBuilder<Resource, HasConstraintMessage> {
        let msg = message.into();
        ResourceErrorBuilder {
            resource_type: self.resource_type,
            detail: msg.clone(),
            variant: self.variant,
            resource: self.resource,
            context: HasConstraintMessage(msg),
            reason: self.reason,
        }
    }
}

impl<Resource> ResourceErrorBuilder<Resource, HasFieldViolations> {
    #[must_use]
    pub fn with_field_violation(
        mut self,
        field: impl Into<String>,
        description: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        self.context
            .0
            .push(FieldViolation::new(field, description, reason));
        self
    }
}

// ---------------------------------------------------------------------------
// with_precondition_violation() — NeedsPreconditionViolation → HasPreconditionViolations
// ---------------------------------------------------------------------------

impl<Resource> ResourceErrorBuilder<Resource, NeedsPreconditionViolation> {
    #[must_use]
    pub fn with_precondition_violation(
        self,
        subject: impl Into<String>,
        description: impl Into<String>,
        type_: impl Into<String>,
    ) -> ResourceErrorBuilder<Resource, HasPreconditionViolations> {
        ResourceErrorBuilder {
            resource_type: self.resource_type,
            detail: self.detail,
            variant: self.variant,
            resource: self.resource,
            context: HasPreconditionViolations(vec![PreconditionViolation::new(
                type_,
                subject,
                description,
            )]),
            reason: self.reason,
        }
    }
}

impl<Resource> ResourceErrorBuilder<Resource, HasPreconditionViolations> {
    #[must_use]
    pub fn with_precondition_violation(
        mut self,
        subject: impl Into<String>,
        description: impl Into<String>,
        type_: impl Into<String>,
    ) -> Self {
        self.context
            .0
            .push(PreconditionViolation::new(type_, subject, description));
        self
    }
}

// ---------------------------------------------------------------------------
// with_quota_violation() — NeedsQuotaViolation → HasQuotaViolations
// ---------------------------------------------------------------------------

impl<Resource> ResourceErrorBuilder<Resource, NeedsQuotaViolation> {
    #[must_use]
    pub fn with_quota_violation(
        self,
        subject: impl Into<String>,
        description: impl Into<String>,
    ) -> ResourceErrorBuilder<Resource, HasQuotaViolations> {
        ResourceErrorBuilder {
            resource_type: self.resource_type,
            detail: self.detail,
            variant: self.variant,
            resource: self.resource,
            context: HasQuotaViolations(vec![QuotaViolation::new(subject, description)]),
            reason: self.reason,
        }
    }
}

impl<Resource> ResourceErrorBuilder<Resource, HasQuotaViolations> {
    #[must_use]
    pub fn with_quota_violation(
        mut self,
        subject: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        self.context
            .0
            .push(QuotaViolation::new(subject, description));
        self
    }
}

// ---------------------------------------------------------------------------
// with_reason() — NeedsReason → HasReason
// ---------------------------------------------------------------------------

impl<Resource> ResourceErrorBuilder<Resource, NeedsReason> {
    #[must_use]
    pub fn with_reason(
        self,
        reason: impl Into<String>,
    ) -> ResourceErrorBuilder<Resource, HasReason> {
        ResourceErrorBuilder {
            resource_type: self.resource_type,
            detail: self.detail,
            variant: self.variant,
            resource: self.resource,
            context: HasReason,
            reason: Some(reason.into()),
        }
    }
}

// ---------------------------------------------------------------------------
// Public builder-returning constructors on CanonicalError (non-macro categories)
// ---------------------------------------------------------------------------

impl CanonicalError {
    #[must_use]
    pub fn internal(detail: impl Into<String>) -> ResourceErrorBuilder<ResourceAbsent, NoContext> {
        ResourceErrorBuilder {
            resource_type: None,
            detail: detail.into(),
            variant: ErrorVariant::Internal,
            resource: ResourceAbsent,
            context: NoContext,
            reason: None,
        }
    }

    #[must_use]
    pub fn service_unavailable() -> ServiceUnavailableBuilder {
        ServiceUnavailableBuilder {
            retry_after_seconds: None,
        }
    }

    #[must_use]
    pub fn unauthenticated() -> ResourceErrorBuilder<ResourceAbsent, NeedsReason> {
        ResourceErrorBuilder {
            resource_type: None,
            detail: String::from("Authentication required"),
            variant: ErrorVariant::Unauthenticated,
            resource: ResourceAbsent,
            context: NeedsReason,
            reason: None,
        }
    }
}

// ---------------------------------------------------------------------------
// create() — gated by Resource + Context Resolved traits
// ---------------------------------------------------------------------------

impl<Resource, Context> ResourceErrorBuilder<Resource, Context>
where
    Resource: ResourceResolved,
    Context: ContextResolved,
{
    #[must_use]
    pub fn create(self) -> CanonicalError {
        let resource_name = self.resource.resolve();
        let ctx_data = self.context.into_context_data();
        let rt = self.resource_type.unwrap_or("");

        let err = match self.variant {
            ErrorVariant::NotFound => {
                let rn = resource_name.as_deref().unwrap_or("");
                CanonicalError::__not_found(NotFound::new(rt, rn))
            }
            ErrorVariant::AlreadyExists => {
                let rn = resource_name.as_deref().unwrap_or("");
                CanonicalError::__already_exists(AlreadyExists::new(rt, rn))
            }
            ErrorVariant::Aborted => {
                CanonicalError::__aborted(Aborted::new(self.reason.as_deref().unwrap_or("")))
            }
            ErrorVariant::Unknown => CanonicalError::__unknown(Unknown::new(&self.detail)),
            ErrorVariant::DeadlineExceeded => {
                CanonicalError::__deadline_exceeded(DeadlineExceeded::new())
            }
            ErrorVariant::PermissionDenied => {
                CanonicalError::__permission_denied(PermissionDenied::new())
            }
            ErrorVariant::InvalidArgument => {
                let ctx = if let Some(fmt) = ctx_data.format_message {
                    InvalidArgument::format(fmt)
                } else if let Some(cst) = ctx_data.constraint_message {
                    InvalidArgument::constraint(cst)
                } else {
                    InvalidArgument::fields(ctx_data.field_violations)
                };
                CanonicalError::__invalid_argument(ctx)
            }
            ErrorVariant::OutOfRange => {
                CanonicalError::__out_of_range(OutOfRange::new(ctx_data.field_violations))
            }
            ErrorVariant::ResourceExhausted => CanonicalError::__resource_exhausted(
                ResourceExhausted::new(ctx_data.quota_violations),
            ),
            ErrorVariant::FailedPrecondition => CanonicalError::__failed_precondition(
                FailedPrecondition::new(ctx_data.precondition_violations),
            ),
            ErrorVariant::Cancelled => CanonicalError::__cancelled(Cancelled::new()),
            ErrorVariant::Unimplemented => CanonicalError::__unimplemented(Unimplemented::new()),
            ErrorVariant::Internal => CanonicalError::__internal(Internal::new(&self.detail)),
            ErrorVariant::DataLoss => {
                let rn = resource_name.as_deref().unwrap_or("");
                CanonicalError::__data_loss(DataLoss::new(rt, rn))
            }
            ErrorVariant::Unauthenticated => {
                let mut ctx = Unauthenticated::new();
                if let Some(reason) = self.reason {
                    ctx = ctx.with_reason(reason);
                }
                CanonicalError::__unauthenticated(ctx)
            }
        };

        let mut err = if matches!(err, CanonicalError::Internal { .. }) {
            err
        } else {
            err.with_detail(&self.detail)
        };

        if let Some(rt) = self.resource_type {
            err = err.with_resource_type(rt);
        }

        if let Some(rn) = resource_name {
            err.with_resource(rn)
        } else {
            err
        }
    }
}

// ---------------------------------------------------------------------------
// ServiceUnavailableBuilder — dedicated builder for ServiceUnavailable
// ---------------------------------------------------------------------------

pub struct ServiceUnavailableBuilder {
    retry_after_seconds: Option<u64>,
}

impl ServiceUnavailableBuilder {
    #[must_use]
    pub fn with_retry_after_seconds(mut self, seconds: u64) -> Self {
        self.retry_after_seconds = Some(seconds);
        self
    }

    #[must_use]
    pub fn create(self) -> CanonicalError {
        CanonicalError::__service_unavailable(ServiceUnavailable::new(
            self.retry_after_seconds.unwrap_or(0),
        ))
        .with_detail("Service temporarily unavailable")
    }
}
