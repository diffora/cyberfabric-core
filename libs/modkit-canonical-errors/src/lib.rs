extern crate self as cf_modkit_errors;

pub mod builder;
pub mod context;
pub mod error;
pub mod problem;

pub use cf_modkit_errors_macros::resource_error;

pub use builder::{ResourceErrorBuilder, ServiceUnavailableBuilder};
pub use context::{
    Aborted, AlreadyExists, Cancelled, DataLoss, DeadlineExceeded, FailedPrecondition,
    FieldViolation, Internal, InvalidArgument, NotFound, OutOfRange, PermissionDenied,
    PreconditionViolation, QuotaViolation, ResourceExhausted, ServiceUnavailable, Unauthenticated,
    Unimplemented, Unknown,
};
pub use error::CanonicalError;
pub use problem::Problem;
