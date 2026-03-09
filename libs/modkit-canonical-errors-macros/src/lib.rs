use proc_macro::TokenStream;
use quote::quote;
use syn::{Fields, ItemStruct, LitStr, parse_macro_input};

/// Generates a resource error type with builder-returning constructors for the 13 canonical
/// error categories that carry a `resource_type`.
///
/// Generated constructors either accept a detail string or are zero-argument
/// (using a default message). Each returns a `ResourceErrorBuilder` with
/// typestate enforcement — required fields must be set via builder methods
/// (e.g. `.with_resource(...)`, `.with_reason(...)`) before `.create()`
/// compiles.
///
/// Categories where `resource_type` is absent (`internal`,
/// `service_unavailable`, `unauthenticated`) are **not** generated — use
/// `CanonicalError::*()` directly for those.
///
/// # Example
///
/// ```ignore
/// #[resource_error("gts.cf.core.tenants.tenant.v1~")]
/// struct TenantResourceError;
///
/// let err = TenantResourceError::not_found("tenant not found")
///     .with_resource("tenant-123")
///     .create();
/// assert_eq!(err.resource_type(), Some("gts.cf.core.tenants.tenant.v1~"));
/// ```
#[proc_macro_attribute]
pub fn resource_error(attr: TokenStream, item: TokenStream) -> TokenStream {
    let gts_type = parse_macro_input!(attr as LitStr);
    let input = parse_macro_input!(item as ItemStruct);

    let gts_value = gts_type.value();
    if let Err(e) = gts_id::validate_gts_id(&gts_value, false) {
        return syn::Error::new_spanned(&gts_type, format!("invalid GTS type: {e}"))
            .to_compile_error()
            .into();
    }

    if !matches!(input.fields, Fields::Unit) {
        return syn::Error::new_spanned(
            &input,
            "#[resource_error] can only be applied to unit structs (e.g. `struct MyError;`)",
        )
        .to_compile_error()
        .into();
    }

    let vis = &input.vis;
    let name = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let expanded = quote! {
        #input

        impl #impl_generics #name #ty_generics #where_clause {
            // --- resource_name required ---

            #vis fn not_found(detail: impl Into<String>)
                -> ::cf_modkit_errors::ResourceErrorBuilder<
                    ::cf_modkit_errors::builder::ResourceMissing,
                    ::cf_modkit_errors::builder::NoContext,
                >
            {
                ::cf_modkit_errors::ResourceErrorBuilder::__not_found(#gts_type, detail)
            }

            #vis fn already_exists(detail: impl Into<String>)
                -> ::cf_modkit_errors::ResourceErrorBuilder<
                    ::cf_modkit_errors::builder::ResourceMissing,
                    ::cf_modkit_errors::builder::NoContext,
                >
            {
                ::cf_modkit_errors::ResourceErrorBuilder::__already_exists(#gts_type, detail)
            }

            #vis fn data_loss(detail: impl Into<String>)
                -> ::cf_modkit_errors::ResourceErrorBuilder<
                    ::cf_modkit_errors::builder::ResourceMissing,
                    ::cf_modkit_errors::builder::NoContext,
                >
            {
                ::cf_modkit_errors::ResourceErrorBuilder::__data_loss(#gts_type, detail)
            }

            // --- resource_name optional ---

            #vis fn aborted(detail: impl Into<String>)
                -> ::cf_modkit_errors::ResourceErrorBuilder<
                    ::cf_modkit_errors::builder::ResourceOptional,
                    ::cf_modkit_errors::builder::NeedsReason,
                >
            {
                ::cf_modkit_errors::ResourceErrorBuilder::__aborted(#gts_type, detail)
            }

            #vis fn unknown(detail: impl Into<String>)
                -> ::cf_modkit_errors::ResourceErrorBuilder<
                    ::cf_modkit_errors::builder::ResourceOptional,
                    ::cf_modkit_errors::builder::NoContext,
                >
            {
                ::cf_modkit_errors::ResourceErrorBuilder::__unknown(#gts_type, detail)
            }

            #vis fn deadline_exceeded(detail: impl Into<String>)
                -> ::cf_modkit_errors::ResourceErrorBuilder<
                    ::cf_modkit_errors::builder::ResourceOptional,
                    ::cf_modkit_errors::builder::NoContext,
                >
            {
                ::cf_modkit_errors::ResourceErrorBuilder::__deadline_exceeded(#gts_type, detail)
            }

            // --- resource_name absent ---

            #vis fn permission_denied()
                -> ::cf_modkit_errors::ResourceErrorBuilder<
                    ::cf_modkit_errors::builder::ResourceAbsent,
                    ::cf_modkit_errors::builder::NoContext,
                >
            {
                ::cf_modkit_errors::ResourceErrorBuilder::__permission_denied(#gts_type, "You do not have permission to perform this operation")
            }

            #vis fn unimplemented(detail: impl Into<String>)
                -> ::cf_modkit_errors::ResourceErrorBuilder<
                    ::cf_modkit_errors::builder::ResourceOptional,
                    ::cf_modkit_errors::builder::NoContext,
                >
            {
                ::cf_modkit_errors::ResourceErrorBuilder::__unimplemented(#gts_type, detail)
            }

            #vis fn cancelled()
                -> ::cf_modkit_errors::ResourceErrorBuilder<
                    ::cf_modkit_errors::builder::ResourceAbsent,
                    ::cf_modkit_errors::builder::NoContext,
                >
            {
                ::cf_modkit_errors::ResourceErrorBuilder::__cancelled(#gts_type, "Operation cancelled by the client")
            }

            // --- resource_name optional, needs field violations ---

            #vis fn invalid_argument()
                -> ::cf_modkit_errors::ResourceErrorBuilder<
                    ::cf_modkit_errors::builder::ResourceOptional,
                    ::cf_modkit_errors::builder::NeedsFieldViolation,
                >
            {
                ::cf_modkit_errors::ResourceErrorBuilder::__invalid_argument(#gts_type, "Request validation failed")
            }

            // --- resource_name optional, needs field violations ---

            #vis fn out_of_range(detail: impl Into<String>)
                -> ::cf_modkit_errors::ResourceErrorBuilder<
                    ::cf_modkit_errors::builder::ResourceOptional,
                    ::cf_modkit_errors::builder::NeedsFieldViolation,
                >
            {
                ::cf_modkit_errors::ResourceErrorBuilder::__out_of_range(#gts_type, detail)
            }

            // --- resource_name optional, needs quota violations ---

            #vis fn resource_exhausted(detail: impl Into<String>)
                -> ::cf_modkit_errors::ResourceErrorBuilder<
                    ::cf_modkit_errors::builder::ResourceOptional,
                    ::cf_modkit_errors::builder::NeedsQuotaViolation,
                >
            {
                ::cf_modkit_errors::ResourceErrorBuilder::__resource_exhausted(#gts_type, detail)
            }

            // --- resource_name optional, needs precondition violations ---

            #vis fn failed_precondition()
                -> ::cf_modkit_errors::ResourceErrorBuilder<
                    ::cf_modkit_errors::builder::ResourceOptional,
                    ::cf_modkit_errors::builder::NeedsPreconditionViolation,
                >
            {
                ::cf_modkit_errors::ResourceErrorBuilder::__failed_precondition(#gts_type, "Operation precondition not met")
            }
        }
    };

    expanded.into()
}
