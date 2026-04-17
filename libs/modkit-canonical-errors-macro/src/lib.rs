#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
//! Proc-macro for canonical error resource types.
//!
//! Provides the `#[resource_error("gts...")]` attribute macro.

use proc_macro::TokenStream;
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::quote;
use syn::LitStr;
use syn::parse_macro_input;

/// Attribute macro that generates a resource error type with builder-returning
/// constructors for the 13 canonical error categories that carry a
/// `resource_type`.
///
/// # Usage
///
/// ```rust,ignore
/// use modkit_canonical_errors::resource_error;
///
/// #[resource_error("gts.cf.core.users.user.v1~")]
/// struct UserResourceError;
/// ```
///
/// The GTS resource-type literal is validated at compile time.
///
/// Generated constructors either accept a detail string or are zero-argument
/// (using a default message). Each returns a `ResourceErrorBuilder` with
/// typestate enforcement.
#[proc_macro_attribute]
pub fn resource_error(attr: TokenStream, item: TokenStream) -> TokenStream {
    let gts_lit = parse_macro_input!(attr as LitStr);
    let input = parse_macro_input!(item as syn::ItemStruct);

    match generate_resource_error(&gts_lit, &input) {
        Ok(tokens) => tokens.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

const CANONICAL_ERRORS_PKG: &str = "cf-modkit-canonical-errors";
const CANONICAL_ERRORS_LIB: &str = "modkit_canonical_errors";

/// Resolves the path to the `modkit_canonical_errors` crate at the expansion site.
///
/// Uses `CARGO_PKG_NAME` to detect when the macro is invoked from within the
/// canonical-errors package itself (e.g. integration tests), where the lib name
/// (`modkit_canonical_errors`) differs from the package name
/// (`cf-modkit-canonical-errors`). For external consumers the resolution is
/// delegated to `proc_macro_crate`.
fn resolve_crate_path(gts_lit: &LitStr) -> syn::Result<TokenStream2> {
    let in_self = std::env::var("CARGO_PKG_NAME").is_ok_and(|p| p == CANONICAL_ERRORS_PKG);

    if in_self {
        // Inside the cf-modkit-canonical-errors package.
        // `crate` is correct only for the lib target; integration tests and
        // examples access the library as an extern crate by its [lib] name.
        let is_lib = std::env::var("CARGO_CRATE_NAME").is_ok_and(|c| c == CANONICAL_ERRORS_LIB);

        if is_lib {
            return Ok(quote!(crate));
        }

        let ident = syn::Ident::new(CANONICAL_ERRORS_LIB, proc_macro2::Span::call_site());
        return Ok(quote!(::#ident));
    }

    match proc_macro_crate::crate_name(CANONICAL_ERRORS_PKG) {
        Ok(proc_macro_crate::FoundCrate::Itself) => Ok(quote!(crate)),
        Ok(proc_macro_crate::FoundCrate::Name(n)) => {
            // When the dependency is not renamed, `proc_macro_crate` returns the
            // package name normalised to a Rust identifier.  If [lib].name differs
            // from the package name (as it does here) we must map back to the actual
            // lib name, otherwise the generated code references a non-existent crate.
            let pkg_normalized = CANONICAL_ERRORS_PKG.replace('-', "_");
            let effective = if n == pkg_normalized {
                CANONICAL_ERRORS_LIB
            } else {
                &n
            };
            let ident = syn::Ident::new(effective, proc_macro2::Span::call_site());
            Ok(quote!(::#ident))
        }
        Err(_) => Err(syn::Error::new_spanned(
            gts_lit,
            "cf-modkit-canonical-errors must be a direct dependency",
        )),
    }
}

fn generate_resource_error(gts_lit: &LitStr, input: &syn::ItemStruct) -> syn::Result<TokenStream2> {
    let gts_type = gts_lit.value();
    validate_gts_resource_type_str(&gts_type, gts_lit.span())?;

    if !matches!(input.fields, syn::Fields::Unit) {
        return Err(syn::Error::new_spanned(
            &input.ident,
            "#[resource_error] only supports unit structs (e.g. `struct MyError;`)",
        ));
    }
    if !input.generics.params.is_empty() || input.generics.where_clause.is_some() {
        return Err(syn::Error::new_spanned(
            &input.ident,
            "#[resource_error] does not support generics or where-clauses",
        ));
    }

    let crate_path = resolve_crate_path(gts_lit)?;

    let vis = &input.vis;
    let name = &input.ident;

    Ok(quote! {
        #input

        impl #name {
            // --- resource_name required ---

            #vis fn not_found(detail: impl Into<String>)
                -> #crate_path::ResourceErrorBuilder<
                    #crate_path::builder::ResourceMissing,
                    #crate_path::builder::NoContext,
                >
            {
                #crate_path::ResourceErrorBuilder::__not_found(#gts_type, detail)
            }

            #vis fn already_exists(detail: impl Into<String>)
                -> #crate_path::ResourceErrorBuilder<
                    #crate_path::builder::ResourceMissing,
                    #crate_path::builder::NoContext,
                >
            {
                #crate_path::ResourceErrorBuilder::__already_exists(#gts_type, detail)
            }

            #vis fn data_loss(detail: impl Into<String>)
                -> #crate_path::ResourceErrorBuilder<
                    #crate_path::builder::ResourceMissing,
                    #crate_path::builder::NoContext,
                >
            {
                #crate_path::ResourceErrorBuilder::__data_loss(#gts_type, detail)
            }

            // --- resource_name optional ---

            #vis fn aborted(detail: impl Into<String>)
                -> #crate_path::ResourceErrorBuilder<
                    #crate_path::builder::ResourceOptional,
                    #crate_path::builder::NeedsReason,
                >
            {
                #crate_path::ResourceErrorBuilder::__aborted(#gts_type, detail)
            }

            #vis fn unknown(detail: impl Into<String>)
                -> #crate_path::ResourceErrorBuilder<
                    #crate_path::builder::ResourceOptional,
                    #crate_path::builder::NoContext,
                >
            {
                #crate_path::ResourceErrorBuilder::__unknown(#gts_type, detail)
            }

            #vis fn deadline_exceeded(detail: impl Into<String>)
                -> #crate_path::ResourceErrorBuilder<
                    #crate_path::builder::ResourceOptional,
                    #crate_path::builder::NoContext,
                >
            {
                #crate_path::ResourceErrorBuilder::__deadline_exceeded(#gts_type, detail)
            }

            // --- resource_name absent ---

            #vis fn permission_denied()
                -> #crate_path::ResourceErrorBuilder<
                    #crate_path::builder::ResourceAbsent,
                    #crate_path::builder::NeedsReason,
                >
            {
                #crate_path::ResourceErrorBuilder::__permission_denied(#gts_type, "You do not have permission to perform this operation")
            }

            #vis fn unimplemented(detail: impl Into<String>)
                -> #crate_path::ResourceErrorBuilder<
                    #crate_path::builder::ResourceOptional,
                    #crate_path::builder::NoContext,
                >
            {
                #crate_path::ResourceErrorBuilder::__unimplemented(#gts_type, detail)
            }

            #vis fn cancelled()
                -> #crate_path::ResourceErrorBuilder<
                    #crate_path::builder::ResourceAbsent,
                    #crate_path::builder::NoContext,
                >
            {
                #crate_path::ResourceErrorBuilder::__cancelled(#gts_type, "Operation cancelled by the client")
            }

            // --- resource_name optional, needs field violations ---

            #vis fn invalid_argument()
                -> #crate_path::ResourceErrorBuilder<
                    #crate_path::builder::ResourceOptional,
                    #crate_path::builder::NeedsFieldViolation,
                >
            {
                #crate_path::ResourceErrorBuilder::__invalid_argument(#gts_type, "Request validation failed")
            }

            #vis fn out_of_range(detail: impl Into<String>)
                -> #crate_path::ResourceErrorBuilder<
                    #crate_path::builder::ResourceOptional,
                    #crate_path::builder::NeedsFieldViolation,
                >
            {
                #crate_path::ResourceErrorBuilder::__out_of_range(#gts_type, detail)
            }

            // --- resource_name optional, needs quota violations ---

            #vis fn resource_exhausted(detail: impl Into<String>)
                -> #crate_path::ResourceErrorBuilder<
                    #crate_path::builder::ResourceOptional,
                    #crate_path::builder::NeedsQuotaViolation,
                >
            {
                #crate_path::ResourceErrorBuilder::__resource_exhausted(#gts_type, detail)
            }

            // --- resource_name optional, needs precondition violations ---

            #vis fn failed_precondition()
                -> #crate_path::ResourceErrorBuilder<
                    #crate_path::builder::ResourceOptional,
                    #crate_path::builder::NeedsPreconditionViolation,
                >
            {
                #crate_path::ResourceErrorBuilder::__failed_precondition(#gts_type, "Operation precondition not met")
            }
        }
    })
}

/// Validates a GTS resource-type literal at proc-macro time.
///
/// Expected format: `gts.<vendor>.<package>.<namespace>.<type>.<version>~`
fn validate_gts_resource_type_str(s: &str, span: Span) -> syn::Result<()> {
    let b = s.as_bytes();
    let len = b.len();

    if len == 0 {
        return Err(syn::Error::new(span, "GTS resource type must not be empty"));
    }

    if b[len - 1] != b'~' {
        return Err(syn::Error::new(span, "GTS resource type must end with '~'"));
    }

    #[allow(unknown_lints)]
    #[allow(de0901_gts_string_pattern)]
    if len < 6 || !s.starts_with("gts.") {
        return Err(syn::Error::new(
            span,
            "GTS resource type must start with 'gts.'",
        ));
    }

    let body = &s[4..len - 1];
    if body.is_empty() {
        return Err(syn::Error::new(
            span,
            "GTS resource type must have segments after 'gts.' prefix",
        ));
    }

    let segments: Vec<&str> = body.split('.').collect();

    for seg in &segments {
        if seg.is_empty() {
            return Err(syn::Error::new(
                span,
                "GTS resource type contains an empty segment",
            ));
        }
        if !seg
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
        {
            return Err(syn::Error::new(
                span,
                "GTS resource type segments must contain only lowercase ASCII letters, digits, or underscores",
            ));
        }
    }

    // Need >= 5 segments: vendor.package.namespace.type.version
    if segments.len() < 5 {
        return Err(syn::Error::new(
            span,
            "GTS resource type must have at least 5 segments after 'gts.': vendor.package.namespace.type.version",
        ));
    }

    // Version segment validation
    // SAFETY: segments.len() >= 5 is checked above, so `.last()` is always `Some`.
    let Some(version) = segments.last() else {
        unreachable!()
    };
    if !version.starts_with('v') || version.len() < 2 {
        return Err(syn::Error::new(
            span,
            "GTS resource type must end with a version segment starting with 'v' (e.g. v1)",
        ));
    }
    if !version[1..].bytes().all(|c| c.is_ascii_digit()) {
        return Err(syn::Error::new(
            span,
            "GTS resource type version segment after 'v' must contain only ASCII digits",
        ));
    }

    Ok(())
}
