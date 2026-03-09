# ModKit Canonical Errors Macros

Procedural macros for the `cf-modkit-canonical-errors` crate.

## Overview

The `cf-modkit-canonical-errors-macros` crate provides:

- `resource_error` – an attribute macro that generates a resource error type with builder-returning constructors for the canonical error categories that carry a `resource_type`

## Usage

```rust
use cf_modkit_errors::resource_error;

#[resource_error("gts.cf.core.tenants.tenant.v1~")]
struct TenantResourceError;

let err = TenantResourceError::not_found("tenant not found")
    .with_resource("tenant-123")
    .create();
```

Categories where `resource_type` is absent (`internal`, `service_unavailable`, `unauthenticated`) are not generated — use `CanonicalError::*()` directly for those.

## License

Licensed under Apache-2.0.
