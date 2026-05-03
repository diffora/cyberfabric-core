# ADR: Cross-Origin Resource Sharing (CORS)

- **Status**: Accepted
- **Date**: 2026-02-03
- **Deciders**: OAGW Team

## Context and Problem Statement

OAGW proxies requests to upstream services. When web browsers make requests from one origin (e.g., `https://app.example.com`) to OAGW proxy endpoint on another origin (e.g.,
`https://api.example.com`), browsers enforce CORS policies. Without proper CORS support, browser-based clients cannot use OAGW.

**Key challenges**:

- CORS is browser-specific (non-browser clients ignore it)
- Preflight OPTIONS requests must be handled locally (not proxied)
- CORS headers vary by upstream service requirements
- Credential-bearing requests require strict origin matching
- Security: overly permissive CORS exposes APIs to unauthorized origins

## Decision Drivers

- Support browser-based clients (SPAs, web apps)
- Security: prevent unauthorized cross-origin access
- Flexibility: per-upstream/route CORS configuration
- Performance: minimize preflight overhead
- Standards compliance: RFC 6454, WHATWG Fetch spec

## Considered Options

### Option 1: Proxy CORS to Upstream

Forward all requests (including OPTIONS preflight) to upstream. Let upstream handle CORS.

**Configuration**: None (passthrough)

**Pros**:

- Simple (no OAGW logic)
- Upstream controls CORS policy
- No configuration needed

**Cons**:

- Preflight adds round-trip latency (OPTIONS → upstream → client)
- Upstream may not support CORS
- Cannot enforce OAGW-level origin restrictions
- Preflight fails if upstream unavailable (even for cached responses)

### Option 2: CORS Guard Plugin

Implement CORS as a guard plugin. Configurable per upstream/route.

**Configuration**:

```json
{
  "plugins": {
    "items": [
      {
        "type": "gts.cf.core.oagw.guard_plugin.v1~cf.core.oagw.cors.v1",
        "config": {
          "allowed_origins": [ "https://app.example.com", "https://admin.example.com" ],
          "allowed_methods": [ "GET", "POST", "PUT", "DELETE" ],
          "expose_headers": [ "X-Request-ID" ],
          "allow_credentials": true
        }
      }
    ]
  }
}
```

**Pros**:

- Flexible per-upstream/route configuration
- Local preflight handling (no upstream round-trip)
- Can enforce stricter CORS than upstream
- Works even if upstream is down

**Cons**:

- Requires explicit configuration
- Plugin must run before all other plugins (order matters)
- Complexity in plugin chain management

### Option 3: Built-in CORS Handler (Recommended)

CORS as first-class feature in upstream/route configuration. Handled before plugin chain.

**Configuration**:

```json
{
  "server": {
    "endpoints": [ { "scheme": "https", "host": "api.service.com", "port": 443 } ]
  },
  "cors": {
    "enabled": true,
    "allowed_origins": [ "https://app.example.com" ],
    "allowed_methods": [ "GET", "POST" ],
    "expose_headers": [ "X-Request-ID" ],
    "allow_credentials": true
  }
}
```

**Pros**:

- First-class feature (no plugin ordering issues)
- Preflight handled before routing/auth/plugins (fast path)
- Clear configuration model
- Standards-compliant default behavior

**Cons**:

- Adds built-in logic to OAGW core
- Not extensible via plugins (but can be overridden)

## Comparison Matrix

| Criteria                 | Option 1 (Proxy) | Option 2 (Plugin) | Option 3 (Built-in) |
|--------------------------|:----------------:|:-----------------:|:-------------------:|
| Preflight latency        |       High       |        Low        |         Low         |
| Configuration complexity |       None       |      Medium       |         Low         |
| Upstream independence    |        No        |        Yes        |         Yes         |
| Plugin ordering issues   |       N/A        |        Yes        |         No          |
| Standards compliance     |     Depends      |        Yes        |         Yes         |
| Works when upstream down |        No        |        Yes        |         Yes         |

## Decision Outcome

**Chosen**: Option 3 (Built-in CORS Handler)

**Rationale**:

1. **Performance**: Preflight handled immediately, no upstream round-trip
2. **Reliability**: Works even if upstream is down or doesn't support CORS
3. **Simplicity**: Clear configuration model, no plugin ordering complexity
4. **Security**: OAGW-level origin enforcement before request reaches upstream
5. **Standards**: Proper CORS implementation per WHATWG Fetch spec

Options 1 and 2 rejected:

- Option 1: Adds latency, fails if upstream unavailable
- Option 2: Plugin ordering issues, more complex configuration

## Configuration Schema

### Upstream/Route CORS Field

```json
{
  "cors": {
    "type": "object",
    "properties": {
      "enabled": {
        "type": "boolean",
        "default": false,
        "description": "Enable CORS for this upstream/route"
      },
      "allowed_origins": {
        "type": "array",
        "items": { "type": "string", "format": "uri" },
        "description": "Allowed origins. Use ['*'] for any origin (not recommended with credentials)."
      },
      "allowed_methods": {
        "type": "array",
        "items": { "type": "string", "enum": [ "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS" ] },
        "default": [ "GET", "POST" ],
        "description": "Allowed HTTP methods"
      },
      "expose_headers": {
        "type": "array",
        "items": { "type": "string" },
        "default": [ ],
        "description": "Headers exposed to browser (beyond CORS-safelisted headers)"
      },
      "allow_credentials": {
        "type": "boolean",
        "default": false,
        "description": "Allow credentials (cookies, auth headers). Requires specific origins (not '*')."
      }
    },
    "required": [ "enabled" ]
  }
}
```

### Configuration Examples

**Public API (no credentials)**:

```json
{
  "cors": {
    "enabled": true,
    "allowed_origins": [ "*" ],
    "allowed_methods": [ "GET", "POST" ]
  }
}
```

**Authenticated API (with credentials)**:

```json
{
  "cors": {
    "enabled": true,
    "allowed_origins": [
      "https://app.example.com",
      "https://admin.example.com"
    ],
    "allowed_methods": [ "GET", "POST", "PUT", "DELETE" ],
    "expose_headers": [ "X-Request-ID", "X-RateLimit-Remaining" ],
    "allow_credentials": true
  }
}
```

**Development (localhost)**:

```json
{
  "cors": {
    "enabled": true,
    "allowed_origins": [
      "http://localhost:3000",
      "http://localhost:5173"
    ],
    "allowed_methods": [ "GET", "POST", "PUT", "DELETE" ],
    "allow_credentials": true
  }
}
```

## Implementation Details

### Preflight Request Handling

Browser preflight requests contain no credentials (per WHATWG Fetch spec), so no tenant context is available for upstream resolution. The proxy handler detects preflight and returns a permissive 204 that echoes back the requested origin, method, and headers. Origin and method validation is deferred to the actual request.

```
OPTIONS /api/oagw/v1/proxy/api.example.com/users
Origin: https://app.example.com
Access-Control-Request-Method: POST
Access-Control-Request-Headers: Content-Type, Authorization

↓

1. Handler detects CORS preflight (OPTIONS + Origin + Access-Control-Request-Method)
2. Return 204 No Content echoing the request's origin, method, and headers
   (no upstream resolution, no tenant context required)
```

**Response headers** (preflight):

```http
HTTP/1.1 204 No Content
Access-Control-Allow-Origin: https://app.example.com
Access-Control-Allow-Methods: POST
Access-Control-Allow-Headers: Content-Type, Authorization
Access-Control-Max-Age: 86400
Vary: Origin, Access-Control-Request-Method, Access-Control-Request-Headers
```

Origin enforcement happens on the subsequent actual request — after upstream resolution, the origin is validated against the upstream's CORS config before the request is forwarded. See [Actual Request Handling](#actual-request-handling).

### Actual Request Handling

```
POST /api/oagw/v1/proxy/api.example.com/users
Origin: https://app.example.com
Content-Type: application/json

↓

1. Resolve upstream (requires tenant context from authenticated request)
2. Check: Is origin in allowed_origins? (403 if not)
3. Check: Is method in allowed_methods? (403 if not)
4. Forward request to upstream
5. Add CORS headers to response
```

**Response headers** (actual request):

```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://app.example.com
Access-Control-Expose-Headers: X-Request-ID
Access-Control-Allow-Credentials: true
Vary: Origin
```

### Origin Matching

**Exact match**:

```json
"allowed_origins": [ "https://app.example.com" ]
```

Matches: `https://app.example.com`
Rejects: `https://evil.com`, `https://app.example.com:8080`, `http://app.example.com`

**Wildcard** (discouraged with credentials):

```json
"allowed_origins": [ "*" ]
```

Matches: Any origin
Note: Cannot use with `allow_credentials: true`

**Multiple origins**:

```json
"allowed_origins": [
"https://app.example.com",
"https://admin.example.com"
]
```

### Security Considerations

**Deny by default**: CORS disabled unless explicitly enabled.

**Strict origin validation**:

- No regex patterns (prevents bypasses like `https://evil.com.example.com`)
- Port-sensitive matching (`:443` ≠ `:8443`)
- Protocol-sensitive (HTTP ≠ HTTPS)

**Credentials restriction**:

```rust
if config.allow_credentials & & config.allowed_origins.contains("*") {
return Err("Cannot use allow_credentials with wildcard origin");
}
```

**Preflight optimization**:

- Return permissive 204 No Content at handler level (no upstream resolution, no body)
- Origin validation happens on the actual request (after upstream resolution, before forwarding)
- Skip per-request auth/plugin checks for preflight (global/edge rate limiting and WAF/DDoS controls still apply)

**Vary header**:
Always include `Vary: Origin` to prevent cache poisoning.

## Hierarchical Configuration

CORS configuration follows sharing modes:

```json
{
  "cors": {
    "sharing": "inherit",
    "enabled": true,
    "allowed_origins": [ "https://app.example.com" ]
  }
}
```

**Merge behavior**:

- Parent: `allowed_origins: ["https://app.example.com"]`
- Child: `allowed_origins: ["https://admin.example.com"]`
- Effective: `["https://app.example.com", "https://admin.example.com"]` (union)

With `sharing: enforce`, child cannot add origins.

## Error Responses

**Origin not allowed** (actual request — disallowed origin rejected before forwarding to upstream):

```http
HTTP/1.1 403 Forbidden
Content-Type: application/problem+json

{
  "type": "gts.cf.core.errors.err.v1~cf.oagw.cors.origin_not_allowed.v1",
  "title": "CORS Origin Not Allowed",
  "status": 403,
  "detail": "Origin 'https://evil.com' not in allowed origins list"
}
```

**Method not allowed** (actual request — disallowed method rejected before forwarding to upstream):

```http
HTTP/1.1 403 Forbidden

{
  "type": "gts.cf.core.errors.err.v1~cf.oagw.cors.method_not_allowed.v1",
  "title": "CORS Method Not Allowed",
  "status": 403,
  "detail": "Method 'DELETE' not in allowed methods list"
}
```

## Consequences

### Positive

- Browser-based clients can use OAGW
- Fast preflight handling (no upstream round-trip)
- Works when upstream unavailable
- Secure by default (disabled unless configured)
- Standards-compliant implementation

### Negative

- No Adds built-in logic to OAGW core
- No Requires CORS configuration for each upstream/route
- No Not extensible via plugins (but can be disabled if needed)

### Neutral

- CORS only affects browser clients (other clients unaffected)
- Configuration complexity proportional to security requirements
- Preflight requests bypass per-request auth/plugin checks (by design) but still pass through global/edge rate limiting and WAF/DDoS controls

## Links

- [MDN: CORS](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)
- [WHATWG Fetch Standard](https://fetch.spec.whatwg.org/#http-cors-protocol)
- [RFC 6454: Origin](https://datatracker.ietf.org/doc/html/rfc6454)
- [OWASP: CORS Security](https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny)
