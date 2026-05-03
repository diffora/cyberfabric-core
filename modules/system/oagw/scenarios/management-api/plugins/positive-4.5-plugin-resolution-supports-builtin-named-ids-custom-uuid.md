# Plugin resolution: builtin named ids vs custom UUID ids

## Scenario A: attach builtin plugin

Attach builtin plugin by named id (example from design):
- `gts.cf.core.oagw.transform_plugin.v1~cf.core.oagw.logging.v1`

Expected:
- Upstream/route update succeeds.
- Proxy invocation succeeds and plugin behavior is observed (e.g., log emitted).

## Scenario B: attach missing custom plugin UUID

Attach custom plugin id that does not exist in DB:
- `gts.cf.core.oagw.guard_plugin.v1~550e8400-e29b-41d4-a716-446655440000`

Invoke proxy.

Expected:
- `503 Service Unavailable`
- `Content-Type: application/problem+json`
- Error type `gts.cf.core.errors.err.v1~cf.oagw.plugin.not_found.v1`
- `X-OAGW-Error-Source: gateway`
