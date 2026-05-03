# Management API requires bearer auth

## Request

```http
POST /api/oagw/v1/upstreams HTTP/1.1
Host: oagw.example.com
Content-Type: application/json

{
  "server": {
    "endpoints": [
      { "scheme": "https", "host": "httpbin.org", "port": 443 }
    ]
  },
  "protocol": "gts.cf.core.oagw.protocol.v1~cf.core.oagw.http.v1"
}
```

## Expected response

- `401 Unauthorized`
- `Content-Type: application/problem+json`

```json
{
  "type": "gts.cf.core.errors.err.v1~cf.oagw.auth.failed.v1",
  "title": "Authentication Failed",
  "status": 401,
  "detail": "Missing or invalid bearer token",
  "instance": "/api/oagw/v1/upstreams"
}
```
