# IP-based endpoint requires explicit alias

## Request

```http
POST /api/oagw/v1/upstreams HTTP/1.1
Host: oagw.example.com
Authorization: Bearer <tenant-token>
Content-Type: application/json

{
  "server": {
    "endpoints": [
      { "scheme": "https", "host": "10.0.1.1", "port": 443 }
    ]
  },
  "protocol": "gts.cf.core.oagw.protocol.v1~cf.core.oagw.http.v1"
}
```

## Expected response

- `400 Bad Request`
- `Content-Type: application/problem+json`

```json
{
  "type": "gts.cf.core.errors.err.v1~cf.oagw.validation.error.v1",
  "title": "Validation Error",
  "status": 400,
  "detail": "alias is required for IP-based endpoints",
  "instance": "/api/oagw/v1/upstreams"
}
```
