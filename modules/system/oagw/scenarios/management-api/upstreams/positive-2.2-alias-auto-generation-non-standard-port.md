# Alias generation for non-standard port

## Request

```http
POST /api/oagw/v1/upstreams HTTP/1.1
Host: oagw.example.com
Authorization: Bearer <tenant-token>
Content-Type: application/json

{
  "server": {
    "endpoints": [
      { "scheme": "https", "host": "api.example.com", "port": 8443 }
    ]
  },
  "protocol": "gts.cf.core.oagw.protocol.v1~cf.core.oagw.http.v1"
}
```

## Expected response

- `201 Created`
- Alias includes port for non-standard port.

```json
{
  "id": "gts.cf.core.oagw.upstream.v1~<uuid>",
  "alias": "api.example.com:8443",
  "server": {
    "endpoints": [
      { "scheme": "https", "host": "api.example.com", "port": 8443 }
    ]
  }
}
```
