# Outbound auth: noop

## Upstream configuration

```json
{
  "alias": "public.example.com",
  "server": {
    "endpoints": [
      { "scheme": "https", "host": "public.example.com", "port": 443 }
    ]
  },
  "protocol": "gts.cf.core.oagw.protocol.v1~cf.core.oagw.http.v1",
  "auth": {
    "type": "gts.cf.core.oagw.auth_plugin.v1~cf.core.oagw.noop.v1",
    "config": {}
  }
}
```

## Inbound request

```http
GET /api/oagw/v1/proxy/public.example.com/health HTTP/1.1
Host: oagw.example.com
Authorization: Bearer <tenant-token>
```

## Expected behavior

- Gateway forwards request without injecting credentials.
- Upstream does not receive additional auth headers from OAGW.
