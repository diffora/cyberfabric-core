# Re-enable route restores proxy traffic

## Step 1: Create upstream and route

```http
POST /api/oagw/v1/upstreams HTTP/1.1
Host: oagw.example.com
Authorization: Bearer <tenant-token>
Content-Type: application/json

{
  "server": {
    "endpoints": [
      { "scheme": "https", "host": "httpbin.org", "port": 443 }
    ]
  },
  "protocol": "gts.cf.core.oagw.protocol.v1~cf.core.oagw.http.v1",
  "alias": "httpbin.org"
}
```

Expected: `201 Created` with upstream id.

```http
POST /api/oagw/v1/routes HTTP/1.1
Host: oagw.example.com
Authorization: Bearer <tenant-token>
Content-Type: application/json

{
  "upstream_id": "gts.cf.core.oagw.upstream.v1~<uuid>",
  "match": {
    "http": {
      "methods": ["GET"],
      "path": "/get"
    }
  }
}
```

Expected: `201 Created` with route id `gts.cf.core.oagw.route.v1~<route-uuid>`.

## Step 2: Disable route

```http
PUT /api/oagw/v1/routes/gts.cf.core.oagw.route.v1~<route-uuid> HTTP/1.1
Host: oagw.example.com
Authorization: Bearer <tenant-token>
Content-Type: application/json

{
  "upstream_id": "gts.cf.core.oagw.upstream.v1~<uuid>",
  "match": {
    "http": {
      "methods": ["GET"],
      "path": "/get"
    }
  },
  "enabled": false
}
```

Expected: `200 OK`.

## Step 3: Verify proxy blocked

```http
GET /api/oagw/v1/proxy/httpbin.org/get HTTP/1.1
Host: oagw.example.com
Authorization: Bearer <tenant-token>
```

Expected: `404` with `X-OAGW-Error-Source: gateway` (route not found).

## Step 4: Re-enable route

```http
PUT /api/oagw/v1/routes/gts.cf.core.oagw.route.v1~<route-uuid> HTTP/1.1
Host: oagw.example.com
Authorization: Bearer <tenant-token>
Content-Type: application/json

{
  "upstream_id": "gts.cf.core.oagw.upstream.v1~<uuid>",
  "match": {
    "http": {
      "methods": ["GET"],
      "path": "/get"
    }
  },
  "enabled": true
}
```

Expected: `200 OK`.

## Step 5: Verify proxy restored

```http
GET /api/oagw/v1/proxy/httpbin.org/get HTTP/1.1
Host: oagw.example.com
Authorization: Bearer <tenant-token>
```

## Expected response

- `200 OK`
- Response body from upstream httpbin.org
- No `X-OAGW-Error-Source` header (success case)
