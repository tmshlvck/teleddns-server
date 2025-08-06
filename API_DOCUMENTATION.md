# TeleDDNS Server API Documentation

## Overview

The TeleDDNS Server provides a comprehensive RESTful API for managing DNS zones, resource records, and server configurations. The API includes auto-generated interactive documentation powered by OpenAPI/Swagger.

## Accessing API Documentation

The API documentation is available at the following endpoints when the server is running:

- **Swagger UI (Interactive)**: `http://your-server/api/docs/`
- **ReDoc (Alternative UI)**: `http://your-server/api/redoc/`
- **OpenAPI Schema (JSON)**: `http://your-server/api/schema/`

The interactive documentation allows you to:
- Browse all available endpoints
- View request/response schemas
- Try out API calls directly from the browser (works automatically if logged into Django admin)
- Download the OpenAPI specification

**Note**: If you're logged into Django admin, Swagger UI will automatically authenticate your requests using session authentication. For token authentication in Swagger UI, click "Authorize" and enter: `Token YOUR_TOKEN_HERE`

## Authentication

The API supports two authentication methods:

1. **Token Authentication** (recommended for programmatic access)
2. **Session Authentication** (used by the browsable API and Swagger UI)

### Understanding Authentication Behavior

- **All API endpoints require authentication** except for `/api/health/`
- If you're logged into Django admin, Swagger UI will work automatically (session auth)
- For programmatic access, use Token authentication
- Missing or invalid authentication returns `401 Unauthorized`

### Obtaining an API Token

1. **Via Admin Interface**:
   - Login to Django admin at `/admin/`
   - Go to "Auth Tokens" section
   - Create a token for your user

2. **Via API** (requires session auth or basic auth):
   ```bash
   # Get existing token (or create if none exists)
   curl -X GET http://your-server/api/token/ \
     -H "Content-Type: application/json" \
     -u username:password
   
   # Regenerate token (invalidates old token)
   curl -X POST http://your-server/api/token/ \
     -H "Content-Type: application/json" \
     -u username:password
   ```

### Using the Token

Include the token in the Authorization header for all API requests:

```bash
curl -H "Authorization: Token YOUR_TOKEN_HERE" http://your-server/api/zones/
```

**Important**: The format must be exactly `Token YOUR_TOKEN_HERE` (note the space after "Token").

### Authentication Errors

- `401 Unauthorized` with `"Authentication credentials were not provided."` - No token provided
- `401 Unauthorized` with `"Invalid token."` - Token is incorrect or has been deleted
- `403 Forbidden` - Token is valid but user lacks permission for the operation

## API Endpoints

### Core Resources

#### Zones
- `GET /api/zones/` - List all zones
- `POST /api/zones/` - Create a new zone
- `GET /api/zones/{id}/` - Get zone details
- `PUT /api/zones/{id}/` - Update zone
- `DELETE /api/zones/{id}/` - Delete zone
- `POST /api/zones/{id}/sync/` - Synchronize zone to DNS servers
- `GET /api/zones/{id}/validate/` - Validate zone configuration
- `GET /api/zones/{id}/check/` - Check zone on DNS server
- `POST /api/zones/{id}/increment_serial/` - Increment SOA serial

#### Slave-Only Zones
- `GET /api/slave-zones/` - List slave-only zones
- `POST /api/slave-zones/` - Create slave-only zone
- `GET /api/slave-zones/{id}/` - Get slave-only zone details
- `PUT /api/slave-zones/{id}/` - Update slave-only zone
- `DELETE /api/slave-zones/{id}/` - Delete slave-only zone
- `POST /api/slave-zones/{id}/sync/` - Sync configuration to slave servers

#### Resource Records
Each record type has its own endpoint set:

- A Records: `/api/records/a/`
- AAAA Records: `/api/records/aaaa/`
- CNAME Records: `/api/records/cname/`
- MX Records: `/api/records/mx/`
- NS Records: `/api/records/ns/`
- PTR Records: `/api/records/ptr/`
- SRV Records: `/api/records/srv/`
- TXT Records: `/api/records/txt/`
- CAA Records: `/api/records/caa/`
- DS Records: `/api/records/ds/`
- DNSKEY Records: `/api/records/dnskey/`
- TLSA Records: `/api/records/tlsa/`

Each record type endpoint supports:
- `GET /api/records/{type}/` - List records
- `POST /api/records/{type}/` - Create record
- `GET /api/records/{type}/{id}/` - Get record details
- `PUT /api/records/{type}/{id}/` - Update record
- `DELETE /api/records/{type}/{id}/` - Delete record

#### Infrastructure
- `GET /api/servers/` - List DNS servers
- `POST /api/servers/` - Add DNS server
- `GET /api/servers/{id}/` - Get server details
- `PUT /api/servers/{id}/` - Update server
- `DELETE /api/servers/{id}/` - Delete server

#### Administration
- `GET /api/users/` - List users
- `GET /api/groups/` - List groups
- `GET /api/audit-logs/` - View audit logs

## Common Operations

### Creating a Zone

```bash
curl -X POST http://your-server/api/zones/ \
  -H "Authorization: Token YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "origin": "example.com.",
    "owner_id": 1,
    "group_id": 1,
    "master_server": 1,
    "slave_servers": [2, 3]
  }'
```

### Adding an A Record

```bash
curl -X POST http://your-server/api/records/a/ \
  -H "Authorization: Token YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "zone": 1,
    "label": "www",
    "ttl": 3600,
    "value": "192.168.1.100"
  }'
```

### Synchronizing a Zone

```bash
curl -X POST http://your-server/api/zones/1/sync/ \
  -H "Authorization: Token YOUR_TOKEN"
```

### Creating a Slave-Only Zone

```bash
curl -X POST http://your-server/api/slave-zones/ \
  -H "Authorization: Token YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "origin": "external.example.com.",
    "external_master": "ns1.external-provider.com",
    "slave_server_ids": [1, 2],
    "owner_id": 1,
    "group_id": 1
  }'
```

## Query Parameters

### Pagination
- `page` - Page number (default: 1)
- `page_size` - Items per page (default: 100, max: 1000)

Example: `/api/zones/?page=2&page_size=50`

### Searching
- `search` - Search term

Example: `/api/zones/?search=example.com`

### Ordering
- `ordering` - Field to sort by (prefix with `-` for descending)

Example: `/api/zones/?ordering=-updated_at`

### Filtering by Zone
For resource records, filter by zone ID:

Example: `/api/records/a/?zone=1`

## Response Format

### Successful Response
```json
{
  "id": 1,
  "origin": "example.com.",
  "owner": {
    "id": 1,
    "username": "admin"
  },
  "is_dirty": false,
  "created_at": "2024-01-01T00:00:00Z",
  "updated_at": "2024-01-01T12:00:00Z"
}
```

### Error Response
```json
{
  "error": "You do not have permission to perform this action",
  "detail": "Additional error information"
}
```

### Paginated Response
```json
{
  "count": 150,
  "next": "http://your-server/api/zones/?page=2",
  "previous": null,
  "results": [
    {
      "id": 1,
      "origin": "example.com.",
      ...
    }
  ]
}
```

## Dynamic DNS (DDNS)

The DDNS update endpoint is separate from the main API and uses different authentication:

### Endpoint
- `POST /update/` or `POST /ddns/update/`

### Authentication
DDNS uses HTTP Basic Authentication with zone-specific credentials.

### Parameters
- `hostname` - FQDN to update
- `myip` - New IP address (optional, auto-detected if not provided)

### Example
```bash
curl -X POST http://your-server/update/ \
  -u ddns-user:ddns-password \
  -d "hostname=home.example.com&myip=203.0.113.45"
```

### Response Codes
- `good [IP]` - Update successful
- `nochg [IP]` - IP address unchanged
- `badauth` - Authentication failed
- `nohost` - Hostname not found
- `notfqdn` - Invalid hostname format
- `badip` - Invalid IP address

## Rate Limiting

- API requests: 1000 per hour per user
- DDNS updates: 60 per hour per IP address

## Best Practices

1. **Always use HTTPS** in production to protect API tokens
2. **Store tokens securely** and rotate them periodically
3. **Use specific permissions** - create users with minimal required permissions
4. **Monitor audit logs** to track API usage
5. **Synchronize zones** after making changes to propagate to DNS servers
6. **Validate zones** before synchronization to catch errors early

## Troubleshooting

### Common Issues

1. **401 Unauthorized**
   - Check that your token is correct
   - Ensure token is in the format: `Authorization: Token YOUR_TOKEN` (with space after "Token")
   - Verify the token exists in the database (wasn't deleted or regenerated)
   - Note: The `/api/token/` endpoint itself requires session or basic auth, not token auth

2. **403 Forbidden**
   - User lacks permission for the requested operation
   - Check user group memberships and zone ownership

3. **400 Bad Request**
   - Validate JSON syntax
   - Check required fields are present
   - Ensure data types are correct

4. **Zone not syncing**
   - Check if zone is marked as dirty
   - Verify server connectivity
   - Check server API credentials

5. **Swagger UI works but curl doesn't**
   - This means you're authenticated via session (logged into Django admin)
   - For curl/programmatic access, you need to use token authentication
   - Get your token from `/api/token/` or Django admin

### Debug Mode

For detailed error messages during development:
- Set `DEBUG=True` in environment
- Check server logs for detailed stack traces

## Additional Resources

- [Django REST Framework Documentation](https://www.django-rest-framework.org/)
- [OpenAPI Specification](https://swagger.io/specification/)
- [RFC 1035 - Domain Names](https://tools.ietf.org/html/rfc1035)