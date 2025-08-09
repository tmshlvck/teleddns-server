# TeleDDNS Server - Django Edition

A robust, scalable Dynamic DNS (DDNS) server built with Django and Django REST Framework. This is a complete rewrite of the original TeleDDNS Server, offering enhanced features, better security, and a comprehensive REST API.

## Features

- **Dynamic DNS Updates**: Support for updating A and AAAA records via HTTP(S)
- **Comprehensive REST API**: Full CRUD operations for all DNS resources
- **Django Admin Interface**: User-friendly web interface for DNS management
- **Multi-user Support**: User and group-based access control
- **Audit Logging**: Complete audit trail of all changes
- **Zone Management**: Support for multiple DNS zones with full SOA record control
- **Resource Records**: Support for A, AAAA, CNAME, MX, NS, PTR, SRV, TXT, CAA, DS, DNSKEY, and TLSA records
- **Background Synchronization**: Automatic pushing of changes to backend DNS servers
- **Authentication Options**:
  - Token-based authentication for API access
  - HTTP Basic Authentication for DDNS updates
  - Django session authentication for admin interface
- **Permission System**: Fine-grained permissions based on ownership and group membership

## Requirements

- Python 3.12 or higher
- SQLite (included with Python)
- A backend DNS server with HTTP API support (e.g., PowerDNS, Knot DNS with TeleAPI)

## Installation

### Using Poetry (Recommended)

1. Clone the repository:
```bash
git clone https://github.com/tmshlvck/teleddns-server.git
cd teleddns-server
```

2. Install dependencies:
```bash
poetry install
```

3. Copy the example environment file:
```bash
cp .env.example .env
```

4. Edit `.env` and configure your settings:
   - `SECRET_KEY` - Generate a new one for production
   - `ALLOWED_HOSTS` - Your server's hostname(s)

5. Run migrations:
```bash
poetry run python manage.py migrate
```

6. Create a superuser:
```bash
poetry run python manage.py createsuperuser
```

7. Collect static files:
```bash
poetry run python manage.py collectstatic
```

### Using pip

1. Clone the repository and create a virtual environment:
```bash
git clone https://github.com/tmshlvck/teleddns-server.git
cd teleddns-server
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Follow steps 3-7 from the Poetry installation above.

## Configuration

### Environment Variables

Key environment variables (see `.env.example` for all options):

- `SECRET_KEY`: Django secret key (required)
- `DEBUG`: Set to `False` in production
- `DATABASE_URL`: SQLite database path (default: `sqlite:///db.sqlite3`)
- `ALLOWED_HOSTS`: Comma-separated list of allowed hostnames
- `DDNS_DEFAULT_TTL`: Default TTL for DNS records (default: 3600)
- `DDNS_RR_TTL`: TTL for resource records (default: 60)
- `SYNC_THREAD_INTERVAL`: Background sync thread check interval in seconds (default: 60)
- `SYNC_THREAD_MAX_BACKOFF_SECONDS`: Maximum backoff time in seconds (default: 86400 = 24 hours)
- `SYNC_THREAD_BACKOFF_BASE`: Exponential backoff base for retries (default: 2)

### DNS Server Configuration

1. Log in to the Django admin at `/admin/`
2. Add DNS servers under "DNS Servers"
3. Configure:
   - API URL: The base URL of your DNS server's API
   - API Key: Authentication key for the DNS server
   - Master/Slave Templates: Template names used by your DNS server

### Zone Setup

1. Create zones in the admin interface
2. Set appropriate SOA values
3. Assign owner and group permissions
4. Add resource records as needed

## Usage

### Starting the Development Server

```bash
python manage.py runserver
# Or with Poetry:
poetry run python manage.py runserver
```

### Starting the Production Server

Using uvicorn (ASGI):
```bash
uvicorn teleddns_server.asgi:application --host 0.0.0.0 --port 8000
```

## Production Deployment

For production deployments, we provide comprehensive guides and a deployment helper script:

### Deployment Options

1. **Systemd Service** - Traditional deployment with Poetry
2. **Podman/Docker** - Container-based deployment

### Quick Start

```bash
# Download and run the deployment helper
sudo ./deploy.sh
```

The deployment helper provides an interactive menu to:
- Install with systemd or Podman
- Configure Nginx with SSL
- Create database backups
- Monitor service status

### Documentation

See the detailed production deployment guide: [docs/PRODUCTION_DEPLOYMENT.md](docs/PRODUCTION_DEPLOYMENT.md)

Key features:
- Nginx reverse proxy with SSL termination
- Let's Encrypt certificate automation
- Systemd service management
- Health monitoring
- Automatic database backups
- Security hardening

### Environment Variables

Production deployments require proper environment configuration. See `.env.example` for all available options.

### DDNS Updates

The DDNS endpoints support both GET and POST requests:

- `/ddns/update/` - Main DDNS endpoint (JSON responses)
- `/update` - Legacy endpoint for backward compatibility
- `/ddns/update/simple/` - Simple text responses for basic clients

Example DDNS update:
```bash
# Using curl with Basic Auth
curl -u username:password "https://ddns.example.com/ddns/update/?hostname=home.example.com&myip=192.168.1.100"

# Using token authentication
curl -H "Authorization: Token your-api-token" "https://ddns.example.com/ddns/update/?hostname=home.example.com"

# Auto-detect IP
curl -u username:password "https://ddns.example.com/ddns/update/?hostname=home.example.com"
```

### REST API

The TeleDDNS Server provides a comprehensive RESTful API with auto-generated interactive documentation.

#### API Documentation

- **Swagger UI**: http://localhost:8000/api/docs/ - Interactive API documentation with "Try it out" functionality
- **ReDoc**: http://localhost:8000/api/redoc/ - Alternative clean documentation interface
- **OpenAPI Schema**: http://localhost:8000/api/schema/ - Machine-readable API specification (OpenAPI 3.0)

#### Authentication

The API supports two authentication methods:

1. **Token Authentication** (recommended for programmatic access):
   ```bash
   curl -H "Authorization: Token YOUR_TOKEN_HERE" http://localhost:8000/api/zones/
   ```

2. **Session Authentication** (automatically used in Swagger UI when logged into Django admin)

To obtain an API token:
```bash
# Get or create token (requires basic auth)
curl -u username:password -X GET http://localhost:8000/api/token/

# Regenerate token (invalidates old token)
curl -u username:password -X POST http://localhost:8000/api/token/
```

#### API Endpoints

All API endpoints are under `/api/`:

- `/api/servers/` - DNS server management (superuser only)
- `/api/zones/` - Zone management
- `/api/records/a/` - A records
- `/api/records/aaaa/` - AAAA records
- `/api/records/cname/` - CNAME records
- `/api/records/mx/` - MX records
- `/api/records/ns/` - NS records
- `/api/records/ptr/` - PTR records
- `/api/records/srv/` - SRV records
- `/api/records/txt/` - TXT records
- `/api/records/caa/` - CAA records
- `/api/records/ds/` - DS records
- `/api/records/dnskey/` - DNSKEY records
- `/api/records/tlsa/` - TLSA records
- `/api/token/` - API token management
- `/api/audit-logs/` - Audit log viewing

#### Example API Usage

```bash
# Get API token
curl -u username:password -X GET https://ddns.example.com/api/token/

# List zones
curl -H "Authorization: Token your-api-token" https://ddns.example.com/api/zones/

# Create a new A record
curl -X POST https://ddns.example.com/api/records/a/ \
  -H "Authorization: Token your-api-token" \
  -H "Content-Type: application/json" \
  -d '{
    "zone": 1,
    "label": "www",
    "ttl": 3600,
    "value": "192.168.1.100"
  }'

# Synchronize a zone to DNS servers
curl -X POST https://ddns.example.com/api/zones/1/sync/ \
  -H "Authorization: Token your-api-token"
```

For detailed API documentation and to test endpoints interactively, visit the Swagger UI at `/api/docs/` when the server is running.

# Create an A record
curl -H "Authorization: Token your-api-token" \
     -H "Content-Type: application/json" \
     -X POST https://ddns.example.com/api/records/a/ \
     -d '{"zone": 1, "label": "test", "value": "192.168.1.100", "ttl": 3600}'
```

### Zone Synchronization

Synchronize dirty zones to DNS servers:
```bash
# Sync all dirty zones
python manage.py sync_zones

# Sync specific zone
python manage.py sync_zones --zone example.com.

# Force sync even if not dirty
python manage.py sync_zones --force

# Dry run to see what would be synced
python manage.py sync_zones --dry-run
```

Set up a cron job for automatic synchronization:
```cron
# Sync zones every 5 minutes
*/5 * * * * cd /path/to/teleddns-server && /path/to/venv/bin/python manage.py sync_zones --quiet
```

## Docker Deployment

### Build and Run

1. Build the Docker image:
```bash
docker build -t teleddns-server .
```

2. Run the container:
```bash
docker run -d \
  --name teleddns \
  -p 8000:8000 \
  -v teleddns-data:/data \
  --env-file .env \
  teleddns-server
```

The container will:
- Automatically run database migrations
- Collect static files
- Start uvicorn on port 8000
- Store the SQLite database in the `/data` volume

### Docker Environment

When running in Docker, make sure your `.env` file contains:
```bash
DATABASE_URL=sqlite:////data/db.sqlite3
```

### Nginx Proxy Configuration

If you're using an external Nginx proxy, here's a basic configuration:

```nginx
location / {
    proxy_pass http://localhost:8000;
    proxy_set_header Host $http_host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

## Production Deployment

### Systemd Service

Create `/etc/systemd/system/teleddns.service`:
```ini
[Unit]
Description=TeleDDNS Server
After=network.target

[Service]
Type=notify
User=teleddns
Group=teleddns
WorkingDirectory=/opt/teleddns-server
Environment="PATH=/opt/teleddns-server/venv/bin"
ExecStart=/opt/teleddns-server/venv/bin/uvicorn teleddns_server.asgi:application --host 0.0.0.0 --port 8000
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

### Zone Synchronization Cron

Add to your crontab:
```bash
*/5 * * * * cd /opt/teleddns-server && /opt/teleddns-server/venv/bin/python manage.py sync_zones --quiet
```

## Development

### Running Tests

```bash
python manage.py test
```

### Creating Database Migrations

If you modify models:
```bash
python manage.py makemigrations
python manage.py migrate
```

## Security Considerations

1. Always use HTTPS in production (configure in your external proxy)
2. Generate a strong `SECRET_KEY`
3. Keep the DNS server API keys secure
4. Regularly review audit logs
5. Use strong passwords for all users
6. Consider implementing rate limiting in your proxy
7. Keep Django and all dependencies up to date

## API Authentication

### Token Authentication

1. Users can generate tokens via the admin interface or API
2. Include the token in requests:
   ```
   Authorization: Token your-api-token-here
   ```

### Basic Authentication

For DDNS updates, you can use HTTP Basic Authentication:
```
Authorization: Basic base64(username:password)
```

## Backup and Restore

### Backup

To backup your data:
```bash
# Backup SQLite database
cp db.sqlite3 backup/db.sqlite3.$(date +%Y%m%d)

# Or if using Docker
docker exec teleddns python manage.py dumpdata > backup.json
```

### Restore

To restore from backup:
```bash
# Restore SQLite database
cp backup/db.sqlite3.20240101 db.sqlite3

# Or if using Docker
docker exec teleddns python manage.py loaddata backup.json
```

## License

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

See the LICENSE file for details.

## Author

(C) 2015-2024 Tomas Hlavacek (tmshlvck@gmail.com)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Changelog

### Version 2.0.0 (Django Edition)

- Complete rewrite using Django framework
- New REST API with full CRUD operations
- Enhanced permission system with user and group support
- Comprehensive audit logging
- Support for 12+ DNS record types
- Improved zone synchronization
- Token-based API authentication
- Django admin interface
- Simplified deployment with SQLite and uvicorn
