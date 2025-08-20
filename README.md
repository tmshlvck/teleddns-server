# TeleDDNS Server

A Django-based Dynamic DNS server that manages DNS records through multiple interfaces and synchronizes them to backend DNS servers.

## Overview

TeleDDNS Server provides:
- **Django Admin interface** for DNS record management
- **REST API** for programmatic access
- **DDNS update endpoint** for dynamic IP updates
- **Automatic synchronization** to backend DNS servers (PowerDNS, Knot DNS, etc.)

## Key Features

### Multiple Access Methods
- **Django Admin** - Web-based management at `/admin/`
- **REST API** - Full CRUD operations at `/api/`
- **DDNS Updates** - Dynamic updates at `/ddns/update/` or `/update`

### Security & Permissions
- Users can only manage their own zones and records
- Group-based access control for shared zones
- Superusers have full access
- Consistent permissions across Admin, API, and DDNS interfaces

### Audit & Logging
- Complete audit trail of all changes in database
- Changes logged to stdout
- Dirty flags track zones and servers requiring synchronization

### Backend Synchronization
- Background worker thread checks every 60 seconds for changes
- For record changes: updates zone file and triggers reload
- For master zones: pushes config and zone content, then reconfigures
- For slave zones: pushes config to all slaves, then reconfigures
- Failed syncs retain dirty flags for automatic retry

## Quick Start

### Installation

1. Clone the repository:
```bash
git clone https://github.com/tmshlvck/teleddns-server.git
cd teleddns-server
```

2. Install with Poetry:
```bash
poetry install
```

3. Configure environment:
```bash
cp .env.example .env
# Edit .env with your settings
```

4. Initialize database:
```bash
poetry run python manage.py migrate
poetry run python manage.py createsuperuser
poetry run python manage.py collectstatic
```

5. Run development server:
```bash
poetry run python manage.py runserver
```

### Production Deployment

For production, use the deployment script:
```bash
sudo ./deploy.sh
```

This provides options for:
- Systemd service installation
- Docker/Podman deployment  
- Nginx configuration with SSL
- Automatic backups

### Mounting Under a Subdirectory

To mount TeleDDNS under a subdirectory (e.g., `/ddns`), you'll need to configure both Nginx and Django:

1. **Nginx configuration:**
```nginx
location /ddns/ {
    proxy_pass http://localhost:8000/;
    proxy_set_header Host $http_host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header SCRIPT_NAME /ddns;
}
```

2. **Django configuration** - Add to your `.env`:
```bash
FORCE_SCRIPT_NAME=/ddns
```

This will make Django aware it's mounted under `/ddns`, so URLs like `/ddns/admin/` and `/ddns/api/` will work correctly.

**Note:** The simplified `/update` endpoint assumes root mounting. Use `/ddns/update/` when mounted under a subdirectory.

### Static Files Handling

Since all static files come from Django Admin, REST Framework, and DRF Spectacular, you have two options:

**Option 1: Traditional `collectstatic` (default)**
```bash
poetry run python manage.py collectstatic --noinput
```
This collects ~10MB of static files that need to be served by Nginx or your web server.

**Option 2: WhiteNoise (serve from Python)**
WhiteNoise allows Django to serve its own static files efficiently in production:

1. Install WhiteNoise:
```bash
poetry add whitenoise
```

2. Add to `MIDDLEWARE` in settings.py (after SecurityMiddleware):
```python
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',  # Add this
    # ... rest of middleware
]
```

3. Add WhiteNoise settings:
```python
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'
```

With WhiteNoise, you still run `collectstatic` once during deployment, but Python serves the files directly. This simplifies deployment as you don't need to configure Nginx for static files.

## Usage

### DDNS Updates

Update DNS records dynamically:
```bash
# With basic auth
curl -u username:password "https://ddns.example.com/ddns/update/?hostname=home.example.com&myip=1.2.3.4"

# With token auth
curl -H "Authorization: Token your-token" "https://ddns.example.com/ddns/update/?hostname=home.example.com"
```

### REST API

Access the API with token authentication:
```bash
# Get token
curl -u username:password https://ddns.example.com/api/token/

# List zones
curl -H "Authorization: Token your-token" https://ddns.example.com/api/zones/

# Create A record
curl -X POST -H "Authorization: Token your-token" \
     -H "Content-Type: application/json" \
     -d '{"zone": 1, "label": "test", "value": "1.2.3.4", "ttl": 3600}' \
     https://ddns.example.com/api/records/a/
```

API documentation available at:
- `/api/docs/` - Interactive Swagger UI
- `/api/redoc/` - ReDoc documentation
- `/api/schema/` - OpenAPI schema

### Manual Synchronization

Manually run synchronization of all dirty zones and configurations:
```bash
poetry run python manage.py sync
```

This runs the same synchronization that the background worker performs every 60 seconds.

## Configuration

Key settings in `.env`:
- `SECRET_KEY` - Django secret key (required)
- `ALLOWED_HOSTS` - Comma-separated hostnames
- `SYNC_THREAD_INTERVAL` - Backend sync interval (default: 60 seconds)

Configure DNS servers in Django Admin under "DNS Servers" with:
- API URL and authentication
- Master/slave role templates

## Architecture

- **Django** - Web framework
- **Django REST Framework** - API implementation
- **SQLite** - Default database (PostgreSQL supported)
- **Background Worker** - Synchronizes changes to DNS servers
- **Backend API** - Communicates with PowerDNS, Knot DNS, or other servers

## License

GNU General Public License v3.0 or later

(C) 2015-2024 Tomas Hlavacek (tmshlvck@gmail.com)