# TeleDDNS Server

Simple DDNS API server with Django Admin for management.

Features:
* The best client for this server is [TeleDDNS](https://github.com/tmshlvck/teleddns), although DDNS over HTTP(S) protocol is implemented to largest extent I could manage and I am committed to support any other cliets that may have issues sending updates to this API.
* This server works with one or more Knot DNS 3.x servers with the [TeleAPI](https://github.com/tmshlvck/teleapi) connector.
* There is a Starlette Admin webapp at `/admin` that can be used to manually mange DNS records and trigger Knot config and zone synchronization.

## Deployment

Install & configure Knot:
```
apt-get install knot
```

Deploy TeleAPI:
```
git clone https://github.com/tmshlvck/teleapi.git
cd teleapi
cargo build --release
sudo cp target/release/teleapi /usr/local/bin/
cat <<EOF >etc/teleapi.yaml
---
listen: 127.0.0.1
listen_port: 8586
apikey: "abcd1234"
commands:
- endpoint: "/zonewrite"
  write_file: "/var/lib/knot/{zonename}.zone"
  user: knot
  group: knot
  mode: 0o644
- endpoint: "/configwrite"
  write_file: "/etc/knot/knot-ddnsm-test.conf"
  user: knot
  group: knot
  mode: 0o644
- endpoint: "/zonereload"
  shell: "/usr/sbin/knotc zone-reload {zonename}"
- endpoint: "/zonecheck"
  shell: "/usr/bin/kzonecheck /var/lib/knot/{zonename}.zone"
- endpoint: "/configreload"
  shell: "/usr/sbin/knotc reload"
EOF
sudo cp teleapi.service /etc/systemd/system/teleapi.service
sudo systemctl daemon-reload
sudo systemctl enable teleapi
sudo systemctl restart teleapi
```

To build, deploy, install and inspect logs of the Podman container run
the following as `root`:

### Option 1: Host Network (Recommended)
```bash
mkdir /srv/teleddns-server
podman build -f Dockerfile -t teleddns-server:latest .
podman run -d \
  --name teleddns-server \
  --network host \
  -v /srv/teleddns-server:/data \
  -e SECRET_KEY="your-secure-secret-key-here" \
  -e ALLOWED_HOSTS="your-domain.com,localhost" \
  -e ADMIN_PASSWORD="your-admin-password" \
  -e LISTEN="127.0.0.1:8085" \
  teleddns-server:latest
```

### Option 2: Port Mapping
```bash
mkdir /srv/teleddns-server
podman build -f Dockerfile -t teleddns-server:latest .
podman run -d \
  --name teleddns-server \
  -p 8085:8000 \
  -v /srv/teleddns-server:/data \
  -e SECRET_KEY="your-secure-secret-key-here" \
  -e ALLOWED_HOSTS="your-domain.com,localhost" \
  -e ADMIN_PASSWORD="your-admin-password" \
  -e LISTEN="0.0.0.0:8000" \
  teleddns-server:latest
```

### Standalone (No Container)
```bash
cd /path/to/teleddns-server
LISTEN="127.0.0.1:8085" ADMIN_PASSWORD="admin123" ./start-teleddns.sh
```

Setup systemd service:
```bash
podman logs teleddns-server
podman generate systemd teleddns-server >/etc/systemd/system/teleddns-server.service
systemctl daemon-reload
systemctl enable teleddns-server
```

The server will be available at the configured LISTEN address:
- Django Admin: `/admin/`
- DDNS API: `/ddns/update` or `/update`
- Health Check: `/healthcheck/`

Create NGINX proxy and use Certbot to create SSL certificate for the domain. The DDNS update protocol uses Basic Authentication that transmits passwords as plain-text and therefore it would be absolutely insecure and prone to all kinds of MITM attacks without HTTPS.

Add proxy section to your NGINX site (i.e. `/etc/nginx/sites-enabled/default`):
```
server {
...
  location /ddns/ {
    proxy_pass http://localhost:8085/;
    proxy_http_version 1.1;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header Host $http_host;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header Upgrade $http_upgrade;
    proxy_redirect off;
    proxy_buffering off;
  }
...
}
```

Install and configure Knot: `apt-get install knot` and configure `/etc/knot/knot.conf`:
```
server:
    rundir: "/run/knot"
    user: knot:knot
    listen: [0.0.0.0@53, ::@53]

log:
  - target: syslog
    any: info

database:
    storage: "/var/lib/knot"

template:
  - id: t_master
    storage: "/var/lib/knot"
  - id: t_slave
    storage: "/var/lib/knot"

include: knot-ddnsm.conf
```

## Development

### Setup

After cloning the repository, set up the Django development environment:

```bash
# Install dependencies
poetry install

# Create and apply database migrations
poetry run python manage.py makemigrations
poetry run python manage.py migrate

# Create superuser for admin access
poetry run python manage.py createsuperuser

# Start development server
poetry run python manage.py runserver
```

The server will be available at:
- `http://127.0.0.1:8000/` - API endpoints
- `http://127.0.0.1:8000/admin/` - Django Admin interface

### Running Tests

The project includes a comprehensive test suite using pytest with Django fixtures.

#### Basic Test Commands

```bash
# Run all tests
poetry run pytest

# Run tests with verbose output
poetry run pytest -v

# Run only unit tests (fast)
poetry run pytest -m unit

# Run only integration tests
poetry run pytest -m integration

# Run specific test file
poetry run pytest tests/dns_manager/test_models.py

# Run with coverage report
poetry run pytest --cov=dns_manager

# Keep test database for inspection (reuse-db)
poetry run pytest --reuse-db -v
```

#### Test Structure

- `tests/conftest.py` - Global fixtures and test configuration
- `tests/dns_manager/test_models.py` - Comprehensive model tests
- Fixtures create realistic test data: `user1`, `group1`, `zone1.tld`, and full DNS records

#### Creating Synthetic Test Data

You can create comprehensive test data in your development database on demand:

```bash
# Create default test data (user1/testpass123, zone1.tld)
poetry run python manage.py create_test_data

# Create test data with custom domain
poetry run python manage.py create_test_data --zone example.org

# Create test data with custom user credentials
poetry run python manage.py create_test_data --user testuser --password mypass123

# Clear existing test data before creating new
poetry run python manage.py create_test_data --clear

# Full example with all options
poetry run python manage.py create_test_data --clear --zone mytest.com --user admin --password admin123
```

The synthetic data includes:
- **Users**: `user1`, `user2` with authentication
- **Groups**: `group1` with user memberships
- **Servers**: DNS server with TeleAPI configuration
- **Zones**: Complete zone with SOA record
- **DNS Records**: All supported types (A, AAAA, NS, PTR, CNAME, TXT, CAA, MX, SRV, SSHFP, TLSA, DNSKEY, DS, NAPTR)

After creating test data, you can:
1. Login to Django Admin at `http://127.0.0.1:8000/admin/`
2. Explore the API endpoints
3. Test DDNS functionality
4. View the complete zone file output

#### Keeping Test Database

Use `--reuse-db` with pytest to keep the test database after tests run. This allows you to:

```bash
# Run tests and keep the database
poetry run pytest --reuse-db -v

# Then explore the database manually
poetry run python manage.py shell
poetry run python manage.py dbshell
```
