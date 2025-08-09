# Production Deployment Guide

This guide covers deploying TeleDDNS Server in production using either systemd or Podman, with Nginx as a reverse proxy handling SSL termination.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Option 1: Systemd Service Deployment](#option-1-systemd-service-deployment)
3. [Option 2: Podman Container Deployment](#option-2-podman-container-deployment)
4. [Nginx Configuration](#nginx-configuration)
5. [SSL Certificate Setup](#ssl-certificate-setup)
6. [Security Considerations](#security-considerations)
7. [Monitoring and Maintenance](#monitoring-and-maintenance)

## Prerequisites

- Ubuntu 22.04 LTS or similar Linux distribution
- Python 3.12+
- Nginx
- Certbot (for Let's Encrypt certificates)
- Poetry (for systemd deployment)
- Podman (for container deployment)

## Option 1: Systemd Service Deployment

### 1. Install System Dependencies

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Python and dependencies
sudo apt install -y python3.12 python3.12-venv python3.12-dev build-essential nginx certbot python3-certbot-nginx

# Install Poetry
curl -sSL https://install.python-poetry.org | python3 -
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

### 2. Setup Application

```bash
# Create application user
sudo useradd -r -s /bin/bash -d /opt/teleddns teleddns

# Create directories
sudo mkdir -p /opt/teleddns /var/log/teleddns /etc/teleddns
sudo chown -R teleddns:teleddns /opt/teleddns /var/log/teleddns /etc/teleddns

# Clone repository as teleddns user
sudo -u teleddns git clone https://github.com/yourusername/teleddns-server.git /opt/teleddns/app
cd /opt/teleddns/app

# Install dependencies with Poetry
sudo -u teleddns poetry install --only main

# Create environment file
sudo tee /etc/teleddns/env <<EOF
# Django settings
SECRET_KEY="your-production-secret-key-here"
DEBUG=False
ALLOWED_HOSTS=teleddns.example.com,localhost,127.0.0.1
DATABASE_URL=sqlite:////opt/teleddns/data/db.sqlite3

# API settings
API_DISABLE_SESSION_AUTH=True

# Sync thread settings
SYNC_THREAD_INTERVAL=60
SYNC_THREAD_MAX_BACKOFF_SECONDS=86400
SYNC_THREAD_BACKOFF_BASE=2

# DNS settings
DDNS_DEFAULT_TTL=3600
DDNS_RR_TTL=60
EOF

# Set permissions
sudo chmod 600 /etc/teleddns/env
sudo chown teleddns:teleddns /etc/teleddns/env

# Create data directory
sudo mkdir -p /opt/teleddns/data
sudo chown teleddns:teleddns /opt/teleddns/data

# Run initial setup
sudo -u teleddns bash -c 'cd /opt/teleddns/app && poetry run python manage.py migrate'
sudo -u teleddns bash -c 'cd /opt/teleddns/app && poetry run python manage.py collectstatic --noinput'
sudo -u teleddns bash -c 'cd /opt/teleddns/app && poetry run python manage.py createsuperuser'
```

### 3. Create Systemd Service

```bash
sudo tee /etc/systemd/system/teleddns.service <<EOF
[Unit]
Description=TeleDDNS Server
After=network.target

[Service]
Type=exec
User=teleddns
Group=teleddns
WorkingDirectory=/opt/teleddns/app
EnvironmentFile=/etc/teleddns/env
ExecStart=/home/teleddns/.local/bin/poetry run uvicorn teleddns_server.asgi:application --host 127.0.0.1 --port 8000 --workers 4 --log-config /etc/teleddns/logging.json
Restart=always
RestartSec=3

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/teleddns/data /var/log/teleddns

[Install]
WantedBy=multi-user.target
EOF
```

### 4. Create Logging Configuration

```bash
sudo tee /etc/teleddns/logging.json <<EOF
{
  "version": 1,
  "disable_existing_loggers": false,
  "formatters": {
    "default": {
      "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    }
  },
  "handlers": {
    "file": {
      "class": "logging.handlers.RotatingFileHandler",
      "formatter": "default",
      "filename": "/var/log/teleddns/uvicorn.log",
      "maxBytes": 10485760,
      "backupCount": 10
    },
    "console": {
      "class": "logging.StreamHandler",
      "formatter": "default",
      "stream": "ext://sys.stdout"
    }
  },
  "loggers": {
    "uvicorn": {
      "handlers": ["file", "console"],
      "level": "INFO"
    },
    "uvicorn.error": {
      "handlers": ["file", "console"],
      "level": "INFO",
      "propagate": false
    },
    "uvicorn.access": {
      "handlers": ["file", "console"],
      "level": "INFO",
      "propagate": false
    }
  }
}
EOF

sudo chown teleddns:teleddns /etc/teleddns/logging.json
```

### 5. Enable and Start Service

```bash
# Enable and start the service
sudo systemctl daemon-reload
sudo systemctl enable teleddns
sudo systemctl start teleddns

# Check status
sudo systemctl status teleddns
sudo journalctl -u teleddns -f
```

## Option 2: Podman Container Deployment

### 1. Install Podman

```bash
# Install Podman
sudo apt update
sudo apt install -y podman podman-compose

# Enable podman socket for rootless containers
systemctl --user enable --now podman.socket
```

### 2. Create Deployment Directory

```bash
mkdir -p ~/teleddns-deployment
cd ~/teleddns-deployment

# Create docker-compose.yml for podman-compose
cat > docker-compose.yml <<EOF
version: '3.8'

services:
  teleddns:
    image: teleddns-server:latest
    container_name: teleddns-server
    restart: always
    ports:
      - "127.0.0.1:8000:8000"
    volumes:
      - teleddns-data:/data
      - ./env:/app/.env:ro
    environment:
      - DJANGO_SETTINGS_MODULE=teleddns_server.settings
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/api/health/"]
      interval: 30s
      timeout: 3s
      retries: 3
      start_period: 40s

volumes:
  teleddns-data:
    driver: local
EOF

# Create environment file
cat > env <<EOF
SECRET_KEY=your-production-secret-key-here
DEBUG=False
ALLOWED_HOSTS=teleddns.example.com,localhost,127.0.0.1
DATABASE_URL=sqlite:////data/db.sqlite3
API_DISABLE_SESSION_AUTH=True
SYNC_THREAD_INTERVAL=60
SYNC_THREAD_MAX_BACKOFF_SECONDS=86400
SYNC_THREAD_BACKOFF_BASE=2
DDNS_DEFAULT_TTL=3600
DDNS_RR_TTL=60
EOF

chmod 600 env
```

### 3. Build and Run Container

```bash
# Clone repository and build image
git clone https://github.com/yourusername/teleddns-server.git
cd teleddns-server
podman build -t teleddns-server:latest .

# Run with podman-compose
cd ~/teleddns-deployment
podman-compose up -d

# Check logs
podman-compose logs -f

# Create superuser
podman exec -it teleddns-server poetry run python manage.py createsuperuser
```

### 4. Create Systemd Service for Podman

```bash
# Generate systemd service for the container
cd ~/teleddns-deployment
podman generate systemd --new --name teleddns-server > ~/.config/systemd/user/teleddns-container.service

# Enable and start the service
systemctl --user daemon-reload
systemctl --user enable teleddns-container
systemctl --user start teleddns-container

# Enable lingering to keep user services running
sudo loginctl enable-linger $USER
```

## Nginx Configuration

### 1. Create Nginx Site Configuration

```bash
sudo tee /etc/nginx/sites-available/teleddns <<'EOF'
# Redirect HTTP to HTTPS
server {
    listen 80;
    listen [::]:80;
    server_name teleddns.example.com;
    
    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }
    
    location / {
        return 301 https://$server_name$request_uri;
    }
}

# HTTPS Server
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name teleddns.example.com;

    # SSL certificates (will be configured by certbot)
    ssl_certificate /etc/letsencrypt/live/teleddns.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/teleddns.example.com/privkey.pem;
    
    # SSL settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    ssl_stapling on;
    ssl_stapling_verify on;

    # Security headers
    add_header Strict-Transport-Security "max-age=63072000" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # Logging
    access_log /var/log/nginx/teleddns.access.log;
    error_log /var/log/nginx/teleddns.error.log;

    # API endpoints
    location /api/ {
        proxy_pass http://127.0.0.1:8000/api/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    # DDNS update endpoints
    location /update/ {
        proxy_pass http://127.0.0.1:8000/update/;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /ddns/ {
        proxy_pass http://127.0.0.1:8000/ddns/;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Admin interface
    location /admin/ {
        proxy_pass http://127.0.0.1:8000/admin/;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Static files
    location /static/ {
        alias /opt/teleddns/app/staticfiles/;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }

    # Block access to sensitive files
    location ~ /\. {
        deny all;
    }

    location ~ \.(env|sqlite3|db)$ {
        deny all;
    }

    # Root location
    location / {
        # Redirect to API docs or return 404
        return 301 /api/docs/;
    }
}
EOF

# Enable the site
sudo ln -s /etc/nginx/sites-available/teleddns /etc/nginx/sites-enabled/
sudo nginx -t
```

## SSL Certificate Setup

### 1. Obtain Let's Encrypt Certificate

```bash
# Install certbot
sudo apt install -y certbot python3-certbot-nginx

# Obtain certificate
sudo certbot --nginx -d teleddns.example.com --non-interactive --agree-tos --email admin@example.com

# The certificate will be automatically configured in Nginx
```

### 2. Setup Automatic Renewal

```bash
# Test renewal
sudo certbot renew --dry-run

# Certbot automatically creates a systemd timer for renewal
sudo systemctl status certbot.timer
```

## Security Considerations

### 1. Firewall Configuration

```bash
# Install ufw if not present
sudo apt install -y ufw

# Configure firewall
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow http
sudo ufw allow https
sudo ufw enable
```

### 2. Fail2ban Configuration

```bash
# Install fail2ban
sudo apt install -y fail2ban

# Create jail for TeleDDNS
sudo tee /etc/fail2ban/jail.d/teleddns.conf <<EOF
[teleddns-api]
enabled = true
port = http,https
filter = teleddns-api
logpath = /var/log/nginx/teleddns.access.log
maxretry = 10
findtime = 600
bantime = 3600

[teleddns-ddns]
enabled = true
port = http,https
filter = teleddns-ddns
logpath = /var/log/nginx/teleddns.access.log
maxretry = 5
findtime = 300
bantime = 7200
EOF

# Create filters
sudo tee /etc/fail2ban/filter.d/teleddns-api.conf <<EOF
[Definition]
failregex = ^<HOST> .* "(GET|POST) /api/.* HTTP/.*" 401
ignoreregex =
EOF

sudo tee /etc/fail2ban/filter.d/teleddns-ddns.conf <<EOF
[Definition]
failregex = ^<HOST> .* "(GET|POST) /(update|ddns)/.* HTTP/.*" 401
ignoreregex =
EOF

# Restart fail2ban
sudo systemctl restart fail2ban
```

### 3. Database Backup

```bash
# Create backup script
sudo tee /opt/teleddns/backup.sh <<'EOF'
#!/bin/bash
BACKUP_DIR="/opt/teleddns/backups"
DB_PATH="/opt/teleddns/data/db.sqlite3"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

mkdir -p $BACKUP_DIR

# Create backup
sqlite3 $DB_PATH ".backup '$BACKUP_DIR/teleddns_$TIMESTAMP.db'"

# Keep only last 30 days of backups
find $BACKUP_DIR -name "teleddns_*.db" -mtime +30 -delete

# Compress backups older than 7 days
find $BACKUP_DIR -name "teleddns_*.db" -mtime +7 -exec gzip {} \;
EOF

sudo chmod +x /opt/teleddns/backup.sh
sudo chown teleddns:teleddns /opt/teleddns/backup.sh

# Add to crontab
echo "0 2 * * * /opt/teleddns/backup.sh" | sudo -u teleddns crontab -
```

## Monitoring and Maintenance

### 1. Health Monitoring

```bash
# Create monitoring script
sudo tee /opt/teleddns/health-check.sh <<'EOF'
#!/bin/bash
HEALTH_URL="https://teleddns.example.com/api/health/"
SYNC_URL="https://teleddns.example.com/api/sync-status/"
TOKEN="your-monitoring-token"

# Check health endpoint
if ! curl -sf $HEALTH_URL > /dev/null; then
    echo "Health check failed" | mail -s "TeleDDNS Health Alert" admin@example.com
fi

# Check sync status
SYNC_STATUS=$(curl -sf -H "Authorization: Token $TOKEN" $SYNC_URL)
FAILURES=$(echo $SYNC_STATUS | jq -r '.total_failures')

if [ "$FAILURES" -gt "10" ]; then
    echo "High sync failure count: $FAILURES" | mail -s "TeleDDNS Sync Alert" admin@example.com
fi
EOF

sudo chmod +x /opt/teleddns/health-check.sh
sudo chown teleddns:teleddns /opt/teleddns/health-check.sh

# Add to crontab
echo "*/5 * * * * /opt/teleddns/health-check.sh" | sudo -u teleddns crontab -
```

### 2. Log Rotation

```bash
# Create logrotate configuration
sudo tee /etc/logrotate.d/teleddns <<EOF
/var/log/teleddns/*.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    create 0640 teleddns teleddns
    sharedscripts
    postrotate
        systemctl reload teleddns >/dev/null 2>&1 || true
    endscript
}

/var/log/nginx/teleddns.*.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    create 0640 www-data adm
    sharedscripts
    postrotate
        [ -f /var/run/nginx.pid ] && kill -USR1 $(cat /var/run/nginx.pid)
    endscript
}
EOF
```

### 3. Performance Tuning

```bash
# Optimize Nginx
sudo tee -a /etc/nginx/nginx.conf <<EOF

# Performance optimizations
worker_processes auto;
worker_rlimit_nofile 65535;

events {
    worker_connections 4096;
    use epoll;
    multi_accept on;
}

http {
    # Enable compression
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css text/xml text/javascript application/json application/javascript application/xml+rss application/rss+xml application/atom+xml image/svg+xml;
    
    # Connection settings
    keepalive_timeout 65;
    keepalive_requests 100;
    
    # Buffer settings
    client_body_buffer_size 128k;
    client_max_body_size 10m;
    client_header_buffer_size 1k;
    large_client_header_buffers 4 16k;
    output_buffers 1 32k;
    postpone_output 1460;
    
    # Cache settings
    open_file_cache max=1000 inactive=20s;
    open_file_cache_valid 30s;
    open_file_cache_min_uses 2;
    open_file_cache_errors on;
}
EOF

# Restart Nginx
sudo nginx -t && sudo systemctl restart nginx
```

## Troubleshooting

### Common Issues

1. **Service won't start**
   ```bash
   # Check logs
   sudo journalctl -u teleddns -n 100
   # Check permissions
   ls -la /opt/teleddns/data/
   ```

2. **Database locked errors**
   ```bash
   # Ensure only one instance is running
   sudo systemctl stop teleddns
   sudo lsof /opt/teleddns/data/db.sqlite3
   sudo systemctl start teleddns
   ```

3. **Nginx 502 Bad Gateway**
   ```bash
   # Check if application is running
   sudo systemctl status teleddns
   curl http://127.0.0.1:8000/api/health/
   ```

4. **High memory usage**
   ```bash
   # Reduce uvicorn workers
   # Edit systemd service or docker-compose.yml
   # Change --workers 4 to --workers 2
   ```

## Maintenance Commands

```bash
# View logs
sudo journalctl -u teleddns -f
sudo tail -f /var/log/teleddns/uvicorn.log
sudo tail -f /var/log/nginx/teleddns.error.log

# Restart services
sudo systemctl restart teleddns
sudo systemctl restart nginx

# Database maintenance
sudo -u teleddns sqlite3 /opt/teleddns/data/db.sqlite3 "VACUUM;"
sudo -u teleddns sqlite3 /opt/teleddns/data/db.sqlite3 "ANALYZE;"

# Update application
cd /opt/teleddns/app
sudo -u teleddns git pull
sudo -u teleddns poetry install --only main
sudo -u teleddns poetry run python manage.py migrate
sudo -u teleddns poetry run python manage.py collectstatic --noinput
sudo systemctl restart teleddns
```
