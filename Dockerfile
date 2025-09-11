FROM python:3.12-slim
VOLUME /data

ARG POETRY_NO_INTERACTION=1
ARG POETRY_VIRTUALENVS_IN_PROJECT=1
ARG POETRY_VIRTUALENVS_CREATE=1
ARG POETRY_CACHE_DIR=/tmp/poetry_cache

# Django environment variables
ENV SECRET_KEY="django-production-change-me-secret-key-12345"
ENV DEBUG="False"
ENV ALLOWED_HOSTS="*"
ENV DJANGO_SETTINGS_MODULE="teleddns_server.settings.production"
ENV DJANGO_LOG_LEVEL="INFO"
ENV LISTEN="0.0.0.0:8000"
ENV DATABASE_PATH="/data/teleddns.sqlite"
ENV CONTAINER="true"

# TeleDDNS Backend Sync Settings
ENV BACKEND_SYNC_PERIOD="300"
ENV BACKEND_SYNC_DELAY="10"
ENV DISABLE_BACKEND_SYNC="False"

# CORS settings for API access
ENV CORS_ALLOWED_ORIGINS="http://localhost:3000"

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y python3-poetry && rm -rf /var/lib/apt/lists/*

# Copy dependency files and README (needed for poetry install)
COPY pyproject.toml poetry.lock* README.md ./

# Install Python dependencies (no-root since this is a Django app, not a package)
RUN poetry lock && poetry install --only=main --no-root && rm -rf $POETRY_CACHE_DIR

# Copy Django project files
COPY dns_manager/ ./dns_manager/
COPY ddns/ ./ddns/
COPY restapi/ ./restapi/
COPY teleddns_server/ ./teleddns_server/
COPY manage.py ./
COPY start-teleddns.sh ./

# Create necessary directories and setup script
RUN mkdir -p /data && chmod +x start-teleddns.sh

# Run Django setup commands
RUN poetry run python manage.py collectstatic --noinput || true

# Extract port from LISTEN for EXPOSE
RUN echo $LISTEN | cut -d: -f2 > /tmp/port
EXPOSE 8000

CMD ["./start-teleddns.sh"]
