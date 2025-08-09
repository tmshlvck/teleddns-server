# TeleDDNS Server - Production Dockerfile with Poetry
FROM python:3.12-slim

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Poetry
ENV POETRY_VERSION=1.7.1 \
    POETRY_HOME="/opt/poetry" \
    POETRY_VIRTUALENVS_CREATE=false \
    POETRY_NO_INTERACTION=1

RUN curl -sSL https://install.python-poetry.org | python3 - --version $POETRY_VERSION
ENV PATH="$POETRY_HOME/bin:$PATH"

# Create non-root user
RUN groupadd -r teleddns && useradd -r -g teleddns teleddns

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DJANGO_SETTINGS_MODULE=teleddns_server.settings

# Create application directories
RUN mkdir -p /app /data && \
    chown -R teleddns:teleddns /app /data

# Set working directory
WORKDIR /app

# Copy dependency files first for better caching
COPY pyproject.toml poetry.lock ./

# Install dependencies as root (needed for system packages)
RUN poetry install --no-root --only main

# Copy application code
COPY --chown=teleddns:teleddns . .

# Install the application
RUN poetry install --only-root

# Switch to non-root user
USER teleddns

# Create volume for persistent data
VOLUME ["/data"]

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8000/api/health/ || exit 1

# Run migrations and start uvicorn
CMD ["sh", "-c", "poetry run python manage.py migrate --noinput && poetry run python manage.py collectstatic --noinput && poetry run uvicorn teleddns_server.asgi:application --host 0.0.0.0 --port 8000 --workers 4"]
