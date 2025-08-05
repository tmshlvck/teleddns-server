# TeleDDNS Server - Simplified Dockerfile
FROM python:3.12-slim

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r teleddns && useradd -r -g teleddns teleddns

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DJANGO_SETTINGS_MODULE=teleddns_server.settings \
    PATH="/home/teleddns/.local/bin:$PATH"

# Create application directories
RUN mkdir -p /app /data && \
    chown -R teleddns:teleddns /app /data

# Set working directory
WORKDIR /app

# Switch to non-root user
USER teleddns

# Copy requirements first for better caching
COPY --chown=teleddns:teleddns requirements.txt ./
RUN pip install --user --no-cache-dir -r requirements.txt

# Copy application code
COPY --chown=teleddns:teleddns . .

# Create volume for SQLite database
VOLUME ["/data"]

# Expose port
EXPOSE 8000

# Run migrations and start uvicorn
CMD ["sh", "-c", "python manage.py migrate --noinput && python manage.py collectstatic --noinput && uvicorn teleddns_server.asgi:application --host 0.0.0.0 --port 8000"]
