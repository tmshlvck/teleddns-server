#!/bin/bash
set -e

# Environment defaults
LISTEN=${LISTEN:-"127.0.0.1:8000"}
PYTHON_CMD="poetry run python"

echo "Starting TeleDDNS Server..."

# Run migrations
echo "Running migrations..."
$PYTHON_CMD manage.py migrate

# Setup admin user if password provided
if [ -n "$ADMIN_PASSWORD" ]; then
    echo "Setting up admin user..."
    $PYTHON_CMD manage.py shell -c "
from django.contrib.auth import get_user_model
User = get_user_model()
if not User.objects.filter(username='admin').exists():
    User.objects.create_superuser('admin', 'admin@example.com', '$ADMIN_PASSWORD')
    print('Admin user created')
else:
    admin = User.objects.get(username='admin')
    admin.set_password('$ADMIN_PASSWORD')
    admin.save()
    print('Admin password updated')
"
fi

# Start server
echo "Starting server on $LISTEN"
exec $PYTHON_CMD manage.py runserver "$LISTEN"