# Test configuration for pytest

import os
import sys
from unittest.mock import patch

# Set environment variables for testing before importing teleddns_server
os.environ.setdefault('ADMIN_PASSWORD', 'admin123')
os.environ.setdefault('SESSION_SECRET', 'test-secret-key-for-testing')
os.environ.setdefault('DB_URL', 'sqlite://')  # In-memory database
os.environ.setdefault('DISABLE_BACKEND_LOOP', 'true')

# Mock sys.argv to prevent CLI parsing
original_argv = sys.argv.copy()
sys.argv = ['pytest']

try:
    # Now import teleddns_server modules
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
finally:
    # Restore original argv after imports
    pass  # We'll restore it after all imports are done