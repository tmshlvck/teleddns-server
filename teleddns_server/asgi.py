"""
ASGI config for teleddns_server project.

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/5.0/howto/deployment/asgi/
"""

import os
import logging
import threading

from django.core.asgi import get_asgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'teleddns_server.settings')

application = get_asgi_application()

# Initialize backend worker thread for production deployment
# This runs after Django is fully initialized
logger = logging.getLogger('manager')

# Use a lock to ensure thread starts only once across multiple workers
_init_lock = threading.Lock()
_initialized = False

def init_backend_worker():
    """Initialize the backend worker thread once Django is ready"""
    global _initialized

    with _init_lock:
        if _initialized:
            return
        _initialized = True

        try:
            from manager.backend_worker import backend_worker
            if not backend_worker.thread or not backend_worker.thread.is_alive():
                backend_worker.start()
                logger.info("Backend worker thread initialized for ASGI application")
        except Exception as e:
            logger.error(f"Failed to start backend worker thread in ASGI: {e}")

# Start the backend worker thread after a short delay to ensure Django is ready
init_timer = threading.Timer(10.0, init_backend_worker)
init_timer.daemon = True
init_timer.start()
