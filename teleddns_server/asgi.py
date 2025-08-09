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

# Initialize sync thread for production deployment
# This runs after Django is fully initialized
logger = logging.getLogger('manager')

# Use a lock to ensure thread starts only once across multiple workers
_init_lock = threading.Lock()
_initialized = False

def init_sync_thread():
    """Initialize the sync thread once Django is ready"""
    global _initialized

    with _init_lock:
        if _initialized:
            return
        _initialized = True

        try:
            from manager.sync_thread import sync_thread
            if not sync_thread.thread or not sync_thread.thread.is_alive():
                sync_thread.start()
                logger.info("Sync thread initialized for ASGI application")
        except Exception as e:
            logger.error(f"Failed to start sync thread in ASGI: {e}")

# Start the sync thread after a short delay to ensure Django is ready
init_timer = threading.Timer(10.0, init_sync_thread)
init_timer.daemon = True
init_timer.start()
