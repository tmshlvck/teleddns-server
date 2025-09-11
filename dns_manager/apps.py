"""
Django app configuration for dns_manager.

Handles app initialization including background sync service startup.
"""
import logging
from django.apps import AppConfig
from django.conf import settings

logger = logging.getLogger(__name__)


class DnsManagerConfig(AppConfig):
    """Django app configuration for DNS Manager."""
    
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'dns_manager'
    verbose_name = 'DNS Manager'
    
    def ready(self):
        """Called when Django finishes loading the app."""
        # Only start sync service if not disabled and not in testing
        disable_backend = getattr(settings, 'DISABLE_BACKEND_SYNC', False)
        is_testing = getattr(settings, 'TESTING', False)
        
        if not disable_backend and not is_testing:
            try:
                from .sync import start_background_sync
                start_background_sync()
                logger.info("Background sync service started during app initialization")
            except Exception as e:
                logger.error(f"Failed to start background sync service: {e}")
        else:
            logger.info("Background sync service disabled")
