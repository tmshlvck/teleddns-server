"""
Background synchronization service for TeleDDNS Server.

Handles periodic and triggered synchronization of dirty zones and server configs
to backend DNS servers.
"""
import logging
import threading
import time
from datetime import datetime, timezone
from typing import Optional
from django.conf import settings

from .models import Server, MasterZone
from .backend import update_zone, update_config

logger = logging.getLogger(__name__)


def generate_bind_zone_content(zone) -> str:
    """
    Generate complete BIND zone file content.
    
    Args:
        zone: MasterZone instance
        
    Returns:
        Complete BIND zone file content as string
    """
    from .models import DNS_RECORD_CLASSES
    
    # Start with zone header (SOA record)
    zone_lines = [zone.format_bind_zone_header()]
    
    # Add all records for this zone using all defined DNS record types
    for record_class in DNS_RECORD_CLASSES:
        records = record_class.objects.filter(zone=zone).order_by('label')
        for record in records:
            zone_lines.append(record.format_bind_zone())
    
    return '\n'.join(zone_lines) + '\n'


def generate_knot_config_content(server) -> str:
    """
    Generate Knot DNS configuration content.
    
    Args:
        server: Server instance
        
    Returns:
        Knot DNS configuration content as string
    """
    config_lines = []
    
    # Add master zones
    master_zones = server.master_zones.all()
    for zone in master_zones:
        zone_name = zone.origin.rstrip('.')
        config_lines.append(f"zone:")
        config_lines.append(f"- domain: {zone.origin}")
        config_lines.append(f"  template: {server.master_template}")
        config_lines.append(f"  file: {zone_name}.zone")
    
    # Add slave zones
    slave_zones = server.slave_zones.all()
    for zone in slave_zones:
        zone_name = zone.origin.rstrip('.')
        config_lines.append(f"zone:")
        config_lines.append(f"- domain: {zone.origin}")
        config_lines.append(f"  template: {server.slave_template}")
        config_lines.append(f"  file: {zone_name}.zone")
    
    return '\n'.join(config_lines) + '\n' if config_lines else '\n'

# Global sync service instance
_sync_service: Optional['BackgroundSyncService'] = None


class BackgroundSyncService:
    """Background service for syncing dirty zones and configs to backend servers."""
    
    def __init__(self, sync_period: int = 300, sync_delay: int = 10):
        """
        Initialize background sync service.
        
        Args:
            sync_period: Regular sync interval in seconds (default: 300s)
            sync_delay: Delay before triggered sync in seconds (default: 10s)
        """
        self.sync_period = sync_period
        self.sync_delay = sync_delay
        self.running = False
        self.thread: Optional[threading.Thread] = None
        self.event = threading.Event()
        
    def start(self):
        """Start the background sync service."""
        if self.running:
            logger.warning("Background sync service already running")
            return
            
        self.running = True
        self.thread = threading.Thread(target=self._sync_loop, daemon=True)
        self.thread.start()
        logger.info(f"Background sync service started (period={self.sync_period}s, delay={self.sync_delay}s)")
        
    def stop(self):
        """Stop the background sync service."""
        if not self.running:
            return
            
        self.running = False
        self.event.set()  # Wake up the thread
        if self.thread:
            self.thread.join(timeout=5)
        logger.info("Background sync service stopped")
        
    def trigger_sync(self):
        """Trigger immediate sync (with delay)."""
        if self.running:
            self.event.set()
            logger.debug("Background sync triggered")
        else:
            logger.warning("Background sync service not running - cannot trigger")
            
    def _sync_loop(self):
        """Main sync loop running in background thread."""
        logger.debug("Background sync loop started")
        
        while self.running:
            try:
                # Wait for either timeout or trigger event
                triggered = self.event.wait(timeout=self.sync_period)
                
                if not self.running:
                    break
                    
                if triggered:
                    # Clear event and wait for additional changes to batch
                    self.event.clear()
                    logger.debug(f"Sync triggered - waiting {self.sync_delay}s for batching")
                    time.sleep(self.sync_delay)
                    
                if not self.running:
                    break
                    
                # Perform sync
                self._do_sync_iteration()
                
            except Exception as e:
                logger.error(f"Error in background sync loop: {e}", exc_info=True)
                # Continue running even if there's an error
                time.sleep(10)  # Short delay before retrying
                
        logger.debug("Background sync loop finished")
        
    def _do_sync_iteration(self):
        """Perform one sync iteration - sync dirty servers and zones."""
        logger.debug("Background sync iteration starting")
        
        try:
            # Sync servers with dirty configs
            dirty_servers = Server.objects.filter(config_dirty=True, is_active=True)
            
            for server in dirty_servers:
                try:
                    logger.info(f"Syncing config for server {server.name} (id={server.id})")
                    
                    # Generate config content
                    config_content = generate_knot_config_content(server)
                    
                    # Send config to backend
                    update_config(config_content, server.api_url, server.api_key)
                    
                    # Clear dirty flag and update timestamp
                    server.config_dirty = False
                    server.last_config_sync = datetime.now(timezone.utc)
                    server.last_update_metadata = 'Background config sync'
                    server.save(update_fields=['config_dirty', 'last_config_sync', 'last_update_metadata'])
                    
                    logger.info(f"Successfully synced config for server {server.name}")
                    
                except Exception as e:
                    logger.error(f"Failed to sync config for server {server.name}: {e}", exc_info=True)
            
            # Sync zones with dirty content
            dirty_zones = MasterZone.objects.filter(
                content_dirty=True,
                master_server__is_active=True
            ).select_related('master_server')
            
            for zone in dirty_zones:
                try:
                    logger.info(f"Syncing content for zone {zone.origin} (id={zone.id})")
                    
                    # Generate zone content
                    zone_content = generate_bind_zone_content(zone)
                    
                    # Send zone to backend
                    zone_name = zone.origin.rstrip('.')
                    update_zone(
                        zone_name,
                        zone_content,
                        zone.master_server.api_url,
                        zone.master_server.api_key
                    )
                    
                    # Clear dirty flag and update timestamp
                    zone.content_dirty = False
                    zone.last_content_sync = datetime.now(timezone.utc)
                    zone.last_update_metadata = 'Background content sync'
                    zone.save(update_fields=['content_dirty', 'last_content_sync', 'last_update_metadata'])
                    
                    logger.info(f"Successfully synced content for zone {zone.origin}")
                    
                except Exception as e:
                    logger.error(f"Failed to sync content for zone {zone.origin}: {e}", exc_info=True)
                    
        except Exception as e:
            logger.error(f"Error in sync iteration: {e}", exc_info=True)
            
        logger.debug("Background sync iteration finished")


def get_sync_service() -> BackgroundSyncService:
    """Get the global sync service instance."""
    global _sync_service
    if _sync_service is None:
        # Get sync settings from Django settings
        sync_period = getattr(settings, 'BACKEND_SYNC_PERIOD', 300)
        sync_delay = getattr(settings, 'BACKEND_SYNC_DELAY', 10)
        _sync_service = BackgroundSyncService(sync_period, sync_delay)
    return _sync_service


def start_background_sync():
    """Start the background sync service."""
    sync_service = get_sync_service()
    sync_service.start()


def stop_background_sync():
    """Stop the background sync service."""
    global _sync_service
    if _sync_service:
        _sync_service.stop()


def trigger_background_sync():
    """Trigger immediate background sync."""
    sync_service = get_sync_service()
    sync_service.trigger_sync()