"""
TeleDDNS Server - Backend Worker Thread
(C) 2015-2024 Tomas Hlavacek (tmshlvck@gmail.com)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

import logging
import threading
import time
from typing import Set

from django.conf import settings
from django.db import transaction
from django.db.models import Q

from .models import (
    Server, Zone,
    ZoneServer
)
from .backend_api import (
    push_server_reload, update_zone,
    DNSServerError
)

logger = logging.getLogger('manager.backend_worker')


class BackendWorkerThread:
    """Background worker thread for synchronizing DNS configurations to backend servers"""

    def __init__(self):
        self.thread = None
        self.stop_event = threading.Event()
        self.interval = getattr(settings, 'SYNC_THREAD_INTERVAL', 60)  # Default 60 seconds

    def start(self):
        """Start the background worker thread"""
        if self.thread and self.thread.is_alive():
            logger.warning("Backend worker thread already running")
            return

        self.stop_event.clear()
        # Use daemon thread for web server, non-daemon for management commands
        import sys
        is_management_command = len(sys.argv) > 1 and sys.argv[0].endswith('manage.py')
        self.thread = threading.Thread(target=self._run, daemon=not is_management_command)
        self.thread.start()
        logger.info(f"Backend worker thread started with interval {self.interval}s")

    def stop(self):
        """Stop the background worker thread"""
        logger.info("Stopping backend worker thread")
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=10)
            logger.info("Backend worker thread stopped")

    def is_running(self):
        """Check if the worker thread is running"""
        return self.thread and self.thread.is_alive()

    def _run(self):
        """Main thread loop"""
        # Initial delay to ensure Django is fully initialized
        initial_delay = 5  # seconds
        logger.info(f"Backend worker waiting {initial_delay}s for Django initialization")
        if self.stop_event.wait(initial_delay):
            return  # Thread was stopped during initial delay

        logger.info("Backend worker starting main loop")
        while not self.stop_event.is_set():
            try:
                self.do_sync()
            except Exception as e:
                logger.exception(f"Unexpected error in backend worker: {e}")

            # Wait for the configured interval or until stop is signaled
            self.stop_event.wait(self.interval)

    def do_sync(self):
        """Perform synchronization work - can be called manually or by the thread"""
        logger.debug("Sync worker started")

        # Process dirty server configurations
        dirty_servers = self._get_dirty_config_servers()
        if dirty_servers:
            logger.info(f"Found {len(dirty_servers)} servers with dirty configurations")
            self._sync_server_configs(dirty_servers)

        # Process zones with dirty content
        dirty_zones = self._get_dirty_content_zones()
        if dirty_zones:
            logger.info(f"Found {len(dirty_zones)} zones with dirty content")
            self._sync_zone_content(dirty_zones)

    def _get_dirty_config_servers(self) -> Set[Server]:
        """Get unique set of servers that need configuration reload"""
        servers = set()

        # Check ZoneServer for dirty configs
        zone_servers = ZoneServer.objects.filter(
            config_dirty=True
        ).select_related('server')

        for zone_server in zone_servers:
            servers.add(zone_server.server)

        return servers

    def _get_dirty_content_zones(self) -> Set[Zone]:
        """Get zones that need content synchronization"""
        # Get zones with dirty content
        dirty_zones = set(Zone.objects.filter(content_dirty=True))

        # Also get zones with dirty content on their master servers
        zone_servers_with_dirty_content = ZoneServer.objects.filter(
            role='master',
            content_dirty=True
        ).select_related('zone')

        for zone_server in zone_servers_with_dirty_content:
            dirty_zones.add(zone_server.zone)

        return dirty_zones



    def _sync_server_configs(self, servers: Set[Server]):
        """Synchronize configurations for dirty servers"""
        for server in servers:
            try:
                logger.info(f"Reloading configuration on server {server.name}")
                push_server_reload(server)

                # Clear dirty flags for this server
                with transaction.atomic():
                    # Clear zone config dirty flags
                    ZoneServer.objects.filter(
                        server=server,
                        config_dirty=True
                    ).update(
                        config_dirty=False,
                        config_dirty_since=None
                    )

                logger.info(f"Successfully reloaded configuration on server {server.name}")

            except DNSServerError as e:
                logger.error(f"Failed to reload configuration on server {server.name}: {e}")
                # Just log the error and continue - will retry on next cycle
            except Exception as e:
                logger.exception(f"Unexpected error reloading server {server.name}: {e}")

    def _sync_zone_content(self, zones: Set[Zone]):
        """Synchronize content for dirty zones"""
        for zone in zones:
            try:
                logger.info(f"Synchronizing zone {zone.origin}")

                success, errors = update_zone(zone)

                if success:
                    # Clear dirty flags
                    with transaction.atomic():
                        Zone.objects.filter(id=zone.id).update(
                            content_dirty=False,
                            content_dirty_since=None
                        )

                    logger.info(f"Successfully synchronized zone {zone.origin}")
                else:
                    logger.error(f"Failed to synchronize zone {zone.origin}: {errors}")
                    # Will retry on next cycle

            except Exception as e:
                logger.exception(f"Unexpected error synchronizing zone {zone.origin}: {e}")




# Global instance
backend_worker = BackendWorkerThread()
