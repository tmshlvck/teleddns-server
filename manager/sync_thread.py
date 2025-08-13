"""
TeleDDNS Server - Background Synchronization Thread
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
from datetime import datetime, timedelta
from typing import Dict, Set, Tuple
from collections import defaultdict

from django.conf import settings
from django.db import models, transaction
from django.db.models import Q

from .models import (
    Server, Zone, SlaveOnlyZone,
    ZoneServerStatus, SlaveOnlyZoneServerStatus
)
from .services import (
    push_server_reload, update_zone, update_slave_only_zone,
    DNSServerError
)

logger = logging.getLogger('manager.sync_thread')


class SyncBackgroundThread:
    """Background thread for synchronizing DNS configurations and zones"""

    def __init__(self):
        self.thread = None
        self.stop_event = threading.Event()
        self.interval = getattr(settings, 'SYNC_THREAD_INTERVAL', 60)  # Default 60 seconds
        self.max_backoff_seconds = getattr(settings, 'SYNC_THREAD_MAX_BACKOFF_SECONDS', 86400)  # Default 24 hours
        self.backoff_base = getattr(settings, 'SYNC_THREAD_BACKOFF_BASE', 2)

        # Local ephemeral failure tracking
        # Format: {(object_type, object_id, server_id): failure_count}
        self.failure_counts: Dict[Tuple[str, int, int], int] = defaultdict(int)
        self.last_attempt_time: Dict[Tuple[str, int, int], datetime] = {}

    def start(self):
        """Start the background thread"""
        if self.thread and self.thread.is_alive():
            logger.warning("Sync thread already running")
            return

        self.stop_event.clear()
        # Use daemon thread for web server, non-daemon for management commands
        import sys
        is_management_command = len(sys.argv) > 1 and sys.argv[0].endswith('manage.py')
        self.thread = threading.Thread(target=self._run, daemon=not is_management_command)
        self.thread.start()
        logger.info(f"Sync background thread started with interval {self.interval}s")

    def stop(self):
        """Stop the background thread"""
        logger.info("Stopping sync background thread")
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=10)
            logger.info("Sync background thread stopped")

    def _run(self):
        """Main thread loop"""
        # Initial delay to ensure Django is fully initialized
        initial_delay = 5  # seconds
        logger.info(f"Sync thread waiting {initial_delay}s for Django initialization")
        if self.stop_event.wait(initial_delay):
            return  # Thread was stopped during initial delay

        logger.info("Sync thread starting main loop")
        while not self.stop_event.is_set():
            try:
                self._sync_cycle()
            except Exception as e:
                logger.exception(f"Unexpected error in sync cycle: {e}")

            # Wait for the configured interval or until stop is signaled
            self.stop_event.wait(self.interval)

    def _sync_cycle(self):
        """Perform one synchronization cycle"""
        logger.debug("Starting sync cycle")

        # Process dirty configurations
        dirty_servers = self._get_dirty_config_servers()
        if dirty_servers:
            logger.info(f"Found {len(dirty_servers)} servers with dirty configurations")
            self._sync_server_configs(dirty_servers)

        # Process zones with dirty content
        dirty_zones = self._get_dirty_content_zones()
        if dirty_zones:
            logger.info(f"Found {len(dirty_zones)} zones with dirty content")
            self._sync_zone_content(dirty_zones)

        # Process slave-only zones with dirty configurations
        dirty_slave_zones = self._get_dirty_slave_only_zones()
        if dirty_slave_zones:
            logger.info(f"Found {len(dirty_slave_zones)} slave-only zones with dirty configurations")
            self._sync_slave_only_zones(dirty_slave_zones)

    def _get_dirty_config_servers(self) -> Set[Server]:
        """Get unique set of servers that need configuration reload"""
        servers = set()

        # Check ZoneServerStatus for dirty configs
        zone_statuses = ZoneServerStatus.objects.filter(
            config_dirty=True
        ).select_related('server', 'zone')

        for status in zone_statuses:
            if self._should_retry(('zone_config', status.zone.id, status.server.id)):
                servers.add(status.server)

        # Check SlaveOnlyZoneServerStatus for dirty configs
        slave_statuses = SlaveOnlyZoneServerStatus.objects.filter(
            config_dirty=True
        ).select_related('server', 'zone')

        for status in slave_statuses:
            if self._should_retry(('slave_config', status.zone.id, status.server.id)):
                servers.add(status.server)

        return servers

    def _get_dirty_content_zones(self) -> Set[Zone]:
        """Get zones that need content synchronization"""
        zones = set()

        # Get zones with dirty content or master config
        dirty_zones = Zone.objects.filter(
            Q(content_dirty=True) | Q(master_config_dirty=True)
        ).select_related('master_server')

        for zone in dirty_zones:
            if self._should_retry(('zone_content', zone.id, zone.master_server.id)):
                zones.add(zone)

        return zones

    def _get_dirty_slave_only_zones(self) -> Set[SlaveOnlyZone]:
        """Get slave-only zones that need configuration synchronization"""
        zones = set()

        # Find slave-only zones with dirty servers
        dirty_statuses = SlaveOnlyZoneServerStatus.objects.filter(
            config_dirty=True
        ).select_related('zone').prefetch_related('zone__slave_servers')

        # Get unique zones
        for status in dirty_statuses:
            # Use a composite key to check retry status for each server
            if self._should_retry(('slave_zone', status.zone.id, status.server.id)):
                zones.add(status.zone)

        return zones

    def _should_retry(self, key: Tuple[str, int, int]) -> bool:
        """Check if we should retry based on failure count and backoff"""
        failure_count = self.failure_counts[key]

        # If no failures, always retry
        if failure_count == 0:
            return True

        # Check backoff time
        last_attempt = self.last_attempt_time.get(key)
        if last_attempt:
            # Calculate backoff with exponential increase up to max_backoff_seconds
            backoff_seconds = min(
                self.backoff_base ** failure_count,
                self.max_backoff_seconds
            )
            next_attempt = last_attempt + timedelta(seconds=backoff_seconds)
            if datetime.now() < next_attempt:
                return False

        return True

    def _sync_server_configs(self, servers: Set[Server]):
        """Synchronize configurations for dirty servers"""
        for server in servers:
            try:
                logger.info(f"Reloading configuration on server {server.name}")
                push_server_reload(server)

                # Clear dirty flags for this server
                with transaction.atomic():
                    # Clear zone config dirty flags
                    ZoneServerStatus.objects.filter(
                        server=server,
                        config_dirty=True
                    ).update(
                        config_dirty=False,
                        config_dirty_since=None
                    )

                    # Clear slave zone config dirty flags
                    SlaveOnlyZoneServerStatus.objects.filter(
                        server=server,
                        config_dirty=True
                    ).update(
                        config_dirty=False,
                        config_dirty_since=None
                    )

                # Reset failure tracking for all zones on this server
                keys_to_reset = []
                for key in self.failure_counts:
                    if key[2] == server.id and key[0] in ('zone_config', 'slave_config'):
                        keys_to_reset.append(key)

                for key in keys_to_reset:
                    del self.failure_counts[key]
                    self.last_attempt_time.pop(key, None)

                logger.info(f"Successfully reloaded configuration on server {server.name}")

            except DNSServerError as e:
                logger.error(f"Failed to reload configuration on server {server.name}: {e}")
                self._record_failures_for_server(server)
            except Exception as e:
                logger.exception(f"Unexpected error reloading server {server.name}: {e}")
                self._record_failures_for_server(server)

    def _sync_zone_content(self, zones: Set[Zone]):
        """Synchronize content for dirty zones"""
        for zone in zones:
            key = ('zone_content', zone.id, zone.master_server.id)
            try:
                logger.info(f"Synchronizing zone {zone.origin}")
                self.last_attempt_time[key] = datetime.now()

                success, errors = update_zone(zone)

                if success:
                    # Reset failure tracking
                    del self.failure_counts[key]
                    self.last_attempt_time.pop(key, None)

                    # Clear dirty flags
                    with transaction.atomic():
                        Zone.objects.filter(id=zone.id).update(
                            content_dirty=False,
                            content_dirty_since=None,
                            master_config_dirty=False,
                            master_config_dirty_since=None
                        )

                    logger.info(f"Successfully synchronized zone {zone.origin}")
                else:
                    # Record failure
                    self.failure_counts[key] += 1
                    logger.error(f"Failed to synchronize zone {zone.origin}: {errors}")

            except Exception as e:
                logger.exception(f"Unexpected error synchronizing zone {zone.origin}: {e}")
                self.failure_counts[key] += 1

    def _sync_slave_only_zones(self, zones: Set[SlaveOnlyZone]):
        """Synchronize configuration for dirty slave-only zones"""
        for zone in zones:
            try:
                logger.info(f"Synchronizing slave-only zone {zone.origin}")

                # Track failures per zone-server combination
                failed_servers = []

                # Get all dirty server statuses for this zone
                dirty_statuses = SlaveOnlyZoneServerStatus.objects.filter(
                    zone=zone,
                    config_dirty=True
                ).select_related('server')

                for status in dirty_statuses:
                    key = ('slave_zone', zone.id, status.server.id)
                    if not self._should_retry(key):
                        continue

                    self.last_attempt_time[key] = datetime.now()

                # Try to update the zone
                success, errors = update_slave_only_zone(zone)

                if success:
                    # Reset failure tracking for all servers of this zone
                    for status in dirty_statuses:
                        key = ('slave_zone', zone.id, status.server.id)
                        self.failure_counts.pop(key, None)
                        self.last_attempt_time.pop(key, None)
                    logger.info(f"Successfully synchronized slave-only zone {zone.origin}")
                else:
                    # Record failures for each server
                    for status in dirty_statuses:
                        key = ('slave_zone', zone.id, status.server.id)
                        self.failure_counts[key] += 1
                    logger.error(f"Failed to synchronize slave-only zone {zone.origin}: {errors}")

            except Exception as e:
                logger.exception(f"Unexpected error synchronizing slave-only zone {zone.origin}: {e}")
                # Record failures for all servers
                dirty_statuses = SlaveOnlyZoneServerStatus.objects.filter(
                    zone=zone,
                    config_dirty=True
                ).select_related('server')

                for status in dirty_statuses:
                    key = ('slave_zone', zone.id, status.server.id)
                    self.failure_counts[key] += 1

    def _record_failures_for_server(self, server: Server):
        """Record failures for all configurations on a server"""
        # Record failures for zone configs
        zone_statuses = ZoneServerStatus.objects.filter(
            server=server,
            config_dirty=True
        ).select_related('zone')

        for status in zone_statuses:
            key = ('zone_config', status.zone.id, server.id)
            self.failure_counts[key] += 1
            self.last_attempt_time[key] = datetime.now()

        # Record failures for slave zone configs
        slave_statuses = SlaveOnlyZoneServerStatus.objects.filter(
            server=server,
            config_dirty=True
        ).select_related('zone')

        for status in slave_statuses:
            key = ('slave_config', status.zone.id, server.id)
            self.failure_counts[key] += 1
            self.last_attempt_time[key] = datetime.now()

    def get_status(self) -> dict:
        """Get current status of the sync thread"""
        status = {
            'running': self.thread and self.thread.is_alive(),
            'interval': self.interval,
            'failure_counts': dict(self.failure_counts),
            'total_failures': sum(self.failure_counts.values()),
            'max_backoff_seconds': self.max_backoff_seconds,
            'max_backoff_hours': self.max_backoff_seconds / 3600,
            'backoff_base': self.backoff_base,
        }

        # Add next retry times for failed items
        next_retry_times = {}
        for key, count in self.failure_counts.items():
            if count > 0 and key in self.last_attempt_time:
                backoff_seconds = min(
                    self.backoff_base ** count,
                    self.max_backoff_seconds
                )
                next_retry = self.last_attempt_time[key] + timedelta(seconds=backoff_seconds)
                next_retry_times[str(key)] = {
                    'next_retry': next_retry.isoformat(),
                    'backoff_seconds': backoff_seconds,
                    'backoff_hours': backoff_seconds / 3600
                }

        if next_retry_times:
            status['next_retry_times'] = next_retry_times

        return status


# Global instance
sync_thread = SyncBackgroundThread()
