"""
TeleDDNS Server - Sync Zones Management Command
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
import sys
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction, models

from manager.models import Zone, Server, SlaveOnlyZone
from manager.services import sync_all_dirty_zones, update_zone, push_server_config, sync_all_dirty_slave_only_zones, update_slave_only_zone

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    """
    Django management command to synchronize dirty zones to DNS servers.

    This command should be run periodically (e.g., via cron or systemd timer)
    to push pending zone changes to the configured DNS servers.
    """

    help = 'Synchronize zones marked as dirty to their DNS servers'

    def add_arguments(self, parser):
        parser.add_argument(
            '--zone',
            type=str,
            help='Synchronize only the specified zone (by origin)',
        )
        parser.add_argument(
            '--server',
            type=str,
            help='Synchronize only zones for the specified server (by name)',
        )
        parser.add_argument(
            '--force',
            action='store_true',
            help='Force synchronization even for zones not marked as dirty',
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be synchronized without actually doing it',
        )
        parser.add_argument(
            '--update-config',
            action='store_true',
            help='Also update server configurations',
        )
        parser.add_argument(
            '--quiet',
            action='store_true',
            help='Suppress non-error output',
        )

    def handle(self, *args, **options):
        """Main command handler"""
        self.quiet = options['quiet']
        self.dry_run = options['dry_run']

        if self.dry_run:
            self.log_info("DRY RUN MODE - No changes will be made")

        try:
            # Update server configurations if requested
            if options['update_config']:
                self._update_server_configs()

            # Synchronize zones
            if options['zone']:
                self._sync_single_zone(options['zone'], options['force'])
            elif options['server']:
                self._sync_server_zones(options['server'], options['force'])
            else:
                self._sync_all_zones(options['force'])
                self._sync_all_slave_only_zones(options['force'])

        except KeyboardInterrupt:
            self.log_error("\nOperation cancelled by user")
            sys.exit(1)
        except Exception as e:
            self.log_error(f"Unexpected error: {e}")
            logger.exception("Unexpected error in sync_zones command")
            sys.exit(1)

    def _sync_single_zone(self, zone_origin, force=False):
        """Synchronize a single zone"""
        try:
            zone = Zone.objects.select_related('master_server').get(origin=zone_origin)
        except Zone.DoesNotExist:
            raise CommandError(f"Zone '{zone_origin}' not found")

        if not force and not (zone.content_dirty or zone.master_config_dirty):
            self.log_info(f"Zone {zone.origin} is already synchronized (use --force to sync anyway)")
            return

        self.log_info(f"Synchronizing zone {zone.origin}")

        if self.dry_run:
            self.log_info(f"Would synchronize zone {zone.origin} to server {zone.master_server.name}")
            return

        success, errors = update_zone(zone)

        if success:
            self.log_success(f"Successfully synchronized zone {zone.origin}")
        else:
            self.log_error(f"Failed to synchronize zone {zone.origin}:")
            for error in errors:
                self.log_error(f"  - {error}")
            sys.exit(1)

    def _sync_server_zones(self, server_name, force=False):
        """Synchronize all zones for a specific server"""
        try:
            server = Server.objects.get(name=server_name)
        except Server.DoesNotExist:
            raise CommandError(f"Server '{server_name}' not found")

        zones = Zone.objects.filter(master_server=server)
        if not force:
            zones = zones.filter(models.Q(content_dirty=True) | models.Q(master_config_dirty=True))

        # Also get slave-only zones for this server that need sync
        from manager.models import SlaveOnlyZoneServerStatus
        if not force:
            # Find slave-only zones that have dirty status for this server
            dirty_statuses = SlaveOnlyZoneServerStatus.objects.filter(
                server=server,
                config_dirty=True
            ).values_list('zone_id', flat=True)
            slave_only_zones = SlaveOnlyZone.objects.filter(id__in=dirty_statuses)
        else:
            slave_only_zones = SlaveOnlyZone.objects.filter(slave_servers=server)

        zone_count = zones.count()
        slave_only_count = slave_only_zones.count()
        total_count = zone_count + slave_only_count

        if total_count == 0:
            self.log_info(f"No zones to synchronize for server {server_name}")
            return

        self.log_info(f"Synchronizing {total_count} zone(s) for server {server_name} ({zone_count} master/slave, {slave_only_count} slave-only)")

        success_count = 0
        fail_count = 0

        for zone in zones:
            if self.dry_run:
                self.log_info(f"Would synchronize zone {zone.origin}")
                success_count += 1
                continue

            try:
                success, errors = update_zone(zone)
                if success:
                    success_count += 1
                    self.log_success(f"Synchronized zone {zone.origin}")
                else:
                    fail_count += 1
                    self.log_error(f"Failed to synchronize zone {zone.origin}:")
                    for error in errors:
                        self.log_error(f"  - {error}")
            except Exception as e:
                fail_count += 1
                self.log_error(f"Error synchronizing zone {zone.origin}: {e}")

        # Sync slave-only zones
        for zone in slave_only_zones:
            if self.dry_run:
                self.log_info(f"Would synchronize slave-only zone {zone.origin}")
                success_count += 1
                continue

            try:
                success, errors = update_slave_only_zone(zone)
                if success:
                    success_count += 1
                    self.log_success(f"Synchronized slave-only zone {zone.origin}")
                else:
                    fail_count += 1
                    self.log_error(f"Failed to synchronize slave-only zone {zone.origin}:")
                    for error in errors:
                        self.log_error(f"  - {error}")
            except Exception as e:
                fail_count += 1
                self.log_error(f"Error synchronizing slave-only zone {zone.origin}: {e}")

        # Summary
        self.log_info(f"\nSynchronization complete:")
        self.log_info(f"  - Success: {success_count}")
        self.log_info(f"  - Failed: {fail_count}")

        if fail_count > 0:
            sys.exit(1)

    def _sync_all_zones(self, force=False):
        """Synchronize all dirty zones"""
        if force:
            from django.utils import timezone
            now = timezone.now()
            zones = Zone.objects.all()
            zone_count = zones.count()
            # Mark all zones as dirty if force is used
            Zone.objects.update(
                content_dirty=True,
                master_config_dirty=True,
                content_dirty_since=now,
                master_config_dirty_since=now
            )
            self.log_info(f"Marked all zones as dirty (force mode)")

        if self.dry_run:
            dirty_zones = Zone.objects.filter(
                models.Q(content_dirty=True) | models.Q(master_config_dirty=True)
            ).select_related('master_server')
            if dirty_zones.exists():
                self.log_info(f"Would synchronize {dirty_zones.count()} dirty zone(s):")
                for zone in dirty_zones:
                    dirty_types = []
                    if zone.content_dirty:
                        dirty_types.append("content")
                    if zone.master_config_dirty:
                        dirty_types.append("config")
                    self.log_info(f"  - {zone.origin} -> {zone.master_server.name} ({', '.join(dirty_types)})")
            else:
                self.log_info("No dirty zones to synchronize")
            return

        results = sync_all_dirty_zones()

        # Display results
        self.log_info(f"\nSynchronization complete:")
        self.log_info(f"  - Total zones: {results['total']}")
        self.log_info(f"  - Success: {results['success']}")
        self.log_info(f"  - Failed: {results['failed']}")

        if results['errors']:
            self.log_error("\nErrors:")
            for error in results['errors']:
                self.log_error(f"  - {error}")

        if results['failed'] > 0:
            sys.exit(1)

    def _sync_all_slave_only_zones(self, force=False):
        """Synchronize all dirty slave-only zones"""
        if force:
            from django.utils import timezone
            from manager.models import SlaveOnlyZoneServerStatus
            now = timezone.now()
            # Mark all slave-only zone server statuses as dirty if force is used
            for zone in SlaveOnlyZone.objects.all():
                for server in zone.slave_servers.all():
                    SlaveOnlyZoneServerStatus.objects.update_or_create(
                        zone=zone,
                        server=server,
                        defaults={'config_dirty': True, 'config_dirty_since': now}
                    )
            self.log_info(f"Marked all slave-only zones as dirty (force mode)")

        if self.dry_run:
            from manager.models import SlaveOnlyZoneServerStatus
            dirty_statuses = SlaveOnlyZoneServerStatus.objects.filter(
                config_dirty=True
            ).select_related('zone').prefetch_related('zone__slave_servers')

            if dirty_statuses.exists():
                # Group by zone
                zones_dict = {}
                for status in dirty_statuses:
                    if status.zone.id not in zones_dict:
                        zones_dict[status.zone.id] = {
                            'zone': status.zone,
                            'dirty_servers': []
                        }
                    zones_dict[status.zone.id]['dirty_servers'].append(status.server.name)

                self.log_info(f"Would synchronize {len(zones_dict)} dirty slave-only zone(s):")
                for zone_info in zones_dict.values():
                    zone = zone_info['zone']
                    dirty_servers = zone_info['dirty_servers']
                    self.log_info(f"  - {zone.origin} -> [{', '.join(dirty_servers)}]")
            else:
                self.log_info("No dirty slave-only zones to synchronize")
            return

        results = sync_all_dirty_slave_only_zones()

        # Display results
        if results['total'] > 0:
            self.log_info(f"\nSlave-only zone synchronization complete:")
            self.log_info(f"  - Total zones: {results['total']}")
            self.log_info(f"  - Success: {results['success']}")
            self.log_info(f"  - Failed: {results['failed']}")

            if results['errors']:
                self.log_error("\nErrors:")
                for error in results['errors']:
                    self.log_error(f"  - {error}")

            if results['failed'] > 0:
                sys.exit(1)

    def _update_server_configs(self):
        """Update configurations for all servers"""
        servers = Server.objects.all()

        self.log_info(f"Updating configurations for {servers.count()} server(s)")

        success_count = 0
        fail_count = 0

        for server in servers:
            if self.dry_run:
                self.log_info(f"Would update configuration for server {server.name}")
                success_count += 1
                continue

            try:
                if push_server_config(server):
                    success_count += 1
                    self.log_success(f"Updated configuration for server {server.name}")
                else:
                    fail_count += 1
                    self.log_error(f"Failed to update configuration for server {server.name}")
            except Exception as e:
                fail_count += 1
                self.log_error(f"Error updating configuration for server {server.name}: {e}")

        self.log_info(f"\nServer configuration update complete:")
        self.log_info(f"  - Success: {success_count}")
        self.log_info(f"  - Failed: {fail_count}")

        if fail_count > 0:
            self.log_error("Some server configurations failed to update")

    def log_info(self, message):
        """Log info message"""
        if not self.quiet:
            self.stdout.write(message)
        logger.info(message)

    def log_success(self, message):
        """Log success message"""
        if not self.quiet:
            self.stdout.write(self.style.SUCCESS(message))
        logger.info(message)

    def log_error(self, message):
        """Log error message"""
        self.stderr.write(self.style.ERROR(message))
        logger.error(message)
