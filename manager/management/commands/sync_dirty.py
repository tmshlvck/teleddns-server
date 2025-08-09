"""
TeleDDNS Server - Manual Sync Dirty Management Command
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

from django.core.management.base import BaseCommand
from django.db.models import Q
from manager.models import Zone, SlaveOnlyZone, ZoneServerStatus, SlaveOnlyZoneServerStatus
from manager.services import sync_all_dirty_zones, sync_all_dirty_slave_only_zones


class Command(BaseCommand):
    help = 'Manually synchronize all dirty zones and configurations'

    def add_arguments(self, parser):
        parser.add_argument(
            '--zones-only',
            action='store_true',
            help='Only sync dirty zones (skip slave-only zones)'
        )
        parser.add_argument(
            '--slave-zones-only',
            action='store_true',
            help='Only sync dirty slave-only zones'
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be synced without actually syncing'
        )

    def handle(self, *args, **options):
        zones_only = options.get('zones_only', False)
        slave_zones_only = options.get('slave_zones_only', False)
        dry_run = options.get('dry_run', False)

        if zones_only and slave_zones_only:
            self.stdout.write(self.style.ERROR('Cannot specify both --zones-only and --slave-zones-only'))
            return

        total_synced = 0
        total_errors = []

        # Sync regular zones
        if not slave_zones_only:
            self.stdout.write('Checking for dirty zones...')

            # Find dirty zones
            dirty_zones = Zone.objects.filter(
                Q(content_dirty=True) | Q(master_config_dirty=True)
            ).select_related('master_server')

            # Also find zones with dirty slave servers
            zones_with_dirty_slaves = ZoneServerStatus.objects.filter(
                config_dirty=True
            ).values_list('zone_id', flat=True).distinct()

            all_dirty_zones = Zone.objects.filter(
                Q(id__in=dirty_zones) | Q(id__in=zones_with_dirty_slaves)
            ).select_related('master_server').distinct()

            dirty_count = all_dirty_zones.count()

            if dirty_count > 0:
                self.stdout.write(f'Found {dirty_count} dirty zones')

                if dry_run:
                    self.stdout.write('Zones that would be synced:')
                    for zone in all_dirty_zones:
                        reasons = []
                        if zone.content_dirty:
                            reasons.append('content dirty')
                        if zone.master_config_dirty:
                            reasons.append('master config dirty')

                        # Check slave servers
                        dirty_slaves = ZoneServerStatus.objects.filter(
                            zone=zone,
                            config_dirty=True
                        ).select_related('server')

                        if dirty_slaves.exists():
                            slave_names = ', '.join([s.server.name for s in dirty_slaves])
                            reasons.append(f'slave servers dirty: {slave_names}')

                        self.stdout.write(f'  - {zone.origin} ({", ".join(reasons)})')
                else:
                    results = sync_all_dirty_zones()
                    total_synced += results['success']
                    total_errors.extend(results['errors'])

                    self.stdout.write(f'Synced {results["success"]}/{results["total"]} zones successfully')
                    if results['failed'] > 0:
                        self.stdout.write(self.style.WARNING(f'{results["failed"]} zones failed'))
            else:
                self.stdout.write('No dirty zones found')

        # Sync slave-only zones
        if not zones_only:
            self.stdout.write('\nChecking for dirty slave-only zones...')

            # Find dirty slave-only zones
            dirty_statuses = SlaveOnlyZoneServerStatus.objects.filter(
                config_dirty=True
            ).select_related('zone').prefetch_related('zone__slave_servers')

            # Get unique zones
            dirty_zones = {}
            for status in dirty_statuses:
                if status.zone.id not in dirty_zones:
                    dirty_zones[status.zone.id] = status.zone

            dirty_zones_list = list(dirty_zones.values())
            dirty_count = len(dirty_zones_list)

            if dirty_count > 0:
                self.stdout.write(f'Found {dirty_count} dirty slave-only zones')

                if dry_run:
                    self.stdout.write('Slave-only zones that would be synced:')
                    for zone in dirty_zones_list:
                        dirty_servers = SlaveOnlyZoneServerStatus.objects.filter(
                            zone=zone,
                            config_dirty=True
                        ).select_related('server')

                        server_names = ', '.join([s.server.name for s in dirty_servers])
                        self.stdout.write(f'  - {zone.origin} (dirty servers: {server_names})')
                else:
                    results = sync_all_dirty_slave_only_zones()
                    total_synced += results['success']
                    total_errors.extend(results['errors'])

                    self.stdout.write(f'Synced {results["success"]}/{results["total"]} slave-only zones successfully')
                    if results['failed'] > 0:
                        self.stdout.write(self.style.WARNING(f'{results["failed"]} slave-only zones failed'))
            else:
                self.stdout.write('No dirty slave-only zones found')

        # Summary
        self.stdout.write('\n' + '=' * 50)
        if dry_run:
            self.stdout.write('DRY RUN - No changes were made')
        else:
            self.stdout.write(f'Total zones synced successfully: {total_synced}')

            if total_errors:
                self.stdout.write(self.style.ERROR(f'\nErrors encountered ({len(total_errors)}):'))
                for error in total_errors:
                    self.stdout.write(self.style.ERROR(f'  - {error}'))
            else:
                self.stdout.write(self.style.SUCCESS('\nAll syncs completed successfully!'))
