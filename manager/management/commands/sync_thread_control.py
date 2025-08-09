"""
TeleDDNS Server - Sync Thread Control Management Command
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

import json
from django.core.management.base import BaseCommand, CommandError
from manager.sync_thread import sync_thread


class Command(BaseCommand):
    help = 'Control the background synchronization thread'

    def add_arguments(self, parser):
        # Add subcommands
        subparsers = parser.add_subparsers(
            dest='action',
            help='Action to perform'
        )

        # Start command
        subparsers.add_parser(
            'start',
            help='Start the synchronization thread'
        )

        # Stop command
        subparsers.add_parser(
            'stop',
            help='Stop the synchronization thread'
        )

        # Status command
        status_parser = subparsers.add_parser(
            'status',
            help='Show synchronization thread status'
        )
        status_parser.add_argument(
            '--json',
            action='store_true',
            help='Output status in JSON format'
        )

        # Force sync command
        subparsers.add_parser(
            'force-sync',
            help='Force an immediate synchronization cycle'
        )

    def handle(self, *args, **options):
        action = options.get('action')

        if not action:
            raise CommandError('Please specify an action: start, stop, status, or force-sync')

        if action == 'start':
            self.handle_start()
        elif action == 'stop':
            self.handle_stop()
        elif action == 'status':
            self.handle_status(options.get('json', False))
        elif action == 'force-sync':
            self.handle_force_sync()
        else:
            raise CommandError(f'Unknown action: {action}')

    def handle_start(self):
        """Start the sync thread"""
        status = sync_thread.get_status()
        if status['running']:
            self.stdout.write(self.style.WARNING('Sync thread is already running'))
        else:
            sync_thread.start()
            self.stdout.write(self.style.SUCCESS('Sync thread started successfully'))

    def handle_stop(self):
        """Stop the sync thread"""
        status = sync_thread.get_status()
        if not status['running']:
            self.stdout.write(self.style.WARNING('Sync thread is not running'))
        else:
            sync_thread.stop()
            self.stdout.write(self.style.SUCCESS('Sync thread stopped successfully'))

    def handle_status(self, json_format=False):
        """Show sync thread status"""
        status = sync_thread.get_status()

        if json_format:
            self.stdout.write(json.dumps(status, indent=2))
        else:
            self.stdout.write(f"Sync Thread Status")
            self.stdout.write(f"==================")
            self.stdout.write(f"Running: {'Yes' if status['running'] else 'No'}")
            self.stdout.write(f"Interval: {status['interval']} seconds")
            self.stdout.write(f"Max backoff: {status['max_backoff_seconds']} seconds ({status['max_backoff_hours']} hours)")
            self.stdout.write(f"Backoff base: {status['backoff_base']}")
            self.stdout.write(f"Total failures: {status['total_failures']}")

            if status['failure_counts']:
                self.stdout.write(f"\nCurrent failures:")
                for key, count in status['failure_counts'].items():
                    obj_type, obj_id, server_id = key
                    self.stdout.write(f"  - {obj_type} ID={obj_id}, Server ID={server_id}: {count} failures")

                    # Show next retry time if available
                    if 'next_retry_times' in status and str(key) in status['next_retry_times']:
                        retry_info = status['next_retry_times'][str(key)]
                        self.stdout.write(f"    Next retry: {retry_info['next_retry']} (in {retry_info['backoff_hours']:.1f} hours)")

    def handle_force_sync(self):
        """Force an immediate sync cycle"""
        status = sync_thread.get_status()
        if not status['running']:
            self.stdout.write(self.style.WARNING('Sync thread is not running. Starting it first...'))
            sync_thread.start()

        # Trigger immediate sync by stopping and restarting
        self.stdout.write('Forcing immediate synchronization...')
        sync_thread.stop_event.set()  # This will cause the thread to wake up
        sync_thread.stop_event.clear()  # Reset for normal operation
        self.stdout.write(self.style.SUCCESS('Synchronization cycle triggered'))
