"""
TeleDDNS Server - Manual Sync Management Command
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
from manager.backend_worker import backend_worker


class Command(BaseCommand):
    help = 'Manually synchronize all dirty zones and configurations to backend DNS servers'

    def add_arguments(self, parser):
        parser.add_argument(
            '--quiet',
            action='store_true',
            help='Suppress output except for errors'
        )

    def handle(self, *args, **options):
        quiet = options.get('quiet', False)

        if not quiet:
            self.stdout.write('Starting manual synchronization...')

        try:
            # Run the synchronization work
            backend_worker.do_sync()

            if not quiet:
                self.stdout.write(self.style.SUCCESS('Synchronization completed successfully'))

        except Exception as e:
            self.stderr.write(self.style.ERROR(f'Synchronization failed: {e}'))
            raise
