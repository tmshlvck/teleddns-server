"""
TeleDDNS Server - Manager App Configuration
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

import os
from django.apps import AppConfig


class ManagerConfig(AppConfig):
    """Configuration for the manager app"""
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'manager'
    verbose_name = 'DNS Manager'

    def ready(self):
        """Import signal handlers and start background tasks when the app is ready"""
        from . import signals  # noqa

        # Only start the sync thread when running the development server
        # Production servers (WSGI/ASGI) handle this in their respective files
        import sys
        if (len(sys.argv) > 1 and
            sys.argv[1] == 'runserver' and
            os.environ.get('RUN_MAIN') == 'true'):
            # Start sync thread for development server
            from .sync_thread import sync_thread
            sync_thread.start()
