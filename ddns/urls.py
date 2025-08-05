"""
TeleDDNS Server - DDNS App URLs
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

from django.urls import path

from .views import ddns_update, ddns_update_simple, ddns_status

urlpatterns = [
    # Main DDNS update endpoint (JSON responses)
    path('update/', ddns_update, name='ddns-update'),

    # Legacy update endpoint at root level (for backward compatibility)
    path('update', ddns_update, name='ddns-update-legacy'),

    # Simple text response endpoint (for compatibility with simple clients)
    path('update/simple/', ddns_update_simple, name='ddns-update-simple'),

    # Status endpoint
    path('status/', ddns_status, name='ddns-status'),
]
