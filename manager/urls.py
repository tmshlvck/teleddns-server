"""
TeleDDNS Server - Manager App URLs
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

from django.urls import path, include
from rest_framework.routers import DefaultRouter

from .views import (
    ServerViewSet, ZoneViewSet, SlaveOnlyZoneViewSet, AViewSet, AAAAViewSet,
    CNAMEViewSet, MXViewSet, NSViewSet, PTRViewSet,
    SRVViewSet, TXTViewSet, CAAViewSet, DSViewSet,
    DNSKEYViewSet, TLSAViewSet, AuditLogViewSet,
    UserViewSet, GroupViewSet, token_view, health_check, sync_status
)

# Create a router and register our viewsets with it
router = DefaultRouter()

# Infrastructure endpoints
router.register(r'servers', ServerViewSet, basename='server')
router.register(r'zones', ZoneViewSet, basename='zone')
router.register(r'slave-zones', SlaveOnlyZoneViewSet, basename='slaveonlyzone')

# Resource record endpoints
router.register(r'records/a', AViewSet, basename='a')
router.register(r'records/aaaa', AAAAViewSet, basename='aaaa')
router.register(r'records/cname', CNAMEViewSet, basename='cname')
router.register(r'records/mx', MXViewSet, basename='mx')
router.register(r'records/ns', NSViewSet, basename='ns')
router.register(r'records/ptr', PTRViewSet, basename='ptr')
router.register(r'records/srv', SRVViewSet, basename='srv')
router.register(r'records/txt', TXTViewSet, basename='txt')
router.register(r'records/caa', CAAViewSet, basename='caa')
router.register(r'records/ds', DSViewSet, basename='ds')
router.register(r'records/dnskey', DNSKEYViewSet, basename='dnskey')
router.register(r'records/tlsa', TLSAViewSet, basename='tlsa')

# Admin endpoints
router.register(r'audit-logs', AuditLogViewSet, basename='auditlog')
router.register(r'users', UserViewSet, basename='user')
router.register(r'groups', GroupViewSet, basename='group')

# The API URLs are now determined automatically by the router
urlpatterns = [
    # Public endpoints (no auth required)
    path('health/', health_check, name='api-health'),

    # System endpoints (auth required)
    path('sync-status/', sync_status, name='api-sync-status'),

    # Token management endpoint
    path('token/', token_view, name='api-token'),

    # Include all router URLs
    path('', include(router.urls)),
]
