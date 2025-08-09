"""
TeleDDNS Server - Manager App Views
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

from django.db.models import Q
from django.contrib.auth.models import User, Group
from django.db import models
from rest_framework import viewsets, filters, status
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.authentication import SessionAuthentication
from rest_framework.authtoken.models import Token
from drf_spectacular.utils import extend_schema, extend_schema_view

from .models import (
    Server, Zone, A, AAAA, CNAME, MX, NS, PTR, SRV, TXT,
    CAA, DS, DNSKEY, TLSA, AuditLog, RR_MODELS, SlaveOnlyZone
)
from .serializers import (
    ServerSerializer, ZoneSerializer, ASerializer, AAAASerializer,
    CNAMESerializer, MXSerializer, NSSerializer, PTRSerializer,
    SRVSerializer, TXTSerializer, CAASerializer, DSSerializer,
    DNSKEYSerializer, TLSASerializer, AuditLogSerializer,
    UserSerializer, GroupSerializer, TokenSerializer,
    RR_SERIALIZERS, SlaveOnlyZoneSerializer
)
from .permissions import IsOwnerOrInGroup, IsSuperuserOrReadOnly
from .services import update_zone, check_zone_on_server, validate_zone_consistency
from .api_docs import (
    zone_schema_extensions, rr_schema_extensions,
    sync_zone_schema, check_zone_schema, validate_zone_schema,
    increment_serial_schema
)
from .signals import set_request_context


class BaseOwnershipViewSet(viewsets.ModelViewSet):
    """Base viewset that handles ownership and group filtering"""
    permission_classes = [IsAuthenticated, IsOwnerOrInGroup]
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]

    def get_queryset(self):
        """Filter queryset based on user permissions"""
        queryset = super().get_queryset()

        # Superusers see everything
        if self.request.user.is_superuser:
            return queryset

        # Regular users see only objects they own or belong to their groups
        user_groups = self.request.user.groups.all()

        # Build the filter
        filters = Q(owner=self.request.user)
        if user_groups.exists():
            filters |= Q(group__in=user_groups)

        return queryset.filter(filters).distinct()

    def perform_create(self, serializer):
        """Set owner and group on creation"""
        # Set the audit context
        set_request_context(user=self.request.user, source='API')

        # If owner not specified, use the requesting user
        if 'owner' not in serializer.validated_data:
            serializer.validated_data['owner'] = self.request.user

        # If group not specified and user has groups, use the first one
        if 'group' not in serializer.validated_data:
            if self.request.user.groups.exists():
                serializer.validated_data['group'] = self.request.user.groups.first()

        super().perform_create(serializer)

    def perform_update(self, serializer):
        """Set audit context for updates"""
        set_request_context(user=self.request.user, source='API')
        super().perform_update(serializer)

    def perform_destroy(self, instance):
        """Set audit context for deletions"""
        set_request_context(user=self.request.user, source='API')
        super().perform_destroy(instance)


class ServerViewSet(viewsets.ModelViewSet):
    """ViewSet for DNS servers - only superusers can modify"""
    queryset = Server.objects.all()
    serializer_class = ServerSerializer
    permission_classes = [IsAuthenticated, IsSuperuserOrReadOnly]
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['name', 'api_url']
    ordering_fields = ['name', 'created_at']
    ordering = ['name']


@extend_schema_view(**zone_schema_extensions)
class ZoneViewSet(BaseOwnershipViewSet):
    """
    ViewSet for DNS zones with ownership filtering.

    Provides CRUD operations for DNS zones, along with zone management actions
    like synchronization, validation, and serial number management.

    ## List Zones
    Returns all zones visible to the user (owned by user or their groups).

    ## Create Zone
    Creates a new DNS zone. Requires origin, owner, group, and master_server.

    ## Retrieve Zone
    Get details of a specific zone by ID.

    ## Update Zone
    Update zone properties. Note that modifying records will automatically
    increment the SOA serial and mark the zone as dirty.

    ## Delete Zone
    Deletes a zone and all its associated resource records.
    """
    queryset = Zone.objects.select_related('owner', 'group', 'master_server').prefetch_related('slave_servers')
    serializer_class = ZoneSerializer
    search_fields = ['origin']
    ordering_fields = ['origin', 'updated_at']
    ordering = ['origin']

    @sync_zone_schema
    @action(detail=True, methods=['post'])
    def sync(self, request, pk=None):
        """
        Synchronize a zone to its DNS servers.

        Pushes the zone data to the configured master server and updates
        the zone's dirty flag upon successful synchronization.

        **Permissions**: User must be superuser, have sync_zone permission,
        or be the zone owner.

        **Request**: No body required (POST with empty body)

        **Response**:
        - 200: Zone synchronized successfully
        - 403: Insufficient permissions
        - 400: Synchronization failed (with error details)
        - 500: Internal server error
        """
        zone = self.get_object()

        # Check permission
        if not request.user.is_superuser and zone.owner != request.user:
            return Response(
                {'error': 'Only zone owner or superuser can sync'},
                status=status.HTTP_403_FORBIDDEN
            )

        # Perform sync
        success, errors = update_zone(zone)

        if success:
            return Response({
                'status': 'success',
                'message': f'Zone {zone.origin} synchronized successfully'
            })
        else:
            return Response({
                'status': 'error',
                'message': f'Failed to synchronize zone {zone.origin}',
                'errors': errors
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @check_zone_schema
    @action(detail=True, methods=['get'])
    def check(self, request, pk=None):
        """Check zone status on DNS server"""
        zone = self.get_object()

        result = check_zone_on_server(zone, zone.master_server)

        return Response({
            'zone': zone.origin,
            'server': zone.master_server.name,
            'check_result': result
        })

    @validate_zone_schema
    @action(detail=True, methods=['get'])
    def validate(self, request, pk=None):
        """Validate zone consistency"""
        zone = self.get_object()

        errors = validate_zone_consistency(zone)

        if errors:
            return Response({
                'status': 'invalid',
                'errors': errors
            }, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({
                'status': 'valid',
                'message': 'Zone data is consistent'
            })

    @increment_serial_schema
    @action(detail=True, methods=['post'])
    def increment_serial(self, request, pk=None):
        """Increment zone serial number"""
        zone = self.get_object()

        # Check permission
        if not request.user.is_superuser and zone.owner != request.user:
            return Response(
                {'error': 'Only zone owner or superuser can increment serial'},
                status=status.HTTP_403_FORBIDDEN
            )

        zone.increment_serial()
        new_serial = zone.soa.serial if hasattr(zone, 'soa') else None
        return Response({
            'status': 'success',
            'new_serial': new_serial
        })


# Resource Record ViewSets
class ResourceRecordViewSet(BaseOwnershipViewSet):
    """Base viewset for resource records"""
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['label', 'value']
    ordering_fields = ['label', 'ttl', 'created_at']
    ordering = ['label', 'created_at']

    def get_queryset(self):
        """Enhanced queryset filtering for RR types"""
        queryset = super().get_queryset()

        # Filter by zone if specified
        zone_id = self.request.query_params.get('zone')
        if zone_id:
            queryset = queryset.filter(zone_id=zone_id)

        # For non-superusers, also filter by zones they have access to
        if not self.request.user.is_superuser:
            # Get zones the user can access
            user_groups = self.request.user.groups.all()
            zone_filters = Q(zone__owner=self.request.user)
            if user_groups.exists():
                zone_filters |= Q(zone__group__in=user_groups)

            accessible_zones = Zone.objects.filter(zone_filters).values_list('id', flat=True)
            queryset = queryset.filter(zone_id__in=accessible_zones)

        return queryset.select_related('zone', 'owner', 'group')


@extend_schema_view(**{k: v.format(model_name='A') if hasattr(v, 'format') else v for k, v in rr_schema_extensions.items()})
class AViewSet(ResourceRecordViewSet):
    queryset = A.objects.all()
    serializer_class = ASerializer


@extend_schema_view(**{k: v.format(model_name='AAAA') if hasattr(v, 'format') else v for k, v in rr_schema_extensions.items()})
class AAAAViewSet(ResourceRecordViewSet):
    queryset = AAAA.objects.all()
    serializer_class = AAAASerializer


@extend_schema_view(**{k: v.format(model_name='CNAME') if hasattr(v, 'format') else v for k, v in rr_schema_extensions.items()})
class CNAMEViewSet(ResourceRecordViewSet):
    queryset = CNAME.objects.all()
    serializer_class = CNAMESerializer


@extend_schema_view(**{k: v.format(model_name='MX') if hasattr(v, 'format') else v for k, v in rr_schema_extensions.items()})
class MXViewSet(ResourceRecordViewSet):
    queryset = MX.objects.all()
    serializer_class = MXSerializer
    ordering_fields = ['label', 'priority', 'created_at']
    ordering = ['label', 'priority']


@extend_schema_view(**{k: v.format(model_name='NS') if hasattr(v, 'format') else v for k, v in rr_schema_extensions.items()})
class NSViewSet(ResourceRecordViewSet):
    queryset = NS.objects.all()
    serializer_class = NSSerializer


@extend_schema_view(**{k: v.format(model_name='PTR') if hasattr(v, 'format') else v for k, v in rr_schema_extensions.items()})
class PTRViewSet(ResourceRecordViewSet):
    queryset = PTR.objects.all()
    serializer_class = PTRSerializer


@extend_schema_view(**{k: v.format(model_name='SRV') if hasattr(v, 'format') else v for k, v in rr_schema_extensions.items()})
class SRVViewSet(ResourceRecordViewSet):
    queryset = SRV.objects.all()
    serializer_class = SRVSerializer
    ordering_fields = ['label', 'priority', 'weight', 'created_at']
    ordering = ['label', 'priority', 'weight']


@extend_schema_view(**{k: v.format(model_name='TXT') if hasattr(v, 'format') else v for k, v in rr_schema_extensions.items()})
class TXTViewSet(ResourceRecordViewSet):
    queryset = TXT.objects.all()
    serializer_class = TXTSerializer


@extend_schema_view(**{k: v.format(model_name='CAA') if hasattr(v, 'format') else v for k, v in rr_schema_extensions.items()})
class CAAViewSet(ResourceRecordViewSet):
    queryset = CAA.objects.all()
    serializer_class = CAASerializer
    search_fields = ['label', 'tag', 'value']


@extend_schema_view(**{k: v.format(model_name='DS') if hasattr(v, 'format') else v for k, v in rr_schema_extensions.items()})
class DSViewSet(ResourceRecordViewSet):
    queryset = DS.objects.all()
    serializer_class = DSSerializer
    search_fields = ['label', 'digest']


@extend_schema_view(**{k: v.format(model_name='DNSKEY') if hasattr(v, 'format') else v for k, v in rr_schema_extensions.items()})
class DNSKEYViewSet(ResourceRecordViewSet):
    queryset = DNSKEY.objects.all()
    serializer_class = DNSKEYSerializer
    search_fields = ['label']


@extend_schema_view(**{k: v.format(model_name='TLSA') if hasattr(v, 'format') else v for k, v in rr_schema_extensions.items()})
class TLSAViewSet(ResourceRecordViewSet):
    queryset = TLSA.objects.all()
    serializer_class = TLSASerializer
    search_fields = ['label']


class AuditLogViewSet(viewsets.ReadOnlyModelViewSet):
    """Read-only viewset for audit logs"""
    queryset = AuditLog.objects.select_related('user', 'content_type')
    serializer_class = AuditLogSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['user__username', 'description', 'changed_data']
    ordering_fields = ['timestamp']
    ordering = ['-timestamp']

    def get_queryset(self):
        """Filter audit logs based on user permissions"""
        queryset = super().get_queryset()

        # Superusers see all audit logs
        if self.request.user.is_superuser:
            return queryset

        # Regular users only see logs for their own actions
        return queryset.filter(user=self.request.user)


class UserViewSet(viewsets.ReadOnlyModelViewSet):
    """Read-only viewset for users"""
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [filters.SearchFilter]
    search_fields = ['username', 'email', 'first_name', 'last_name']

    def get_queryset(self):
        """Users can only see themselves unless they're superusers"""
        if self.request.user.is_superuser:
            return super().get_queryset()
        return User.objects.filter(id=self.request.user.id)


class GroupViewSet(viewsets.ReadOnlyModelViewSet):
    """Read-only viewset for groups"""
    queryset = Group.objects.all()
    serializer_class = GroupSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [filters.SearchFilter]
    search_fields = ['name']

    def get_queryset(self):
        """Users can only see groups they belong to unless they're superusers"""
        if self.request.user.is_superuser:
            return super().get_queryset()
        return self.request.user.groups.all()


@extend_schema(
    methods=['GET'],
    summary='Get API token',
    description='Retrieve the authenticated user\'s API token. If no token exists, one will be created.',
    responses={
        200: {
            'description': 'Token retrieved successfully',
            'example': {
                'key': 'abcd1234567890abcd1234567890abcd12345678',
                'user': {
                    'id': 1,
                    'username': 'admin',
                    'email': 'admin@example.com'
                },
                'created': '2024-01-01T00:00:00Z'
            }
        }
    },
    tags=['Authentication'],
)
@extend_schema(
    methods=['POST'],
    summary='Regenerate API token',
    description='Generate a new API token for the authenticated user. This will invalidate the existing token.',
    request=None,
    responses={
        201: {
            'description': 'New token generated successfully',
            'example': {
                'message': 'New token generated successfully',
                'token': {
                    'key': 'newtoken1234567890abcd1234567890abcd1234',
                    'user': {
                        'id': 1,
                        'username': 'admin',
                        'email': 'admin@example.com'
                    },
                    'created': '2024-01-01T12:00:00Z'
                }
            }
        }
    },
    tags=['Authentication'],
)
@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def token_view(request):
    """
    GET: Retrieve the user's API token
    POST: Generate a new API token (replaces existing one)
    """
    if request.method == 'GET':
        token, created = Token.objects.get_or_create(user=request.user)
        serializer = TokenSerializer(token)
        return Response(serializer.data)

    elif request.method == 'POST':
        # Delete existing token if any
        Token.objects.filter(user=request.user).delete()

        # Create new token
        token = Token.objects.create(user=request.user)
        serializer = TokenSerializer(token)

        return Response(
            {
                'message': 'New token generated successfully',
                'token': serializer.data
            },
            status=status.HTTP_201_CREATED
        )


class SlaveOnlyZoneViewSet(BaseOwnershipViewSet):
    """ViewSet for slave-only zones with ownership filtering"""
    queryset = SlaveOnlyZone.objects.select_related('owner', 'group').prefetch_related('slave_servers')
    serializer_class = SlaveOnlyZoneSerializer
    search_fields = ['origin', 'external_master']
    ordering_fields = ['origin', 'updated_at']
    ordering = ['origin']

    @action(detail=True, methods=['post'])
    def sync(self, request, pk=None):
        """Synchronize a slave-only zone configuration to its slave servers"""
        zone = self.get_object()

        # Check permission to sync
        if not (request.user.is_superuser or
                request.user.has_perm('manager.sync_slave_only_zone') or
                zone.owner == request.user):
            return Response(
                {'error': 'You do not have permission to sync this zone'},
                status=status.HTTP_403_FORBIDDEN
            )

        try:
            from .services import update_slave_only_zone
            success, errors = update_slave_only_zone(zone)

            if success:
                return Response({
                    'status': 'success',
                    'message': f'Slave-only zone {zone.origin} synchronized successfully'
                })
            else:
                return Response({
                    'status': 'error',
                    'errors': errors
                }, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            logger.error(f"Error syncing slave-only zone {zone.origin}: {str(e)}")
            return Response({
                'status': 'error',
                'message': f'Internal error: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @action(detail=True, methods=['post'])
    def mark_dirty(self, request, pk=None):
        """Mark a slave-only zone as dirty"""
        zone = self.get_object()

        from django.utils import timezone
        from .models import SlaveOnlyZoneServerStatus

        now = timezone.now()
        servers_marked = 0

        # Mark all slave servers as needing config update
        for server in zone.slave_servers.all():
            status, created = SlaveOnlyZoneServerStatus.objects.get_or_create(
                zone=zone,
                server=server,
                defaults={'config_dirty': True, 'config_dirty_since': now}
            )
            if not created and not status.config_dirty:
                status.config_dirty = True
                status.config_dirty_since = now
                status.save(update_fields=['config_dirty', 'config_dirty_since', 'updated_at'])
            servers_marked += 1

        return Response({
            'status': 'success',
            'message': f'Slave-only zone {zone.origin} marked as dirty on {servers_marked} server(s)'
        })


@extend_schema(
    summary='Health check endpoint',
    description='Public endpoint to check if the API is operational. No authentication required.',
    responses={
        200: {
            'description': 'API is healthy',
            'example': {
                'status': 'healthy',
                'message': 'TeleDDNS Server API is operational',
                'version': '1.0.0',
                'timestamp': '2024-01-01T12:00:00Z'
            }
        }
    },
    tags=['Health']
)
@api_view(['GET'])
@permission_classes([AllowAny])
def health_check(request):
    """
    Public health check endpoint.

    This endpoint requires no authentication and can be used for:
    - Monitoring services to check API availability
    - Load balancer health checks
    - Simple connectivity tests
    """
    from django.utils import timezone
    from django.conf import settings

    return Response({
        'status': 'healthy',
        'message': 'TeleDDNS Server API is operational',
        'version': getattr(settings, 'API_VERSION', '1.0.0'),
        'timestamp': timezone.now().isoformat()
    })


@extend_schema(
    summary='Get sync thread status',
    description='Get the current status of the background synchronization thread',
    responses={200: dict},
    tags=['System']
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def sync_status(request):
    """
    Get the status of the background synchronization thread.

    This endpoint shows:
    - Whether the sync thread is running
    - Current configuration (interval, retries, etc.)
    - Current failure counts and retry states
    """
    from .sync_thread import sync_thread

    status = sync_thread.get_status()
    return Response(status)
