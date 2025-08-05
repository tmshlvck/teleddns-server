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
from rest_framework import viewsets, status, filters
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.authtoken.models import Token

from .models import (
    Server, Zone, A, AAAA, CNAME, MX, NS, PTR, SRV, TXT,
    CAA, DS, DNSKEY, TLSA, AuditLog, RR_MODELS
)
from .serializers import (
    ServerSerializer, ZoneSerializer, ASerializer, AAAASerializer,
    CNAMESerializer, MXSerializer, NSSerializer, PTRSerializer,
    SRVSerializer, TXTSerializer, CAASerializer, DSSerializer,
    DNSKEYSerializer, TLSASerializer, AuditLogSerializer,
    UserSerializer, GroupSerializer, TokenSerializer
)
from .permissions import IsOwnerOrInGroup, IsSuperuserOrReadOnly
from .services import update_zone, check_zone_on_server, validate_zone_consistency
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


class ZoneViewSet(BaseOwnershipViewSet):
    """ViewSet for DNS zones with ownership filtering"""
    queryset = Zone.objects.select_related('owner', 'group', 'master_server').prefetch_related('slave_servers')
    serializer_class = ZoneSerializer
    search_fields = ['origin', 'soa_mname', 'soa_rname']
    ordering_fields = ['origin', 'soa_serial', 'updated_at']
    ordering = ['origin']

    @action(detail=True, methods=['post'])
    def sync(self, request, pk=None):
        """Synchronize a zone to its DNS servers"""
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

        return Response({
            'status': 'success',
            'new_serial': zone.soa_serial
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


class AViewSet(ResourceRecordViewSet):
    queryset = A.objects.all()
    serializer_class = ASerializer


class AAAAViewSet(ResourceRecordViewSet):
    queryset = AAAA.objects.all()
    serializer_class = AAAASerializer


class CNAMEViewSet(ResourceRecordViewSet):
    queryset = CNAME.objects.all()
    serializer_class = CNAMESerializer


class MXViewSet(ResourceRecordViewSet):
    queryset = MX.objects.all()
    serializer_class = MXSerializer
    ordering_fields = ['label', 'priority', 'created_at']
    ordering = ['label', 'priority']


class NSViewSet(ResourceRecordViewSet):
    queryset = NS.objects.all()
    serializer_class = NSSerializer


class PTRViewSet(ResourceRecordViewSet):
    queryset = PTR.objects.all()
    serializer_class = PTRSerializer


class SRVViewSet(ResourceRecordViewSet):
    queryset = SRV.objects.all()
    serializer_class = SRVSerializer
    ordering_fields = ['label', 'priority', 'weight', 'created_at']
    ordering = ['label', 'priority', 'weight']


class TXTViewSet(ResourceRecordViewSet):
    queryset = TXT.objects.all()
    serializer_class = TXTSerializer


class CAAViewSet(ResourceRecordViewSet):
    queryset = CAA.objects.all()
    serializer_class = CAASerializer
    search_fields = ['label', 'tag', 'value']


class DSViewSet(ResourceRecordViewSet):
    queryset = DS.objects.all()
    serializer_class = DSSerializer
    search_fields = ['label', 'digest']


class DNSKEYViewSet(ResourceRecordViewSet):
    queryset = DNSKEY.objects.all()
    serializer_class = DNSKEYSerializer
    search_fields = ['label']


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
