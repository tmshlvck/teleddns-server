"""
TeleDDNS Server - Manager App Serializers
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

from rest_framework import serializers
from django.contrib.auth.models import User, Group
from rest_framework.authtoken.models import Token

from .models import (
    Server, Zone, A, AAAA, CNAME, MX, NS, PTR, SRV, TXT,
    CAA, DS, DNSKEY, TLSA, AuditLog, SOA, SlaveOnlyZone
)


class UserSerializer(serializers.ModelSerializer):
    """Serializer for User model"""
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 'is_active']
        read_only_fields = ['id']


class GroupSerializer(serializers.ModelSerializer):
    """Serializer for Group model"""
    class Meta:
        model = Group
        fields = ['id', 'name']
        read_only_fields = ['id']


class TokenSerializer(serializers.ModelSerializer):
    """Serializer for Token model"""
    user = UserSerializer(read_only=True)

    class Meta:
        model = Token
        fields = ['key', 'user', 'created']
        read_only_fields = ['key', 'created']


class ServerSerializer(serializers.ModelSerializer):
    """Serializer for DNS Server model"""
    master_zones_count = serializers.IntegerField(source='master_zones.count', read_only=True)
    slave_zones_count = serializers.IntegerField(source='slave_zones.count', read_only=True)

    class Meta:
        model = Server
        fields = [
            'id', 'name', 'api_url', 'api_key', 'master_template', 'slave_template',
            'master_zones_count', 'slave_zones_count', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']
        extra_kwargs = {
            'api_key': {'write_only': True}  # Don't expose API key in responses
        }


class ZoneSerializer(serializers.ModelSerializer):
    """Serializer for DNS Zone model"""
    owner = UserSerializer(read_only=True)
    group = GroupSerializer(read_only=True)
    owner_id = serializers.PrimaryKeyRelatedField(
        queryset=User.objects.all(),
        source='owner',
        write_only=True
    )
    group_id = serializers.PrimaryKeyRelatedField(
        queryset=Group.objects.all(),
        source='group',
        write_only=True
    )
    master_server_name = serializers.CharField(source='master_server.name', read_only=True)
    slave_servers_names = serializers.StringRelatedField(source='slave_servers', many=True, read_only=True)

    class Meta:
        model = Zone
        fields = [
            'id', 'origin',
            'owner', 'owner_id', 'group', 'group_id',
            'master_server', 'master_server_name', 'slave_servers', 'slave_servers_names',
            'content_dirty', 'content_dirty_since', 'master_config_dirty', 'master_config_dirty_since',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']

    def validate_origin(self, value):
        """Ensure origin ends with a dot"""
        if not value.endswith('.'):
            value += '.'
        return value


class ResourceRecordSerializer(serializers.ModelSerializer):
    """Base serializer for all resource record types"""
    zone_origin = serializers.CharField(source='zone.origin', read_only=True)
    owner = UserSerializer(read_only=True)
    group = GroupSerializer(read_only=True)
    owner_id = serializers.PrimaryKeyRelatedField(
        queryset=User.objects.all(),
        source='owner',
        write_only=True,
        required=False
    )
    group_id = serializers.PrimaryKeyRelatedField(
        queryset=Group.objects.all(),
        source='group',
        write_only=True,
        required=False
    )

    class Meta:
        fields = [
            'id', 'zone', 'zone_origin', 'label', 'ttl', 'rrclass',
            'owner', 'owner_id', 'group', 'group_id',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']

    def create(self, validated_data):
        """Set owner and group from request if not provided"""
        request = self.context.get('request')
        if request and hasattr(request, 'user'):
            if 'owner' not in validated_data:
                validated_data['owner'] = request.user
            if 'group' not in validated_data and request.user.groups.exists():
                validated_data['group'] = request.user.groups.first()
        return super().create(validated_data)


class ASerializer(ResourceRecordSerializer):
    """Serializer for A records"""
    class Meta(ResourceRecordSerializer.Meta):
        model = A
        fields = ResourceRecordSerializer.Meta.fields + ['value']


class AAAASerializer(ResourceRecordSerializer):
    """Serializer for AAAA records"""
    class Meta(ResourceRecordSerializer.Meta):
        model = AAAA
        fields = ResourceRecordSerializer.Meta.fields + ['value']


class CNAMESerializer(ResourceRecordSerializer):
    """Serializer for CNAME records"""
    class Meta(ResourceRecordSerializer.Meta):
        model = CNAME
        fields = ResourceRecordSerializer.Meta.fields + ['value']


class MXSerializer(ResourceRecordSerializer):
    """Serializer for MX records"""
    class Meta(ResourceRecordSerializer.Meta):
        model = MX
        fields = ResourceRecordSerializer.Meta.fields + ['priority', 'value']


class NSSerializer(ResourceRecordSerializer):
    """Serializer for NS records"""
    class Meta(ResourceRecordSerializer.Meta):
        model = NS
        fields = ResourceRecordSerializer.Meta.fields + ['value']


class PTRSerializer(ResourceRecordSerializer):
    """Serializer for PTR records"""
    class Meta(ResourceRecordSerializer.Meta):
        model = PTR
        fields = ResourceRecordSerializer.Meta.fields + ['value']


class SRVSerializer(ResourceRecordSerializer):
    """Serializer for SRV records"""
    class Meta(ResourceRecordSerializer.Meta):
        model = SRV
        fields = ResourceRecordSerializer.Meta.fields + ['priority', 'weight', 'port', 'value']


class TXTSerializer(ResourceRecordSerializer):
    """Serializer for TXT records"""
    class Meta(ResourceRecordSerializer.Meta):
        model = TXT
        fields = ResourceRecordSerializer.Meta.fields + ['value']


class CAASerializer(ResourceRecordSerializer):
    """Serializer for CAA records"""
    class Meta(ResourceRecordSerializer.Meta):
        model = CAA
        fields = ResourceRecordSerializer.Meta.fields + ['flag', 'tag', 'value']


class DSSerializer(ResourceRecordSerializer):
    """Serializer for DS records"""
    class Meta(ResourceRecordSerializer.Meta):
        model = DS
        fields = ResourceRecordSerializer.Meta.fields + ['key_tag', 'algorithm', 'digest_type', 'digest']


class DNSKEYSerializer(ResourceRecordSerializer):
    """Serializer for DNSKEY records"""
    class Meta(ResourceRecordSerializer.Meta):
        model = DNSKEY
        fields = ResourceRecordSerializer.Meta.fields + ['flags', 'protocol', 'algorithm', 'public_key']


class TLSASerializer(ResourceRecordSerializer):
    """Serializer for TLSA records"""
    class Meta(ResourceRecordSerializer.Meta):
        model = TLSA
        fields = ResourceRecordSerializer.Meta.fields + ['usage', 'selector', 'matching_type', 'certificate_data']


class AuditLogSerializer(serializers.ModelSerializer):
    """Serializer for Audit Log entries"""
    user = UserSerializer(read_only=True)
    content_type_name = serializers.SerializerMethodField()
    object_repr = serializers.SerializerMethodField()

    class Meta:
        model = AuditLog
        fields = [
            'id', 'timestamp', 'user', 'source', 'action',
            'content_type', 'content_type_name', 'object_id', 'object_repr',
            'changed_data', 'description'
        ]
        read_only_fields = fields  # All fields are read-only

    def get_content_type_name(self, obj):
        """Return human-readable content type name"""
        return f"{obj.content_type.app_label}.{obj.content_type.model}"

    def get_object_repr(self, obj):
        """Return string representation of the affected object"""
        try:
            return str(obj.content_object)
        except:
            return f"{obj.content_type} #{obj.object_id}"


# Mapping of model classes to their serializers
RR_SERIALIZERS = {
    A: ASerializer,
    AAAA: AAAASerializer,
    CNAME: CNAMESerializer,
    MX: MXSerializer,
    NS: NSSerializer,
    PTR: PTRSerializer,
    SRV: SRVSerializer,
    TXT: TXTSerializer,
    CAA: CAASerializer,
    DS: DSSerializer,
    DNSKEY: DNSKEYSerializer,
    TLSA: TLSASerializer,
}


class SOASerializer(serializers.ModelSerializer):
    """Serializer for SOA records"""
    zone_origin = serializers.CharField(source='zone.origin', read_only=True)

    class Meta:
        model = SOA
        fields = [
            'id', 'zone', 'zone_origin', 'name', 'rrclass', 'ttl',
            'mname', 'rname', 'serial', 'refresh', 'retry', 'expire', 'minimum',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


class SlaveOnlyZoneSerializer(serializers.ModelSerializer):
    """Serializer for slave-only zones"""
    owner = UserSerializer(read_only=True)
    group = GroupSerializer(read_only=True)
    owner_id = serializers.PrimaryKeyRelatedField(
        queryset=User.objects.all(),
        source='owner',
        write_only=True
    )
    group_id = serializers.PrimaryKeyRelatedField(
        queryset=Group.objects.all(),
        source='group',
        write_only=True
    )
    slave_servers = ServerSerializer(many=True, read_only=True)
    slave_server_ids = serializers.PrimaryKeyRelatedField(
        queryset=Server.objects.all(),
        source='slave_servers',
        write_only=True,
        many=True
    )

    class Meta:
        model = SlaveOnlyZone
        fields = [
            'id', 'origin', 'external_master', 'slave_servers', 'slave_server_ids',
            'owner', 'owner_id', 'group', 'group_id',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']
        extra_kwargs = {
            'origin': {'validators': []},  # We'll handle validation in the view
        }
