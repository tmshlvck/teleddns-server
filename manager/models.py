"""
TeleDDNS Server - Manager App Models
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

import re
import ipaddress
from django.db import models
from django.contrib.auth.models import User, Group
from django.contrib.contenttypes.models import ContentType
from django.contrib.contenttypes.fields import GenericForeignKey
from django.core.exceptions import ValidationError
from django.utils import timezone
from django.conf import settings


# Regular expressions for validation
ORIGIN_REGEX = re.compile(r"^((?![0-9]+$)(?!-)[a-zA-Z0-9\.-]{,1024}(?<!-))\.$")
NAME_REGEX = re.compile(r"^((?![0-9]+$)(?!-)[a-zA-Z0-9\.-]{,1024}(?<!-))$")
RRLABEL_REGEX = re.compile(r"^(?![0-9]+$)(?!-)[a-zA-Z0-9\.-]{,63}(?<!-)$")
DNSNAME_REGEX = re.compile(r"^[a-zA-Z0-9\.-]+$")


def generate_soa_serial():
    """Generate a new SOA serial number in YYYYMMDDNN format"""
    from django.utils import timezone
    now = timezone.now()
    # Format: YYYYMMDD01
    return int(now.strftime('%Y%m%d') + '01')


def validate_origin(value):
    """Validate DNS zone origin"""
    value = value.strip()
    if not ORIGIN_REGEX.match(value):
        raise ValidationError(f"Origin {value} is not a valid DNS zone origin")
    return value


def validate_dns_name(value):
    """Validate generic DNS name"""
    value = value.strip()
    if value == '@':
        return value
    if not NAME_REGEX.match(value):
        raise ValidationError(f"Name {value} is not a valid DNS name")
    return value


def validate_rr_label(value):
    """Validate resource record label"""
    value = value.strip()
    if value == '@':
        return value
    if not RRLABEL_REGEX.match(value):
        raise ValidationError(f"Label {value} is not a valid resource record label")
    return value


def validate_dns_hostname(value):
    """Validate DNS hostname for RR values"""
    value = value.strip()
    if not DNSNAME_REGEX.match(value):
        raise ValidationError(f"Hostname {value} is not a valid DNS hostname")
    return value


def validate_ipv4(value):
    """Validate IPv4 address"""
    try:
        ipaddress.IPv4Address(value)
    except ValueError:
        raise ValidationError(f"{value} is not a valid IPv4 address")
    return value


def validate_ipv6(value):
    """Validate IPv6 address"""
    try:
        ipaddress.IPv6Address(value)
    except ValueError:
        raise ValidationError(f"{value} is not a valid IPv6 address")
    return value


class Server(models.Model):
    """DNS server backend configuration"""
    name = models.CharField(max_length=255, unique=True)
    api_url = models.URLField(max_length=500, help_text="API endpoint URL for the DNS server")
    api_key = models.CharField(max_length=255, help_text="API authentication key")
    master_template = models.CharField(max_length=100, help_text="Template name for master zones")
    slave_template = models.CharField(max_length=100, help_text="Template name for slave zones")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "DNS Server"
        verbose_name_plural = "DNS Servers"
        ordering = ['name']

    def __str__(self):
        return self.name


class Zone(models.Model):
    """DNS Zone with SOA record"""
    RRCLASS_CHOICES = [
        ('IN', 'IN'),
    ]

    # Zone identification
    origin = models.CharField(
        max_length=255,
        unique=True,
        validators=[validate_origin],
        help_text="Zone origin (e.g., example.com.)"
    )

    # Ownership and permissions
    owner = models.ForeignKey(User, on_delete=models.PROTECT, related_name='owned_zones')
    group = models.ForeignKey(Group, on_delete=models.PROTECT, related_name='zones')

    # Server relationships
    master_server = models.ForeignKey(
        Server,
        on_delete=models.PROTECT,
        related_name='master_zones',
        help_text="Primary DNS server hosting this zone"
    )
    slave_servers = models.ManyToManyField(
        Server,
        related_name='slave_zones',
        blank=True,
        help_text="Secondary DNS servers for this zone"
    )

    # Status tracking
    content_dirty = models.BooleanField(
        default=False,
        help_text="Zone content (resource records) has pending changes that need to be synchronized"
    )
    content_dirty_since = models.DateTimeField(
        null=True,
        blank=True,
        help_text="When content was marked dirty"
    )
    master_config_dirty = models.BooleanField(
        default=False,
        help_text="Master server configuration has changed and needs reload"
    )
    master_config_dirty_since = models.DateTimeField(
        null=True,
        blank=True,
        help_text="When master config was marked dirty"
    )

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "DNS Zone"
        verbose_name_plural = "DNS Zones"
        ordering = ['origin']
        permissions = [
            ("sync_zone", "Can synchronize zone to DNS server"),
        ]

    def __str__(self):
        return self.origin

    def format_bind_zone(self):
        """Format zone header in BIND format"""
        # This method is deprecated - use SOA model instead
        if hasattr(self, 'soa'):
            return (
                f"$ORIGIN {self.origin};\n"
                f"$TTL {settings.DDNS_DEFAULT_TTL};\n"
                f"{self.soa.format_bind_zone()}"
            )
        else:
            # Return basic zone header without SOA
            return f"$ORIGIN {self.origin};\n$TTL {settings.DDNS_DEFAULT_TTL};"

    def increment_serial(self):
        """Increment zone serial number"""
        # Increment serial through SOA record
        if hasattr(self, 'soa'):
            self.soa.increment_serial()
        else:
            raise ValueError(f"Zone {self.origin} has no associated SOA record")


class SOA(models.Model):
    """SOA (Start of Authority) record for a zone"""
    RRCLASS_CHOICES = [
        ('IN', 'IN'),
    ]

    zone = models.OneToOneField(
        Zone,
        on_delete=models.CASCADE,
        related_name='soa',
        help_text="Zone this SOA record belongs to"
    )

    # SOA fields
    name = models.CharField(
        max_length=255,
        default='@',
        validators=[validate_dns_name],
        help_text="SOA record name (usually @)"
    )
    rrclass = models.CharField(
        max_length=2,
        choices=RRCLASS_CHOICES,
        default='IN',
        db_column='class'
    )
    ttl = models.PositiveIntegerField(
        default=3600,
        help_text="SOA record TTL in seconds"
    )
    mname = models.CharField(
        max_length=255,
        validators=[validate_dns_name],
        help_text="Primary name server"
    )
    rname = models.CharField(
        max_length=255,
        validators=[validate_dns_name],
        help_text="Responsible person email (replace @ with .)"
    )
    serial = models.PositiveBigIntegerField(
        default=generate_soa_serial,
        help_text="Zone serial number (YYYYMMDDNN format)"
    )
    refresh = models.PositiveIntegerField(
        default=86400,
        help_text="Refresh interval in seconds"
    )
    retry = models.PositiveIntegerField(
        default=7200,
        help_text="Retry interval in seconds"
    )
    expire = models.PositiveIntegerField(
        default=3600000,
        help_text="Expire time in seconds"
    )
    minimum = models.PositiveIntegerField(
        default=172800,
        help_text="Minimum TTL in seconds"
    )

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "SOA Record"
        verbose_name_plural = "SOA Records"

    def __str__(self):
        return f"SOA for {self.zone.origin}"

    def format_bind_zone(self):
        """Format SOA record in BIND format"""
        return (
            f"{self.name:<63} {self.ttl:<5} {self.rrclass:<2} SOA "
            f"{self.mname} {self.rname.replace('@', '.')} "
            f"{self.serial} {self.refresh} {self.retry} "
            f"{self.expire} {self.minimum}"
        )

    def increment_serial(self):
        """Increment the serial number using YYYYMMDDNN format"""
        from django.utils import timezone
        now = timezone.now()
        today_prefix = int(now.strftime('%Y%m%d'))

        # Extract the date part and sequence part from current serial
        current_date = self.serial // 100
        current_seq = self.serial % 100

        if current_date == today_prefix:
            # Same day, increment sequence
            new_seq = current_seq + 1
            if new_seq > 99:
                # Can't increment further today
                raise ValueError(f"Serial number sequence exhausted for {now.strftime('%Y-%m-%d')}")
            self.serial = today_prefix * 100 + new_seq
        else:
            # Different day, start with 01
            self.serial = today_prefix * 100 + 1

        self.save(update_fields=['serial', 'updated_at'])


class SlaveOnlyZone(models.Model):
    """DNS Zone that only has slave servers with external master"""

    # Zone identification
    origin = models.CharField(
        max_length=255,
        unique=True,
        validators=[validate_origin],
        help_text="Zone origin (e.g., example.com.)"
    )

    # External master server
    external_master = models.CharField(
        max_length=255,
        validators=[validate_dns_hostname],
        help_text="External master server hostname or IP address"
    )

    # Slave servers
    slave_servers = models.ManyToManyField(
        Server,
        related_name='slave_only_zones',
        help_text="Slave DNS servers for this zone"
    )

    # Ownership and permissions
    owner = models.ForeignKey(User, on_delete=models.PROTECT, related_name='owned_slave_only_zones')
    group = models.ForeignKey(Group, on_delete=models.PROTECT, related_name='slave_only_zones')

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Slave Only Zone"
        verbose_name_plural = "Slave Only Zones"
        ordering = ['origin']
        permissions = [
            ("sync_slave_only_zone", "Can synchronize slave only zone to DNS server"),
        ]

    def __str__(self):
        return f"{self.origin} (slave only)"


class ResourceRecord(models.Model):
    """Abstract base class for all resource records"""
    RRCLASS_CHOICES = [
        ('IN', 'IN'),
    ]

    zone = models.ForeignKey(Zone, on_delete=models.CASCADE)
    label = models.CharField(
        max_length=255,
        validators=[validate_rr_label],
        help_text="Record label (e.g., www, @, or subdomain)"
    )
    ttl = models.PositiveIntegerField(
        default=3600,
        help_text="Time to live in seconds"
    )
    rrclass = models.CharField(
        max_length=2,
        choices=RRCLASS_CHOICES,
        default='IN',
        db_column='class'
    )

    # Ownership
    owner = models.ForeignKey(User, on_delete=models.PROTECT)
    group = models.ForeignKey(Group, on_delete=models.PROTECT)

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True
        ordering = ['label', 'created_at']
        indexes = [
            models.Index(fields=['zone', 'label']),
        ]

    def __str__(self):
        return f"{self.label} {self.__class__.__name__}"


class A(ResourceRecord):
    """IPv4 Address record"""
    value = models.CharField(
        max_length=15,
        validators=[validate_ipv4],
        help_text="IPv4 address"
    )

    class Meta:
        verbose_name = "A Record"
        verbose_name_plural = "A Records"

    def format_bind_zone(self):
        return f"{self.label:<63} {self.ttl:<5} {self.rrclass:<2} A {self.value}"


class AAAA(ResourceRecord):
    """IPv6 Address record"""
    value = models.CharField(
        max_length=39,
        validators=[validate_ipv6],
        help_text="IPv6 address"
    )

    class Meta:
        verbose_name = "AAAA Record"
        verbose_name_plural = "AAAA Records"

    def format_bind_zone(self):
        return f"{self.label:<63} {self.ttl:<5} {self.rrclass:<2} AAAA {self.value}"


class CNAME(ResourceRecord):
    """Canonical name record"""
    value = models.CharField(
        max_length=255,
        validators=[validate_dns_hostname],
        help_text="Target hostname"
    )

    class Meta:
        verbose_name = "CNAME Record"
        verbose_name_plural = "CNAME Records"

    def format_bind_zone(self):
        return f"{self.label:<63} {self.ttl:<5} {self.rrclass:<2} CNAME {self.value}"


class MX(ResourceRecord):
    """Mail exchanger record"""
    priority = models.PositiveSmallIntegerField(
        help_text="Priority (lower values have higher priority)"
    )
    value = models.CharField(
        max_length=255,
        validators=[validate_dns_hostname],
        help_text="Mail server hostname"
    )

    class Meta:
        verbose_name = "MX Record"
        verbose_name_plural = "MX Records"
        ordering = ['label', 'priority', 'created_at']

    def format_bind_zone(self):
        return f"{self.label:<63} {self.ttl:<5} {self.rrclass:<2} MX {self.priority} {self.value}"


class NS(ResourceRecord):
    """Name server record"""
    value = models.CharField(
        max_length=255,
        validators=[validate_dns_hostname],
        help_text="Name server hostname"
    )

    class Meta:
        verbose_name = "NS Record"
        verbose_name_plural = "NS Records"

    def format_bind_zone(self):
        return f"{self.label:<63} {self.ttl:<5} {self.rrclass:<2} NS {self.value}"


class PTR(ResourceRecord):
    """Pointer record"""
    value = models.CharField(
        max_length=255,
        validators=[validate_dns_hostname],
        help_text="Target hostname"
    )

    class Meta:
        verbose_name = "PTR Record"
        verbose_name_plural = "PTR Records"

    def format_bind_zone(self):
        return f"{self.label:<63} {self.ttl:<5} {self.rrclass:<2} PTR {self.value}"


class SRV(ResourceRecord):
    """Service record"""
    priority = models.PositiveSmallIntegerField(help_text="Priority")
    weight = models.PositiveSmallIntegerField(help_text="Weight")
    port = models.PositiveIntegerField(help_text="Port number")
    value = models.CharField(
        max_length=255,
        validators=[validate_dns_hostname],
        help_text="Target hostname"
    )

    class Meta:
        verbose_name = "SRV Record"
        verbose_name_plural = "SRV Records"
        ordering = ['label', 'priority', 'weight', 'created_at']

    def clean(self):
        """Override label validation for SRV records"""
        # SRV records can have special labels like _service._proto
        self.label = self.label.strip()
        super().clean()

    def format_bind_zone(self):
        return f"{self.label:<63} {self.ttl:<5} {self.rrclass:<2} SRV {self.priority} {self.weight} {self.port} {self.value}"


class TXT(ResourceRecord):
    """Text record"""
    value = models.TextField(help_text="Text content")

    class Meta:
        verbose_name = "TXT Record"
        verbose_name_plural = "TXT Records"

    def format_bind_zone(self):
        # Escape quotes in the value
        escaped_value = self.value.replace('"', '\\"')
        return f'{self.label:<63} {self.ttl:<5} {self.rrclass:<2} TXT "{escaped_value}"'


class CAA(ResourceRecord):
    """Certification Authority Authorization record"""
    TAG_CHOICES = [
        ('issue', 'issue'),
        ('issuewild', 'issuewild'),
        ('iodef', 'iodef'),
        ('contactemail', 'contactemail'),
        ('contactphone', 'contactphone'),
    ]

    flag = models.PositiveSmallIntegerField(
        default=0,
        help_text="CAA flag (usually 0)"
    )
    tag = models.CharField(
        max_length=20,
        choices=TAG_CHOICES,
        help_text="CAA property tag"
    )
    value = models.CharField(
        max_length=255,
        help_text="CAA property value"
    )

    class Meta:
        verbose_name = "CAA Record"
        verbose_name_plural = "CAA Records"

    def format_bind_zone(self):
        return f'{self.label:<63} {self.ttl:<5} {self.rrclass:<2} CAA {self.flag} {self.tag} "{self.value}"'


class DS(ResourceRecord):
    """Delegation Signer record"""
    key_tag = models.PositiveIntegerField(help_text="Key tag")
    algorithm = models.PositiveSmallIntegerField(help_text="Algorithm number")
    digest_type = models.PositiveSmallIntegerField(help_text="Digest type")
    digest = models.CharField(max_length=255, help_text="Digest value (hex)")

    class Meta:
        verbose_name = "DS Record"
        verbose_name_plural = "DS Records"

    def format_bind_zone(self):
        return f"{self.label:<63} {self.ttl:<5} {self.rrclass:<2} DS {self.key_tag} {self.algorithm} {self.digest_type} {self.digest}"


class DNSKEY(ResourceRecord):
    """DNS Key record"""
    flags = models.PositiveIntegerField(help_text="Key flags")
    protocol = models.PositiveSmallIntegerField(default=3, help_text="Protocol (always 3)")
    algorithm = models.PositiveSmallIntegerField(help_text="Algorithm number")
    public_key = models.TextField(help_text="Base64 encoded public key")

    class Meta:
        verbose_name = "DNSKEY Record"
        verbose_name_plural = "DNSKEY Records"

    def format_bind_zone(self):
        return f"{self.label:<63} {self.ttl:<5} {self.rrclass:<2} DNSKEY {self.flags} {self.protocol} {self.algorithm} {self.public_key}"


class TLSA(ResourceRecord):
    """Transport Layer Security Authentication record"""
    usage = models.PositiveSmallIntegerField(help_text="Certificate usage")
    selector = models.PositiveSmallIntegerField(help_text="Selector")
    matching_type = models.PositiveSmallIntegerField(help_text="Matching type")
    certificate_data = models.TextField(help_text="Certificate association data (hex)")

    class Meta:
        verbose_name = "TLSA Record"
        verbose_name_plural = "TLSA Records"

    def format_bind_zone(self):
        return f"{self.label:<63} {self.ttl:<5} {self.rrclass:<2} TLSA {self.usage} {self.selector} {self.matching_type} {self.certificate_data}"


# List of all RR model classes for iteration
RR_MODELS = [A, AAAA, CNAME, MX, NS, PTR, SRV, TXT, CAA, DS, DNSKEY, TLSA]


class ZoneServerStatus(models.Model):
    """Track synchronization status between a Zone and a Server"""
    zone = models.ForeignKey(
        'Zone',
        on_delete=models.CASCADE,
        related_name='server_statuses'
    )
    server = models.ForeignKey(
        'Server',
        on_delete=models.CASCADE,
        related_name='zone_statuses'
    )

    # Status tracking
    config_dirty = models.BooleanField(
        default=False,
        help_text="Server configuration for this zone needs update"
    )
    config_dirty_since = models.DateTimeField(
        null=True,
        blank=True,
        help_text="When config was marked dirty"
    )
    last_sync_time = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Last successful synchronization time"
    )

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = [('zone', 'server')]
        verbose_name = "Zone Server Status"
        verbose_name_plural = "Zone Server Statuses"

    def __str__(self):
        return f"{self.zone.origin} on {self.server.name}"


class SlaveOnlyZoneServerStatus(models.Model):
    """Track synchronization status between a SlaveOnlyZone and a Server"""
    zone = models.ForeignKey(
        'SlaveOnlyZone',
        on_delete=models.CASCADE,
        related_name='server_statuses'
    )
    server = models.ForeignKey(
        'Server',
        on_delete=models.CASCADE,
        related_name='slave_only_zone_statuses'
    )

    # Status tracking
    config_dirty = models.BooleanField(
        default=False,
        help_text="Server configuration for this zone needs update"
    )
    config_dirty_since = models.DateTimeField(
        null=True,
        blank=True,
        help_text="When config was marked dirty"
    )
    last_sync_time = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Last successful synchronization time"
    )

    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = [('zone', 'server')]
        verbose_name = "Slave Only Zone Server Status"
        verbose_name_plural = "Slave Only Zone Server Statuses"

    def __str__(self):
        return f"{self.zone.origin} on {self.server.name}"


class AuditLog(models.Model):
    """Audit log for tracking all changes"""
    ACTION_CHOICES = [
        ('CREATE', 'Create'),
        ('UPDATE', 'Update'),
        ('DELETE', 'Delete'),
    ]

    SOURCE_CHOICES = [
        ('DDNS', 'DDNS Update'),
        ('API', 'REST API'),
        ('ADMIN', 'Admin Interface'),
        ('SYSTEM', 'System'),
    ]

    timestamp = models.DateTimeField(default=timezone.now, db_index=True)
    user = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        related_name='audit_logs'
    )
    source = models.CharField(max_length=10, choices=SOURCE_CHOICES)
    action = models.CharField(max_length=10, choices=ACTION_CHOICES)

    # Generic relation to any model
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE)
    object_id = models.PositiveBigIntegerField()
    content_object = GenericForeignKey('content_type', 'object_id')

    # JSON snapshot of the changed data
    changed_data = models.JSONField(
        help_text="Snapshot of the changed data"
    )

    # Optional description
    description = models.TextField(blank=True)

    class Meta:
        verbose_name = "Audit Log Entry"
        verbose_name_plural = "Audit Log Entries"
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['-timestamp', 'user']),
            models.Index(fields=['content_type', 'object_id']),
        ]

    def __str__(self):
        return f"{self.timestamp} - {self.user} - {self.action} - {self.content_type}"
