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

    # SOA fields
    soa_name = models.CharField(
        max_length=255,
        default='@',
        validators=[validate_dns_name],
        db_column='soa_NAME',
        help_text="SOA record name (usually @)"
    )
    soa_class = models.CharField(
        max_length=2,
        choices=RRCLASS_CHOICES,
        default='IN',
        db_column='soa_CLASS'
    )
    soa_ttl = models.PositiveIntegerField(
        default=3600,
        db_column='soa_TTL',
        help_text="SOA record TTL in seconds"
    )
    soa_mname = models.CharField(
        max_length=255,
        validators=[validate_dns_name],
        db_column='soa_MNAME',
        help_text="Primary name server"
    )
    soa_rname = models.CharField(
        max_length=255,
        validators=[validate_dns_name],
        db_column='soa_RNAME',
        help_text="Responsible person email (replace @ with .)"
    )
    soa_serial = models.PositiveBigIntegerField(
        db_column='soa_SERIAL',
        help_text="Zone serial number"
    )
    soa_refresh = models.PositiveIntegerField(
        default=86400,
        db_column='soa_REFRESH',
        help_text="Refresh interval in seconds"
    )
    soa_retry = models.PositiveIntegerField(
        default=7200,
        db_column='soa_RETRY',
        help_text="Retry interval in seconds"
    )
    soa_expire = models.PositiveIntegerField(
        default=3600000,
        db_column='soa_EXPIRE',
        help_text="Expire time in seconds"
    )
    soa_minimum = models.PositiveIntegerField(
        default=172800,
        db_column='soa_MINIMUM',
        help_text="Minimum TTL in seconds"
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

    # Status
    is_dirty = models.BooleanField(
        default=False,
        help_text="Zone has pending changes that need to be synchronized"
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
        return (
            f"$ORIGIN {self.origin};\n"
            f"$TTL {settings.DDNS_DEFAULT_TTL};\n"
            f"{self.soa_name:<63} {self.soa_ttl:<5} {self.soa_class:<2} SOA "
            f"{self.soa_mname} {self.soa_rname.replace('@', '.')} "
            f"{self.soa_serial} {self.soa_refresh} {self.soa_retry} "
            f"{self.soa_expire} {self.soa_minimum}"
        )

    def increment_serial(self):
        """Increment zone serial number"""
        self.soa_serial += 1
        self.save(update_fields=['soa_serial', 'updated_at'])


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
