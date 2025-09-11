from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.validators import RegexValidator
from django.core.exceptions import ValidationError
import ipaddress
import re


class User(AbstractUser):
    """Extended user model with 2FA and SSO support"""
    
    # 2FA TOTP fields
    totp_secret = models.CharField(max_length=32, null=True, blank=True)
    totp_enabled = models.BooleanField(default=False)
    totp_backup_codes = models.TextField(null=True, blank=True)
    
    # SSO Integration
    sso_provider = models.CharField(max_length=50, null=True, blank=True)
    sso_subject_id = models.CharField(max_length=255, null=True, blank=True)
    sso_enabled = models.BooleanField(default=False)
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_update_metadata = models.TextField(blank=True, default='')
    
    def __str__(self):
        return self.username


class UserToken(models.Model):
    """API Bearer tokens for REST API authentication"""
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='api_tokens')
    token_hash = models.CharField(max_length=64, unique=True)
    description = models.CharField(max_length=255, blank=True, default='')
    
    expires_at = models.DateTimeField(null=True, blank=True)
    last_used = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    scopes = models.CharField(max_length=255, default='*')
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_update_metadata = models.TextField(blank=True, default='')
    
    def __str__(self):
        return f"{self.description or 'Token'} ({self.user.username})"
    
    @staticmethod
    def hash(token: str) -> str:
        """Hash a token for storage in database."""
        import hashlib
        return hashlib.sha256(token.encode('utf-8')).hexdigest()
    
    @staticmethod
    def generate_token() -> str:
        """Generate a new random token."""
        import secrets
        return secrets.token_urlsafe(32)
    
    def save(self, *args, **kwargs):
        """Override save to auto-generate token if not provided."""
        if not self.token_hash:
            # Generate new token and hash it
            token = self.generate_token()
            self.token_hash = self.hash(token)
            # Store the plain token temporarily for retrieval
            self._plain_token = token
        super().save(*args, **kwargs)
    
    def get_plain_token(self) -> str:
        """Get the plain token (only available after creation)."""
        return getattr(self, '_plain_token', None)
    
    class Meta:
        db_table = 'usertoken'


class UserPassKey(models.Model):
    """WebAuthn/PassKey credentials"""
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='passkeys')
    credential_id = models.CharField(max_length=255, unique=True)
    public_key = models.TextField()
    sign_count = models.PositiveIntegerField(default=0)
    
    name = models.CharField(max_length=255, blank=True, default='')
    last_used = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_update_metadata = models.TextField(blank=True, default='')
    
    class Meta:
        db_table = 'userpasskey'


class Group(models.Model):
    """User groups for permissions"""
    
    name = models.CharField(max_length=255, unique=True)
    description = models.TextField(blank=True, default='')
    users = models.ManyToManyField(User, through='UserGroup', related_name='user_groups')
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_update_metadata = models.TextField(blank=True, default='')
    
    def __str__(self):
        return self.name


class UserGroup(models.Model):
    """Many-to-many relationship between users and groups"""
    
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    group = models.ForeignKey(Group, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        unique_together = ('user', 'group')
        db_table = 'usergroup'


class Server(models.Model):
    """DNS Master/Slave server configuration"""
    
    name = models.CharField(max_length=255)
    api_url = models.URLField()
    api_key = models.CharField(max_length=255)
    master_template = models.TextField()
    slave_template = models.TextField()
    is_active = models.BooleanField(default=True)
    
    # Owner and group assignment
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='owned_servers')
    group = models.ForeignKey(Group, on_delete=models.SET_NULL, null=True, blank=True, related_name='group_servers')
    
    # Server status tracking
    last_config_sync = models.DateTimeField(null=True, blank=True)
    config_dirty = models.BooleanField(default=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_update_metadata = models.TextField(blank=True, default='')
    
    def save(self, *args, **kwargs):
        """Override save to mark server config as dirty when changed."""
        # Check if this is an update
        is_update = self.pk is not None
        
        if is_update:
            # Check if config-related fields changed
            old_instance = Server.objects.get(pk=self.pk)
            config_changed = (
                old_instance.api_url != self.api_url or
                old_instance.api_key != self.api_key or
                old_instance.master_template != self.master_template or
                old_instance.slave_template != self.slave_template
            )
            
            if config_changed:
                self.config_dirty = True
                self.last_update_metadata = 'Server configuration updated'
                
                # Trigger background sync after save
                super().save(*args, **kwargs)
                
                try:
                    from .sync import trigger_background_sync
                    trigger_background_sync()
                except ImportError:
                    pass  # Sync module may not be available during migrations
                return
        
        super().save(*args, **kwargs)
    
    def __str__(self):
        return self.name


class RRClass(models.TextChoices):
    """DNS RR Class"""
    IN = 'IN', 'Internet'


class MasterZone(models.Model):
    """DNS zone configuration with embedded SOA record"""
    
    # Zone origin (must end with .)
    origin = models.CharField(
        max_length=255, 
        validators=[RegexValidator(
            regex=r'^((?![0-9]+$)(?!-)[a-zA-Z0-9\.-]{,1024}(?<!-))\.$',
            message='Origin must be a valid DNS name ending with a dot'
        )]
    )
    
    # SOA Record fields (embedded since there's exactly one SOA per zone)
    soa_name = models.CharField(
        max_length=255, 
        validators=[RegexValidator(
            regex=r'^(@|((?![0-9]+$)(?!-)[a-zA-Z0-9\.-]{,1024}(?<!-)))$',
            message='SOA name must be @ or a valid DNS name'
        )]
    )
    soa_class = models.CharField(max_length=10, choices=RRClass.choices, default=RRClass.IN)
    soa_ttl = models.PositiveIntegerField(default=3600)
    soa_mname = models.CharField(
        max_length=255,
        validators=[RegexValidator(
            regex=r'^(@|((?![0-9]+$)(?!-)[a-zA-Z0-9\.-]{,1024}(?<!-)))$',
            message='SOA MNAME must be @ or a valid DNS name'
        )]
    )
    soa_rname = models.CharField(
        max_length=255,
        validators=[RegexValidator(
            regex=r'^(@|((?![0-9]+$)(?!-)[a-zA-Z0-9\.-]{,1024}(?<!-)))$',
            message='SOA RNAME must be @ or a valid DNS name'
        )]
    )
    soa_serial = models.PositiveIntegerField()
    soa_refresh = models.PositiveIntegerField(default=3600)
    soa_retry = models.PositiveIntegerField(default=1800)
    soa_expire = models.PositiveIntegerField(default=1209600)  # 2 weeks
    soa_minimum = models.PositiveIntegerField(default=86400)   # 1 day
    
    # Owner and group assignment
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='owned_zones')
    group = models.ForeignKey(Group, on_delete=models.SET_NULL, null=True, blank=True, related_name='group_zones')
    
    # Server assignments
    master_server = models.ForeignKey(Server, on_delete=models.SET_NULL, null=True, blank=True, related_name='master_zones')
    slave_servers = models.ManyToManyField(Server, through='SlaveZoneServer', related_name='slave_zones')
    
    # Backend sync tracking
    content_dirty = models.BooleanField(default=True)
    last_content_sync = models.DateTimeField(null=True, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_update_metadata = models.TextField(blank=True, default='')
    
    def save(self, *args, **kwargs):
        """Override save to mark zone content as dirty when SOA fields change."""
        # Check if this is an update
        is_update = self.pk is not None
        
        if is_update:
            # Check if SOA-related fields changed
            old_instance = MasterZone.objects.get(pk=self.pk)
            soa_changed = (
                old_instance.soa_name != self.soa_name or
                old_instance.soa_ttl != self.soa_ttl or
                old_instance.soa_mname != self.soa_mname or
                old_instance.soa_rname != self.soa_rname or
                old_instance.soa_refresh != self.soa_refresh or
                old_instance.soa_retry != self.soa_retry or
                old_instance.soa_expire != self.soa_expire or
                old_instance.soa_minimum != self.soa_minimum
            )
            
            if soa_changed:
                self.content_dirty = True
                self.last_update_metadata = 'Zone SOA record updated'
                
                # Trigger background sync after save
                super().save(*args, **kwargs)
                
                try:
                    from .sync import trigger_background_sync
                    trigger_background_sync()
                except ImportError:
                    pass  # Sync module may not be available during migrations
                return
        
        super().save(*args, **kwargs)
    
    def __str__(self):
        return self.origin
    
    def format_bind_zone_header(self):
        """Format the SOA record for BIND zone file"""
        return f"""$ORIGIN {self.origin}
$TTL {self.soa_ttl}
{self.soa_name:<63} {self.soa_ttl:<5} {self.soa_class:<2} SOA {self.soa_mname} {self.soa_rname.replace('@', '.')} {self.soa_serial} {self.soa_refresh} {self.soa_retry} {self.soa_expire} {self.soa_minimum}"""


class SlaveZoneServer(models.Model):
    """Many-to-many relationship between zones and slave servers"""
    
    zone = models.ForeignKey(MasterZone, on_delete=models.CASCADE)
    server = models.ForeignKey(Server, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        unique_together = ('zone', 'server')
        db_table = 'slavezoneserver'


class UserLabelAuthorization(models.Model):
    """User-specific zone label permissions"""
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='label_authorizations')
    zone = models.ForeignKey(MasterZone, on_delete=models.CASCADE)
    label_pattern = models.CharField(max_length=255)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_update_metadata = models.TextField(blank=True, default='')
    
    def verify_access(self, label):
        """Check if label matches the pattern"""
        if not self.label_pattern:
            return True
        return bool(re.match(self.label_pattern, label))
    
    class Meta:
        db_table = 'userlabelauthorization'


class GroupLabelAuthorization(models.Model):
    """Group-specific zone label permissions"""
    
    group = models.ForeignKey(Group, on_delete=models.CASCADE, related_name='label_authorizations')
    zone = models.ForeignKey(MasterZone, on_delete=models.CASCADE)
    label_pattern = models.CharField(max_length=255)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_update_metadata = models.TextField(blank=True, default='')
    
    def verify_access(self, label):
        """Check if label matches the pattern"""
        if not self.label_pattern:
            return True
        return bool(re.match(self.label_pattern, label))
    
    class Meta:
        db_table = 'grouplabelauthorization'


# DNS Record Models
class ResourceRecord(models.Model):
    """Abstract base class for all DNS resource records"""
    
    zone = models.ForeignKey(MasterZone, on_delete=models.CASCADE, related_name='%(class)s_records')
    label = models.CharField(
        max_length=63,
        validators=[RegexValidator(
            regex=r'^(@|((?![0-9]+$)(?!-)[a-zA-Z0-9_\.-]{,63}(?<!-)))$',
            message='Label must be @ or a valid DNS label'
        )]
    )
    ttl = models.PositiveIntegerField(default=3600)
    rrclass = models.CharField(max_length=10, choices=RRClass.choices, default=RRClass.IN)
    value = models.TextField()
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_update_metadata = models.TextField(blank=True, default='')
    
    class Meta:
        abstract = True
    
    def save(self, *args, **kwargs):
        """Override save to mark zone as dirty when record changes."""
        # Check if this is an update by looking at the primary key
        is_update = self.pk is not None
        
        # Save the record first
        super().save(*args, **kwargs)
        
        # Mark the zone as dirty and trigger sync
        if self.zone_id:
            from datetime import datetime, timezone
            from .sync import trigger_background_sync
            
            # Update zone dirty flag
            MasterZone.objects.filter(id=self.zone_id).update(
                content_dirty=True,
                last_update_metadata=f'DNS record {"updated" if is_update else "created"}: {self.__class__.__name__} {self.label}'
            )
            
            # Trigger background sync
            trigger_background_sync()
    
    def delete(self, *args, **kwargs):
        """Override delete to mark zone as dirty when record is deleted."""
        zone_id = self.zone_id
        record_info = f'{self.__class__.__name__} {self.label}'
        
        # Delete the record first
        super().delete(*args, **kwargs)
        
        # Mark the zone as dirty and trigger sync
        if zone_id:
            from datetime import datetime, timezone
            from .sync import trigger_background_sync
            
            # Update zone dirty flag
            MasterZone.objects.filter(id=zone_id).update(
                content_dirty=True,
                last_update_metadata=f'DNS record deleted: {record_info}'
            )
            
            # Trigger background sync
            trigger_background_sync()
    
    def format_bind_zone(self):
        """Format record for BIND zone file - to be overridden by subclasses"""
        record_type = self.__class__.__name__.upper()
        return f"{self.label:<63} {self.ttl:<5} {self.rrclass:<2} {record_type}\t{self.value}"


# Concrete DNS Record Types
class A(ResourceRecord):
    """IPv4 address record"""
    
    def clean(self):
        try:
            ipaddress.IPv4Address(self.value)
        except ipaddress.AddressValueError:
            raise ValidationError({'value': 'Invalid IPv4 address'})
    
    def format_bind_zone(self):
        return f"{self.label:<63} {self.ttl:<5} {self.rrclass:<2} A\t{self.value}"


class AAAA(ResourceRecord):
    """IPv6 address record"""
    
    def clean(self):
        try:
            ipaddress.IPv6Address(self.value)
        except ipaddress.AddressValueError:
            raise ValidationError({'value': 'Invalid IPv6 address'})
    
    def format_bind_zone(self):
        return f"{self.label:<63} {self.ttl:<5} {self.rrclass:<2} AAAA\t{self.value}"


class NS(ResourceRecord):
    """Name server record"""
    
    def clean(self):
        if not re.match(r'^[a-zA-Z0-9\.-]+$', self.value):
            raise ValidationError({'value': 'Invalid DNS name for NS record'})
    
    def format_bind_zone(self):
        return f"{self.label:<63} {self.ttl:<5} {self.rrclass:<2} NS\t{self.value}"


class PTR(ResourceRecord):
    """Pointer record"""
    
    def clean(self):
        if not re.match(r'^[a-zA-Z0-9\.-]+$', self.value):
            raise ValidationError({'value': 'Invalid DNS name for PTR record'})
    
    def format_bind_zone(self):
        return f"{self.label:<63} {self.ttl:<5} {self.rrclass:<2} PTR\t{self.value}"


class CNAME(ResourceRecord):
    """Canonical name record"""
    
    def clean(self):
        if not re.match(r'^[a-zA-Z0-9\.-]+$', self.value):
            raise ValidationError({'value': 'Invalid DNS name for CNAME record'})
    
    def format_bind_zone(self):
        return f"{self.label:<63} {self.ttl:<5} {self.rrclass:<2} CNAME\t{self.value}"


class TXT(ResourceRecord):
    """Text record"""
    
    def format_bind_zone(self):
        return f'{self.label:<63} {self.ttl:<5} {self.rrclass:<2} TXT\t"{self.value}"'


class CAATag(models.TextChoices):
    """CAA record tags"""
    ISSUE = 'issue', 'Issue'
    ISSUEWILD = 'issuewild', 'Issue Wild'
    IODEF = 'iodef', 'IODEF'
    CONTACTEMAIL = 'contactemail', 'Contact Email'
    CONTACTPHONE = 'contactphone', 'Contact Phone'


class CAA(ResourceRecord):
    """Certification Authority Authorization record"""
    
    flag = models.PositiveSmallIntegerField()
    tag = models.CharField(max_length=20, choices=CAATag.choices)
    
    def format_bind_zone(self):
        return f'{self.label:<63} {self.ttl:<5} {self.rrclass:<2} CAA\t{self.flag}\t{self.tag} "{self.value}"'


class MX(ResourceRecord):
    """Mail exchange record"""
    
    priority = models.PositiveSmallIntegerField()
    
    def clean(self):
        if not re.match(r'^[a-zA-Z0-9\.-]+$', self.value):
            raise ValidationError({'value': 'Invalid DNS name for MX record'})
    
    def format_bind_zone(self):
        return f"{self.label:<63} {self.ttl:<5} {self.rrclass:<2} MX {self.priority} {self.value}"


class SRV(ResourceRecord):
    """Service record"""
    
    priority = models.PositiveSmallIntegerField()
    weight = models.PositiveSmallIntegerField()
    port = models.PositiveSmallIntegerField()
    
    def clean(self):
        if not re.match(r'^[a-zA-Z0-9\.-]+$', self.value):
            raise ValidationError({'value': 'Invalid DNS name for SRV record'})
    
    def format_bind_zone(self):
        return f'{self.label:<63} {self.ttl:<5} {self.rrclass:<2} SRV\t{self.priority} {self.weight} {self.port} {self.value}'


class SSHFP(ResourceRecord):
    """SSH fingerprint record"""
    
    algorithm = models.PositiveSmallIntegerField(
        choices=[
            (1, 'RSA'),
            (2, 'DSA'),
            (3, 'ECDSA'),
            (4, 'Ed25519'),
        ]
    )
    hash_type = models.PositiveSmallIntegerField(
        choices=[
            (1, 'SHA-1'),
            (2, 'SHA-256'),
        ]
    )
    fingerprint = models.CharField(max_length=255)
    
    def save(self, *args, **kwargs):
        # For SSHFP, value should be the fingerprint
        if not self.value:
            self.value = self.fingerprint
        super().save(*args, **kwargs)
    
    def format_bind_zone(self):
        return f"{self.label:<63} {self.ttl:<5} {self.rrclass:<2} SSHFP {self.algorithm} {self.hash_type} {self.fingerprint}"


class TLSA(ResourceRecord):
    """TLSA record"""
    
    cert_usage = models.PositiveSmallIntegerField(choices=[(i, str(i)) for i in range(4)])
    selector = models.PositiveSmallIntegerField(choices=[(0, '0'), (1, '1')])
    matching_type = models.PositiveSmallIntegerField(choices=[(i, str(i)) for i in range(3)])
    cert_data = models.TextField()
    
    def save(self, *args, **kwargs):
        # For TLSA, value should be the cert_data
        if not self.value:
            self.value = self.cert_data
        super().save(*args, **kwargs)
    
    def format_bind_zone(self):
        return f"{self.label:<63} {self.ttl:<5} {self.rrclass:<2} TLSA {self.cert_usage} {self.selector} {self.matching_type} {self.cert_data}"


class DNSKEY(ResourceRecord):
    """DNSKEY record"""
    
    flags = models.PositiveSmallIntegerField()
    protocol = models.PositiveSmallIntegerField(default=3)
    algorithm = models.PositiveSmallIntegerField()
    public_key = models.TextField()
    
    def save(self, *args, **kwargs):
        # For DNSKEY, value should be the public_key
        if not self.value:
            self.value = self.public_key
        super().save(*args, **kwargs)
    
    def format_bind_zone(self):
        return f"{self.label:<63} {self.ttl:<5} {self.rrclass:<2} DNSKEY {self.flags} {self.protocol} {self.algorithm} {self.public_key}"


class DS(ResourceRecord):
    """DS record"""
    
    key_tag = models.PositiveSmallIntegerField()
    algorithm = models.PositiveSmallIntegerField()
    digest_type = models.PositiveSmallIntegerField()
    digest = models.CharField(max_length=255)
    
    def save(self, *args, **kwargs):
        # For DS, value should be the digest
        if not self.value:
            self.value = self.digest
        super().save(*args, **kwargs)
    
    def format_bind_zone(self):
        return f"{self.label:<63} {self.ttl:<5} {self.rrclass:<2} DS {self.key_tag} {self.algorithm} {self.digest_type} {self.digest}"


class NAPTR(ResourceRecord):
    """NAPTR record"""
    
    order = models.PositiveSmallIntegerField()
    preference = models.PositiveSmallIntegerField()
    flags = models.CharField(max_length=10)
    service = models.CharField(max_length=255)
    regexp = models.CharField(max_length=255)
    replacement = models.CharField(max_length=255)
    
    def save(self, *args, **kwargs):
        # For NAPTR, value should be the replacement
        if not self.value:
            self.value = self.replacement
        super().save(*args, **kwargs)
    
    def clean(self):
        if not re.match(r'^[a-zA-Z0-9\.-]+$', self.replacement):
            raise ValidationError({'replacement': 'Invalid DNS name for NAPTR replacement'})
    
    def format_bind_zone(self):
        return f'{self.label:<63} {self.ttl:<5} {self.rrclass:<2} NAPTR {self.order} {self.preference} "{self.flags}" "{self.service}" "{self.regexp}" {self.replacement}'


# List of all DNS record classes for easy iteration
DNS_RECORD_CLASSES = [A, AAAA, NS, PTR, CNAME, TXT, CAA, MX, SRV, SSHFP, TLSA, DNSKEY, DS, NAPTR]
