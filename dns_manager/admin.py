from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.utils.html import format_html
from django.urls import reverse
from django.utils.safestring import mark_safe
from django.http import HttpResponseForbidden
from django.contrib.admin import AdminSite
from django.contrib.auth import get_user_model

from .models import (
    User, UserToken, UserPassKey, Group, UserGroup,
    Server, MasterZone, SlaveZoneServer,
    UserLabelAuthorization, GroupLabelAuthorization,
    A, AAAA, NS, PTR, CNAME, TXT, CAA, MX, SRV, SSHFP, TLSA, DNSKEY, DS, NAPTR,
    DNS_RECORD_CLASSES
)


# Custom Admin Site for enhanced security
class TeleDDNSAdminSite(AdminSite):
    site_header = 'TeleDDNS Server Administration'
    site_title = 'TeleDDNS Admin'
    index_title = 'DNS Management Console'
    
    def has_permission(self, request):
        """Only allow superusers and staff users access to admin."""
        return request.user.is_active and (request.user.is_superuser or request.user.is_staff)


# Create custom admin site instance
admin_site = TeleDDNSAdminSite(name='teleddns_admin')


# Custom User Admin
@admin.register(User, site=admin_site)
class UserAdmin(BaseUserAdmin):
    list_display = ('username', 'email', 'first_name', 'last_name', 'is_staff', 
                   'is_active', 'totp_enabled', 'sso_enabled', 'date_joined')
    list_filter = ('is_staff', 'is_superuser', 'is_active', 'totp_enabled', 
                   'sso_enabled', 'date_joined')
    search_fields = ('username', 'first_name', 'last_name', 'email')
    ordering = ('username',)
    filter_horizontal = ('groups', 'user_permissions')
    
    fieldsets = BaseUserAdmin.fieldsets + (
        ('2FA Settings', {
            'fields': ('totp_secret', 'totp_enabled', 'totp_backup_codes')
        }),
        ('SSO Integration', {
            'fields': ('sso_provider', 'sso_subject_id', 'sso_enabled')
        }),
        ('Metadata', {
            'fields': ('last_update_metadata',),
            'classes': ('collapse',)
        }),
    )
    
    readonly_fields = ('date_joined', 'last_login', 'created_at', 'updated_at')


@admin.register(UserToken, site=admin_site)
class UserTokenAdmin(admin.ModelAdmin):
    list_display = ('description', 'user', 'is_active', 'expires_at', 'last_used', 'created_at')
    list_filter = ('is_active', 'created_at', 'expires_at')
    search_fields = ('description', 'user__username')
    readonly_fields = ('token_hash', 'last_used', 'created_at', 'updated_at')
    raw_id_fields = ('user',)
    
    fieldsets = (
        (None, {
            'fields': ('user', 'description', 'token_hash')
        }),
        ('Access Control', {
            'fields': ('is_active', 'scopes', 'expires_at', 'last_used')
        }),
        ('Metadata', {
            'fields': ('last_update_metadata', 'created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )


@admin.register(UserPassKey, site=admin_site)
class UserPassKeyAdmin(admin.ModelAdmin):
    list_display = ('name', 'user', 'is_active', 'last_used', 'created_at')
    list_filter = ('is_active', 'created_at')
    search_fields = ('name', 'user__username', 'credential_id')
    readonly_fields = ('credential_id', 'public_key', 'sign_count', 'last_used', 
                      'created_at', 'updated_at')
    raw_id_fields = ('user',)


@admin.register(Group, site=admin_site)
class GroupAdmin(admin.ModelAdmin):
    list_display = ('name', 'description', 'user_count', 'created_at')
    search_fields = ('name', 'description')
    readonly_fields = ('created_at', 'updated_at', 'user_list')
    
    fieldsets = (
        (None, {
            'fields': ('name', 'description')
        }),
        ('Users', {
            'fields': ('user_list',),
            'classes': ('collapse',)
        }),
        ('Metadata', {
            'fields': ('last_update_metadata', 'created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    def user_count(self, obj):
        return obj.users.count()
    user_count.short_description = 'Users'
    
    def user_list(self, obj):
        if not obj.pk:
            return 'Save group first'
        users = obj.users.all()
        if users:
            user_links = []
            for user in users:
                admin_url = reverse('teleddns_admin:dns_manager_user_change', args=[user.pk])
                user_links.append(f'<a href="{admin_url}">{user.username}</a>')
            return format_html('<br>'.join(user_links))
        return 'No users'
    user_list.short_description = 'Users in Group'


@admin.register(Server, site=admin_site)
class ServerAdmin(admin.ModelAdmin):
    list_display = ('name', 'api_url', 'owner', 'group', 'is_active', 
                   'config_dirty', 'last_config_sync')
    list_filter = ('is_active', 'config_dirty', 'created_at', 'last_config_sync')
    search_fields = ('name', 'api_url', 'owner__username')
    readonly_fields = ('last_config_sync', 'created_at', 'updated_at')
    raw_id_fields = ('owner', 'group')
    
    fieldsets = (
        (None, {
            'fields': ('name', 'api_url', 'api_key', 'is_active')
        }),
        ('Ownership', {
            'fields': ('owner', 'group')
        }),
        ('Templates', {
            'fields': ('master_template', 'slave_template'),
            'classes': ('collapse',)
        }),
        ('Sync Status', {
            'fields': ('config_dirty', 'last_config_sync')
        }),
        ('Metadata', {
            'fields': ('last_update_metadata', 'created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    actions = ['mark_config_dirty', 'clear_config_dirty']
    
    def mark_config_dirty(self, request, queryset):
        count = queryset.update(config_dirty=True)
        self.message_user(request, f'{count} server(s) marked as config dirty.')
    mark_config_dirty.short_description = 'Mark config as dirty'
    
    def clear_config_dirty(self, request, queryset):
        count = queryset.update(config_dirty=False)
        self.message_user(request, f'{count} server(s) marked as config clean.')
    clear_config_dirty.short_description = 'Clear config dirty flag'


@admin.register(MasterZone, site=admin_site)
class MasterZoneAdmin(admin.ModelAdmin):
    list_display = ('origin', 'owner', 'group', 'master_server', 'soa_serial',
                   'content_dirty', 'last_content_sync', 'record_count')
    list_filter = ('content_dirty', 'created_at', 'last_content_sync', 'master_server')
    search_fields = ('origin', 'owner__username', 'soa_mname', 'soa_rname')
    readonly_fields = ('last_content_sync', 'created_at', 'updated_at', 'record_summary', 'slave_server_list')
    raw_id_fields = ('owner', 'group', 'master_server')
    
    fieldsets = (
        (None, {
            'fields': ('origin', 'owner', 'group')
        }),
        ('SOA Record', {
            'fields': ('soa_name', 'soa_class', 'soa_ttl', 'soa_mname', 'soa_rname',
                      'soa_serial', 'soa_refresh', 'soa_retry', 'soa_expire', 'soa_minimum'),
            'classes': ('collapse',)
        }),
        ('Server Assignment', {
            'fields': ('master_server', 'slave_server_list')
        }),
        ('Sync Status', {
            'fields': ('content_dirty', 'last_content_sync')
        }),
        ('Records', {
            'fields': ('record_summary',),
            'classes': ('collapse',)
        }),
        ('Metadata', {
            'fields': ('last_update_metadata', 'created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    actions = ['increment_serial', 'mark_content_dirty', 'clear_content_dirty', 'show_zone_file']
    
    def record_count(self, obj):
        total = sum(getattr(obj, f'{cls.__name__.lower()}_records').count() 
                   for cls in DNS_RECORD_CLASSES)
        return total
    record_count.short_description = 'Records'
    
    def record_summary(self, obj):
        if not obj.pk:
            return 'Save zone first to see records'
        
        summary = []
        for cls in DNS_RECORD_CLASSES:
            count = getattr(obj, f'{cls.__name__.lower()}_records').count()
            if count > 0:
                admin_url = reverse(f'teleddns_admin:dns_manager_{cls.__name__.lower()}_changelist')
                summary.append(
                    f'<a href="{admin_url}?zone__id__exact={obj.pk}">{cls.__name__}: {count}</a>'
                )
        
        if summary:
            return format_html('<br>'.join(summary))
        return 'No records'
    record_summary.short_description = 'Record Summary'
    
    def increment_serial(self, request, queryset):
        for zone in queryset:
            zone.soa_serial += 1
            zone.content_dirty = True
            zone.save()
        count = queryset.count()
        self.message_user(request, f'Incremented serial for {count} zone(s).')
    increment_serial.short_description = 'Increment SOA serial'
    
    def slave_server_list(self, obj):
        """Display slave servers for this zone as clickable links."""
        slave_servers = obj.slave_servers.all()
        if not slave_servers:
            return '-'
        
        links = []
        for server in slave_servers[:3]:  # Limit to first 3 servers
            url = reverse('admin:dns_manager_server_change', args=[server.pk])
            links.append(f'<a href="{url}">{server.name}</a>')
        
        result = ', '.join(links)
        if slave_servers.count() > 3:
            result += f' (+{slave_servers.count() - 3} more)'
        return format_html(result)
    slave_server_list.short_description = 'Slave Servers'
    
    def mark_content_dirty(self, request, queryset):
        count = queryset.update(content_dirty=True)
        self.message_user(request, f'{count} zone(s) marked as content dirty.')
    mark_content_dirty.short_description = 'Mark content as dirty'
    
    def clear_content_dirty(self, request, queryset):
        count = queryset.update(content_dirty=False)
        self.message_user(request, f'{count} zone(s) marked as content clean.')
    clear_content_dirty.short_description = 'Clear content dirty flag'
    
    def show_zone_file(self, request, queryset):
        if queryset.count() != 1:
            self.message_user(request, 'Select exactly one zone to show zone file.', level='ERROR')
            return
        
        zone = queryset.first()
        zone_content = [zone.format_bind_zone_header()]
        
        # Add all records
        for cls in DNS_RECORD_CLASSES:
            records = getattr(zone, f'{cls.__name__.lower()}_records').all()
            for record in records:
                zone_content.append(record.format_bind_zone())
        
        full_zone = '\n'.join(zone_content)
        self.message_user(request, format_html(
            f'Zone file for {zone.origin}:<br><pre>{full_zone}</pre>'
        ))
    show_zone_file.short_description = 'Show complete zone file'


# Base admin for DNS records
class DNSRecordAdmin(admin.ModelAdmin):
    list_display = ('label', 'zone', 'rrclass', 'ttl', 'value_display', 'updated_at')
    list_filter = ('zone', 'rrclass', 'created_at')
    search_fields = ('label', 'zone__origin', 'value')
    readonly_fields = ('created_at', 'updated_at', 'bind_format')
    raw_id_fields = ('zone',)
    
    fieldsets = (
        (None, {
            'fields': ('zone', 'label', 'ttl', 'rrclass', 'value')
        }),
        ('Preview', {
            'fields': ('bind_format',),
            'classes': ('collapse',)
        }),
        ('Metadata', {
            'fields': ('last_update_metadata', 'created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    def value_display(self, obj):
        return obj.value[:50] + ('...' if len(obj.value) > 50 else '')
    value_display.short_description = 'Value'
    
    def bind_format(self, obj):
        if obj.pk:
            return format_html('<pre>{}</pre>', obj.format_bind_zone())
        return 'Save record first'
    bind_format.short_description = 'BIND Format'
    
    actions = ['mark_zone_dirty']
    
    def mark_zone_dirty(self, request, queryset):
        zones = set(record.zone for record in queryset)
        for zone in zones:
            zone.content_dirty = True
            zone.save()
        self.message_user(request, f'Marked {len(zones)} zone(s) as content dirty.')
    mark_zone_dirty.short_description = 'Mark zone as content dirty'


# Register all DNS record types
@admin.register(A, site=admin_site)
class AAdmin(DNSRecordAdmin):
    list_display = DNSRecordAdmin.list_display + ('ip_version',)
    
    def ip_version(self, obj):
        return 'IPv4'


@admin.register(AAAA, site=admin_site)
class AAAAAdmin(DNSRecordAdmin):
    list_display = DNSRecordAdmin.list_display + ('ip_version',)
    
    def ip_version(self, obj):
        return 'IPv6'


@admin.register(NS, site=admin_site)
class NSAdmin(DNSRecordAdmin):
    pass


@admin.register(PTR, site=admin_site)
class PTRAdmin(DNSRecordAdmin):
    pass


@admin.register(CNAME, site=admin_site)
class CNAMEAdmin(DNSRecordAdmin):
    pass


@admin.register(TXT, site=admin_site)
class TXTAdmin(DNSRecordAdmin):
    pass


@admin.register(CAA, site=admin_site)
class CAAAdmin(DNSRecordAdmin):
    list_display = DNSRecordAdmin.list_display + ('flag', 'tag')
    list_filter = DNSRecordAdmin.list_filter + ('flag', 'tag')
    
    fieldsets = (
        (None, {
            'fields': ('zone', 'label', 'ttl', 'rrclass', 'flag', 'tag', 'value')
        }),
    ) + DNSRecordAdmin.fieldsets[1:]


@admin.register(MX, site=admin_site)
class MXAdmin(DNSRecordAdmin):
    list_display = DNSRecordAdmin.list_display + ('priority',)
    list_filter = DNSRecordAdmin.list_filter + ('priority',)
    
    fieldsets = (
        (None, {
            'fields': ('zone', 'label', 'ttl', 'rrclass', 'priority', 'value')
        }),
    ) + DNSRecordAdmin.fieldsets[1:]


@admin.register(SRV, site=admin_site)
class SRVAdmin(DNSRecordAdmin):
    list_display = DNSRecordAdmin.list_display + ('priority', 'weight', 'port')
    list_filter = DNSRecordAdmin.list_filter + ('priority', 'port')
    
    fieldsets = (
        (None, {
            'fields': ('zone', 'label', 'ttl', 'rrclass', 'priority', 'weight', 'port', 'value')
        }),
    ) + DNSRecordAdmin.fieldsets[1:]


@admin.register(SSHFP, site=admin_site)
class SSHFPAdmin(DNSRecordAdmin):
    list_display = DNSRecordAdmin.list_display + ('algorithm', 'hash_type')
    list_filter = DNSRecordAdmin.list_filter + ('algorithm', 'hash_type')
    
    fieldsets = (
        (None, {
            'fields': ('zone', 'label', 'ttl', 'rrclass', 'algorithm', 'hash_type', 'fingerprint')
        }),
    ) + DNSRecordAdmin.fieldsets[1:]
    
    readonly_fields = DNSRecordAdmin.readonly_fields + ('value',)


@admin.register(TLSA, site=admin_site)
class TLSAAdmin(DNSRecordAdmin):
    list_display = DNSRecordAdmin.list_display + ('cert_usage', 'selector', 'matching_type')
    list_filter = DNSRecordAdmin.list_filter + ('cert_usage', 'selector', 'matching_type')
    
    fieldsets = (
        (None, {
            'fields': ('zone', 'label', 'ttl', 'rrclass', 'cert_usage', 'selector', 
                      'matching_type', 'cert_data')
        }),
    ) + DNSRecordAdmin.fieldsets[1:]
    
    readonly_fields = DNSRecordAdmin.readonly_fields + ('value',)


@admin.register(DNSKEY, site=admin_site)
class DNSKEYAdmin(DNSRecordAdmin):
    list_display = DNSRecordAdmin.list_display + ('flags', 'protocol', 'algorithm')
    list_filter = DNSRecordAdmin.list_filter + ('flags', 'algorithm')
    
    fieldsets = (
        (None, {
            'fields': ('zone', 'label', 'ttl', 'rrclass', 'flags', 'protocol', 
                      'algorithm', 'public_key')
        }),
    ) + DNSRecordAdmin.fieldsets[1:]
    
    readonly_fields = DNSRecordAdmin.readonly_fields + ('value',)


@admin.register(DS, site=admin_site)
class DSAdmin(DNSRecordAdmin):
    list_display = DNSRecordAdmin.list_display + ('key_tag', 'algorithm', 'digest_type')
    list_filter = DNSRecordAdmin.list_filter + ('algorithm', 'digest_type')
    
    fieldsets = (
        (None, {
            'fields': ('zone', 'label', 'ttl', 'rrclass', 'key_tag', 'algorithm', 
                      'digest_type', 'digest')
        }),
    ) + DNSRecordAdmin.fieldsets[1:]
    
    readonly_fields = DNSRecordAdmin.readonly_fields + ('value',)


@admin.register(NAPTR, site=admin_site)
class NAPTRAdmin(DNSRecordAdmin):
    list_display = DNSRecordAdmin.list_display + ('order', 'preference')
    list_filter = DNSRecordAdmin.list_filter + ('order', 'preference')
    
    fieldsets = (
        (None, {
            'fields': ('zone', 'label', 'ttl', 'rrclass', 'order', 'preference',
                      'flags', 'service', 'regexp', 'replacement')
        }),
    ) + DNSRecordAdmin.fieldsets[1:]
    
    readonly_fields = DNSRecordAdmin.readonly_fields + ('value',)


@admin.register(UserLabelAuthorization, site=admin_site)
class UserLabelAuthorizationAdmin(admin.ModelAdmin):
    list_display = ('user', 'zone', 'label_pattern', 'created_at')
    list_filter = ('created_at', 'zone')
    search_fields = ('user__username', 'zone__origin', 'label_pattern')
    raw_id_fields = ('user', 'zone')
    readonly_fields = ('created_at', 'updated_at')


@admin.register(GroupLabelAuthorization, site=admin_site)
class GroupLabelAuthorizationAdmin(admin.ModelAdmin):
    list_display = ('group', 'zone', 'label_pattern', 'created_at')
    list_filter = ('created_at', 'zone')
    search_fields = ('group__name', 'zone__origin', 'label_pattern')
    raw_id_fields = ('group', 'zone')
    readonly_fields = ('created_at', 'updated_at')
