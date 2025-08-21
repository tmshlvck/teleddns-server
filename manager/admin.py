"""
TeleDDNS Server - Manager App Admin Configuration
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

import logging
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.models import User
from django.db import models
from django.utils.html import format_html
from rest_framework.authtoken.models import Token
from rest_framework.authtoken.admin import TokenAdmin

from .models import (
    Server, Zone, A, AAAA, CNAME, MX, NS, PTR, SRV, TXT,
    CAA, DS, DNSKEY, TLSA, AuditLog, RR_MODELS, SOA,
    ZoneServer
)

logger = logging.getLogger(__name__)


# Customize Token admin only if it's already registered
if admin.site.is_registered(Token):
    admin.site.unregister(Token)


#@admin.register(Token)
#class CustomTokenAdmin(TokenAdmin):
#    """Enhanced Token admin with better display"""
#    list_display = ('key', 'user', 'created')
#    fields = ('user',)
#    ordering = ('-created',)
#    readonly_fields = ('key', 'created')
#
#    def has_add_permission(self, request):
#        """Disable add permission - tokens should be created via API"""
#        return False


class TokenInline(admin.TabularInline):
    """Inline for displaying user tokens"""
    model = Token
    extra = 0
    can_delete = True
    readonly_fields = ('key', 'created')
    verbose_name = "API Token"
    verbose_name_plural = "API Tokens"


# Extend the default User admin to include tokens
class UserAdmin(BaseUserAdmin):
    inlines = BaseUserAdmin.inlines + (TokenInline,)


# Re-register User with our custom admin
admin.site.unregister(User)
admin.site.register(User, UserAdmin)


@admin.register(Server)
class ServerAdmin(admin.ModelAdmin):
    """Admin interface for DNS servers"""
    list_display = ('name', 'api_url', 'master_zones_count', 'slave_zones_count', 'created_at')
    list_filter = ('created_at',)
    search_fields = ('name', 'api_url')
    readonly_fields = ('created_at', 'updated_at')
    fieldsets = (
        (None, {
            'fields': ('name', 'api_url', 'api_key')
        }),
        ('Templates', {
            'fields': ('master_template', 'slave_template')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

    def master_zones_count(self, obj):
        return obj.zone_servers.filter(role='master').count()
    master_zones_count.short_description = 'Master Zones'

    def slave_zones_count(self, obj):
        return obj.zone_servers.filter(role='slave').count()
    slave_zones_count.short_description = 'Slave Zones'


# Resource Record Inlines
class ResourceRecordInline(admin.TabularInline):
    """Base inline for resource records"""
    extra = 0
    fields = ('label', 'ttl', 'value', 'owner', 'group')
    autocomplete_fields = ('owner', 'group')

    def get_queryset(self, request):
        qs = super().get_queryset(request)
        return qs.select_related('owner', 'group')

    def formfield_for_foreignkey(self, db_field, request, **kwargs):
        if db_field.name == 'owner':
            kwargs['initial'] = request.user
            if not request.user.is_superuser:
                # Limit choices to current user for non-superusers
                kwargs['queryset'] = User.objects.filter(id=request.user.id)
        if db_field.name == 'group':
            if request.user.groups.exists():
                kwargs['initial'] = request.user.groups.first()
                if not request.user.is_superuser:
                    # Limit choices to user's groups for non-superusers
                    kwargs['queryset'] = request.user.groups.all()
        return super().formfield_for_foreignkey(db_field, request, **kwargs)


class AInline(ResourceRecordInline):
    model = A
    verbose_name = "A Record"
    verbose_name_plural = "A Records"


class AAAAInline(ResourceRecordInline):
    model = AAAA
    verbose_name = "AAAA Record"
    verbose_name_plural = "AAAA Records"


class CNAMEInline(ResourceRecordInline):
    model = CNAME
    verbose_name = "CNAME Record"
    verbose_name_plural = "CNAME Records"


class MXInline(ResourceRecordInline):
    model = MX
    fields = ('label', 'ttl', 'priority', 'value', 'owner', 'group')
    verbose_name = "MX Record"
    verbose_name_plural = "MX Records"


class NSInline(ResourceRecordInline):
    model = NS
    verbose_name = "NS Record"
    verbose_name_plural = "NS Records"


class PTRInline(ResourceRecordInline):
    model = PTR
    verbose_name = "PTR Record"
    verbose_name_plural = "PTR Records"


class SRVInline(ResourceRecordInline):
    model = SRV
    fields = ('label', 'ttl', 'priority', 'weight', 'port', 'value', 'owner', 'group')
    verbose_name = "SRV Record"
    verbose_name_plural = "SRV Records"


class TXTInline(ResourceRecordInline):
    model = TXT
    verbose_name = "TXT Record"
    verbose_name_plural = "TXT Records"


class CAAInline(ResourceRecordInline):
    model = CAA
    fields = ('label', 'ttl', 'flag', 'tag', 'value', 'owner', 'group')
    verbose_name = "CAA Record"
    verbose_name_plural = "CAA Records"


class DSInline(ResourceRecordInline):
    model = DS
    fields = ('label', 'ttl', 'key_tag', 'algorithm', 'digest_type', 'digest', 'owner', 'group')
    verbose_name = "DS Record"
    verbose_name_plural = "DS Records"


class DNSKEYInline(ResourceRecordInline):
    model = DNSKEY
    fields = ('label', 'ttl', 'flags', 'protocol', 'algorithm', 'public_key', 'owner', 'group')
    verbose_name = "DNSKEY Record"
    verbose_name_plural = "DNSKEY Records"


class TLSAInline(ResourceRecordInline):
    model = TLSA
    fields = ('label', 'ttl', 'usage', 'selector', 'matching_type', 'certificate_data', 'owner', 'group')
    verbose_name = "TLSA Record"
    verbose_name_plural = "TLSA Records"


class SOAInline(admin.StackedInline):
    model = SOA
    verbose_name = "SOA Record"
    verbose_name_plural = "SOA Record"
    max_num = 1
    extra = 1
    can_delete = False
    fields = (
        'name', 'rrclass', 'ttl',
        'mname', 'rname', 'serial',
        'refresh', 'retry', 'expire', 'minimum'
    )
    readonly_fields = ('serial',)

    def has_add_permission(self, request, obj):
        """Only allow adding if no SOA exists"""
        if obj and hasattr(obj, 'soa'):
            return False
        return super().has_add_permission(request, obj)


class ZoneServerInline(admin.TabularInline):
    """Inline admin for zone server relationships"""
    model = ZoneServer
    extra = 1
    fields = ('server', 'role', 'config_dirty', 'config_dirty_since', 'last_sync_time')
    readonly_fields = ('config_dirty', 'config_dirty_since', 'last_sync_time')


@admin.register(Zone)
class ZoneAdmin(admin.ModelAdmin):
    """Admin interface for DNS zones with all resource records"""
    list_display = (
        'origin', 'get_soa_serial', 'status_indicator',
        'owner', 'group', 'updated_at'
    )
    list_filter = ('content_dirty', 'owner', 'group', 'created_at')
    search_fields = ('origin',)
    autocomplete_fields = ('owner', 'group')
    readonly_fields = ('created_at', 'updated_at', 'get_soa_info')

    fieldsets = (
        (None, {
            'fields': ('origin', 'owner', 'group')
        }),
        ('SOA Information', {
            'fields': ('get_soa_info',),
            'description': 'SOA record is managed separately. <a href="../soa/">View SOA records</a>'
        }),
        ('Status', {
            'fields': ('content_dirty', 'content_dirty_since'),
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

    inlines = [
        SOAInline,  # SOA should be first as it's the most important
        ZoneServerInline,  # Show zone-server relationships
        AInline, AAAAInline, CNAMEInline, MXInline, NSInline,
        PTRInline, SRVInline, TXTInline, CAAInline,
        DSInline, DNSKEYInline, TLSAInline
    ]

    actions = ['increment_serial', 'mark_content_dirty', 'mark_config_dirty', 'mark_clean']

    def get_queryset(self, request):
        qs = super().get_queryset(request)
        if request.user.is_superuser:
            return qs
        return qs.filter(
            models.Q(owner=request.user) |
            models.Q(group__in=request.user.groups.all())
        )

    def status_indicator(self, obj):
        if obj.content_dirty:
            color = 'orange'
            text = 'Pending Sync'
        else:
            # Check if any servers need sync
            servers_dirty = obj.zone_servers.filter(
                config_dirty=True
            ).exists()
            if servers_dirty:
                color = 'orange'
                text = 'Pending Sync (Servers)'
            else:
                color = 'green'
                text = 'Synchronized'
        return format_html(
            '<span style="color: {};">⬤ {}</span>',
            color, text
        )
    status_indicator.short_description = 'Status'

    def get_soa_serial(self, obj):
        """Get SOA serial number from related SOA record"""
        if hasattr(obj, 'soa'):
            return obj.soa.serial
        return '-'
    get_soa_serial.short_description = 'Serial'
    get_soa_serial.admin_order_field = 'soa__serial'

    def get_soa_info(self, obj):
        """Display SOA record information"""
        if hasattr(obj, 'soa'):
            soa = obj.soa
            return format_html(
                '<strong>Primary NS:</strong> {}<br>'
                '<strong>Contact:</strong> {}<br>'
                '<strong>Serial:</strong> {}<br>'
                '<strong>Refresh:</strong> {} / <strong>Retry:</strong> {} / '
                '<strong>Expire:</strong> {} / <strong>Minimum:</strong> {}',
                soa.mname, soa.rname, soa.serial,
                soa.refresh, soa.retry, soa.expire, soa.minimum
            )
        return format_html(
            '<em>No SOA record found. <a href="../soa/add/?zone={}">Create SOA record</a></em>',
            obj.pk
        )
    get_soa_info.short_description = 'SOA Record Details'

    @admin.action(description="Increment serial number")
    def increment_serial(self, request, queryset):
        for zone in queryset:
            zone.increment_serial()
        self.message_user(request, f"Serial incremented for {queryset.count()} zone(s)")

    @admin.action(description="Mark content as dirty (needs sync)")
    def mark_content_dirty(self, request, queryset):
        updated = queryset.update(content_dirty=True)
        self.message_user(request, f"Marked {updated} zone(s) content as dirty")

    @admin.action(description="Mark all servers config as dirty")
    def mark_config_dirty(self, request, queryset):
        from django.utils import timezone
        now = timezone.now()
        count = 0
        for zone in queryset:
            zone.zone_servers.update(config_dirty=True, config_dirty_since=now)
            count += zone.zone_servers.count()
        self.message_user(request, f"Marked {count} zone-server configs as dirty")

    @admin.action(description="Mark zones as clean (no sync needed)")
    def mark_clean(self, request, queryset):
        updated = queryset.update(content_dirty=False, content_dirty_since=None)
        # Also mark server relationships as clean
        for zone in queryset:
            zone.zone_servers.update(
                config_dirty=False, config_dirty_since=None
            )
        self.message_user(request, f"Marked {updated} zone(s) as clean")

    def save_formset(self, request, form, formset, change):
        """Override to set is_dirty when resource records change"""
        instances = formset.save(commit=False)
        for obj in formset.deleted_objects:
            obj.delete()
        for instance in instances:
            instance.save()
        formset.save_m2m()

        # Mark zone as dirty if any resource records were changed
        if instances or formset.deleted_objects:
            zone = form.instance
            try:
                from django.db import transaction
                with transaction.atomic():
                    from django.utils import timezone
                    zone.content_dirty = True
                    zone.content_dirty_since = timezone.now()
                    zone.save(update_fields=['content_dirty', 'content_dirty_since'])
            except Exception as e:
                logger.error(f"Failed to mark zone as dirty after formset save: {e}")

    def save_model(self, request, obj, form, change):
        """Override to set ownership for new zones"""
        if not change:  # New zone
            if not obj.owner_id:
                obj.owner = request.user
            if not obj.group_id and request.user.groups.exists():
                obj.group = request.user.groups.first()
        super().save_model(request, obj, form, change)


# Register individual RR models for direct access
class ResourceRecordAdmin(admin.ModelAdmin):
    """Base admin class for resource records"""
    list_display = ('label', 'zone', 'ttl', 'value', 'owner', 'updated_at')
    list_filter = ('zone', 'owner', 'group', 'created_at')
    search_fields = ('label', 'value', 'zone__origin')
    autocomplete_fields = ('zone', 'owner', 'group')
    readonly_fields = ('created_at', 'updated_at')

    def get_queryset(self, request):
        qs = super().get_queryset(request)
        qs = qs.select_related('zone', 'owner', 'group')
        if request.user.is_superuser:
            return qs
        return qs.filter(
            models.Q(owner=request.user) |
            models.Q(group__in=request.user.groups.all())
        )

    def save_model(self, request, obj, form, change):
        """Set zone as dirty when RR is saved"""
        # Set default owner and group if not specified
        if not change:  # New record
            if not obj.owner_id:
                obj.owner = request.user
            if not obj.group_id and request.user.groups.exists():
                obj.group = request.user.groups.first()

        # Save the record
        super().save_model(request, obj, form, change)

        # Mark zone as dirty in a separate transaction to avoid conflicts
        if obj.zone:
            try:
                from django.db import transaction
                with transaction.atomic():
                    from django.utils import timezone
                    obj.zone.content_dirty = True
                    obj.zone.content_dirty_since = timezone.now()
                    obj.zone.save(update_fields=['content_dirty', 'content_dirty_since'])
            except Exception as e:
                logger.error(f"Failed to mark zone as dirty: {e}")


# Register all RR models with customized admin classes
for rr_model in RR_MODELS:
    if rr_model == MX:
        @admin.register(MX)
        class MXAdmin(ResourceRecordAdmin):
            list_display = ('label', 'zone', 'ttl', 'priority', 'value', 'owner', 'updated_at')
    elif rr_model == SRV:
        @admin.register(SRV)
        class SRVAdmin(ResourceRecordAdmin):
            list_display = ('label', 'zone', 'ttl', 'priority', 'weight', 'port', 'value', 'owner', 'updated_at')
    elif rr_model == CAA:
        @admin.register(CAA)
        class CAAAdmin(ResourceRecordAdmin):
            list_display = ('label', 'zone', 'ttl', 'flag', 'tag', 'value', 'owner', 'updated_at')
    elif rr_model == DS:
        @admin.register(DS)
        class DSAdmin(ResourceRecordAdmin):
            list_display = ('label', 'zone', 'ttl', 'key_tag', 'algorithm', 'digest_type', 'owner', 'updated_at')
    elif rr_model == DNSKEY:
        @admin.register(DNSKEY)
        class DNSKEYAdmin(ResourceRecordAdmin):
            list_display = ('label', 'zone', 'ttl', 'flags', 'algorithm', 'owner', 'updated_at')
    elif rr_model == TLSA:
        @admin.register(TLSA)
        class TLSAAdmin(ResourceRecordAdmin):
            list_display = ('label', 'zone', 'ttl', 'usage', 'selector', 'matching_type', 'owner', 'updated_at')
    else:
        # Register A, AAAA, CNAME, NS, PTR, TXT with base admin
        admin.site.register(rr_model, ResourceRecordAdmin)


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    """Read-only admin interface for audit logs"""
    list_display = ('timestamp', 'user', 'source', 'action', 'content_type', 'object_repr', 'description')
    list_filter = ('source', 'action', 'content_type', 'timestamp')
    search_fields = ('user__username', 'description', 'changed_data')
    date_hierarchy = 'timestamp'
    readonly_fields = (
        'timestamp', 'user', 'source', 'action',
        'content_type', 'object_id', 'content_object',
        'changed_data_pretty', 'description'
    )

    def has_add_permission(self, request):
        """Audit logs are read-only"""
        return False

    def has_change_permission(self, request, obj=None):
        """Audit logs are read-only"""
        return False

    def has_delete_permission(self, request, obj=None):
        """Audit logs cannot be deleted via admin"""
        return False

    def object_repr(self, obj):
        """Display string representation of the modified object"""
        try:
            return str(obj.content_object)
        except:
            return f"{obj.content_type} #{obj.object_id}"
    object_repr.short_description = 'Object'

    def changed_data_pretty(self, obj):
        """Pretty print JSON data"""
        import json
        return format_html(
            '<pre style="white-space: pre-wrap;">{}</pre>',
            json.dumps(obj.changed_data, indent=2)
        )
    changed_data_pretty.short_description = 'Changed Data'


@admin.register(SOA)
class SOAAdmin(admin.ModelAdmin):
    """Admin interface for SOA records"""
    list_display = ('zone', 'mname', 'rname', 'serial', 'ttl', 'updated_at')
    list_filter = ('updated_at', 'zone')
    search_fields = ('zone__origin', 'mname', 'rname')
    readonly_fields = ('created_at', 'updated_at')
    autocomplete_fields = ['zone']

    fieldsets = (
        (None, {
            'fields': ('zone', 'name', 'rrclass', 'ttl')
        }),
        ('SOA Fields', {
            'fields': ('mname', 'rname', 'serial', 'refresh', 'retry', 'expire', 'minimum')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

    def get_queryset(self, request):
        """Optimize query with select_related"""
        qs = super().get_queryset(request)
        return qs.select_related('zone')





@admin.register(ZoneServer)
class ZoneServerAdmin(admin.ModelAdmin):
    """Admin interface for Zone-Server relationships (for debugging)"""
    list_display = ('zone', 'server', 'role', 'config_dirty', 'config_dirty_since', 'last_sync_time', 'updated_at')
    list_filter = ('role', 'config_dirty', 'server', 'last_sync_time')
    search_fields = ('zone__origin', 'server__name')
    readonly_fields = ('zone', 'server', 'role', 'created_at', 'updated_at')
    date_hierarchy = 'last_sync_time'

    def has_add_permission(self, request):
        # These should only be created by the system
        return False
