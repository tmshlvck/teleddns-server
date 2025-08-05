"""
TeleDDNS Server - Manager App Signals
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
from django.db.models.signals import post_save, post_delete, pre_save
from django.dispatch import receiver
from django.contrib.contenttypes.models import ContentType
from django.forms.models import model_to_dict
from django.core.serializers.json import DjangoJSONEncoder

from .models import Zone, AuditLog, RR_MODELS

logger = logging.getLogger(__name__)


# Thread-local storage for request context
import threading
from contextlib import contextmanager

_thread_locals = threading.local()

# Flag to control signal handling
_signals_disabled = threading.local()


@contextmanager
def disable_signals():
    """Context manager to temporarily disable signal handling"""
    old_value = getattr(_signals_disabled, 'disabled', False)
    _signals_disabled.disabled = True
    try:
        yield
    finally:
        _signals_disabled.disabled = old_value


def signals_enabled():
    """Check if signals are enabled"""
    return not getattr(_signals_disabled, 'disabled', False)


def set_request_context(user=None, source='SYSTEM'):
    """Set the request context for audit logging"""
    _thread_locals.user = user
    _thread_locals.source = source


def get_request_context():
    """Get the current request context"""
    return getattr(_thread_locals, 'user', None), getattr(_thread_locals, 'source', 'SYSTEM')


def clear_request_context():
    """Clear the request context"""
    if hasattr(_thread_locals, 'user'):
        del _thread_locals.user
    if hasattr(_thread_locals, 'source'):
        del _thread_locals.source


class AuditLogMiddleware:
    """Middleware to capture request context for audit logging"""
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Determine the source based on the request path
        source = 'SYSTEM'
        if request.path.startswith('/admin/'):
            source = 'ADMIN'
        elif request.path.startswith('/api/'):
            source = 'API'
        elif request.path.startswith('/ddns/') or request.path == '/update/':
            source = 'DDNS'

        # Set the request context
        user = request.user if request.user.is_authenticated else None
        set_request_context(user=user, source=source)

        try:
            response = self.get_response(request)
        finally:
            # Clear the context after the request
            clear_request_context()

        return response


def create_audit_log(instance, action, changed_fields=None, old_values=None):
    """Create an audit log entry"""
    # Skip if signals are disabled
    if not signals_enabled():
        return

    user, source = get_request_context()

    # Prepare changed data
    changed_data = {}
    if action == 'CREATE':
        # For create, log all fields
        changed_data = model_to_dict(instance, exclude=['id'])
    elif action == 'UPDATE' and changed_fields:
        # For update, only log changed fields
        for field in changed_fields:
            changed_data[field] = {
                'old': old_values.get(field) if old_values else None,
                'new': getattr(instance, field, None)
            }
    elif action == 'DELETE':
        # For delete, log all fields
        changed_data = model_to_dict(instance, exclude=['id'])

    # Convert any model instances in changed_data to their string representation
    def serialize_value(val):
        """Recursively serialize values for JSON storage"""
        if hasattr(val, 'pk'):
            return str(val)
        elif hasattr(val, 'all'):  # ManyRelatedManager
            return [str(item) for item in val.all()]
        elif isinstance(val, dict):
            return {k: serialize_value(v) for k, v in val.items()}
        elif isinstance(val, (list, tuple)):
            return [serialize_value(item) for item in val]
        else:
            return val

    changed_data = serialize_value(changed_data)

    try:
        # Ensure we have a valid pk before creating audit log
        if instance.pk is None:
            logger.warning(f"Cannot create audit log for unsaved {instance.__class__.__name__}")
            return

        AuditLog.objects.create(
            user=user,
            source=source,
            action=action,
            content_type=ContentType.objects.get_for_model(instance),
            object_id=instance.pk,
            changed_data=changed_data,
            description=f"{action} {instance.__class__.__name__}: {str(instance)}"
        )
    except Exception as e:
        logger.error(f"Failed to create audit log: {e}")


# Store original field values before save
@receiver(pre_save, sender=Zone)
def store_zone_original_values(sender, instance, **kwargs):
    """Store original values before saving a Zone"""
    if instance.pk:
        try:
            instance._original_values = model_to_dict(
                Zone.objects.get(pk=instance.pk)
            )
        except Zone.DoesNotExist:
            instance._original_values = None
    else:
        instance._original_values = None


# Audit logging for Zone model
@receiver(post_save, sender=Zone)
def audit_zone_save(sender, instance, created, **kwargs):
    """Create audit log when a Zone is saved"""
    # Skip if signals are disabled
    if not signals_enabled():
        return

    if created:
        create_audit_log(instance, 'CREATE')
    else:
        # Determine which fields changed
        if hasattr(instance, '_original_values') and instance._original_values:
            changed_fields = []
            for field, old_value in instance._original_values.items():
                new_value = getattr(instance, field, None)
                if old_value != new_value:
                    changed_fields.append(field)

            if changed_fields:
                create_audit_log(
                    instance,
                    'UPDATE',
                    changed_fields=changed_fields,
                    old_values=instance._original_values
                )


@receiver(post_delete, sender=Zone)
def audit_zone_delete(sender, instance, **kwargs):
    """Create audit log when a Zone is deleted"""
    # Skip if signals are disabled
    if not signals_enabled():
        return

    create_audit_log(instance, 'DELETE')


# Audit logging and zone dirty marking for all RR models
for rr_model in RR_MODELS:
    # Store original values before save
    @receiver(pre_save, sender=rr_model)
    def store_rr_original_values(sender, instance, **kwargs):
        """Store original values before saving a ResourceRecord"""
        if instance.pk:
            try:
                instance._original_values = model_to_dict(
                    sender.objects.get(pk=instance.pk)
                )
            except sender.DoesNotExist:
                instance._original_values = None
        else:
            instance._original_values = None

    # Post-save signal
    @receiver(post_save, sender=rr_model)
    def audit_rr_save_and_mark_dirty(sender, instance, created, **kwargs):
        """Create audit log and mark zone as dirty when a ResourceRecord is saved"""
        # Skip if signals are disabled
        if not signals_enabled():
            return

        # Create audit log
        if created:
            create_audit_log(instance, 'CREATE')
        else:
            # Determine which fields changed
            if hasattr(instance, '_original_values') and instance._original_values:
                changed_fields = []
                for field, old_value in instance._original_values.items():
                    new_value = getattr(instance, field, None)
                    if old_value != new_value:
                        changed_fields.append(field)

                if changed_fields:
                    create_audit_log(
                        instance,
                        'UPDATE',
                        changed_fields=changed_fields,
                        old_values=instance._original_values
                    )

        # Mark zone as dirty if not already updating from a signal
        if hasattr(instance, 'zone') and instance.zone and not getattr(instance, '_signal_updating', False):
            try:
                # Use a separate transaction for marking zone dirty
                from django.db import transaction
                with transaction.atomic():
                    zone = instance.zone
                    zone._signal_updating = True
                    if not zone.is_dirty:
                        zone.is_dirty = True
                        zone.save(update_fields=['is_dirty', 'updated_at'])
                        logger.info(f"Marked zone {zone.origin} as dirty due to {sender.__name__} change")
            except Exception as e:
                logger.error(f"Failed to mark zone as dirty: {e}")
            finally:
                if hasattr(instance.zone, '_signal_updating'):
                    delattr(instance.zone, '_signal_updating')

    # Post-delete signal
    @receiver(post_delete, sender=rr_model)
    def audit_rr_delete_and_mark_dirty(sender, instance, **kwargs):
        """Create audit log and mark zone as dirty when a ResourceRecord is deleted"""
        # Skip if signals are disabled
        if not signals_enabled():
            return

        # Create audit log
        create_audit_log(instance, 'DELETE')

        # Mark zone as dirty
        if hasattr(instance, 'zone') and instance.zone:
            try:
                # Use a separate transaction for marking zone dirty
                from django.db import transaction
                with transaction.atomic():
                    zone = instance.zone
                    if not zone.is_dirty:
                        zone.is_dirty = True
                        zone.save(update_fields=['is_dirty', 'updated_at'])
                        logger.info(f"Marked zone {zone.origin} as dirty due to {sender.__name__} deletion")
            except Exception as e:
                logger.error(f"Failed to mark zone as dirty on deletion: {e}")


# Add the middleware to settings
# Note: This should be added to MIDDLEWARE in settings.py:
# 'manager.signals.AuditLogMiddleware',
