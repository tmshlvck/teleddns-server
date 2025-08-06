"""
TeleDDNS Server - DDNS App Services
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
import ipaddress
from typing import Optional, Tuple, List
from django.db import transaction
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from django.contrib.contenttypes.models import ContentType
from django.conf import settings

from manager.models import Zone, A, AAAA, AuditLog
from manager.services import increment_zone_serial

logger = logging.getLogger(__name__)


class DDNSError(Exception):
    """Base exception for DDNS errors"""
    pass


class DDNSAuthenticationError(DDNSError):
    """Raised when authentication fails"""
    pass


class DDNSPermissionError(DDNSError):
    """Raised when user lacks permission"""
    pass


class DDNSValidationError(DDNSError):
    """Raised when input validation fails"""
    pass


def verify_user_password(username: str, password: str) -> Optional[User]:
    """
    Verify user credentials using Django authentication.

    Args:
        username: Username
        password: Password

    Returns:
        User object if authentication successful, None otherwise
    """
    user = authenticate(username=username, password=password)
    if user and user.is_active:
        return user
    return None


def find_zone_for_domain(domain_name: str) -> Tuple[Optional[Zone], Optional[str]]:
    """
    Find the zone and label for a given domain name.

    Args:
        domain_name: The domain name to look up (e.g., "www.example.com")

    Returns:
        Tuple of (Zone, label) if found, (None, None) otherwise
    """
    # Normalize domain name
    domain_name = domain_name.strip().lower()
    if not domain_name.endswith('.'):
        domain_name += '.'

    # Split domain into labels
    labels = domain_name.split('.')

    # Try to find the zone by checking each possible zone origin
    for i in range(1, len(labels)):
        possible_origin = '.'.join(labels[i:])
        if not possible_origin:
            continue

        try:
            zone = Zone.objects.get(origin=possible_origin)
            label = '.'.join(labels[:i]).rstrip('.')
            if not label:
                label = '@'
            return zone, label
        except Zone.DoesNotExist:
            continue

    return None, None


def check_zone_access(user: User, zone: Zone, label: str) -> bool:
    """
    Check if a user has permission to update a specific label in a zone.

    Args:
        user: The user to check
        zone: The zone to check access for
        label: The label within the zone

    Returns:
        True if user has access, False otherwise
    """
    # Superusers have unrestricted access
    if user.is_superuser:
        return True

    # Check if user owns the zone
    if zone.owner == user:
        return True

    # Check if user is in the zone's group
    if zone.group in user.groups.all():
        return True

    # Check if user owns any records in this zone
    from manager.models import RR_MODELS
    for rr_model in RR_MODELS:
        if rr_model.objects.filter(zone=zone, owner=user).exists():
            return True

    return False


def normalize_ip_address(ip_addr: str) -> Tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, type]:
    """
    Normalize and validate an IP address.

    Args:
        ip_addr: IP address string

    Returns:
        Tuple of (normalized IP address object, record type class)

    Raises:
        DDNSValidationError: If IP address is invalid
    """
    try:
        ip_obj = ipaddress.ip_address(ip_addr.strip())
        if isinstance(ip_obj, ipaddress.IPv4Address):
            return ip_obj, A
        elif isinstance(ip_obj, ipaddress.IPv6Address):
            return ip_obj, AAAA
        else:
            raise DDNSValidationError(f"Unknown IP address type: {type(ip_obj)}")
    except ValueError as e:
        raise DDNSValidationError(f"Invalid IP address '{ip_addr}': {str(e)}")


@transaction.atomic
def update_ddns_record(
    user: User,
    domain_name: str,
    ip_address: str,
    source: str = 'DDNS'
) -> Tuple[bool, str, Zone]:
    """
    Update or create a DDNS record.

    Args:
        user: The authenticated user
        domain_name: The domain name to update
        ip_address: The new IP address
        source: The source of the update (for audit log)

    Returns:
        Tuple of (changed, message, zone) where:
        - changed: True if any changes were made
        - message: Description of what happened
        - zone: The affected Zone object

    Raises:
        DDNSError: On various error conditions
    """
    # Find the zone and label
    zone, label = find_zone_for_domain(domain_name)
    if not zone:
        raise DDNSValidationError(f"No zone found for domain '{domain_name}'")

    # Check access permissions
    if not check_zone_access(user, zone, label):
        raise DDNSPermissionError(
            f"User '{user.username}' does not have permission to update '{domain_name}' in zone '{zone.origin}'"
        )

    # Normalize and validate IP address
    ip_obj, record_class = normalize_ip_address(ip_address)
    ip_str = str(ip_obj)

    # Lock the zone for update
    zone = Zone.objects.select_for_update().get(pk=zone.pk)

    # Find existing records
    existing_records = list(record_class.objects.filter(
        zone=zone,
        label=label
    ).order_by('created_at'))

    changed = False
    action_taken = []

    # Handle multiple records - keep only the first one
    if len(existing_records) > 1:
        for record in existing_records[1:]:
            logger.info(
                f"DDNS: Deleting duplicate {record_class.__name__} record "
                f"{label}.{zone.origin} -> {record.value}"
            )

            # Create audit log for deletion
            AuditLog.objects.create(
                user=user,
                source=source,
                action='DELETE',
                content_type=ContentType.objects.get_for_model(record),
                object_id=record.pk,
                changed_data={
                    'zone': str(zone),
                    'label': label,
                    'value': record.value,
                    'ttl': record.ttl
                },
                description=f"DDNS deleted duplicate {record_class.__name__} record"
            )

            record.delete()
            changed = True
            action_taken.append(f"deleted duplicate {record_class.__name__} record")

    # Handle the primary record
    if existing_records:
        record = existing_records[0]
        if record.value != ip_str:
            old_value = record.value
            record.value = ip_str
            record.ttl = settings.DDNS_RR_TTL
            record.save()

            logger.info(
                f"DDNS: Updated {record_class.__name__} record "
                f"{label}.{zone.origin} from {old_value} to {ip_str}"
            )

            # Create audit log for update
            AuditLog.objects.create(
                user=user,
                source=source,
                action='UPDATE',
                content_type=ContentType.objects.get_for_model(record),
                object_id=record.pk,
                changed_data={
                    'value': {
                        'old': old_value,
                        'new': ip_str
                    },
                    'ttl': {
                        'old': record.ttl,
                        'new': settings.DDNS_RR_TTL
                    }
                },
                description=f"DDNS updated {record_class.__name__} record"
            )

            changed = True
            action_taken.append(f"updated {record_class.__name__} record from {old_value} to {ip_str}")
        else:
            logger.info(
                f"DDNS: No change needed for {record_class.__name__} record "
                f"{label}.{zone.origin} -> {ip_str}"
            )
            action_taken.append(f"no change needed, {record_class.__name__} record already set to {ip_str}")
    else:
        # Create new record
        record = record_class.objects.create(
            zone=zone,
            label=label,
            ttl=settings.DDNS_RR_TTL,
            rrclass='IN',
            value=ip_str,
            owner=user,
            group=zone.group
        )

        logger.info(
            f"DDNS: Created new {record_class.__name__} record "
            f"{label}.{zone.origin} -> {ip_str}"
        )

        # Create audit log for creation
        AuditLog.objects.create(
            user=user,
            source=source,
            action='CREATE',
            content_type=ContentType.objects.get_for_model(record),
            object_id=record.pk,
            changed_data={
                'zone': str(zone),
                'label': label,
                'value': ip_str,
                'ttl': settings.DDNS_RR_TTL,
                'owner': user.username,
                'group': zone.group.name if zone.group else None
            },
            description=f"DDNS created {record_class.__name__} record"
        )

        changed = True
        action_taken.append(f"created new {record_class.__name__} record with value {ip_str}")

    # Update zone if changed
    if changed:
        # Increment serial using the Zone's method which handles SOA
        zone.increment_serial()
        zone.is_dirty = True
        zone.save(update_fields=['is_dirty', 'updated_at'])

        serial = zone.soa.serial if hasattr(zone, 'soa') else 'N/A'
        logger.info(
            f"DDNS: Incremented serial for zone {zone.origin} to {serial} "
            f"and marked as dirty"
        )

    # Build response message
    if changed:
        message = f"DDNS update successful for {domain_name}: " + ", ".join(action_taken)
    else:
        message = f"DDNS update for {domain_name}: " + ", ".join(action_taken)

    return changed, message, zone


def extract_basic_auth_credentials(auth_header: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Extract username and password from HTTP Basic Auth header.

    Args:
        auth_header: The Authorization header value

    Returns:
        Tuple of (username, password) or (None, None) if invalid
    """
    if not auth_header or not auth_header.startswith('Basic '):
        return None, None

    try:
        import base64
        encoded_credentials = auth_header[6:]  # Remove 'Basic ' prefix
        decoded = base64.b64decode(encoded_credentials).decode('utf-8')
        username, password = decoded.split(':', 1)
        return username, password
    except Exception as e:
        logger.warning(f"Failed to decode Basic Auth header: {e}")
        return None, None
