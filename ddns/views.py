"""
DDNS API views for TeleDDNS Server.

Implements Dynamic DNS update endpoints compatible with standard DDNS clients.
Supports both basic authentication and bearer token authentication.
"""
import logging
import ipaddress
from typing import Optional
from datetime import datetime, timezone

from django.http import JsonResponse, HttpRequest
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.contrib.auth import authenticate
from django.contrib.auth.models import AnonymousUser
from django.utils.decorators import method_decorator
from django.views import View
import base64

from dns_manager.models import (
    User, UserToken, UserPassKey, MasterZone, A, AAAA,
    UserLabelAuthorization, GroupLabelAuthorization
)
from .utils import (
    verify_bearer_token, can_write_to_zone, 
    trigger_background_sync, get_basic_auth_credentials
)

logger = logging.getLogger(__name__)


class DDNSStatus:
    """Standard DDNS response status messages."""
    GOOD = "good"
    NOCHG = "nochg" 
    BADAUTH = "badauth"
    NOTFQDN = "notfqdn"
    NOHOST = "nohost"
    BADAGENT = "badagent"
    ABUSE = "abuse"
    
    
def ddns_response(status: str, ip: str = "", message: str = "") -> JsonResponse:
    """Create standardized DDNS response."""
    detail = f"{status}"
    if ip:
        detail += f" {ip}"
    if message:
        detail += f" - {message}"
    
    return JsonResponse({"detail": detail}, status=200)


def ddns_error_response(status_code: int, status: str, message: str = "") -> JsonResponse:
    """Create standardized DDNS error response."""
    detail = status
    if message:
        detail += f" - {message}"
        
    response = JsonResponse({"detail": detail}, status=status_code)
    if status_code == 401:
        response['WWW-Authenticate'] = 'Basic, Bearer'
    return response


@csrf_exempt
@require_http_methods(["GET", "POST"])
def ddns_update(request: HttpRequest) -> JsonResponse:
    """
    DDNS update endpoint supporting both /ddns/update and /update paths.
    
    Parameters:
        hostname (str): Full domain name to update (e.g., host.example.com)
        myip (str): IPv4 or IPv6 address to set, or empty to delete records
        
    Authentication:
        - Basic Auth: username/password (only if user has no 2FA/PassKey)
        - Bearer Token: Authorization: Bearer <token>
        
    Returns:
        JSON response with status and details
    """
    try:
        # Extract parameters
        hostname = request.GET.get('hostname', '').strip()
        myip = request.GET.get('myip', '').strip()
        
        if not hostname:
            return ddns_error_response(400, DDNSStatus.NOTFQDN, "hostname parameter required")
            
        logger.info(f"DDNS update request: hostname={hostname}, myip={myip}, IP={request.META.get('REMOTE_ADDR')}")
        
        # Try bearer token authentication first
        user = None
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')
        
        if auth_header.lower().startswith('bearer '):
            token = auth_header[7:].strip()
            user = verify_bearer_token(token)
            if user:
                logger.info(f"DDNS bearer token auth successful for user: {user.username}")
            else:
                logger.warning(f"DDNS bearer token auth failed for token: {token[:10]}...")
                
        # Try basic authentication if no bearer token
        elif auth_header.lower().startswith('basic '):
            username, password = get_basic_auth_credentials(auth_header)
            if username and password:
                user = authenticate(request, username=username, password=password)
                if user and user.is_active:
                    # Check if user has 2FA/PassKey enabled - if so, reject basic auth
                    if (user.totp_enabled or user.sso_enabled or 
                        UserPassKey.objects.filter(user=user).exists()):
                        logger.warning(f"Basic auth rejected for user {username} - 2FA/PassKey enabled")
                        return ddns_error_response(
                            401, DDNSStatus.BADAUTH, 
                            "Basic authentication not allowed for users with 2FA/PassKey/SSO. Use bearer token."
                        )
                    logger.info(f"DDNS basic auth successful for user: {username}")
                else:
                    logger.warning(f"DDNS basic auth failed for user: {username}")
                    
        if not user:
            return ddns_error_response(401, DDNSStatus.BADAUTH, "Authentication required")
            
        # Process DDNS update
        return _process_ddns_update(user, hostname, myip)
        
    except Exception as e:
        logger.exception(f"Unexpected error in DDNS update: {e}")
        return ddns_error_response(500, "911", f"Server error: {str(e)}")


def _process_ddns_update(user: User, hostname: str, myip: str) -> JsonResponse:
    """Process the actual DDNS update logic."""
    
    def fqdn(domain: str) -> str:
        """Ensure domain ends with a dot."""
        return domain.rstrip('.').strip() + '.'
    
    # Find the zone for this hostname
    search_labels = fqdn(hostname).split('.')
    zone = None
    label = None
    
    # Try to match zone from longest to shortest suffix
    for i in range(1, len(search_labels)):
        zone_origin = fqdn('.'.join(search_labels[i:]))
        try:
            zone = MasterZone.objects.get(origin=zone_origin)
            label = '.'.join(search_labels[:i])
            break
        except MasterZone.DoesNotExist:
            continue
    
    if not zone:
        logger.warning(f"No zone found for hostname: {hostname}")
        return ddns_error_response(404, DDNSStatus.NOHOST, f"Zone not found for {hostname}")
    
    # Check permissions
    if not can_write_to_zone(user, zone, label):
        logger.warning(f"User {user.username} unauthorized for zone {zone.origin}, label {label}")
        return ddns_error_response(
            401, DDNSStatus.BADAUTH, 
            f"Unauthorized access to zone {zone.origin}"
        )
    
    # Handle deletion (empty myip)
    if not myip:
        return _delete_ddns_records(user, zone, label, hostname)
    
    # Validate IP address
    try:
        ip_addr = ipaddress.ip_address(myip)
    except ValueError as e:
        logger.warning(f"Invalid IP address {myip}: {e}")
        return ddns_error_response(400, DDNSStatus.NOTFQDN, f"Invalid IP address: {myip}")
    
    # Determine record type
    if ip_addr.version == 4:
        record_class = A
        record_type = "A"
    elif ip_addr.version == 6:
        record_class = AAAA  
        record_type = "AAAA"
    else:
        return ddns_error_response(400, DDNSStatus.NOTFQDN, f"Unsupported IP version: {ip_addr.version}")
    
    # Find existing records
    existing_records = list(record_class.objects.filter(zone=zone, label=label))
    
    changed = False
    ip_str = str(ip_addr)
    
    # Remove duplicate records (keep only first one)
    if len(existing_records) > 1:
        for record in existing_records[1:]:
            logger.info(f"Deleting duplicate {record_type} record: {record.label}.{zone.origin} -> {record.value}")
            record.delete()
            changed = True
    
    # Update or create record
    if existing_records:
        record = existing_records[0]
        if record.value == ip_str:
            logger.info(f"DDNS no change: {record_type} {label}.{zone.origin} -> {ip_str}")
            return ddns_response(DDNSStatus.NOCHG, ip_str)
        else:
            logger.info(f"Updating {record_type} record: {label}.{zone.origin} {record.value} -> {ip_str}")
            record.value = ip_str
            record.last_update_metadata = f"DDNS update by {user.username}"
            record.save()
            changed = True
    else:
        logger.info(f"Creating {record_type} record: {label}.{zone.origin} -> {ip_str}")
        record_class.objects.create(
            zone=zone,
            label=label,
            value=ip_str,
            ttl=300,  # Default DDNS TTL
            last_update_metadata=f"DDNS create by {user.username}"
        )
        changed = True
    
    # Update zone if changed
    if changed:
        zone.soa_serial += 1
        zone.content_dirty = True
        zone.last_update_metadata = f"DDNS update by {user.username}"
        zone.save()
        
        # Trigger background sync
        trigger_background_sync()
        
        logger.info(f"DDNS update successful: {record_type} {label}.{zone.origin} -> {ip_str}")
        return ddns_response(DDNSStatus.GOOD, ip_str)
    
    return ddns_response(DDNSStatus.NOCHG, ip_str)


def _delete_ddns_records(user: User, zone: MasterZone, label: str, hostname: str) -> JsonResponse:
    """Delete A and AAAA records for the hostname."""
    deleted_count = 0
    
    # Delete A records
    a_records = A.objects.filter(zone=zone, label=label)
    a_count = a_records.count()
    if a_count > 0:
        logger.info(f"Deleting {a_count} A records for {label}.{zone.origin}")
        a_records.delete()
        deleted_count += a_count
    
    # Delete AAAA records  
    aaaa_records = AAAA.objects.filter(zone=zone, label=label)
    aaaa_count = aaaa_records.count()
    if aaaa_count > 0:
        logger.info(f"Deleting {aaaa_count} AAAA records for {label}.{zone.origin}")
        aaaa_records.delete()
        deleted_count += aaaa_count
    
    if deleted_count > 0:
        # Update zone
        zone.soa_serial += 1
        zone.content_dirty = True
        zone.last_update_metadata = f"DDNS delete by {user.username}"
        zone.save()
        
        # Trigger background sync
        trigger_background_sync()
        
        logger.info(f"DDNS deletion successful: removed {deleted_count} records for {hostname}")
        return ddns_response(DDNSStatus.GOOD, "", f"Deleted {deleted_count} records")
    else:
        logger.info(f"DDNS deletion - no records found for {hostname}")
        return ddns_response(DDNSStatus.NOCHG, "", "No records to delete")


