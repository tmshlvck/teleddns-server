"""
Utility functions for DDNS functionality.

Contains authentication, authorization, and background sync utilities.
"""
import base64
import logging
import threading
from typing import Optional, Tuple
from datetime import datetime, timezone

from django.contrib.auth import get_user_model
from dns_manager.models import (
    UserToken, UserPassKey, MasterZone, 
    UserLabelAuthorization, GroupLabelAuthorization
)

logger = logging.getLogger(__name__)
User = get_user_model()

# Global event for triggering background sync
_sync_event = None


def get_basic_auth_credentials(auth_header: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Extract username and password from Basic auth header.
    
    Args:
        auth_header: Authorization header value
        
    Returns:
        Tuple of (username, password) or (None, None) if invalid
    """
    try:
        # Remove 'Basic ' prefix
        encoded = auth_header[6:].strip()
        # Decode base64
        decoded = base64.b64decode(encoded).decode('utf-8')
        # Split on first colon
        if ':' in decoded:
            username, password = decoded.split(':', 1)
            return username, password
    except Exception as e:
        logger.warning(f"Failed to parse basic auth header: {e}")
    
    return None, None


def verify_bearer_token(token: str) -> Optional[User]:
    """
    Verify bearer token and return associated user.
    
    Args:
        token: Bearer token string
        
    Returns:
        User instance if valid token, None otherwise
    """
    try:
        user_token = UserToken.objects.select_related('user').filter(
            token_hash=UserToken.hash(token),
            is_active=True
        ).first()
        
        if user_token:
            # Check expiration
            if not user_token.expires_at or user_token.expires_at > datetime.now(timezone.utc):
                # Update last used timestamp
                user_token.last_used = datetime.now(timezone.utc)
                user_token.save(update_fields=['last_used'])
                
                logger.debug(f"Bearer token authenticated for user: {user_token.user.username}")
                return user_token.user
            else:
                logger.debug(f"Bearer token expired for user: {user_token.user.username}")
        
    except Exception as e:
        logger.warning(f"Error verifying bearer token: {e}")
    
    return None


def can_write_to_zone(user: User, zone: MasterZone, label: str) -> bool:
    """
    Check if user has write permission for specific label in zone.
    
    Args:
        user: User instance
        zone: MasterZone instance  
        label: DNS label/hostname within zone
        
    Returns:
        True if user can write to this label, False otherwise
    """
    # Superuser/admin has access to everything
    if user.is_superuser:
        return True
    
    # Zone owner has access to everything in the zone
    if zone.owner_id == user.id:
        return True
    
    # Check if user is in the zone's group (if zone has a group)
    if zone.group_id:
        if user.user_groups.filter(id=zone.group_id).exists():
            return True
    
    # Check explicit user label authorizations
    user_auths = UserLabelAuthorization.objects.filter(
        user=user,
        zone=zone
    )
    for auth in user_auths:
        if auth.verify_access(label):
            return True
    
    # Check group label authorizations for all user's groups
    user_group_ids = user.user_groups.values_list('id', flat=True)
    if user_group_ids:
        group_auths = GroupLabelAuthorization.objects.filter(
            group_id__in=user_group_ids,
            zone=zone
        )
        for auth in group_auths:
            if auth.verify_access(label):
                return True
    
    return False


def trigger_background_sync():
    """
    Trigger immediate background sync.
    
    This is called after DDNS updates to immediately sync changes
    to backend DNS servers.
    """
    try:
        from dns_manager.sync import trigger_background_sync as dns_trigger_sync
        dns_trigger_sync()
        logger.debug("Background sync triggered by DDNS update")
    except ImportError as e:
        logger.warning(f"Could not import background sync: {e}")
    except Exception as e:
        logger.error(f"Error triggering background sync: {e}")