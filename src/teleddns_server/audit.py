# TeleDDNS-Server
# (C) 2015-2024 Tomas Hlavacek (tmshlvck@gmail.com)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import logging
from typing import Optional, Dict, Any, Union
from datetime import datetime
from enum import Enum
from dataclasses import dataclass, asdict
import json

from .model import User


class AuditSource(Enum):
    """Source of the audit event"""
    WEB = "WEB"
    API = "API"
    DDNS = "DDNS"
    ADMIN = "ADMIN"
    SYSTEM = "SYSTEM"


class AuditAction(Enum):
    """Type of action being audited"""
    CREATE = "CREATE"
    READ = "READ"
    UPDATE = "UPDATE"
    DELETE = "DELETE"
    LOGIN = "LOGIN"
    LOGOUT = "LOGOUT"
    ENABLE = "ENABLE"
    DISABLE = "DISABLE"
    SYNC = "SYNC"
    FAILED_LOGIN = "FAILED_LOGIN"


class AuditResource(Enum):
    """Resource being acted upon"""
    USER = "user"
    GROUP = "group"
    ZONE = "zone"
    RECORD = "record"
    SERVER = "server"
    API_TOKEN = "api_token"
    DDNS_UPDATE = "ddns_update"
    AUTHENTICATION = "authentication"
    TOTP = "totp"
    PASSKEY = "passkey"
    BACKEND_SYNC = "backend_sync"


@dataclass
class AuditEvent:
    """Structured audit event"""
    timestamp: datetime
    source: AuditSource
    action: AuditAction
    resource: AuditResource
    resource_id: Optional[Union[int, str]] = None
    user_id: Optional[int] = None
    username: Optional[str] = None
    client_ip: str = "unknown"
    user_agent: Optional[str] = None
    success: bool = True
    details: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for logging"""
        data = asdict(self)
        data['timestamp'] = self.timestamp.isoformat()
        data['source'] = self.source.value
        data['action'] = self.action.value
        data['resource'] = self.resource.value
        return data
    
    def to_log_string(self) -> str:
        """Convert to structured log string"""
        base = (f"AUDIT: {self.source.value} {self.action.value} {self.resource.value}"
               f" user={self.username or 'anonymous'} ip={self.client_ip}")
        
        if self.resource_id:
            base += f" resource_id={self.resource_id}"
            
        if self.user_agent:
            base += f" user_agent='{self.user_agent}'"
            
        if not self.success:
            base += f" success=false"
            if self.error_message:
                base += f" error='{self.error_message}'"
        
        if self.details:
            try:
                details_str = json.dumps(self.details, separators=(',', ':'))
                base += f" details={details_str}"
            except (TypeError, ValueError):
                base += f" details='{str(self.details)}'"
                
        return base


class AuditLogger:
    """Centralized audit logging"""
    
    def __init__(self):
        self.logger = logging.getLogger("teleddns.audit")
        self.logger.setLevel(logging.INFO)
        
        # Ensure audit logs go to a separate handler if needed
        # In production, you might want to send audit logs to a separate file
        # or external system like Elasticsearch or Splunk
    
    def log_event(self, event: AuditEvent):
        """Log an audit event"""
        self.logger.info(event.to_log_string())
    
    def log(self, 
            source: AuditSource,
            action: AuditAction,
            resource: AuditResource,
            user: Optional[User] = None,
            resource_id: Optional[Union[int, str]] = None,
            client_ip: str = "unknown",
            user_agent: Optional[str] = None,
            success: bool = True,
            details: Optional[Dict[str, Any]] = None,
            error_message: Optional[str] = None):
        """Log an audit event with parameters"""
        
        event = AuditEvent(
            timestamp=datetime.utcnow(),
            source=source,
            action=action,
            resource=resource,
            resource_id=resource_id,
            user_id=user.id if user else None,
            username=user.username if user else None,
            client_ip=client_ip,
            user_agent=user_agent,
            success=success,
            details=details,
            error_message=error_message
        )
        
        self.log_event(event)
    
    def log_user_action(self,
                       user: User,
                       action: AuditAction,
                       resource: AuditResource,
                       resource_id: Optional[Union[int, str]] = None,
                       client_ip: str = "unknown",
                       user_agent: Optional[str] = None,
                       details: Optional[Dict[str, Any]] = None,
                       source: AuditSource = AuditSource.API):
        """Log a user action"""
        self.log(
            source=source,
            action=action,
            resource=resource,
            user=user,
            resource_id=resource_id,
            client_ip=client_ip,
            user_agent=user_agent,
            details=details
        )
    
    def log_authentication(self,
                          username: str,
                          success: bool,
                          client_ip: str = "unknown",
                          user_agent: Optional[str] = None,
                          error_message: Optional[str] = None,
                          source: AuditSource = AuditSource.WEB):
        """Log authentication attempts"""
        action = AuditAction.LOGIN if success else AuditAction.FAILED_LOGIN
        
        event = AuditEvent(
            timestamp=datetime.utcnow(),
            source=source,
            action=action,
            resource=AuditResource.AUTHENTICATION,
            username=username,
            client_ip=client_ip,
            user_agent=user_agent,
            success=success,
            error_message=error_message
        )
        
        self.log_event(event)
    
    def log_ddns_update(self,
                       user: User,
                       hostname: str,
                       ip_address: str,
                       record_type: str,
                       success: bool,
                       client_ip: str = "unknown",
                       error_message: Optional[str] = None):
        """Log DDNS updates"""
        self.log(
            source=AuditSource.DDNS,
            action=AuditAction.UPDATE,
            resource=AuditResource.DDNS_UPDATE,
            user=user,
            resource_id=hostname,
            client_ip=client_ip,
            success=success,
            details={
                "hostname": hostname,
                "ip_address": ip_address,
                "record_type": record_type
            },
            error_message=error_message
        )
    
    def log_backend_sync(self,
                        zone_origin: str,
                        server_name: str,
                        success: bool,
                        error_message: Optional[str] = None,
                        details: Optional[Dict[str, Any]] = None):
        """Log backend synchronization events"""
        self.log(
            source=AuditSource.SYSTEM,
            action=AuditAction.SYNC,
            resource=AuditResource.BACKEND_SYNC,
            resource_id=zone_origin,
            success=success,
            details=dict(details or {}, server=server_name),
            error_message=error_message
        )


# Global audit logger instance
audit_logger = AuditLogger()


# Convenience functions for common audit patterns
def audit_user_action(user: User, action: AuditAction, resource: AuditResource, 
                     resource_id: Optional[Union[int, str]] = None,
                     client_ip: str = "unknown", details: Optional[Dict[str, Any]] = None,
                     source: AuditSource = AuditSource.API):
    """Convenience function for user actions"""
    audit_logger.log_user_action(user, action, resource, resource_id, client_ip, None, details, source)


def audit_authentication(username: str, success: bool, client_ip: str = "unknown",
                        error_message: Optional[str] = None, source: AuditSource = AuditSource.WEB):
    """Convenience function for authentication events"""
    audit_logger.log_authentication(username, success, client_ip, None, error_message, source)


def audit_ddns_update(user: User, hostname: str, ip_address: str, record_type: str,
                     success: bool, client_ip: str = "unknown", error_message: Optional[str] = None):
    """Convenience function for DDNS updates"""
    audit_logger.log_ddns_update(user, hostname, ip_address, record_type, success, client_ip, error_message)


def audit_backend_sync(zone_origin: str, server_name: str, success: bool,
                      error_message: Optional[str] = None, details: Optional[Dict[str, Any]] = None):
    """Convenience function for backend sync events"""
    audit_logger.log_backend_sync(zone_origin, server_name, success, error_message, details)