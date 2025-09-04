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

from typing import Optional, Any
from fastapi.exceptions import HTTPException
from fastapi import status
from sqlmodel import Session, select
import logging
import asyncio

from .model import *
from datetime import timedelta
from .backend import update_zone, update_config, check_zone
from dataclasses import dataclass
from typing import List
from .audit import audit_ddns_update, audit_authentication, AuditSource, AuditAction, AuditResource

@dataclass
class ZoneUpdateData:
    """Data structure for zone updates without database objects"""
    zone_id: int
    origin: str
    zone_content: str
    master_server_api_url: str
    master_server_api_key: str


@dataclass
class ServerConfigData:
    """Data structure for server config updates without database objects"""
    server_id: int
    server_name: str
    config_content: str
    api_url: str
    api_key: str


def extract_zone_data(zone_id: int) -> ZoneUpdateData:
    """Extract zone data for async processing"""
    with Session(engine) as session:
        try:
            zone = session.get(Zone, zone_id)
            if not zone:
                raise ValueError(f"Zone with id {zone_id} not found")
            
            # Get the associated server
            server = None
            if zone.server_id:
                server = session.get(Server, zone.server_id)
            
            if not server:
                raise ValueError(f"Zone {zone_id} has no associated server or server not found")
            
            zone_data = [zone.format_bind_zone()]
            for rrclass in RR_CLASSES:
                statement = select(rrclass).where(rrclass.zone_id == zone_id, rrclass.placeholder == False)
                for rr in session.exec(statement).all():
                    zone_data.append(rr.format_bind_zone())
            zone_data.append('')
            
            return ZoneUpdateData(
                zone_id=zone.id,
                origin=zone.origin,
                zone_content='\n'.join(zone_data),
                master_server_api_url=server.api_url,
                master_server_api_key=server.api_key
            )
        except Exception as e:
            logging.error(f"Error extracting zone data for zone_id {zone_id}: {e}")
            raise


def extract_server_config_data(server_id: int) -> ServerConfigData:
    """Extract server config data for async processing"""
    with Session(engine) as session:
        try:
            server = session.get(Server, server_id)
            if not server:
                raise ValueError(f"Server with id {server_id} not found")
            
            config_data = []
            statement = select(Zone).where(Zone.server_id == server_id)
            for zone in session.exec(statement).all():
                config_data.append(f"""zone:
- domain: {zone.origin}
  template: {server.master_template}
  file: {zone.origin.rstrip('.').strip()}.zone
""")
            config_data.append('')
            
            return ServerConfigData(
                server_id=server.id,
                server_name=server.name,
                config_content='\n'.join(config_data),
                api_url=server.api_url,
                api_key=server.api_key
            )
        except Exception as e:
            logging.error(f"Error extracting server config data for server_id {server_id}: {e}")
            raise


# helper functions not bound to web views


def verify_user(username: str, password: str, ip_address: str = "unknown") -> Optional[User]:
    """Verify user credentials - simplified without rate limiting"""
    with Session(engine) as session:
        statement = select(User).where(User.username == username)
        user = session.exec(statement).one_or_none()
        
        if user and user.verify_password(password):
            # Check if user has 2FA/PassKey enabled - if so, basic auth is not allowed
            if user.has_2fa or user.has_passkey:
                logging.warning(f"User {username} has 2FA/PassKey enabled, basic auth not allowed")
                return None
            return user
        else:
            return None
            
            
def verify_token(token: str) -> Optional[User]:
    """Verify API token and return associated user"""
    with Session(engine) as session:
        statement = select(APIToken).where(APIToken.token == token)
        api_token = session.exec(statement).one_or_none()
        
        if api_token:
            return api_token.user
        return None


def set_password(username: str, password: str, admin: bool = False):
    with Session(engine) as session:
        statement = select(User).where(User.username == username)
        user = session.exec(statement).one_or_none()
        if user:
            user.password = user.gen_hash(password)
            logging.info(f"New password set to the existing user {username}")
        else:
            session.add(User(username=username, password=User.gen_hash(password),
                             is_admin=admin))
            logging.info(f"Created new user {username} and password with admin flag {admin}")
        session.commit()


def mark_zone_for_update(zone_id: int):
    """Mark zone as needing update (replaces defer_update_zone)"""
    from .sync import update_last_change_time
    with Session(engine) as session:
        zone = session.get(Zone, zone_id)
        if zone:
            zone.needs_update = True
            # Mark associated server for config update if it exists
            if zone.server_id:
                server = session.get(Server, zone.server_id)
                if server:
                    server.needs_config_update = True
            session.commit()
            update_last_change_time()
            
            
def mark_server_for_config_update(server_id: int):
    """Mark server config as needing update (replaces defer_update_config)"""
    from .sync import update_last_change_time
    with Session(engine) as session:
        server = session.get(Server, server_id)
        if server:
            server.needs_config_update = True
            session.commit()
            update_last_change_time()


# Legacy functions for backward compatibility            
async def defer_update_zone(zone_data: ZoneUpdateData):
    """Legacy function - now just marks zone for update"""
    mark_zone_for_update(zone_data.zone_id)


async def defer_update_config(server_data: ServerConfigData):
    """Legacy function - now just marks server for config update"""
    mark_server_for_config_update(server_data.server_id)
    
async def run_check_zone(zone_id: int) -> Any:
    """Check zone using zone ID to avoid database session issues"""
    with Session(engine) as session:
        zone = session.get(Zone, zone_id)
        if not zone:
            raise ValueError(f"Zone with id {zone_id} not found")
        
        # Get the associated server
        server = None
        if zone.server_id:
            server = session.get(Server, zone.server_id)
        
        if not server:
            raise ValueError(f"Zone {zone_id} has no associated server or server not found")
        
        return await check_zone(
            zone.origin.rstrip('.').strip(),
            server.api_url,
            server.api_key
        )


def can_write_to_zone(session: Session, user: User, zone: Zone, label: str) -> bool:
    """Check if user can write to zone based on ownership or group membership"""
    if user.is_admin:
        return True
    
    # Check if user owns the zone
    if zone.user_id == user.id:
        return True
        
    # Check if user is in the zone's group
    if zone.group_id:
        for group in user.groups:
            if group.id == zone.group_id:
                return True
    
    return False

    
# HTTP endpoints

async def ddns_update(username: str, password: str, domain_name: str, ipaddr: str, client_ip: str = "unknown") -> str:
    def fqdn(domain: str) -> str:
        return domain.rstrip('.').strip() + '.'

    # Step 1: Authenticate user (separate transaction)
    user = verify_user(username, password, client_ip)
    if not user:
        raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
                headers={"WWW-Authenticate": "Basic"})

    # Step 2: Find zone and validate access (short transaction)
    search_labels = fqdn(domain_name).split('.')
    zone_id = None
    label = None
    zone_origin = None
    
    with Session(engine) as session:
        try:
            for i in range(1, len(search_labels)):
                statement = select(Zone).where(Zone.origin == fqdn('.'.join(search_labels[i:])))
                if zone := session.exec(statement).one_or_none():
                    zone_id = zone.id
                    zone_origin = zone.origin
                    label = '.'.join(search_labels[:i])
                    break
            else:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Zone not found for domain {domain_name}")
        
            if not can_write_to_zone(session, user, zone, label):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=f"Unauthorized access to zone {zone.origin}",
                    headers={"WWW-Authenticate": "Basic"})
        except Exception as e:
            logging.error(f"Error during zone lookup for {domain_name}: {e}")
            raise

    # Step 3: Validate IP address (no database)
    try:
        norm_ipaddr = ipaddress.ip_address(ipaddr)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e))

    if norm_ipaddr.version == 6:
        table = AAAA
    elif norm_ipaddr.version == 4:
        table = A
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid protocol version {norm_ipaddr.version}")

    # Step 4: Update DNS records (short transaction)
    changed = False
    with Session(engine) as session:
        try:
            # Re-fetch zone in this transaction
            zone = session.get(Zone, zone_id)
            if not zone:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Zone not found")
            
            statement = select(table).where(table.label == label, table.zone_id == zone_id)
            matched_rrs = [rr for rr in session.exec(statement).all()]
            
            # Clean up duplicate records
            if len(matched_rrs) > 1:
                for rr in matched_rrs[1:]:
                    logging.info(f"Deleting duplicate {table.__name__} RR {rr.label=} {zone.origin=} {rr.value=}")
                    session.delete(rr)
                    changed = True
            
            # Update or create record
            if len(matched_rrs) >= 1:
                rr = matched_rrs[0]
                if rr.label == label and rr.rrclass == RRClass.IN and rr.value == str(norm_ipaddr):
                    logging.info(f"Found matching {table.__name__} RR {rr.label=} {zone.origin} {rr.value=}")
                else:
                    logging.info(f"Updating {table.__name__} RR {label=} {zone.origin=} {rr.value} -> {norm_ipaddr}")
                    rr.value = str(norm_ipaddr)
                    rr.ttl = settings.DDNS_RR_TTL
                    changed = True
            else:
                logging.info(f"Creating {table.__name__} RR {label=} {zone.origin=} {norm_ipaddr}")
                new_rr = table(
                    label=label, 
                    rrclass=RRClass.IN, 
                    ttl=settings.DDNS_RR_TTL, 
                    zone_id=zone_id, 
                    value=str(norm_ipaddr)
                )
                session.add(new_rr)
                changed = True

            if changed:
                zone.soa_SERIAL += 1
                zone.needs_update = True
                session.commit()
                
                # Audit successful DDNS update
                audit_ddns_update(
                    user=user,
                    hostname=domain_name,
                    ip_address=str(norm_ipaddr),
                    record_type=table.__name__,
                    success=True,
                    client_ip=client_ip
                )
                
        except Exception as e:
            session.rollback()
            logging.error(f"Error updating DNS record for {domain_name}: {e}")
            
            # Audit failed DDNS update
            audit_ddns_update(
                user=user,
                hostname=domain_name,
                ip_address=str(norm_ipaddr),
                record_type=table.__name__,
                success=False,
                client_ip=client_ip,
                error_message=str(e)
            )
            
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Database error: {str(e)}")

    # The zone is already marked for update in the previous step
    if changed:
        return f"DDNS updated {table.__name__} {label=} {zone_origin=} -> {norm_ipaddr}"
    else:
        return f"DDNS noop {table.__name__} {label=} {zone_origin=} -> {norm_ipaddr}"
