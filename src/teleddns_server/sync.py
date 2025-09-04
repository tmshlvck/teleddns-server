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

import asyncio
import logging
from datetime import datetime, timedelta
from typing import List, Tuple
from sqlmodel import Session, select

from .model import engine, Zone, Server
from .backend import update_zone, update_config
from .view import extract_zone_data, extract_server_config_data
from .settings import settings
from .audit import audit_backend_sync

# Global state for healthcheck
last_update_time: datetime = datetime.utcnow()
last_push_time: datetime = datetime.utcnow()
startup_time: datetime = datetime.utcnow()


async def backend_sync_loop():
    """
    Background task that handles zone and server config synchronization
    according to the SPECS timing requirements.
    """
    global last_update_time, last_push_time
    
    logging.info("Starting backend sync loop")
    
    while True:
        try:
            # Wait for UPDATE_DELAY seconds
            await asyncio.sleep(settings.UPDATE_DELAY)
            
            # Check for zones that need updates
            zones_to_update = get_zones_needing_update()
            servers_to_update = get_servers_needing_config_update()
            
            if zones_to_update or servers_to_update:
                logging.info(f"Found {len(zones_to_update)} zones and {len(servers_to_update)} servers needing updates")
                
                # Update zones
                for zone_id, last_mod in zones_to_update:
                    try:
                        zone_data = extract_zone_data(zone_id)
                        await update_zone(
                            zone_data.origin.rstrip('.').strip(),
                            zone_data.zone_content,
                            zone_data.master_server_api_url,
                            zone_data.master_server_api_key
                        )
                        mark_zone_updated(zone_id)
                        last_push_time = datetime.utcnow()
                        logging.info(f"Successfully synced zone {zone_data.origin}")
                        
                        # Audit successful sync
                        audit_backend_sync(
                            zone_origin=zone_data.origin,
                            server_name="backend",  # We could get server name from zone_data if needed
                            success=True,
                            details={"serial": zone_data.zone_content.split('\n')[0] if zone_data.zone_content else None}
                        )
                        
                    except Exception as e:
                        logging.error(f"Failed to sync zone {zone_id}: {e}")
                        
                        # Audit failed sync
                        audit_backend_sync(
                            zone_origin=extract_zone_data(zone_id).origin if zone_id else "unknown",
                            server_name="backend",
                            success=False,
                            error_message=str(e)
                        )
                
                # Update server configs
                for server_id, last_mod in servers_to_update:
                    try:
                        server_data = extract_server_config_data(server_id)
                        await update_config(
                            server_data.config_content,
                            server_data.api_url,
                            server_data.api_key
                        )
                        mark_server_config_updated(server_id)
                        last_push_time = datetime.utcnow()
                        logging.info(f"Successfully synced config for server {server_data.server_name}")
                    except Exception as e:
                        logging.error(f"Failed to sync config for server {server_id}: {e}")
            
            # Check if we should wake up due to UPDATE_INTERVAL
            await asyncio.sleep(max(0, settings.UPDATE_INTERVAL - settings.UPDATE_DELAY))
            
        except Exception as e:
            logging.error(f"Error in backend sync loop: {e}")
            await asyncio.sleep(settings.UPDATE_DELAY)


def get_zones_needing_update() -> List[Tuple[int, datetime]]:
    """
    Get zones that need updates but haven't been updated recently.
    Skip zones updated within UPDATE_MINIMUM_DELAY seconds.
    """
    cutoff_time = datetime.utcnow() - timedelta(seconds=settings.UPDATE_MINIMUM_DELAY)
    
    with Session(engine) as session:
        statement = select(Zone).where(
            Zone.needs_update == True
        ).where(
            (Zone.last_updated == None) | (Zone.last_updated <= cutoff_time)
        )
        
        zones = session.exec(statement).all()
        return [(zone.id, zone.last_updated) for zone in zones]


def get_servers_needing_config_update() -> List[Tuple[int, datetime]]:
    """
    Get servers that need config updates but haven't been updated recently.
    Skip servers updated within UPDATE_MINIMUM_DELAY seconds.
    """
    cutoff_time = datetime.utcnow() - timedelta(seconds=settings.UPDATE_MINIMUM_DELAY)
    
    with Session(engine) as session:
        statement = select(Server).where(
            Server.needs_config_update == True
        ).where(
            (Server.config_last_updated == None) | (Server.config_last_updated <= cutoff_time)
        )
        
        servers = session.exec(statement).all()
        return [(server.id, server.config_last_updated) for server in servers]


def mark_zone_updated(zone_id: int):
    """Mark zone as successfully updated"""
    with Session(engine) as session:
        zone = session.get(Zone, zone_id)
        if zone:
            zone.needs_update = False
            zone.last_updated = datetime.utcnow()
            session.commit()


def mark_server_config_updated(server_id: int):
    """Mark server config as successfully updated"""
    with Session(engine) as session:
        server = session.get(Server, server_id)
        if server:
            server.needs_config_update = False
            server.config_last_updated = datetime.utcnow()
            session.commit()


def update_last_change_time():
    """Called when any change is made to update the last_update_time"""
    global last_update_time
    last_update_time = datetime.utcnow()


def get_health_status() -> Tuple[str, int, datetime, datetime]:
    """
    Get health status for the /healthcheck endpoint.
    Returns (status, uptime_seconds, last_update, last_push)
    """
    global startup_time, last_update_time, last_push_time
    
    now = datetime.utcnow()
    uptime = int((now - startup_time).total_seconds())
    
    status = "OK"
    
    # Check if we haven't had updates for too long
    if (now - last_update_time).total_seconds() > settings.WARN_ON_NOUPDATE and uptime > settings.WARN_ON_NOUPDATE:
        status = "WARN"
    
    # Check if we haven't pushed for too long
    if (now - last_push_time).total_seconds() > settings.WARN_ON_NOPUSH and uptime > settings.WARN_ON_NOPUSH:
        status = "WARN"
    
    return status, uptime, last_update_time, last_push_time