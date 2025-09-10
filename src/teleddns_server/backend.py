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

from typing import Dict, Optional, Annotated, Tuple, Any
import logging
import aiohttp
import urllib.parse
import asyncio

#from .view import gen_bind_zone, ddns_update
from .model import *

async def _api_call_get(endpoint: str, apikey: str)->Tuple[int, str]:
    async with aiohttp.ClientSession() as session:
        async with session.get(endpoint, headers={'Authorization': f"Bearer {apikey}"}) as resp:
            return (resp.status, await resp.text())


#async def _api_call_get_json(endpoint: str, apikey: str, json: bool = False)->Tuple[int, Any]:
#    async with aiohttp.ClientSession() as session:
#        async with session.get(endpoint, headers={'Authorization': f"Bearer {apikey}"}) as resp:
#            return (resp.status, await resp.json())


async def _api_call_post(endpoint: str, apikey: str, data: str)->Tuple[int, str]:
    async with aiohttp.ClientSession() as session:
        async with session.post(endpoint,
                                headers={'Authorization': f"Bearer {apikey}", 'Content-Type': 'text/plain'},
                                data=data) as resp:
            return (resp.status, await resp.text())


async def update_zone(zone_name: str, zone_data: str, server_api_endpoint: str, server_api_key: str):
    logging.debug(f"Updating zone {zone_name}")

    furl = urllib.parse.urljoin(server_api_endpoint, f'/zonewrite?zonename={zone_name}')
    status, response = await _api_call_post(furl, server_api_key, zone_data)
    logging.info(f"Call to {furl} finished {status=}, {response=}")

    lurl = urllib.parse.urljoin(server_api_endpoint, f'/zonereload?zonename={zone_name}')
    status, response = await _api_call_get(lurl, server_api_key)
    logging.info(f"Call to {lurl} finished {status=}, {response=}")


#async def check_zone(zone_name: str, server_api_endpoint: str, server_api_key: str) -> str:
#    logging.debug(f"Checking zone {zone_name}")
#
#    curl = urllib.parse.urljoin(server_api_endpoint, f'/zonecheck?zonename={zone_name}')
#    status, response = await _api_call_get_json(curl, server_api_key)
#    logging.info(f"Call to {curl} finished {status=}, {response=}")
#    return response


async def update_config(server_config: str, server_api_endpoint: str, server_api_key: str):
    logging.debug(f"Updating config using API endpoint {server_api_endpoint}")

    furl = urllib.parse.urljoin(server_api_endpoint, f'/configwrite')
    status, response = await _api_call_post(furl, server_api_key, server_config)
    logging.info(f"Call to {furl} finished {status=}, {response=}")

    lurl = urllib.parse.urljoin(server_api_endpoint, f'/configreload')
    status, response = await _api_call_get(lurl, server_api_key)
    logging.info(f"Call to {lurl} finished {status=}, {response=}")


async def background_sync_loop():
    """Background task that syncs dirty configs and zones to backend servers every 60 seconds"""
    from datetime import datetime, timezone
    from sqlmodel import Session, select
    from .model import engine, Server, MasterZone, RR_CLASSES

    while True:
        try:
            await asyncio.sleep(60)

            logging.debug("Background sync loop iteration starting")

            with Session(engine) as session:
                # Sync servers with dirty configs
                dirty_servers = session.exec(
                    select(Server).where(Server.config_dirty == True)
                ).all()

                for server in dirty_servers:
                    try:
                        logging.info(f"Syncing config for server {server.name} (id={server.id})")

                        # Generate config data
                        config_data = []

                        # Add master zones
                        master_zones = session.exec(
                            select(MasterZone).where(MasterZone.master_server_id == server.id)
                        ).all()

                        for zone in master_zones:
                            config_data.append(f"zone:\n- domain: {zone.origin}\n  template: {server.master_template}\n  file: {zone.origin.rstrip('.').strip()}.zone")

                        # Add slave zones (zones where this server is a slave)
                        from .model import SlaveZoneServer
                        slave_zone_servers = session.exec(
                            select(SlaveZoneServer).where(SlaveZoneServer.server_id == server.id)
                        ).all()

                        for szs in slave_zone_servers:
                            zone = session.get(MasterZone, szs.zone_id)
                            if zone:
                                config_data.append(f"zone:\n- domain: {zone.origin}\n  template: {server.slave_template}\n  file: {zone.origin.rstrip('.').strip()}.zone")

                        config_content = '\n'.join(config_data) + '\n' if config_data else '\n'

                        # Send config to backend
                        await update_config(config_content, server.api_url, server.api_key)

                        # Clear dirty flag and update timestamp
                        server.config_dirty = False
                        server.last_config_sync = datetime.now(timezone.utc)
                        session.add(server)
                        session.commit()

                        logging.info(f"Successfully synced config for server {server.name}")

                    except Exception as e:
                        logging.error(f"Failed to sync config for server {server.name}: {e}")

                # Sync zones with dirty content
                dirty_zones = session.exec(
                    select(MasterZone).where(MasterZone.content_dirty == True)
                ).all()

                for zone in dirty_zones:
                    try:
                        logging.info(f"Syncing content for zone {zone.origin} (id={zone.id})")

                        # Generate zone data
                        zone_data = [zone.format_bind_zone()]

                        # Add all RR records for this zone
                        for rrclass in RR_CLASSES:
                            rr_records = session.exec(
                                select(rrclass).where(rrclass.zone_id == zone.id)
                            ).all()
                            for rr in rr_records:
                                zone_data.append(rr.format_bind_zone())

                        zone_content = '\n'.join(zone_data) + '\n'

                        # Send zone to backend
                        await update_zone(
                            zone.origin.rstrip('.').strip(),
                            zone_content,
                            zone.master_server.api_url,
                            zone.master_server.api_key
                        )

                        # Clear dirty flag and update timestamp
                        zone.content_dirty = False
                        zone.last_content_sync = datetime.now(timezone.utc)
                        session.add(zone)
                        session.commit()

                        logging.info(f"Successfully synced content for zone {zone.origin}")

                    except Exception as e:
                        logging.error(f"Failed to sync content for zone {zone.origin}: {e}")

        except Exception as e:
            logging.error(f"Error in background sync loop: {e}")
            # Continue running even if there's an error
