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

from typing import Dict, Optional, Tuple
from fastapi.exceptions import HTTPException
from fastapi.responses import PlainTextResponse, JSONResponse
from fastapi import status
from pydantic import BaseModel
from sqlmodel import Session, select
import logging
import asyncio

from .model import *
from .backend import update_zone, update_config

# helper functions not bound to web views
def verify_user(username: str, password: str) -> Optional[User]:
    with Session(engine) as session:
        statement = select(User).where(User.username == username)
        user = session.exec(statement).one_or_none()
        if user and user.verify_password(password):
            return user
        else:
            return None


def can_write_to_zone(user: User, zone: MasterZone, label: str) -> bool:
    if user.is_admin:
        return True
    else:
        with Session(engine) as session:
            statement = select(AccessRule).where(AccessRule.user == user, AccessRule.zone == zone)
            for r in session.exec(statement).all():
                if r.verify_access(label):
                    return True
    return False


async def defer_update_zone(zone: MasterZone):
    zone_data = []
    with Session(engine) as session:
        zone_data.append(zone.format_bind_zone())
        for rrclass in RR_CLASSES:
            statement = select(rrclass).where(rrclass.zone == zone)
            for rr in session.exec(statement).all():
                zone_data.append(rr.format_bind_zone())

    await asyncio.create_task(update_zone(zone.origin.rstrip('.').strip(),
                                          '\n'.join(zone_data),
                                          zone.master_server.api_url,
                                          zone.master_server.api_key))


async def defer_update_config(server: Server):
    config_data = []
    with Session(engine) as session:
        statement = select(MasterZone).where(MasterZone.master_server == server)
        for zobj in session.exec(statement).all():
            config_data.append(f"""zone:
- domain: {zobj.origin}
  template: {server.master_template}
  file: {zobj.origin.rstrip('.').strip()}.zone
""")
    
        statement = select(MasterZone).where(server in MasterZone.slave_servers)
        for zobj in session.exec(statement).all():
            config_data.append(f"""zone:
- domain: {zobj.origin}
  template: {server.slave_template}
  file: {zobj.origin.rstrip('.').strip()}.zone
""")
    
    await asyncio.create_task(update_config('\n'.join(config_data),
                                            server.api_url,
                                            server.api_key))


#async def get_zones() -> List[MasterZone]:
#    with Session(engine) as session:
#        statement = select(MasterZone)
#        return session.exec(statement).all()
#
#
#async def get_servers() -> List[Server]:
#    with Session(engine) as session:
#        statement = select(Server)
#        return session.exec(statement).all()

    
# HTTP endpoints

async def ddns_update(username: str, password: str, domain_name: str, ipaddr: str) -> str:
    norm_domain_name = fqdn(domain_name)
    user = verify_user(username, password)
    if not user:
        raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password",
                headers={"WWW-Authenticate": "Basic"})

    search_labels = fqdn(norm_domain_name).split('.')
    with Session(engine) as session:
        for i in range(1,len(search_labels)):
            statement = select(MasterZone).where(MasterZone.origin == fqdn('.'.join(search_labels[i:])))
            if zone := session.exec(statement).one_or_none():
                label = '.'.join(search_labels[:i])
                break
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Zone not found for domain {domain_name}")
    
    if not can_write_to_zone(user, zone, label):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Unauthorized access to zone {zone.origin}",
            headers={"WWW-Authenticate": "Basic"})
    
    try:
        norm_ipaddr = ipaddress.ip_address(ipaddr)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e))
    
    with Session(engine) as session:
        if norm_ipaddr.version == 6:
            table = AAAA
        elif norm_ipaddr.version == 4:
            table = A
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid protocol version {norm_ipaddr.version}")
        
        statement = select(table).where(table.label == label, table.zone == zone)
        changed = False
        found = False
        for rr in session.exec(statement):
            if rr.label == label and rr.rrclass == RRClass.IN and rr.zone == zone and rr.value == str(norm_ipaddr):
                found = True
                logging.info("Found matching RR: {table.__name__} {rr.label=} {zone.origin} {rr.value=}")
            else:
                logging.info(f"Deleting {table.__name__} {rr.label=} {zone.origin} {rr.value=}")
                rr.delete()
                changed = False
        
        if not found:
            session.add(table(label=label, rrclass=RRClass.IN, ttl=settings.DDNS_RR_TTL, zone=zone, value=str(norm_ipaddr)))
            logging.info(f"Creating {table.__name__} RR {label=} {zone.origin} {norm_ipaddr}")
            changed = True

        if changed:
            zone.soa_SERIAL += 1
            session.commit()
            await defer_update_zone(zone)

        return f"DDNS update {table.__name__} {label=} {zone.origin=} -> {norm_ipaddr}"
