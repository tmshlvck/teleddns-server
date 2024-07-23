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
from .backend import update_zone, update_config, check_zone

# helper functions not bound to web views
def verify_user(username: str, password: str) -> Optional[User]:
    with Session(engine) as session:
        statement = select(User).where(User.username == username)
        user = session.exec(statement).one_or_none()
        if user and user.verify_password(password):
            return user
        else:
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


async def defer_update_zone(zone: MasterZone):
    zone_data = []
    with Session(engine) as session:
        zone_data.append(zone.format_bind_zone())
        for rrclass in RR_CLASSES:
            statement = select(rrclass).where(rrclass.zone == zone)
            for rr in session.exec(statement).all():
                zone_data.append(rr.format_bind_zone())
    zone_data.append('')

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
    
        statement = select(MasterZone, SlaveZoneServer).where(MasterZone.id == SlaveZoneServer.zone_id).where(SlaveZoneServer.server_id == server.id)
        for zobj, _ in session.exec(statement).all():
            config_data.append(f"""zone:
- domain: {zobj.origin}
  template: {server.slave_template}
  file: {zobj.origin.rstrip('.').strip()}.zone
""")
    config_data.append('')
    
    await asyncio.create_task(update_config('\n'.join(config_data),
                                            server.api_url,
                                            server.api_key))
    
async def run_check_zone(zone: MasterZone) -> Any:
    return await check_zone(zone.origin.rstrip('.').strip(),
                            zone.master_server.api_url,
                            zone.master_server.api_key)


def can_write_to_zone(session: Session, user: User, zone: MasterZone, label: str) -> bool:
    if user.is_admin:
        return True
    else:
        statement = select(AccessRule).where(AccessRule.user == user, AccessRule.zone == zone)
        for r in session.exec(statement).all():
            if r.verify_access(label):
                return True
    return False

    
# HTTP endpoints

async def ddns_update(username: str, password: str, domain_name: str, ipaddr: str) -> str:
    def fqdn(domain: str) -> str:
        return domain.rstrip('.').strip() + '.'

    user = verify_user(username, password)
    if not user:
        raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
                headers={"WWW-Authenticate": "Basic"})

    search_labels = fqdn(domain_name).split('.')
    with Session(engine, expire_on_commit=False) as session:
        for i in range(1,len(search_labels)):
            statement = select(MasterZone).where(MasterZone.origin == fqdn('.'.join(search_labels[i:])))
            if zone := session.exec(statement).one_or_none():
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
        
        statement = select(table).where(table.label == label, table.zone == zone)
        matched_rrs = [rr for rr in session.exec(statement).all()]
        changed = False
        if len(matched_rrs) > 1:
            for rr in matched_rrs[1:]:
                logging.info(f"Deleting {table.__name__} RR {rr.label=} {zone.origin} {rr.value=}")
                session.delete(rr)
                changed = True
        
        if len(matched_rrs) >= 1:
            rr = matched_rrs[0]
            if rr.label == label and rr.rrclass == RRClass.IN and rr.zone == zone and rr.value == str(norm_ipaddr):
                logging.info(f"Found matching {table.__name__} RR {rr.label=} {zone.origin} {rr.value=}")
            else:
                logging.info(f"Updating {table.__name__} RR {label=} {zone.origin} {rr.value} -> {norm_ipaddr}")
                rr.value = str(norm_ipaddr)
                changed = True
        else:
            logging.info(f"Creating {table.__name__} RR {label=} {zone.origin} {norm_ipaddr}")
            session.add(table(label=label, rrclass=RRClass.IN, ttl=settings.DDNS_RR_TTL, zone=zone, value=str(norm_ipaddr)))
            changed = True

        if changed:
            zone.soa_SERIAL += 1
            session.commit()
            await defer_update_zone(zone)
            return f"DDNS updated {table.__name__} {label=} {zone.origin=} -> {norm_ipaddr}"
        else:
            return f"DDNS noop {table.__name__} {label=} {zone.origin=} -> {norm_ipaddr}"
