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
import ipaddress
from datetime import timezone

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


def verify_bearer_token(token: str) -> Optional[User]:
    with Session(engine) as session:
        statement = select(UserToken).where(
            UserToken.token_hash == UserToken.hash(token),
            UserToken.is_active == True
        )
        user_token = session.exec(statement).one_or_none()

        print(f"TOKEN AUTH RESULT: {str(user_token)}")

        if user_token and (not user_token.expires_at or user_token.expires_at > datetime.now(timezone.utc)):
            # Update last used timestamp
            user_token.last_used = datetime.now(timezone.utc)
            session.commit()
            return user_token.user
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


#async def defer_update_zone(zone_id: int, master_server_api_url: str, master_server_api_key: str):
#    zone_data = []
#    with Session(engine) as session:
#        zone = session.get(MasterZone, zone_id)
#        if not zone:
#            raise ValueError(f"Zone with id {zone_id} not found")
#
#        zone_data.append(zone.format_bind_zone())
#        for rrclass in RR_CLASSES:
#            statement = select(rrclass).where(rrclass.zone_id == zone_id)
#            for rr in session.exec(statement).all():
#                zone_data.append(rr.format_bind_zone())
#    zone_data.append('')
#
#    await asyncio.create_task(update_zone(zone.origin.rstrip('.').strip(),
#                                          '\n'.join(zone_data),
#                                          master_server_api_url,
#                                          master_server_api_key))
#
#
#async def defer_update_config(server_id: int, server_api_url: str, server_api_key: str, master_template: str, slave_template: str):
#    config_data = []
#    with Session(engine) as session:
#        statement = select(MasterZone).where(MasterZone.master_server_id == server_id)
#        for zobj in session.exec(statement).all():
#            config_data.append(f"""zone:
#- domain: {zobj.origin}
#  template: {master_template}
#  file: {zobj.origin.rstrip('.').strip()}.zone
#""")
#
#        statement = select(MasterZone, SlaveZoneServer).where(MasterZone.id == SlaveZoneServer.zone_id).where(SlaveZoneServer.server_id == server_id)
#        for zobj, _ in session.exec(statement).all():
#            config_data.append(f"""zone:
#- domain: {zobj.origin}
#  template: {slave_template}
#  file: {zobj.origin.rstrip('.').strip()}.zone
#""")
#    config_data.append('')
#
#    await asyncio.create_task(update_config('\n'.join(config_data),
#                                            server_api_url,
#                                            server_api_key))
#
#async def run_check_zone(zone_id: int) -> Any:
#    with Session(engine) as session:
#        zone = session.get(MasterZone, zone_id)
#        if not zone:
#            raise ValueError(f"Zone with id {zone_id} not found")
#        session.refresh(zone, ["master_server"])
#        return await check_zone(zone.origin.rstrip('.').strip(),
#                                zone.master_server.api_url,
#                                zone.master_server.api_key)


def can_write_to_zone(session: Session, user: User, zone: MasterZone, label: str) -> bool:
    # Admin has access to everything
    if user.is_admin:
        return True

    # Zone owner has access to everything in the zone
    if zone.owner_id == user.id:
        return True

    # Check if user is in the zone's group (if zone has a group)
    if zone.group_id:
        user_group_statement = select(UserGroup).where(
            UserGroup.user_id == user.id,
            UserGroup.group_id == zone.group_id
        )
        if session.exec(user_group_statement).one_or_none():
            return True

    # Check explicit user label authorizations
    user_auth_statement = select(UserLabelAuthorization).where(
        UserLabelAuthorization.user_id == user.id,
        UserLabelAuthorization.zone_id == zone.id
    )
    for auth in session.exec(user_auth_statement).all():
        if auth.verify_access(label):
            return True

    # Check group label authorizations for all user's groups
    user_groups_statement = select(UserGroup).where(UserGroup.user_id == user.id)
    user_groups = session.exec(user_groups_statement).all()

    for user_group in user_groups:
        group_auth_statement = select(GroupLabelAuthorization).where(
            GroupLabelAuthorization.group_id == user_group.group_id,
            GroupLabelAuthorization.zone_id == zone.id
        )
        for auth in session.exec(group_auth_statement).all():
            if auth.verify_access(label):
                return True

    return False


# HTTP endpoints
async def ddns_update_token(bearer_token: str, domain_name: str, ipaddr: str) -> str:
    logging.info(f"DYNDNS GET update: bearer token auth hostname {domain_name} myip: {ipaddr}")
    user = verify_bearer_token(bearer_token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"})

    logging.info(f"DYNDNS GET update: bearer token resolved to user {user}")
    return await _ddns_update(user, domain_name, ipaddr)


async def ddns_update_basic(username: str, password: str, domain_name: str, ipaddr: str) -> str:
    logging.info(f"DYNDNS GET update: basic auth user {username} hostname {domain_name} myip: {ipaddr}")
    user = verify_user(username, password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"})

    # Check if user has 2FA/PassKey enabled - if so, reject basic auth
    # Use a fresh session to avoid detached instance issues
    with Session(engine) as check_session:
        fresh_user = check_session.get(User, user.id)
        has_passkeys = check_session.exec(select(UserPassKey).where(UserPassKey.user_id == user.id)).first() is not None

        if fresh_user.totp_enabled or fresh_user.sso_enabled or has_passkeys:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Basic authentication not allowed for users with 2FA/PassKey/SSO enabled. Use bearer token.",
                headers={"WWW-Authenticate": "Bearer"})

    return await _ddns_update(user, domain_name, ipaddr)


async def _ddns_update(user: User, domain_name: str, ipaddr: str) -> str:
    def fqdn(domain: str) -> str:
        return domain.rstrip('.').strip() + '.'

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
                logging.info(f"Deleting {table.__name__} RR {rr.label=} {zone.origin=} {rr.value=}")
                session.delete(rr)
                changed = True

        if len(matched_rrs) >= 1:
            rr = matched_rrs[0]
            if rr.label == label and rr.rrclass == RRClass.IN and rr.zone == zone and rr.value == str(norm_ipaddr):
                logging.info(f"Found matching {table.__name__} RR {rr.label=} {zone.origin} {rr.value=}")
            else:
                logging.info(f"Updating {table.__name__} RR {label=} {zone.origin=} {rr.value} -> {norm_ipaddr}")
                rr.value = str(norm_ipaddr)
                changed = True
        else:
            logging.info(f"Creating {table.__name__} RR {label=} {zone.origin=} {norm_ipaddr}")
            session.add(table(label=label, rrclass=RRClass.IN, ttl=settings.DDNS_RR_TTL, zone=zone, value=str(norm_ipaddr)))
            changed = True

        if changed:
            zone.soa_SERIAL += 1
            zone.content_dirty = True
            session.commit()
            return f"DDNS updated {table.__name__} {label=} {zone.origin=} -> {norm_ipaddr}"
        else:
            return f"DDNS noop {table.__name__} {label=} {zone.origin=} -> {norm_ipaddr}"
