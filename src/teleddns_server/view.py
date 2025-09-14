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
from datetime import datetime, timezone
from .model import *
from .backend import update_zone, update_config
from .settings import settings

# Global event for triggering immediate background sync
_sync_event = None


def trigger_background_sync():
    """Trigger immediate background sync by setting the event."""
    if _sync_event is not None:
        _sync_event.set()


# Output data formatting
def generate_bind_zone_content(session: Session, zone: MasterZone) -> str:
    """Generate BIND zone file content from a zone and its RR records.

    Args:
        session: SQLModel.Session
        zone: MasterZone instance
        rrs: Dict mapping RR class to list of RR instances

    Returns:
        Complete BIND zone file content as string
    """
    zone_data = [zone.format_bind_zone()]

    # Collect all RR records for this zone
    for rrclass in RR_CLASSES:
        for rr in session.exec(
            select(rrclass).where(rrclass.zone_id == zone.id)
        ).all():
            zone_data.append(rr.format_bind_zone())

    return '\n'.join(zone_data) + '\n'


def generate_knot_config_content(session: Session, server: Server) -> str:
    """Generate Knot DNS configuration content.

    Args:
        session: SQLModel.Session
        server: .model.Server

    Returns:
        Knot DNS configuration content as string
    """
    config_data = []

    # Add master zones
    for zone in server.master_zones:
        config_data.append(f"zone:\n- domain: {zone.origin}\n  template: {server.master_template}\n  file: {zone.origin.rstrip('.').strip()}.zone")

    for zone in server.slave_zones:
        config_data.append(f"zone:\n- domain: {zone.origin}\n  template: {server.slave_template}\n  file: {zone.origin.rstrip('.').strip()}.zone")

    return '\n'.join(config_data) + '\n' if config_data else '\n'

async def do_background_sync():
    """Perform one iteration of background sync - sync dirty configs and zones to backend servers"""

    logging.debug("Background sync iteration starting")

    with Session(engine) as session:
        # Sync servers with dirty configs
        dirty_servers = session.exec(
            select(Server).where(Server.config_dirty == True).where(Server.is_active == True)
        ).all()

        for server in dirty_servers:
            try:
                logging.info(f"Syncing config for server {server.name} (id={server.id})")

                # Generate config content using view function
                config_content = generate_knot_config_content(session, server)

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

                # Generate zone content using view function
                zone_content = generate_bind_zone_content(session, zone)

                # Send zone to backend
                if zone.master_server.is_active:
                    await update_zone(
                        zone.origin.rstrip('.').strip(),
                        zone_content,
                        zone.master_server.api_url,
                        zone.master_server.api_key
                    )
                else:
                    logging.warning(f"Skipping zone {zone.origin} sync for inactive master server {zone.master_server.name}")

                # Clear dirty flag and update timestamp
                zone.content_dirty = False
                zone.last_content_sync = datetime.now(timezone.utc)
                session.add(zone)
                session.commit()

                logging.info(f"Successfully synced content for zone {zone.origin}")

            except Exception as e:
                logging.error(f"Failed to sync content for zone {zone.origin}: {e}")

    logging.debug("Background sync iteration finished")

async def background_sync_loop():
    """Background task that syncs dirty configs and zones to backend servers.

    Runs every BACKEND_SYNC_PERIOD seconds or immediately when triggered by DDNS updates.
    """
    global _sync_event
    _sync_event = asyncio.Event()

    while True:
        try:
            # Wait for either configured timeout or sync event trigger
            try:
                await asyncio.wait_for(_sync_event.wait(), timeout=settings.BACKEND_SYNC_PERIOD)
                _sync_event.clear()
                logging.debug("Background sync triggered by event")
            except asyncio.TimeoutError:
                logging.debug(f"Background sync triggered by timeout ({settings.BACKEND_SYNC_PERIOD}s)")

            # Add a short delay before starting sync (to batch multiple updates)
            await asyncio.sleep(settings.BACKEND_SYNC_DELAY)
            await do_background_sync()

        except Exception as e:
            logging.error(f"Error in background sync loop: {e}")
            # Continue running even if there's an error


# helper functions not bound to web views
def verify_user(username: str, password: str) -> Optional[User]:
    with Session(engine) as session:
        statement = select(User).where(User.username == username)
        user = session.exec(statement).one_or_none()
        if user and user.verify_password(password) and user.is_active:
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

        if user_token and (not user_token.expires_at or user_token.expires_at > datetime.now(timezone.utc)) and
            user_token.is_active and user_token.user.is_active:
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
async def ddns_update_token(bearer_token: str, domain_name: str, ipaddr: str, src_ip: str) -> str:
    logging.info(f"DYNDNS GET update: (auth bearer) hostname {domain_name} myip: {ipaddr} source_ip: {src_ip}")
    user = verify_bearer_token(bearer_token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"})

    logging.debug(f"DYNDNS GET update: bearer token resolved to user {user}")
    return await _ddns_update(user, domain_name, ipaddr, src_ip)


async def ddns_update_basic(username: str, password: str, domain_name: str, ipaddr: str, src_ip: str) -> str:
    logging.info(f"DYNDNS GET update: (auth basic) hostname {domain_name} myip: {ipaddr} source_ip: {src_ip}")
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
            logging.error(f"User {user.username} has either TOTP or PassKey enabled -> Basic Auth denied. Use bearer token.")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Basic authentication not allowed for users with 2FA/PassKey/SSO enabled. Use bearer token.",
                headers={"WWW-Authenticate": "Bearer"})

    return await _ddns_update(user, domain_name, ipaddr, src_ip)


async def _ddns_update(user: User, domain_name: str, ipaddr: str, src_ip: str) -> str:
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
            session.add(table(label=label, rrclass=RRClass.IN, ttl=settings.DDNS_RR_TTL, zone=zone, value=str(norm_ipaddr), last_update_info=f"DDNS {src_ip}"))
            changed = True

        if changed:
            zone.soa_SERIAL += 1
            zone.content_dirty = True
            zone.last_update_info = f"DDNS {src_ip}"

            # Update the record's last_update_info as well if it exists
            if len(matched_rrs) >= 1:
                matched_rrs[0].last_update_info = f"DDNS {src_ip}"

            session.commit()
            # Trigger immediate background sync after DDNS update
            trigger_background_sync()
            return f"DDNS updated {table.__name__} {label=} {zone.origin=} -> {norm_ipaddr}"
        else:
            return f"DDNS noop {table.__name__} {label=} {zone.origin=} -> {norm_ipaddr}"
