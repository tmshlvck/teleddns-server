"""
TeleDDNS Server - Manager App Services
(C) 2015-2024 Tomas Hlavacek (tmshlvck@gmail.com)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

import logging
import requests
from typing import List, Dict, Any, Optional, Tuple
from django.conf import settings
from django.db import transaction
from django.utils import timezone

from .models import Zone, Server, RR_MODELS

logger = logging.getLogger(__name__)


class DNSServerError(Exception):
    """Exception raised when DNS server operations fail"""
    pass


def generate_zone_file(zone: Zone) -> str:
    """
    Generate a complete BIND-format zone file for the given zone.

    Args:
        zone: The Zone object to generate the file for

    Returns:
        A string containing the complete zone file
    """
    lines = []

    # Add zone header and SOA record
    # Check if zone has a separate SOA record
    if hasattr(zone, 'soa'):
        # Use the new SOA model
        lines.append(f"$ORIGIN {zone.origin};\n$TTL {settings.DDNS_DEFAULT_TTL};")
        lines.append(zone.soa.format_bind_zone())
    else:
        # Fall back to fake SOA fields to avoid spitting out invalid zone
        lines.append(f"$ORIGIN {zone.origin};\n$TTL {settings.DDNS_DEFAULT_TTL};")
        lines.append("@    3600  IN SOA unknown.tld na.unknown.tld 1970010100 86400 7200 3600000 172800")

    # Add all resource records
    for rr_model in RR_MODELS:
        # Skip SOA model since it's already handled above
        if rr_model.__name__ == 'SOA':
            continue
        records = rr_model.objects.filter(zone=zone).order_by('label', 'created_at')
        for record in records:
            lines.append(record.format_bind_zone())

    # Add empty line at the end
    lines.append('')

    return '\n'.join(lines)


def push_zone_to_server(zone: Zone, server: Server) -> bool:
    """
    Push a zone file to a DNS server via its API.

    Args:
        zone: The Zone object to push
        server: The Server object to push to

    Returns:
        True if successful, False otherwise

    Raises:
        DNSServerError: If the server returns an error
    """
    try:
        # Generate the zone file
        zone_content = generate_zone_file(zone)

        # Prepare the API request
        zone_name = zone.origin.rstrip('.').strip()
        url = f"{server.api_url.rstrip('/')}/zonewrite?zonename={zone_name}"

        headers = {
            'Authorization': f'Bearer {server.api_key}',
            'Content-Type': 'text/plain',
        }

        # Send the zone file to the server
        logger.info(f"Pushing zone {zone.origin} to server {server.name}")
        response = requests.put(
            url,
            data=zone_content,
            headers=headers,
            timeout=30
        )

        if response.status_code == 201:
            logger.info(f"Successfully pushed zone {zone.origin} to server {server.name}")

            # Reload the zone after successful push
            try:
                if push_zone_reload(zone, server):
                    logger.info(f"Successfully reloaded zone {zone.origin} on server {server.name}")
                else:
                    logger.warning(f"Zone {zone.origin} was pushed to server {server.name} but reload failed")
                    # Still return True as the zone content was successfully written
            except DNSServerError as e:
                logger.warning(f"Zone {zone.origin} was pushed to server {server.name} but reload failed: {str(e)}")
                # Still return True as the zone content was successfully written

            return True
        else:
            logger.error(
                f"Failed to push zone {zone.origin} to server {server.name}: "
                f"HTTP {response.status_code} - {response.text}"
            )
            raise DNSServerError(
                f"Server returned HTTP {response.status_code}: {response.text}"
            )

    except requests.RequestException as e:
        logger.error(f"Network error pushing zone {zone.origin} to server {server.name}: {e}")
        raise DNSServerError(f"Network error: {e}")
    except Exception as e:
        logger.error(f"Unexpected error pushing zone {zone.origin} to server {server.name}: {e}")
        raise DNSServerError(f"Unexpected error: {e}")


def update_zone(zone: Zone) -> Tuple[bool, List[str]]:
    """
    Update a zone on all its configured servers.

    Args:
        zone: The Zone object to update

    Returns:
        A tuple of (success, errors) where success is True if all servers
        were updated successfully, and errors is a list of error messages
    """
    from django.utils import timezone
    from .models import ZoneServer

    errors = []
    overall_success = True

    # Track which servers were successfully updated
    successful_servers = []

    # Get master and slave servers from ZoneServer relationships
    master_zone_server = zone.zone_servers.filter(role='master').select_related('server').first()
    if not master_zone_server:
        return False, ["No master server configured for this zone"]

    master_server = master_zone_server.server

    # 1. Push zone content to master server if content is dirty
    if zone.content_dirty:
        try:
            if push_zone_to_server(zone, master_server):
                successful_servers.append(('master_content', master_zone_server))
                logger.info(f"Successfully pushed zone content for {zone.origin} to master {master_server.name}")
            else:
                overall_success = False
                errors.append(f"Failed to update master server {master_server.name}")
        except DNSServerError as e:
            overall_success = False
            errors.append(f"Master server {master_server.name}: {str(e)}")

    # 2. Update master server config if needed
    if master_zone_server.config_dirty:
        try:
            if push_server_config(master_server):
                # Also reload the server
                try:
                    if push_server_reload(master_server):
                        successful_servers.append(('master_config', master_zone_server))
                        logger.info(f"Successfully updated and reloaded master config for {zone.origin} on {master_server.name}")
                    else:
                        overall_success = False
                        errors.append(f"Failed to reload master server {master_server.name} after config update")
                except Exception as e:
                    overall_success = False
                    errors.append(f"Failed to reload master server {master_server.name}: {str(e)}")
            else:
                overall_success = False
                errors.append(f"Failed to update master server config {master_server.name}")
        except Exception as e:
            overall_success = False
            errors.append(f"Master server config {master_server.name}: {str(e)}")

    # 3. Update slave server configurations if needed
    slave_zone_servers = zone.zone_servers.filter(
        role='slave',
        config_dirty=True
    ).select_related('server')

    for zone_server in slave_zone_servers:
        try:
            if push_server_config(zone_server.server):
                # Also reload the server
                try:
                    if push_server_reload(zone_server.server):
                        successful_servers.append(('slave_config', zone_server))
                        logger.info(f"Successfully updated and reloaded slave config for {zone.origin} on {zone_server.server.name}")
                    else:
                        overall_success = False
                        errors.append(f"Failed to reload slave server {zone_server.server.name} after config update")
                except Exception as e:
                    overall_success = False
                    errors.append(f"Failed to reload slave server {zone_server.server.name}: {str(e)}")
            else:
                overall_success = False
                errors.append(f"Failed to update slave server config {zone_server.server.name}")
        except Exception as e:
            overall_success = False
            errors.append(f"Slave server config {zone_server.server.name}: {str(e)}")

    # 4. Update sync status based on what succeeded
    with transaction.atomic():
        now = timezone.now()

        # Update zone-level content dirty flag if master content was synced
        for op_type, zone_server in successful_servers:
            if op_type == 'master_content' and zone.content_dirty:
                zone.content_dirty = False
                zone.content_dirty_since = None
                zone.save(update_fields=['content_dirty', 'content_dirty_since', 'updated_at'])

        # Update ZoneServer statuses
        for op_type, zone_server in successful_servers:
            updates = {'last_sync_time': now}

            if op_type in ['master_config', 'slave_config']:
                updates['config_dirty'] = False
                updates['config_dirty_since'] = None

            # Update the ZoneServer instance
            for key, value in updates.items():
                setattr(zone_server, key, value)
            zone_server.save(update_fields=list(updates.keys()) + ['updated_at'])

    return overall_success, errors


def generate_server_config(server: Server) -> str:
    """
    Generate server configuration for all zones on a server.

    Args:
        server: The Server object to generate config for

    Returns:
        A string containing the server configuration
    """
    from .models import ZoneServer

    config_lines = []

    # Get all zone-server relationships for this server
    zone_servers = ZoneServer.objects.filter(
        server=server
    ).select_related('zone').order_by('zone__origin')

    for zone_server in zone_servers:
        zone = zone_server.zone

        if zone_server.role == 'master':
            # Master zone configuration
            config_lines.append(f"""zone:
- domain: {zone.origin}
  template: {server.master_template}
  file: {zone.origin.rstrip('.').strip()}.zone
""")
        else:  # role == 'slave'
            # Slave zone configuration
            # Find the master server for this zone
            master_zone_server = ZoneServer.objects.filter(
                zone=zone,
                role='master'
            ).select_related('server').first()

            if master_zone_server:
                config_lines.append(f"""zone:
- domain: {zone.origin}
  template: {server.slave_template}
  master: {master_zone_server.server.name}
  file: {zone.origin.rstrip('.').strip()}.zone
""")

    # Add empty line at the end
    config_lines.append('')

    return '\n'.join(config_lines)


def push_server_config(server: Server) -> bool:
    """
    Push server configuration to a DNS server.

    Args:
        server: The Server object to push config to

    Returns:
        True if successful, False otherwise

    Raises:
        DNSServerError: If the server returns an error
    """
    try:
        # Generate the configuration
        config_content = generate_server_config(server)

        # Prepare the API request
        url = f"{server.api_url.rstrip('/')}/configwrite"

        headers = {
            'Authorization': f'Bearer {server.api_key}',
            'Content-Type': 'text/plain',
        }

        # Send the configuration to the server
        logger.info(f"Pushing configuration to server {server.name}")
        response = requests.put(
            url,
            data=config_content,
            headers=headers,
            timeout=30
        )

        if response.status_code == 201:
            logger.info(f"Successfully pushed configuration to server {server.name}")
            return True
        else:
            logger.error(
                f"Failed to push configuration to server {server.name}: "
                f"HTTP {response.status_code} - {response.text}"
            )
            raise DNSServerError(
                f"Server returned HTTP {response.status_code}: {response.text}"
            )

    except requests.RequestException as e:
        logger.error(f"Network error pushing configuration to server {server.name}: {e}")
        raise DNSServerError(f"Network error: {e}")
    except Exception as e:
        logger.error(f"Unexpected error pushing configuration to server {server.name}: {e}")
        raise DNSServerError(f"Unexpected error: {e}")


def push_server_reload(server: Server) -> bool:
    """
    Trigger a configuration reload on a DNS server.

    Args:
        server: The Server object to reload

    Returns:
        True if successful, False otherwise

    Raises:
        DNSServerError: If the server returns an error
    """
    try:
        # Prepare the API request
        url = f"{server.api_url.rstrip('/')}/configreload"

        headers = {
            'Authorization': f'Bearer {server.api_key}',
        }

        # Send the reload request to the server
        logger.info(f"Triggering configuration reload on server {server.name}")
        response = requests.post(
            url,
            headers=headers,
            timeout=30
        )

        if response.status_code == 200:
            logger.info(f"Successfully triggered reload on server {server.name}")
            return True
        else:
            logger.error(
                f"Failed to reload server {server.name}: "
                f"HTTP {response.status_code} - {response.text}"
            )
            raise DNSServerError(
                f"Server returned HTTP {response.status_code}: {response.text}"
            )

    except requests.RequestException as e:
        logger.error(f"Network error reloading server {server.name}: {e}")
        raise DNSServerError(f"Network error: {e}")
    except Exception as e:
        logger.error(f"Unexpected error reloading server {server.name}: {e}")
        raise DNSServerError(f"Unexpected error: {e}")


def push_zone_reload(zone: Zone, server: Server) -> bool:
    """
    Trigger a zone-specific reload on a DNS server.

    Args:
        zone: The Zone object to reload
        server: The Server object to reload the zone on

    Returns:
        True if successful, False otherwise

    Raises:
        DNSServerError: If the server returns an error
    """
    try:
        # Prepare the API request
        zone_name = zone.origin.rstrip('.').strip()
        url = f"{server.api_url.rstrip('/')}/zonereload?zonename={zone_name}"

        headers = {
            'Authorization': f'Bearer {server.api_key}',
        }

        # Send the zone reload request to the server
        logger.info(f"Triggering zone reload for {zone.origin} on server {server.name}")
        response = requests.get(
            url,
            headers=headers,
            timeout=30
        )

        if response.status_code == 200:
            logger.info(f"Successfully triggered zone reload for {zone.origin} on server {server.name}")
            return True
        else:
            logger.error(
                f"Failed to reload zone {zone.origin} on server {server.name}: "
                f"HTTP {response.status_code} - {response.text}"
            )
            raise DNSServerError(
                f"Server returned HTTP {response.status_code}: {response.text}"
            )

    except requests.RequestException as e:
        logger.error(f"Network error reloading zone {zone.origin} on server {server.name}: {e}")
        raise DNSServerError(f"Network error: {e}")
    except Exception as e:
        logger.error(f"Unexpected error reloading zone {zone.origin} on server {server.name}: {e}")
        raise DNSServerError(f"Unexpected error: {e}")


def check_zone_on_server(zone: Zone, server: Server) -> Dict[str, Any]:
    """
    Check the status of a zone on a DNS server.

    Args:
        zone: The Zone object to check
        server: The Server object to check on

    Returns:
        A dictionary with the check results
    """
    try:
        zone_name = zone.origin.rstrip('.').strip()
        url = f"{server.api_url.rstrip('/')}/zonecheck?zonename={zone_name}"

        headers = {
            'Authorization': f'Bearer {server.api_key}',
        }

        response = requests.get(
            url,
            headers=headers,
            timeout=30
        )

        if response.status_code == 201:
            return response.json()
        else:
            return {
                'status': 'error',
                'message': f'HTTP {response.status_code}: {response.text}'
            }

    except requests.RequestException as e:
        logger.error(f"Network error checking zone {zone.origin} on server {server.name}: {e}")
        return {
            'status': 'error',
            'message': f'Network error: {str(e)}'
        }
    except Exception as e:
        logger.error(f"Unexpected error checking zone {zone.origin} on server {server.name}: {e}")
        return {
            'status': 'error',
            'message': f'Unexpected error: {str(e)}'
        }


def sync_all_dirty_zones() -> Dict[str, Any]:
    """
    Synchronize all zones marked as dirty to their respective servers.

    Returns:
        A dictionary with synchronization results
    """
    from .models import ZoneServerStatus

    results = {
        'total': 0,
        'success': 0,
        'failed': 0,
        'errors': []
    }

    # Find zones with dirty content or any dirty server configs
    all_dirty_zones = Zone.objects.filter(
        models.Q(content_dirty=True) | models.Q(zone_servers__config_dirty=True)
    ).prefetch_related('zone_servers__server').distinct()

    results['total'] = all_dirty_zones.count()

    for zone in all_dirty_zones:
        try:
            success, errors = update_zone(zone)
            if success:
                results['success'] += 1
                logger.info(f"Successfully synchronized zone {zone.origin}")
            else:
                results['failed'] += 1
                for error in errors:
                    results['errors'].append(f"{zone.origin}: {error}")
                    logger.error(f"Failed to synchronize zone {zone.origin}: {error}")
        except Exception as e:
            results['failed'] += 1
            results['errors'].append(f"{zone.origin}: Unexpected error: {str(e)}")
            logger.exception(f"Unexpected error synchronizing zone {zone.origin}")

    return results








def validate_zone_consistency(zone: Zone) -> List[str]:
    """
    Validate the consistency of a zone's data.

    Args:
        zone: The Zone object to validate

    Returns:
        A list of validation errors (empty if valid)
    """
    errors = []

    # Check for duplicate labels in certain record types
    exclusive_types = [CNAME]  # CNAME records must not coexist with other records

    for rr_model in exclusive_types:
        cname_records = rr_model.objects.filter(zone=zone)
        for cname in cname_records:
            # Check if there are other records with the same label
            for other_model in RR_MODELS:
                if other_model == rr_model:
                    continue

                if other_model.objects.filter(zone=zone, label=cname.label).exists():
                    errors.append(
                        f"CNAME record '{cname.label}' conflicts with other record types"
                    )

    # Check for required NS records at zone apex
    ns_at_apex = NS.objects.filter(zone=zone, label='@').count()
    if ns_at_apex == 0:
        errors.append("Zone must have at least one NS record at the apex (@)")

    # Add more validation rules as needed

    return errors


def increment_zone_serial(zone: Zone) -> int:
    """
    Increment a zone's serial number and mark it as dirty.

    Args:
        zone: The Zone object to update

    Returns:
        The new serial number
    """
    with transaction.atomic():
        # Increment serial through SOA record
        if hasattr(zone, 'soa'):
            zone.soa.increment_serial()
            new_serial = zone.soa.serial
        else:
            raise ValueError(f"Zone {zone.origin} has no associated SOA record")

        from django.utils import timezone
        zone.content_dirty = True
        zone.content_dirty_since = timezone.now()
        zone.save(update_fields=['content_dirty', 'content_dirty_since', 'updated_at'])

    logger.info(f"Incremented serial for zone {zone.origin} to {new_serial}")
    return new_serial
