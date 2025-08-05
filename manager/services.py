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
    lines.append(zone.format_bind_zone())

    # Add all resource records
    for rr_model in RR_MODELS:
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
        url = f"{server.api_url.rstrip('/')}/zones/{zone_name}"

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

        if response.status_code == 200:
            logger.info(f"Successfully pushed zone {zone.origin} to server {server.name}")
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
    errors = []
    success = True

    # Push to master server
    try:
        if not push_zone_to_server(zone, zone.master_server):
            success = False
            errors.append(f"Failed to update master server {zone.master_server.name}")
    except DNSServerError as e:
        success = False
        errors.append(f"Master server {zone.master_server.name}: {str(e)}")

    # Note: Slave servers typically get their zone data via AXFR from the master,
    # so we don't push zone content to them. We might need to notify them instead.

    # If successful, mark zone as clean
    if success:
        with transaction.atomic():
            zone.is_dirty = False
            zone.save(update_fields=['is_dirty', 'updated_at'])

    return success, errors


def generate_server_config(server: Server) -> str:
    """
    Generate server configuration for all zones on a server.

    Args:
        server: The Server object to generate config for

    Returns:
        A string containing the server configuration
    """
    config_lines = []

    # Add master zones
    master_zones = Zone.objects.filter(master_server=server).order_by('origin')
    for zone in master_zones:
        config_lines.append(f"""zone:
- domain: {zone.origin}
  template: {server.master_template}
  file: {zone.origin.rstrip('.').strip()}.zone
""")

    # Add slave zones
    slave_zones = server.slave_zones.all().order_by('origin')
    for zone in slave_zones:
        config_lines.append(f"""zone:
- domain: {zone.origin}
  template: {server.slave_template}
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
        url = f"{server.api_url.rstrip('/')}/config"

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

        if response.status_code == 200:
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
        url = f"{server.api_url.rstrip('/')}/zones/{zone_name}/check"

        headers = {
            'Authorization': f'Bearer {server.api_key}',
        }

        response = requests.get(
            url,
            headers=headers,
            timeout=30
        )

        if response.status_code == 200:
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
    results = {
        'total': 0,
        'success': 0,
        'failed': 0,
        'errors': []
    }

    dirty_zones = Zone.objects.filter(is_dirty=True).select_related('master_server')
    results['total'] = dirty_zones.count()

    for zone in dirty_zones:
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
            error_msg = f"{zone.origin}: Unexpected error: {str(e)}"
            results['errors'].append(error_msg)
            logger.error(error_msg)

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
        zone.soa_serial += 1
        zone.is_dirty = True
        zone.save(update_fields=['soa_serial', 'is_dirty', 'updated_at'])

    logger.info(f"Incremented serial for zone {zone.origin} to {zone.soa_serial}")
    return zone.soa_serial
