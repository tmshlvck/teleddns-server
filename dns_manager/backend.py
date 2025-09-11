"""
Backend integration for TeleDDNS Server.

Handles synchronous communication with Knot DNS servers.
Converts the original async backend functions to synchronous versions.
"""
import logging
import requests
import urllib.parse
from typing import Tuple
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


def _api_call_get(endpoint: str, apikey: str, timeout: int = 30) -> Tuple[int, str]:
    """Make GET request to backend API."""
    try:
        headers = {'Authorization': f"Bearer {apikey}"}
        response = requests.get(endpoint, headers=headers, timeout=timeout)
        return response.status_code, response.text
    except Exception as e:
        logger.error(f"API GET call to {endpoint} failed: {e}")
        raise


def _api_call_post(endpoint: str, apikey: str, data: str, timeout: int = 30) -> Tuple[int, str]:
    """Make POST request to backend API."""
    try:
        headers = {
            'Authorization': f"Bearer {apikey}",
            'Content-Type': 'text/plain'
        }
        response = requests.post(endpoint, headers=headers, data=data, timeout=timeout)
        return response.status_code, response.text
    except Exception as e:
        logger.error(f"API POST call to {endpoint} failed: {e}")
        raise


def update_zone(zone_name: str, zone_data: str, server_api_endpoint: str, server_api_key: str):
    """
    Update zone file on backend DNS server.
    
    Args:
        zone_name: DNS zone name (e.g., example.com)
        zone_data: Complete BIND zone file content
        server_api_endpoint: Backend API URL
        server_api_key: Backend API authorization key
        
    Raises:
        Exception: If update fails
    """
    logger.debug(f"Updating zone {zone_name} on {server_api_endpoint}")

    # Write zone file
    write_url = urllib.parse.urljoin(server_api_endpoint, f'/zonewrite?zonename={zone_name}')
    status, response = _api_call_post(write_url, server_api_key, zone_data)
    logger.info(f"Zone write to {write_url} finished: status={status}, response={response}")
    
    if status >= 400:
        raise Exception(f"Zone write failed with status {status}: {response}")

    # Reload zone
    reload_url = urllib.parse.urljoin(server_api_endpoint, f'/zonereload?zonename={zone_name}')
    status, response = _api_call_get(reload_url, server_api_key)
    logger.info(f"Zone reload at {reload_url} finished: status={status}, response={response}")
    
    if status >= 400:
        raise Exception(f"Zone reload failed with status {status}: {response}")


def update_config(server_config: str, server_api_endpoint: str, server_api_key: str):
    """
    Update DNS server configuration.
    
    Args:
        server_config: Complete Knot DNS configuration content
        server_api_endpoint: Backend API URL  
        server_api_key: Backend API authorization key
        
    Raises:
        Exception: If update fails
    """
    logger.debug(f"Updating config on {server_api_endpoint}")

    # Write config file
    write_url = urllib.parse.urljoin(server_api_endpoint, '/configwrite')
    status, response = _api_call_post(write_url, server_api_key, server_config)
    logger.info(f"Config write to {write_url} finished: status={status}, response={response}")
    
    if status >= 400:
        raise Exception(f"Config write failed with status {status}: {response}")

    # Reload config
    reload_url = urllib.parse.urljoin(server_api_endpoint, '/configreload')
    status, response = _api_call_get(reload_url, server_api_key)
    logger.info(f"Config reload at {reload_url} finished: status={status}, response={response}")
    
    if status >= 400:
        raise Exception(f"Config reload failed with status {status}: {response}")


