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
