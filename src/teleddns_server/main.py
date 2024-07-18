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

from typing import Dict, Optional, Annotated
from fastapi import FastAPI, Depends, status
from fastapi.responses import PlainTextResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.exceptions import HTTPException
import logging
import asyncio

from pydantic import BaseModel

from .admin import add_admin
from .view import ddns_update
from .model import User

app = FastAPI()
security = HTTPBasic()
add_admin(app)


class Status(BaseModel):
    detail: str

@app.get("/")
def get_root() -> Status:
    return Status(detail="NOOP")

#responses={400:{'model': Status, 'description': 'Bad request'},
#           401:{'model': Status, 'description': 'Unauthorized request'},
#           404:{'model': Status, 'description': 'Zone not found'}}
#@app.get("/zone/{zonename}", response_class=PlainTextResponse, responses=responses)
#async def get_zone(zonename: str) -> PlainTextResponse:
#    # TODO: API key auth
#    return PlainTextResponse(content=await gen_bind_zone(zonename))
    


# DynDNS Example HTTP query:
# POST /nic/update?hostname=subdomain.yourdomain.com&myip=1.2.3.4 HTTP/1.1
# Host: domains.google.com
# Authorization: Basic base64-encoded-auth-string
ddns_responses={400:{'model': Status, 'description': 'Bad request'},
                401:{'model': Status, 'description': 'Unauthorized request'},
                404:{'model': Status, 'description': 'Zone not found'}}
@app.get("/ddns/update", response_model=Status, responses=ddns_responses)
@app.get("/update", response_model=Status, responses=ddns_responses)
async def get_ddns_update(creds: Annotated[HTTPBasicCredentials, Depends(security)], hostname: str, myip: str) -> Status:
    logging.info(f"DYNDNS GET update: user {creds.username} hostname {hostname} myip: {myip}")
    update_status = await ddns_update(creds.username, creds.password, hostname, myip)
    return Status(detail=update_status)
