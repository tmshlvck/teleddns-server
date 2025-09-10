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

from typing import Dict, Optional, Annotated, Union
from fastapi import FastAPI, Depends, status, Header
from fastapi.responses import PlainTextResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials, HTTPBearer
from fastapi.exceptions import HTTPException
import logging
import asyncio

from pydantic import BaseModel

from .admin import add_admin
from .view import ddns_update
from .model import User
from .settings import settings

app = FastAPI(root_path=settings.ROOT_PATH)
security = HTTPBasic()
bearer_security = HTTPBearer(auto_error=False)
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


@app.get('/robots.txt', response_class=PlainTextResponse)
async def robots():
    return """User-agent: *\nDisallow: /"""


# DynDNS Example HTTP query:
# POST /nic/update?hostname=subdomain.yourdomain.com&myip=1.2.3.4 HTTP/1.1
# Host: domains.google.com
# Authorization: Basic base64-encoded-auth-string
async def get_auth_credentials(
    basic_creds: Annotated[Optional[HTTPBasicCredentials], Depends(security)],
    bearer_token: Annotated[Optional[str], Depends(bearer_security)]
) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """Extract authentication credentials from either Basic or Bearer auth."""
    if bearer_token and bearer_token.credentials:
        return None, None, bearer_token.credentials
    elif basic_creds:
        return basic_creds.username, basic_creds.password, None
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Basic, Bearer"})

ddns_responses={400:{'model': Status, 'description': 'Bad request'},
                401:{'model': Status, 'description': 'Unauthorized request'},
                404:{'model': Status, 'description': 'Zone not found'}}
@app.get("/ddns/update", response_model=Status, responses=ddns_responses)
@app.get("/update", response_model=Status, responses=ddns_responses)
async def get_ddns_update(
    auth_creds: Annotated[tuple, Depends(get_auth_credentials)],
    hostname: str,
    myip: str
) -> Status:
    username, password, bearer_token = auth_creds

    if bearer_token:
        logging.info(f"DYNDNS GET update: bearer token auth hostname {hostname} myip: {myip}")
    else:
        logging.info(f"DYNDNS GET update: basic auth user {username} hostname {hostname} myip: {myip}")

    try:
        update_status = await ddns_update(
            username or "",
            password or "",
            hostname,
            myip,
            bearer_token
        )
        return Status(detail=update_status)
    except HTTPException:
        raise
    except Exception as e:
        logging.exception("Unexpected exception in ddns_update:")
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))
