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
from fastapi import FastAPI, Depends, status, Request
from fastapi.responses import PlainTextResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials, HTTPBearer, HTTPAuthorizationCredentials
from fastapi.exceptions import HTTPException
import logging
import asyncio

from pydantic import BaseModel

from .admin import add_admin
from .view import ddns_update_basic, ddns_update_token
from .model import User
from .settings import settings
from .backend import background_sync_loop

app = FastAPI(root_path=settings.ROOT_PATH)
basic_security = HTTPBasic()
bearer_security = HTTPBearer(auto_error=False)
add_admin(app)

@app.on_event("startup")
async def startup_event():
    """Start the background sync loop on startup"""
    asyncio.create_task(background_sync_loop())


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
ddns_responses={400:{'model': Status, 'description': 'Bad request'},
                401:{'model': Status, 'description': 'Unauthorized request'},
                404:{'model': Status, 'description': 'Zone not found'}}
@app.get("/ddns/update", response_model=Status, responses=ddns_responses)
@app.get("/update", response_model=Status, responses=ddns_responses)
async def get_ddns_update(
    request: Request,
    hostname: str,
    myip: str
) -> Status:

    try:
        basic_creds = await basic_security(request)
    except:
        basic_creds = None

    try:
        bearer_token = await bearer_security(request)
    except:
        bearer_token = None

    logging.error(f"DEBUG: {str(bearer_token)}")
    try:
        if bearer_token and bearer_token.credentials:
            update_status = await ddns_update_token(
                bearer_token.credentials,
                hostname,
                myip,
            )
            return Status(detail=update_status)
        elif basic_creds:
            logging.info(f"DYNDNS GET update: basic auth hostname {hostname} myip: {myip}")
            update_status = await ddns_update_basic(
                basic_creds.username,
                basic_creds.password,
                hostname,
                myip,
            )
            return Status(detail=update_status)
        else:
            logging.debug("No authentication provided")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required",
                headers={"WWW-Authenticate": "Basic, Bearer"})
    except HTTPException:
        raise
    except Exception as e:
        logging.exception("Unexpected exception in ddns_update:")
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))
