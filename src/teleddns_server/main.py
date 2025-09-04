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
from fastapi import FastAPI, Depends, status, Request
from fastapi.responses import PlainTextResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.exceptions import HTTPException
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
import logging
import asyncio
from contextlib import asynccontextmanager
from datetime import datetime

from pydantic import BaseModel

from .admin import add_admin
from .view import ddns_update
from .model import User, engine, SQLModel
from .settings import settings
from .sync import backend_sync_loop, get_health_status, update_last_change_time
# from .fastapi_users_auth import auth_backend, fastapi_users
from .api import router as api_router
from .web import router as web_router, auth_router
from .metrics import metrics_endpoint

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    import teleddns_server.sync as sync_module
    sync_module.startup_time = datetime.utcnow()
    
    # Create database tables
    SQLModel.metadata.create_all(engine)
    logging.info("Database tables created/verified")
    
    # Start background sync task if not disabled
    sync_task = None
    if not settings.DISABLE_BACKEND_LOOP:
        sync_task = asyncio.create_task(backend_sync_loop())
        logging.info("Backend sync loop started")
    
    yield
    
    # Shutdown
    if sync_task:
        sync_task.cancel()
        try:
            await sync_task
        except asyncio.CancelledError:
            pass
        logging.info("Backend sync loop stopped")

app = FastAPI(
    title="TeleDDNS Server",
    description="DDNS API combined with DNS management system",
    version="1.0.0",
    root_path=settings.ROOT_PATH, 
    lifespan=lifespan
)

# Add session middleware for web interface
app.add_middleware(SessionMiddleware, secret_key=settings.SESSION_SECRET)

# Authentication routes will be added later
# app.include_router(
#     fastapi_users.get_auth_router(auth_backend),
#     prefix="/auth/jwt",
#     tags=["auth"]
# )

# Add API routes
app.include_router(api_router)

# Add web interface routes  
app.include_router(web_router)

# Add authentication routes
app.include_router(auth_router)

# Add admin interface
security = HTTPBasic()
add_admin(app)

# Static files for web interface
# app.mount("/static", StaticFiles(directory="static"), name="static")


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


@app.get('/healthcheck', response_class=PlainTextResponse)
async def healthcheck():
    """Health check endpoint as specified in SPECS"""
    status, uptime, last_update, last_push = get_health_status()
    
    last_update_ts = int(last_update.timestamp())
    last_push_ts = int(last_push.timestamp())
    
    return f"{status} uptime={uptime} last_update={last_update_ts} last_push={last_push_ts}"


@app.get('/metrics')
async def prometheus_metrics():
    """Prometheus metrics endpoint"""
    return await metrics_endpoint()


# DynDNS Example HTTP query:
# POST /nic/update?hostname=subdomain.yourdomain.com&myip=1.2.3.4 HTTP/1.1
# Host: domains.google.com
# Authorization: Basic base64-encoded-auth-string
ddns_responses={400:{'model': Status, 'description': 'Bad request'},
                401:{'model': Status, 'description': 'Unauthorized request'},
                404:{'model': Status, 'description': 'Zone not found'}}
@app.get("/ddns/update", response_model=Status, responses=ddns_responses)
@app.get("/update", response_model=Status, responses=ddns_responses)
async def get_ddns_update(request: Request, creds: Annotated[HTTPBasicCredentials, Depends(security)], hostname: str, myip: str) -> Status:
    client_ip = request.client.host if request.client else "unknown"
    logging.info(f"DYNDNS GET update: user {creds.username} from {client_ip} hostname {hostname} myip: {myip}")
    try:
        update_status = await ddns_update(creds.username, creds.password, hostname, myip, client_ip)
        # Update the last change time for health monitoring
        update_last_change_time()
        return Status(detail=update_status)
    except HTTPException:
        raise
    except Exception as e:
        logging.exception("Unexpected exception in ddns_update:")
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))
