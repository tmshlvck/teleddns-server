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

from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Request, Header
from pydantic import BaseModel
from sqlmodel import Session, select
import logging
import secrets
from datetime import datetime

from .model import (
    engine, User, Group, Zone, Server, APIToken, RR_CLASSES,
    A, AAAA, NS, PTR, CNAME, TXT, CAA, MX, SRV, RRClass
)
# from .fastapi_users_auth import get_current_user, require_api_token
from fastapi.security import HTTPBearer
from .view import verify_user, verify_token
from .view import mark_zone_for_update, mark_server_for_config_update, can_write_to_zone
from .sync import update_last_change_time

router = APIRouter(prefix="/api/v1", tags=["REST API"])

# Authentication dependency
async def get_current_user(authorization: Optional[str] = Header(None)) -> User:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid authorization header")
    
    token = authorization.split(" ")[1]
    user = verify_token(token)
    
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    if not user.is_active:
        raise HTTPException(status_code=401, detail="User account is disabled")
    
    return user

# Pydantic models for API requests/responses
class UserResponse(BaseModel):
    id: int
    username: str
    email: Optional[str] = None
    is_admin: bool
    is_active: bool
    has_2fa: bool
    has_passkey: bool

class GroupResponse(BaseModel):
    id: int
    name: str
    description: Optional[str] = None

class ServerResponse(BaseModel):
    id: int
    name: str
    api_url: str
    master_template: str

class ServerCreate(BaseModel):
    name: str
    api_url: str
    api_key: str
    master_template: str

class ZoneResponse(BaseModel):
    id: int
    origin: str
    soa_SERIAL: int
    server_id: int
    user_id: Optional[int] = None
    group_id: Optional[int] = None
    needs_update: bool

class ZoneCreate(BaseModel):
    origin: str
    server_id: int
    soa_MNAME: Optional[str] = "ns1.example.com."
    soa_RNAME: Optional[str] = "admin.example.com."
    soa_REFRESH: Optional[int] = 3600
    soa_RETRY: Optional[int] = 900
    soa_EXPIRE: Optional[int] = 1209600
    soa_MINIMUM: Optional[int] = 86400
    user_id: Optional[int] = None
    group_id: Optional[int] = None

class RRResponse(BaseModel):
    id: int
    zone_id: int
    label: str
    ttl: int
    rrclass: str
    value: str
    placeholder: bool

class RRCreate(BaseModel):
    zone_id: int
    label: str
    ttl: Optional[int] = 3600
    rrclass: Optional[str] = "IN"
    value: str

class TokenResponse(BaseModel):
    id: int
    token: str
    description: Optional[str] = None
    created_at: datetime

class TokenCreate(BaseModel):
    description: Optional[str] = None


def audit_log(user: User, action: str, resource: str, resource_id: int, 
              details: Optional[Dict[str, Any]] = None, client_ip: str = "unknown"):
    """Audit logging function"""
    log_entry = f"AUDIT: user={user.username} action={action} resource={resource} id={resource_id} ip={client_ip}"
    if details:
        log_entry += f" details={details}"
    logging.info(log_entry)


# User endpoints (admin only)
@router.get("/users", response_model=List[UserResponse])
async def list_users(user: User = Depends(get_current_user)):
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    with Session(engine) as session:
        users = session.exec(select(User)).all()
        return [UserResponse(**user.dict()) for user in users]


# Group endpoints (admin only)  
@router.get("/groups", response_model=List[GroupResponse])
async def list_groups(user: User = Depends(get_current_user)):
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    with Session(engine) as session:
        groups = session.exec(select(Group)).all()
        return [GroupResponse(**group.dict()) for group in groups]


# Server endpoints (admin only)
@router.get("/servers", response_model=List[ServerResponse])
async def list_servers(user: User = Depends(get_current_user)):
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    with Session(engine) as session:
        servers = session.exec(select(Server)).all()
        return [ServerResponse(
            id=server.id,
            name=server.name,
            api_url=server.api_url,
            master_template=server.master_template
        ) for server in servers]


@router.post("/servers", response_model=ServerResponse)
async def create_server(
    server_data: ServerCreate, 
    request: Request,
    user: User = Depends(get_current_user)
):
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    with Session(engine) as session:
        server = Server(**server_data.dict())
        session.add(server)
        session.commit()
        session.refresh(server)
        
        audit_log(user, "CREATE", "server", server.id, 
                 {"name": server.name}, request.client.host if request.client else "unknown")
        update_last_change_time()
        
        return ServerResponse(
            id=server.id,
            name=server.name,
            api_url=server.api_url,
            master_template=server.master_template
        )


# Zone endpoints
@router.get("/zones", response_model=List[ZoneResponse])
async def list_zones(user: User = Depends(get_current_user)):
    with Session(engine) as session:
        if user.is_admin:
            zones = session.exec(select(Zone)).all()
        else:
            # Filter zones by user access
            zones = session.exec(
                select(Zone).where(
                    (Zone.user_id == user.id) | 
                    (Zone.group_id.in_([g.id for g in user.groups]))
                )
            ).all()
        
        return [ZoneResponse(**zone.dict()) for zone in zones]


@router.post("/zones", response_model=ZoneResponse)
async def create_zone(
    zone_data: ZoneCreate,
    request: Request,
    user: User = Depends(get_current_user)
):
    with Session(engine) as session:
        # Check if zone already exists
        existing = session.exec(
            select(Zone).where(Zone.origin == zone_data.origin.rstrip('.') + '.')
        ).first()
        
        if existing:
            raise HTTPException(status_code=400, detail="Zone already exists")
        
        # Create zone
        zone_dict = zone_data.dict()
        zone_dict['origin'] = zone_data.origin.rstrip('.') + '.'
        zone_dict['soa_NAME'] = zone_dict['origin']
        zone_dict['soa_CLASS'] = RRClass.IN
        zone_dict['soa_TTL'] = zone_data.soa_MINIMUM or 86400
        zone_dict['soa_SERIAL'] = int(datetime.utcnow().timestamp())
        zone_dict['needs_update'] = True
        
        # Set ownership
        if not zone_data.user_id and not user.is_admin:
            zone_dict['user_id'] = user.id
        
        zone = Zone(**zone_dict)
        session.add(zone)
        session.commit()
        session.refresh(zone)
        
        # Create default NS records
        ns_record = NS(
            zone_id=zone.id,
            label="@",
            ttl=86400,
            rrclass=RRClass.IN,
            value=zone_data.soa_MNAME
        )
        session.add(ns_record)
        session.commit()
        
        mark_zone_for_update(zone.id)
        audit_log(user, "CREATE", "zone", zone.id, 
                 {"origin": zone.origin}, request.client.host if request.client else "unknown")
        
        return ZoneResponse(**zone.dict())


@router.get("/zones/{zone_id}", response_model=ZoneResponse)
async def get_zone(zone_id: int, user: User = Depends(get_current_user)):
    with Session(engine) as session:
        zone = session.get(Zone, zone_id)
        if not zone:
            raise HTTPException(status_code=404, detail="Zone not found")
        
        if not user.is_admin and not can_write_to_zone(session, user, zone, ""):
            raise HTTPException(status_code=403, detail="Access denied")
        
        return ZoneResponse(**zone.dict())


# DNS Record endpoints
@router.get("/zones/{zone_id}/records", response_model=List[RRResponse])
async def list_zone_records(zone_id: int, user: User = Depends(get_current_user)):
    with Session(engine) as session:
        zone = session.get(Zone, zone_id)
        if not zone:
            raise HTTPException(status_code=404, detail="Zone not found")
        
        if not user.is_admin and not can_write_to_zone(session, user, zone, ""):
            raise HTTPException(status_code=403, detail="Access denied")
        
        records = []
        for rr_class in RR_CLASSES:
            rrs = session.exec(
                select(rr_class).where(rr_class.zone_id == zone_id)
            ).all()
            
            for rr in rrs:
                records.append(RRResponse(
                    id=rr.id,
                    zone_id=rr.zone_id,
                    label=rr.label,
                    ttl=rr.ttl,
                    rrclass=rr.rrclass.value,
                    value=rr.value,
                    placeholder=rr.placeholder
                ))
        
        return records


@router.post("/zones/{zone_id}/records/{record_type}", response_model=RRResponse)
async def create_record(
    zone_id: int,
    record_type: str,
    record_data: RRCreate,
    request: Request,
    user: User = Depends(get_current_user)
):
    # Map record type to class
    type_map = {
        "A": A, "AAAA": AAAA, "NS": NS, "PTR": PTR,
        "CNAME": CNAME, "TXT": TXT, "CAA": CAA, "MX": MX, "SRV": SRV
    }
    
    if record_type.upper() not in type_map:
        raise HTTPException(status_code=400, detail="Invalid record type")
    
    rr_class = type_map[record_type.upper()]
    
    with Session(engine) as session:
        zone = session.get(Zone, zone_id)
        if not zone:
            raise HTTPException(status_code=404, detail="Zone not found")
        
        if not user.is_admin and not can_write_to_zone(session, user, zone, record_data.label):
            raise HTTPException(status_code=403, detail="Access denied")
        
        # Create record
        record_dict = record_data.dict()
        record_dict['rrclass'] = RRClass.IN
        
        record = rr_class(**record_dict)
        session.add(record)
        
        # Update zone serial
        zone.soa_SERIAL += 1
        zone.needs_update = True
        
        session.commit()
        session.refresh(record)
        
        mark_zone_for_update(zone_id)
        audit_log(user, "CREATE", f"{record_type.upper()}_record", record.id,
                 {"label": record.label, "value": record.value, "zone": zone.origin},
                 request.client.host if request.client else "unknown")
        
        return RRResponse(
            id=record.id,
            zone_id=record.zone_id,
            label=record.label,
            ttl=record.ttl,
            rrclass=record.rrclass.value,
            value=record.value,
            placeholder=record.placeholder
        )


# API Token endpoints (user can manage their own tokens)
@router.get("/tokens", response_model=List[TokenResponse])
async def list_tokens(user: User = Depends(get_current_user)):
    with Session(engine) as session:
        tokens = session.exec(
            select(APIToken).where(APIToken.user_id == user.id)
        ).all()
        
        return [TokenResponse(
            id=token.id,
            token=token.token,
            description=token.description,
            created_at=token.created_at
        ) for token in tokens]


@router.post("/tokens", response_model=TokenResponse)
async def create_token(
    token_data: TokenCreate,
    request: Request,
    user: User = Depends(get_current_user)
):
    with Session(engine) as session:
        token = APIToken(
            token=secrets.token_urlsafe(32),
            description=token_data.description,
            user_id=user.id
        )
        session.add(token)
        session.commit()
        session.refresh(token)
        
        audit_log(user, "CREATE", "api_token", token.id,
                 {"description": token.description},
                 request.client.host if request.client else "unknown")
        
        return TokenResponse(
            id=token.id,
            token=token.token,
            description=token.description,
            created_at=token.created_at
        )


@router.delete("/tokens/{token_id}")
async def delete_token(
    token_id: int,
    request: Request,
    user: User = Depends(get_current_user)
):
    with Session(engine) as session:
        token = session.get(APIToken, token_id)
        if not token:
            raise HTTPException(status_code=404, detail="Token not found")
        
        if token.user_id != user.id and not user.is_admin:
            raise HTTPException(status_code=403, detail="Access denied")
        
        audit_log(user, "DELETE", "api_token", token.id,
                 {"description": token.description},
                 request.client.host if request.client else "unknown")
        
        session.delete(token)
        session.commit()
        
        return {"detail": "Token deleted"}