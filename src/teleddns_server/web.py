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

from typing import Optional, Dict, Any
from fastapi import APIRouter, Depends, Request, Form, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlmodel import Session, select, func
import secrets
import logging
from datetime import datetime

from .model import (
    engine, User, Zone, Server, APIToken, RR_CLASSES,
    A, AAAA, NS, PTR, CNAME, TXT, CAA, MX, SRV, RRClass
)
from .fastapi_users_auth import generate_totp_secret, generate_totp_qr_code
from fastapi import Header
from .view import verify_token, verify_user
from .view import mark_zone_for_update, can_write_to_zone
from .sync import update_last_change_time
import re
import ipaddress
from urllib.parse import quote

router = APIRouter(prefix="/web", tags=["Web Interface"])
templates = Jinja2Templates(directory="src/teleddns_server/templates")

# Simple session-based auth for web interface
def get_current_user_web(request: Request) -> User:
    user_id = request.session.get("user_id")
    if not user_id:
        # Redirect to login page instead of returning 401
        login_url = "/auth/login"
        if request.url.path != "/auth/login":
            login_url += f"?next={request.url.path}"
        raise HTTPException(
            status_code=status.HTTP_302_FOUND,
            detail="Redirecting to login",
            headers={"Location": login_url}
        )
    
    with Session(engine) as session:
        user = session.get(User, user_id)
        if not user:
            # Clear invalid session and redirect to login
            request.session.clear()
            raise HTTPException(
                status_code=status.HTTP_302_FOUND,
                detail="Redirecting to login",
                headers={"Location": "/auth/login"}
            )
        return user


def audit_log_web(user: User, action: str, resource: str, resource_id: int, 
                  details: Optional[Dict[str, Any]] = None, client_ip: str = "unknown"):
    """Audit logging for web interface actions"""
    log_entry = f"WEB_AUDIT: user={user.username} action={action} resource={resource} id={resource_id} ip={client_ip}"
    if details:
        log_entry += f" details={details}"
    logging.info(log_entry)


def _validate_record_value(record_type: str, value: str) -> Optional[str]:
    """Validate DNS record value based on type. Returns error message or None if valid."""
    if not value:
        return "Record value cannot be empty"
    
    try:
        if record_type == "A":
            ipaddress.IPv4Address(value)
        elif record_type == "AAAA":
            ipaddress.IPv6Address(value)
        elif record_type == "CNAME" or record_type == "NS" or record_type == "PTR":
            if not value.endswith('.'):
                return f"{record_type} records should end with a dot (.)"
            if not re.match(r'^[a-zA-Z0-9.-]+\.$', value):
                return f"Invalid {record_type} record format"
        elif record_type == "MX":
            parts = value.split(None, 1)
            if len(parts) != 2:
                return "MX record format: [priority] [hostname]"
            try:
                priority = int(parts[0])
                if priority < 0 or priority > 65535:
                    return "MX priority must be between 0 and 65535"
            except ValueError:
                return "MX priority must be a number"
            if not parts[1].endswith('.'):
                return "MX hostname should end with a dot (.)"
        elif record_type == "SRV":
            parts = value.split(None, 3)
            if len(parts) != 4:
                return "SRV record format: [priority] [weight] [port] [target]"
            try:
                priority, weight, port = int(parts[0]), int(parts[1]), int(parts[2])
                if not (0 <= priority <= 65535 and 0 <= weight <= 65535 and 1 <= port <= 65535):
                    return "SRV values out of range"
            except ValueError:
                return "SRV priority, weight, and port must be numbers"
            if not parts[3].endswith('.'):
                return "SRV target should end with a dot (.)"
        elif record_type == "CAA":
            parts = value.split(None, 2)
            if len(parts) != 3:
                return "CAA record format: [flag] [tag] [value]"
            try:
                flag = int(parts[0])
                if not (0 <= flag <= 255):
                    return "CAA flag must be between 0 and 255"
            except ValueError:
                return "CAA flag must be a number"
            if parts[1] not in ["issue", "issuewild", "iodef"]:
                return "CAA tag must be 'issue', 'issuewild', or 'iodef'"
    except ipaddress.AddressValueError:
        return f"Invalid {record_type} address format"
    except Exception as e:
        return f"Invalid {record_type} record: {str(e)}"
    
    return None


@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, user: User = Depends(get_current_user_web)):
    """Main dashboard"""
    with Session(engine) as session:
        # Get statistics
        if user.is_admin:
            zone_count = session.exec(select(func.count(Zone.id))).one()
            server_count = session.exec(select(func.count(Server.id))).one()
        else:
            # Count zones user has access to
            zone_count = session.exec(
                select(func.count(Zone.id)).where(
                    (Zone.user_id == user.id) |
                    (Zone.group_id.in_([g.id for g in user.groups]))
                )
            ).one()
            server_count = 0
        
        token_count = session.exec(
            select(func.count(APIToken.id)).where(APIToken.user_id == user.id)
        ).one()
        
        # Count total records across all RR types
        record_count = 0
        for rr_class in RR_CLASSES:
            count = session.exec(
                select(func.count(rr_class.id)).where(rr_class.placeholder == False)
            ).one()
            record_count += count
        
        # Get recent zones
        if user.is_admin:
            recent_zones = session.exec(
                select(Zone).order_by(Zone.updated_at.desc()).limit(5)
            ).all()
        else:
            recent_zones = session.exec(
                select(Zone).where(
                    (Zone.user_id == user.id) |
                    (Zone.group_id.in_([g.id for g in user.groups]))
                ).order_by(Zone.updated_at.desc()).limit(5)
            ).all()

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "user": user,
        "zone_count": zone_count,
        "record_count": record_count,
        "token_count": token_count,
        "server_count": server_count,
        "recent_zones": recent_zones
    })


@router.get("/zones", response_class=HTMLResponse)
async def list_zones(request: Request, user: User = Depends(get_current_user_web)):
    """List zones page"""
    with Session(engine) as session:
        if user.is_admin:
            zones = session.exec(select(Zone)).all()
        else:
            zones = session.exec(
                select(Zone).where(
                    (Zone.user_id == user.id) |
                    (Zone.group_id.in_([g.id for g in user.groups]))
                )
            ).all()
        
        # Get record counts for each zone
        zones_with_counts = []
        for zone in zones:
            record_count = 0
            for rr_class in RR_CLASSES:
                count = session.exec(
                    select(func.count(rr_class.id)).where(
                        rr_class.zone_id == zone.id,
                        rr_class.placeholder == False
                    )
                ).one()
                record_count += count
            
            zone_dict = zone.__dict__.copy()
            zone_dict['record_count'] = record_count
            zones_with_counts.append(zone_dict)
        
        servers = session.exec(select(Server)).all()

    return templates.TemplateResponse("zones.html", {
        "request": request,
        "user": user,
        "zones": zones_with_counts,
        "servers": servers
    })


@router.post("/zones")
async def create_zone_web(
    request: Request,
    origin: str = Form(...),
    server_id: int = Form(...),
    soa_MNAME: str = Form(...),
    soa_RNAME: str = Form(...),
    user: User = Depends(get_current_user_web)
):
    """Create zone from web form"""
    client_ip = request.client.host if request.client else "unknown"
    
    with Session(engine) as session:
        # Check if zone already exists
        origin_fqdn = origin.rstrip('.') + '.'
        existing = session.exec(
            select(Zone).where(Zone.origin == origin_fqdn)
        ).first()
        
        if existing:
            raise HTTPException(status_code=400, detail="Zone already exists")
        
        # Create zone
        zone = Zone(
            origin=origin_fqdn,
            soa_NAME=origin_fqdn,
            soa_CLASS=RRClass.IN,
            soa_TTL=86400,
            soa_MNAME=soa_MNAME,
            soa_RNAME=soa_RNAME,
            soa_SERIAL=int(datetime.utcnow().timestamp()),
            soa_REFRESH=3600,
            soa_RETRY=900,
            soa_EXPIRE=1209600,
            soa_MINIMUM=86400,
            server_id=server_id,
            user_id=user.id if not user.is_admin else None,
            needs_update=True
        )
        
        session.add(zone)
        session.commit()
        session.refresh(zone)
        
        # Create default NS record
        ns_record = NS(
            zone_id=zone.id,
            label="@",
            ttl=86400,
            rrclass=RRClass.IN,
            value=soa_MNAME
        )
        session.add(ns_record)
        session.commit()
        
        mark_zone_for_update(zone.id)
        audit_log_web(user, "CREATE", "zone", zone.id, 
                     {"origin": zone.origin}, client_ip)
        
        return RedirectResponse(url="/web/zones", status_code=303)


@router.get("/zones/new", response_class=HTMLResponse)
async def new_zone(request: Request, user: User = Depends(get_current_user_web)):
    """Display zone creation form"""
    with Session(engine) as session:
        servers = session.exec(select(Server)).all()
        
    return templates.TemplateResponse("zone_create.html", {
        "request": request,
        "user": user,
        "servers": servers
    })


@router.get("/zones/{zone_id}/edit", response_class=HTMLResponse)
async def edit_zone(request: Request, zone_id: int, user: User = Depends(get_current_user_web)):
    """Display zone edit form"""
    with Session(engine) as session:
        zone = session.get(Zone, zone_id)
        if not zone:
            raise HTTPException(status_code=404, detail="Zone not found")
        
        if not user.is_admin and not can_write_to_zone(session, user, zone, ""):
            raise HTTPException(status_code=403, detail="Access denied")
        
        servers = session.exec(select(Server)).all()
        
    return templates.TemplateResponse("zone_edit.html", {
        "request": request,
        "user": user,
        "zone": zone,
        "servers": servers
    })


@router.post("/zones/{zone_id}/edit")
async def update_zone(
    request: Request,
    zone_id: int,
    origin: str = Form(...),
    server_id: int = Form(...),
    soa_MNAME: str = Form(...),
    soa_RNAME: str = Form(...),
    user: User = Depends(get_current_user_web)
):
    """Update zone from web form"""
    client_ip = request.client.host if request.client else "unknown"
    
    with Session(engine) as session:
        zone = session.get(Zone, zone_id)
        if not zone:
            raise HTTPException(status_code=404, detail="Zone not found")
        
        if not user.is_admin and not can_write_to_zone(session, user, zone, ""):
            raise HTTPException(status_code=403, detail="Access denied")
        
        # Update zone fields
        origin_fqdn = origin.rstrip('.') + '.'
        zone.origin = origin_fqdn
        zone.soa_NAME = origin_fqdn
        zone.soa_MNAME = soa_MNAME
        zone.soa_RNAME = soa_RNAME
        zone.server_id = server_id
        zone.needs_update = True
        zone.soa_SERIAL += 1  # Increment serial for zone updates
        
        session.commit()
        session.refresh(zone)
        
        mark_zone_for_update(zone.id)
        audit_log_web(user, "UPDATE", "zone", zone.id, 
                     {"origin": zone.origin}, client_ip)
        
        return RedirectResponse(url=f"/web/zones/{zone.id}", status_code=303)


@router.get("/zones/{zone_id}", response_class=HTMLResponse)
async def view_zone(request: Request, zone_id: int, user: User = Depends(get_current_user_web)):
    """View zone details"""
    with Session(engine) as session:
        zone = session.get(Zone, zone_id)
        if not zone:
            raise HTTPException(status_code=404, detail="Zone not found")
        
        if not user.is_admin and not can_write_to_zone(session, user, zone, ""):
            raise HTTPException(status_code=403, detail="Access denied")
        
        # Get all records for this zone
        records = []
        for rr_class in RR_CLASSES:
            rrs = session.exec(
                select(rr_class).where(rr_class.zone_id == zone_id)
            ).all()
            
            for rr in rrs:
                records.append({
                    'id': rr.id,
                    'type': rr_class.__name__,
                    'label': rr.label,
                    'ttl': rr.ttl,
                    'value': rr.value,
                    'placeholder': rr.placeholder
                })
        
        # Sort records by label, then by type
        records.sort(key=lambda x: (x['label'], x['type']))

    return templates.TemplateResponse("zone_detail.html", {
        "request": request,
        "user": user,
        "zone": zone,
        "records": records
    })


# DNS Record Management Routes
@router.get("/zones/{zone_id}/records/new", response_class=HTMLResponse)
async def new_record(request: Request, zone_id: int, user: User = Depends(get_current_user_web)):
    """Display record creation form"""
    with Session(engine) as session:
        zone = session.get(Zone, zone_id)
        if not zone:
            raise HTTPException(status_code=404, detail="Zone not found")
        
        if not user.is_admin and not can_write_to_zone(session, user, zone, ""):
            raise HTTPException(status_code=403, detail="Access denied")
        
    return templates.TemplateResponse("record_create.html", {
        "request": request,
        "user": user,
        "zone": zone
    })

@router.post("/zones/{zone_id}/records")
async def create_record_web(
    request: Request,
    zone_id: int,
    record_type: str = Form(...),
    label: str = Form(""),
    ttl: int = Form(300),
    value: str = Form(...),
    user: User = Depends(get_current_user_web)
):
    """Create record from web form"""
    client_ip = request.client.host if request.client else "unknown"
    
    # Map record type to class
    type_map = {
        "A": A, "AAAA": AAAA, "NS": NS, "PTR": PTR,
        "CNAME": CNAME, "TXT": TXT, "CAA": CAA, "MX": MX, "SRV": SRV
    }
    
    if record_type.upper() not in type_map:
        raise HTTPException(status_code=400, detail="Invalid record type")
    
    record_class = type_map[record_type.upper()]
    
    with Session(engine) as session:
        zone = session.get(Zone, zone_id)
        if not zone:
            raise HTTPException(status_code=404, detail="Zone not found")
        
        if not user.is_admin and not can_write_to_zone(session, user, zone, ""):
            raise HTTPException(status_code=403, detail="Access denied")
        
        try:
            # Validate record data based on type
            cleaned_label = label.strip() if label.strip() else ""
            cleaned_value = value.strip()
            
            # Validate TTL
            if ttl < 1 or ttl > 86400:
                return RedirectResponse(url=f"/web/zones/{zone_id}/records/new?error={quote('TTL must be between 1 and 86400 seconds')}", status_code=303)
            
            # Type-specific validation
            validation_error = _validate_record_value(record_type.upper(), cleaned_value)
            if validation_error:
                return RedirectResponse(url=f"/web/zones/{zone_id}/records/new?error={quote(validation_error)}", status_code=303)
            
            # Check for duplicate records (same label, type, value)
            existing = session.exec(
                select(record_class).where(
                    record_class.zone_id == zone_id,
                    record_class.label == cleaned_label,
                    record_class.value == cleaned_value
                )
            ).first()
            
            if existing:
                return RedirectResponse(url=f"/web/zones/{zone_id}/records/new?error={quote('A record with this name and value already exists')}", status_code=303)
            
            # Create record
            record = record_class(
                zone_id=zone_id,
                label=cleaned_label,
                rrclass=RRClass.IN,
                ttl=ttl,
                value=cleaned_value
            )
            
            session.add(record)
            session.commit()
            session.refresh(record)
            
            # Mark zone for update
            mark_zone_for_update(zone_id)
            audit_log_web(user, "CREATE", record_type.lower(), record.id, 
                         {"label": record.label, "value": record.value}, client_ip)
            
            record_name = record.label or "@"
            return RedirectResponse(url=f"/web/zones/{zone_id}?success={record_type} record '{record_name}' created successfully", status_code=303)
            
        except Exception as e:
            session.rollback()
            logging.error(f"Error creating record: {e}")
            error_msg = str(e) if "duplicate" in str(e).lower() else "Failed to create record"
            return RedirectResponse(url=f"/web/zones/{zone_id}/records/new?error={quote(error_msg)}", status_code=303)

@router.get("/zones/{zone_id}/records/{record_id}/edit", response_class=HTMLResponse)
async def edit_record(request: Request, zone_id: int, record_id: int, user: User = Depends(get_current_user_web)):
    """Display record edit form"""
    with Session(engine) as session:
        zone = session.get(Zone, zone_id)
        if not zone:
            raise HTTPException(status_code=404, detail="Zone not found")
        
        if not user.is_admin and not can_write_to_zone(session, user, zone, ""):
            raise HTTPException(status_code=403, detail="Access denied")
        
        # Find the record in all RR classes
        record = None
        record_type = None
        for rr_class in RR_CLASSES:
            potential_record = session.get(rr_class, record_id)
            if potential_record and potential_record.zone_id == zone_id:
                record = potential_record
                record_type = rr_class.__name__
                break
        
        if not record:
            raise HTTPException(status_code=404, detail="Record not found")
        
    return templates.TemplateResponse("record_edit.html", {
        "request": request,
        "user": user,
        "zone": zone,
        "record": record,
        "record_type": record_type
    })

@router.post("/zones/{zone_id}/records/{record_id}/edit")
async def update_record_web(
    request: Request,
    zone_id: int,
    record_id: int,
    record_type: str = Form(...),
    label: str = Form(""),
    ttl: int = Form(300),
    value: str = Form(...),
    user: User = Depends(get_current_user_web)
):
    """Update record from web form"""
    client_ip = request.client.host if request.client else "unknown"
    
    # Map record type to class
    type_map = {
        "A": A, "AAAA": AAAA, "NS": NS, "PTR": PTR,
        "CNAME": CNAME, "TXT": TXT, "CAA": CAA, "MX": MX, "SRV": SRV
    }
    
    if record_type.upper() not in type_map:
        raise HTTPException(status_code=400, detail="Invalid record type")
    
    record_class = type_map[record_type.upper()]
    
    with Session(engine) as session:
        zone = session.get(Zone, zone_id)
        if not zone:
            raise HTTPException(status_code=404, detail="Zone not found")
        
        if not user.is_admin and not can_write_to_zone(session, user, zone, ""):
            raise HTTPException(status_code=403, detail="Access denied")
        
        record = session.get(record_class, record_id)
        if not record or record.zone_id != zone_id:
            raise HTTPException(status_code=404, detail="Record not found")
        
        try:
            # Validate record data based on type
            cleaned_label = label.strip() if label.strip() else ""
            cleaned_value = value.strip()
            
            # Validate TTL
            if ttl < 1 or ttl > 86400:
                return RedirectResponse(url=f"/web/zones/{zone_id}/records/{record_id}/edit?error={quote('TTL must be between 1 and 86400 seconds')}", status_code=303)
            
            # Type-specific validation
            validation_error = _validate_record_value(record_type.upper(), cleaned_value)
            if validation_error:
                return RedirectResponse(url=f"/web/zones/{zone_id}/records/{record_id}/edit?error={quote(validation_error)}", status_code=303)
            
            # Check for duplicate records (same label, type, value) excluding current record
            existing = session.exec(
                select(record_class).where(
                    record_class.zone_id == zone_id,
                    record_class.label == cleaned_label,
                    record_class.value == cleaned_value,
                    record_class.id != record_id
                )
            ).first()
            
            if existing:
                return RedirectResponse(url=f"/web/zones/{zone_id}/records/{record_id}/edit?error={quote('A record with this name and value already exists')}", status_code=303)
            
            # Update record
            record.label = cleaned_label
            record.ttl = ttl
            record.value = cleaned_value
            
            session.commit()
            
            # Mark zone for update
            mark_zone_for_update(zone_id)
            audit_log_web(user, "UPDATE", record_type.lower(), record.id, 
                         {"label": record.label, "value": record.value}, client_ip)
            
            record_name = record.label or "@"
            return RedirectResponse(url=f"/web/zones/{zone_id}?success={record_type} record '{record_name}' updated successfully", status_code=303)
            
        except Exception as e:
            session.rollback()
            logging.error(f"Error updating record: {e}")
            error_msg = str(e) if "duplicate" in str(e).lower() else "Failed to update record"
            return RedirectResponse(url=f"/web/zones/{zone_id}/records/{record_id}/edit?error={quote(error_msg)}", status_code=303)

@router.post("/zones/{zone_id}/records/{record_id}/delete")
async def delete_record_web(
    request: Request,
    zone_id: int,
    record_id: int,
    user: User = Depends(get_current_user_web)
):
    """Delete record"""
    client_ip = request.client.host if request.client else "unknown"
    
    with Session(engine) as session:
        zone = session.get(Zone, zone_id)
        if not zone:
            raise HTTPException(status_code=404, detail="Zone not found")
        
        if not user.is_admin and not can_write_to_zone(session, user, zone, ""):
            raise HTTPException(status_code=403, detail="Access denied")
        
        # Find the record in all RR classes
        record = None
        record_type = None
        for rr_class in RR_CLASSES:
            potential_record = session.get(rr_class, record_id)
            if potential_record and potential_record.zone_id == zone_id:
                record = potential_record
                record_type = rr_class.__name__
                break
        
        if not record:
            raise HTTPException(status_code=404, detail="Record not found")
        
        try:
            # Store record info for audit log
            record_label = record.label
            record_value = record.value
            
            session.delete(record)
            session.commit()
            
            # Mark zone for update
            mark_zone_for_update(zone_id)
            audit_log_web(user, "DELETE", record_type.lower(), record_id, 
                         {"label": record_label, "value": record_value}, client_ip)
            
            return RedirectResponse(url=f"/web/zones/{zone_id}?success=Record deleted successfully", status_code=303)
            
        except Exception as e:
            session.rollback()
            logging.error(f"Error deleting record: {e}")
            return RedirectResponse(url=f"/web/zones/{zone_id}?error=Failed to delete record", status_code=303)


@router.get("/tokens", response_class=HTMLResponse)
async def list_tokens(request: Request, user: User = Depends(get_current_user_web)):
    """List API tokens"""
    with Session(engine) as session:
        tokens = session.exec(
            select(APIToken).where(APIToken.user_id == user.id)
        ).all()

    return templates.TemplateResponse("tokens.html", {
        "request": request,
        "user": user,
        "tokens": tokens
    })


@router.post("/tokens")
async def create_token_web(
    request: Request,
    description: Optional[str] = Form(None),
    user: User = Depends(get_current_user_web)
):
    """Create API token from web form"""
    client_ip = request.client.host if request.client else "unknown"
    
    with Session(engine) as session:
        token = APIToken(
            token=secrets.token_urlsafe(32),
            description=description,
            user_id=user.id
        )
        session.add(token)
        session.commit()
        session.refresh(token)
        
        audit_log_web(user, "CREATE", "api_token", token.id,
                     {"description": description}, client_ip)
        
        return RedirectResponse(url="/web/tokens", status_code=303)


@router.delete("/tokens/{token_id}")
async def delete_token_web(
    request: Request,
    token_id: int,
    user: User = Depends(get_current_user_web)
):
    """Delete API token via HTMX"""
    client_ip = request.client.host if request.client else "unknown"
    
    with Session(engine) as session:
        token = session.get(APIToken, token_id)
        if not token:
            raise HTTPException(status_code=404, detail="Token not found")
        
        if token.user_id != user.id:
            raise HTTPException(status_code=403, detail="Access denied")
        
        audit_log_web(user, "DELETE", "api_token", token.id,
                     {"description": token.description}, client_ip)
        
        session.delete(token)
        session.commit()
        
        return HTMLResponse("")  # Empty response for HTMX swap


@router.get("/security", response_class=HTMLResponse)
async def security_settings(request: Request, user: User = Depends(get_current_user_web)):
    """Security settings page - 2FA and PassKey setup"""
    return templates.TemplateResponse("security.html", {
        "request": request,
        "user": user
    })


@router.post("/security/2fa/enable")
async def enable_2fa(request: Request, user: User = Depends(get_current_user_web)):
    """Enable 2FA for user"""
    client_ip = request.client.host if request.client else "unknown"
    
    if user.has_2fa:
        raise HTTPException(status_code=400, detail="2FA already enabled")
    
    # Generate secret and QR code
    secret = generate_totp_secret()
    qr_code = generate_totp_qr_code(user, secret)
    
    # Store secret temporarily in session (in production, use secure storage)
    # For now, we'll update the user directly
    with Session(engine) as session:
        db_user = session.get(User, user.id)
        db_user.totp_secret = secret
        db_user.has_2fa = True
        session.commit()
        
        audit_log_web(user, "ENABLE", "2fa", user.id, {}, client_ip)
    
    return templates.TemplateResponse("2fa_setup.html", {
        "request": request,
        "user": user,
        "secret": secret,
        "qr_code": qr_code
    })


# Authentication routes (separate router for auth)
auth_router = APIRouter(prefix="/auth", tags=["Authentication"])

@auth_router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, next: Optional[str] = None, error: Optional[str] = None):
    """Display login form"""
    return templates.TemplateResponse("login.html", {
        "request": request,
        "next": next,
        "error": error
    })

@auth_router.post("/login")
async def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    next: Optional[str] = Form(None)
):
    """Handle login form submission"""
    client_ip = request.client.host if request.client else "unknown"
    
    # First verify username and password
    with Session(engine) as session:
        statement = select(User).where(User.username == username)
        user = session.exec(statement).one_or_none()
        
        if not user or not user.verify_password(password):
            logging.warning(f"Failed login attempt for user '{username}' from {client_ip}")
            return templates.TemplateResponse("login.html", {
                "request": request,
                "error": "Invalid username or password",
                "next": next
            })
        
        if not user.is_active:
            logging.warning(f"Login attempt for inactive user '{username}' from {client_ip}")
            return templates.TemplateResponse("login.html", {
                "request": request,
                "error": "Account is disabled",
                "next": next
            })
        
        # Handle 2FA verification if enabled
        if user.has_2fa and user.totp_secret:
            # Store pending 2FA state in session
            request.session["pending_2fa_user_id"] = user.id
            request.session["pending_2fa_timestamp"] = datetime.now().timestamp()
            request.session["pending_2fa_next"] = next
            
            # Redirect to dedicated 2FA verification page
            return RedirectResponse(url="/auth/2fa-verify", status_code=303)
                
        # If passkey is enabled, we should handle that too, but for now just log warning
        if user.has_passkey:
            logging.warning(f"User '{username}' has passkey enabled but using password login")
    
    # Set user session
    request.session["user_id"] = user.id
    
    # Log successful login
    logging.info(f"Successful login for user '{username}' from {client_ip}")
    audit_log_web(user, "LOGIN", "session", user.id, {"client_ip": client_ip}, client_ip)
    
    # Redirect to next page or dashboard
    redirect_url = next or "/web/"
    return RedirectResponse(url=redirect_url, status_code=303)

@auth_router.get("/2fa-verify", response_class=HTMLResponse)
async def verify_2fa_page(request: Request):
    """Display 2FA verification form"""
    # Check if user has pending 2FA session
    user_id = request.session.get("pending_2fa_user_id")
    timestamp = request.session.get("pending_2fa_timestamp")
    
    if not user_id or not timestamp:
        return RedirectResponse(url="/auth/login?error=Please log in first", status_code=303)
    
    # Check if session has expired (5 minutes)
    current_time = datetime.now().timestamp()
    if current_time - timestamp > 300:  # 5 minutes
        # Clear expired session
        request.session.pop("pending_2fa_user_id", None)
        request.session.pop("pending_2fa_timestamp", None) 
        request.session.pop("pending_2fa_next", None)
        return RedirectResponse(url="/auth/login?error=Session expired", status_code=303)
    
    # Get user info for display
    with Session(engine) as session:
        user = session.get(User, user_id)
        if not user:
            # Clear invalid session
            request.session.pop("pending_2fa_user_id", None)
            request.session.pop("pending_2fa_timestamp", None)
            request.session.pop("pending_2fa_next", None)
            return RedirectResponse(url="/auth/login?error=Invalid session", status_code=303)
    
    time_left = int(300 - (current_time - timestamp))  # Remaining seconds
    
    return templates.TemplateResponse("2fa_verify.html", {
        "request": request,
        "username": user.username,
        "time_left": time_left
    })

@auth_router.post("/2fa-verify")
async def verify_2fa_submit(
    request: Request,
    totp_code: str = Form(...)
):
    """Handle 2FA verification form submission"""
    client_ip = request.client.host if request.client else "unknown"
    
    # Check if user has pending 2FA session
    user_id = request.session.get("pending_2fa_user_id")
    timestamp = request.session.get("pending_2fa_timestamp")
    next_url = request.session.get("pending_2fa_next")
    
    if not user_id or not timestamp:
        return RedirectResponse(url="/auth/login?error=Please log in first", status_code=303)
    
    # Check if session has expired (5 minutes)
    current_time = datetime.now().timestamp()
    if current_time - timestamp > 300:  # 5 minutes
        # Clear expired session
        request.session.pop("pending_2fa_user_id", None)
        request.session.pop("pending_2fa_timestamp", None)
        request.session.pop("pending_2fa_next", None)
        return RedirectResponse(url="/auth/login?error=Session expired", status_code=303)
    
    # Get user and verify TOTP
    with Session(engine) as session:
        user = session.get(User, user_id)
        if not user or not user.totp_secret:
            # Clear invalid session
            request.session.pop("pending_2fa_user_id", None)
            request.session.pop("pending_2fa_timestamp", None)
            request.session.pop("pending_2fa_next", None)
            return RedirectResponse(url="/auth/login?error=Invalid session", status_code=303)
        
        # Verify TOTP code
        from .fastapi_users_auth import verify_totp_code
        if not verify_totp_code(user.totp_secret, totp_code):
            logging.warning(f"Invalid 2FA code for user '{user.username}' from {client_ip}")
            time_left = int(300 - (current_time - timestamp))
            return templates.TemplateResponse("2fa_verify.html", {
                "request": request,
                "username": user.username,
                "error": "Invalid authentication code. Please try again.",
                "time_left": time_left
            })
    
    # Clear pending 2FA session
    request.session.pop("pending_2fa_user_id", None)
    request.session.pop("pending_2fa_timestamp", None)
    request.session.pop("pending_2fa_next", None)
    
    # Set user session - successful login
    request.session["user_id"] = user.id
    
    # Log successful login
    logging.info(f"Successful 2FA login for user '{user.username}' from {client_ip}")
    audit_log_web(user, "LOGIN", "session", user.id, {"client_ip": client_ip, "2fa": True}, client_ip)
    
    # Redirect to next page or dashboard
    redirect_url = next_url or "/web/"
    return RedirectResponse(url=redirect_url, status_code=303)

@auth_router.get("/2fa-cancel")
async def cancel_2fa(request: Request):
    """Cancel 2FA verification and return to login"""
    # Clear pending 2FA session
    request.session.pop("pending_2fa_user_id", None)
    request.session.pop("pending_2fa_timestamp", None)
    request.session.pop("pending_2fa_next", None)
    
    return RedirectResponse(url="/auth/login", status_code=303)

@auth_router.get("/logout")
async def logout(request: Request):
    """Handle logout"""
    user_id = request.session.get("user_id")
    client_ip = request.client.host if request.client else "unknown"
    
    if user_id:
        with Session(engine) as session:
            user = session.get(User, user_id)
            if user:
                logging.info(f"User '{user.username}' logged out from {client_ip}")
                audit_log_web(user, "LOGOUT", "session", user.id, {"client_ip": client_ip}, client_ip)
    
    # Clear all session data (including any pending 2FA sessions)
    request.session.clear()
    
    # Redirect to login page
    return RedirectResponse(url="/auth/login", status_code=303)