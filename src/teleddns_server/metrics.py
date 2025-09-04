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

from typing import Dict
from prometheus_client import Counter, Gauge, Histogram, generate_latest, CONTENT_TYPE_LATEST
from fastapi import Response
from sqlmodel import Session, select, func
from datetime import datetime, timedelta

from .model import engine, Zone, RR_CLASSES
from .sync import startup_time, last_update_time, last_push_time

# Prometheus metrics
ddns_updates_total = Counter(
    'teleddns_ddns_updates_total',
    'Total number of DDNS updates',
    ['status', 'record_type']
)

api_requests_total = Counter(
    'teleddns_api_requests_total', 
    'Total number of API requests',
    ['method', 'endpoint', 'status_code']
)

zones_total = Gauge(
    'teleddns_zones_total',
    'Total number of zones'
)

records_total = Gauge(
    'teleddns_records_total',
    'Total number of DNS records',
    ['record_type', 'zone']
)

backend_sync_duration = Histogram(
    'teleddns_backend_sync_duration_seconds',
    'Time spent syncing to backend servers'
)

uptime_seconds = Gauge(
    'teleddns_uptime_seconds',
    'Uptime in seconds'
)

last_update_timestamp = Gauge(
    'teleddns_last_update_timestamp',
    'Timestamp of last update'
)

last_push_timestamp = Gauge(
    'teleddns_last_push_timestamp', 
    'Timestamp of last backend push'
)


def update_zone_metrics():
    """Update zone and record count metrics"""
    with Session(engine) as session:
        # Count total zones
        total_zones = session.exec(select(func.count(Zone.id))).one()
        zones_total.set(total_zones)
        
        # Count records per type and zone
        for rr_class in RR_CLASSES:
            # Total records of this type
            total_count = session.exec(
                select(func.count(rr_class.id)).where(rr_class.placeholder == False)
            ).one()
            
            record_type = rr_class.__name__
            records_total.labels(record_type=record_type, zone='_total').set(total_count)
            
            # Records per zone
            zone_counts = session.exec(
                select(Zone.origin, func.count(rr_class.id))
                .join(rr_class, Zone.id == rr_class.zone_id)
                .where(rr_class.placeholder == False)
                .group_by(Zone.origin)
            ).all()
            
            for zone_origin, count in zone_counts:
                records_total.labels(
                    record_type=record_type, 
                    zone=zone_origin.rstrip('.')
                ).set(count)


def update_uptime_metrics():
    """Update uptime and timestamp metrics"""
    now = datetime.utcnow()
    uptime = (now - startup_time).total_seconds()
    
    uptime_seconds.set(uptime)
    last_update_timestamp.set(last_update_time.timestamp())
    last_push_timestamp.set(last_push_time.timestamp())


async def metrics_endpoint():
    """Prometheus metrics endpoint"""
    # Update metrics before serving
    update_zone_metrics()
    update_uptime_metrics()
    
    # Generate and return metrics
    metrics_data = generate_latest()
    return Response(content=metrics_data, media_type=CONTENT_TYPE_LATEST)