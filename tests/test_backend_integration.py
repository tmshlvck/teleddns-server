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

import pytest
import asyncio
import tempfile
import os
import threading
import time
from datetime import datetime, timezone
from sqlmodel import Session, SQLModel, create_engine
from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse
import uvicorn
import requests

# Import our modules
import sys
import os

# Disable CLI parsing for tests
os.environ['DISABLE_CLI_PARSING'] = '1'

# Add the src directory to Python path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from teleddns_server.model import (
    User, Group, MasterZone, Server, A, AAAA, RRClass, engine as default_engine
)
from teleddns_server.backend import background_sync_loop


class MockBackendServer:
    """Mock backend server that logs all requests and responds with 200 OK"""

    def __init__(self, host="127.0.0.1", port=8086):
        self.host = host
        self.port = port
        self.app = FastAPI()
        self.requests_log = []
        self.server = None
        self.thread = None
        self.setup_routes()

    def setup_routes(self):
        """Set up mock backend API routes"""

        @self.app.get("/configwrite")
        async def config_write():
            self.log_request("GET", "/configwrite", None, {})
            return PlainTextResponse("Config write OK", status_code=200)

        @self.app.post("/configwrite")
        async def config_write_post(request: Request):
            body = await request.body()
            headers = dict(request.headers)
            self.log_request("POST", "/configwrite", body.decode(), headers)
            return PlainTextResponse("Config write OK", status_code=200)

        @self.app.get("/configreload")
        async def config_reload():
            self.log_request("GET", "/configreload", None, {})
            return PlainTextResponse("Config reload OK", status_code=200)

        @self.app.get("/zonewrite")
        async def zone_write():
            self.log_request("GET", "/zonewrite", None, {})
            return PlainTextResponse("Zone write OK", status_code=200)

        @self.app.post("/zonewrite")
        async def zone_write_post(request: Request):
            body = await request.body()
            headers = dict(request.headers)
            query_params = dict(request.query_params)
            self.log_request("POST", "/zonewrite", body.decode(), headers, query_params)
            return PlainTextResponse("Zone write OK", status_code=200)

        @self.app.get("/zonereload")
        async def zone_reload(request: Request):
            query_params = dict(request.query_params)
            self.log_request("GET", "/zonereload", None, {}, query_params)
            return PlainTextResponse("Zone reload OK", status_code=200)

        @self.app.get("/zonecheck")
        async def zone_check(request: Request):
            query_params = dict(request.query_params)
            self.log_request("GET", "/zonecheck", None, {}, query_params)
            return {"status": "ok", "errors": []}

    def log_request(self, method, path, body, headers, query_params=None):
        """Log the request details"""
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "method": method,
            "path": path,
            "body": body,
            "headers": headers,
            "query_params": query_params or {}
        }
        self.requests_log.append(log_entry)

    def start(self):
        """Start the mock backend server in a separate thread"""
        def run_server():
            config = uvicorn.Config(self.app, host=self.host, port=self.port, log_level="error")
            self.server = uvicorn.Server(config)
            asyncio.run(self.server.serve())

        self.thread = threading.Thread(target=run_server, daemon=True)
        self.thread.start()

        # Wait for server to start
        max_attempts = 50
        for i in range(max_attempts):
            try:
                response = requests.get(f"http://{self.host}:{self.port}/configreload", timeout=1)
                if response.status_code == 200:
                    return
            except:
                pass
            time.sleep(0.1)

        raise RuntimeError(f"Mock backend server failed to start after {max_attempts/10} seconds")

    def stop(self):
        """Stop the mock backend server"""
        if self.server:
            self.server.should_exit = True
        if self.thread:
            self.thread.join(timeout=1)

    def get_requests_log(self):
        """Get all logged requests"""
        return self.requests_log.copy()

    def clear_log(self):
        """Clear the requests log"""
        self.requests_log.clear()

    def wait_for_requests(self, min_count=1, timeout=10):
        """Wait for at least min_count requests to be received"""
        start_time = time.time()
        while len(self.requests_log) < min_count and (time.time() - start_time) < timeout:
            time.sleep(0.1)
        return len(self.requests_log) >= min_count


@pytest.fixture(scope="module")
def mock_backend():
    """Create and start mock backend server"""
    backend = MockBackendServer()
    backend.start()
    yield backend
    backend.stop()


@pytest.fixture
def test_db():
    """Create a temporary in-memory database for testing"""
    # Create temporary SQLite file
    temp_db = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
    temp_db.close()

    test_engine = create_engine(f"sqlite:///{temp_db.name}", connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(test_engine)

    yield test_engine

    # Cleanup
    os.unlink(temp_db.name)


@pytest.fixture
def setup_backend_test_data(test_db, mock_backend):
    """Set up test data: server, zones, and users"""
    # Patch the global engine for this test
    import teleddns_server.model
    import teleddns_server.backend
    original_engine = teleddns_server.model.engine
    teleddns_server.model.engine = test_db
    teleddns_server.backend.engine = test_db

    # Clear mock backend log
    mock_backend.clear_log()

    with Session(test_db) as session:
        # Create server pointing to mock backend
        server = Server(
            name="mock-backend-server",
            api_url=f"http://127.0.0.1:{mock_backend.port}",
            api_key="test-api-key-12345",
            master_template="t_master",
            slave_template="t_slave",
            config_dirty=True  # Mark as needing config sync
        )
        session.add(server)
        session.commit()
        session.refresh(server)

        # Create admin user
        admin_user = User(
            username="admin",
            email="admin@test.com",
            password=User.gen_hash("admin_pass"),
            is_admin=True
        )
        session.add(admin_user)
        session.commit()
        session.refresh(admin_user)

        # Create test zones
        zone1 = MasterZone(
            origin="test1.example.com.",
            soa_NAME="@",
            soa_CLASS=RRClass.IN,
            soa_TTL=3600,
            soa_MNAME="ns1.test1.example.com.",
            soa_RNAME="admin.test1.example.com.",
            soa_SERIAL=1001,
            soa_REFRESH=7200,
            soa_RETRY=3600,
            soa_EXPIRE=1209600,
            soa_MINIMUM=86400,
            owner_id=admin_user.id,
            master_server_id=server.id,
            content_dirty=True  # Mark as needing content sync
        )
        session.add(zone1)

        zone2 = MasterZone(
            origin="test2.example.com.",
            soa_NAME="@",
            soa_CLASS=RRClass.IN,
            soa_TTL=3600,
            soa_MNAME="ns1.test2.example.com.",
            soa_RNAME="admin.test2.example.com.",
            soa_SERIAL=2001,
            soa_REFRESH=7200,
            soa_RETRY=3600,
            soa_EXPIRE=1209600,
            soa_MINIMUM=86400,
            owner_id=admin_user.id,
            master_server_id=server.id,
            content_dirty=True  # Mark as needing content sync
        )
        session.add(zone2)

        session.commit()
        session.refresh(zone1)
        session.refresh(zone2)

        # Add some DNS records to the zones
        a_record1 = A(
            label="www",
            rrclass=RRClass.IN,
            ttl=300,
            zone_id=zone1.id,
            value="192.0.2.100"
        )
        session.add(a_record1)

        aaaa_record1 = AAAA(
            label="www",
            rrclass=RRClass.IN,
            ttl=300,
            zone_id=zone1.id,
            value="2001:db8::100"
        )
        session.add(aaaa_record1)

        a_record2 = A(
            label="mail",
            rrclass=RRClass.IN,
            ttl=600,
            zone_id=zone2.id,
            value="192.0.2.200"
        )
        session.add(a_record2)

        session.commit()

        yield {
            'engine': test_db,
            'server': server,
            'admin_user': admin_user,
            'zone1': zone1,
            'zone2': zone2,
            'backend': mock_backend
        }

    # Restore original engine
    teleddns_server.model.engine = original_engine
    teleddns_server.backend.engine = original_engine


class TestBackendIntegration:

    def test_backend_config_sync(self, setup_backend_test_data):
        """Test that backend sync sends config to mock backend"""
        data = setup_backend_test_data
        backend = data['backend']

        # Clear any existing logs
        backend.clear_log()

        # Test config sync using the actual update_config function
        async def test_sync():
            from teleddns_server.backend import update_config

            # Create test config content
            config_content = """zone:
- domain: test1.example.com.
  template: t_master
  file: test1.example.com.zone
zone:
- domain: test2.example.com.
  template: t_master
  file: test2.example.com.zone
"""

            # Send config to backend using the real function
            await update_config(config_content, f"http://127.0.0.1:{backend.port}", "test-api-key-12345")

        # Run the test
        asyncio.run(test_sync())

        # Check what requests were received
        requests_log = backend.get_requests_log()

        # Wait for backend to receive requests
        assert backend.wait_for_requests(min_count=1, timeout=5), "Expected at least 1 request"

        # Should have received config write and reload requests
        config_write_requests = [r for r in requests_log if r['path'] == '/configwrite' and r['method'] == 'POST']
        config_reload_requests = [r for r in requests_log if r['path'] == '/configreload' and r['method'] == 'GET']

        assert len(config_write_requests) >= 1, f"Should have received config write request, got {len(config_write_requests)}"
        assert len(config_reload_requests) >= 1, f"Should have received config reload request, got {len(config_reload_requests)}"

        # Check config write request content
        config_req = config_write_requests[0]
        assert 'authorization' in [k.lower() for k in config_req['headers'].keys()]

        # Find the authorization header (case-insensitive)
        auth_header = None
        for k, v in config_req['headers'].items():
            if k.lower() == 'authorization':
                auth_header = v
                break

        assert auth_header == 'Bearer test-api-key-12345', f"Expected 'Bearer test-api-key-12345', got '{auth_header}'"

        # Config should contain zone definitions
        config_body = config_req['body']
        assert 'test1.example.com.' in config_body
        assert 'test2.example.com.' in config_body
        assert 't_master' in config_body

    def test_backend_zone_sync(self, setup_backend_test_data):
        """Test that zone sync sends zone content to mock backend"""
        data = setup_backend_test_data
        backend = data['backend']

        # Clear any existing logs
        backend.clear_log()

        # Test zone sync using the actual update_zone function
        async def test_sync():
            from teleddns_server.backend import update_zone

            # Create test zone content (BIND format)
            zone_content = """$ORIGIN test1.example.com.
$TTL 3600
@    IN  SOA  ns1.test1.example.com. admin.test1.example.com. (
         1001        ; serial number
         7200        ; refresh period
         3600        ; retry period
         1209600     ; expire time
         86400 )     ; minimum TTL

@    IN  NS   ns1.test1.example.com.
@    IN  NS   ns2.test1.example.com.
www  IN  A    192.0.2.100
www  IN  AAAA 2001:db8::100
"""

            # Send zone to backend using the real function
            await update_zone("test1.example.com", zone_content, f"http://127.0.0.1:{backend.port}", "test-api-key-12345")

        # Run the test
        asyncio.run(test_sync())

        # Check what requests were received
        requests_log = backend.get_requests_log()

        # Should have received zone write and reload requests
        zone_write_requests = [r for r in requests_log if r['path'] == '/zonewrite' and r['method'] == 'POST']
        zone_reload_requests = [r for r in requests_log if r['path'] == '/zonereload' and r['method'] == 'GET']

        assert len(zone_write_requests) >= 1, f"Should have received zone write request, got {len(zone_write_requests)}"
        assert len(zone_reload_requests) >= 1, f"Should have received zone reload request, got {len(zone_reload_requests)}"

        # Check zone write request
        zone_req = zone_write_requests[0]
        assert 'authorization' in [k.lower() for k in zone_req['headers'].keys()]

        # Find the authorization header (case-insensitive)
        auth_header = None
        for k, v in zone_req['headers'].items():
            if k.lower() == 'authorization':
                auth_header = v
                break

        assert auth_header == 'Bearer test-api-key-12345', f"Expected 'Bearer test-api-key-12345', got '{auth_header}'"

        # Check query params for zone name
        assert 'zonename' in zone_req['query_params']
        assert zone_req['query_params']['zonename'] == 'test1.example.com'

        # Zone content should contain DNS records
        zone_body = zone_req['body']
        assert 'test1.example.com.' in zone_body
        assert 'SOA' in zone_body
        assert 'www' in zone_body
        assert '192.0.2.100' in zone_body
        assert '2001:db8::100' in zone_body

    def test_background_sync_zone_dirty(self, setup_backend_test_data):
        """Test that background sync sends zone content to backend when content_dirty=True"""
        data = setup_backend_test_data
        backend = data['backend']

        # Clear any existing logs
        backend.clear_log()

        # Run one iteration of the background sync
        async def run_sync():
            # Import the sync functions directly and run them once
            from teleddns_server.backend import update_config, update_zone
            from datetime import datetime, timezone
            from sqlmodel import Session, select
            from teleddns_server.model import Server, MasterZone, RR_CLASSES

            with Session(data['engine']) as session:
                # Sync servers with dirty configs
                dirty_servers = session.exec(
                    select(Server).where(Server.config_dirty == True)
                ).all()

                for server in dirty_servers:
                    # Generate config data
                    config_data = []

                    # Add master zones
                    master_zones = session.exec(
                        select(MasterZone).where(MasterZone.master_server_id == server.id)
                    ).all()

                    for zone in master_zones:
                        config_data.append(f"zone:\n- domain: {zone.origin}\n  template: {server.master_template}\n  file: {zone.origin.rstrip('.').strip()}.zone")

                    config_content = '\n'.join(config_data) + '\n' if config_data else '\n'

                    # Send config to backend
                    await update_config(config_content, server.api_url, server.api_key)

                    # Clear dirty flag and update timestamp
                    server.config_dirty = False
                    server.last_config_sync = datetime.now(timezone.utc)
                    session.add(server)
                    session.commit()

                # Sync zones with dirty content
                dirty_zones = session.exec(
                    select(MasterZone).where(MasterZone.content_dirty == True)
                ).all()

                for zone in dirty_zones:
                    # Generate zone data
                    zone_data = [zone.format_bind_zone()]

                    # Add all RR records for this zone
                    for rrclass in RR_CLASSES:
                        rr_records = session.exec(
                            select(rrclass).where(rrclass.zone_id == zone.id)
                        ).all()
                        for rr in rr_records:
                            zone_data.append(rr.format_bind_zone())

                    zone_content = '\n'.join(zone_data) + '\n'

                    # Send zone to backend
                    await update_zone(
                        zone.origin.rstrip('.').strip(),
                        zone_content,
                        zone.master_server.api_url,
                        zone.master_server.api_key
                    )

                    # Clear dirty flag and update timestamp
                    zone.content_dirty = False
                    zone.last_content_sync = datetime.now(timezone.utc)
                    session.add(zone)
                    session.commit()

        # Run the sync
        asyncio.run(run_sync())

        # Wait for backend to receive requests
        assert backend.wait_for_requests(min_count=4, timeout=5), "Expected at least 4 requests (config + 2 zones)"

        # Check the logged requests
        requests_log = backend.get_requests_log()

        # Should have received zone write and reload requests for each zone
        zone_write_requests = [r for r in requests_log if r['path'] == '/zonewrite' and r['method'] == 'POST']
        zone_reload_requests = [r for r in requests_log if r['path'] == '/zonereload' and r['method'] == 'GET']

        assert len(zone_write_requests) >= 2, f"Should have received 2 zone write requests, got {len(zone_write_requests)}"
        assert len(zone_reload_requests) >= 2, f"Should have received 2 zone reload requests, got {len(zone_reload_requests)}"

        # Check zone write requests
        zone1_req = None
        zone2_req = None

        for req in zone_write_requests:
            if 'zonename=test1.example.com' in str(req['query_params']):
                zone1_req = req
            elif 'zonename=test2.example.com' in str(req['query_params']):
                zone2_req = req

        assert zone1_req is not None, "Should have received zone write request for test1.example.com"
        assert zone2_req is not None, "Should have received zone write request for test2.example.com"

        # Check zone1 content
        zone1_body = zone1_req['body']
        assert 'test1.example.com.' in zone1_body
        assert 'ns1.test1.example.com.' in zone1_body
        assert 'admin.test1.example.com.' in zone1_body
        assert 'www' in zone1_body
        assert '192.0.2.100' in zone1_body
        assert '2001:db8::100' in zone1_body

        # Check zone2 content
        zone2_body = zone2_req['body']
        assert 'test2.example.com.' in zone2_body
        assert 'ns1.test2.example.com.' in zone2_body
        assert 'mail' in zone2_body
        assert '192.0.2.200' in zone2_body

        # Verify content_dirty flags were cleared in database
        with Session(data['engine']) as session:
            zone1 = session.get(MasterZone, data['zone1'].id)
            zone2 = session.get(MasterZone, data['zone2'].id)

            assert zone1.content_dirty is False, "zone1 content_dirty flag should be cleared"
            assert zone1.last_content_sync is not None, "zone1 last_content_sync should be updated"

            assert zone2.content_dirty is False, "zone2 content_dirty flag should be cleared"
            assert zone2.last_content_sync is not None, "zone2 last_content_sync should be updated"

    def test_backend_api_authentication(self, setup_backend_test_data):
        """Test that backend API calls include proper authentication headers"""
        data = setup_backend_test_data
        backend = data['backend']

        # Clear any existing logs
        backend.clear_log()

        # Run sync directly
        async def run_sync():
            from teleddns_server.backend import update_config
            from datetime import datetime, timezone
            from sqlmodel import Session, select
            from teleddns_server.model import Server, MasterZone

            with Session(data['engine']) as session:
                # Get the server
                server = session.get(Server, data['server'].id)

                # Generate minimal config
                config_content = "zone:\n- domain: test1.example.com.\n  template: t_master\n  file: test1.example.com.zone\n"

                # Send config to backend
                await update_config(config_content, server.api_url, server.api_key)

        # Run the sync
        asyncio.run(run_sync())

        # Wait for requests
        assert backend.wait_for_requests(min_count=1, timeout=5), "No requests received"

        # Check all requests have proper authentication
        requests_log = backend.get_requests_log()

        for req in requests_log:
            if req['method'] in ['POST', 'GET']:
                assert 'authorization' in [k.lower() for k in req['headers'].keys()], f"Request {req['path']} missing authorization header"

                # Find the authorization header (case-insensitive)
                auth_header = None
                for k, v in req['headers'].items():
                    if k.lower() == 'authorization':
                        auth_header = v
                        break

                assert auth_header == 'Bearer test-api-key-12345', f"Wrong authorization header: {auth_header}"

    def test_zone_content_format(self, setup_backend_test_data):
        """Test that zone content sent to backend is in proper BIND format"""
        data = setup_backend_test_data
        backend = data['backend']

        # Clear logs and run sync
        backend.clear_log()

        async def run_sync():
            from teleddns_server.backend import update_zone
            from sqlmodel import Session, select
            from teleddns_server.model import MasterZone, RR_CLASSES

            with Session(data['engine']) as session:
                # Get zone1
                zone = session.get(MasterZone, data['zone1'].id)

                # Generate zone data
                zone_data = [zone.format_bind_zone()]

                # Add all RR records for this zone
                for rrclass in RR_CLASSES:
                    rr_records = session.exec(
                        select(rrclass).where(rrclass.zone_id == zone.id)
                    ).all()
                    for rr in rr_records:
                        zone_data.append(rr.format_bind_zone())

                zone_content = '\n'.join(zone_data) + '\n'

                # Send zone to backend
                await update_zone(
                    zone.origin.rstrip('.').strip(),
                    zone_content,
                    zone.master_server.api_url,
                    zone.master_server.api_key
                )

        asyncio.run(run_sync())

        # Get zone write requests
        requests_log = backend.get_requests_log()
        zone_writes = [r for r in requests_log if r['path'] == '/zonewrite' and r['method'] == 'POST']

        assert len(zone_writes) >= 1, "Should have at least one zone write"

        # Check zone content format
        zone_content = zone_writes[0]['body']
        lines = zone_content.strip().split('\n')

        # Should start with SOA record
        soa_line = None
        for line in lines:
            if 'SOA' in line:
                soa_line = line
                break

        assert soa_line is not None, "Zone should contain SOA record"
        assert 'IN SOA' in soa_line, "SOA record should be in proper format"

        # Should contain A/AAAA records
        has_a_record = any('IN A' in line for line in lines)
        has_aaaa_record = any('IN AAAA' in line for line in lines)

        assert has_a_record or has_aaaa_record, "Zone should contain A or AAAA records"
