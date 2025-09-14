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
import base64
from sqlmodel import Session, SQLModel, create_engine, select
from fastapi.testclient import TestClient

# Import our modules
import sys
import os

# Disable CLI parsing for tests
os.environ['DISABLE_CLI_PARSING'] = '1'

# Add the src directory to Python path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from teleddns_server.model import (
    User, UserToken, Group, UserGroup, MasterZone, Server,
    UserLabelAuthorization, GroupLabelAuthorization,
    A, AAAA, RRClass, engine as default_engine
)
from teleddns_server.main import app
from tests.test_settings import test_settings


class MockBackend:
    """Mock backend to avoid actual HTTP calls during tests"""
    def __init__(self):
        self.calls = []

    async def update_zone(self, zone_name, zone_data, api_url, api_key):
        self.calls.append(('update_zone', zone_name, zone_data, api_url, api_key))
        return "OK"

    async def update_config(self, server_config, api_url, api_key):
        self.calls.append(('update_config', server_config, api_url, api_key))
        return "OK"


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
def mock_backend(monkeypatch):
    """Mock the backend update functions"""
    backend = MockBackend()

    async def mock_update_zone(zone_name, zone_data, api_url, api_key):
        return await backend.update_zone(zone_name, zone_data, api_url, api_key)

    async def mock_update_config(server_config, api_url, api_key):
        return await backend.update_config(server_config, api_url, api_key)

    # Patch the backend module functions
    monkeypatch.setattr("teleddns_server.view.update_zone", mock_update_zone)
    monkeypatch.setattr("teleddns_server.backend.update_zone", mock_update_zone)
    monkeypatch.setattr("teleddns_server.backend.update_config", mock_update_config)

    return backend


@pytest.fixture
def setup_test_data(test_db):
    """Set up test data: users, groups, zones, server"""
    # Patch the global engine for this test
    import teleddns_server.model
    import teleddns_server.view
    original_engine = teleddns_server.model.engine
    teleddns_server.model.engine = test_db
    teleddns_server.view.engine = test_db

    with Session(test_db) as session:
        # Create server
        server = Server(
            name="test-server",
            api_url="http://localhost:8080/api",
            api_key="test-key",
            master_template="master_template",
            slave_template="slave_template"
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

        # Create standard user
        user1 = User(
            username="user1",
            email="user1@test.com",
            password=User.gen_hash("user1_pass"),
            is_admin=False
        )
        session.add(user1)

        # Create user2 (no group membership)
        user2 = User(
            username="user2",
            email="user2@test.com",
            password=User.gen_hash("user2_pass"),
            is_admin=False
        )
        session.add(user2)

        session.commit()
        session.refresh(admin_user)
        session.refresh(user1)
        session.refresh(user2)

        # Create groups
        group1 = Group(name="group1", description="Test group 1")
        session.add(group1)
        
        admin_group = Group(name="admin_group", description="Admin only group")
        session.add(admin_group)
        session.commit()
        session.refresh(group1)
        session.refresh(admin_group)

        # Add user1 to group1
        user_group = UserGroup(user_id=user1.id, group_id=group1.id)
        session.add(user_group)

        # Create bearer tokens for testing
        admin_token = "admin_token_123456"
        admin_token_hash = UserToken.hash(admin_token)
        admin_user_token = UserToken(
            token_hash=admin_token_hash,
            description="Admin test token",
            user_id=admin_user.id,
            is_active=True
        )
        session.add(admin_user_token)

        user1_token = "user1_token_789012"
        user1_token_hash = UserToken.hash(user1_token)
        user1_user_token = UserToken(
            token_hash=user1_token_hash,
            description="User1 test token",
            user_id=user1.id,
            is_active=True
        )
        session.add(user1_user_token)

        # Create zones
        # Zone1: owned by user1
        zone1 = MasterZone(
            origin="zone1.tld.",
            soa_NAME="@",
            soa_CLASS=RRClass.IN,
            soa_TTL=3600,
            soa_MNAME="ns1.zone1.tld.",
            soa_RNAME="admin.zone1.tld.",
            soa_SERIAL=1,
            soa_REFRESH=7200,
            soa_RETRY=3600,
            soa_EXPIRE=1209600,
            soa_MINIMUM=86400,
            owner_id=user1.id,
            group_id=group1.id,
            master_server_id=server.id
        )
        session.add(zone1)

        # Zone2: owned by admin, group is group1 (so user1 should have access via group)
        zone2 = MasterZone(
            origin="zone2.tld.",
            soa_NAME="@",
            soa_CLASS=RRClass.IN,
            soa_TTL=3600,
            soa_MNAME="ns1.zone2.tld.",
            soa_RNAME="admin.zone2.tld.",
            soa_SERIAL=1,
            soa_REFRESH=7200,
            soa_RETRY=3600,
            soa_EXPIRE=1209600,
            soa_MINIMUM=86400,
            owner_id=admin_user.id,
            group_id=group1.id,
            master_server_id=server.id
        )
        session.add(zone2)

        # Zone3: owned by admin, admin-only group (user1 should not have access)
        zone3 = MasterZone(
            origin="zone3.tld.",
            soa_NAME="@",
            soa_CLASS=RRClass.IN,
            soa_TTL=3600,
            soa_MNAME="ns1.zone3.tld.",
            soa_RNAME="admin.zone3.tld.",
            soa_SERIAL=1,
            soa_REFRESH=7200,
            soa_RETRY=3600,
            soa_EXPIRE=1209600,
            soa_MINIMUM=86400,
            owner_id=admin_user.id,
            group_id=admin_group.id,
            master_server_id=server.id
        )
        session.add(zone3)

        session.commit()
        session.refresh(zone1)
        session.refresh(zone2)
        session.refresh(zone3)

        yield {
            'engine': test_db,
            'server': server,
            'admin_user': admin_user,
            'user1': user1,
            'user2': user2,
            'group1': group1,
            'zone1': zone1,  # user1 owns this
            'zone2': zone2,  # admin owns, group1 has access
            'zone3': zone3,  # admin owns, no group access
            'admin_token': admin_token,
            'user1_token': user1_token
        }

    # Restore original engine
    teleddns_server.model.engine = original_engine
    teleddns_server.view.engine = original_engine


@pytest.fixture
def test_client(setup_test_data, mock_backend):
    """Create HTTP test client with mocked FastAPI app"""
    # Use FastAPI TestClient which wraps the app properly
    client = TestClient(app)

    yield client


class TestDDNSHTTPIntegration:

    def test_basic_auth_valid_credentials(self, test_client, setup_test_data):
        """Test successful DDNS update with valid basic auth credentials"""
        data = setup_test_data

        # Encode basic auth credentials
        credentials = base64.b64encode(b"user1:user1_pass").decode()
        headers = {"Authorization": f"Basic {credentials}"}

        # Test /ddns/update endpoint
        response = test_client.get(
            "/ddns/update?hostname=test.zone1.tld&myip=192.168.1.1",
            headers=headers
        )

        assert response.status_code == 200
        result = response.json()
        assert "DDNS updated A" in result["detail"]
        assert "192.168.1.1" in result["detail"]

        # Verify record was created in database
        with Session(data['engine']) as session:
            a_record = session.exec(
                select(A).where(A.label == "test", A.zone_id == data['zone1'].id)
            ).first()
            assert a_record is not None
            assert a_record.value == "192.168.1.1"

    def test_update_endpoint_equivalent(self, test_client, setup_test_data):
        """Test that /update endpoint works identically to /ddns/update"""
        data = setup_test_data

        credentials = base64.b64encode(b"user1:user1_pass").decode()
        headers = {"Authorization": f"Basic {credentials}"}

        # Test /update endpoint (alternative endpoint)
        response = test_client.get(
            "/update?hostname=alt.zone1.tld&myip=192.168.1.2",
            headers=headers
        )

        assert response.status_code == 200
        result = response.json()
        assert "DDNS updated A" in result["detail"]
        assert "192.168.1.2" in result["detail"]

        # Verify record was created in database
        with Session(data['engine']) as session:
            a_record = session.exec(
                select(A).where(A.label == "alt", A.zone_id == data['zone1'].id)
            ).first()
            assert a_record is not None
            assert a_record.value == "192.168.1.2"

    def test_basic_auth_invalid_credentials(self, test_client, setup_test_data):
        """Test DDNS update fails with invalid basic auth credentials"""

        # Test wrong password
        credentials = base64.b64encode(b"user1:wrong_password").decode()
        headers = {"Authorization": f"Basic {credentials}"}

        response = test_client.get(
            "/ddns/update?hostname=test.zone1.tld&myip=192.168.1.1",
            headers=headers
        )

        assert response.status_code == 401
        result = response.json()
        assert "Incorrect username or password" in result["detail"]

        # Test non-existent user
        credentials = base64.b64encode(b"nonexistent:password").decode()
        headers = {"Authorization": f"Basic {credentials}"}

        response = test_client.get(
            "/ddns/update?hostname=test.zone1.tld&myip=192.168.1.1",
            headers=headers
        )

        assert response.status_code == 401
        result = response.json()
        assert "Incorrect username or password" in result["detail"]

    def test_bearer_token_valid(self, test_client, setup_test_data):
        """Test successful DDNS update with valid bearer token"""
        data = setup_test_data

        print(f"Debug: user1_token = {data['user1_token']}")
        headers = {"Authorization": f"Bearer {data['user1_token']}"}
        print(f"Debug: headers = {headers}")

        response = test_client.get(
            "/ddns/update?hostname=bearer.zone1.tld&myip=10.0.0.1",
            headers=headers
        )

        if response.status_code != 200:
            print(f"Status: {response.status_code}, Response: {response.json()}")

        assert response.status_code == 200
        result = response.json()
        assert "DDNS updated A" in result["detail"]
        assert "10.0.0.1" in result["detail"]

        # Verify record was created in database
        with Session(data['engine']) as session:
            a_record = session.exec(
                select(A).where(A.label == "bearer", A.zone_id == data['zone1'].id)
            ).first()
            assert a_record is not None
            assert a_record.value == "10.0.0.1"

    def test_bearer_token_invalid(self, test_client, setup_test_data):
        """Test DDNS update fails with invalid bearer token"""

        headers = {"Authorization": "Bearer invalid_token_12345"}

        response = test_client.get(
            "/ddns/update?hostname=test.zone1.tld&myip=192.168.1.1",
            headers=headers
        )

        assert response.status_code == 401
        result = response.json()
        assert "Authentication required" in result["detail"]

    def test_no_auth_header_fails(self, test_client, setup_test_data):
        """Test DDNS update fails without authentication header"""

        response = test_client.get(
            "/ddns/update?hostname=test.zone1.tld&myip=192.168.1.1"
        )

        assert response.status_code == 401
        result = response.json()
        assert "Authentication required" in result["detail"]

    def test_2fa_user_basic_auth_rejected(self, test_client, setup_test_data):
        """Test that users with 2FA enabled cannot use basic auth"""
        data = setup_test_data

        # Enable 2FA for user1
        with Session(data['engine']) as session:
            user1 = session.get(User, data['user1'].id)
            user1.totp_enabled = True
            session.commit()

        # Basic auth should be rejected
        credentials = base64.b64encode(b"user1:user1_pass").decode()
        headers = {"Authorization": f"Basic {credentials}"}

        response = test_client.get(
            "/ddns/update?hostname=test.zone1.tld&myip=192.168.1.1",
            headers=headers
        )

        assert response.status_code == 401
        result = response.json()
        assert "Basic authentication not allowed" in result["detail"]
        assert "2FA" in result["detail"]

        # But bearer token should still work
        headers = {"Authorization": f"Bearer {data['user1_token']}"}

        response = test_client.get(
            "/ddns/update?hostname=test2fa.zone1.tld&myip=192.168.1.10",
            headers=headers
        )

        assert response.status_code == 200
        result = response.json()
        assert "DDNS updated A" in result["detail"]

    def test_zone_owner_can_update(self, test_client, setup_test_data):
        """Test zone owner can update their own zone"""
        data = setup_test_data

        credentials = base64.b64encode(b"user1:user1_pass").decode()
        headers = {"Authorization": f"Basic {credentials}"}

        # user1 owns zone1
        response = test_client.get(
            "/ddns/update?hostname=owner.zone1.tld&myip=172.16.1.1",
            headers=headers
        )

        assert response.status_code == 200
        result = response.json()
        assert "DDNS updated A" in result["detail"]
        assert "172.16.1.1" in result["detail"]

        # Verify record and SOA serial increment
        with Session(data['engine']) as session:
            a_record = session.exec(
                select(A).where(A.label == "owner", A.zone_id == data['zone1'].id)
            ).first()
            assert a_record is not None
            assert a_record.value == "172.16.1.1"

            zone = session.get(MasterZone, data['zone1'].id)
            assert zone.soa_SERIAL == 2  # Should be incremented from 1

    def test_admin_can_update_any_zone(self, test_client, setup_test_data):
        """Test admin can update any zone"""
        data = setup_test_data

        credentials = base64.b64encode(b"admin:admin_pass").decode()
        headers = {"Authorization": f"Basic {credentials}"}

        # Admin should be able to update zone1 (owned by user1)
        response = test_client.get(
            "/ddns/update?hostname=admin-test.zone1.tld&myip=203.0.113.1",
            headers=headers
        )

        assert response.status_code == 200
        result = response.json()
        assert "DDNS updated A" in result["detail"]

        # Admin should be able to update zone3 (owned by admin)
        response = test_client.get(
            "/ddns/update?hostname=admin-test.zone3.tld&myip=203.0.113.2",
            headers=headers
        )

        assert response.status_code == 200
        result = response.json()
        assert "DDNS updated A" in result["detail"]

    def test_group_member_can_update(self, test_client, setup_test_data):
        """Test user can access zone via group membership"""
        data = setup_test_data

        credentials = base64.b64encode(b"user1:user1_pass").decode()
        headers = {"Authorization": f"Basic {credentials}"}

        # user1 is in group1, zone2 is owned by admin but group1 has access
        response = test_client.get(
            "/ddns/update?hostname=group-access.zone2.tld&myip=198.51.100.1",
            headers=headers
        )

        assert response.status_code == 200
        result = response.json()
        assert "DDNS updated A" in result["detail"]
        assert "198.51.100.1" in result["detail"]

        # Verify record was created
        with Session(data['engine']) as session:
            a_record = session.exec(
                select(A).where(A.label == "group-access", A.zone_id == data['zone2'].id)
            ).first()
            assert a_record is not None
            assert a_record.value == "198.51.100.1"

    def test_unauthorized_zone_access_fails(self, test_client, setup_test_data):
        """Test user cannot access zones they don't own and aren't in group for"""
        data = setup_test_data

        # user1 should not be able to access zone3 (owned by admin, no group access)
        credentials = base64.b64encode(b"user1:user1_pass").decode()
        headers = {"Authorization": f"Basic {credentials}"}

        response = test_client.get(
            "/ddns/update?hostname=unauthorized.zone3.tld&myip=192.168.1.100",
            headers=headers
        )

        assert response.status_code == 401
        result = response.json()
        assert "Unauthorized access" in result["detail"]

        # user2 (not in any group) should not access zone2
        credentials = base64.b64encode(b"user2:user2_pass").decode()
        headers = {"Authorization": f"Basic {credentials}"}

        response = test_client.get(
            "/ddns/update?hostname=unauthorized.zone2.tld&myip=192.168.1.101",
            headers=headers
        )

        assert response.status_code == 401
        result = response.json()
        assert "Unauthorized access" in result["detail"]

    def test_ddns_ipv4_and_ipv6_updates(self, test_client, setup_test_data):
        """Test DDNS updates work with both IPv4 and IPv6 addresses"""
        data = setup_test_data

        credentials = base64.b64encode(b"user1:user1_pass").decode()
        headers = {"Authorization": f"Basic {credentials}"}

        # Test IPv4
        response = test_client.get(
            "/ddns/update?hostname=ipv4test.zone1.tld&myip=192.0.2.100",
            headers=headers
        )

        assert response.status_code == 200
        result = response.json()
        assert "DDNS updated A" in result["detail"]
        assert "192.0.2.100" in result["detail"]

        # Test IPv6
        response = test_client.get(
            "/ddns/update?hostname=ipv6test.zone1.tld&myip=2001:db8::42",
            headers=headers
        )

        assert response.status_code == 200
        result = response.json()
        assert "DDNS updated AAAA" in result["detail"]
        assert "2001:db8::42" in result["detail"]

        # Verify both records were created
        with Session(data['engine']) as session:
            a_record = session.exec(
                select(A).where(A.label == "ipv4test", A.zone_id == data['zone1'].id)
            ).first()
            assert a_record is not None
            assert a_record.value == "192.0.2.100"

            aaaa_record = session.exec(
                select(AAAA).where(AAAA.label == "ipv6test", A.zone_id == data['zone1'].id)
            ).first()
            assert aaaa_record is not None
            assert aaaa_record.value == "2001:db8::42"

    def test_ddns_record_replacement(self, test_client, setup_test_data):
        """Test that DDNS updates replace existing records"""
        data = setup_test_data

        credentials = base64.b64encode(b"user1:user1_pass").decode()
        headers = {"Authorization": f"Basic {credentials}"}

        # Create initial record
        response = test_client.get(
            "/ddns/update?hostname=replace.zone1.tld&myip=192.0.2.1",
            headers=headers
        )

        assert response.status_code == 200
        assert "192.0.2.1" in response.json()["detail"]

        # Update the same hostname with different IP
        response = test_client.get(
            "/ddns/update?hostname=replace.zone1.tld&myip=192.0.2.2",
            headers=headers
        )

        assert response.status_code == 200
        assert "192.0.2.2" in response.json()["detail"]

        # Verify only the new record exists
        with Session(data['engine']) as session:
            a_records = session.exec(
                select(A).where(A.label == "replace", A.zone_id == data['zone1'].id)
            ).all()
            assert len(a_records) == 1
            assert a_records[0].value == "192.0.2.2"

    def test_ddns_noop_when_ip_unchanged(self, test_client, setup_test_data):
        """Test that DDNS returns noop when IP is already correct"""
        data = setup_test_data

        credentials = base64.b64encode(b"user1:user1_pass").decode()
        headers = {"Authorization": f"Basic {credentials}"}

        # Create initial record
        response = test_client.get(
            "/ddns/update?hostname=noop.zone1.tld&myip=192.0.2.50",
            headers=headers
        )

        assert response.status_code == 200
        result = response.json()
        assert "DDNS updated A" in result["detail"]

        # Get the zone serial after first update
        with Session(data['engine']) as session:
            zone = session.get(MasterZone, data['zone1'].id)
            serial_after_update = zone.soa_SERIAL

        # Try to update with same IP - should be noop
        response = test_client.get(
            "/ddns/update?hostname=noop.zone1.tld&myip=192.0.2.50",
            headers=headers
        )

        assert response.status_code == 200
        result = response.json()
        assert "DDNS noop A" in result["detail"]

        # Verify serial number didn't change for noop
        with Session(data['engine']) as session:
            zone = session.get(MasterZone, data['zone1'].id)
            assert zone.soa_SERIAL == serial_after_update

    def test_invalid_ip_address(self, test_client, setup_test_data):
        """Test DDNS update fails with invalid IP address"""

        credentials = base64.b64encode(b"user1:user1_pass").decode()
        headers = {"Authorization": f"Basic {credentials}"}

        response = test_client.get(
            "/ddns/update?hostname=test.zone1.tld&myip=not.an.ip.address",
            headers=headers
        )

        assert response.status_code == 400
        result = response.json()
        assert "does not appear to be an IPv4 or IPv6 address" in result["detail"] or "Invalid IP address" in result["detail"]

    def test_zone_not_found(self, test_client, setup_test_data):
        """Test DDNS update fails when zone is not found"""

        credentials = base64.b64encode(b"user1:user1_pass").decode()
        headers = {"Authorization": f"Basic {credentials}"}

        response = test_client.get(
            "/ddns/update?hostname=test.nonexistent.zone&myip=192.168.1.1",
            headers=headers
        )

        assert response.status_code == 404
        result = response.json()
        assert "Zone not found" in result["detail"]

    def test_user_label_authorization(self, test_client, setup_test_data):
        """Test UserLabelAuthorization allows specific label patterns"""
        data = setup_test_data

        # Create UserLabelAuthorization: user2 can access labels matching "special-.*" pattern in zone3
        with Session(data['engine']) as session:
            user_auth = UserLabelAuthorization(
                user_id=data['user2'].id,
                zone_id=data['zone3'].id,
                label_pattern="special-.*"
            )
            session.add(user_auth)
            session.commit()

        credentials = base64.b64encode(b"user2:user2_pass").decode()
        headers = {"Authorization": f"Basic {credentials}"}

        # user2 should be able to access zone3 with matching pattern
        response = test_client.get(
            "/ddns/update?hostname=special-label.zone3.tld&myip=203.0.113.100",
            headers=headers
        )

        assert response.status_code == 200
        result = response.json()
        assert "DDNS updated A" in result["detail"]

        # user2 should NOT be able to access zone3 with non-matching pattern
        response = test_client.get(
            "/ddns/update?hostname=regular-label.zone3.tld&myip=203.0.113.101",
            headers=headers
        )

        assert response.status_code == 401
        result = response.json()
        assert "Unauthorized access" in result["detail"]
