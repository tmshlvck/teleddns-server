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
import hashlib
from datetime import datetime
from sqlmodel import Session, SQLModel, create_engine, select
from fastapi.exceptions import HTTPException

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
    A, AAAA, RRClass
)
from teleddns_server.view import ddns_update, can_write_to_zone


class MockBackend:
    """Mock backend to avoid actual HTTP calls during tests"""
    def __init__(self):
        self.calls = []
    
    async def update_zone(self, zone_name, zone_data, api_url, api_key):
        self.calls.append(('update_zone', zone_name, zone_data, api_url, api_key))
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
    
    # Patch the backend module functions
    monkeypatch.setattr("teleddns_server.view.update_zone", mock_update_zone)
    
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
            password=User.gen_hash("test"),
            is_admin=True
        )
        session.add(admin_user)
        
        # Create standard user
        user1 = User(
            username="user1",
            email="user1@test.com", 
            password=User.gen_hash("test"),
            is_admin=False
        )
        session.add(user1)
        session.commit()
        session.refresh(admin_user)
        session.refresh(user1)
        
        # Create group
        group1 = Group(name="group1", description="Test group 1")
        session.add(group1)
        session.commit()
        session.refresh(group1)
        
        # Add user1 to group1
        user_group = UserGroup(user_id=user1.id, group_id=group1.id)
        session.add(user_group)
        
        # Create bearer tokens for testing
        admin_token = "admin_token_123"
        admin_token_hash = hashlib.sha256(admin_token.encode()).hexdigest()
        admin_user_token = UserToken(
            token_hash=admin_token_hash,
            description="Admin test token",
            user_id=admin_user.id,
            is_active=True
        )
        session.add(admin_user_token)
        
        user1_token = "user1_token_456"
        user1_token_hash = hashlib.sha256(user1_token.encode()).hexdigest()
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
        
        # Zone3: owned by admin, no group (user1 should not have access)
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


class TestDDNSAuthentication:
    
    @pytest.mark.asyncio
    async def test_admin_ddns_updates_ipv4_and_ipv6(self, setup_test_data, mock_backend):
        """Test admin can update any zone with both IPv4 and IPv6 addresses"""
        data = setup_test_data
        
        # Test IPv4 update on zone1
        result = await ddns_update("admin", "test", "label1.zone1.tld", "192.168.1.1")
        assert "DDNS updated A" in result
        assert "192.168.1.1" in result
        
        # Test IPv6 update on zone1  
        result = await ddns_update("admin", "test", "label2.zone1.tld", "2001:db8::1")
        assert "DDNS updated AAAA" in result
        assert "2001:db8::1" in result
        
        # Verify records were created
        with Session(data['engine']) as session:
            a_record = session.exec(select(A).where(A.label == "label1", A.zone_id == data['zone1'].id)).first()
            assert a_record is not None
            assert a_record.value == "192.168.1.1"
            
            aaaa_record = session.exec(select(AAAA).where(AAAA.label == "label2", AAAA.zone_id == data['zone1'].id)).first()
            assert aaaa_record is not None
            assert aaaa_record.value == "2001:db8::1"
    
    @pytest.mark.asyncio
    async def test_admin_bearer_token_auth(self, setup_test_data, mock_backend):
        """Test admin can authenticate using bearer token"""
        data = setup_test_data
        
        result = await ddns_update("", "", "label3.zone1.tld", "192.168.1.3", bearer_token=data['admin_token'])
        assert "DDNS updated A" in result
        assert "192.168.1.3" in result
    
    @pytest.mark.asyncio  
    async def test_zone_owner_ddns_updates(self, setup_test_data, mock_backend):
        """Test zone owner can update their own zone"""
        data = setup_test_data
        
        # user1 owns zone1, should be able to update
        result = await ddns_update("user1", "test", "owner-label.zone1.tld", "10.0.0.1")
        assert "DDNS updated A" in result
        
        # user1 with bearer token
        result = await ddns_update("", "", "owner-label2.zone1.tld", "10.0.0.2", bearer_token=data['user1_token'])
        assert "DDNS updated A" in result
    
    @pytest.mark.asyncio
    async def test_group_based_zone_access(self, setup_test_data, mock_backend):
        """Test user can access zone via group membership"""
        data = setup_test_data
        
        # user1 is in group1, zone2 is owned by admin but group1 has access
        result = await ddns_update("user1", "test", "group-label.zone2.tld", "172.16.1.1")
        assert "DDNS updated A" in result
        
        # Test with bearer token
        result = await ddns_update("", "", "group-label2.zone2.tld", "172.16.1.2", bearer_token=data['user1_token'])
        assert "DDNS updated A" in result
    
    @pytest.mark.asyncio
    async def test_unauthorized_zone_access_failures(self, setup_test_data, mock_backend):
        """Test user cannot access zones they don't own and aren't in group for"""
        data = setup_test_data
        
        # user1 should not be able to access zone3 (owned by admin, no group access)
        with pytest.raises(HTTPException) as exc_info:
            await ddns_update("user1", "test", "unauthorized.zone3.tld", "192.168.1.100")
        assert exc_info.value.status_code == 401
        assert "Unauthorized access" in str(exc_info.value.detail)
        
        # Test with bearer token too
        with pytest.raises(HTTPException) as exc_info:
            await ddns_update("", "", "unauthorized2.zone3.tld", "192.168.1.101", bearer_token=data['user1_token'])
        assert exc_info.value.status_code == 401
    
    @pytest.mark.asyncio
    async def test_user_label_authorization_scenarios(self, setup_test_data, mock_backend):
        """Test UserLabelAuthorization patterns"""
        data = setup_test_data
        
        with Session(data['engine']) as session:
            # Create UserLabelAuthorization: user1 can access labels matching "special-.*" pattern in zone3
            user_auth = UserLabelAuthorization(
                user_id=data['user1'].id,
                zone_id=data['zone3'].id,
                label_pattern="special-.*"
            )
            session.add(user_auth)
            session.commit()
        
        # user1 should be able to access zone3 with matching pattern
        result = await ddns_update("user1", "test", "special-label.zone3.tld", "203.0.113.1")
        assert "DDNS updated A" in result
        
        # user1 should NOT be able to access zone3 with non-matching pattern
        with pytest.raises(HTTPException) as exc_info:
            await ddns_update("user1", "test", "regular-label.zone3.tld", "203.0.113.2")
        assert exc_info.value.status_code == 401
        
        # Test with bearer token - should work with pattern match
        result = await ddns_update("", "", "special-token.zone3.tld", "203.0.113.3", bearer_token=data['user1_token'])
        assert "DDNS updated A" in result
    
    @pytest.mark.asyncio
    async def test_group_label_authorization_scenarios(self, setup_test_data, mock_backend):
        """Test GroupLabelAuthorization patterns"""
        data = setup_test_data
        
        # Create another user not in group1 to test group-specific access
        with Session(data['engine']) as session:
            user2 = User(
                username="user2",
                email="user2@test.com",
                password=User.gen_hash("test"),
                is_admin=False
            )
            session.add(user2)
            session.commit()
            session.refresh(user2)
            
            # Create GroupLabelAuthorization: group1 can access labels matching "group-.*" pattern in zone3
            group_auth = GroupLabelAuthorization(
                group_id=data['group1'].id,
                zone_id=data['zone3'].id,
                label_pattern="group-.*"
            )
            session.add(group_auth)
            session.commit()
        
        # user1 (in group1) should be able to access zone3 with matching pattern
        result = await ddns_update("user1", "test", "group-access.zone3.tld", "198.51.100.1")
        assert "DDNS updated A" in result
        
        # user2 (not in group1) should NOT be able to access zone3 even with matching pattern
        with pytest.raises(HTTPException) as exc_info:
            await ddns_update("user2", "test", "group-access2.zone3.tld", "198.51.100.2") 
        assert exc_info.value.status_code == 401
    
    @pytest.mark.asyncio
    async def test_invalid_credentials(self, setup_test_data, mock_backend):
        """Test authentication failures with wrong credentials"""
        data = setup_test_data
        
        # Wrong password
        with pytest.raises(HTTPException) as exc_info:
            await ddns_update("user1", "wrong_password", "test.zone1.tld", "192.168.1.200")
        assert exc_info.value.status_code == 401
        
        # Wrong username
        with pytest.raises(HTTPException) as exc_info:
            await ddns_update("nonexistent", "test", "test.zone1.tld", "192.168.1.201")
        assert exc_info.value.status_code == 401
        
        # Wrong bearer token
        with pytest.raises(HTTPException) as exc_info:
            await ddns_update("", "", "test.zone1.tld", "192.168.1.202", bearer_token="invalid_token")
        assert exc_info.value.status_code == 401
    
    @pytest.mark.asyncio
    async def test_2fa_user_basic_auth_rejection(self, setup_test_data, mock_backend):
        """Test that users with 2FA enabled cannot use basic auth"""
        data = setup_test_data
        
        with Session(data['engine']) as session:
            # Enable 2FA for user1
            user1 = session.get(User, data['user1'].id)
            user1.totp_enabled = True
            session.commit()
        
        # user1 with 2FA should be rejected for basic auth
        with pytest.raises(HTTPException) as exc_info:
            await ddns_update("user1", "test", "test.zone1.tld", "192.168.1.210")
        assert exc_info.value.status_code == 401
        assert "Basic authentication not allowed" in str(exc_info.value.detail)
        
        # But bearer token should still work
        result = await ddns_update("", "", "test2fa.zone1.tld", "192.168.1.211", bearer_token=data['user1_token'])
        assert "DDNS updated A" in result
    
    def test_can_write_to_zone_function(self, setup_test_data):
        """Test the can_write_to_zone authorization function directly"""
        data = setup_test_data
        
        with Session(data['engine']) as session:
            admin_user = session.get(User, data['admin_user'].id)
            user1 = session.get(User, data['user1'].id)
            zone1 = session.get(MasterZone, data['zone1'].id)
            zone2 = session.get(MasterZone, data['zone2'].id)
            zone3 = session.get(MasterZone, data['zone3'].id)
            
            # Admin can write to any zone
            assert can_write_to_zone(session, admin_user, zone1, "any-label") == True
            assert can_write_to_zone(session, admin_user, zone2, "any-label") == True
            assert can_write_to_zone(session, admin_user, zone3, "any-label") == True
            
            # user1 owns zone1
            assert can_write_to_zone(session, user1, zone1, "any-label") == True
            
            # user1 can access zone2 via group
            assert can_write_to_zone(session, user1, zone2, "any-label") == True
            
            # user1 cannot access zone3 (no ownership, no group, no explicit auth)
            assert can_write_to_zone(session, user1, zone3, "any-label") == False