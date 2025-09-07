# Simple authorization tests without full app setup

import pytest
import os
import sys
from sqlmodel import Session, SQLModel, create_engine
from sqlmodel.pool import StaticPool
import secrets

# Set test environment
os.environ.setdefault('ADMIN_PASSWORD', 'admin123')
os.environ.setdefault('SESSION_SECRET', 'test-secret-key')
os.environ.setdefault('DB_URL', 'sqlite://')
os.environ.setdefault('DISABLE_BACKEND_LOOP', 'true')

# Mock sys.argv for testing
sys.argv = ['test']

# Import after setting environment
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from teleddns_server.model import (
    User, Group, Zone, Server, APIToken, UserGroupLink, RRClass
)
from teleddns_server.view import verify_user, verify_token, can_write_to_zone


@pytest.fixture(name="test_engine")
def test_engine_fixture():
    """Create test database engine"""
    engine = create_engine(
        "sqlite://", 
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    return engine


@pytest.fixture(name="test_data")
def test_data_fixture(test_engine):
    """Create test data"""
    with Session(test_engine) as session:
        # Create users
        admin_user = User(
            username="admin",
            email="admin@test.com",
            password=User.gen_hash("admin123"),
            is_admin=True,
            is_active=True,
            is_verified=True
        )
        
        regular_user = User(
            username="user1", 
            email="user1@test.com",
            password=User.gen_hash("password123"),
            is_admin=False,
            is_active=True,
            is_verified=True
        )
        
        user_with_2fa = User(
            username="user2fa",
            email="user2fa@test.com",
            password=User.gen_hash("password123"), 
            is_admin=False,
            is_active=True,
            is_verified=True,
            has_2fa=True,
            totp_secret="SECRETKEY123"
        )
        
        group_user = User(
            username="groupuser",
            email="groupuser@test.com",
            password=User.gen_hash("password123"),
            is_admin=False,
            is_active=True,
            is_verified=True
        )
        
        session.add(admin_user)
        session.add(regular_user)
        session.add(user_with_2fa)
        session.add(group_user)
        session.commit()
        session.refresh(admin_user)
        session.refresh(regular_user)
        session.refresh(user_with_2fa)
        session.refresh(group_user)
        
        # Create group
        test_group = Group(name="testgroup", description="Test group")
        session.add(test_group)
        session.commit()
        session.refresh(test_group)
        
        # Add group_user to test_group
        group_link = UserGroupLink(user_id=group_user.id, group_id=test_group.id)
        session.add(group_link)
        session.commit()
        
        # Create server
        test_server = Server(
            name="test-server",
            api_url="http://test-server:8080",
            api_key="test-api-key",
            master_template="test_master"
        )
        session.add(test_server)
        session.commit()
        session.refresh(test_server)
        
        # Create API token
        token = APIToken(
            token=secrets.token_urlsafe(32),
            description="Test token",
            user_id=regular_user.id
        )
        session.add(token)
        session.commit()
        
        # Create zones
        user_zone = Zone(
            origin="user.example.com.",
            soa_NAME="user.example.com.",
            soa_CLASS=RRClass.IN,
            soa_TTL=86400,
            soa_MNAME="ns1.example.com.",
            soa_RNAME="admin.example.com.",
            soa_SERIAL=2024010101,
            soa_REFRESH=3600,
            soa_RETRY=900,
            soa_EXPIRE=1209600,
            soa_MINIMUM=86400,
            server_id=test_server.id,
            user_id=regular_user.id
        )
        
        group_zone = Zone(
            origin="group.example.com.",
            soa_NAME="group.example.com.",
            soa_CLASS=RRClass.IN,
            soa_TTL=86400,
            soa_MNAME="ns1.example.com.",
            soa_RNAME="admin.example.com.",
            soa_SERIAL=2024010102,
            soa_REFRESH=3600,
            soa_RETRY=900,
            soa_EXPIRE=1209600,
            soa_MINIMUM=86400,
            server_id=test_server.id,
            user_id=admin_user.id,
            group_id=test_group.id
        )
        
        session.add(user_zone)
        session.add(group_zone)
        session.commit()
        session.refresh(user_zone)
        session.refresh(group_zone)
        
        return {
            'admin_id': admin_user.id,
            'user1_id': regular_user.id,
            'user2fa_id': user_with_2fa.id,
            'groupuser_id': group_user.id,
            'group_id': test_group.id,
            'server_id': test_server.id,
            'token_id': token.id,
            'token_string': token.token,
            'user_zone_id': user_zone.id,
            'group_zone_id': group_zone.id
        }


class TestBasicAuth:
    """Test basic authentication functionality"""
    
    def test_verify_user_success(self, test_data, test_engine):
        """Test successful user verification"""
        # Mock the engine in the view module
        import teleddns_server.view
        original_engine = teleddns_server.view.engine
        teleddns_server.view.engine = test_engine
        
        try:
            user = verify_user("user1", "password123")
            assert user is not None
            assert user.username == "user1"
        finally:
            teleddns_server.view.engine = original_engine
    
    def test_verify_user_invalid_password(self, test_data, test_engine):
        """Test user verification with wrong password"""
        import teleddns_server.view
        original_engine = teleddns_server.view.engine
        teleddns_server.view.engine = test_engine
        
        try:
            user = verify_user("user1", "wrongpassword")
            assert user is None
        finally:
            teleddns_server.view.engine = original_engine
    
    def test_verify_user_with_2fa_blocked(self, test_data, test_engine):
        """Test that 2FA users are blocked from basic auth"""
        import teleddns_server.view
        original_engine = teleddns_server.view.engine
        teleddns_server.view.engine = test_engine
        
        try:
            user = verify_user("user2fa", "password123")
            assert user is None  # Should be blocked due to 2FA
        finally:
            teleddns_server.view.engine = original_engine
    
    def test_verify_token_success(self, test_data, test_engine):
        """Test successful token verification using relationships"""
        import teleddns_server.view
        original_engine = teleddns_server.view.engine
        teleddns_server.view.engine = test_engine
        
        try:
            user = verify_token(test_data['token_string'])
            assert user is not None
            assert user.username == "user1"
        finally:
            teleddns_server.view.engine = original_engine
    
    def test_verify_token_invalid(self, test_data, test_engine):
        """Test token verification with invalid token"""
        import teleddns_server.view
        original_engine = teleddns_server.view.engine
        teleddns_server.view.engine = test_engine
        
        try:
            user = verify_token("invalid-token")
            assert user is None
        finally:
            teleddns_server.view.engine = original_engine


class TestZoneAuth:
    """Test zone authorization"""
    
    def test_can_write_to_zone_owner(self, test_data, test_engine):
        """Test zone owner can write"""
        with Session(test_engine) as session:
            # Re-fetch objects in this session
            user = session.get(User, test_data['user1_id'])
            zone = session.get(Zone, test_data['user_zone_id'])
            result = can_write_to_zone(session, user, zone, "test")
            assert result is True
    
    def test_can_write_to_zone_group_member(self, test_data, test_engine):
        """Test group member can write to group zone"""
        with Session(test_engine) as session:
            # Re-fetch objects in this session - the relationships will be loaded automatically
            user = session.get(User, test_data['groupuser_id'])
            zone = session.get(Zone, test_data['group_zone_id'])
            result = can_write_to_zone(session, user, zone, "test")
            assert result is True
    
    def test_admin_can_write_any_zone(self, test_data, test_engine):
        """Test admin can write to any zone"""
        with Session(test_engine) as session:
            # Re-fetch objects in this session
            admin = session.get(User, test_data['admin_id'])
            user_zone = session.get(Zone, test_data['user_zone_id'])
            group_zone = session.get(Zone, test_data['group_zone_id'])
            
            result = can_write_to_zone(session, admin, user_zone, "test")
            assert result is True
            
            result = can_write_to_zone(session, admin, group_zone, "test")  
            assert result is True


class TestZoneModel:
    """Test zone model constraints"""
    
    def test_zone_requires_user_id(self, test_data, test_engine):
        """Test that zones must have user_id"""
        with Session(test_engine) as session:
            # This should work - using IDs directly
            zone = Zone(
                origin="test.example.com.",
                soa_NAME="test.example.com.",
                soa_CLASS=RRClass.IN,
                soa_TTL=86400,
                soa_MNAME="ns1.example.com.",
                soa_RNAME="admin.example.com.",
                soa_SERIAL=2024010101,
                soa_REFRESH=3600,
                soa_RETRY=900,
                soa_EXPIRE=1209600,
                soa_MINIMUM=86400,
                server_id=test_data['server_id'],
                user_id=test_data['user1_id']
            )
            session.add(zone)
            session.commit()  # Should succeed
    
    def test_zone_group_id_can_be_null(self, test_data, test_engine):
        """Test that zone group_id can be NULL"""
        with Session(test_engine) as session:
            zone = Zone(
                origin="nogroup.example.com.",
                soa_NAME="nogroup.example.com.",
                soa_CLASS=RRClass.IN,
                soa_TTL=86400,
                soa_MNAME="ns1.example.com.",
                soa_RNAME="admin.example.com.",
                soa_SERIAL=2024010101,
                soa_REFRESH=3600,
                soa_RETRY=900,
                soa_EXPIRE=1209600,
                soa_MINIMUM=86400,
                server_id=test_data['server_id'],
                user_id=test_data['user1_id'],
                group_id=None
            )
            session.add(zone)
            session.commit()  # Should succeed


if __name__ == "__main__":
    pytest.main([__file__])