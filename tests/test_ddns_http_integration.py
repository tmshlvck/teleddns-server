"""
DDNS HTTP Integration Tests for TeleDDNS Server Django Implementation.

Comprehensive tests for DDNS endpoints using Django's test client,
adapted from the original FastAPI tests.
"""
import base64
import pytest
from django.test import TestCase, Client, TransactionTestCase
from django.contrib.auth import get_user_model
from django.conf import settings
from unittest.mock import patch, MagicMock

from dns_manager.models import (
    User, UserToken, UserPassKey, Group, UserGroup, MasterZone, Server, 
    A, AAAA, UserLabelAuthorization, GroupLabelAuthorization, RRClass
)

User = get_user_model()


class MockBackendSyncService:
    """Mock backend sync service to avoid actual HTTP calls during tests."""
    
    def __init__(self):
        self.calls = []
        self.running = False
        
    def start(self):
        self.running = True
        
    def stop(self):
        self.running = False
        
    def trigger_sync(self):
        self.calls.append('trigger_sync')


@pytest.mark.django_db 
class TestDDNSHTTPIntegration(TransactionTestCase):
    """DDNS HTTP integration tests."""
    
    def setUp(self):
        """Set up test data: users, groups, zones, servers."""
        # Mock the background sync service
        self.mock_sync_patcher = patch('dns_manager.sync.get_sync_service')
        mock_get_sync_service = self.mock_sync_patcher.start()
        self.mock_sync_service = MockBackendSyncService()
        mock_get_sync_service.return_value = self.mock_sync_service
        
        # Mock backend HTTP calls
        self.backend_patcher = patch('dns_manager.backend.update_zone')
        self.config_patcher = patch('dns_manager.backend.update_config')
        self.mock_update_zone = self.backend_patcher.start()
        self.mock_update_config = self.config_patcher.start()
        
        self.client = Client()
        
        # Create server
        self.admin_user = User.objects.create_user(
            username='admin',
            email='admin@test.com',
            password='admin_pass',
            is_superuser=True,
            is_staff=True
        )
        
        self.server = Server.objects.create(
            name='test-server',
            api_url='http://localhost:8080/api',
            api_key='test-key',
            master_template='master_template',
            slave_template='slave_template',
            owner=self.admin_user
        )
        
        # Create standard users
        self.user1 = User.objects.create_user(
            username='user1',
            email='user1@test.com',
            password='user1_pass'
        )
        
        self.user2 = User.objects.create_user(
            username='user2',
            email='user2@test.com', 
            password='user2_pass'
        )
        
        # Create group and add user1 to it
        self.group1 = Group.objects.create(
            name='group1',
            description='Test group 1'
        )
        UserGroup.objects.create(user=self.user1, group=self.group1)
        
        # Create bearer tokens for testing
        self.admin_token_str = 'admin_token_123456'
        self.admin_token = UserToken.objects.create(
            user=self.admin_user,
            token_hash=UserToken.hash(self.admin_token_str),
            description='Admin test token'
        )
        
        self.user1_token_str = 'user1_token_789012'
        self.user1_token = UserToken.objects.create(
            user=self.user1,
            token_hash=UserToken.hash(self.user1_token_str),
            description='User1 test token'
        )
        
        # Create zones
        # Zone1: owned by user1
        self.zone1 = MasterZone.objects.create(
            origin='zone1.tld.',
            soa_name='@',
            soa_mname='ns1.zone1.tld.',
            soa_rname='admin.zone1.tld.',
            soa_serial=1,
            owner=self.user1,
            master_server=self.server
        )
        
        # Zone2: owned by admin, group is group1 (so user1 should have access via group) 
        self.zone2 = MasterZone.objects.create(
            origin='zone2.tld.',
            soa_name='@',
            soa_mname='ns1.zone2.tld.',
            soa_rname='admin.zone2.tld.',
            soa_serial=1,
            owner=self.admin_user,
            group=self.group1,
            master_server=self.server
        )
        
        # Zone3: owned by admin, no group (user1 should not have access)
        self.zone3 = MasterZone.objects.create(
            origin='zone3.tld.',
            soa_name='@',
            soa_mname='ns1.zone3.tld.',
            soa_rname='admin.zone3.tld.',
            soa_serial=1,
            owner=self.admin_user,
            master_server=self.server
        )
        
    def tearDown(self):
        """Clean up mocks."""
        self.mock_sync_patcher.stop()
        self.backend_patcher.stop() 
        self.config_patcher.stop()
        
    def test_basic_auth_valid_credentials(self):
        """Test successful DDNS update with valid basic auth credentials."""
        credentials = base64.b64encode(b'user1:user1_pass').decode()
        headers = {'HTTP_AUTHORIZATION': f'Basic {credentials}'}
        
        response = self.client.get(
            '/ddns/update?hostname=test.zone1.tld&myip=192.168.1.1',
            **headers
        )
        
        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertIn('good', result['detail'])
        self.assertIn('192.168.1.1', result['detail'])
        
        # Verify record was created in database
        a_record = A.objects.filter(label='test', zone=self.zone1).first()
        self.assertIsNotNone(a_record)
        self.assertEqual(a_record.value, '192.168.1.1')
        
    def test_update_endpoint_equivalent(self):
        """Test that /update endpoint works identically to /ddns/update."""
        credentials = base64.b64encode(b'user1:user1_pass').decode()
        headers = {'HTTP_AUTHORIZATION': f'Basic {credentials}'}
        
        response = self.client.get(
            '/update?hostname=alt.zone1.tld&myip=192.168.1.2',
            **headers
        )
        
        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertIn('good', result['detail'])
        self.assertIn('192.168.1.2', result['detail'])
        
        # Verify record was created
        a_record = A.objects.filter(label='alt', zone=self.zone1).first()
        self.assertIsNotNone(a_record)
        self.assertEqual(a_record.value, '192.168.1.2')
        
    def test_basic_auth_invalid_credentials(self):
        """Test DDNS update fails with invalid basic auth credentials."""
        # Wrong password
        credentials = base64.b64encode(b'user1:wrong_password').decode()
        headers = {'HTTP_AUTHORIZATION': f'Basic {credentials}'}
        
        response = self.client.get(
            '/ddns/update?hostname=test.zone1.tld&myip=192.168.1.1',
            **headers
        )
        
        self.assertEqual(response.status_code, 401)
        result = response.json()
        self.assertIn('badauth', result['detail'])
        
        # Non-existent user
        credentials = base64.b64encode(b'nonexistent:password').decode()
        headers = {'HTTP_AUTHORIZATION': f'Basic {credentials}'}
        
        response = self.client.get(
            '/ddns/update?hostname=test.zone1.tld&myip=192.168.1.1',
            **headers
        )
        
        self.assertEqual(response.status_code, 401)
        result = response.json()
        self.assertIn('badauth', result['detail'])
        
    def test_bearer_token_valid(self):
        """Test successful DDNS update with valid bearer token."""
        headers = {'HTTP_AUTHORIZATION': f'Bearer {self.user1_token_str}'}
        
        response = self.client.get(
            '/ddns/update?hostname=bearer.zone1.tld&myip=10.0.0.1',
            **headers
        )
        
        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertIn('good', result['detail'])
        self.assertIn('10.0.0.1', result['detail'])
        
        # Verify record was created
        a_record = A.objects.filter(label='bearer', zone=self.zone1).first()
        self.assertIsNotNone(a_record)
        self.assertEqual(a_record.value, '10.0.0.1')
        
    def test_bearer_token_invalid(self):
        """Test DDNS update fails with invalid bearer token."""
        headers = {'HTTP_AUTHORIZATION': 'Bearer invalid_token_12345'}
        
        response = self.client.get(
            '/ddns/update?hostname=test.zone1.tld&myip=192.168.1.1',
            **headers
        )
        
        self.assertEqual(response.status_code, 401)
        result = response.json()
        self.assertIn('badauth', result['detail'])
        
    def test_no_auth_header_fails(self):
        """Test DDNS update fails without authentication header."""
        response = self.client.get(
            '/ddns/update?hostname=test.zone1.tld&myip=192.168.1.1'
        )
        
        self.assertEqual(response.status_code, 401)
        result = response.json()
        self.assertIn('badauth', result['detail'])
        
    def test_2fa_user_basic_auth_rejected(self):
        """Test that users with 2FA enabled cannot use basic auth."""
        # Enable 2FA for user1
        self.user1.totp_enabled = True
        self.user1.save()
        
        # Basic auth should be rejected
        credentials = base64.b64encode(b'user1:user1_pass').decode()
        headers = {'HTTP_AUTHORIZATION': f'Basic {credentials}'}
        
        response = self.client.get(
            '/ddns/update?hostname=test.zone1.tld&myip=192.168.1.1',
            **headers
        )
        
        self.assertEqual(response.status_code, 401)
        result = response.json()
        self.assertIn('badauth', result['detail'])
        self.assertIn('2FA', result['detail'])
        
        # But bearer token should still work
        headers = {'HTTP_AUTHORIZATION': f'Bearer {self.user1_token_str}'}
        
        response = self.client.get(
            '/ddns/update?hostname=test2fa.zone1.tld&myip=192.168.1.10',
            **headers
        )
        
        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertIn('good', result['detail'])
        
    def test_zone_owner_can_update(self):
        """Test zone owner can update their own zone."""
        credentials = base64.b64encode(b'user1:user1_pass').decode()
        headers = {'HTTP_AUTHORIZATION': f'Basic {credentials}'}
        
        # user1 owns zone1
        response = self.client.get(
            '/ddns/update?hostname=owner.zone1.tld&myip=172.16.1.1',
            **headers
        )
        
        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertIn('good', result['detail'])
        self.assertIn('172.16.1.1', result['detail'])
        
        # Verify record and SOA serial increment
        a_record = A.objects.filter(label='owner', zone=self.zone1).first()
        self.assertIsNotNone(a_record)
        self.assertEqual(a_record.value, '172.16.1.1')
        
        self.zone1.refresh_from_db()
        self.assertEqual(self.zone1.soa_serial, 2)  # Should be incremented from 1
        
    def test_admin_can_update_any_zone(self):
        """Test admin can update any zone."""
        credentials = base64.b64encode(b'admin:admin_pass').decode()
        headers = {'HTTP_AUTHORIZATION': f'Basic {credentials}'}
        
        # Admin should be able to update zone1 (owned by user1)
        response = self.client.get(
            '/ddns/update?hostname=admin-test.zone1.tld&myip=203.0.113.1',
            **headers
        )
        
        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertIn('good', result['detail'])
        
        # Admin should be able to update zone3 (owned by admin)
        response = self.client.get(
            '/ddns/update?hostname=admin-test.zone3.tld&myip=203.0.113.2',
            **headers
        )
        
        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertIn('good', result['detail'])
        
    def test_group_member_can_update(self):
        """Test user can access zone via group membership."""
        credentials = base64.b64encode(b'user1:user1_pass').decode()
        headers = {'HTTP_AUTHORIZATION': f'Basic {credentials}'}
        
        # user1 is in group1, zone2 is owned by admin but group1 has access
        response = self.client.get(
            '/ddns/update?hostname=group-access.zone2.tld&myip=198.51.100.1',
            **headers
        )
        
        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertIn('good', result['detail'])
        self.assertIn('198.51.100.1', result['detail'])
        
        # Verify record was created
        a_record = A.objects.filter(label='group-access', zone=self.zone2).first()
        self.assertIsNotNone(a_record)
        self.assertEqual(a_record.value, '198.51.100.1')
        
    def test_unauthorized_zone_access_fails(self):
        """Test user cannot access zones they don't own and aren't in group for."""
        # user1 should not be able to access zone3 (owned by admin, no group access)
        credentials = base64.b64encode(b'user1:user1_pass').decode()
        headers = {'HTTP_AUTHORIZATION': f'Basic {credentials}'}
        
        response = self.client.get(
            '/ddns/update?hostname=unauthorized.zone3.tld&myip=192.168.1.100',
            **headers
        )
        
        self.assertEqual(response.status_code, 401)
        result = response.json()
        self.assertIn('badauth', result['detail'])
        
        # user2 (not in any group) should not access zone2
        credentials = base64.b64encode(b'user2:user2_pass').decode()
        headers = {'HTTP_AUTHORIZATION': f'Basic {credentials}'}
        
        response = self.client.get(
            '/ddns/update?hostname=unauthorized.zone2.tld&myip=192.168.1.101',
            **headers
        )
        
        self.assertEqual(response.status_code, 401)
        result = response.json()
        self.assertIn('badauth', result['detail'])
        
    def test_ddns_ipv4_and_ipv6_updates(self):
        """Test DDNS updates work with both IPv4 and IPv6 addresses."""
        credentials = base64.b64encode(b'user1:user1_pass').decode()
        headers = {'HTTP_AUTHORIZATION': f'Basic {credentials}'}
        
        # Test IPv4
        response = self.client.get(
            '/ddns/update?hostname=ipv4test.zone1.tld&myip=192.0.2.100',
            **headers
        )
        
        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertIn('good', result['detail'])
        self.assertIn('192.0.2.100', result['detail'])
        
        # Test IPv6
        response = self.client.get(
            '/ddns/update?hostname=ipv6test.zone1.tld&myip=2001:db8::42',
            **headers
        )
        
        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertIn('good', result['detail'])
        self.assertIn('2001:db8::42', result['detail'])
        
        # Verify both records were created
        a_record = A.objects.filter(label='ipv4test', zone=self.zone1).first()
        self.assertIsNotNone(a_record)
        self.assertEqual(a_record.value, '192.0.2.100')
        
        aaaa_record = AAAA.objects.filter(label='ipv6test', zone=self.zone1).first()
        self.assertIsNotNone(aaaa_record)
        self.assertEqual(aaaa_record.value, '2001:db8::42')
        
    def test_ddns_record_replacement(self):
        """Test that DDNS updates replace existing records."""
        credentials = base64.b64encode(b'user1:user1_pass').decode()
        headers = {'HTTP_AUTHORIZATION': f'Basic {credentials}'}
        
        # Create initial record
        response = self.client.get(
            '/ddns/update?hostname=replace.zone1.tld&myip=192.0.2.1',
            **headers
        )
        
        self.assertEqual(response.status_code, 200)
        self.assertIn('192.0.2.1', response.json()['detail'])
        
        # Update the same hostname with different IP
        response = self.client.get(
            '/ddns/update?hostname=replace.zone1.tld&myip=192.0.2.2',
            **headers
        )
        
        self.assertEqual(response.status_code, 200)
        self.assertIn('192.0.2.2', response.json()['detail'])
        
        # Verify only the new record exists
        a_records = A.objects.filter(label='replace', zone=self.zone1)
        self.assertEqual(a_records.count(), 1)
        self.assertEqual(a_records.first().value, '192.0.2.2')
        
    def test_ddns_noop_when_ip_unchanged(self):
        """Test that DDNS returns noop when IP is already correct."""
        credentials = base64.b64encode(b'user1:user1_pass').decode()
        headers = {'HTTP_AUTHORIZATION': f'Basic {credentials}'}
        
        # Create initial record
        response = self.client.get(
            '/ddns/update?hostname=noop.zone1.tld&myip=192.0.2.50',
            **headers
        )
        
        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertIn('good', result['detail'])
        
        # Get the zone serial after first update
        self.zone1.refresh_from_db()
        serial_after_update = self.zone1.soa_serial
        
        # Try to update with same IP - should be noop
        response = self.client.get(
            '/ddns/update?hostname=noop.zone1.tld&myip=192.0.2.50',
            **headers
        )
        
        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertIn('nochg', result['detail'])
        
        # Verify serial number didn't change for noop
        self.zone1.refresh_from_db()
        self.assertEqual(self.zone1.soa_serial, serial_after_update)
        
    def test_invalid_ip_address(self):
        """Test DDNS update fails with invalid IP address."""
        credentials = base64.b64encode(b'user1:user1_pass').decode()
        headers = {'HTTP_AUTHORIZATION': f'Basic {credentials}'}
        
        response = self.client.get(
            '/ddns/update?hostname=test.zone1.tld&myip=not.an.ip.address',
            **headers
        )
        
        self.assertEqual(response.status_code, 400)
        result = response.json()
        self.assertIn('notfqdn', result['detail'])
        
    def test_zone_not_found(self):
        """Test DDNS update fails when zone is not found."""
        credentials = base64.b64encode(b'user1:user1_pass').decode()
        headers = {'HTTP_AUTHORIZATION': f'Basic {credentials}'}
        
        response = self.client.get(
            '/ddns/update?hostname=test.nonexistent.zone&myip=192.168.1.1',
            **headers
        )
        
        self.assertEqual(response.status_code, 404)
        result = response.json()
        self.assertIn('nohost', result['detail'])
        
    def test_user_label_authorization(self):
        """Test UserLabelAuthorization allows specific label patterns."""
        # Create UserLabelAuthorization: user2 can access labels matching "special-.*" pattern in zone3
        UserLabelAuthorization.objects.create(
            user=self.user2,
            zone=self.zone3,
            label_pattern='special-.*'
        )
        
        credentials = base64.b64encode(b'user2:user2_pass').decode()
        headers = {'HTTP_AUTHORIZATION': f'Basic {credentials}'}
        
        # user2 should be able to access zone3 with matching pattern
        response = self.client.get(
            '/ddns/update?hostname=special-label.zone3.tld&myip=203.0.113.100',
            **headers
        )
        
        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertIn('good', result['detail'])
        
        # user2 should NOT be able to access zone3 with non-matching pattern
        response = self.client.get(
            '/ddns/update?hostname=regular-label.zone3.tld&myip=203.0.113.101',
            **headers
        )
        
        self.assertEqual(response.status_code, 401)
        result = response.json()
        self.assertIn('badauth', result['detail'])
        
    def test_missing_hostname_parameter(self):
        """Test DDNS update fails when hostname parameter is missing."""
        credentials = base64.b64encode(b'user1:user1_pass').decode()
        headers = {'HTTP_AUTHORIZATION': f'Basic {credentials}'}
        
        response = self.client.get(
            '/ddns/update?myip=192.168.1.1',
            **headers
        )
        
        self.assertEqual(response.status_code, 400)
        result = response.json()
        self.assertIn('notfqdn', result['detail'])
        
    def test_ddns_deletion_with_empty_myip(self):
        """Test DDNS deletion by providing empty myip parameter."""
        credentials = base64.b64encode(b'user1:user1_pass').decode()
        headers = {'HTTP_AUTHORIZATION': f'Basic {credentials}'}
        
        # First create some records
        A.objects.create(zone=self.zone1, label='delete-test', value='1.2.3.4')
        AAAA.objects.create(zone=self.zone1, label='delete-test', value='2001:db8::1')
        
        # Delete records with empty myip
        response = self.client.get(
            '/ddns/update?hostname=delete-test.zone1.tld&myip=',
            **headers
        )
        
        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertIn('good', result['detail'])
        self.assertIn('Deleted 2 records', result['detail'])
        
        # Verify records were deleted
        self.assertEqual(A.objects.filter(label='delete-test', zone=self.zone1).count(), 0)
        self.assertEqual(AAAA.objects.filter(label='delete-test', zone=self.zone1).count(), 0)
        
    def test_passkey_user_basic_auth_rejected(self):
        """Test that users with PassKey enabled cannot use basic auth.""" 
        # Create a PassKey for user1
        UserPassKey.objects.create(
            user=self.user1,
            credential_id='test_cred_id',
            public_key='test_public_key',
            name='Test PassKey'
        )
        
        # Basic auth should be rejected
        credentials = base64.b64encode(b'user1:user1_pass').decode()
        headers = {'HTTP_AUTHORIZATION': f'Basic {credentials}'}
        
        response = self.client.get(
            '/ddns/update?hostname=test.zone1.tld&myip=192.168.1.1',
            **headers
        )
        
        self.assertEqual(response.status_code, 401)
        result = response.json()
        self.assertIn('badauth', result['detail'])
        self.assertIn('PassKey', result['detail'])
        
        # But bearer token should still work
        headers = {'HTTP_AUTHORIZATION': f'Bearer {self.user1_token_str}'}
        
        response = self.client.get(
            '/ddns/update?hostname=testpasskey.zone1.tld&myip=192.168.1.20',
            **headers
        )
        
        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertIn('good', result['detail'])