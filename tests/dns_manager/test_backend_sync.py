"""
Tests for backend synchronization functionality.

Tests the complete sync workflow including:
- Mock backend HTTP server
- Zone content sync
- Server config sync  
- Background sync service
"""
import pytest
import threading
import time
import json
from unittest.mock import patch, MagicMock
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from datetime import datetime, timezone

from django.test import TestCase, override_settings
from django.contrib.auth import get_user_model

from dns_manager.models import (
    Server, MasterZone, A, AAAA, NS, Group, UserGroup
)
from dns_manager.backend import update_zone, update_config
from dns_manager.sync import generate_bind_zone_content, generate_knot_config_content
from dns_manager.sync import BackgroundSyncService, get_sync_service


class MockBackendHandler(BaseHTTPRequestHandler):
    """Mock HTTP handler for backend DNS server API."""
    
    # Class variables to track requests
    requests_log = []
    zone_writes = {}
    config_writes = {}
    
    def log_message(self, format, *args):
        """Suppress default logging to avoid test output noise."""
        pass
    
    def do_POST(self):
        """Handle POST requests (zonewrite, configwrite)."""
        path = self.path
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8')
        
        # Check authorization header
        auth_header = self.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            self.send_response(401)
            self.end_headers()
            self.wfile.write(b'Unauthorized')
            return
            
        api_key = auth_header[7:]  # Remove 'Bearer ' prefix
        
        # Log the request
        MockBackendHandler.requests_log.append({
            'method': 'POST',
            'path': path,
            'auth': api_key,
            'body': body,
            'timestamp': datetime.now(timezone.utc)
        })
        
        if path.startswith('/zonewrite'):
            # Parse zone name from query parameters
            parsed = urlparse(path)
            query_params = parse_qs(parsed.query)
            zone_name = query_params.get('zonename', ['unknown'])[0]
            
            # Store zone content
            MockBackendHandler.zone_writes[zone_name] = {
                'content': body,
                'api_key': api_key,
                'timestamp': datetime.now(timezone.utc)
            }
            
            self.send_response(200)
            self.end_headers()
            self.wfile.write(f'Zone {zone_name} written successfully'.encode())
            
        elif path.startswith('/configwrite'):
            # Store config content
            MockBackendHandler.config_writes[api_key] = {
                'content': body,
                'timestamp': datetime.now(timezone.utc)
            }
            
            self.send_response(200)  
            self.end_headers()
            self.wfile.write(b'Config written successfully')
            
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'Not Found')
    
    def do_GET(self):
        """Handle GET requests (zonereload, configreload)."""
        path = self.path
        
        # Check authorization header
        auth_header = self.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            self.send_response(401)
            self.end_headers() 
            self.wfile.write(b'Unauthorized')
            return
            
        api_key = auth_header[7:]  # Remove 'Bearer ' prefix
        
        # Log the request
        MockBackendHandler.requests_log.append({
            'method': 'GET',
            'path': path,
            'auth': api_key,
            'timestamp': datetime.now(timezone.utc)
        })
        
        if path.startswith('/zonereload'):
            # Parse zone name from query parameters
            parsed = urlparse(path)
            query_params = parse_qs(parsed.query)
            zone_name = query_params.get('zonename', ['unknown'])[0]
            
            self.send_response(200)
            self.end_headers()
            self.wfile.write(f'Zone {zone_name} reloaded successfully'.encode())
            
        elif path.startswith('/configreload'):
            self.send_response(200)
            self.end_headers() 
            self.wfile.write(b'Config reloaded successfully')
            
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'Not Found')
    
    @classmethod
    def reset(cls):
        """Reset all stored data."""
        cls.requests_log = []
        cls.zone_writes = {}
        cls.config_writes = {}


class MockBackendServer:
    """Mock backend server for testing."""
    
    def __init__(self, port=0):
        self.server = HTTPServer(('127.0.0.1', port), MockBackendHandler)
        self.port = self.server.server_address[1]
        self.thread = None
        
    def start(self):
        """Start the mock server in a background thread."""
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        # Give the server a moment to start
        time.sleep(0.1)
        
    def stop(self):
        """Stop the mock server."""
        if self.server:
            self.server.shutdown()
            self.server.server_close()
        if self.thread:
            self.thread.join(timeout=1)
    
    @property
    def url(self):
        """Get the base URL of the mock server."""
        return f'http://127.0.0.1:{self.port}'


@override_settings(
    TESTING=True,
    DISABLE_BACKEND_SYNC=True,  # Disable auto-start, we'll start manually
    BACKEND_SYNC_PERIOD=1,      # Fast sync for testing
    BACKEND_SYNC_DELAY=0.1      # Fast delay for testing
)
class BackendSyncTestCase(TestCase):
    """Test cases for backend synchronization."""
    
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        # Start mock backend server
        cls.mock_server = MockBackendServer()
        cls.mock_server.start()
        
    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        # Stop mock backend server
        cls.mock_server.stop()
    
    def setUp(self):
        """Set up test data."""
        # Reset mock server data
        MockBackendHandler.reset()
        
        # Create test user and group
        User = get_user_model()
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123',
            email='test@example.com'
        )
        
        self.group = Group.objects.create(name='testgroup')
        UserGroup.objects.create(user=self.user, group=self.group)
        
        # Create test server pointing to mock backend
        self.server = Server.objects.create(
            name='Test Server',
            api_url=self.mock_server.url,
            api_key='test-api-key-12345',
            master_template='t_master',
            slave_template='t_slave',
            owner=self.user,
            group=self.group,
            is_active=True,
            config_dirty=False  # Start clean
        )
        
        # Create test zone
        self.zone = MasterZone.objects.create(
            origin='example.com.',
            master_server=self.server,
            owner=self.user,
            group=self.group,
            
            # SOA record fields
            soa_name='@',
            soa_ttl=3600,
            soa_mname='ns1.example.com.',
            soa_rname='admin.example.com.',
            soa_serial=2024091101,
            soa_refresh=3600,
            soa_retry=1800,
            soa_expire=604800,
            soa_minimum=86400,
            
            content_dirty=False  # Start clean
        )
        
        # Create some DNS records
        A.objects.create(
            zone=self.zone,
            label='@',
            ttl=3600,
            value='192.0.2.1'
        )
        
        A.objects.create(
            zone=self.zone,
            label='www',
            ttl=3600,
            value='192.0.2.2'
        )
        
        AAAA.objects.create(
            zone=self.zone,
            label='@',
            ttl=3600,
            value='2001:db8::1'
        )
        
        NS.objects.create(
            zone=self.zone,
            label='@',
            ttl=3600,
            value='ns1.example.com.'
        )
    
    def test_generate_bind_zone_content(self):
        """Test BIND zone file generation."""
        zone_content = generate_bind_zone_content(self.zone)
        
        # Check that zone content contains expected elements
        self.assertIn('$ORIGIN example.com.', zone_content)
        self.assertIn('$TTL 3600', zone_content)
        self.assertIn('SOA ns1.example.com. admin.example.com.', zone_content)
        self.assertIn('192.0.2.1', zone_content)
        self.assertIn('192.0.2.2', zone_content) 
        self.assertIn('2001:db8::1', zone_content)
        self.assertIn('ns1.example.com.', zone_content)
        
    def test_generate_knot_config_content(self):
        """Test Knot DNS config generation."""
        config_content = generate_knot_config_content(self.server)
        
        # Check that config contains expected elements
        self.assertIn('zone:', config_content)
        self.assertIn('domain: example.com.', config_content)
        self.assertIn('template: t_master', config_content)
        self.assertIn('file: example.com.zone', config_content)
    
    def test_update_zone_direct(self):
        """Test direct zone update to mock backend."""
        zone_name = 'example.com'
        zone_data = generate_bind_zone_content(self.zone)
        
        # Call update_zone directly
        update_zone(zone_name, zone_data, self.mock_server.url, 'test-api-key-12345')
        
        # Check that requests were made to mock server
        self.assertEqual(len(MockBackendHandler.requests_log), 2)  # POST + GET
        
        # Check zone write request
        zone_write_req = MockBackendHandler.requests_log[0]
        self.assertEqual(zone_write_req['method'], 'POST')
        self.assertIn('/zonewrite', zone_write_req['path'])
        self.assertEqual(zone_write_req['auth'], 'test-api-key-12345')
        self.assertIn('$ORIGIN example.com.', zone_write_req['body'])
        
        # Check zone reload request
        zone_reload_req = MockBackendHandler.requests_log[1]
        self.assertEqual(zone_reload_req['method'], 'GET')
        self.assertIn('/zonereload', zone_reload_req['path'])
        self.assertEqual(zone_reload_req['auth'], 'test-api-key-12345')
        
        # Check zone data was stored
        self.assertIn('example.com', MockBackendHandler.zone_writes)
        stored_zone = MockBackendHandler.zone_writes['example.com']
        self.assertEqual(stored_zone['api_key'], 'test-api-key-12345')
        self.assertIn('$ORIGIN example.com.', stored_zone['content'])
    
    def test_update_config_direct(self):
        """Test direct config update to mock backend."""
        config_data = generate_knot_config_content(self.server)
        
        # Call update_config directly
        update_config(config_data, self.mock_server.url, 'test-api-key-12345')
        
        # Check that requests were made to mock server
        self.assertEqual(len(MockBackendHandler.requests_log), 2)  # POST + GET
        
        # Check config write request
        config_write_req = MockBackendHandler.requests_log[0]
        self.assertEqual(config_write_req['method'], 'POST')
        self.assertIn('/configwrite', config_write_req['path'])
        self.assertEqual(config_write_req['auth'], 'test-api-key-12345')
        self.assertIn('domain: example.com.', config_write_req['body'])
        
        # Check config reload request  
        config_reload_req = MockBackendHandler.requests_log[1]
        self.assertEqual(config_reload_req['method'], 'GET')
        self.assertIn('/configreload', config_reload_req['path'])
        self.assertEqual(config_reload_req['auth'], 'test-api-key-12345')
        
        # Check config data was stored
        self.assertIn('test-api-key-12345', MockBackendHandler.config_writes)
        stored_config = MockBackendHandler.config_writes['test-api-key-12345']
        self.assertIn('domain: example.com.', stored_config['content'])


@override_settings(
    TESTING=True,
    DISABLE_BACKEND_SYNC=True,  # Disable auto-start, we'll start manually
    BACKEND_SYNC_PERIOD=0.5,    # Very fast sync for testing
    BACKEND_SYNC_DELAY=0.1      # Very fast delay for testing
)
class BackgroundSyncIntegrationTestCase(TestCase):
    """Integration tests for background sync service."""
    
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        # Start mock backend server
        cls.mock_server = MockBackendServer()
        cls.mock_server.start()
        
    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        # Stop mock backend server
        cls.mock_server.stop()
    
    def setUp(self):
        """Set up test data."""
        # Reset mock server data
        MockBackendHandler.reset()
        
        # Create test user and group
        User = get_user_model()
        self.user = User.objects.create_user(
            username='testuser',
            password='testpass123', 
            email='test@example.com'
        )
        
        self.group = Group.objects.create(name='testgroup')
        UserGroup.objects.create(user=self.user, group=self.group)
    
    def test_zone_sync_via_sync_iteration(self):
        """Test that dirty zones get synced via direct sync iteration call."""
        # Create server and zone
        server = Server.objects.create(
            name='Test Server',
            api_url=self.mock_server.url,
            api_key='zone-sync-key-123',
            master_template='t_master',
            slave_template='t_slave', 
            owner=self.user,
            group=self.group,
            is_active=True,
            config_dirty=False
        )
        
        zone = MasterZone.objects.create(
            origin='sync-test.com.',
            master_server=server,
            owner=self.user,
            group=self.group,
            
            # SOA record fields
            soa_name='@',
            soa_ttl=3600,
            soa_mname='ns1.sync-test.com.',
            soa_rname='admin.sync-test.com.',
            soa_serial=2024091101,
            soa_refresh=3600,
            soa_retry=1800,
            soa_expire=604800,
            soa_minimum=86400,
            
            content_dirty=True  # Mark as dirty for sync
        )
        
        # Add some DNS records
        A.objects.create(zone=zone, label='@', ttl=300, value='192.0.2.100')
        A.objects.create(zone=zone, label='test', ttl=300, value='192.0.2.101')
        
        # Create sync service and call sync iteration directly
        sync_service = BackgroundSyncService(sync_period=0.5, sync_delay=0.1)
        
        # Call the sync iteration method directly (synchronously)
        sync_service._do_sync_iteration()
        
        # Check that zone was synced
        zone.refresh_from_db()
        self.assertFalse(zone.content_dirty, "Zone should no longer be dirty after sync")
        self.assertIsNotNone(zone.last_content_sync, "Zone should have last_content_sync timestamp")
        
        # Check that requests were made to mock server
        self.assertGreaterEqual(len(MockBackendHandler.requests_log), 2, "Should have zone write + reload requests")
        
        # Find zone write request
        zone_write_requests = [r for r in MockBackendHandler.requests_log 
                             if r['method'] == 'POST' and '/zonewrite' in r['path']]
        self.assertEqual(len(zone_write_requests), 1, "Should have exactly one zone write request")
        
        zone_write_req = zone_write_requests[0]
        self.assertEqual(zone_write_req['auth'], 'zone-sync-key-123')
        self.assertIn('$ORIGIN sync-test.com.', zone_write_req['body'])
        self.assertIn('192.0.2.100', zone_write_req['body'])
        self.assertIn('192.0.2.101', zone_write_req['body'])
        
        # Check zone data was stored in mock server
        self.assertIn('sync-test.com', MockBackendHandler.zone_writes)
        stored_zone = MockBackendHandler.zone_writes['sync-test.com']
        self.assertEqual(stored_zone['api_key'], 'zone-sync-key-123')
    
    def test_server_config_sync_via_sync_iteration(self):
        """Test that dirty server configs get synced via direct sync iteration call."""
        # Create server with config_dirty=True
        server = Server.objects.create(
            name='Config Test Server',
            api_url=self.mock_server.url,
            api_key='config-sync-key-456',
            master_template='t_master_custom',
            slave_template='t_slave_custom',
            owner=self.user,
            group=self.group,
            is_active=True,
            config_dirty=True  # Mark as dirty for sync
        )
        
        # Create a zone to generate config content
        MasterZone.objects.create(
            origin='config-test.org.',
            master_server=server,
            owner=self.user,
            group=self.group,
            
            # SOA record fields
            soa_name='@',
            soa_ttl=3600,
            soa_mname='ns1.config-test.org.',
            soa_rname='admin.config-test.org.',
            soa_serial=2024091102,
            soa_refresh=7200,
            soa_retry=3600,
            soa_expire=1209600,
            soa_minimum=172800,
            
            content_dirty=False  # Don't sync zone, just server config
        )
        
        # Create sync service and call sync iteration directly
        sync_service = BackgroundSyncService(sync_period=0.5, sync_delay=0.1)
        
        # Call the sync iteration method directly (synchronously)
        sync_service._do_sync_iteration()
        
        # Check that server was synced
        server.refresh_from_db()
        self.assertFalse(server.config_dirty, "Server should no longer be dirty after sync")
        self.assertIsNotNone(server.last_config_sync, "Server should have last_config_sync timestamp")
        
        # Check that requests were made to mock server
        self.assertGreaterEqual(len(MockBackendHandler.requests_log), 2, "Should have config write + reload requests")
        
        # Find config write request
        config_write_requests = [r for r in MockBackendHandler.requests_log 
                               if r['method'] == 'POST' and '/configwrite' in r['path']]
        self.assertEqual(len(config_write_requests), 1, "Should have exactly one config write request")
        
        config_write_req = config_write_requests[0]
        self.assertEqual(config_write_req['auth'], 'config-sync-key-456')
        self.assertIn('domain: config-test.org.', config_write_req['body'])
        self.assertIn('template: t_master_custom', config_write_req['body'])
        
        # Check config data was stored in mock server
        self.assertIn('config-sync-key-456', MockBackendHandler.config_writes)
        stored_config = MockBackendHandler.config_writes['config-sync-key-456']
        self.assertIn('domain: config-test.org.', stored_config['content'])
    
    def test_mixed_zone_and_config_sync_via_sync_iteration(self):
        """Test syncing both zones and server configs together via direct sync iteration call."""
        # Create server with config_dirty=True
        server = Server.objects.create(
            name='Mixed Test Server', 
            api_url=self.mock_server.url,
            api_key='mixed-sync-key-789',
            master_template='t_master_mixed',
            slave_template='t_slave_mixed',
            owner=self.user,
            group=self.group,
            is_active=True,
            config_dirty=True
        )
        
        # Create zone with content_dirty=True
        zone = MasterZone.objects.create(
            origin='mixed-test.net.',
            master_server=server,
            owner=self.user,
            group=self.group,
            
            # SOA record fields
            soa_name='@',
            soa_ttl=7200,
            soa_mname='ns1.mixed-test.net.',
            soa_rname='admin.mixed-test.net.',
            soa_serial=2024091103,
            soa_refresh=3600,
            soa_retry=1800,
            soa_expire=604800,
            soa_minimum=86400,
            
            content_dirty=True
        )
        
        # Add DNS record
        A.objects.create(zone=zone, label='mixed', ttl=600, value='192.0.2.200')
        
        # Create sync service and call sync iteration directly
        sync_service = BackgroundSyncService(sync_period=0.5, sync_delay=0.1)
        
        # Call the sync iteration method directly (synchronously)
        sync_service._do_sync_iteration()
        
        # Check both were synced
        server.refresh_from_db()
        zone.refresh_from_db()
        
        self.assertFalse(server.config_dirty, "Server should no longer be dirty")
        self.assertFalse(zone.content_dirty, "Zone should no longer be dirty")
        self.assertIsNotNone(server.last_config_sync, "Server should have sync timestamp")
        self.assertIsNotNone(zone.last_content_sync, "Zone should have sync timestamp")
        
        # Check both types of requests were made
        zone_write_requests = [r for r in MockBackendHandler.requests_log 
                             if r['method'] == 'POST' and '/zonewrite' in r['path']]
        config_write_requests = [r for r in MockBackendHandler.requests_log 
                               if r['method'] == 'POST' and '/configwrite' in r['path']]
        
        self.assertEqual(len(zone_write_requests), 1, "Should have zone write request")
        self.assertEqual(len(config_write_requests), 1, "Should have config write request")
        
        # Verify both auth keys match
        self.assertEqual(zone_write_requests[0]['auth'], 'mixed-sync-key-789')
        self.assertEqual(config_write_requests[0]['auth'], 'mixed-sync-key-789')
        
        # Verify content was stored
        self.assertIn('mixed-test.net', MockBackendHandler.zone_writes)
        self.assertIn('mixed-sync-key-789', MockBackendHandler.config_writes)