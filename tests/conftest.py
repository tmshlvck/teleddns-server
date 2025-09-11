"""
Global pytest configuration and fixtures for TeleDDNS Server tests.
"""
import pytest
import os
import django
from django.conf import settings

# Configure Django settings
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'teleddns_server.settings')
django.setup()

from django.contrib.auth import get_user_model
from dns_manager.models import (
    Group, Server, MasterZone, 
    A, AAAA, NS, PTR, CNAME, TXT, CAA, MX, SRV, SSHFP, TLSA, DNSKEY, DS, NAPTR
)

User = get_user_model()


@pytest.fixture
def user1(db):
    """Create a test user with username 'user1' and password 'testpass123'."""
    return User.objects.create_user(
        username='user1',
        email='user1@example.com',
        password='testpass123',
        first_name='Test',
        last_name='User',
        last_update_metadata='Created by pytest fixture'
    )


@pytest.fixture 
def user2(db):
    """Create a second test user."""
    return User.objects.create_user(
        username='user2',
        email='user2@example.com',
        password='testpass456',
        first_name='Another',
        last_name='User',
        last_update_metadata='Created by pytest fixture'
    )


@pytest.fixture
def admin_user(db):
    """Create an admin user."""
    return User.objects.create_superuser(
        username='admin',
        email='admin@example.com',
        password='admin123',
        last_update_metadata='Created by pytest fixture'
    )


@pytest.fixture
def group1(db, user1):
    """Create a test group with user1 as member."""
    group = Group.objects.create(
        name='group1',
        description='Test group 1',
        last_update_metadata='Created by pytest fixture'
    )
    group.users.add(user1)
    return group


@pytest.fixture
def server1(db, user1, group1):
    """Create a test DNS server."""
    return Server.objects.create(
        name='Test Server 1',
        api_url='http://localhost:8586',
        api_key='test-api-key-123',
        master_template='''
zone "{{ zone.origin }}" {
    type master;
    file "/var/lib/knot/{{ zone.origin }}zone";
    notify yes;
    also-notify { {{ slave_servers|join:", " }}; };
};
        '''.strip(),
        slave_template='''
zone "{{ zone.origin }}" {
    type slave;
    masters { {{ master_server }}; };
    file "/var/lib/knot/slave/{{ zone.origin }}zone";
};
        '''.strip(),
        owner=user1,
        group=group1,
        last_update_metadata='Created by pytest fixture'
    )


@pytest.fixture
def zone1_tld(db, user1, group1, server1):
    """Create zone1.tld with SOA record."""
    return MasterZone.objects.create(
        origin='zone1.tld.',
        soa_name='@',
        soa_serial=2024091101,
        soa_mname='ns1.zone1.tld.',
        soa_rname='admin.zone1.tld.',
        soa_refresh=3600,
        soa_retry=1800,
        soa_expire=1209600,
        soa_minimum=86400,
        owner=user1,
        group=group1,
        master_server=server1,
        last_update_metadata='Created by pytest fixture'
    )


@pytest.fixture
def dns_records(db, zone1_tld):
    """Create comprehensive DNS records in zone1.tld."""
    records = {}
    
    # A records
    records['a1'] = A.objects.create(
        zone=zone1_tld,
        label='arr1',
        value='1.2.3.4',
        ttl=3600,
        last_update_metadata='Created by pytest fixture'
    )
    
    records['a2'] = A.objects.create(
        zone=zone1_tld,
        label='@',
        value='192.0.2.1',
        ttl=3600,
        last_update_metadata='Created by pytest fixture'
    )
    
    # AAAA records
    records['aaaa1'] = AAAA.objects.create(
        zone=zone1_tld,
        label='ipv6',
        value='2001:db8::1',
        ttl=3600,
        last_update_metadata='Created by pytest fixture'
    )
    
    records['aaaa2'] = AAAA.objects.create(
        zone=zone1_tld,
        label='@',
        value='2001:db8::100',
        ttl=3600,
        last_update_metadata='Created by pytest fixture'
    )
    
    # NS records
    records['ns1'] = NS.objects.create(
        zone=zone1_tld,
        label='@',
        value='ns1.zone1.tld.',
        ttl=86400,
        last_update_metadata='Created by pytest fixture'
    )
    
    records['ns2'] = NS.objects.create(
        zone=zone1_tld,
        label='@',
        value='ns2.zone1.tld.',
        ttl=86400,
        last_update_metadata='Created by pytest fixture'
    )
    
    # PTR record
    records['ptr1'] = PTR.objects.create(
        zone=zone1_tld,
        label='ptr1',
        value='arr1.zone1.tld.',
        ttl=3600,
        last_update_metadata='Created by pytest fixture'
    )
    
    # CNAME record
    records['cname1'] = CNAME.objects.create(
        zone=zone1_tld,
        label='www',
        value='zone1.tld.',
        ttl=3600,
        last_update_metadata='Created by pytest fixture'
    )
    
    # TXT records
    records['txt1'] = TXT.objects.create(
        zone=zone1_tld,
        label='_test',
        value='v=test123',
        ttl=3600,
        last_update_metadata='Created by pytest fixture'
    )
    
    records['txt_spf'] = TXT.objects.create(
        zone=zone1_tld,
        label='@',
        value='v=spf1 include:_spf.google.com ~all',
        ttl=3600,
        last_update_metadata='Created by pytest fixture'
    )
    
    # CAA record
    records['caa1'] = CAA.objects.create(
        zone=zone1_tld,
        label='@',
        value='letsencrypt.org',
        flag=0,
        tag='issue',
        ttl=3600,
        last_update_metadata='Created by pytest fixture'
    )
    
    # MX records
    records['mx1'] = MX.objects.create(
        zone=zone1_tld,
        label='@',
        value='mail1.zone1.tld.',
        priority=10,
        ttl=3600,
        last_update_metadata='Created by pytest fixture'
    )
    
    records['mx2'] = MX.objects.create(
        zone=zone1_tld,
        label='@',
        value='mail2.zone1.tld.',
        priority=20,
        ttl=3600,
        last_update_metadata='Created by pytest fixture'
    )
    
    # SRV records
    records['srv1'] = SRV.objects.create(
        zone=zone1_tld,
        label='_sip._tcp',
        value='sip.zone1.tld.',
        priority=10,
        weight=50,
        port=5060,
        ttl=3600,
        last_update_metadata='Created by pytest fixture'
    )
    
    records['srv2'] = SRV.objects.create(
        zone=zone1_tld,
        label='_http._tcp',
        value='web.zone1.tld.',
        priority=0,
        weight=10,
        port=80,
        ttl=3600,
        last_update_metadata='Created by pytest fixture'
    )
    
    # SSHFP record
    records['sshfp1'] = SSHFP.objects.create(
        zone=zone1_tld,
        label='ssh',
        algorithm=1,  # RSA
        hash_type=1,  # SHA-1
        fingerprint='123456789abcdef0123456789abcdef012345678',
        ttl=3600,
        last_update_metadata='Created by pytest fixture'
    )
    
    # TLSA record
    records['tlsa1'] = TLSA.objects.create(
        zone=zone1_tld,
        label='_443._tcp',
        cert_usage=3,
        selector=1,
        matching_type=1,
        cert_data='abcdef123456789abcdef123456789abcdef123456789abcdef',
        ttl=3600,
        last_update_metadata='Created by pytest fixture'
    )
    
    # DNSKEY record
    records['dnskey1'] = DNSKEY.objects.create(
        zone=zone1_tld,
        label='@',
        flags=257,
        protocol=3,
        algorithm=8,
        public_key='AwEAAcGQHOeU0WOgVGGb/1EfXrKvwUw4VF/DllSJ0fH2KpQZ1ZGKb7RfCfJxg',
        ttl=86400,
        last_update_metadata='Created by pytest fixture'
    )
    
    # DS record
    records['ds1'] = DS.objects.create(
        zone=zone1_tld,
        label='subdomain',
        key_tag=12345,
        algorithm=8,
        digest_type=2,
        digest='abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef',
        ttl=86400,
        last_update_metadata='Created by pytest fixture'
    )
    
    # NAPTR record
    records['naptr1'] = NAPTR.objects.create(
        zone=zone1_tld,
        label='@',
        order=100,
        preference=50,
        flags='u',
        service='E2U+sip',
        regexp='!^.*$!sip:info@zone1.tld!',
        replacement='.',
        ttl=3600,
        last_update_metadata='Created by pytest fixture'
    )
    
    return records


@pytest.fixture
def complete_test_data(db, user1, user2, admin_user, group1, server1, zone1_tld, dns_records):
    """Complete test dataset with all fixtures combined."""
    return {
        'users': {
            'user1': user1,
            'user2': user2,
            'admin': admin_user,
        },
        'groups': {
            'group1': group1,
        },
        'servers': {
            'server1': server1,
        },
        'zones': {
            'zone1_tld': zone1_tld,
        },
        'records': dns_records,
    }