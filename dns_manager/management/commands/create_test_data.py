"""
Django management command to create synthetic test data for TeleDDNS Server.

This command creates the same comprehensive test dataset that pytest fixtures generate,
but allows you to create it on demand in your development database.
"""
from django.core.management.base import BaseCommand, CommandError
from django.contrib.auth import get_user_model
from django.db import transaction
from dns_manager.models import (
    Group, Server, MasterZone,
    A, AAAA, NS, PTR, CNAME, TXT, CAA, MX, SRV, SSHFP, TLSA, DNSKEY, DS, NAPTR
)

User = get_user_model()


class Command(BaseCommand):
    help = 'Create comprehensive synthetic test data for development and testing'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--clear',
            action='store_true',
            help='Clear existing test data before creating new data',
        )
        parser.add_argument(
            '--zone',
            type=str,
            default='zone1.tld',
            help='Domain name for the test zone (default: zone1.tld)',
        )
        parser.add_argument(
            '--user',
            type=str,
            default='user1',
            help='Username for the test user (default: user1)',
        )
        parser.add_argument(
            '--password',
            type=str,
            default='testpass123',
            help='Password for the test user (default: testpass123)',
        )
        
    def handle(self, *args, **options):
        zone_name = options['zone']
        username = options['user']
        password = options['password']
        
        if not zone_name.endswith('.'):
            zone_name += '.'
            
        self.stdout.write(
            self.style.SUCCESS(f'Creating synthetic test data...')
        )
        
        try:
            with transaction.atomic():
                if options['clear']:
                    self.clear_test_data()
                    
                data = self.create_test_data(zone_name, username, password)
                self.print_summary(data, zone_name)
                
        except Exception as e:
            raise CommandError(f'Failed to create test data: {str(e)}')
            
    def clear_test_data(self):
        """Clear existing test data."""
        self.stdout.write('Clearing existing test data...')
        
        # Delete in order to avoid foreign key constraints
        for model in [A, AAAA, NS, PTR, CNAME, TXT, CAA, MX, SRV, SSHFP, TLSA, DNSKEY, DS, NAPTR]:
            count = model.objects.count()
            if count > 0:
                model.objects.all().delete()
                self.stdout.write(f'  Deleted {count} {model.__name__} records')
                
        MasterZone.objects.all().delete()
        Server.objects.all().delete()
        Group.objects.all().delete()
        
        # Don't delete superusers
        User.objects.filter(is_superuser=False).delete()
        
        self.stdout.write(self.style.SUCCESS('Test data cleared.'))
        
    def create_test_data(self, zone_name, username, password):
        """Create comprehensive test data."""
        data = {}
        
        # Create users
        self.stdout.write('Creating users...')
        user1, created = User.objects.get_or_create(
            username=username,
            defaults={
                'email': f'{username}@example.com',
                'first_name': 'Test',
                'last_name': 'User',
                'last_update_metadata': 'Created by create_test_data command'
            }
        )
        if created:
            user1.set_password(password)
            user1.save()
            
        user2, created = User.objects.get_or_create(
            username='user2',
            defaults={
                'email': 'user2@example.com',
                'first_name': 'Another',
                'last_name': 'User',
                'last_update_metadata': 'Created by create_test_data command'
            }
        )
        if created:
            user2.set_password('testpass456')
            user2.save()
            
        data['users'] = {'user1': user1, 'user2': user2}
        
        # Create group
        self.stdout.write('Creating group...')
        group1, created = Group.objects.get_or_create(
            name='group1',
            defaults={
                'description': 'Test group 1',
                'last_update_metadata': 'Created by create_test_data command'
            }
        )
        group1.users.add(user1)
        data['groups'] = {'group1': group1}
        
        # Create server
        self.stdout.write('Creating DNS server...')
        server1, created = Server.objects.get_or_create(
            name='Test Server 1',
            defaults={
                'api_url': 'http://localhost:8586',
                'api_key': 'test-api-key-123',
                'master_template': self.get_master_template(),
                'slave_template': self.get_slave_template(),
                'owner': user1,
                'group': group1,
                'last_update_metadata': 'Created by create_test_data command'
            }
        )
        data['servers'] = {'server1': server1}
        
        # Create zone
        self.stdout.write(f'Creating zone {zone_name}...')
        zone_origin = zone_name
        zone1, created = MasterZone.objects.get_or_create(
            origin=zone_origin,
            defaults={
                'soa_name': '@',
                'soa_serial': 2024091101,
                'soa_mname': f'ns1.{zone_name}',
                'soa_rname': f'admin.{zone_name}',
                'soa_refresh': 3600,
                'soa_retry': 1800,
                'soa_expire': 1209600,
                'soa_minimum': 86400,
                'owner': user1,
                'group': group1,
                'master_server': server1,
                'last_update_metadata': 'Created by create_test_data command'
            }
        )
        data['zones'] = {'zone1': zone1}
        
        # Create DNS records
        self.stdout.write('Creating DNS records...')
        records = self.create_dns_records(zone1)
        data['records'] = records
        
        return data
        
    def create_dns_records(self, zone):
        """Create comprehensive DNS records."""
        records = {}
        metadata = 'Created by create_test_data command'
        
        # A records
        records['a1'] = A.objects.create(
            zone=zone, label='arr1', value='1.2.3.4', 
            last_update_metadata=metadata
        )
        records['a2'] = A.objects.create(
            zone=zone, label='@', value='192.0.2.1',
            last_update_metadata=metadata
        )
        
        # AAAA records
        records['aaaa1'] = AAAA.objects.create(
            zone=zone, label='ipv6', value='2001:db8::1',
            last_update_metadata=metadata
        )
        records['aaaa2'] = AAAA.objects.create(
            zone=zone, label='@', value='2001:db8::100',
            last_update_metadata=metadata
        )
        
        # NS records
        records['ns1'] = NS.objects.create(
            zone=zone, label='@', value=f'ns1.{zone.origin}', ttl=86400,
            last_update_metadata=metadata
        )
        records['ns2'] = NS.objects.create(
            zone=zone, label='@', value=f'ns2.{zone.origin}', ttl=86400,
            last_update_metadata=metadata
        )
        
        # PTR record
        records['ptr1'] = PTR.objects.create(
            zone=zone, label='ptr1', value=f'arr1.{zone.origin}',
            last_update_metadata=metadata
        )
        
        # CNAME record
        records['cname1'] = CNAME.objects.create(
            zone=zone, label='www', value=zone.origin,
            last_update_metadata=metadata
        )
        
        # TXT records
        records['txt1'] = TXT.objects.create(
            zone=zone, label='_test', value='v=test123',
            last_update_metadata=metadata
        )
        records['txt_spf'] = TXT.objects.create(
            zone=zone, label='@', value='v=spf1 include:_spf.google.com ~all',
            last_update_metadata=metadata
        )
        
        # CAA record
        records['caa1'] = CAA.objects.create(
            zone=zone, label='@', value='letsencrypt.org',
            flag=0, tag='issue', last_update_metadata=metadata
        )
        
        # MX records
        records['mx1'] = MX.objects.create(
            zone=zone, label='@', value=f'mail1.{zone.origin}',
            priority=10, last_update_metadata=metadata
        )
        records['mx2'] = MX.objects.create(
            zone=zone, label='@', value=f'mail2.{zone.origin}',
            priority=20, last_update_metadata=metadata
        )
        
        # SRV records
        records['srv1'] = SRV.objects.create(
            zone=zone, label='_sip._tcp', value=f'sip.{zone.origin}',
            priority=10, weight=50, port=5060, last_update_metadata=metadata
        )
        records['srv2'] = SRV.objects.create(
            zone=zone, label='_http._tcp', value=f'web.{zone.origin}',
            priority=0, weight=10, port=80, last_update_metadata=metadata
        )
        
        # SSHFP record
        records['sshfp1'] = SSHFP.objects.create(
            zone=zone, label='ssh', algorithm=1, hash_type=1,
            fingerprint='123456789abcdef0123456789abcdef012345678',
            last_update_metadata=metadata
        )
        
        # TLSA record
        records['tlsa1'] = TLSA.objects.create(
            zone=zone, label='_443._tcp', cert_usage=3, selector=1, matching_type=1,
            cert_data='abcdef123456789abcdef123456789abcdef123456789abcdef',
            last_update_metadata=metadata
        )
        
        # DNSKEY record
        records['dnskey1'] = DNSKEY.objects.create(
            zone=zone, label='@', flags=257, protocol=3, algorithm=8,
            public_key='AwEAAcGQHOeU0WOgVGGb/1EfXrKvwUw4VF/DllSJ0fH2KpQZ1ZGKb7RfCfJxg',
            ttl=86400, last_update_metadata=metadata
        )
        
        # DS record
        records['ds1'] = DS.objects.create(
            zone=zone, label='subdomain', key_tag=12345, algorithm=8, digest_type=2,
            digest='abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef',
            ttl=86400, last_update_metadata=metadata
        )
        
        # NAPTR record
        records['naptr1'] = NAPTR.objects.create(
            zone=zone, label='@', order=100, preference=50, flags='u',
            service='E2U+sip', regexp='!^.*$!sip:info@{zone.origin[:-1]}!',
            replacement='.', last_update_metadata=metadata
        )
        
        return records
        
    def get_master_template(self):
        """Master server template."""
        return '''
zone "{{ zone.origin }}" {
    type master;
    file "/var/lib/knot/{{ zone.origin }}zone";
    notify yes;
    also-notify { {{ slave_servers|join:", " }}; };
};
        '''.strip()
        
    def get_slave_template(self):
        """Slave server template."""
        return '''
zone "{{ zone.origin }}" {
    type slave;
    masters { {{ master_server }}; };
    file "/var/lib/knot/slave/{{ zone.origin }}zone";
};
        '''.strip()
        
    def print_summary(self, data, zone_name):
        """Print summary of created data."""
        self.stdout.write(self.style.SUCCESS('\n🎉 Test data created successfully!'))
        self.stdout.write('\nCreated:')
        self.stdout.write(f'  👤 {len(data["users"])} users')
        self.stdout.write(f'  👥 {len(data["groups"])} groups') 
        self.stdout.write(f'  🖥️  {len(data["servers"])} servers')
        self.stdout.write(f'  🌐 {len(data["zones"])} zones ({zone_name})')
        self.stdout.write(f'  📝 {len(data["records"])} DNS records')
        
        # Print zone file
        zone = data['zones']['zone1']
        records = data['records']
        
        self.stdout.write(f'\n{"="*60}')
        self.stdout.write(f'COMPLETE ZONE FILE FOR {zone_name.upper()}:')
        self.stdout.write('='*60)
        
        # Zone header
        self.stdout.write(zone.format_bind_zone_header())
        
        # All records
        for record_name, record in records.items():
            self.stdout.write(record.format_bind_zone())
            
        self.stdout.write('='*60)
        
        # Login info
        user = data['users']['user1']
        self.stdout.write(f'\n💡 You can now login with:')
        self.stdout.write(f'   Username: {user.username}')
        self.stdout.write(f'   Password: (the password you specified)')
        self.stdout.write(f'   Admin URL: http://127.0.0.1:8000/admin/')
        
        self.stdout.write(f'\n🧪 Run tests with: poetry run pytest tests/ -v')