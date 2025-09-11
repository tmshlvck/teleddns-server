"""
Comprehensive tests for DNS Manager models.
"""
import pytest
from django.core.exceptions import ValidationError
from django.contrib.auth import get_user_model
from dns_manager.models import (
    Group, Server, MasterZone, UserToken, UserPassKey,
    A, AAAA, NS, PTR, CNAME, TXT, CAA, MX, SRV, SSHFP, TLSA, DNSKEY, DS, NAPTR,
    UserLabelAuthorization, GroupLabelAuthorization
)

User = get_user_model()


@pytest.mark.unit
class TestUserModel:
    """Test the custom User model."""
    
    def test_user_creation(self, user1):
        assert user1.username == 'user1'
        assert user1.email == 'user1@example.com'
        assert user1.check_password('testpass123')
        assert user1.last_update_metadata == 'Created by pytest fixture'
        
    def test_user_str_representation(self, user1):
        assert str(user1) == 'user1'
        
    def test_user_2fa_fields(self, user1):
        assert user1.totp_enabled is False
        assert user1.totp_secret is None
        assert user1.sso_enabled is False


@pytest.mark.unit
class TestGroupModel:
    """Test the Group model."""
    
    def test_group_creation(self, group1):
        assert group1.name == 'group1'
        assert group1.description == 'Test group 1'
        
    def test_group_str_representation(self, group1):
        assert str(group1) == 'group1'
        
    def test_group_user_relationship(self, group1, user1):
        assert user1 in group1.users.all()
        assert group1 in user1.user_groups.all()


@pytest.mark.unit
class TestServerModel:
    """Test the Server model."""
    
    def test_server_creation(self, server1, user1, group1):
        assert server1.name == 'Test Server 1'
        assert server1.api_url == 'http://localhost:8586'
        assert server1.api_key == 'test-api-key-123'
        assert server1.owner == user1
        assert server1.group == group1
        assert server1.is_active is True
        assert server1.config_dirty is True
        
    def test_server_str_representation(self, server1):
        assert str(server1) == 'Test Server 1'


@pytest.mark.unit
class TestMasterZoneModel:
    """Test the MasterZone model."""
    
    def test_zone_creation(self, zone1_tld, user1, group1, server1):
        assert zone1_tld.origin == 'zone1.tld.'
        assert zone1_tld.soa_name == '@'
        assert zone1_tld.soa_serial == 2024091101
        assert zone1_tld.owner == user1
        assert zone1_tld.group == group1
        assert zone1_tld.master_server == server1
        
    def test_zone_str_representation(self, zone1_tld):
        assert str(zone1_tld) == 'zone1.tld.'
        
    def test_zone_bind_format(self, zone1_tld):
        bind_output = zone1_tld.format_bind_zone_header()
        assert '$ORIGIN zone1.tld.' in bind_output
        assert 'SOA ns1.zone1.tld.' in bind_output
        assert '2024091101' in bind_output
        
    def test_zone_validation_invalid_origin(self, user1):
        with pytest.raises(ValidationError):
            zone = MasterZone(
                origin='invalid-origin',  # Missing trailing dot
                soa_name='@',
                soa_serial=1,
                soa_mname='ns1.example.com.',
                soa_rname='admin.example.com.',
                owner=user1
            )
            zone.full_clean()


@pytest.mark.unit 
class TestDNSRecords:
    """Test all DNS record types."""
    
    def test_a_record_creation(self, dns_records):
        a_record = dns_records['a1']
        assert a_record.label == 'arr1'
        assert a_record.value == '1.2.3.4'
        assert 'A\t1.2.3.4' in a_record.format_bind_zone()
        
    def test_a_record_validation(self, zone1_tld):
        with pytest.raises(ValidationError):
            invalid_a = A(zone=zone1_tld, label='test', value='invalid-ip')
            invalid_a.full_clean()
            
    def test_aaaa_record_creation(self, dns_records):
        aaaa_record = dns_records['aaaa1']
        assert aaaa_record.label == 'ipv6'
        assert aaaa_record.value == '2001:db8::1'
        assert 'AAAA\t2001:db8::1' in aaaa_record.format_bind_zone()
        
    def test_aaaa_record_validation(self, zone1_tld):
        with pytest.raises(ValidationError):
            invalid_aaaa = AAAA(zone=zone1_tld, label='test', value='invalid-ipv6')
            invalid_aaaa.full_clean()
            
    def test_ns_record_creation(self, dns_records):
        ns_record = dns_records['ns1']
        assert ns_record.value == 'ns1.zone1.tld.'
        assert 'NS\tns1.zone1.tld.' in ns_record.format_bind_zone()
        
    def test_ptr_record_creation(self, dns_records):
        ptr_record = dns_records['ptr1']
        assert ptr_record.value == 'arr1.zone1.tld.'
        assert 'PTR\tarr1.zone1.tld.' in ptr_record.format_bind_zone()
        
    def test_cname_record_creation(self, dns_records):
        cname_record = dns_records['cname1']
        assert cname_record.label == 'www'
        assert cname_record.value == 'zone1.tld.'
        assert 'CNAME\tzone1.tld.' in cname_record.format_bind_zone()
        
    def test_txt_record_creation(self, dns_records):
        txt_record = dns_records['txt1']
        assert txt_record.value == 'v=test123'
        assert 'TXT\t"v=test123"' in txt_record.format_bind_zone()
        
    def test_caa_record_creation(self, dns_records):
        caa_record = dns_records['caa1']
        assert caa_record.flag == 0
        assert caa_record.tag == 'issue'
        assert caa_record.value == 'letsencrypt.org'
        assert 'CAA\t0\tissue "letsencrypt.org"' in caa_record.format_bind_zone()
        
    def test_mx_record_creation(self, dns_records):
        mx_record = dns_records['mx1']
        assert mx_record.priority == 10
        assert mx_record.value == 'mail1.zone1.tld.'
        assert 'MX 10 mail1.zone1.tld.' in mx_record.format_bind_zone()
        
    def test_srv_record_creation(self, dns_records):
        srv_record = dns_records['srv1']
        assert srv_record.label == '_sip._tcp'
        assert srv_record.priority == 10
        assert srv_record.weight == 50
        assert srv_record.port == 5060
        assert srv_record.value == 'sip.zone1.tld.'
        bind_output = srv_record.format_bind_zone()
        assert 'SRV\t10 50 5060 sip.zone1.tld.' in bind_output
        
    def test_sshfp_record_creation(self, dns_records):
        sshfp_record = dns_records['sshfp1']
        assert sshfp_record.algorithm == 1  # RSA
        assert sshfp_record.hash_type == 1  # SHA-1
        assert '123456789abcdef0123456789abcdef012345678' in sshfp_record.fingerprint
        bind_output = sshfp_record.format_bind_zone()
        assert 'SSHFP 1 1' in bind_output
        
    def test_tlsa_record_creation(self, dns_records):
        tlsa_record = dns_records['tlsa1']
        assert tlsa_record.cert_usage == 3
        assert tlsa_record.selector == 1  
        assert tlsa_record.matching_type == 1
        bind_output = tlsa_record.format_bind_zone()
        assert 'TLSA 3 1 1' in bind_output
        
    def test_dnskey_record_creation(self, dns_records):
        dnskey_record = dns_records['dnskey1']
        assert dnskey_record.flags == 257
        assert dnskey_record.protocol == 3
        assert dnskey_record.algorithm == 8
        bind_output = dnskey_record.format_bind_zone()
        assert 'DNSKEY 257 3 8' in bind_output
        
    def test_ds_record_creation(self, dns_records):
        ds_record = dns_records['ds1']
        assert ds_record.key_tag == 12345
        assert ds_record.algorithm == 8
        assert ds_record.digest_type == 2
        bind_output = ds_record.format_bind_zone()
        assert 'DS 12345 8 2' in bind_output
        
    def test_naptr_record_creation(self, dns_records):
        naptr_record = dns_records['naptr1']
        assert naptr_record.order == 100
        assert naptr_record.preference == 50
        assert naptr_record.flags == 'u'
        assert naptr_record.service == 'E2U+sip'
        bind_output = naptr_record.format_bind_zone()
        assert 'NAPTR 100 50 "u" "E2U+sip"' in bind_output


@pytest.mark.unit
class TestRecordRelationships:
    """Test record relationships with zones."""
    
    def test_zone_record_relationships(self, zone1_tld, dns_records):
        # Test that zone has all the expected record types
        assert zone1_tld.a_records.count() == 2
        assert zone1_tld.aaaa_records.count() == 2
        assert zone1_tld.ns_records.count() == 2
        assert zone1_tld.ptr_records.count() == 1
        assert zone1_tld.cname_records.count() == 1
        assert zone1_tld.txt_records.count() == 2
        assert zone1_tld.caa_records.count() == 1
        assert zone1_tld.mx_records.count() == 2
        assert zone1_tld.srv_records.count() == 2
        assert zone1_tld.sshfp_records.count() == 1
        assert zone1_tld.tlsa_records.count() == 1
        assert zone1_tld.dnskey_records.count() == 1
        assert zone1_tld.ds_records.count() == 1
        assert zone1_tld.naptr_records.count() == 1
        
    def test_record_zone_relationship(self, dns_records):
        # Test that records properly reference their zone
        for record_name, record in dns_records.items():
            assert record.zone.origin == 'zone1.tld.'


@pytest.mark.integration
class TestCompleteDataset:
    """Test the complete dataset functionality."""
    
    def test_complete_test_data_structure(self, complete_test_data):
        data = complete_test_data
        
        # Check users
        assert 'user1' in data['users']
        assert 'user2' in data['users'] 
        assert 'admin' in data['users']
        
        # Check groups
        assert 'group1' in data['groups']
        
        # Check servers
        assert 'server1' in data['servers']
        
        # Check zones
        assert 'zone1_tld' in data['zones']
        
        # Check records
        assert len(data['records']) == 20  # Total number of DNS records
        
    def test_full_zone_bind_output(self, complete_test_data):
        """Test complete zone file generation."""
        zone = complete_test_data['zones']['zone1_tld']
        records = complete_test_data['records']
        
        # Generate complete zone file
        zone_content = [zone.format_bind_zone_header()]
        
        # Add all records
        for record_name, record in records.items():
            zone_content.append(record.format_bind_zone())
            
        full_zone = '\n'.join(zone_content)
        
        # Verify zone file contains expected elements
        assert '$ORIGIN zone1.tld.' in full_zone
        assert 'SOA ns1.zone1.tld.' in full_zone
        assert 'arr1' in full_zone
        assert '1.2.3.4' in full_zone
        assert '2001:db8::1' in full_zone
        assert 'v=test123' in full_zone
        assert 'mail1.zone1.tld.' in full_zone
        
        # Print zone file for manual inspection
        print(f"\n{'='*50}")
        print("COMPLETE ZONE FILE:")
        print('='*50)
        print(full_zone)
        print('='*50)
        
    def test_user_permissions_and_ownership(self, complete_test_data):
        """Test user ownership and permissions."""
        user1 = complete_test_data['users']['user1']
        zone = complete_test_data['zones']['zone1_tld']
        server = complete_test_data['servers']['server1']
        
        # Test ownership
        assert user1.owned_zones.count() == 1
        assert user1.owned_servers.count() == 1
        assert zone.owner == user1
        assert server.owner == user1
        
        # Test group membership  
        assert user1.user_groups.count() == 1
        group = user1.user_groups.first()
        assert group.name == 'group1'


@pytest.mark.integration
@pytest.mark.slow
class TestDataValidation:
    """Test data validation across the complete dataset."""
    
    def test_all_records_validate(self, complete_test_data):
        """Ensure all created records pass validation."""
        records = complete_test_data['records']
        
        for record_name, record in records.items():
            try:
                record.full_clean()
            except ValidationError as e:
                pytest.fail(f"Record {record_name} failed validation: {e}")
                
    def test_zone_serial_increment(self, complete_test_data):
        """Test SOA serial number handling."""
        zone = complete_test_data['zones']['zone1_tld']
        original_serial = zone.soa_serial
        
        # Simulate serial increment
        zone.soa_serial = original_serial + 1
        zone.save()
        
        zone.refresh_from_db()
        assert zone.soa_serial == original_serial + 1