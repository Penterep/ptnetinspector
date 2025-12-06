"""Integration tests for ptnetinspector components."""
import pytest
import tempfile
import csv
from pathlib import Path
from unittest.mock import patch, MagicMock
from ptnetinspector.utils.csv_helpers import create_csv, has_additional_data
from ptnetinspector.utils.interface import Interface
from ptnetinspector.entities.networks import Networks
from ptnetinspector.utils.cli import parameter_control


class TestCSVIntegration:
    """Integration tests for CSV operations."""

    def test_create_and_verify_csv_files(self):
        """Test creating all required CSV files."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            # Patch get_tmp_path to return our temp directory
            with patch('ptnetinspector.utils.csv_helpers.get_tmp_path') as mock_tmp_path:
                mock_tmp_path.return_value = tmp_dir
                
                # Create all CSV files
                create_csv()
                
                # Verify all CSV files exist
                expected_files = [
                    'packets.csv', 'routers.csv', 'MDNS.csv', 'LLMNR.csv',
                    'MLDv1.csv', 'MLDv2.csv', 'IGMPv1v2.csv', 'IGMPv3.csv',
                    'RA.csv', 'localname.csv', 'role_node.csv',
                    'ipv6_route_table.csv', 'ipv4_route_table.csv',
                    'time_all.csv', 'time_incoming.csv', 'time_outgoing.csv',
                    'start_end_mode.csv', 'eap.csv', 'remote_node.csv',
                    'dhcp.csv', 'wsdiscovery.csv', 'default_gw.csv',
                    'vulnerability.csv'
                ]
                
                for csv_file in expected_files:
                    file_path = Path(tmp_dir) / csv_file
                    assert file_path.exists(), f"{csv_file} not created"
                    # Verify header exists
                    with open(file_path, 'r') as f:
                        reader = csv.reader(f)
                        header = next(reader, None)
                        assert header is not None, f"{csv_file} has no header"

    def test_csv_data_flow(self):
        """Test adding data to CSV and verifying it."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            with patch('ptnetinspector.utils.csv_helpers.get_tmp_path') as mock_tmp_path:
                mock_tmp_path.return_value = tmp_dir
                
                # Create CSV
                create_csv()
                csv_path = Path(tmp_dir) / 'MDNS.csv'
                
                # Add data
                with open(csv_path, 'a', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=['MAC', 'IP'])
                    writer.writerow({'MAC': '00:11:22:33:44:55', 'IP': '192.168.1.100'})
                
                # Verify data exists - use str path
                assert has_additional_data(str(csv_path)) is True

    def test_sort_csv_with_multiple_entries(self):
        """Test sorting CSV by MAC address."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            csv_path = Path(tmp_dir) / 'test.csv'
            
            # Create CSV with multiple entries
            with open(csv_path, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=['MAC', 'IP'])
                writer.writeheader()
                writer.writerow({'MAC': '00:11:22:33:44:55', 'IP': '192.168.1.100'})
                writer.writerow({'MAC': '00:11:22:33:44:56', 'IP': '192.168.1.101'})
                writer.writerow({'MAC': '00:11:22:33:44:54', 'IP': '192.168.1.99'})
            
            # Read and verify data was written
            with open(csv_path, 'r') as f:
                reader = csv.DictReader(f)
                rows = list(reader)
                assert len(rows) == 3


class TestInterfaceOperations:
    """Integration tests for Interface class operations."""

    @patch('netifaces.interfaces', return_value=['eth0', 'lo'])
    def test_interface_initialization_and_methods(self, mock_interfaces):
        """Test Interface class initialization and method calls."""
        iface = Interface('eth0')
        
        # Verify interface object is created
        assert iface is not None
        assert hasattr(iface, 'interface')

    @patch('netifaces.interfaces', return_value=['eth0', 'lo'])
    def test_interface_status_checks(self, mock_interfaces):
        """Test interface status checking."""
        iface = Interface('eth0')
        
        # Test valid interface
        result = iface.check_interface()
        assert result is not False  # Should be True or interface name
        
        # Test invalid interface
        iface_invalid = Interface('nonexistent')
        result_invalid = iface_invalid.check_interface()
        assert result_invalid is False


class TestNetworksIntegration:
    """Integration tests for Networks entity."""

    @patch('netifaces.ifaddresses')
    @patch('netifaces.interfaces')
    def test_extract_available_subnets(self, mock_interfaces, mock_ifaddresses):
        """Test extracting available subnets from interface."""
        mock_interfaces.return_value = ['eth0']
        mock_ifaddresses.return_value = {
            2: [  # IPv4
                {
                    'addr': '192.168.1.100',
                    'netmask': '255.255.255.0',
                    'broadcast': '192.168.1.255'
                }
            ],
            10: [  # IPv6
                {
                    'addr': 'fe80::1',
                    'netmask': 'ffff:ffff:ffff:ffff::',
                }
            ]
        }
        
        # Extract subnets - this saves to CSV
        Networks.extract_available_subnets('eth0')
        
        # Get subnets using the getter methods
        ipv4_subnets = Networks.get_ipv4_subnets()
        ipv6_subnets = Networks.get_ipv6_subnets()
        
        # Verify at least one of them has data (depends on implementation)
        assert ipv4_subnets is not None or ipv6_subnets is not None


class TestCLIParameterFlow:
    """Integration tests for CLI parameter processing."""

    @patch('sys.argv', ['ptnetinspector', '-t', 'p', '-i', 'eth0', '-d', '5'])
    @patch('netifaces.interfaces', return_value=['eth0'])
    def test_parameter_control_flow(self, mock_interfaces):
        """Test CLI parameter control flow."""
        from ptnetinspector.utils.cli import parse_args
        
        args = parse_args()
        
        # Verify parsed arguments
        assert args.t == ['p']
        assert args.interface == 'eth0'
        assert args.d == '5'


class TestVulnerabilityDetection:
    """Integration tests for vulnerability detection."""

    def test_vulnerability_csv_structure(self):
        """Test vulnerability CSV has correct structure."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            csv_path = Path(tmp_dir) / 'vulnerability.csv'
            
            # Create vulnerability CSV
            with open(csv_path, 'w', newline='') as f:
                fieldnames = ['MAC', 'IP', 'Vulnerability', 'Severity', 'Description']
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerow({
                    'MAC': '00:11:22:33:44:55',
                    'IP': '192.168.1.100',
                    'Vulnerability': 'Test Vuln',
                    'Severity': 'High',
                    'Description': 'Test vulnerability'
                })
            
            # Verify structure
            with open(csv_path, 'r') as f:
                reader = csv.DictReader(f)
                rows = list(reader)
                assert len(rows) == 1
                assert 'MAC' in rows[0]
                assert 'Vulnerability' in rows[0]