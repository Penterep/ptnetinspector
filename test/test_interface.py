"""Tests for Interface class."""
import pytest
from unittest.mock import Mock, patch, MagicMock
from ptnetinspector.utils.interface import Interface


class TestInterface:
    """Test Interface class methods."""

    def test_interface_initialization(self):
        """Test Interface object creation."""
        iface = Interface("eth0")
        assert iface.interface == "eth0"

    @patch('netifaces.interfaces')
    def test_check_interface_exists(self, mock_interfaces):
        """Test checking if interface exists."""
        mock_interfaces.return_value = ['lo', 'eth0', 'wlan0']
        
        iface = Interface("eth0")
        assert iface.check_interface() is True
        
        iface_invalid = Interface("nonexistent")
        assert iface_invalid.check_interface() is False

    @patch('netifaces.interfaces')
    @patch('netifaces.ifaddresses')
    def test_get_interface_ips(self, mock_ifaddresses, mock_interfaces):
        """Test getting interface IP addresses."""
        mock_interfaces.return_value = ['eth0']
        mock_ifaddresses.return_value = {
            2: [{'addr': '192.168.1.100'}],  # AF_INET
            10: [{'addr': 'fe80::1'}]  # AF_INET6
        }
        
        iface = Interface("eth0")
        ips = iface.get_interface_ips()
        
        assert '192.168.1.100' in ips
        assert 'fe80::1' in ips

    @patch('netifaces.interfaces')
    @patch('netifaces.ifaddresses')
    def test_get_interface_ipv4_ips(self, mock_ifaddresses, mock_interfaces):
        """Test getting IPv4 addresses only."""
        mock_interfaces.return_value = ['eth0']
        mock_ifaddresses.return_value = {
            2: [{'addr': '192.168.1.100'}, {'addr': '10.0.0.1'}]
        }
        
        iface = Interface("eth0")
        ipv4_ips = iface.get_interface_ipv4_ips()
        
        assert '192.168.1.100' in ipv4_ips
        assert '10.0.0.1' in ipv4_ips
        assert len(ipv4_ips) == 2

    @patch('netifaces.interfaces')
    @patch('netifaces.ifaddresses')
    def test_get_interface_ipv6_ips(self, mock_ifaddresses, mock_interfaces):
        """Test getting IPv6 addresses only."""
        mock_interfaces.return_value = ['eth0']
        mock_ifaddresses.return_value = {
            10: [
                {'addr': 'fe80::1%eth0'},
                {'addr': '2001:db8::1'}
            ]
        }
        
        iface = Interface("eth0")
        ipv6_ips = iface.get_interface_ipv6_ips()
        
        assert 'fe80::1' in ipv6_ips
        assert '2001:db8::1' in ipv6_ips

    @patch('netifaces.interfaces')
    @patch('netifaces.ifaddresses')
    def test_get_interface_link_local_list(self, mock_ifaddresses, mock_interfaces):
        """Test getting link-local IPv6 addresses."""
        mock_interfaces.return_value = ['eth0']
        mock_ifaddresses.return_value = {
            2: [{'addr': '192.168.1.100'}],
            10: [
                {'addr': 'fe80::1'},
                {'addr': '2001:db8::1'},
                {'addr': 'fe80::abcd:ef01:2345:6789'}
            ]
        }
        
        iface = Interface("eth0")
        link_local = iface.get_interface_link_local_list()
        
        assert 'fe80::1' in link_local
        assert 'fe80::abcd:ef01:2345:6789' in link_local
        assert '2001:db8::1' not in link_local

    @patch('subprocess.run')
    def test_check_status_up(self, mock_run):
        """Test checking interface status when up."""
        mock_run.return_value = Mock(
            stdout="2: eth0: <BROADCAST,MULTICAST,UP> state UP",
            returncode=0
        )
        
        iface = Interface("eth0")
        status = iface.check_status()
        
        assert "state UP" in status
        assert status != "Interface down"

    @patch('subprocess.run')
    def test_check_status_down(self, mock_run):
        """Test checking interface status when down."""
        mock_run.return_value = Mock(
            stdout="2: eth0: <BROADCAST,MULTICAST> state DOWN",
            returncode=0
        )
        
        iface = Interface("eth0")
        status = iface.check_status()
        
        assert status == "Interface down"

    @patch('subprocess.check_output')
    def test_check_available_ipv6(self, mock_check_output):
        """Test checking if IPv6 is available."""
        mock_check_output.return_value = """
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    inet6 fe80::1/64 scope link
    inet6 2001:db8::1/64 scope global
"""
        
        iface = Interface("eth0")
        assert iface.check_available_ipv6() is True

    @patch('subprocess.run')
    def test_set_ipv6_address(self, mock_run):
        """Test setting IPv6 address on interface."""
        mock_run.return_value = Mock(returncode=0)
        
        iface = Interface("eth0")
        iface.set_ipv6_address("2001:db8::100")
        
        mock_run.assert_called_once()
        args = mock_run.call_args[0][0]
        assert "ip" in args
        assert "addr" in args
        assert "add" in args
        assert "2001:db8::100/64" in args
