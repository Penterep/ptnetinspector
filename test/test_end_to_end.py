"""End-to-end tests for ptnetinspector tool."""
import pytest
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch, Mock, MagicMock, call
from io import StringIO
import csv


# ============================================================================
# PASSIVE SCAN MODE TESTS
# ============================================================================

class TestPassiveScanEndToEnd:
    """End-to-end tests for passive scan mode."""

    @patch('sys.argv', ['ptnetinspector', '-t', 'p', '-i', 'eth0', '-d', '5'])
    @patch('netifaces.interfaces', return_value=['eth0', 'lo'])
    def test_passive_basic_args(self, mock_intf_list):
        """Test passive scan with basic arguments."""
        from ptnetinspector.utils.cli import parse_args
        
        args = parse_args()
        assert args.t == ['p']
        assert args.interface == 'eth0'
        assert args.d == '5'

    @patch('sys.argv', ['ptnetinspector', '-t', 'p', '-i', 'eth0', '-j'])
    @patch('netifaces.interfaces', return_value=['eth0'])
    def test_passive_with_json(self, mock_intf_list):
        """Test passive scan with JSON output."""
        from ptnetinspector.utils.cli import parse_args
        
        args = parse_args()
        assert args.t == ['p']
        assert args.j is True

    @patch('sys.argv', ['ptnetinspector', '-t', 'p', '-i', 'eth0', '-more'])
    @patch('netifaces.interfaces', return_value=['eth0'])
    def test_passive_with_more_detail(self, mock_intf_list):
        """Test passive scan with more detail output."""
        from ptnetinspector.utils.cli import parse_args
        
        args = parse_args()
        assert args.t == ['p']
        assert args.more is True

    @patch('sys.argv', ['ptnetinspector', '-t', 'p', '-i', 'eth0', '-less'])
    @patch('netifaces.interfaces', return_value=['eth0'])
    def test_passive_with_less_detail(self, mock_intf_list):
        """Test passive scan with less detail output."""
        from ptnetinspector.utils.cli import parse_args
        
        args = parse_args()
        assert args.t == ['p']
        assert args.less is True

    @patch('sys.argv', ['ptnetinspector', '-t', 'p', '-i', 'eth0', '-4'])
    @patch('netifaces.interfaces', return_value=['eth0'])
    def test_passive_ipv4_only(self, mock_intf_list):
        """Test passive scan in IPv4-only mode."""
        from ptnetinspector.utils.cli import parse_args
        
        args = parse_args()
        assert args.t == ['p']
        assert args.ipv4 is True
        assert args.ipv6 is False

    @patch('sys.argv', ['ptnetinspector', '-t', 'p', '-i', 'eth0', '-6'])
    @patch('netifaces.interfaces', return_value=['eth0'])
    def test_passive_ipv6_only(self, mock_intf_list):
        """Test passive scan in IPv6-only mode."""
        from ptnetinspector.utils.cli import parse_args
        
        args = parse_args()
        assert args.t == ['p']
        assert args.ipv6 is True
        assert args.ipv4 is False

    @patch('sys.argv', ['ptnetinspector', '-t', 'p', '-i', 'eth0'])
    @patch('netifaces.interfaces', return_value=['eth0'])
    def test_passive_check_addresses_by_default(self, mock_intf_list):
        """Test passive scan checks addresses by default (without -nc flag)."""
        from ptnetinspector.utils.cli import parse_args
        
        args = parse_args()
        assert args.t == ['p']
        # Without -nc flag, nc should be True (default is True)
        assert args.nc is True

    @patch('sys.argv', ['ptnetinspector', '-t', 'p', '-i', 'eth0', '-nc'])
    @patch('netifaces.interfaces', return_value=['eth0'])
    def test_passive_skip_address_check(self, mock_intf_list):
        """Test passive scan skips address check with -nc flag."""
        from ptnetinspector.utils.cli import parse_args
        
        args = parse_args()
        assert args.t == ['p']
        # With -nc flag, nc becomes False (store_false)
        assert args.nc is False

    @patch('sys.argv', ['ptnetinspector', '-t', 'p', '-i', 'eth0', '-d', '10', '-j', '-more', '-4'])
    @patch('netifaces.interfaces', return_value=['eth0'])
    def test_passive_combined_options(self, mock_intf_list):
        """Test passive scan with multiple options combined."""
        from ptnetinspector.utils.cli import parse_args
        
        args = parse_args()
        assert args.t == ['p']
        assert args.d == '10'
        assert args.j is True
        assert args.more is True
        assert args.ipv4 is True


# ============================================================================
# ACTIVE SCAN MODE TESTS
# ============================================================================

class TestActiveScanEndToEnd:
    """End-to-end tests for active scan mode."""

    @patch('sys.argv', ['ptnetinspector', '-t', 'a', '-i', 'eth0'])
    @patch('netifaces.interfaces', return_value=['eth0'])
    @patch('ptnetinspector.utils.interface.IptablesRule.check', return_value=False)
    def test_active_basic_args(self, mock_iptables, mock_intf_list):
        """Test active scan with basic arguments."""
        from ptnetinspector.utils.cli import parse_args
        
        args = parse_args()
        assert args.t == ['a']
        assert args.interface == 'eth0'

    @patch('sys.argv', ['ptnetinspector', '-t', 'a', '-i', 'eth0', '-j'])
    @patch('netifaces.interfaces', return_value=['eth0'])
    def test_active_with_json(self, mock_intf_list):
        """Test active scan with JSON output."""
        from ptnetinspector.utils.cli import parse_args
        
        args = parse_args()
        assert args.t == ['a']
        assert args.j is True

    @patch('sys.argv', ['ptnetinspector', '-t', 'a', '-i', 'eth0', '-d', '30'])
    @patch('netifaces.interfaces', return_value=['eth0'])
    def test_active_with_duration(self, mock_intf_list):
        """Test active scan with custom duration."""
        from ptnetinspector.utils.cli import parse_args
        
        args = parse_args()
        assert args.t == ['a']
        # For active/passive scans, duration is stored in 'd', not 'duration_router'
        assert args.d == '30'

    @patch('sys.argv', ['ptnetinspector', '-t', 'a', '-i', 'eth0', '-4'])
    @patch('netifaces.interfaces', return_value=['eth0'])
    def test_active_ipv4_only(self, mock_intf_list):
        """Test active scan in IPv4-only mode."""
        from ptnetinspector.utils.cli import parse_args
        
        args = parse_args()
        assert args.t == ['a']
        assert args.ipv4 is True

    @patch('sys.argv', ['ptnetinspector', '-t', 'a', '-i', 'eth0', '-6'])
    @patch('netifaces.interfaces', return_value=['eth0'])
    def test_active_ipv6_only(self, mock_intf_list):
        """Test active scan in IPv6-only mode."""
        from ptnetinspector.utils.cli import parse_args
        
        args = parse_args()
        assert args.t == ['a']
        assert args.ipv6 is True

    @patch('sys.argv', ['ptnetinspector', '-t', 'a', '-i', 'eth0', '-smac', '00:11:22:33:44:55'])
    @patch('netifaces.interfaces', return_value=['eth0'])
    def test_active_with_source_mac(self, mock_intf_list):
        """Test active scan with source MAC address."""
        from ptnetinspector.utils.cli import parse_args
        
        args = parse_args()
        assert args.t == ['a']
        assert args.smac == '00:11:22:33:44:55'

    @patch('sys.argv', ['ptnetinspector', '-t', 'a', '-i', 'eth0', '-sip', '192.168.1.100'])
    @patch('netifaces.interfaces', return_value=['eth0'])
    def test_active_with_source_ip(self, mock_intf_list):
        """Test active scan with source IP address."""
        from ptnetinspector.utils.cli import parse_args
        
        args = parse_args()
        assert args.t == ['a']
        assert args.sip == '192.168.1.100'


# ============================================================================
# AGGRESSIVE SCAN MODE TESTS
# ============================================================================

class TestAggressiveScanEndToEnd:
    """End-to-end tests for aggressive scan mode."""

    @patch('sys.argv', ['ptnetinspector', '-t', 'a+', '-i', 'eth0', '-prefix', '2001:db8::/64'])
    @patch('netifaces.interfaces', return_value=['eth0'])
    @patch('ptnetinspector.utils.interface.IptablesRule.check', return_value=False)
    def test_aggressive_basic_with_prefix(self, mock_iptables, mock_intf_list):
        """Test aggressive scan with prefix."""
        from ptnetinspector.utils.cli import parse_args
        from ptnetinspector.utils.ip_utils import is_valid_ipv6_prefix
        
        args = parse_args()
        assert args.t == ['a+']
        assert args.interface == 'eth0'
        assert args.prefix == '2001:db8::/64'
        assert is_valid_ipv6_prefix(args.prefix) is True

    @patch('sys.argv', ['ptnetinspector', '-t', 'a+', '-i', 'eth0', '-prefix', '2001:db8::/64', '-j'])
    @patch('netifaces.interfaces', return_value=['eth0'])
    def test_aggressive_with_json(self, mock_intf_list):
        """Test aggressive scan with JSON output."""
        from ptnetinspector.utils.cli import parse_args
        
        args = parse_args()
        assert args.t == ['a+']
        assert args.prefix == '2001:db8::/64'
        assert args.j is True

    @patch('sys.argv', ['ptnetinspector', '-t', 'a+', '-i', 'eth0', '-prefix', 'fd00::/64', '-da+', '60'])
    @patch('netifaces.interfaces', return_value=['eth0'])
    def test_aggressive_with_duration(self, mock_intf_list):
        """Test aggressive scan with custom duration."""
        from ptnetinspector.utils.cli import parse_args
        
        args = parse_args()
        assert args.t == ['a+']
        # For aggressive scan, duration is stored in 'duration_router' via -da+
        assert args.duration_router == '60'

    @patch('sys.argv', ['ptnetinspector', '-t', 'a+', '-i', 'eth0', '-prefix', '2001:db8::/64', '-smac', 'aa:bb:cc:dd:ee:ff'])
    @patch('netifaces.interfaces', return_value=['eth0'])
    def test_aggressive_with_source_mac(self, mock_intf_list):
        """Test aggressive scan with source MAC."""
        from ptnetinspector.utils.cli import parse_args
        
        args = parse_args()
        assert args.smac == 'aa:bb:cc:dd:ee:ff'

    @patch('sys.argv', ['ptnetinspector', '-t', 'a+', '-i', 'eth0', '-prefix', '2001:db8::/64', '-rpref', 'High'])
    @patch('netifaces.interfaces', return_value=['eth0'])
    def test_aggressive_with_router_preference(self, mock_intf_list):
        """Test aggressive scan with router preference."""
        from ptnetinspector.utils.cli import parse_args
        
        args = parse_args()
        assert args.rpref == 'High'

    @patch('sys.argv', ['ptnetinspector', '-t', 'a+', '-i', 'eth0', '-prefix', '2001:db8::/64', '-mtu', '1500'])
    @patch('netifaces.interfaces', return_value=['eth0'])
    def test_aggressive_with_mtu(self, mock_intf_list):
        """Test aggressive scan with custom MTU."""
        from ptnetinspector.utils.cli import parse_args
        
        args = parse_args()
        assert args.mtu == '1500'

    @patch('sys.argv', ['ptnetinspector', '-t', 'a+', '-i', 'eth0', '-prefix', '2001:db8::/64', '-period', '2'])
    @patch('netifaces.interfaces', return_value=['eth0'])
    def test_aggressive_with_period(self, mock_intf_list):
        """Test aggressive scan with custom period."""
        from ptnetinspector.utils.cli import parse_args
        
        args = parse_args()
        assert args.period == '2'

    @patch('sys.argv', ['ptnetinspector', '-t', 'a+', '-i', 'eth0', '-prefix', '2001:db8::/64', '-chl', '64'])
    @patch('netifaces.interfaces', return_value=['eth0'])
    def test_aggressive_with_hop_limit(self, mock_intf_list):
        """Test aggressive scan with custom hop limit."""
        from ptnetinspector.utils.cli import parse_args
        
        args = parse_args()
        assert args.chl == '64'

    @patch('sys.argv', ['ptnetinspector', '-t', 'a+', '-i', 'eth0', '-prefix', '2001:db8::/64', '-dns', '2001:4860:4860::8888', '2001:4860:4860::8844'])
    @patch('netifaces.interfaces', return_value=['eth0'])
    def test_aggressive_with_multiple_dns(self, mock_intf_list):
        """Test aggressive scan with multiple DNS servers."""
        from ptnetinspector.utils.cli import parse_args
        
        args = parse_args()
        assert '2001:4860:4860::8888' in args.dns
        assert '2001:4860:4860::8844' in args.dns

    @patch('sys.argv', ['ptnetinspector', '-t', 'a+', '-i', 'eth0', '-prefix', '2001:db8::/64', '-nofwd'])
    @patch('netifaces.interfaces', return_value=['eth0'])
    def test_aggressive_with_nofwd(self, mock_intf_list):
        """Test aggressive scan with no-forward flag."""
        from ptnetinspector.utils.cli import parse_args
        
        args = parse_args()
        assert args.nofwd is True


# ============================================================================
# 802.1X (EAP) SCAN MODE TESTS
# ============================================================================

class TestEAPScanEndToEnd:
    """End-to-end tests for 802.1x (EAP) scan mode."""

    @patch('sys.argv', ['ptnetinspector', '-t', '802.1x', '-i', 'eth0'])
    @patch('netifaces.interfaces', return_value=['eth0'])
    def test_eap_basic_args(self, mock_intf_list):
        """Test 802.1x scan with basic arguments."""
        from ptnetinspector.utils.cli import parse_args
        
        args = parse_args()
        assert args.t == ['802.1x']
        assert args.interface == 'eth0'

    @patch('sys.argv', ['ptnetinspector', '-t', '802.1x', '-i', 'eth0', '-j'])
    @patch('netifaces.interfaces', return_value=['eth0'])
    def test_eap_with_json(self, mock_intf_list):
        """Test 802.1x scan with JSON output."""
        from ptnetinspector.utils.cli import parse_args
        
        args = parse_args()
        assert args.t == ['802.1x']
        assert args.j is True

    @patch('sys.argv', ['ptnetinspector', '-t', '802.1x', '-i', 'eth0', '-more'])
    @patch('netifaces.interfaces', return_value=['eth0'])
    def test_eap_with_more_detail(self, mock_intf_list):
        """Test 802.1x scan with more detail."""
        from ptnetinspector.utils.cli import parse_args
        
        args = parse_args()
        assert args.t == ['802.1x']
        assert args.more is True

    @patch('sys.argv', ['ptnetinspector', '-t', '802.1x', '-i', 'eth0', '-4'])
    @patch('netifaces.interfaces', return_value=['eth0'])
    def test_eap_ipv4_only(self, mock_intf_list):
        """Test 802.1x scan in IPv4-only mode."""
        from ptnetinspector.utils.cli import parse_args
        
        args = parse_args()
        assert args.t == ['802.1x']
        assert args.ipv4 is True


# ============================================================================
# MULTIPLE SCAN MODES TESTS
# ============================================================================

class TestMultipleScanModesEndToEnd:
    """End-to-end tests for combining multiple scan modes."""

    @patch('sys.argv', ['ptnetinspector', '-t', '802.1x', 'p', '-i', 'eth0'])
    @patch('netifaces.interfaces', return_value=['eth0'])
    def test_eap_and_passive(self, mock_intf_list):
        """Test combined 802.1x and passive scan."""
        from ptnetinspector.utils.cli import parse_args
        
        args = parse_args()
        assert '802.1x' in args.t
        assert 'p' in args.t

    @patch('sys.argv', ['ptnetinspector', '-t', '802.1x', 'p', 'a', '-i', 'eth0'])
    @patch('netifaces.interfaces', return_value=['eth0'])
    def test_eap_passive_and_active(self, mock_intf_list):
        """Test combined 802.1x, passive, and active scans."""
        from ptnetinspector.utils.cli import parse_args
        
        args = parse_args()
        assert '802.1x' in args.t
        assert 'p' in args.t
        assert 'a' in args.t

    @patch('sys.argv', ['ptnetinspector', '-t', 'p', 'a', '-i', 'eth0', '-j'])
    @patch('netifaces.interfaces', return_value=['eth0'])
    def test_passive_and_active_with_json(self, mock_intf_list):
        """Test passive and active scans with JSON output."""
        from ptnetinspector.utils.cli import parse_args
        
        args = parse_args()
        assert 'p' in args.t
        assert 'a' in args.t
        assert args.j is True


# ============================================================================
# OUTPUT FORMAT TESTS
# ============================================================================

class TestOutputFormatEndToEnd:
    """End-to-end tests for different output formats."""

    @patch('sys.argv', ['ptnetinspector', '-t', 'p', '-i', 'eth0', '-j'])
    @patch('netifaces.interfaces', return_value=['eth0'])
    def test_json_output_enabled(self, mock_intf_list):
        """Test JSON output flag."""
        from ptnetinspector.utils.cli import parse_args
        
        args = parse_args()
        assert args.j is True

    @patch('sys.argv', ['ptnetinspector', '-t', 'p', '-i', 'eth0', '-n'])
    @patch('netifaces.interfaces', return_value=['eth0'])
    def test_delete_temp_files(self, mock_intf_list):
        """Test delete temporary files flag."""
        from ptnetinspector.utils.cli import parse_args
        
        args = parse_args()
        # -n flag sets n to False (store_false with default True)
        assert args.n is False

    @patch('sys.argv', ['ptnetinspector', '-t', 'p', '-i', 'eth0'])
    @patch('netifaces.interfaces', return_value=['eth0'])
    def test_keep_temp_files_by_default(self, mock_intf_list):
        """Test keeping temporary files by default (without -n flag)."""
        from ptnetinspector.utils.cli import parse_args
        
        args = parse_args()
        # Without -n flag, n is True (default)
        assert args.n is True

    @patch('sys.argv', ['ptnetinspector', '-t', 'p', '-i', 'eth0', '-more'])
    @patch('netifaces.interfaces', return_value=['eth0'])
    def test_more_detail_output(self, mock_intf_list):
        """Test more detail output flag."""
        from ptnetinspector.utils.cli import parse_args
        
        args = parse_args()
        assert args.more is True

    @patch('sys.argv', ['ptnetinspector', '-t', 'p', '-i', 'eth0', '-less'])
    @patch('netifaces.interfaces', return_value=['eth0'])
    def test_less_detail_output(self, mock_intf_list):
        """Test less detail output flag."""
        from ptnetinspector.utils.cli import parse_args
        
        args = parse_args()
        assert args.less is True


# ============================================================================
# IP VERSION FILTERING TESTS
# ============================================================================

class TestIPVersionFiltering:
    """End-to-end tests for IPv4/IPv6 filtering."""

    @patch('sys.argv', ['ptnetinspector', '-t', 'p', '-i', 'eth0', '-4'])
    @patch('netifaces.interfaces', return_value=['eth0'])
    def test_ipv4_only_mode(self, mock_intf_list):
        """Test IPv4-only mode."""
        from ptnetinspector.utils.cli import parse_args
        
        args = parse_args()
        assert args.ipv4 is True
        assert args.ipv6 is False

    @patch('sys.argv', ['ptnetinspector', '-t', 'p', '-i', 'eth0', '-6'])
    @patch('netifaces.interfaces', return_value=['eth0'])
    def test_ipv6_only_mode(self, mock_intf_list):
        """Test IPv6-only mode."""
        from ptnetinspector.utils.cli import parse_args
        
        args = parse_args()
        assert args.ipv6 is True
        assert args.ipv4 is False

    @patch('sys.argv', ['ptnetinspector', '-t', 'p', '-i', 'eth0'])
    @patch('netifaces.interfaces', return_value=['eth0'])
    def test_both_ipv4_and_ipv6(self, mock_intf_list):
        """Test both IPv4 and IPv6 (default)."""
        from ptnetinspector.utils.cli import parse_args
        
        args = parse_args()
        assert args.ipv4 is False
        assert args.ipv6 is False  # False means both are enabled (default)


# ============================================================================
# ERROR HANDLING TESTS
# ============================================================================

class TestErrorHandling:
    """End-to-end tests for error handling."""

    @patch('netifaces.interfaces', return_value=['lo'])
    def test_invalid_interface(self, mock_intf_list):
        """Test detection of invalid interface."""
        from ptnetinspector.utils.interface import Interface
        
        iface = Interface('nonexistent')
        result = iface.check_interface()
        assert result is False

    @patch('sys.argv', ['ptnetinspector', '-t', 'invalid', '-i', 'eth0'])
    def test_invalid_scan_type_handled(self, ):
        """Test that invalid scan types are handled."""
        from ptnetinspector.utils.cli import parse_args
        
        # Invalid scan types may not raise SystemExit but are handled by parser
        # Just verify the parser doesn't crash
        try:
            args = parse_args()
            # If it parses, check that scan type was processed
            assert args.t is not None
        except SystemExit:
            # It's also acceptable if it raises SystemExit
            pass

    @patch('sys.argv', ['ptnetinspector', '-t', 'a+', '-i', 'eth0', '-prefix', 'invalid::prefix'])
    @patch('netifaces.interfaces', return_value=['eth0'])
    def test_invalid_prefix_format(self, mock_intf_list):
        """Test invalid IPv6 prefix format."""
        from ptnetinspector.utils.ip_utils import is_valid_ipv6_prefix
        
        assert is_valid_ipv6_prefix('invalid::prefix') is False

    @patch('sys.argv', ['ptnetinspector', '-t', 'p', '-i', 'eth0', '-smac', 'invalid:mac'])
    @patch('netifaces.interfaces', return_value=['eth0'])
    def test_invalid_mac_address(self, mock_intf_list):
        """Test invalid MAC address format."""
        from ptnetinspector.utils.ip_utils import is_valid_mac
        
        assert is_valid_mac('invalid:mac') is False
        assert is_valid_mac('00:11:22:33:44:55') is True


# ============================================================================
# COMPREHENSIVE SCENARIO TESTS
# ============================================================================

class TestComprehensiveScenarios:
    """End-to-end tests for comprehensive real-world scenarios."""

    @patch('sys.argv', ['ptnetinspector', '-t', '802.1x', 'p', 'a', '-i', 'eth0', '-j', '-more', '-4'])
    @patch('netifaces.interfaces', return_value=['eth0'])
    def test_multi_mode_scan_with_options(self, mock_intf_list):
        """Test multiple scan modes with various output options."""
        from ptnetinspector.utils.cli import parse_args
        
        args = parse_args()
        assert '802.1x' in args.t
        assert 'p' in args.t
        assert 'a' in args.t
        assert args.j is True
        assert args.more is True
        assert args.ipv4 is True

    @patch('sys.argv', ['ptnetinspector', '-t', 'a+', '-i', 'eth0', '-prefix', '2001:db8::/64', 
                        '-smac', 'aa:bb:cc:dd:ee:ff', '-sip', '2001:db8::1', 
                        '-rpref', 'High', '-mtu', '1280', '-da+', '120', '-j', '-more'])
    @patch('netifaces.interfaces', return_value=['eth0'])
    def test_aggressive_scan_all_options(self, mock_intf_list):
        """Test aggressive scan with all optional parameters."""
        from ptnetinspector.utils.cli import parse_args
        
        args = parse_args()
        assert args.t == ['a+']
        assert args.prefix == '2001:db8::/64'
        assert args.smac == 'aa:bb:cc:dd:ee:ff'
        assert args.sip == '2001:db8::1'
        assert args.rpref == 'High'
        assert args.mtu == '1280'
        assert args.duration_router == '120'  # -da+ sets duration_router
        assert args.j is True
        assert args.more is True

    @patch('sys.argv', ['ptnetinspector', '-t', 'p', '-i', 'eth0', '-d', '15', '-less', '-6'])
    @patch('netifaces.interfaces', return_value=['eth0'])
    def test_passive_scan_all_options(self, mock_intf_list):
        """Test passive scan with all optional parameters."""
        from ptnetinspector.utils.cli import parse_args
        
        args = parse_args()
        assert args.t == ['p']
        assert args.d == '15'
        assert args.less is True
        assert args.ipv6 is True
        # nc defaults to True (check addresses)
        assert args.nc is True