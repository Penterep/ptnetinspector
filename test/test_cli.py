"""Tests for CLI argument parsing."""
import pytest
from unittest.mock import patch, Mock
import sys
from ptnetinspector.utils.cli import parse_args, blockPrint, enablePrint


class TestCLIParsing:
    """Test command-line argument parsing."""

    @patch('sys.argv', ['ptnetinspector', '-t', 'p', '-i', 'eth0'])
    def test_parse_args_passive(self):
        """Test parsing passive scan arguments."""
        args = parse_args()
        assert args.t == ['p']
        assert args.interface == 'eth0'

    @patch('sys.argv', ['ptnetinspector', '-t', 'a', '-i', 'eth0', '-j'])
    def test_parse_args_active_json(self):
        """Test parsing active scan with JSON output."""
        args = parse_args()
        assert args.t == ['a']
        assert args.interface == 'eth0'
        assert args.j is True

    @patch('sys.argv', ['ptnetinspector', '-t', 'a+', '-i', 'eth0', '-prefix', '2001:db8::/64'])
    def test_parse_args_aggressive_with_prefix(self):
        """Test parsing aggressive scan with prefix."""
        args = parse_args()
        assert args.t == ['a+']
        assert args.interface == 'eth0'
        assert args.prefix == '2001:db8::/64'

    @patch('sys.argv', ['ptnetinspector', '-t', '802.1x', 'p', '-i', 'eth0'])
    def test_parse_args_multiple_modes(self):
        """Test parsing multiple scan modes."""
        args = parse_args()
        assert '802.1x' in args.t
        assert 'p' in args.t
        assert args.interface == 'eth0'

    @patch('sys.argv', ['ptnetinspector', '-t', 'a+', '-i', 'eth0', '-dns', '2001:db8::1', '2001:db8::2'])
    def test_parse_args_multiple_dns(self):
        """Test parsing multiple DNS servers."""
        args = parse_args()
        assert args.dns == ['2001:db8::1', '2001:db8::2']

    @patch('sys.argv', ['ptnetinspector', '-t', 'p', '-i', 'eth0', '-4'])
    def test_parse_args_ipv4_only(self):
        """Test parsing IPv4-only mode."""
        args = parse_args()
        assert args.ipv4 is True
        assert args.ipv6 is False

    @patch('sys.argv', ['ptnetinspector', '-t', 'p', '-i', 'eth0', '-6'])
    def test_parse_args_ipv6_only(self):
        """Test parsing IPv6-only mode."""
        args = parse_args()
        assert args.ipv4 is False
        assert args.ipv6 is True

    def test_block_and_enable_print(self, capsys):
        """Test blocking and enabling print output."""
        # Test that blockPrint actually blocks output
        print("Before block")
        
        blockPrint()
        print("During block - should not appear")
        
        enablePrint()
        print("After enable")
        
        # Capture the output
        captured = capsys.readouterr()
        
        # Verify blocking worked
        assert "Before block" in captured.out
        assert "During block" not in captured.out
        assert "After enable" in captured.out
