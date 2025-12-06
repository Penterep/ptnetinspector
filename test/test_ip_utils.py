"""Tests for IP utility functions."""
import pytest
from ptnetinspector.utils.ip_utils import (
    is_valid_ipv4,
    is_valid_ipv6,
    is_valid_mac,
    is_valid_ipv6_prefix,
    is_global_unicast_ipv6,
    is_link_local_ipv6,
    is_ipv6_ula,
    is_non_negative_float,
    is_valid_integer,
    is_valid_MTU,
    check_ipv6_addresses_generated_from_prefix,
)


class TestIPv4Validation:
    """Test IPv4 address validation."""

    def test_valid_ipv4(self):
        assert is_valid_ipv4("192.168.1.1") is True
        assert is_valid_ipv4("10.0.0.1") is True
        assert is_valid_ipv4("172.16.0.1") is True
        assert is_valid_ipv4("8.8.8.8") is True

    def test_invalid_ipv4(self):
        assert is_valid_ipv4("256.1.1.1") is False
        assert is_valid_ipv4("192.168.1") is False
        assert is_valid_ipv4("192.168.1.1.1") is False
        assert is_valid_ipv4("not.an.ip.address") is False
        assert is_valid_ipv4("") is False


class TestIPv6Validation:
    """Test IPv6 address validation."""

    def test_valid_ipv6(self):
        assert is_valid_ipv6("2001:db8::1") is True
        assert is_valid_ipv6("fe80::1") is True
        assert is_valid_ipv6("::1") is True
        assert is_valid_ipv6("2001:0db8:0000:0000:0000:0000:0000:0001") is True

    def test_invalid_ipv6(self):
        assert is_valid_ipv6("not:valid:ipv6") is False
        assert is_valid_ipv6("") is False
        assert is_valid_ipv6(None) is False
        assert is_valid_ipv6(12345) is False

    def test_link_local_ipv6(self):
        assert is_link_local_ipv6("fe80::1") is True
        assert is_link_local_ipv6("fe80::abcd:ef01:2345:6789") is True
        assert is_link_local_ipv6("2001:db8::1") is False
        assert is_link_local_ipv6("192.168.1.1") is False

    def test_global_unicast_ipv6(self):
        assert is_global_unicast_ipv6("2001:db8::1") is True
        assert is_global_unicast_ipv6("fe80::1") is False
        assert is_global_unicast_ipv6("ff02::1") is False  # Multicast

    def test_ipv6_ula(self):
        assert is_ipv6_ula("fd00::1") is True
        assert is_ipv6_ula("fc00::1") is True
        assert is_ipv6_ula("2001:db8::1") is False
        assert is_ipv6_ula("fe80::1") is False


class TestIPv6Prefix:
    """Test IPv6 prefix validation."""

    def test_valid_prefix(self):
        assert is_valid_ipv6_prefix("2001:db8::/32") is True
        assert is_valid_ipv6_prefix("fe80::/64") is True
        assert is_valid_ipv6_prefix("::1/128") is True

    def test_invalid_prefix(self):
        assert is_valid_ipv6_prefix("not-a-prefix") is False
        assert is_valid_ipv6_prefix("2001:db8::/129") is False

    def test_prefix_generation(self):
        assert check_ipv6_addresses_generated_from_prefix("2001:db8::1", "2001:db8::/32") is True
        assert check_ipv6_addresses_generated_from_prefix("2001:db8::1", "2001:abc::/32") is False
        assert check_ipv6_addresses_generated_from_prefix("fe80::1", "fe80::/64") is True


class TestMACValidation:
    """Test MAC address validation."""

    def test_valid_mac(self):
        assert is_valid_mac("00:11:22:33:44:55") is True
        assert is_valid_mac("AA:BB:CC:DD:EE:FF") is True
        assert is_valid_mac("aa:bb:cc:dd:ee:ff") is True
        assert is_valid_mac("00-11-22-33-44-55") is True

    def test_invalid_mac(self):
        assert is_valid_mac("00:11:22:33:44") is False
        assert is_valid_mac("00:11:22:33:44:55:66") is False
        assert is_valid_mac("not-a-mac") is False
        assert is_valid_mac(None) is False
        assert is_valid_mac("") is False


class TestNumericValidation:
    """Test numeric validation functions."""

    def test_non_negative_float(self):
        assert is_non_negative_float("0") is True
        assert is_non_negative_float("1.5") is True
        assert is_non_negative_float("100") is True
        assert is_non_negative_float("-1") is False
        assert is_non_negative_float("not_a_number") is False

    def test_valid_integer(self):
        assert is_valid_integer("0") is True
        assert is_valid_integer("127") is True
        assert is_valid_integer("255") is True
        assert is_valid_integer("256") is False
        assert is_valid_integer("-1") is False
        assert is_valid_integer("not_a_number") is False

    def test_valid_mtu(self):
        assert is_valid_MTU("1500") is True
        assert is_valid_MTU("9000") is True
        assert is_valid_MTU("65535") is True
        assert is_valid_MTU("0") is True
        assert is_valid_MTU("65536") is False
        assert is_valid_MTU("-1") is False
        assert is_valid_MTU("not_a_number") is False
