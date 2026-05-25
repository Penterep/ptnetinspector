"""Tests for runtime tmp-reuse logic (can_reuse_tmp_data, _check_ips_in_addresses)."""
import csv
import pytest
from pathlib import Path

from ptnetinspector.utils.runtime import can_reuse_tmp_data, _check_ips_in_addresses, _check_macs_in_role_node


BASE_SIG = {
    "interface": "eth0",
    "scanning_type": ["a"],
    "check_addresses": False,
    "ip_mode": {"ipv4": True, "ipv6": True},
    "duration_passive": None,
    "duration_aggressive": None,
    "prefix_len": None,
    "network": None,
    "smac": None,
    "sip": None,
    "rpref": None,
    "period": None,
    "chl": None,
    "mtu": None,
    "dns": [],
    "nofwd": False,
    "target_codes": [],
    "target_macs": [],
    "target_ips": [],
}


def _make_sig(**overrides):
    sig = dict(BASE_SIG)
    sig.update(overrides)
    return sig


class TestCheckIpsInAddresses:
    def test_returns_true_when_ip_in_addresses_csv(self, tmp_path):
        addresses = tmp_path / "addresses.csv"
        with open(addresses, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["MAC", "IP"])
            writer.writerow(["aa:bb:cc:dd:ee:ff", "192.168.1.1"])

        assert _check_ips_in_addresses(tmp_path, {"192.168.1.1"}) is True

    def test_returns_true_when_ip_in_addresses_unfiltered_csv(self, tmp_path):
        unfiltered = tmp_path / "addresses_unfiltered.csv"
        with open(unfiltered, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["MAC", "IP"])
            writer.writerow(["aa:bb:cc:dd:ee:ff", "10.0.0.1"])

        assert _check_ips_in_addresses(tmp_path, {"10.0.0.1"}) is True

    def test_returns_false_when_ip_not_in_any_csv(self, tmp_path):
        addresses = tmp_path / "addresses.csv"
        with open(addresses, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["MAC", "IP"])
            writer.writerow(["aa:bb:cc:dd:ee:ff", "192.168.1.1"])

        assert _check_ips_in_addresses(tmp_path, {"10.99.99.99"}) is False

    def test_returns_false_when_no_csv_files_exist(self, tmp_path):
        assert _check_ips_in_addresses(tmp_path, {"192.168.1.1"}) is False

    def test_ipv6_normalization(self, tmp_path):
        """IPs stored by scapy (compressed) match normalized target IPs."""
        addresses = tmp_path / "addresses.csv"
        with open(addresses, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["MAC", "IP"])
            writer.writerow(["aa:bb:cc:dd:ee:ff", "fe80::1"])

        assert _check_ips_in_addresses(tmp_path, {"fe80::1"}) is True

    def test_multiple_targets_all_must_be_present(self, tmp_path):
        addresses = tmp_path / "addresses.csv"
        with open(addresses, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["MAC", "IP"])
            writer.writerow(["aa:bb:cc:dd:ee:ff", "192.168.1.1"])

        assert _check_ips_in_addresses(tmp_path, {"192.168.1.1", "10.0.0.1"}) is False


class TestCanReuseTargetIps:
    def test_no_target_ips_both_sides_can_reuse(self):
        sig = _make_sig(target_ips=[])
        assert can_reuse_tmp_data(sig, sig) is True

    def test_saved_has_target_ip_current_has_none_cannot_reuse(self):
        current = _make_sig(target_ips=[])
        saved = _make_sig(target_ips=["192.168.1.1"])
        assert can_reuse_tmp_data(current, saved) is False

    def test_saved_no_target_current_has_target_ip_found_can_reuse(self, tmp_path):
        addresses = tmp_path / "addresses.csv"
        with open(addresses, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["MAC", "IP"])
            writer.writerow(["aa:bb:cc:dd:ee:ff", "192.168.1.1"])

        current = _make_sig(target_ips=["192.168.1.1"])
        saved = _make_sig(target_ips=[])
        assert can_reuse_tmp_data(current, saved, tmp_path) is True

    def test_saved_no_target_current_has_target_ip_not_found_cannot_reuse(self, tmp_path):
        addresses = tmp_path / "addresses.csv"
        with open(addresses, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["MAC", "IP"])
            writer.writerow(["aa:bb:cc:dd:ee:ff", "192.168.1.1"])

        current = _make_sig(target_ips=["10.99.99.99"])
        saved = _make_sig(target_ips=[])
        assert can_reuse_tmp_data(current, saved, tmp_path) is False

    def test_both_have_same_target_ip_can_reuse(self):
        sig = _make_sig(target_ips=["192.168.1.1"])
        assert can_reuse_tmp_data(sig, sig) is True

    def test_current_is_subset_of_saved_target_ips_can_reuse(self):
        current = _make_sig(target_ips=["192.168.1.1"])
        saved = _make_sig(target_ips=["192.168.1.1", "10.0.0.1"])
        assert can_reuse_tmp_data(current, saved) is True

    def test_current_not_subset_of_saved_target_ips_cannot_reuse(self):
        current = _make_sig(target_ips=["192.168.1.1", "10.99.99.99"])
        saved = _make_sig(target_ips=["192.168.1.1"])
        assert can_reuse_tmp_data(current, saved) is False

    def test_ipv6_target_found_in_results_can_reuse(self, tmp_path):
        addresses = tmp_path / "addresses.csv"
        with open(addresses, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["MAC", "IP"])
            writer.writerow(["aa:bb:cc:dd:ee:ff", "fe80::1"])

        current = _make_sig(target_ips=["fe80::1"])
        saved = _make_sig(target_ips=[])
        assert can_reuse_tmp_data(current, saved, tmp_path) is True

    def test_ipv4_target_not_found_cannot_reuse(self, tmp_path):
        addresses = tmp_path / "addresses.csv"
        with open(addresses, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["MAC", "IP"])
            writer.writerow(["aa:bb:cc:dd:ee:ff", "192.168.1.1"])

        current = _make_sig(target_ips=["192.168.1.99"])
        saved = _make_sig(target_ips=[])
        assert can_reuse_tmp_data(current, saved, tmp_path) is False
