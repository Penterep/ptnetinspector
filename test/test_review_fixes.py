"""Regression tests for the issues raised in the v0.2.1 code review and the
`úpravy ptnetinspector` feedback.

Each test names the item it covers so a future change that reintroduces the
behaviour fails here rather than in the field.
"""
import csv
import ipaddress
import os
from unittest.mock import patch

import pytest
from scapy.all import Ether, IP, IPv6, UDP, raw
from scapy.contrib.igmpv3 import IGMPv3, IGMPv3gr, IGMPv3mr
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet6 import (
    ICMPv6MLDMultAddrRec,
    ICMPv6MLReport2,
    ICMPv6ND_RA,
    ICMPv6NDOptCaptivePortal,
    ICMPv6NDOptDNSSL,
    ICMPv6NDOptPREF64,
    ICMPv6NDOptPrefixInfo,
    ICMPv6NDOptRouteInfo,
)

from ptnetinspector.send.send import IPMode
from ptnetinspector.utils.address_control import AddressMapping, filter_unicast_addresses
from ptnetinspector.utils.csv_helpers import _ip_sort_key, create_csv
from ptnetinspector.utils.ip_utils import classify_ipv6_iid, is_multicast_ipv4, is_valid_ipv6
from ptnetinspector.utils.path import get_csv_path, get_tmp_path, set_current_interface


@pytest.fixture
def scan_dir(tmp_path, monkeypatch):
    """Point the CSV artifacts at a throwaway directory."""
    monkeypatch.setattr("ptnetinspector.utils.path.get_output_dir", lambda base_path=None: tmp_path)
    set_current_interface("testiface")
    create_csv("testiface")
    yield get_tmp_path("testiface")
    set_current_interface(None)


def _save(packets):
    from ptnetinspector.scan import Save

    Save.save_packets("lo", IPMode(True, True), packets)


def _rows(path):
    with open(path, newline="") as handle:
        return list(csv.DictReader(handle))


class TestMalformedPacketsDoNotAbortTheScan:
    """H1/H2: one bad frame used to discard every result collected so far."""

    def test_mldv2_records_number_larger_than_record_list(self, scan_dir):
        packet = Ether(raw(
            Ether(src="aa:bb:cc:00:00:01") / IPv6(src="fe80::1")
            / ICMPv6MLReport2(records_number=4,
                              records=[ICMPv6MLDMultAddrRec(dst="ff02::1:ff00:1")])
        ))

        _save([packet])

        rows = _rows(scan_dir / "MLDv2.csv")
        assert len(rows) == 1
        assert rows[0]["mulip"] == "ff02::1:ff00:1"

    def test_igmpv3_numgrp_larger_than_record_list(self, scan_dir):
        packet = Ether(raw(
            Ether(src="aa:bb:cc:00:00:02") / IP(src="10.0.0.2")
            / IGMPv3(type=0x22) / IGMPv3mr(numgrp=5, records=[IGMPv3gr(maddr="224.0.0.251")])
        ))

        _save([packet])

        rows = _rows(scan_dir / "IGMPv3.csv")
        assert len(rows) == 1
        assert rows[0]["mulip"] == "224.0.0.251"

    def test_dhcp_with_no_options(self, scan_dir):
        packet = (Ether(src="aa:bb:cc:00:00:03") / IP(src="10.0.0.3")
                  / UDP(sport=68, dport=67) / BOOTP() / DHCP(options=[]))

        _save([packet])

        assert _rows(scan_dir / "dhcp.csv") == []

    def test_dhcp_message_type_is_not_the_first_option(self, scan_dir):
        # RFC 2131 does not require message-type first, and ACK (5) - not just
        # OFFER (2) - identifies the server.
        packet = Ether(raw(
            Ether(src="aa:bb:cc:00:00:04") / IP(src="10.0.0.4")
            / UDP(sport=67, dport=68) / BOOTP()
            / DHCP(options=[("server_id", "10.0.0.4"), ("message-type", 5), "end"])
        ))

        _save([packet])

        rows = _rows(scan_dir / "dhcp.csv")
        assert any(row["IP"] == "10.0.0.4" and row["Role"] == "server" for row in rows)


class TestRouterAdvertisementOptions:
    """M2/E4: only the first prefix was kept and most options were discarded."""

    @staticmethod
    def _multi_option_ra():
        return Ether(raw(
            Ether(src="aa:bb:cc:00:00:05") / IPv6(src="fe80::5") / ICMPv6ND_RA()
            / ICMPv6NDOptPrefixInfo(prefix="2001:db8:1::", prefixlen=64)
            / ICMPv6NDOptPrefixInfo(prefix="fd00:1::", prefixlen=64)
            / ICMPv6NDOptDNSSL(searchlist=["corp.internal"])
            / ICMPv6NDOptRouteInfo(prefix="2001:db8:99::", plen=48)
            / ICMPv6NDOptPREF64(prefix="64:ff9b::")
            / ICMPv6NDOptCaptivePortal(URI=b"https://portal.example/")
        ))

    def test_every_advertised_prefix_is_recorded(self, scan_dir):
        _save([self._multi_option_ra()])

        prefixes = {row["Prefix"] for row in _rows(scan_dir / "RA.csv")}
        assert prefixes == {"2001:db8:1::/64", "fd00:1::/64"}

    def test_previously_ignored_options_are_recorded(self, scan_dir):
        _save([self._multi_option_ra()])

        options = {row["Option"]: row["Value"] for row in _rows(scan_dir / "ra_options.csv")}
        assert options["DNSSL"] == "corp.internal"
        assert options["Route Information"] == "2001:db8:99::/48"
        assert options["PREF64"] == "64:ff9b::"
        assert options["Captive Portal"] == "https://portal.example/"


class TestIPv6Validation:
    """M1: the hand-rolled regex used 25[0-4] for embedded IPv4 octets."""

    @pytest.mark.parametrize("address", [
        "::ffff:192.168.1.255",
        "::ffff:255.255.255.255",
        "2001:db8::ffff:10.0.0.255",
    ])
    def test_embedded_ipv4_octet_255_is_valid(self, address):
        assert is_valid_ipv6(address) is True
        # The stdlib is the authority these must agree with.
        assert ipaddress.IPv6Address(address)

    def test_zone_identifiers_are_still_rejected(self):
        assert is_valid_ipv6("fe80::1%eth0") is False

    def test_non_strings_are_rejected(self):
        assert is_valid_ipv6(None) is False
        assert is_valid_ipv6(1.5) is False


class TestNoCheckKeepsEverythingObserved:
    """DOCX/-nc: addresses outside the detected subnet were dropped anyway."""

    OFFLINK = AddressMapping(mac="00:50:56:c0:00:02", ip="192.168.73.1")
    ONLINK = AddressMapping(mac="00:0c:29:5c:c5:a5", ip="192.168.1.3")

    def _filter(self, **kwargs):
        subnets = ([ipaddress.ip_network("192.168.1.0/24")],
                   [ipaddress.ip_network("2a00:a:b:1::/64")])
        with patch("ptnetinspector.entities.networks.Networks.load_networks", return_value=subnets), \
             patch("ptnetinspector.entities.networks.Networks.load_ra_prefixes", return_value=[]):
            return filter_unicast_addresses([self.ONLINK, self.OFFLINK], IPMode(True, True), **kwargs)

    def test_offlink_address_is_filtered_by_default(self):
        kept = {mapping.ip for mapping in self._filter()}
        assert kept == {"192.168.1.3"}

    def test_offlink_address_is_kept_under_nc(self):
        kept = {mapping.ip for mapping in self._filter(keep_solicited_node=True, keep_offlink=True)}
        assert kept == {"192.168.1.3", "192.168.73.1"}

    def test_public_transit_addresses_stay_out_even_under_nc(self):
        # Addresses are attributed to the MAC that sent the frame, so a packet
        # routed through the gateway carries the gateway's MAC with a remote
        # host's address. Keeping those would report 8.8.8.8 as the gateway's.
        transit = AddressMapping(mac="ca:02:69:30:00:08", ip="8.8.8.8")
        subnets = ([ipaddress.ip_network("192.168.1.0/24")], [])
        with patch("ptnetinspector.entities.networks.Networks.load_networks", return_value=subnets), \
             patch("ptnetinspector.entities.networks.Networks.load_ra_prefixes", return_value=[]):
            kept = filter_unicast_addresses(
                [self.ONLINK, self.OFFLINK, transit], IPMode(True, True),
                keep_solicited_node=True, keep_offlink=True,
            )

        addresses = {mapping.ip for mapping in kept}
        assert "192.168.73.1" in addresses   # a neighbour on another private range
        assert "8.8.8.8" not in addresses    # a host beyond the router

    def test_unspecified_address_is_never_kept(self):
        with patch("ptnetinspector.entities.networks.Networks.load_networks", return_value=([], [])), \
             patch("ptnetinspector.entities.networks.Networks.load_ra_prefixes", return_value=[]):
            kept = filter_unicast_addresses(
                [AddressMapping(mac="aa:bb:cc:dd:ee:ff", ip="::")],
                IPMode(True, True), keep_solicited_node=True, keep_offlink=True,
            )
        assert kept == []


class TestVulnerabilityAddressFamily:
    """DOCX: IPv4 findings were written against a device's IPv6 addresses."""

    def test_findings_only_reach_addresses_of_their_own_family(self, scan_dir):
        with open(scan_dir / "addresses.csv", "w", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(["MAC", "IP"])
            writer.writerow(["00:0C:29:5C:C5:A5", "192.168.1.3"])
            writer.writerow(["00:0C:29:5C:C5:A5", "2a00:a:b:1:79d2:f812:ba84:9484"])
        with open(scan_dir / "role_node.csv", "w", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(["MAC", "Device_Number", "Role"])
            writer.writerow(["00:0C:29:5C:C5:A5", "1", "Node"])

        from ptnetinspector.vulnerability import Vulnerability

        vulnerability = Vulnerability(
            "testiface", ["a"], IPMode(True, True), "aa:bb:cc:dd:ee:ff", "", 64, 3, []
        )
        vulnerability._write_vulnerabilities([
            {"ID": "1", "MAC": "00:0C:29:5C:C5:A5", "Mode": "a", "IPver": "4",
             "Code": "PTV-NET-IDENT-4-MDNSDEV", "Description": "IPv4 mDNS", "Label": "2"},
            {"ID": "1", "MAC": "00:0C:29:5C:C5:A5", "Mode": "a", "IPver": "6",
             "Code": "PTV-NET-IDENT-6-LLMNRDEV", "Description": "IPv6 LLMNR", "Label": "2"},
        ])

        for row in _rows(get_csv_path("vulnerability_ip.csv")):
            is_ipv6_address = ":" in row["IP"]
            assert row["IPver"] == ("6" if is_ipv6_address else "4")


class TestDeviceInventory:
    """DOCX: a plain device list, readable when a segment has many hosts."""

    def test_inventory_lists_each_device_once_with_its_addresses(self, scan_dir):
        with open(scan_dir / "addresses.csv", "w", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(["MAC", "IP"])
            writer.writerow(["00:0c:29:5c:c5:a5", "192.168.1.3"])
            writer.writerow(["00:0c:29:5c:c5:a5", "fe80::79d2:f812:ba84:9484"])
            writer.writerow(["ca:02:69:30:00:08", "192.168.1.1"])
        with open(scan_dir / "role_node.csv", "w", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(["MAC", "Device_Number", "Role"])
            writer.writerow(["00:0c:29:5c:c5:a5", "1", "Node"])
            writer.writerow(["ca:02:69:30:00:08", "2", "Router"])

        from ptnetinspector.output.devices import write_device_inventory

        count, directory = write_device_inventory(IPMode(True, True))

        assert count == 2
        assert directory is not None
        rows = _rows(scan_dir / "devices.csv")
        assert [row["MAC"] for row in rows] == ["00:0c:29:5c:c5:a5", "ca:02:69:30:00:08"]
        assert rows[0]["IPv4"] == "192.168.1.3"
        assert rows[0]["IPv6"] == "fe80::79d2:f812:ba84:9484"
        assert (scan_dir / "devices.txt").exists()

    def test_the_flat_form_gives_every_address_its_own_row(self, scan_dir):
        """The searchable form Jan asked for: one row per address, not per device.

        The per-device form keeps a host's addresses together in one cell, which
        reads well but cannot be split on the delimiter.
        """
        with open(scan_dir / "addresses.csv", "w", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(["MAC", "IP"])
            writer.writerow(["00:0c:29:5c:c5:a5", "192.168.1.3"])
            writer.writerow(["00:0c:29:5c:c5:a5", "fe80::79d2:f812:ba84:9484"])
            writer.writerow(["ca:02:69:30:00:08", "192.168.1.1"])
            # discovered, but no address confirmed
            writer.writerow(["00:1b:21:33:44:55", ""])
        with open(scan_dir / "role_node.csv", "w", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(["MAC", "Device_Number", "Role"])
            writer.writerow(["00:0c:29:5c:c5:a5", "1", "Node"])
            writer.writerow(["ca:02:69:30:00:08", "2", "Router"])
            writer.writerow(["00:1b:21:33:44:55", "3", "Node"])

        from ptnetinspector.output.devices import write_device_inventory

        write_device_inventory(IPMode(True, True))
        rows = _rows(scan_dir / "device_addresses.csv")

        assert [(row["MAC"], row["IP"], row["IP_version"]) for row in rows] == [
            ("00:0c:29:5c:c5:a5", "192.168.1.3", "4"),
            ("00:0c:29:5c:c5:a5", "fe80::79d2:f812:ba84:9484", "6"),
            ("ca:02:69:30:00:08", "192.168.1.1", "4"),
            # a device whose addresses never answered still has to be findable
            ("00:1b:21:33:44:55", "", ""),
        ]
        # the device's identity repeats on each of its rows, so a match on an
        # address alone is enough to name the host
        assert rows[1]["Device"] == "1" and rows[1]["Role"] == "Node"

    def test_both_forms_describe_the_same_addresses(self, scan_dir):
        """The flat form is derived, so it must not add or lose an address."""
        with open(scan_dir / "addresses.csv", "w", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(["MAC", "IP"])
            for mac, ip in (("00:0c:29:5c:c5:a5", "192.168.1.3"),
                            ("00:0c:29:5c:c5:a5", "fe80::2"),
                            ("00:0c:29:5c:c5:a5", "fe80::10"),
                            ("ca:02:69:30:00:08", "192.168.1.1")):
                writer.writerow([mac, ip])
        with open(scan_dir / "role_node.csv", "w", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(["MAC", "Device_Number", "Role"])
            writer.writerow(["00:0c:29:5c:c5:a5", "1", "Node"])
            writer.writerow(["ca:02:69:30:00:08", "2", "Router"])

        from ptnetinspector.output.devices import write_device_inventory

        write_device_inventory(IPMode(True, True))
        wide = _rows(scan_dir / "devices.csv")
        flat = _rows(scan_dir / "device_addresses.csv")

        assert len(flat) == sum(int(row["IP_count"]) for row in wide)
        assert sorted(row["IP"] for row in flat) == sorted(
            address for row in wide for address in (row["IPv4"] + " " + row["IPv6"]).split())

    def test_a_family_the_scan_excluded_is_absent_from_the_flat_form(self, scan_dir):
        with open(scan_dir / "addresses.csv", "w", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(["MAC", "IP"])
            writer.writerow(["00:0c:29:5c:c5:a5", "192.168.1.3"])
            writer.writerow(["00:0c:29:5c:c5:a5", "fe80::2"])
        with open(scan_dir / "role_node.csv", "w", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(["MAC", "Device_Number", "Role"])
            writer.writerow(["00:0c:29:5c:c5:a5", "1", "Node"])

        from ptnetinspector.output.devices import write_device_inventory

        write_device_inventory(IPMode(ipv4=True, ipv6=False))
        rows = _rows(scan_dir / "device_addresses.csv")

        assert [row["IP"] for row in rows] == ["192.168.1.3"]
        assert all(row["IP_version"] == "4" for row in rows)


class TestPassiveFingerprinting:
    """E5: classify the interface identifier instead of only flagging it."""

    def test_eui64_address_is_traced_back_to_its_mac(self):
        assert classify_ipv6_iid("fe80::c802:69ff:fe30:8", "ca:02:69:30:00:08") == "EUI-64 (MAC derived)"

    def test_randomized_address_is_named_as_such(self):
        result = classify_ipv6_iid("2a00:a:b:1:79d2:f812:ba84:9484", "00:0c:29:5c:c5:a5")
        assert result == "randomized (stable-privacy or temporary)"

    def test_low_bit_address_is_named_as_manual_or_dhcp(self):
        assert classify_ipv6_iid("2a00:a:b:1::1", "ca:02:69:30:00:08") == "low-bit (manual or DHCPv6)"

    def test_invalid_input_yields_no_claim(self):
        assert classify_ipv6_iid("not-an-address", "ca:02:69:30:00:08") == ""

    def test_neighbour_discovery_hop_limits_make_no_os_claim(self, scan_dir):
        # ND mandates hop limit 255; reading it as an OS default reported every
        # host answering an NS as router-class hardware.
        packet = Ether(raw(
            Ether(src="aa:bb:cc:00:00:09") / IPv6(src="fe80::9") / ICMPv6ND_RA()
        ))

        _save([packet])

        rows = [row for row in _rows(scan_dir / "fingerprint.csv") if row["MAC"] == "aa:bb:cc:00:00:09"]
        assert rows
        assert all(row["OS_guess"] == "" for row in rows)


class TestSmallFixes:
    def test_multicast_check_does_not_swallow_control_flow_exceptions(self):
        # L4: a bare except here also caught KeyboardInterrupt and SystemExit.
        assert is_multicast_ipv4("224.0.0.1") is True
        assert is_multicast_ipv4("not-an-ip") is False

    def test_addresses_sort_numerically_with_ipv4_first(self):
        # L7: string ordering put fe80::10 before fe80::2.
        values = ["fe80::10", "fe80::2", "192.168.1.10", "192.168.1.2"]
        assert sorted(values, key=_ip_sort_key) == [
            "192.168.1.2", "192.168.1.10", "fe80::2", "fe80::10",
        ]

    def test_packet_length_column_is_populated(self, scan_dir):
        # L3: packets.csv declared a length column it never wrote.
        packet = Ether(raw(Ether(src="aa:bb:cc:00:00:0a") / IPv6(src="fe80::a") / UDP()))

        _save([packet])

        rows = [row for row in _rows(scan_dir / "packets.csv") if row["src MAC"] == "aa:bb:cc:00:00:0a"]
        assert rows[0]["length"] == str(len(packet))


class TestExitCodes:
    """M3: a script driving the tool could not tell "scan ran" from "you typo'd
    a flag", and the answer changed depending on whether -j was passed."""

    @staticmethod
    def _run(arguments):
        import subprocess
        import sys
        import tempfile

        return subprocess.run(
            [sys.executable, "-m", "ptnetinspector", *arguments],
            capture_output=True,
            env={"HOME": tempfile.mkdtemp(), "PATH": os.environ.get("PATH", "")},
        ).returncode

    def test_help_succeeds(self):
        assert self._run(["-h"]) == 0

    @pytest.mark.parametrize("arguments", [
        ["-t", "a", "-i", "eth0", "--bogus"],
        ["-t", "bogusmode", "-i", "eth0"],
    ])
    def test_usage_errors_exit_2_regardless_of_json(self, arguments):
        assert self._run(arguments) == 2
        assert self._run(arguments + ["-j"]) == 2

    @pytest.mark.parametrize("arguments", [
        ["-t", "a", "-i", "nosuchinterface0"],
        ["-t", "a"],
    ])
    def test_validation_errors_exit_1_regardless_of_json(self, arguments):
        assert self._run(arguments) == 1
        assert self._run(arguments + ["-j"]) == 1
