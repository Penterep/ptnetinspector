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

    def test_device_summary_uses_device_mac_ip_port_table_with_likely_os(self, scan_dir):
        with open(scan_dir / "addresses.csv", "w", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(["MAC", "IP"])
            writer.writerow(["00:0c:29:5c:c5:a5", "192.168.1.3"])
            writer.writerow(["00:0c:29:5c:c5:a5", "fe80::79d2:f812:ba84:9484"])
        with open(scan_dir / "role_node.csv", "w", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(["MAC", "Device_Number", "Role"])
            writer.writerow(["00:0c:29:5c:c5:a5", "1", "Node"])
        with open(scan_dir / "fingerprint.csv", "w", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(["MAC", "Hop_limit", "IID_type"])
            writer.writerow(["00:0c:29:5c:c5:a5", "64", "randomized"])
        with open(scan_dir / "localname.csv", "w", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(["MAC", "name"])
            writer.writerow(["00:0c:29:5c:c5:a5", "host-01"])

        from ptnetinspector.output.devices import write_device_inventory

        write_device_inventory(IPMode(True, True))

        text = (scan_dir / "devices.txt").read_text(encoding="utf-8")
        assert "Device Summary" in text
        assert "Network intelligence" not in text
        assert "192.168.1.3" in text
        assert "fe80::79d2:f812:ba84:9484" in text
        assert "Linux / macOS / BSD" not in text
        # The inventory renders as a bordered Device / MAC / Vendor / IP / Port grid.
        assert any(line.replace("|", " ").split() == ["Device", "MAC", "Vendor", "IP", "Port"]
                   for line in text.splitlines())
        assert "00:0c:29:5c:c5:a5" in text
        assert "+" in text and "|" in text

        rows = _rows(scan_dir / "devices.csv")
        assert "Likely OS" not in rows[0].keys()

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

    def test_device_summary_expands_vertically_when_many_values_are_present(self, scan_dir):
        with open(scan_dir / "addresses.csv", "w", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(["MAC", "IP"])
            writer.writerow(["00:0c:29:5c:c5:a5", "192.168.1.3"])
            writer.writerow(["00:0c:29:5c:c5:a5", "fe80::79d2:f812:ba84:9484"])
        with open(scan_dir / "role_node.csv", "w", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(["MAC", "Device_Number", "Role"])
            writer.writerow(["00:0c:29:5c:c5:a5", "1", "Node"])
        with open(scan_dir / "observed_ports.csv", "w", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(["MAC", "IP", "Proto", "Port"])
            writer.writerow(["00:0c:29:5c:c5:a5", "192.168.1.3", "tcp", "80"])
            writer.writerow(["00:0c:29:5c:c5:a5", "192.168.1.3", "udp", "53"])
            writer.writerow(["00:0c:29:5c:c5:a5", "192.168.1.3", "tcp", "443"])

        from ptnetinspector.output.devices import _render_table, collect_devices

        table = _render_table(collect_devices(IPMode(True, True)))
        assert "192.168.1.3" in table
        assert "fe80::79d2:f812:ba84:9484" in table
        assert "80/tcp" in table
        assert "53/udp" in table
        assert "443/tcp" in table
        header = next(line for line in table.splitlines() if "Device" in line and "Port" in line)
        assert header.replace("|", " ").split() == ["Device", "MAC", "Vendor", "IP", "Port"]
        # Each address and each port is on its own line (vertical growth), so the
        # three ports produce three distinct lines rather than one wide cell.
        assert sum(1 for line in table.splitlines() if "/tcp" in line or "/udp" in line) == 3

    def test_many_ports_grow_the_table_down_not_across(self):
        """A host with dozens of ports flows onto more lines, not a wider one.

        Each address and each port takes its own line inside its grid cell, so
        the table grows downward; the width is bounded by one IPv6 column, not by
        how many ports the device has.
        """
        from ptnetinspector.output.devices import _render_device_table

        device = {
            "Device": "1",
            "MAC": "00:0c:29:5c:c5:a5",
            "Vendor": "VMware, Inc.",
            "Role": "Host",
            "Hostname": "host-01",
            "IPv4": "192.168.1.3",
            "IPv6": "fe80::29ea:7c83:de9a:f21d 2001:db8::1",
            "IP_count": "3",
            "Ports": " ".join(f"{port}/tcp" for port in range(1000, 1040)),
        }

        text = _render_device_table([device])
        lines = text.splitlines()
        # 40 ports each take a line; the width stays bounded by the columns (one
        # IPv6, the identity fields), nowhere near 40 ports laid side by side.
        assert sum(1 for line in lines if "/tcp" in line) == 40
        # Bounded by the columns (grid borders + one IPv6), not by 40 ports.
        assert max(len(line) for line in lines) <= 90
        assert "fe80::29ea:7c83:de9a:f21d" in text
        assert "2001:db8::1" in text

    def test_grid_separates_devices_and_shows_identity_once(self):
        """Each device is one grid block; its MAC appears once, not per address."""
        from ptnetinspector.output.devices import _render_device_table

        devices = [
            {"Device": "1", "MAC": "00:0c:29:00:00:01", "Vendor": "", "Role": "Host",
             "Hostname": "", "IPv4": "192.168.1.1 192.168.1.9", "IPv6": "", "IP_count": "2",
             "Ports": "22/tcp 80/tcp"},
            {"Device": "2", "MAC": "00:0c:29:00:00:02", "Vendor": "", "Role": "Host",
             "Hostname": "", "IPv4": "192.168.1.2", "IPv6": "", "IP_count": "1",
             "Ports": ""},
        ]

        text = _render_device_table(devices)
        assert "+" in text and "|" in text  # bordered grid, like the other tables
        # Identity is printed once per device even though device 1 has two IPs.
        assert text.count("00:0c:29:00:00:01") == 1
        assert text.count("00:0c:29:00:00:02") == 1
        # Device 2 has no ports: its Port cell is a dash, not borrowed from device 1.
        assert "-" in text

    def test_summary_survives_an_empty_addresses_file(self, scan_dir):
        """role_node.csv is the device list, so the summary must appear from it.

        Under -nc an aggressive IPv6 run can leave addresses.csv empty by the time
        output runs, even though the devices were discovered (role_node.csv is
        built from the addresses that were there earlier). The inventory used to
        require both files and so vanished entirely; now the devices are reported,
        with ports, and simply carry no address counts.
        """
        # addresses.csv exists but holds only its header - the failing condition.
        with open(scan_dir / "addresses.csv", "w", newline="") as handle:
            csv.writer(handle).writerow(["MAC", "IP"])
        with open(scan_dir / "role_node.csv", "w", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(["MAC", "Device_Number", "Role"])
            writer.writerow(["00:0c:29:35:45:d8", "1", "Host"])
            writer.writerow(["ca:01:08:2b:00:00", "2", "Preferred router;IPv6 default GW"])
        with open(scan_dir / "observed_ports.csv", "w", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(["MAC", "IP", "Proto", "Port"])
            writer.writerow(["00:0c:29:35:45:d8", "", "udp", "5353"])

        from ptnetinspector.output.devices import collect_devices, _render_device_table

        devices = collect_devices(IPMode(ipv4=False, ipv6=True))
        assert len(devices) == 2
        macs = {device["MAC"] for device in devices}
        assert macs == {"00:0c:29:35:45:d8", "ca:01:08:2b:00:00"}
        # Addresses are absent, but the port that was observed still shows.
        assert devices[0]["IPv6"] == ""
        assert "5353/udp" in devices[0]["Ports"]

        text = _render_device_table(devices, 80)
        assert "00:0c:29:35:45:d8" in text
        assert "ca:01:08:2b:00:00" in text

    def test_summary_drops_unspecified_and_derives_possible_addresses(self, scan_dir):
        """-nc records noise; the summary must read as real device addresses.

        The unspecified address "::" is never a host's own and is dropped. A
        solicited-node multicast group is not an address the host owns either, so
        it is turned into the "possible" unicast address it implies - unless a
        confirmed address already accounts for that group, in which case it adds
        nothing and is not shown.
        """
        from ptnetinspector.utils.ip_utils import in6_getnsma
        from ptnetinspector.output.devices import collect_devices, _render_device_table

        confirmed = "fe80::20c:29ff:fe2f:d20c"
        covered_group = in6_getnsma(confirmed)          # already implied by `confirmed`
        orphan_group = "ff02::1:ff00:0005"              # no confirmed address implies it
        with open(scan_dir / "addresses.csv", "w", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(["MAC", "IP"])
            writer.writerow(["00:0c:29:2f:d2:0c", "::"])
            writer.writerow(["00:0c:29:2f:d2:0c", confirmed])
            writer.writerow(["00:0c:29:2f:d2:0c", covered_group])
            writer.writerow(["00:0c:29:2f:d2:0c", orphan_group])
        with open(scan_dir / "role_node.csv", "w", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(["MAC", "Device_Number", "Role"])
            writer.writerow(["00:0c:29:2f:d2:0c", "1", "Host"])

        devices = collect_devices(IPMode(ipv4=False, ipv6=True), include_solicited_node=True)
        device = devices[0]
        assert device["IPv6"] == confirmed            # "::" and the groups are not here
        assert "::" not in device["IPv6"].split()
        # The orphan group becomes one possible address; the covered one does not.
        possible = device["IPv6_possible"].split()
        assert len(possible) == 1 and possible[0].endswith("0005")

        text = _render_device_table(devices, 120)
        assert f"{confirmed}" in text
        assert "(possible)" in text
        assert "ff02::1:ff00:0005" not in text        # shown derived, not raw

    def test_validate_keeps_addresses_when_unfiltered_is_header_only(self, scan_dir):
        """A fresh scan must not have its addresses.csv wiped during validation.

        addresses_unfiltered.csv is created with a header up front, so the old
        size>0 check treated it as populated, read zero mappings from it, and
        rewrote addresses.csv empty - which is what left the -nc aggressive run
        with no addresses and no device inventory even though devices were found.
        """
        from ptnetinspector.utils.address_control import validate_addresses_mapping
        from ptnetinspector.utils.csv_helpers import has_additional_data

        # The scan has already converted packets.csv into addresses.csv ...
        with open(scan_dir / "addresses.csv", "w", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(["MAC", "IP"])
            writer.writerow(["00:0c:29:35:45:d8", "fe80::29ea:7c83:de9a:f21d"])
            writer.writerow(["00:0c:29:35:45:d8", "2001:db8::1"])
        # ... while the unfiltered file still holds only its header.
        with open(scan_dir / "addresses_unfiltered.csv", "w", newline="") as handle:
            csv.writer(handle).writerow(["MAC", "IP"])

        validate_addresses_mapping(
            "testiface", IPMode(ipv4=False, ipv6=True), passive=True, verify=False,
        )

        assert has_additional_data(str(scan_dir / "addresses.csv"))
        text = (scan_dir / "addresses.csv").read_text(encoding="utf-8")
        assert "2001:db8::1" in text
        assert "fe80::29ea:7c83:de9a:f21d" in text

    def test_nc_keeps_local_candidates_but_not_relayed_public_addresses(self, scan_dir):
        """-nc keeps unverified local candidates, but not relayed transit.

        No address is probed, so none may be dropped for being unverified or for
        sitting on a second private range of the segment. But a public address
        routed in through the gateway arrives with the gateway's MAC and the
        remote host's IP; attributing it to the gateway is wrong, so it is kept
        only in addresses_unfiltered.csv, not in the per-device addresses.csv.
        """
        from ptnetinspector.utils.address_control import validate_addresses_mapping

        # The scanner knows its own subnet, which is what makes "off-link"
        # meaningful; without it every IPv4 would be kept as a possible local.
        with open(scan_dir / "networks.csv", "w", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(["Network", "Prefix_length"])
            writer.writerow(["192.168.1.0", "24"])

        kept = [
            ("00:0c:29:5c:c5:a5", "192.168.1.3"),    # on-link IPv4
            ("00:0c:29:5c:c5:a5", "fe80::79d2:f812:ba84:9484"),  # link-local
            ("00:50:56:c0:00:02", "192.168.73.1"),   # off-link but private scope
        ]
        dropped = [
            ("00:50:56:e9:10:2e", "140.82.121.5"),   # public, relayed through gw
            ("00:50:56:e9:10:2e", "18.97.36.59"),    # public, relayed through gw
        ]
        with open(scan_dir / "addresses.csv", "w", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(["MAC", "IP"])
            writer.writerows(kept + dropped)
        with open(scan_dir / "addresses_unfiltered.csv", "w", newline="") as handle:
            csv.writer(handle).writerow(["MAC", "IP"])

        validate_addresses_mapping(
            "testiface", IPMode(ipv4=True, ipv6=True), passive=True, verify=False,
        )

        filtered = (scan_dir / "addresses.csv").read_text(encoding="utf-8")
        for _mac, ip in kept:
            assert ip in filtered, f"{ip} (a local candidate) must be kept under -nc"
        for _mac, ip in dropped:
            assert ip not in filtered, f"{ip} (relayed public) must not be attributed to a device"

        # The raw view keeps absolutely everything.
        raw = (scan_dir / "addresses_unfiltered.csv").read_text(encoding="utf-8")
        for _mac, ip in kept + dropped:
            assert ip in raw, f"{ip} must still appear in the unfiltered view"

    def test_handle_output_keeps_device_summary_visible_in_verbose_json_mode(self, scan_dir, capsys):
        with open(scan_dir / "addresses.csv", "w", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(["MAC", "IP"])
            writer.writerow(["00:0c:29:5c:c5:a5", "192.168.1.3"])
            writer.writerow(["00:0c:29:5c:c5:a5", "fe80::79d2:f812:ba84:9484"])
        with open(scan_dir / "role_node.csv", "w", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(["MAC", "Device_Number", "Role"])
            writer.writerow(["00:0c:29:5c:c5:a5", "1", "Node"])
        with open(scan_dir / "vulnerability_mac.csv", "w", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(["ID", "MAC", "Mode", "IPver", "Code", "Description", "Label"])
            writer.writerow(["1", "00:0c:29:5c:c5:a5", "a", "4", "PTV-TEST-1", "Demo", "1"])
        with open(scan_dir / "vulnerability_net.csv", "w", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(["ID", "Mode", "Code", "Description", "Label"])
            writer.writerow(["Network", "a", "PTV-NET-1", "Demo", "1"])

        from ptnetinspector.utils.runtime import configure_output_flags
        from ptnetinspector.utils.runtime import handle_output
        from ptnetinspector.send.send import IPMode

        configure_output_flags(json_output=True, more_detail=True, less_detail=False)
        handle_output(
            "a",
            [],
            [],
            json_output=True,
            more_detail=True,
            less_detail=False,
            check_addresses=True,
            interface="eth0",
            ip_mode=IPMode(True, True),
            target_codes=None,
            get_csv_path_fn=lambda name: str(scan_dir / name),
            target_macs=None,
            target_ips=None,
        )

        captured = capsys.readouterr()
        assert "Device Summary" in captured.out
        assert "192.168.1.3" in captured.out
        assert "fe80::79d2:f812:ba84:9484" in captured.out
        # The Device Summary is placed between the two vulnerability sections.
        assert (captured.out.index("Vulnerability Summary")
                < captured.out.index("Device Summary")
                < captured.out.index("Vulnerability Matrix"))

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
            # a device whose addresses never answered still has to be findable
            ("00:1b:21:33:44:55", "", ""),
            ("ca:02:69:30:00:08", "192.168.1.1", "4"),
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

    def test_fingerprint_makes_no_os_claim(self, scan_dir):
        # The hop-limit OS guess was removed entirely: without active port
        # probing it misled more than it informed (ND mandates hop limit 255,
        # which the old heuristic read as router-class hardware for every host
        # answering an NS). The fingerprint now carries no OS column at all.
        packet = Ether(raw(
            Ether(src="aa:bb:cc:00:00:09") / IPv6(src="fe80::9") / ICMPv6ND_RA()
        ))

        _save([packet])

        rows = [row for row in _rows(scan_dir / "fingerprint.csv") if row["MAC"] == "aa:bb:cc:00:00:09"]
        assert rows
        assert all("OS_guess" not in row for row in rows)


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


class TestVendorLookup:
    """The MAC vendor is the one reliable device label, so its lookup must cover
    the smaller IEEE allocations, not just the classic /24 OUI blocks."""

    def _db(self, tmp_path):
        from ptnetinspector.utils.oui import load_mac_database
        manuf = tmp_path / "manuf"
        manuf.write_text(
            "# comment line\n"
            "00:0C:29\tVMware\tVMware, Inc.\n"
            "00:55:DA:00/28\tShinko\tShinko Technos co.,ltd.\n"
            "00:1B:C5:00:00/36\tConverging\tConverging Systems Inc.\n"
            "00:1B:C5:00:10/36\tOpenRB\tOpenRB.com, Direct SIA\n",
            encoding="utf-8",
        )
        return load_mac_database(str(manuf))

    def test_ma_l_24_bit_oui_still_resolves(self, tmp_path):
        from ptnetinspector.utils.oui import get_vendor
        assert get_vendor("00:0c:29:aa:bb:cc", self._db(tmp_path)) == "VMware, Inc."

    def test_ma_m_28_bit_block_resolves(self, tmp_path):
        # Regression: the /28 mask used to be stripped and the vendor lost.
        from ptnetinspector.utils.oui import get_vendor
        assert get_vendor("00:55:DA:05:11:22", self._db(tmp_path)) == "Shinko Technos co.,ltd."

    def test_ma_s_36_bit_blocks_resolve_to_distinct_vendors(self, tmp_path):
        # Two /36 blocks share a /24; the longer prefix must win, not collapse.
        from ptnetinspector.utils.oui import get_vendor
        db = self._db(tmp_path)
        assert get_vendor("00:1b:c5:00:05:66", db) == "Converging Systems Inc."
        assert get_vendor("00:1b:c5:00:15:66", db) == "OpenRB.com, Direct SIA"

    def test_locally_administered_mac_is_named_not_called_unknown(self, tmp_path):
        from ptnetinspector.utils.oui import get_vendor
        for mac in ("ca:01:08:2b:00:00", "02:00:00:00:00:01"):
            assert get_vendor(mac, self._db(tmp_path)) == "Locally administered (no vendor)"

    def test_globally_unique_but_absent_mac_is_unknown(self, tmp_path):
        from ptnetinspector.utils.oui import get_vendor
        assert get_vendor("08:00:27:11:22:33", self._db(tmp_path)) == "Unknown Vendor"


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
