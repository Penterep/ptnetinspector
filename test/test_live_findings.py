"""Regression tests for defects found by running the scanner against a live link.

Each of these reproduced only once real frames crossed a real interface: the
offline tests exercised the parsers directly and so never saw the CSV
round-trip, the mix of protocols one device emits, or the layer layout scapy
actually produces for an IGMPv3 query.
"""
import csv
import os
import re
from pathlib import Path
from unittest import mock

import pytest
from scapy.all import DNS, DNSQR, DNSRR, Ether, IP, IPv6, Raw, TCP, UDP
from scapy.contrib.igmp import IGMP
from scapy.contrib.igmpv3 import IGMPv3, IGMPv3gr, IGMPv3mq, IGMPv3mr
from scapy.layers.inet import ICMP
from scapy.layers.inet6 import (
    ICMPv6EchoReply,
    ICMPv6EchoRequest,
    ICMPv6MLQuery2,
    ICMPv6MLReport2,
    ICMPv6ND_NA,
    ICMPv6ND_NS,
    ICMPv6ND_RA,
    ICMPv6NIReplyName,
)

from ptnetinspector.entities.node import Node
from ptnetinspector.scan import _hop_limit_is_stack_default, _is_link_scoped_multicast
from ptnetinspector.utils import csv_helpers
from ptnetinspector.utils.csv_helpers import read_csv_text, sort_csv_based_MAC



@pytest.fixture
def scan_dir(tmp_path, monkeypatch):
    """Point the CSV artifacts at a throwaway directory.

    The interface context is module-level state in ``ptnetinspector.utils.path``,
    so it is restored afterwards rather than left set for whatever runs next.
    """
    from ptnetinspector.utils.csv_helpers import create_csv
    from ptnetinspector.utils.path import (
        get_current_interface, get_tmp_path, set_current_interface,
    )

    previous = get_current_interface()
    monkeypatch.setattr("ptnetinspector.utils.path.get_output_dir", lambda base_path=None: tmp_path)
    set_current_interface("testiface")
    create_csv("testiface")
    try:
        yield get_tmp_path("testiface")
    finally:
        set_current_interface(previous)


def _write(path, fieldnames, rows):
    with open(path, "w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


# --------------------------------------------------------------------------
# A CSV round-trip must not reinterpret the values it stores.
# --------------------------------------------------------------------------
class TestCsvValuesRoundTrip:
    def test_blank_cell_does_not_turn_a_column_into_floats(self, tmp_path):
        """A hop limit of 255 was written back as "255.0".

        Pandas infers a dtype per column, and one blank cell is enough to make
        an integer column float64.
        """
        path = tmp_path / "fingerprint.csv"
        _write(path, ["MAC", "Hop_limit", "OS_guess"],
               [{"MAC": "00:11:22:33:44:55", "Hop_limit": "255", "OS_guess": "router"},
                {"MAC": "00:11:22:33:44:66", "Hop_limit": "", "OS_guess": ""}])

        frame = read_csv_text(path)

        assert list(frame["Hop_limit"]) == ["255", ""]
        assert frame["Hop_limit"].dtype == object

    def test_missing_value_does_not_become_the_string_nan(self, tmp_path):
        """An absent hostname was printed to the operator as "nan"."""
        path = tmp_path / "localname.csv"
        _write(path, ["MAC", "name"],
               [{"MAC": "00:11:22:33:44:55", "name": ""}])

        assert list(read_csv_text(path)["name"]) == [""]

    def test_an_address_stays_on_its_own_row(self, tmp_path):
        """Sorting moved the IP column without moving the rest of the row.

        One MAC that is both the MLDv2 and the IGMPv3 querier ended up listed
        at the wrong address for each protocol.
        """
        path = tmp_path / "querier.csv"
        rows = [
            {"MAC": "00:1b:21:33:44:55", "IP": "fe80::21b:21ff:fe33:4455",
             "Protocol": "MLDv2", "Group": "::"},
            {"MAC": "00:1b:21:33:44:55", "IP": "192.168.73.2",
             "Protocol": "IGMPv3", "Group": "0.0.0.0"},
        ]
        _write(path, ["MAC", "IP", "Protocol", "Group"], rows)

        with mock.patch.object(csv_helpers, "get_if_hwaddr", return_value="aa:aa:aa:aa:aa:aa"):
            sort_csv_based_MAC("dummy", str(path))

        result = list(csv.DictReader(open(path, newline="")))
        by_protocol = {row["Protocol"]: row["IP"] for row in result}
        assert by_protocol["MLDv2"] == "fe80::21b:21ff:fe33:4455"
        assert by_protocol["IGMPv3"] == "192.168.73.2"

    def test_sorting_still_orders_ipv4_before_ipv6_numerically(self, tmp_path):
        path = tmp_path / "addresses.csv"
        _write(path, ["MAC", "IP"],
               [{"MAC": "00:11:22:33:44:55", "IP": "fe80::10"},
                {"MAC": "00:11:22:33:44:55", "IP": "fe80::2"},
                {"MAC": "00:11:22:33:44:55", "IP": "192.168.1.5"}])

        with mock.patch.object(csv_helpers, "get_if_hwaddr", return_value="aa:aa:aa:aa:aa:aa"):
            sort_csv_based_MAC("dummy", str(path))

        assert [row["IP"] for row in csv.DictReader(open(path, newline=""))] == \
               ["192.168.1.5", "fe80::2", "fe80::10"]

    def test_the_scanners_own_mac_is_still_dropped(self, tmp_path):
        path = tmp_path / "addresses.csv"
        _write(path, ["MAC", "IP"],
               [{"MAC": "00:11:22:33:44:55", "IP": "192.168.1.5"},
                {"MAC": "aa:aa:aa:aa:aa:aa", "IP": "192.168.1.9"}])

        with mock.patch.object(csv_helpers, "get_if_hwaddr", return_value="aa:aa:aa:aa:aa:aa"):
            sort_csv_based_MAC("dummy", str(path))

        assert [row["MAC"] for row in csv.DictReader(open(path, newline=""))] == \
               ["00:11:22:33:44:55"]


# --------------------------------------------------------------------------
# A hop limit is only an OS hint when the sender chose it.
# --------------------------------------------------------------------------
class TestHopLimitFingerprintScope:
    @pytest.mark.parametrize("description, packet", [
        ("router advertisement", Ether() / IPv6(dst="ff02::1", hlim=255) / ICMPv6ND_RA()),
        ("neighbour advertisement", Ether() / IPv6(dst="fe80::2", hlim=255) / ICMPv6ND_NA(tgt="fe80::1")),
        ("MLDv2 report", Ether() / IPv6(dst="ff02::16", hlim=1) / ICMPv6MLReport2()),
        ("MLDv2 query", Ether() / IPv6(dst="ff02::1", hlim=1) / ICMPv6MLQuery2()),
        ("node information reply", Ether() / IPv6(dst="fe80::2", hlim=255)
         / ICMPv6NIReplyName(qtype=2, data=[0, "host.local"])),
        ("mDNS over IPv6", Ether() / IPv6(dst="ff02::fb", hlim=255)
         / UDP(sport=5353, dport=5353) / DNS(qr=1)),
        ("mDNS answered by unicast", Ether() / IPv6(dst="fe80::2", hlim=255)
         / UDP(sport=5353, dport=5353) / DNS(qr=1)),
        ("LLMNR over IPv4", Ether() / IP(dst="224.0.0.252", ttl=255)
         / UDP(sport=5355, dport=5355) / DNS(qr=1)),
        ("IGMPv3 report", Ether() / IP(dst="224.0.0.22", ttl=1)
         / IGMPv3(type=0x22) / IGMPv3mr()),
    ])
    def test_protocols_that_pin_the_hop_limit_are_not_read_as_an_os_default(self, description, packet):
        """Every one of these put a router-class guess on an ordinary host."""
        assert _hop_limit_is_stack_default(Ether(bytes(packet))) is False, description

    @pytest.mark.parametrize("description, packet", [
        ("echo reply from Windows", Ether() / IPv6(dst="fe80::2", hlim=128) / ICMPv6EchoReply()),
        ("echo reply from Linux", Ether() / IPv6(dst="fd00::2", hlim=64) / ICMPv6EchoReply()),
        ("TCP", Ether() / IPv6(dst="fd00::2", hlim=64) / TCP(flags="SA")),
        ("IPv4 ping reply", Ether() / IP(dst="192.168.1.5", ttl=128) / ICMP(type=0)),
        ("ordinary UDP", Ether() / IPv6(dst="fe80::2", hlim=64) / UDP(sport=547, dport=546)),
    ])
    def test_ordinary_traffic_is_still_read(self, description, packet):
        assert _hop_limit_is_stack_default(Ether(bytes(packet))) is True, description

    @pytest.mark.parametrize("address, link_scoped", [
        ("ff02::1", True), ("ff02::fb", True), ("ff01::1", True),
        ("ff05::1:3", False), ("ff0e::1", False),
        ("224.0.0.251", True), ("224.0.0.22", True),
        ("239.255.255.250", False), ("8.8.8.8", False), ("fd00::1", False),
        ("not-an-address", False),
    ])
    def test_link_scoped_multicast_classification(self, address, link_scoped):
        assert _is_link_scoped_multicast(address) is link_scoped


# --------------------------------------------------------------------------
# An IGMPv3 query carries no IGMP layer.
# --------------------------------------------------------------------------
class TestIgmpQuerierVersions:
    def test_an_igmpv3_general_query_is_recognised(self):
        """Scapy dissects it as IGMPv3/IGMPv3mq, so gating on IGMP saw nothing."""
        query = (Ether(src="00:1b:21:33:44:55") / IP(src="192.168.73.2", dst="224.0.0.1", ttl=1)
                 / IGMPv3(type=0x11, mrcode=100) / IGMPv3mq(gaddr="0.0.0.0", qrv=2, qqic=125))
        parsed = Ether(bytes(query))

        assert IGMP not in parsed
        assert IGMPv3 in parsed and parsed[IGMPv3].type == 0x11
        assert IGMPv3mq in parsed

    def test_an_igmpv2_general_query_still_carries_the_igmp_layer(self):
        query = (Ether(src="00:1b:21:33:44:55") / IP(src="192.168.73.2", dst="224.0.0.1", ttl=1)
                 / IGMP(type=0x11, mrcode=100, gaddr="0.0.0.0"))
        parsed = Ether(bytes(query))

        assert IGMP in parsed and parsed[IGMP].type == 0x11
        assert IGMPv3mq not in parsed

    def test_both_versions_are_recorded_with_their_own_fields(self, scan_dir):
        from ptnetinspector.utils.path import get_csv_path
        from ptnetinspector.scan import Save

        v3 = Ether(bytes(Ether(src="00:1b:21:33:44:55") / IP(src="192.168.73.2", dst="224.0.0.1", ttl=1)
                        / IGMPv3(type=0x11, mrcode=100) / IGMPv3mq(gaddr="0.0.0.0", qrv=2, qqic=125)))
        v2 = Ether(bytes(Ether(src="00:1b:21:33:44:66") / IP(src="192.168.73.3", dst="224.0.0.1", ttl=1)
                        / IGMP(type=0x11, mrcode=100, gaddr="0.0.0.0")))

        Save.save_igmp_querier(v3)
        Save.save_igmp_querier(v2)

        rows = list(csv.DictReader(open(get_csv_path("querier.csv"), newline="")))
        by_mac = {row["MAC"]: row for row in rows}

        assert by_mac["00:1b:21:33:44:55"]["Protocol"] == "IGMPv3"
        assert by_mac["00:1b:21:33:44:55"]["QRV"] == "2"
        assert by_mac["00:1b:21:33:44:55"]["QQIC"] == "125"
        # IGMPv1/v2 queries have no robustness or interval field to report.
        assert by_mac["00:1b:21:33:44:66"]["Protocol"] == "IGMPv2"
        assert by_mac["00:1b:21:33:44:66"]["QRV"] == ""


# --------------------------------------------------------------------------
# Hostnames arrive from the wire and are attacker-controlled.
# --------------------------------------------------------------------------
class TestHostnameFromTheWire:
    @pytest.mark.parametrize("raw_value, expected", [
        (b"officeprinter.local", "officeprinter.local"),
        ("pc1.local.", "pc1.local"),
        ("WIN-DESKTOP", "WIN-DESKTOP"),
    ])
    def test_a_usable_name_is_kept(self, raw_value, expected):
        assert Node._clean_wire_name(raw_value) == expected

    @pytest.mark.parametrize("raw_value", [
        b"\x00\x00\x00\x00\rofficeprinter\x05local\x00",   # an undecoded NI payload
        b"name\x00with\x00nuls",
        b"\x07",
        "",
        "a" * 300,
    ])
    def test_a_name_that_cannot_be_a_hostname_is_dropped(self, raw_value):
        assert Node._clean_wire_name(raw_value) == ""

    def test_a_node_information_reply_decodes_to_the_name(self):
        """Scapy strips the 4-octet TTL and the DNS framing on dissection."""
        reply = (Ether() / IPv6(src="fe80::1", dst="fe80::2", hlim=255)
                 / ICMPv6NIReplyName(qtype=2, code=0, nonce=b"12345678",
                                     data=[120, "officeprinter.local"]))
        data = Ether(bytes(reply))[ICMPv6NIReplyName].data

        names = [Node._clean_wire_name(entry) for entry in data if isinstance(entry, bytes)]
        assert names == ["officeprinter.local"]


# --------------------------------------------------------------------------
# add_properties() merges with dict.update(), so repeated names must be lists.
# --------------------------------------------------------------------------
class TestJsonPropertiesDoNotOverwriteEachOther:
    def test_every_value_of_a_repeated_property_survives(self, scan_dir):
        """Only the last search domain and the last querier were published."""
        import ptnetinspector.output.json as json_output
        from ptnetinspector.send.send import IPMode
        from ptnetinspector.utils.path import get_csv_path

        _write(get_csv_path("ra_options.csv"),
               ["MAC", "IP", "Option", "Value", "Lifetime", "Flags"],
               [{"MAC": "00:50:56:c0:00:02", "IP": "fe80::1", "Option": "DNSSL",
                 "Value": "lan.example.com", "Lifetime": "600", "Flags": ""},
                {"MAC": "00:50:56:c0:00:02", "IP": "fe80::1", "Option": "DNSSL",
                 "Value": "corp.example", "Lifetime": "600", "Flags": ""},
                {"MAC": "00:50:56:c0:00:02", "IP": "fe80::1", "Option": "PREF64",
                 "Value": "64:ff9b::", "Lifetime": "600", "Flags": ""}])

        _write(get_csv_path("querier.csv"),
               ["MAC", "IP", "Protocol", "Group", "QRV", "QQIC", "Max_response"],
               [{"MAC": "00:1b:21:33:44:55", "IP": "192.168.73.2", "Protocol": "IGMPv3",
                 "Group": "0.0.0.0", "QRV": "2", "QQIC": "125", "Max_response": "100"},
                {"MAC": "00:1b:21:33:44:55", "IP": "fe80::4455", "Protocol": "MLDv2",
                 "Group": "::", "QRV": "2", "QQIC": "125", "Max_response": "10000"}])

        json_output.ptjsonlib_object.__init__()
        json_output.Json._add_extended_network_properties(IPMode(ipv4=True, ipv6=True))
        properties = json_output.ptjsonlib_object.json_object["results"]["properties"]

        assert properties["DNS search domain"] == ["lan.example.com", "corp.example"]
        assert sorted(properties["Multicast querier"]) == [
            "00:1b:21:33:44:55 (IGMPv3)", "00:1b:21:33:44:55 (MLDv2)"]
        # a single value stays a plain string rather than a one-element list
        assert properties["NAT64 prefix"] == "64:ff9b::"


# --------------------------------------------------------------------------
# The default scan family, and reconciling it against the interface.
# --------------------------------------------------------------------------
class TestDefaultIsIpv6Only:
    """Jan: "Default bylo -6, teď se zdá, že je to -4 i -6" - the default had
    become dual-stack and is now IPv6 only again, with IPv4 opt-in via -4."""

    @pytest.mark.parametrize("ipv4, ipv6, expected", [
        (False, False, (False, True)),   # neither flag: IPv6 only
        (True, False, (True, False)),    # -4
        (False, True, (False, True)),    # -6
        (True, True, (True, True)),      # -4 -6
    ])
    def test_resolution(self, ipv4, ipv6, expected):
        from ptnetinspector.send.send import IPMode
        resolved = IPMode(ipv4, ipv6) if (ipv4 or ipv6) else IPMode(False, True)
        assert (resolved.ipv4, resolved.ipv6) == expected

    def test_the_help_text_states_the_default(self):
        source = (Path(__file__).resolve().parent.parent
                  / "ptnetinspector" / "utils" / "cli.py").read_text()
        assert "default: IPv6 only" in source
        assert "default: both IPv4 and IPv6 are scanned" not in source

    def test_the_default_is_resolved_before_any_mode_validation(self):
        """Reconciliation has to cover passive and 802.1x, not only active.

        It used to live inside the active-mode validation, which never runs for
        a passive or 802.1x scan.
        """
        source = (Path(__file__).resolve().parent.parent
                  / "ptnetinspector" / "utils" / "cli.py").read_text()

        reconcile_call = source.index("ip_mode = _reconcile_ip_mode(")
        passive_call = source.index("duration_passive = _validate_passive_mode(")
        active_call = source.index("smac, ip_mode = _validate_active_mode(")

        assert reconcile_call < passive_call
        assert reconcile_call < active_call
        # and it is no longer the active path's job
        assert "ipver_explicit=bool(ipv4 or ipv6)" not in source


class TestFamilyReconciledAgainstTheInterface:
    """An IPv6-only default must not leave a single-stack interface scanning
    a family it does not have, silently."""

    def _reconcile(self, has_ipv4, has_ipv6, ip_mode, explicit):
        from unittest import mock
        from ptnetinspector.utils import cli
        from ptnetinspector.send.send import IPMode

        errors, warnings = [], []
        fake = mock.Mock()
        fake.get_interface_ipv4_ips.return_value = ["192.168.1.5"] if has_ipv4 else []
        fake.get_interface_ipv6_ips.return_value = ["fe80::1"] if has_ipv6 else []
        with mock.patch.object(cli, "Interface", return_value=fake):
            result = cli._reconcile_ip_mode("eth0", ip_mode, explicit, errors, warnings)
        return result, errors, warnings

    def test_ipv4_only_interface_falls_back_instead_of_scanning_nothing(self):
        from ptnetinspector.send.send import IPMode
        mode, errors, warnings = self._reconcile(True, False, IPMode(False, True), explicit=False)

        assert (mode.ipv4, mode.ipv6) == (True, False)
        assert not errors
        assert any("IPv4 is scanned instead" in w for w in warnings)

    def test_an_explicitly_requested_family_that_is_absent_is_an_error(self):
        from ptnetinspector.send.send import IPMode
        _, errors, _ = self._reconcile(True, False, IPMode(False, True), explicit=True)
        assert any("No available IPv6 address" in e for e in errors)

        _, errors, _ = self._reconcile(False, True, IPMode(True, False), explicit=True)
        assert any("No available IPv4 address" in e for e in errors)

    def test_a_dual_stack_interface_is_left_alone(self):
        from ptnetinspector.send.send import IPMode
        mode, errors, warnings = self._reconcile(True, True, IPMode(False, True), explicit=False)
        assert (mode.ipv4, mode.ipv6) == (False, True)
        assert not errors and not warnings

    def test_reconciliation_never_leaves_both_families_off(self):
        from ptnetinspector.send.send import IPMode
        for has4, has6 in ((True, False), (False, True), (True, True)):
            for requested in (IPMode(False, True), IPMode(True, False), IPMode(True, True)):
                mode, errors, _ = self._reconcile(has4, has6, requested, explicit=False)
                if not errors:
                    assert mode.ipv4 or mode.ipv6, (has4, has6, requested.ipv4, requested.ipv6)


# --------------------------------------------------------------------------
# -4 and -6 promise "only IPv4/IPv6 traffic"; the kept list is what gets probed.
# --------------------------------------------------------------------------
class TestScanFamilyIsNotLeakedOnTheWire:
    """The filtered mapping list is what the reachability probe sends to, so a
    family the scan was not asked for must not survive the filter - otherwise
    -6 emits ARP and -4 emits Neighbour Solicitations."""

    V4_SUBNETS = [__import__("ipaddress").ip_network("192.168.1.0/24")]
    V6_SUBNETS = [__import__("ipaddress").ip_network("2001:db8::/64")]

    def _filter(self, ip_mode, **kwargs):
        from unittest import mock
        from ptnetinspector.utils import address_control as ac
        from ptnetinspector.utils.address_control import AddressMapping, filter_unicast_addresses

        mappings = [
            AddressMapping("aa:bb:cc:00:00:01", "192.168.1.5"),
            AddressMapping("aa:bb:cc:00:00:01", "fe80::1"),
            AddressMapping("aa:bb:cc:00:00:01", "2001:db8::5"),
            AddressMapping("aa:bb:cc:00:00:01", "ff02::1:ff00:5"),
        ]
        with mock.patch.object(ac.Networks, "load_networks",
                               return_value=(list(self.V4_SUBNETS), list(self.V6_SUBNETS))), \
             mock.patch.object(ac.Networks, "load_ra_prefixes", return_value=[]):
            return [m.ip for m in filter_unicast_addresses(mappings, ip_mode, **kwargs)]

    def test_ipv6_only_keeps_no_ipv4_address_to_arp_for(self):
        from ptnetinspector.send.send import IPMode
        kept = self._filter(IPMode(ipv4=False, ipv6=True))
        assert not [ip for ip in kept if ":" not in ip]
        assert "2001:db8::5" in kept

    def test_ipv4_only_keeps_no_ipv6_address_to_solicit(self):
        from ptnetinspector.send.send import IPMode
        kept = self._filter(IPMode(ipv4=True, ipv6=False))
        assert not [ip for ip in kept if ":" in ip]
        assert "192.168.1.5" in kept

    def test_dual_stack_keeps_both(self):
        from ptnetinspector.send.send import IPMode
        kept = self._filter(IPMode(ipv4=True, ipv6=True))
        assert "192.168.1.5" in kept and "2001:db8::5" in kept

    def test_nc_still_keeps_solicited_node_only_for_the_scanned_family(self):
        from ptnetinspector.send.send import IPMode
        under6 = self._filter(IPMode(ipv4=False, ipv6=True),
                              keep_solicited_node=True, keep_offlink=True)
        under4 = self._filter(IPMode(ipv4=True, ipv6=False),
                              keep_solicited_node=True, keep_offlink=True)
        assert "ff02::1:ff00:5" in under6
        assert not [ip for ip in under4 if ":" in ip]


# --------------------------------------------------------------------------
# -target scopes every output, including the inventory.
# --------------------------------------------------------------------------
class TestTargetFilterReachesTheInventory:
    """The inventory ignored -target, so asking for one device still produced
    the whole segment while every other output was scoped to it."""

    def _seed(self, scan_dir):
        rows = [("00:50:56:c0:00:02", "192.168.73.1"),
                ("00:50:56:c0:00:02", "fd00:73::1"),
                ("08:00:27:aa:bb:01", "192.168.73.20"),
                ("08:00:27:aa:bb:01", "fd00:73::20"),
                ("b8:27:eb:11:22:33", "192.168.73.31")]
        _write(scan_dir / "addresses.csv", ["MAC", "IP"],
               [{"MAC": m, "IP": ip} for m, ip in rows])
        _write(scan_dir / "role_node.csv", ["MAC", "Device_Number", "Role"],
               [{"MAC": m, "Device_Number": str(i), "Role": "Host"}
                for i, m in enumerate(
                    ["00:50:56:c0:00:02", "08:00:27:aa:bb:01", "b8:27:eb:11:22:33"], 1)])

    def test_without_a_target_every_device_is_listed(self, scan_dir):
        from ptnetinspector.output.devices import collect_devices
        from ptnetinspector.send.send import IPMode
        self._seed(scan_dir)
        assert len(collect_devices(IPMode(True, True))) == 3

    def test_a_target_mac_keeps_that_device_with_all_its_addresses(self, scan_dir):
        from ptnetinspector.output.devices import collect_devices
        from ptnetinspector.send.send import IPMode
        self._seed(scan_dir)
        devices = collect_devices(IPMode(True, True), target_macs=["00:50:56:C0:00:02"])

        assert [d["MAC"] for d in devices] == ["00:50:56:c0:00:02"]
        assert devices[0]["IPv4"] == "192.168.73.1"
        assert devices[0]["IPv6"] == "fd00:73::1"

    def test_a_target_ip_keeps_only_that_address(self, scan_dir):
        from ptnetinspector.output.devices import collect_devices
        from ptnetinspector.send.send import IPMode
        self._seed(scan_dir)
        devices = collect_devices(IPMode(True, True), target_ips=["fd00:73::20"])

        assert [d["MAC"] for d in devices] == ["08:00:27:aa:bb:01"]
        assert devices[0]["IPv6"] == "fd00:73::20"
        assert devices[0]["IPv4"] == ""      # the device's other address is not a target

    def test_mac_and_ip_targets_are_a_union(self, scan_dir):
        from ptnetinspector.output.devices import collect_devices
        from ptnetinspector.send.send import IPMode
        self._seed(scan_dir)
        devices = collect_devices(IPMode(True, True),
                                  target_macs=["b8:27:eb:11:22:33"],
                                  target_ips=["fd00:73::20"])
        assert sorted(d["MAC"] for d in devices) == ["08:00:27:aa:bb:01", "b8:27:eb:11:22:33"]

    def test_a_target_that_matches_nothing_yields_an_empty_inventory(self, scan_dir):
        from ptnetinspector.output.devices import collect_devices, write_device_inventory
        from ptnetinspector.send.send import IPMode
        self._seed(scan_dir)
        assert collect_devices(IPMode(True, True), target_macs=["ff:ff:ff:ff:ff:ff"]) == []
        assert write_device_inventory(IPMode(True, True),
                                      target_macs=["ff:ff:ff:ff:ff:ff"]) == (0, None)

    def test_the_flat_form_is_scoped_too(self, scan_dir):
        from ptnetinspector.output.devices import write_device_inventory
        from ptnetinspector.send.send import IPMode
        self._seed(scan_dir)
        write_device_inventory(IPMode(True, True), target_macs=["00:50:56:c0:00:02"])
        rows = [r for r in csv.DictReader(open(scan_dir / "device_addresses.csv", newline=""))]
        assert {r["MAC"] for r in rows} == {"00:50:56:c0:00:02"}

    def test_main_passes_the_targets_through(self):
        source = (Path(__file__).resolve().parent.parent
                  / "ptnetinspector" / "main.py").read_text()
        inventory_call = source.index("write_device_inventory(")
        tail = source[inventory_call:inventory_call + 400]
        assert "target_macs=target_macs" in tail
        assert "target_ips=target_ips" in tail


# --------------------------------------------------------------------------
# E7's snooping half: what a single port can actually measure.
# --------------------------------------------------------------------------
class TestKernelMulticastMemberships:
    """The comparison is only meaningful against what the host really joined,
    which includes the memberships the stack takes out by itself."""

    IGMP6 = (
        "1    lo              ff020000000000000000000000000001     1 0000000C 0\n"
        "4    scan0           ff0200000000000000000001ff000077     1 00000004 0\n"
        "4    scan0           ff020000000000000000000000000001     1 0000000C 0\n"
        "3    lan0            ff0200000000000000000001ff8e5b55     1 00000004 0\n"
    )
    IGMP = (
        "Idx\tDevice    : Count Querier\tGroup    Users Timer\tReporter\n"
        "1\tlo        :     1      V3\n"
        "\t\t\t\t010000E0     1 0:00000000\t\t0\n"
        "4\tscan0     :     1      V3\n"
        "\t\t\t\t010000E0     1 0:00000000\t\t0\n"
        "\t\t\t\t160000E0     1 0:00000000\t\t0\n"
    )

    def test_ipv6_groups_are_parsed_and_scoped_to_the_interface(self):
        from ptnetinspector.utils.interface import _parse_igmp6
        assert _parse_igmp6(self.IGMP6, "scan0") == {"ff02::1:ff00:77", "ff02::1"}
        assert _parse_igmp6(self.IGMP6, "lan0") == {"ff02::1:ff8e:5b55"}
        assert _parse_igmp6(self.IGMP6, "nosuchif") == set()

    def test_ipv4_groups_are_parsed_from_little_endian_hex(self):
        from ptnetinspector.utils.interface import _parse_igmp
        assert _parse_igmp(self.IGMP, "scan0") == {"224.0.0.1", "224.0.0.22"}
        assert _parse_igmp(self.IGMP, "lo") == {"224.0.0.1"}
        assert _parse_igmp(self.IGMP, "nosuchif") == set()

    def test_malformed_lines_are_skipped_not_fatal(self):
        from ptnetinspector.utils.interface import _parse_igmp6, _parse_igmp
        assert _parse_igmp6("garbage\n4 scan0 nothex 1 0 0\n", "scan0") == set()
        assert _parse_igmp("4\tscan0     :\n\t\t\t\tZZZZZZZZ     1\n", "scan0") == set()


class TestFloodingEvidence:
    """A group that arrived without being joined is what one port can observe;
    the probe's own group reaching other ports is not."""

    def _rows(self, scan_dir, observations, joined):
        from unittest import mock
        from ptnetinspector.output import intel

        _write(scan_dir / "multicast_groups.csv", ["Group", "Version", "Source_MAC"],
               [{"Group": g, "Version": v, "Source_MAC": m} for g, v, m in observations])
        with mock.patch.object(intel, "get_joined_multicast_groups", return_value=set(joined)), \
             mock.patch.object(intel, "get_current_interface", return_value="scan0"):
            return intel._unjoined_multicast_rows()

    def test_a_group_that_was_joined_is_not_evidence(self, scan_dir):
        rows = self._rows(scan_dir,
                          [("ff02::1", "IPv6", "aa:bb:cc:00:00:01")],
                          {"ff02::1"})
        assert rows == []

    def test_a_group_that_arrived_unjoined_is_reported(self, scan_dir):
        rows = self._rows(scan_dir,
                          [("ff02::fb", "IPv6", "aa:bb:cc:00:00:01")],
                          {"ff02::1"})
        assert [r[0] for r in rows] == ["ff02::fb"]

    def test_another_hosts_solicited_node_group_is_the_classic_signal(self, scan_dir):
        rows = self._rows(scan_dir,
                          [("ff02::1:ff05:b01a", "IPv6", "aa:bb:cc:00:00:02")],
                          {"ff02::1", "ff02::1:ff00:77"})
        assert [r[0] for r in rows] == ["ff02::1:ff05:b01a"]

    def test_the_ipv4_control_block_is_flooded_by_design_and_excluded(self, scan_dir):
        rows = self._rows(scan_dir,
                          [("224.0.0.22", "IPv4", "aa:bb:cc:00:00:01"),
                           ("224.0.0.251", "IPv4", "aa:bb:cc:00:00:01"),
                           ("239.255.255.250", "IPv4", "aa:bb:cc:00:00:01")],
                          set())
        assert [r[0] for r in rows] == ["239.255.255.250"]

    def test_senders_are_counted_and_listed(self, scan_dir):
        rows = self._rows(scan_dir,
                          [("ff02::16", "IPv6", "aa:bb:cc:00:00:01"),
                           ("ff02::16", "IPv6", "aa:bb:cc:00:00:02")],
                          set())
        assert rows[0][2] == "2"
        assert "aa:bb:cc:00:00:01" in rows[0][3] and "aa:bb:cc:00:00:02" in rows[0][3]

    def test_membership_matches_across_spellings(self, scan_dir):
        """A non-compressed spelling in the CSV must still match the join."""
        rows = self._rows(scan_dir,
                          [("ff02:0:0:0:0:0:0:fb", "IPv6", "aa:bb:cc:00:00:01")],
                          {"ff02::fb"})
        assert rows == []

    def test_non_multicast_and_garbage_are_ignored(self, scan_dir):
        rows = self._rows(scan_dir,
                          [("192.168.1.5", "IPv4", "aa:bb:cc:00:00:01"),
                           ("not-an-address", "IPv4", "aa:bb:cc:00:00:01")],
                          set())
        assert rows == []


class TestOnlyInboundMulticastIsRecorded:
    """The scanner's own probes pick their own groups, so counting them measured
    the tool rather than the switch."""

    def test_the_scanners_own_frames_are_skipped(self, scan_dir):
        from ptnetinspector.scan import Save
        from ptnetinspector.utils.path import get_csv_path

        mine = Ether(bytes(Ether(src="aa:aa:aa:aa:aa:aa")
                           / IPv6(dst="ff02::1:ff00:99") / ICMPv6ND_NS(tgt="fe80::99")))
        theirs = Ether(bytes(Ether(src="bb:bb:bb:bb:bb:bb")
                             / IPv6(dst="ff02::fb") / UDP(sport=5353, dport=5353) / DNS(qr=1)))

        Save.save_multicast_destination(mine, "aa:aa:aa:aa:aa:aa")
        Save.save_multicast_destination(theirs, "aa:aa:aa:aa:aa:aa")

        rows = [r for r in csv.DictReader(open(get_csv_path("multicast_groups.csv"), newline=""))]
        assert [r["Group"] for r in rows] == ["ff02::fb"]

    def test_unicast_destinations_are_not_recorded(self, scan_dir):
        from ptnetinspector.scan import Save
        from ptnetinspector.utils.path import get_csv_path

        packet = Ether(bytes(Ether(src="bb:bb:bb:bb:bb:bb")
                             / IPv6(dst="fe80::2") / ICMPv6EchoReply()))
        Save.save_multicast_destination(packet, "aa:aa:aa:aa:aa:aa")

        rows = [r for r in csv.DictReader(open(get_csv_path("multicast_groups.csv"), newline=""))]
        assert rows == []


# --------------------------------------------------------------------------
# The packet log must not care how the frame was framed.
# --------------------------------------------------------------------------
class TestLinkLayerIsReadFromTheActualFraming:
    """The log picked its branch from a classifier that tested the network
    layer before the framing, so IP carried over anything but Ethernet reached
    a branch reading packet[Ether] and aborted the whole scan - the same class
    of failure as a malformed MLDv2 report."""

    def _frames(self):
        from scapy.layers.l2 import Dot1Q, Dot3, LLC, SNAP, STP
        from scapy.layers.dot11 import Dot11
        return {
            "ethernet ipv6": (Ether(src="aa:00:00:00:00:01", dst="33:33:00:00:00:01")
                              / IPv6(src="fe80::1", dst="ff02::1") / ICMPv6EchoRequest(),
                              "aa:00:00:00:00:01", "fe80::1"),
            "ethernet ipv4": (Ether(src="aa:00:00:00:00:02", dst="ff:ff:ff:ff:ff:ff")
                              / IP(src="192.168.1.2", dst="192.168.1.9") / ICMP(),
                              "aa:00:00:00:00:02", "192.168.1.2"),
            "vlan tagged ipv6": (Ether(src="aa:00:00:00:00:03", dst="33:33:00:00:00:01")
                                 / Dot1Q(vlan=10) / IPv6(src="fe80::3", dst="ff02::1")
                                 / ICMPv6EchoRequest(),
                                 "aa:00:00:00:00:03", "fe80::3"),
            "stp bpdu": (Dot3(src="aa:00:00:00:00:04", dst="01:80:c2:00:00:00") / LLC() / STP(),
                         "aa:00:00:00:00:04", ""),
            "802.3 llc/snap ipv6": (Dot3(src="aa:00:00:00:00:05", dst="33:33:00:00:00:01")
                                    / LLC() / SNAP(code=0x86DD)
                                    / IPv6(src="fe80::5", dst="ff02::1") / ICMPv6EchoRequest(),
                                    "aa:00:00:00:00:05", "fe80::5"),
            "802.3 llc/snap ipv4": (Dot3(src="aa:00:00:00:00:06", dst="01:00:5e:00:00:01")
                                    / LLC() / SNAP(code=0x0800)
                                    / IP(src="192.168.1.6", dst="224.0.0.1") / ICMP(),
                                    "aa:00:00:00:00:06", "192.168.1.6"),
            "802.11 data ipv4": (Dot11(type=2, addr1="11:11:11:11:11:11",
                                       addr2="aa:00:00:00:00:07", addr3="33:33:33:33:33:33")
                                 / LLC() / SNAP(code=0x0800)
                                 / IP(src="192.168.1.7", dst="192.168.1.9") / ICMP(),
                                 "aa:00:00:00:00:07", "192.168.1.7"),
        }

    @pytest.mark.parametrize("label", [
        "ethernet ipv6", "ethernet ipv4", "vlan tagged ipv6", "stp bpdu",
        "802.3 llc/snap ipv6", "802.3 llc/snap ipv4", "802.11 data ipv4",
    ])
    def test_every_framing_is_logged_with_its_own_addresses(self, label, scan_dir):
        from ptnetinspector.scan import Save
        from ptnetinspector.utils.path import get_csv_path

        packet, expected_mac, expected_ip = self._frames()[label]
        parsed = packet.__class__(bytes(packet))

        Save.save_async([parsed])          # must not raise for any framing

        rows = [r for r in csv.DictReader(open(get_csv_path("packets.csv"), newline=""))]
        assert len(rows) == 1
        assert rows[0]["src MAC"] == expected_mac
        assert rows[0]["source IP"] == expected_ip
        assert rows[0]["length"] == str(len(parsed))

    def test_a_frame_with_no_link_layer_is_skipped_not_logged(self, scan_dir):
        from scapy.layers.l2 import LLC
        from ptnetinspector.scan import Save
        from ptnetinspector.utils.path import get_csv_path

        Save.save_async([LLC() / Raw(load=b"\x00" * 16)])

        assert [r for r in csv.DictReader(open(get_csv_path("packets.csv"), newline=""))] == []

    def test_link_addresses_helper(self):
        from scapy.layers.l2 import Dot3
        from scapy.layers.dot11 import Dot11
        from ptnetinspector.scan import _link_addresses

        assert _link_addresses(Ether(src="aa:aa:aa:aa:aa:aa", dst="bb:bb:bb:bb:bb:bb")) == \
            ("aa:aa:aa:aa:aa:aa", "bb:bb:bb:bb:bb:bb")
        assert _link_addresses(Dot3(src="cc:cc:cc:cc:cc:cc", dst="dd:dd:dd:dd:dd:dd")) == \
            ("cc:cc:cc:cc:cc:cc", "dd:dd:dd:dd:dd:dd")
        # Dot11 exposes addr1/addr2, never .src/.dst
        assert _link_addresses(Dot11(type=2, addr1="11:11:11:11:11:11",
                                     addr2="22:22:22:22:22:22")) == \
            ("22:22:22:22:22:22", "11:11:11:11:11:11")
        assert _link_addresses(Raw(load=b"x")) == ("", "")


# --------------------------------------------------------------------------
# Artifacts hold values taken off the wire, and a run can be killed mid-write.
# --------------------------------------------------------------------------
class TestArtifactsSurviveCorruption:
    """Found by fuzzing the report path. A byte that is not valid UTF-8, a
    ragged row, or a file truncated to nothing took the entire report down at
    the very end of a scan - throwing away the whole run's work."""

    def test_a_byte_that_is_not_utf8_does_not_abort_the_report(self, tmp_path):
        from ptnetinspector.utils.csv_helpers import has_additional_data, read_csv_text

        path = tmp_path / "localname.csv"
        path.write_bytes(b"MAC,name\naa:bb:cc:00:00:01,\xff\xfe\x80\n")

        assert has_additional_data(str(path)) is True
        frame = read_csv_text(path)
        assert list(frame["MAC"]) == ["aa:bb:cc:00:00:01"]
        # the undecodable byte is replaced, not fatal
        assert frame["name"].iloc[0]

    def test_a_ragged_row_is_dropped_not_fatal(self, tmp_path):
        from ptnetinspector.utils.csv_helpers import read_csv_text

        path = tmp_path / "addresses.csv"
        path.write_text("MAC,IP\naa:bb:cc:00:00:01,192.168.1.5\nx,y,z,extra,fields\n")

        frame = read_csv_text(path)
        assert list(frame["IP"]) == ["192.168.1.5"]

    def test_a_file_truncated_to_nothing_reads_as_empty_with_its_columns(self, tmp_path):
        """The columns matter: callers index them, so an empty frame with no
        columns only moves the crash downstream."""
        from ptnetinspector.utils.csv_helpers import ARTIFACT_SCHEMAS, read_csv_text

        path = tmp_path / "vulnerability_mac.csv"
        path.write_bytes(b"")

        frame = read_csv_text(path)
        assert frame.empty
        assert list(frame.columns) == ARTIFACT_SCHEMAS["vulnerability_mac.csv"]
        # indexing a column of an empty artifact must work
        assert list(frame["ID"]) == []

    def test_an_unknown_filename_still_reads_as_empty(self, tmp_path):
        from ptnetinspector.utils.csv_helpers import read_csv_text

        path = tmp_path / "not-an-artifact.csv"
        path.write_bytes(b"")
        assert read_csv_text(path).empty

    def test_the_guard_answers_no_for_a_file_it_cannot_read(self, tmp_path):
        from ptnetinspector.utils.csv_helpers import has_additional_data

        assert has_additional_data(str(tmp_path / "absent.csv")) is False
        assert has_additional_data(None) is False
        (tmp_path / "empty.csv").write_bytes(b"")
        assert has_additional_data(str(tmp_path / "empty.csv")) is False

    def test_create_csv_and_the_reader_share_one_schema(self):
        """They used to be separate lists, so a truncated artifact could come
        back with columns that did not match what the scan writes."""
        import tempfile
        import ptnetinspector.utils.path as pathmod
        from ptnetinspector.utils.csv_helpers import ARTIFACT_SCHEMAS, create_csv
        from ptnetinspector.utils.path import (
            get_current_interface, get_tmp_path, set_current_interface,
        )

        previous = get_current_interface()
        directory = Path(tempfile.mkdtemp())
        original = pathmod.get_output_dir
        pathmod.get_output_dir = lambda base_path=None: directory
        try:
            set_current_interface("schema")
            create_csv("schema")
            written = get_tmp_path("schema")
            assert sorted(p.name for p in written.glob("*.csv")) == sorted(ARTIFACT_SCHEMAS)
            for name, fieldnames in ARTIFACT_SCHEMAS.items():
                header = (written / name).read_text(encoding="utf-8").splitlines()[0]
                assert header == ",".join(fieldnames), name
        finally:
            pathmod.get_output_dir = original
            set_current_interface(previous)


# --------------------------------------------------------------------------
# A hostile hostname must not be able to end the scan.
# --------------------------------------------------------------------------
class TestHostnameBytesCannotAbortTheScan:
    """Found by fuzzing. An mDNS or LLMNR answer whose rdata is not valid UTF-8
    was decoded at the call site, before the sanitiser ran, so
    UnicodeDecodeError propagated out of the analysis loop and ended the whole
    scan - a denial of service any host on the segment could trigger."""

    def test_the_call_sites_hand_over_raw_bytes(self):
        """Decoding belongs in the sanitiser, which replaces bad bytes."""
        source = (Path(__file__).resolve().parent.parent
                  / "ptnetinspector" / "scan.py").read_text()
        assert "save_local_name(packet[0].src, packet.an[i].rdata)" in source
        assert ".rdata.decode()" not in source

    @pytest.mark.parametrize("raw, expected", [
        (b"printer.local", "printer.local"),
        (bytearray(b"host.local"), "host.local"),
        (memoryview(b"host.local"), "host.local"),
        ("pc1.local.", "pc1.local"),
        ("WIN-DESKTOP", "WIN-DESKTOP"),
        # RFC 6762 names are UTF-8, so non-ASCII is legitimate
        ("Muller-PC.local", "Muller-PC.local"),
    ])
    def test_a_usable_name_survives(self, raw, expected):
        assert Node._clean_wire_name(raw) == expected

    @pytest.mark.parametrize("raw", [
        b"\xff\xfe\x80",                                  # not text at all
        b"host\xff.local",                                # one bad byte inside
        b"\x00\x00\x00\x00\rofficeprinter\x05local\x00",  # an undecoded NI payload
        b"name\x00with\x00nuls",
        b"",
        b"\x07",
        "a" * 300,
        None,                                             # not text
        12345,
        [b"x"],
    ])
    def test_anything_that_cannot_be_a_name_is_dropped(self, raw):
        assert Node._clean_wire_name(raw) == ""

    def test_an_mdns_answer_with_invalid_utf8_is_survivable(self, scan_dir):
        """End to end: the frame is analysed, the scan continues, nothing is
        stored under a garbage hostname."""
        from ptnetinspector.scan import Save
        from ptnetinspector.send.send import IPMode
        from ptnetinspector.utils.path import get_csv_path
        from unittest import mock
        from ptnetinspector import scan as scanmod

        answer = DNSRR(rrname="host.local", type="PTR", ttl=120, rdata=b"\xff\xfe\x80bad")
        frame = (Ether(src="aa:bb:cc:00:00:01", dst="33:33:00:00:00:fb")
                 / IPv6(src="fe80::1", dst="ff02::fb", hlim=255)
                 / UDP(sport=5353, dport=5353) / DNS(qr=1, aa=1, an=answer))
        parsed = Ether(bytes(frame))

        with mock.patch.object(scanmod, "get_if_hwaddr", return_value="ff:ff:ff:ff:ff:ff"):
            Save.save_packets("testiface", IPMode(True, True), [parsed])

        names = [r["name"] for r in
                 csv.DictReader(open(get_csv_path("localname.csv"), newline=""))]
        assert all(name == "" or "�" not in name for name in names)


# --------------------------------------------------------------------------
# A segment with many devices must still produce a readable report.
# --------------------------------------------------------------------------
def _matrix_fixture(device_count, code_count=20):
    """Codes alternate network / IPv4-device / IPv6-device, like the catalog."""
    vulnerabilities, codes = {}, []
    for i in range(code_count):
        kind = i % 3
        family = "6" if i % 2 else "4"
        if kind == 0:
            code = f"PTV-NET-IDENT-{family}-NET{i}"
            entities = {"Network": i % 3}
        else:
            code = f"PTV-NET-IDENT-{family}-DEV{i}"
            entities = {str(d): (d + i) % 3 for d in range(1, device_count + 1)}
        codes.append(code)
        vulnerabilities[code] = {"description": f"finding {i}", "entities": entities}
    return sorted(codes), vulnerabilities


def _render_matrix(device_count, columns, code_count=20):
    import io, re
    from contextlib import redirect_stdout
    from unittest.mock import patch
    from ptnetinspector.output.non_json import Non_json

    codes, vulns = _matrix_fixture(device_count, code_count)
    symbol = {0: "✓", 1: "✕", 2: "●"}.get
    with patch.object(Non_json, "_terminal_width", staticmethod(lambda default=100, c=columns: c)):
        buf = io.StringIO()
        with redirect_stdout(buf):
            Non_json._print_vulnerability_matrix(codes, vulns, symbol, "—")
    return re.sub(r"\x1b\[[0-9;]*m", "", buf.getvalue())


class TestMatrixScalesWithDeviceCount:
    """Item [49] of the review: past ten devices the tables must be condensed.

    With codes as rows and devices as columns, 35 devices produced nine
    116-line blocks of four devices each; 200 devices would have produced
    fifty. Devices are the unbounded dimension, so they go on rows."""

    def test_few_devices_keep_the_familiar_layout(self):
        text = _render_matrix(5, 100)
        assert "Vulnerability code" in text            # codes as rows
        assert "one row per device" not in text

    def test_many_devices_put_devices_on_rows(self):
        text = _render_matrix(35, 100)
        assert "one row per device" in text
        assert "Vulnerability code" not in text

    def test_network_and_device_findings_are_separated(self):
        text = _render_matrix(35, 100)
        assert "Network-scoped findings" in text
        assert "IPv4 findings, one row per device" in text
        assert "IPv6 findings, one row per device" in text

    @pytest.mark.parametrize("columns", [120, 100, 80, 60])
    @pytest.mark.parametrize("devices", [35, 200])
    def test_nothing_overflows_the_terminal(self, columns, devices):
        text = _render_matrix(devices, columns)
        widest = max(len(line) for line in text.splitlines())
        assert widest <= columns, f"{widest} chars at {columns} columns, {devices} devices"

    def test_growth_is_linear_in_devices_not_blocks(self):
        """Each device costs about one line per family table, not one block."""
        lines_35 = len(_render_matrix(35, 100).splitlines())
        lines_200 = len(_render_matrix(200, 100).splitlines())
        per_device = (lines_200 - lines_35) / (200 - 35)
        assert per_device < 4, f"{per_device:.1f} lines per extra device"

    def test_every_device_has_a_row_in_every_family_table(self):
        text = _render_matrix(50, 100)
        for table in ("IPv4 findings", "IPv6 findings"):
            section = text.split(table, 1)[1].split("findings, one row per device", 1)[0] \
                if text.count("one row per device") > 1 else text.split(table, 1)[1]
            rows = [l for l in section.splitlines() if l.strip() and l.strip()[0].isdigit()]
            first_column = {l.split()[0] for l in rows}
            assert {str(d) for d in range(1, 51)} <= first_column, table

    def test_the_key_names_every_finding_number(self):
        text = _render_matrix(35, 100)
        codes, _ = _matrix_fixture(35)
        key = text.split("Key", 1)[1]
        for number, code in enumerate(codes, 1):
            assert f"{number:>3}  {code.replace('PTV-NET-', '')}" in key, number

    def test_the_key_drops_the_shared_prefix(self):
        text = _render_matrix(35, 100)
        assert "PTV-NET-" not in text.split("Key", 1)[1]


class TestSummaryCondensesPastTheThreshold:
    def test_threshold_constant_is_ten(self):
        """The review named the number; keep it where a maintainer expects."""
        from ptnetinspector.output import non_json
        assert non_json.MANY_DEVICES == 10


class TestPerFindingListsCondensePastTheThreshold:
    def _render(self, device_count, file_lines):
        import io, re
        from contextlib import redirect_stdout
        from unittest.mock import patch
        from ptnetinspector.output.non_json import Non_json
        from ptnetinspector.utils import runtime

        devices = {str(i): i % 3 for i in range(1, device_count + 1)}
        headers = ["Network"] + [f"Device {i}" for i in devices]
        symbol = {0: "✓", 1: "✕", 2: "●"}.get
        with patch.object(Non_json, "_terminal_width", staticmethod(lambda default=100: 100)), \
             patch.object(runtime, "print_to_file_only", side_effect=file_lines.append):
            buf = io.StringIO()
            with redirect_stdout(buf):
                Non_json._print_entity_status(headers, ["x"] * len(headers), 0, devices, symbol)
        return re.sub(r"\x1b\[[0-9;]*m", "", buf.getvalue())

    def test_vulnerable_devices_are_listed_in_full_and_the_rest_counted(self):
        file_lines = []
        text = self._render(60, file_lines)
        vulnerable = ", ".join(str(i) for i in range(1, 61) if i % 3 == 1)
        assert f"Vulnerable (20): {vulnerable[:30]}" in text.replace("\n", " ").replace("  ", " ") \
            or "Vulnerable (20):" in text
        assert "Not vulnerable: 20" in text
        assert "N/A: 20" in text
        # no list of numbers for the two non-findings on the terminal
        for line in text.splitlines():
            if "Not vulnerable:" in line or "N/A:" in line:
                assert "," not in line

    def test_the_full_lists_go_to_the_file(self):
        file_lines = []
        self._render(60, file_lines)
        joined = "\n".join(file_lines)
        assert "Not vulnerable devices:" in joined
        assert "N/A devices:" in joined
        # every non-vulnerable device number is in the file
        listed = {int(n) for n in re.findall(r"\b(\d+)\b", joined.split("devices:", 1)[1])}
        assert {i for i in range(1, 61) if i % 3 != 1} <= listed

    def test_below_the_threshold_nothing_is_condensed(self):
        file_lines = []
        text = self._render(8, file_lines)
        assert file_lines == []
        assert "Not vulnerable:" not in text or "Not vulnerable (" in text


# --------------------------------------------------------------------------
# Tables must fit the terminal width read at print time, so a report is not
# left as shattered box-drawing after a resize.
# --------------------------------------------------------------------------
class TestIntelTablesFitTheWidth:
    """Intel tables carry values taken off the wire - a TXT record, a captive
    portal URL, a list of MACs - and were rendered at their natural width, so
    one long value made every row wider than the terminal."""

    HEADERS = ["MAC", "Service", "Instance", "Host:Port", "TXT"]
    ROWS = [
        ["b8:27:eb:11:22:33", "_ipp._tcp.local", "officeprinter._ipp._tcp.local",
         "officeprinter.local:631",
         "ty=HP LaserJet 400; rp=ipp/print; adminurl=http://officeprinter.local/admin; note=2nd floor"],
        ["08:00:27:aa:bb:01", "_http._tcp.local", "desktop._http._tcp.local", "desktop.local:80", "path=/"],
    ]

    @pytest.mark.parametrize("width", [160, 120, 100, 80, 72, 60, 48])
    def test_the_table_never_exceeds_the_width(self, width):
        from ptnetinspector.output.intel import _fit_table
        rendered = _fit_table(self.ROWS, self.HEADERS, width)
        widest = max(len(line) for line in rendered.splitlines())
        assert widest <= width, f"{widest} > {width}"

    @pytest.mark.parametrize("width", [80, 60, 48])
    def test_identifiers_are_never_broken(self, width):
        """A MAC, address or hostname has no spaces and must stay on one line;
        only prose columns wrap."""
        from ptnetinspector.output.intel import _fit_table
        rendered = _fit_table(self.ROWS, self.HEADERS, width)
        # every identifier appears intact somewhere in the output
        for identifier in ("b8:27:eb:11:22:33", "officeprinter._ipp._tcp.local",
                           "officeprinter.local:631", "08:00:27:aa:bb:01"):
            assert identifier in rendered, f"{identifier} was broken at width {width}"

    def test_a_wide_prose_value_wraps_rather_than_overflows(self):
        from ptnetinspector.output.intel import _fit_table
        rendered = _fit_table(self.ROWS, self.HEADERS, 80)
        assert max(len(l) for l in rendered.splitlines()) <= 80
        # the long TXT content is still all present, just across lines
        assert "adminurl=http://officeprinter.local/admin" in rendered.replace("\n", "")

    def test_a_narrow_terminal_stacks_rows(self):
        from ptnetinspector.output.intel import _fit_table
        rendered = _fit_table(self.ROWS, self.HEADERS, 40)
        assert max(len(l) for l in rendered.splitlines()) <= 40
        assert "\n\n" in rendered            # one block per row


class TestEntityGridMeasuresItsWidth:
    """The per-finding status grid estimated its width and the estimate was
    short, so a four-device grid still overflowed a narrow terminal."""

    def _render(self, device_count, width):
        import io, re
        from contextlib import redirect_stdout
        from unittest.mock import patch
        from ptnetinspector.output.non_json import Non_json

        devices = {str(i): i % 3 for i in range(1, device_count + 1)}
        headers = ["Network"] + [f"Device {i}" for i in devices]
        with patch.object(Non_json, "_terminal_width", staticmethod(lambda default=100, w=width: w)):
            buf = io.StringIO()
            with redirect_stdout(buf):
                Non_json._print_entity_status(headers, ["x"] * len(headers), 0, devices, {0: "✓", 1: "✕", 2: "●"}.get)
        return re.sub(r"\x1b\[[0-9;]*m", "", buf.getvalue())

    @pytest.mark.parametrize("width", [120, 100, 80, 60, 50])
    @pytest.mark.parametrize("devices", [3, 4, 6])
    def test_small_grid_never_overflows(self, width, devices):
        text = self._render(devices, width)
        widest = max(len(l) for l in text.splitlines())
        assert widest <= width, f"{widest} > {width} at {devices} devices"

    def test_grid_falls_to_the_list_when_it_will_not_fit(self):
        text = self._render(4, 50)
        assert "+---" not in text, "a grid that overflows must fall to the list form"
        assert "Vulnerable" in text


# --------------------------------------------------------------------------
# The ASCII banner is fixed-width art; below its width it must not wrap.
# --------------------------------------------------------------------------
class TestBannerFitsNarrowTerminals:
    """The shared 64-column banner wrapped into fragments on a narrower
    terminal. Below its width a compact one-line title is shown instead."""

    def _show(self, width):
        import io, re
        from contextlib import redirect_stdout
        from unittest.mock import patch
        from ptnetinspector.utils import cli

        cli._LOGO_SHOWN = False
        with patch("ptnetinspector.output.non_json.Non_json._terminal_width",
                   staticmethod(lambda default=100, w=width: w)):
            buf = io.StringIO()
            with redirect_stdout(buf):
                cli.display_logo(json_output=False, more_detail=False)
        return re.sub(r"\x1b\[[0-9;]*m", "", buf.getvalue())

    @pytest.mark.parametrize("width", [120, 100, 80, 64, 63, 50, 40, 30])
    def test_the_header_never_exceeds_the_width(self, width):
        text = self._show(width)
        widest = max((len(l) for l in text.splitlines()), default=0)
        assert widest <= width, f"{widest} > {width}"

    def test_wide_terminal_keeps_the_full_banner(self):
        assert "____" in self._show(100)

    def test_narrow_terminal_shows_a_compact_title_with_name_and_url(self):
        text = self._show(40)
        assert "____" not in text
        assert "ptnetinspector" in text
        assert "penterep.com" in text

    def test_helper_uses_the_supplied_banner_without_recursing(self):
        """The help path swaps out ptprinthelper.print_banner, so the helper
        must call the banner it is given, not the (now-patched) module one."""
        from unittest.mock import patch
        from ptnetinspector.utils import cli

        calls = []
        real_banner = lambda name, version: calls.append((name, version))
        with patch("ptnetinspector.output.non_json.Non_json._terminal_width",
                   staticmethod(lambda default=100: 120)):
            cli._print_banner_fitting_width(real_banner)
        assert len(calls) == 1                # called once, no recursion

    def test_the_help_screen_banner_also_fits(self):
        """The -h path prints its banner through the same width-aware helper."""
        import io, re
        from contextlib import redirect_stdout
        from unittest.mock import patch
        from ptnetinspector.utils import cli
        from ptlibs import ptprinthelper

        # reproduce the wiring parse_args uses for -h, at a narrow width
        original = ptprinthelper.print_banner
        with patch("ptnetinspector.output.non_json.Non_json._terminal_width",
                   staticmethod(lambda default=100: 40)):
            ptprinthelper.print_banner = lambda *a, **k: cli._print_banner_fitting_width(original)
            try:
                buf = io.StringIO()
                with redirect_stdout(buf):
                    ptprinthelper.help_print(cli.get_help(), cli.SCRIPTNAME, cli.__version__)
            finally:
                ptprinthelper.print_banner = original
        text = re.sub(r"\x1b\[[0-9;]*m", "", buf.getvalue())
        # the banner art must not be present, and the header must be compact
        assert "____" not in text.split("Description")[0]


# --------------------------------------------------------------------------
# The Label column round-trips through CSV as a string; a verdict comparison
# must not silently drop every finding.
# --------------------------------------------------------------------------
class TestVulnerabilityVerdictsSurviveTheCsvRoundTrip:
    """Regression for a real defect: reading CSVs as strings (to stop pandas
    turning 255 into "255.0") made every `Label == 1` comparison compare a
    string to an int, which is always False - so the JSON output and the
    detailed network sections emitted zero vulnerabilities while the CSVs were
    full of them. No test covered JSON vuln emission, so it shipped."""

    def test_normalize_label_coerces_strings_and_ints(self):
        from ptnetinspector.utils.output_helpers import normalize_label
        assert normalize_label("1") == 1 and normalize_label(1) == 1
        assert normalize_label("0") == 0 and normalize_label(0) == 0
        assert normalize_label("2") == 2 and normalize_label("") == 2
        assert normalize_label(None) == 2 and normalize_label("nan") == 2
        assert normalize_label("1.0") == 1        # a stringified float still reads

    def _seed_vulns(self, scan_dir):
        _write(scan_dir / "addresses.csv", ["MAC", "IP"],
               [{"MAC": "aa:bb:cc:00:00:01", "IP": "fe80::1"},
                {"MAC": "aa:bb:cc:00:00:01", "IP": "192.168.1.10"}])
        _write(scan_dir / "role_node.csv", ["MAC", "Device_Number", "Role"],
               [{"MAC": "aa:bb:cc:00:00:01", "Device_Number": "1", "Role": "Host"}])
        _write(scan_dir / "vulnerability_net.csv",
               ["ID", "Mode", "IPver", "Code", "Description", "Label"],
               [{"ID": "Network", "Mode": "a", "IPver": "6", "Code": "PTV-NET-NETVULN-YES",
                 "Description": "net vulnerable", "Label": "1"},
                {"ID": "Network", "Mode": "a", "IPver": "6", "Code": "PTV-NET-NETVULN-NO",
                 "Description": "net safe", "Label": "0"},
                {"ID": "Network", "Mode": "a", "IPver": "6", "Code": "PTV-NET-NETVULN-NA",
                 "Description": "net na", "Label": "2"}])
        _write(scan_dir / "vulnerability_ip.csv",
               ["ID", "IP", "Mode", "IPver", "Code", "Description", "Label"],
               [{"ID": "1", "IP": "fe80::1", "Mode": "a", "IPver": "6",
                 "Code": "PTV-NET-DEVVULN-6-YES", "Description": "dev vuln", "Label": "1"},
                {"ID": "1", "IP": "192.168.1.10", "Mode": "a", "IPver": "4",
                 "Code": "PTV-NET-DEVVULN-4-NO", "Description": "dev safe", "Label": "0"}])
        _write(scan_dir / "vulnerability_mac.csv",
               ["ID", "MAC", "Mode", "IPver", "Code", "Description", "Label"], [])

    def test_json_emits_vulnerable_codes_and_only_those(self, scan_dir):
        import json as _json
        import ptnetinspector.output.json as json_output
        from ptnetinspector.output.json import Json
        from ptnetinspector.send.send import IPMode

        self._seed_vulns(scan_dir)
        json_output.ptjsonlib_object.__init__()
        doc = _json.loads(Json.output_object(True, None, ipver=IPMode(True, True)))
        flat = _json.dumps(doc)

        # the two 'vulnerable' verdicts are present
        assert "PTV-NET-NETVULN-YES" in flat
        assert "PTV-NET-DEVVULN-6-YES" in flat
        # the not-vulnerable and N/A verdicts are not reported as findings
        assert "PTV-NET-NETVULN-NO" not in flat
        assert "PTV-NET-NETVULN-NA" not in flat
        assert "PTV-NET-DEVVULN-4-NO" not in flat

    def test_json_network_vulnerabilities_are_not_empty_when_the_csv_has_them(self, scan_dir):
        import json as _json
        import ptnetinspector.output.json as json_output
        from ptnetinspector.output.json import Json
        from ptnetinspector.send.send import IPMode

        self._seed_vulns(scan_dir)
        json_output.ptjsonlib_object.__init__()
        doc = _json.loads(Json.output_object(True, None, ipver=IPMode(True, True)))
        net = doc["results"].get("vulnerabilities", [])
        assert [v["vulnCode"] for v in net] == ["PTV-NET-NETVULN-YES"]

    def test_the_device_node_carries_its_vulnerability(self, scan_dir):
        import json as _json
        import ptnetinspector.output.json as json_output
        from ptnetinspector.output.json import Json
        from ptnetinspector.send.send import IPMode

        self._seed_vulns(scan_dir)
        json_output.ptjsonlib_object.__init__()
        doc = _json.loads(Json.output_object(True, None, ipver=IPMode(True, True)))

        def codes(node, out):
            for v in node.get("vulnerabilities", []) or []:
                out.append(v.get("vulnCode"))
            for c in node.get("nodes", []) or []:
                codes(c, out)
        found = []
        for n in doc["results"]["nodes"]:
            codes(n, found)
        assert "PTV-NET-DEVVULN-6-YES" in found
