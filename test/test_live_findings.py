"""Regression tests for defects found by running the scanner against a live link.

Each of these reproduced only once real frames crossed a real interface: the
offline tests exercised the parsers directly and so never saw the CSV
round-trip, the mix of protocols one device emits, or the layer layout scapy
actually produces for an IGMPv3 query.
"""
import csv
import os
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
