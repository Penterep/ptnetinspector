"""Regression tests for dual-stack scanning and the -nc flag.

Covers behaviour that previously went wrong on a network carrying IPv4, IPv6
link-local and IPv6 global unicast traffic at the same time, with devices from
several operating systems.
"""
import csv
import ipaddress
from unittest.mock import patch

import pytest

from ptnetinspector.send.send import IPMode


RA_FIELDS = ['MAC', 'IP', 'M', 'O', 'H', 'A', 'L', 'Preference', 'Router_lft',
             'Reachable_time', 'Retrans_time', 'DNS', 'MTU', 'Prefix',
             'Valid_lft', 'Preferred_lft']


def _write_csv(path, fieldnames, rows):
    with open(path, 'w', newline='') as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


@pytest.fixture
def scan_dir(temp_dir):
    """Temp directory wired in as the tmp/CSV location for the modules under test."""
    def csv_path(name, interface=None):
        return temp_dir / name

    _write_csv(temp_dir / "networks.csv", ['network_prefix', 'prefix_length'], [])
    _write_csv(temp_dir / "RA.csv", RA_FIELDS, [])

    with patch('ptnetinspector.entities.networks.get_csv_path', side_effect=csv_path), \
         patch('ptnetinspector.utils.address_control.get_csv_path', side_effect=csv_path):
        yield temp_dir


def _set_networks(scan_dir, rows):
    _write_csv(scan_dir / "networks.csv", ['network_prefix', 'prefix_length'], [
        {'network_prefix': net, 'prefix_length': plen} for net, plen in rows
    ])


def _set_ra_prefixes(scan_dir, prefixes):
    _write_csv(scan_dir / "RA.csv", RA_FIELDS, [
        {'MAC': '00:11:22:00:00:01', 'IP': 'fe80::211:22ff:fe00:1', 'A': 'Yes', 'Prefix': p}
        for p in prefixes
    ])


class TestLocalAddressRetention:
    """filter_unicast_addresses must keep addresses belonging to on-link devices."""

    def _filter(self, ips):
        from ptnetinspector.utils.address_control import AddressMapping, filter_unicast_addresses

        mappings = [AddressMapping(mac="00:11:22:33:44:55", ip=ip) for ip in ips]
        kept = filter_unicast_addresses(mappings, IPMode(True, True))
        return {m.ip for m in kept}

    def test_keeps_gua_from_scanner_prefix(self, scan_dir):
        _set_networks(scan_dir, [("192.168.1.0", 24), ("2001:db8:1::", 64)])
        assert "2001:db8:1::20" in self._filter(["2001:db8:1::20"])

    def test_keeps_gua_from_other_advertised_prefix(self, scan_dir):
        """A device may use a router prefix the scanner itself did not adopt."""
        _set_networks(scan_dir, [("2001:db8:1::", 64)])
        _set_ra_prefixes(scan_dir, ["2001:db8:1::/64", "2001:db8:2::/64"])
        assert "2001:db8:2::40" in self._filter(["2001:db8:2::40"])

    def test_keeps_unique_local_address(self, scan_dir):
        """macOS/Windows commonly hold a ULA alongside a GUA."""
        _set_networks(scan_dir, [("2001:db8:1::", 64)])
        assert "fd12:3456:789a::30" in self._filter(["fd12:3456:789a::30"])

    def test_keeps_link_local_and_ipv4(self, scan_dir):
        _set_networks(scan_dir, [("192.168.1.0", 24), ("2001:db8:1::", 64)])
        kept = self._filter(["fe80::211:22ff:fe00:2", "192.168.1.20"])
        assert kept == {"fe80::211:22ff:fe00:2", "192.168.1.20"}

    def test_drops_multicast(self, scan_dir):
        _set_networks(scan_dir, [("2001:db8:1::", 64)])
        assert self._filter(["ff02::1"]) == set()

    def test_mixed_os_dual_stack_lan_fully_retained(self, scan_dir):
        """Full mixed-OS LAN: nothing legitimate is silently discarded."""
        _set_networks(scan_dir, [("192.168.1.0", 24), ("2001:db8:1::", 64)])
        _set_ra_prefixes(scan_dir, ["2001:db8:1::/64", "2001:db8:2::/64"])
        addresses = [
            "192.168.1.1", "fe80::211:22ff:fe00:1", "2001:db8:1::1",      # Linux router
            "192.168.1.20", "2001:db8:1::b1ff:cafe",                       # Windows privacy addr
            "192.168.1.30", "fd12:3456:789a::30",                          # macOS ULA
            "192.168.1.40", "2001:db8:2::40",                              # Android, 2nd prefix
            "192.168.1.50", "fe80::211:22ff:fe00:5",                       # IoT printer
        ]
        assert self._filter(addresses) == set(addresses)


class TestRaPrefixLoading:
    """Networks.load_ra_prefixes reads on-link prefixes from observed RAs."""

    def test_reads_advertised_prefixes(self, scan_dir):
        from ptnetinspector.entities.networks import Networks

        _set_ra_prefixes(scan_dir, ["2001:db8:1::/64", "2001:db8:2::/64"])
        assert Networks.load_ra_prefixes() == [
            ipaddress.ip_network("2001:db8:1::/64"),
            ipaddress.ip_network("2001:db8:2::/64"),
        ]

    def test_empty_when_no_ra_seen(self, scan_dir):
        from ptnetinspector.entities.networks import Networks

        assert Networks.load_ra_prefixes() == []

    def test_ignores_malformed_prefix(self, scan_dir):
        from ptnetinspector.entities.networks import Networks

        _set_ra_prefixes(scan_dir, ["not-a-prefix", "2001:db8:9::/64"])
        assert Networks.load_ra_prefixes() == [ipaddress.ip_network("2001:db8:9::/64")]


class TestNoCheckSkipsProbing:
    """-nc must actually suppress the reachability probes."""

    def _run(self, scan_dir, verify):
        from ptnetinspector.utils import address_control

        _write_csv(scan_dir / "addresses.csv", ['MAC', 'IP'],
                   [{'MAC': '00:11:22:33:44:55', 'IP': '2001:db8:1::20'}])
        _set_networks(scan_dir, [("2001:db8:1::", 64)])

        with patch.object(address_control.AddressValidator, 'verify_all_mappings') as probe:
            address_control.validate_addresses_mapping("eth0", IPMode(True, True), verify=verify)
        return probe

    def test_probes_run_by_default(self, scan_dir):
        assert self._run(scan_dir, verify=True).called

    def test_nc_skips_probes(self, scan_dir):
        assert not self._run(scan_dir, verify=False).called

    def test_nc_keeps_unresponsive_addresses(self, scan_dir):
        from ptnetinspector.utils import address_control

        _write_csv(scan_dir / "addresses.csv", ['MAC', 'IP'],
                   [{'MAC': '00:11:22:33:44:55', 'IP': '2001:db8:1::20'}])
        _set_networks(scan_dir, [("2001:db8:1::", 64)])

        address_control.validate_addresses_mapping("eth0", IPMode(True, True), verify=False)

        with open(scan_dir / "addresses.csv") as handle:
            kept = {row['IP'] for row in csv.DictReader(handle)}
        assert kept == {"2001:db8:1::20"}


class TestNoCheckKeepsLocalScope:
    """-nc drops the reachability probe, not the local-network filter.

    Remote hosts merely routed through a gateway must never be attributed to it.
    """

    def _filter(self, ips, keep_solicited_node):
        from ptnetinspector.utils.address_control import AddressMapping, filter_unicast_addresses

        mappings = [AddressMapping(mac="00:50:56:e9:10:2e", ip=ip) for ip in ips]
        kept = filter_unicast_addresses(mappings, IPMode(True, True),
                                        keep_solicited_node=keep_solicited_node)
        return {m.ip for m in kept}

    def test_remote_addresses_excluded_under_nc(self, scan_dir):
        _set_networks(scan_dir, [("192.168.153.0", 24)])
        kept = self._filter(["192.168.153.2", "160.79.104.10", "20.42.65.89"],
                            keep_solicited_node=True)
        assert kept == {"192.168.153.2"}

    def test_solicited_node_groups_kept_only_under_nc(self, scan_dir):
        _set_networks(scan_dir, [("2001:db8:1::", 64)])
        solicited = "ff02::1:ff00:20"
        assert solicited in self._filter([solicited], keep_solicited_node=True)
        assert solicited not in self._filter([solicited], keep_solicited_node=False)

    def test_ordinary_multicast_never_kept(self, scan_dir):
        _set_networks(scan_dir, [("2001:db8:1::", 64)])
        assert self._filter(["ff02::1"], keep_solicited_node=True) == set()


class TestOutputReadsFilteredAddresses:
    """Both modes report from addresses.csv; -nc changes its contents, not the file."""

    @pytest.mark.parametrize("check_addresses", [True, False])
    def test_text_output_source_file(self, temp_dir, check_addresses):
        from ptnetinspector.utils import runtime

        seen = {}

        def fake_output_general(mode, ipver, addresses_file_name=None, **kwargs):
            seen['file'] = addresses_file_name

        with patch.object(runtime, '_suppress_non_json', False), \
             patch.object(runtime.Non_json, 'output_general', side_effect=fake_output_general), \
             patch.object(runtime.Non_json, 'read_vulnerability_table'):
            runtime.handle_output(
                "a", [], [], False, False, False, check_addresses,
                "eth0", IPMode(True, True), None,
                lambda name: temp_dir / name, None, None,
            )

        assert seen['file'].name == "addresses.csv"


class TestPossibleAddressGuessing:
    """Solicited-node groups yield '(possible address)' entries only under -nc.

    These are guesses reconstructed from multicast group membership, so they must
    never appear when probing confirmed the real addresses, must not duplicate an
    address already known, and must agree between the terminal and JSON output.
    """

    MAC_KNOWN = "00:11:22:00:00:01"     # real address plus its own solicited group
    MAC_ONLY_GROUP = "00:11:22:00:00:02"  # only ever seen via a solicited group
    MAC_EXTRA = "00:11:22:00:00:03"     # known address plus a group for an unseen one

    @pytest.fixture
    def rendered(self, temp_dir):
        import ptnetinspector.output.non_json as NJ
        import ptnetinspector.output.json as JS
        import ptnetinspector.utils.csv_helpers as CH

        csv_path = lambda n, i=None: temp_dir / n
        # Redirect at the source so every helper that resolves a CSV path follows.
        with patch('ptnetinspector.utils.path.get_tmp_path', lambda i=None: temp_dir), \
             patch.object(CH, 'get_tmp_path', lambda i=None: temp_dir):
            CH.create_csv()

        _write_csv(temp_dir / "addresses.csv", ['MAC', 'IP'], [
            {'MAC': self.MAC_KNOWN, 'IP': '2001:db8::20'},
            {'MAC': self.MAC_KNOWN, 'IP': 'ff02::1:ff00:20'},
            {'MAC': self.MAC_ONLY_GROUP, 'IP': 'ff02::1:ff00:99'},
            {'MAC': self.MAC_EXTRA, 'IP': 'fe80::211:22ff:fe00:3'},
            {'MAC': self.MAC_EXTRA, 'IP': 'ff02::1:ff44:55'},
            {'MAC': self.MAC_EXTRA, 'IP': '192.168.1.30'},
        ])
        _write_csv(temp_dir / "role_node.csv", ['MAC', 'Device_Number', 'Role'], [
            {'MAC': self.MAC_KNOWN, 'Device_Number': 1, 'Role': 'Host'},
            {'MAC': self.MAC_ONLY_GROUP, 'Device_Number': 2, 'Role': 'Host'},
            {'MAC': self.MAC_EXTRA, 'Device_Number': 3, 'Role': 'Host'},
        ])

        def render(ip_mode, check_addresses):
            import io, contextlib, re as _re, json as _json
            from ptnetinspector.output.non_json import Non_json
            from ptnetinspector.output.json import Json
            with patch('ptnetinspector.utils.path.get_tmp_path', lambda i=None: temp_dir), \
                 patch('ptnetinspector.utils.ip_utils.get_csv_path', csv_path), \
                 patch.object(NJ, 'get_csv_path', csv_path), \
                 patch.object(JS, 'get_csv_path', csv_path):
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    Non_json.output_general("a", ip_mode, temp_dir / "addresses.csv",
                                            check_addresses=check_addresses)
                text = _re.sub(r'\x1b\[[0-9;]*m', '', buf.getvalue())
                JS.ptjsonlib_object.__init__()
                payload = _json.loads(Json.output_object(
                    True, None, ipver=ip_mode, check_addresses=check_addresses))
            term = sorted(l.split()[1] for l in text.splitlines() if "possible address" in l)
            flat = []
            def walk(ns):
                for n in ns or []:
                    flat.append(n); walk(n.get("nodes"))
            walk(payload.get("results", {}).get("nodes"))
            js = sorted(n["properties"]["IP"] for n in flat
                        if n.get("type") == "Address"
                        and n["properties"].get("description") == "possible address")
            return term, js

        return render

    def test_no_guesses_when_probing_enabled(self, rendered):
        term, js = rendered(IPMode(True, True), check_addresses=True)
        assert term == [] and js == []

    def test_guesses_shown_under_nc(self, rendered):
        term, _ = rendered(IPMode(True, True), check_addresses=False)
        assert len(term) == 2

    def test_guess_suppressed_when_real_address_known(self, rendered):
        """Device 1's group is covered by 2001:db8::20, so it must not be guessed."""
        term, _ = rendered(IPMode(True, True), check_addresses=False)
        assert not any(guess.endswith("XX00:0020") for guess in term)

    def test_guess_shown_for_never_observed_address(self, rendered):
        term, _ = rendered(IPMode(True, True), check_addresses=False)
        assert any(guess.endswith("XX00:0099") for guess in term)
        assert any(guess.endswith("XX44:0055") for guess in term)

    def test_no_ipv6_guesses_in_ipv4_only_mode(self, rendered):
        term, js = rendered(IPMode(True, False), check_addresses=False)
        assert term == [] and js == []

    @pytest.mark.parametrize("ip_mode", [IPMode(True, True), IPMode(False, True), IPMode(True, False)])
    @pytest.mark.parametrize("check_addresses", [True, False])
    def test_terminal_and_json_agree(self, rendered, ip_mode, check_addresses):
        term, js = rendered(ip_mode, check_addresses)
        assert term == js


class TestVulnerabilityTableWidth:
    """The per-vulnerability status block must stay inside the terminal width."""

    def _render(self, device_count, columns):
        import io, contextlib, re as _re
        from ptnetinspector.output.non_json import Non_json

        devices = {str(i): i % 3 for i in range(1, device_count + 1)}
        headers = ['Network'] + [f'Device {i}' for i in devices]
        row = ['x'] * len(headers)
        symbol = lambda label: "*"

        with patch.object(Non_json, '_terminal_width', staticmethod(lambda default=100: columns)):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                Non_json._print_entity_status(headers, row, 0, devices, symbol)
        text = _re.sub(r'\x1b\[[0-9;]*m', '', buf.getvalue())
        return text, max((len(l) for l in text.splitlines()), default=0)

    def test_small_network_keeps_grid(self):
        text, width = self._render(3, 100)
        assert '+---' in text, "few devices should still render the familiar grid"
        assert width <= 100

    def test_large_network_stays_within_width(self):
        text, width = self._render(30, 100)
        assert width <= 100, f"line of {width} chars overflows a 100-column terminal"
        assert '+---' not in text, "wide results must not use the per-device grid"

    def test_large_network_lists_every_device(self):
        text, _ = self._render(30, 100)
        listed = set()
        for line in text.splitlines():
            if '(' in line and '):' in line:
                listed.update(p.strip() for p in line.split('):', 1)[1].split(','))
        assert {str(i) for i in range(1, 31)}.issubset(listed)

    def test_narrow_terminal_still_fits(self):
        _, width = self._render(30, 60)
        assert width <= 60
