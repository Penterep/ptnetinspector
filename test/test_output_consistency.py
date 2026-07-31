"""Regression tests for report consistency between the terminal and JSON output.

Covers defects where the two views of the same scan disagreed, or where repeated
evaluation passes (several modes in one command) inflated the results.
"""
import csv
import json as _json
from unittest.mock import patch

import pytest

from ptnetinspector.send.send import IPMode


def _write_csv(path, fieldnames, rows):
    with open(path, 'w', newline='') as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def _nodes(payload):
    flat = []

    def walk(nodes):
        for node in nodes or []:
            flat.append(node)
            walk(node.get("nodes"))

    walk(payload.get("results", {}).get("nodes"))
    return flat


@pytest.fixture
def report(temp_dir):
    """Render the JSON report from CSVs in a temp scan directory."""
    import ptnetinspector.output.json as JS
    import ptnetinspector.utils.csv_helpers as CH

    csv_path = lambda name, iface=None: temp_dir / name
    with patch('ptnetinspector.utils.path.get_tmp_path', lambda i=None: temp_dir), \
         patch.object(CH, 'get_tmp_path', lambda i=None: temp_dir):
        CH.create_csv()

    def render(mode=None):
        with patch('ptnetinspector.utils.path.get_tmp_path', lambda i=None: temp_dir), \
             patch('ptnetinspector.utils.ip_utils.get_csv_path', csv_path), \
             patch.object(JS, 'get_csv_path', csv_path):
            return _json.loads(JS.Json.output_object(True, mode, ipver=IPMode(True, True)))

    return temp_dir, render


class TestJsonReportIsRebuiltNotAppended:
    """Building the report twice in one run must not double every node.

    Passive and 802.1x used to emit their own report before the final one, and the
    shared json object appends nodes, so every device and address appeared twice.
    """

    @pytest.fixture(autouse=True)
    def scan_data(self, report):
        temp_dir, _ = report
        _write_csv(temp_dir / "addresses.csv", ['MAC', 'IP'], [
            {'MAC': '00:11:22:00:00:01', 'IP': '192.168.1.10'},
            {'MAC': '00:11:22:00:00:01', 'IP': 'fe80::211:22ff:fe00:1'},
        ])
        _write_csv(temp_dir / "role_node.csv", ['MAC', 'Device_Number', 'Role'], [
            {'MAC': '00:11:22:00:00:01', 'Device_Number': 1, 'Role': 'Host'},
        ])

    def test_single_build(self, report):
        _, render = report
        nodes = _nodes(render())
        assert sum(1 for n in nodes if n["type"] == "Device") == 1
        assert sum(1 for n in nodes if n["type"] == "Address") == 2

    def test_repeated_builds_do_not_accumulate(self, report):
        _, render = report
        render("p")
        nodes = _nodes(render())
        assert sum(1 for n in nodes if n["type"] == "Device") == 1
        assert sum(1 for n in nodes if n["type"] == "Address") == 2


class TestJsonUsesFilteredAddresses:
    """The report must never fall back to the raw capture.

    addresses_unfiltered.csv still holds remote hosts seen in transit; reporting
    them as device addresses contradicted the terminal output, which only ever
    reads addresses.csv.
    """

    def test_raw_capture_is_not_reported(self, report):
        temp_dir, render = report
        _write_csv(temp_dir / "addresses.csv", ['MAC', 'IP'], [])
        _write_csv(temp_dir / "addresses_unfiltered.csv", ['MAC', 'IP'], [
            {'MAC': '00:11:22:00:00:01', 'IP': '192.168.1.10'},
            {'MAC': '00:11:22:00:00:01', 'IP': '160.79.104.10'},
        ])
        _write_csv(temp_dir / "role_node.csv", ['MAC', 'Device_Number', 'Role'], [
            {'MAC': '00:11:22:00:00:01', 'Device_Number': 1, 'Role': 'Host'},
        ])
        assert _nodes(render()) == []


NET_FIELDS = ['ID', 'Mode', 'IPver', 'Code', 'Description', 'Label']


class TestNetworkVulnerabilityDeduplication:
    """Network findings must survive several evaluation passes without piling up."""

    def _vuln(self, temp_dir):
        import ptnetinspector.vulnerability.base as B
        import ptnetinspector.utils.csv_helpers as CH
        from ptnetinspector.vulnerability.base import VulnerabilityBase

        with patch.object(CH, 'get_tmp_path', lambda i=None: temp_dir):
            CH.create_csv()
        with patch.object(B, 'get_csv_path', lambda name, iface=None: temp_dir / name):
            return VulnerabilityBase(
                "eth0", ["a", "a+"], IPMode(True, True), None, None, None, None, None,
                role_file=temp_dir / "role_node.csv",
                time_incoming_file=temp_dir / "time_incoming.csv",
                time_all_file=temp_dir / "time_all.csv",
                vulnerability_file=temp_dir / "vulnerability_mac.csv",
            )

    def _rows(self, temp_dir):
        with open(temp_dir / "vulnerability_net.csv", newline='') as handle:
            return list(csv.DictReader(handle))

    def test_repeated_passes_write_one_row(self, temp_dir):
        vuln = self._vuln(temp_dir)
        row = ("Network", "", "a,a+", "6", "PTV-NET-TEST-X", "Network allows X", "1")
        for _ in range(3):
            new_rows = []
            vuln._add_vuln_if_new(row, vuln._load_existing_rows(), new_rows)
            vuln._write_vulnerabilities(new_rows)
        assert len(self._rows(temp_dir)) == 1

    def test_network_rows_stay_out_of_the_device_file(self, temp_dir):
        """The device file is MAC-scoped; a network finding must not be copied there."""
        vuln = self._vuln(temp_dir)
        row = ("Network", "", "a,a+", "6", "PTV-NET-TEST-X", "Network allows X", "1")
        new_rows = []
        vuln._add_vuln_if_new(row, vuln._load_existing_rows(), new_rows)
        vuln._write_vulnerabilities(new_rows)
        with open(temp_dir / "vulnerability_mac.csv", newline='') as handle:
            assert list(csv.DictReader(handle)) == []

    def test_device_rows_still_deduplicated(self, temp_dir):
        vuln = self._vuln(temp_dir)
        row = ("1", "00:11:22:00:00:01", "a,a+", "6", "PTV-NET-TEST-XDEV", "Device does X", "1")
        for _ in range(3):
            new_rows = []
            vuln._add_vuln_if_new(row, vuln._load_existing_rows(), new_rows)
            vuln._write_vulnerabilities(new_rows)
        with open(temp_dir / "vulnerability_mac.csv", newline='') as handle:
            assert len(list(csv.DictReader(handle))) == 1


class TestNetworkScopedFindingsAreDisplayed:
    """A finding with no device and no IP family still has to reach the output.

    The 802.1x verdict is network-scoped and carries an empty IPver; it was stored
    and returned in JSON while the terminal showed nothing at all.
    """

    @pytest.fixture
    def rendered(self, temp_dir):
        import ptnetinspector.output.non_json as NJ
        import ptnetinspector.utils.csv_helpers as CH
        import io
        import contextlib
        import re

        csv_path = lambda name, iface=None: temp_dir / name
        with patch('ptnetinspector.utils.path.get_tmp_path', lambda i=None: temp_dir), \
             patch.object(CH, 'get_tmp_path', lambda i=None: temp_dir):
            CH.create_csv()

        _write_csv(temp_dir / "vulnerability_net.csv", NET_FIELDS, [
            {'ID': 'Network', 'Mode': '802.1x', 'IPver': '',
             'Code': 'PTV-NET-NET-MISCONF-8021X',
             'Description': 'Network does not have 802.1x deployed', 'Label': '1'},
        ])

        def render(ip_mode=IPMode(True, True)):
            from ptnetinspector.output.non_json import Non_json
            with patch('ptnetinspector.utils.path.get_tmp_path', lambda i=None: temp_dir), \
                 patch('ptnetinspector.utils.ip_utils.get_csv_path', csv_path), \
                 patch.object(NJ, 'get_csv_path', csv_path):
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    Non_json.read_vulnerability_table("802.1x", ip_mode)
                return re.sub(r'\x1b\[[0-9;]*m', '', buf.getvalue())

        return render

    def test_finding_reaches_the_tables(self, rendered):
        assert "PTV-NET-NET-MISCONF-8021X" in rendered()

    def test_verdict_is_not_forced_to_na(self, rendered):
        """802.1x was hardcoded to render N/A, hiding the verdict it had reached."""
        cells = "\n".join(l for l in rendered().splitlines() if "Legend" not in l)
        assert "✕" in cells, "a stored 'vulnerable' label must render as vulnerable"
        assert "●" not in cells, "nothing here is N/A"

    @pytest.mark.parametrize("ip_mode", [IPMode(True, True), IPMode(True, False), IPMode(False, True)])
    def test_shown_whatever_ip_family_was_selected(self, rendered, ip_mode):
        assert "PTV-NET-NET-MISCONF-8021X" in rendered(ip_mode)


class TestIpVersionSelection:
    """Family-specific findings still have to honour -4 / -6."""

    def test_family_specific_rows_follow_selection(self):
        from ptnetinspector.output.non_json import Non_json

        assert Non_json._ipver_selected('4', IPMode(True, False))
        assert not Non_json._ipver_selected('6', IPMode(True, False))
        assert Non_json._ipver_selected('6', IPMode(False, True))
        assert not Non_json._ipver_selected('4', IPMode(False, True))

    def test_family_agnostic_rows_always_apply(self):
        from ptnetinspector.output.non_json import Non_json

        for ip_mode in (IPMode(True, True), IPMode(True, False), IPMode(False, True)):
            assert Non_json._ipver_selected('', ip_mode)
            assert Non_json._ipver_selected('both', ip_mode)


class TestModeMatching:
    """The Mode column is a list, so 'a' must not be treated as a prefix of 'a+'."""

    def test_exact_entries_only(self):
        from ptnetinspector.utils.output_helpers import mode_matches

        assert mode_matches("a", "a")
        assert mode_matches("a", "a,a+")
        assert mode_matches("a+", "a,a+")
        assert mode_matches("p", "p,a,a+")
        assert not mode_matches("a", "a+"), "aggressive-only findings are not active findings"
        assert not mode_matches("a", "802.1x")
        assert not mode_matches("p", "a,a+")

    def test_no_mode_means_no_filter(self):
        from ptnetinspector.utils.output_helpers import mode_matches

        assert mode_matches(None, "a,a+")
        assert mode_matches(None, "")


class TestPacketTimelineIsRereadPerPass:
    """Each mode appends to the timeline before it is assessed.

    One Vulnerability object evaluates every mode of a run. Caching the timeline for
    its lifetime made every mode after the first assess only the packets captured
    before it ran, which silently lost most findings in multi-mode runs.
    """

    def _vuln(self, temp_dir):
        import ptnetinspector.vulnerability.base as B
        import ptnetinspector.utils.csv_helpers as CH
        from ptnetinspector.vulnerability.base import VulnerabilityBase

        with patch.object(CH, 'get_tmp_path', lambda i=None: temp_dir):
            CH.create_csv()
        with patch.object(B, 'get_csv_path', lambda name, iface=None: temp_dir / name):
            return VulnerabilityBase(
                "eth0", ["a", "a+"], IPMode(True, True), None, None, None, None, None,
                role_file=temp_dir / "role_node.csv",
                time_incoming_file=temp_dir / "time_incoming.csv",
                time_all_file=temp_dir / "time_all.csv",
                vulnerability_file=temp_dir / "vulnerability_mac.csv",
            )

    def _append(self, temp_dir, mac, packet):
        with open(temp_dir / "time_all.csv", 'a', newline='') as handle:
            csv.writer(handle).writerow(["2026-07-31 12:00:00", mac, packet])

    def test_rows_appended_between_passes_are_seen(self, temp_dir):
        vuln = self._vuln(temp_dir)
        self._append(temp_dir, "00:11:22:00:00:01", "first mode packet")
        assert len(vuln._get_time_all_rows()) == 1

        self._append(temp_dir, "00:11:22:00:00:02", "second mode packet")
        assert len(vuln._get_time_all_rows()) == 2, "a later pass must see the new packets"

    def test_unchanged_file_is_not_reread(self, temp_dir):
        vuln = self._vuln(temp_dir)
        self._append(temp_dir, "00:11:22:00:00:01", "packet")
        first = vuln._get_time_all_rows()
        assert vuln._get_time_all_rows() is first, "repeat reads within a pass stay cached"


class TestVulnerabilitySortHandlesEveryFileShape:
    """The dedupe helper is shared by the MAC, IP and network files."""

    def _run(self, temp_dir, rows):
        from ptnetinspector.utils.csv_helpers import sort_and_deduplicate_vul_csv

        path = temp_dir / "vulnerability_net.csv"
        _write_csv(path, NET_FIELDS, rows)
        sort_and_deduplicate_vul_csv(path)
        with open(path, newline='') as handle:
            return list(csv.DictReader(handle))

    def test_network_rows_survive(self, temp_dir):
        """Six-column rows were silently dropped by a length check."""
        rows = self._run(temp_dir, [
            {'ID': 'Network', 'Mode': 'a', 'IPver': '6', 'Code': 'PTV-B',
             'Description': 'b', 'Label': '0'},
            {'ID': 'Network', 'Mode': 'a', 'IPver': '4', 'Code': 'PTV-A',
             'Description': 'a', 'Label': '1'},
        ])
        assert [r['Code'] for r in rows] == ['PTV-A', 'PTV-B']

    def test_identical_rows_collapse(self, temp_dir):
        row = {'ID': 'Network', 'Mode': 'a', 'IPver': '6', 'Code': 'PTV-A',
               'Description': 'a', 'Label': '0'}
        assert len(self._run(temp_dir, [row, dict(row), dict(row)])) == 1

    def test_most_recent_verdict_wins(self, temp_dir):
        """A later pass re-assesses the whole timeline, so its verdict supersedes."""
        row = {'ID': 'Network', 'Mode': 'a', 'IPver': '6', 'Code': 'PTV-A',
               'Description': 'a', 'Label': '2'}
        assert [r['Label'] for r in self._run(temp_dir, [row, {**row, 'Label': '1'}])] == ['1']
        assert [r['Label'] for r in self._run(temp_dir, [{**row, 'Label': '1'}, row])] == ['2']
