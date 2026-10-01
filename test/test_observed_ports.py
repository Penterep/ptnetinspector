"""Tests for passive port observation.

The feature records the transport port a device was seen sending from, as a new
per-device attribute (MAC, IP, Port) folded into the inventory, the JSON report
and the network-intelligence section. It is an observation of traffic, never a
port scan.
"""
import csv

import pytest
from scapy.all import Ether, IP, IPv6, TCP, UDP, get_if_hwaddr, raw

from ptnetinspector.send.send import IPMode
from ptnetinspector.utils.csv_helpers import create_csv
from ptnetinspector.utils.path import get_csv_path, get_tmp_path, set_current_interface


@pytest.fixture
def scan_dir(tmp_path, monkeypatch):
    """Point the CSV artifacts at a throwaway directory."""
    monkeypatch.setattr("ptnetinspector.utils.path.get_output_dir", lambda base_path=None: tmp_path)
    set_current_interface("testiface")
    create_csv("testiface")
    yield get_tmp_path("testiface")
    set_current_interface(None)


def _save(packets, ip_mode=IPMode(True, True)):
    from ptnetinspector.scan import Save

    Save.save_packets("lo", ip_mode, packets)


def _rows(path):
    with open(path, newline="") as handle:
        return list(csv.DictReader(handle))


class TestCapture:
    def test_tcp_source_port_is_recorded(self, scan_dir):
        packet = Ether(raw(
            Ether(src="aa:bb:cc:00:00:01") / IP(src="192.168.1.10")
            / TCP(sport=443, dport=51000)
        ))

        _save([packet])

        rows = _rows(scan_dir / "observed_ports.csv")
        assert rows == [{"MAC": "aa:bb:cc:00:00:01", "IP": "192.168.1.10",
                         "Proto": "tcp", "Port": "443"}]

    def test_udp_source_port_is_recorded(self, scan_dir):
        packet = Ether(raw(
            Ether(src="aa:bb:cc:00:00:02") / IPv6(src="fe80::2")
            / UDP(sport=5353, dport=5353)
        ))

        _save([packet])

        rows = _rows(scan_dir / "observed_ports.csv")
        assert rows == [{"MAC": "aa:bb:cc:00:00:02", "IP": "fe80::2",
                         "Proto": "udp", "Port": "5353"}]

    def test_the_scanners_own_frames_are_skipped(self, scan_dir):
        own_mac = get_if_hwaddr("lo")
        packet = Ether(raw(
            Ether(src=own_mac) / IP(src="127.0.0.1") / TCP(sport=22, dport=40000)
        ))

        _save([packet])

        assert _rows(scan_dir / "observed_ports.csv") == []

    def test_disabled_address_family_is_ignored(self, scan_dir):
        packet = Ether(raw(
            Ether(src="aa:bb:cc:00:00:03") / IP(src="10.0.0.5") / TCP(sport=80, dport=50000)
        ))

        _save([packet], ip_mode=IPMode(False, True))  # IPv6 only

        assert _rows(scan_dir / "observed_ports.csv") == []

    def test_duplicate_port_is_recorded_once(self, scan_dir):
        packet = Ether(raw(
            Ether(src="aa:bb:cc:00:00:04") / IP(src="10.0.0.6") / TCP(sport=22, dport=50001)
        ))

        _save([packet, Ether(raw(packet))])

        assert len(_rows(scan_dir / "observed_ports.csv")) == 1

    def test_a_frame_without_tcp_or_udp_adds_nothing(self, scan_dir):
        packet = Ether(raw(Ether(src="aa:bb:cc:00:00:05") / IP(src="10.0.0.7")))

        _save([packet])

        assert _rows(scan_dir / "observed_ports.csv") == []


class TestServiceName:
    def test_well_known_ports_resolve(self):
        from ptnetinspector.entities.port import Port

        assert Port.service_name("tcp", "443") == "https"
        assert Port.service_name("tcp", 22) == "ssh"
        assert Port.service_name("udp", "5353") == "mdns"

    def test_obscure_iana_names_are_relabelled_to_common_terms(self):
        # The IANA registry calls these domain/shilp/ncube-lm/ms-wbt-server;
        # the report shows the term professionals actually use.
        from ptnetinspector.entities.port import Port

        assert Port.service_name("udp", "53") == "dns"
        assert Port.service_name("tcp", "2049") == "nfs"
        assert Port.service_name("tcp", "1521") == "oracle"
        assert Port.service_name("tcp", "3389") == "rdp"
        assert Port.service_name("tcp", "445") == "smb"

    def test_less_common_port_resolves_from_bundled_iana_table(self):
        # Proves the name comes from the shipped database, not the host's
        # /etc/services, so output is identical on every machine.
        from ptnetinspector.entities.port import Port

        assert Port.service_name("tcp", "3306") == "mysql"
        assert Port.service_name("udp", "1812") == "radius"

    def test_unknown_or_invalid_port_returns_empty(self):
        from ptnetinspector.entities.port import Port

        assert Port.service_name("tcp", "noise") == ""
        assert Port.service_name("tcp", "65000") == ""

    def test_bundled_services_file_exists(self):
        from ptnetinspector.entities.port import get_services_path

        assert get_services_path().is_file()


class TestMainReportLayout:
    def test_ports_row_is_printed_below_the_addresses(self, scan_dir, capsys):
        from ptnetinspector.output.non_json import Non_json

        def w(name, rows, fields):
            with open(get_csv_path(name), "w", newline="") as h:
                wr = csv.DictWriter(h, fieldnames=fields); wr.writeheader(); wr.writerows(rows)

        w("addresses.csv", [{"MAC": "aa:bb:cc:00:00:07", "IP": "192.168.1.50"}], ["MAC", "IP"])
        w("role_node.csv", [{"MAC": "aa:bb:cc:00:00:07", "Device_Number": "1", "Role": "Node"}],
          ["MAC", "Device_Number", "Role"])
        w("observed_ports.csv", [
            {"MAC": "aa:bb:cc:00:00:07", "IP": "192.168.1.50", "Proto": "tcp", "Port": "445"},
            {"MAC": "aa:bb:cc:00:00:07", "IP": "192.168.1.50", "Proto": "tcp", "Port": "22"},
        ], ["MAC", "IP", "Proto", "Port"])

        Non_json.output_general("a", IPMode(True, True))
        out = capsys.readouterr().out
        lines = [ln.strip() for ln in out.splitlines()]

        mac_idx = next(i for i, ln in enumerate(lines) if "MAC" in ln and "aa:bb:cc:00:00:07" in ln)
        ip_idx = next(i for i, ln in enumerate(lines) if "192.168.1.50" in ln)
        port_idx = next(i for i, ln in enumerate(lines) if ln.startswith("Ports"))

        assert mac_idx < ip_idx < port_idx                 # order: MAC, IP, then Ports
        assert "22/tcp (ssh)" in lines[port_idx]
        assert "445/tcp (smb)" in lines[port_idx]


class TestCollectByMac:
    def test_ports_are_grouped_deduplicated_and_sorted(self, scan_dir):
        from ptnetinspector.entities.port import Port

        packets = [
            Ether(raw(Ether(src="aa:bb:cc:00:00:06") / IP(src="10.0.0.8") / TCP(sport=443, dport=5))),
            Ether(raw(Ether(src="aa:bb:cc:00:00:06") / IP(src="10.0.0.8") / TCP(sport=22, dport=6))),
            Ether(raw(Ether(src="aa:bb:cc:00:00:06") / IP(src="10.0.0.9") / UDP(sport=53, dport=7))),
        ]
        _save(packets)

        by_mac = Port.collect_by_mac()
        assert by_mac["AA:BB:CC:00:00:06"] == [("tcp", "22"), ("udp", "53"), ("tcp", "443")]
