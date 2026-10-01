"""Entity for transport ports observed passively in captured traffic.

No probing is done: a port is recorded only because a frame carrying it crossed
the wire during the scan. Each row is attributed to the device that *sent* the
frame (its source MAC and source IP) and the source port it used, so the record
is "this device was seen sending from this port" - not a claim that the port is
open. A device can appear at several addresses and with several ports.
"""
import csv
import logging
from pathlib import Path

from ptnetinspector.utils.path import get_csv_path
from ptnetinspector.entities._registry import registry


logger = logging.getLogger(__name__)

# Lazily-loaded {(proto, port): service} map from the bundled IANA registry, so
# the name resolution is identical on every host rather than depending on
# whatever /etc/services the scanning machine happens to carry.
_SERVICES: dict[tuple[str, int], str] | None = None

# The IANA registry is authoritative but a handful of its short names are the
# formal label rather than the term a network engineer or pentester actually
# uses ("shilp" for NFS, "ncube-lm" for Oracle, "ms-wbt-server" for RDP). These
# relabel those ports to the common name; everything else keeps the IANA name.
# Keyed by port and applied to both TCP and UDP.
_OVERRIDES = {
    53: "dns", 67: "dhcp-server", 68: "dhcp-client", 111: "rpcbind",
    135: "msrpc", 445: "smb", 548: "afp", 1433: "mssql", 1521: "oracle",
    2049: "nfs", 3128: "squid-http", 3268: "ldap-gc", 3389: "rdp",
    5900: "vnc", 5985: "winrm", 5986: "winrm-https", 9100: "jetdirect",
}


def get_services_path() -> Path:
    """Path to the bundled IANA service-name/port database."""
    return Path(__file__).parent.parent / 'data' / 'services.csv'


def _load_services() -> dict[tuple[str, int], str]:
    """Read the bundled port->service table once and cache it."""
    global _SERVICES
    if _SERVICES is not None:
        return _SERVICES

    services: dict[tuple[str, int], str] = {}
    try:
        with open(get_services_path(), 'r', encoding='utf-8', errors='replace', newline='') as handle:
            for row in csv.DictReader(handle):
                proto = str(row.get("Proto", "")).strip().lower()
                name = str(row.get("Service", "")).strip()
                port = str(row.get("Port", "")).strip()
                if not name or not port.isdigit() or proto not in ("tcp", "udp"):
                    continue
                services.setdefault((proto, int(port)), name)
    except OSError as error:
        logger.debug("Could not read bundled services database: %s", error)

    for port, name in _OVERRIDES.items():
        for proto in ("tcp", "udp"):
            services[(proto, port)] = name

    _SERVICES = services
    return _SERVICES


class Port:
    """One transport port seen on a device, keyed by the frame's source."""

    FIELDS = ['MAC', 'IP', 'Proto', 'Port']

    def __init__(self, mac: str, ip: str, proto: str, port: str) -> None:
        self.mac = mac
        self.ip = ip
        self.proto = str(proto).lower()
        self.port = str(port)

    def save(self) -> None:
        key = (self.mac, self.ip, self.proto, self.port)
        if registry.seen("port", key):
            return

        csv_file = get_csv_path("observed_ports.csv")

        with open(csv_file, 'a', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=Port.FIELDS)
            writer.writerow({
                'MAC': self.mac,
                'IP': self.ip,
                'Proto': self.proto,
                'Port': self.port,
            })

    @staticmethod
    def service_name(proto: str, port) -> str:
        """Service name for a port from the bundled IANA table, or "" if none."""
        try:
            number = int(str(port).strip())
        except (TypeError, ValueError):
            return ""
        proto = str(proto).strip().lower()
        return _load_services().get((proto, number), "")

    @staticmethod
    def _port_sort_key(proto: str, port: str) -> tuple:
        try:
            number = int(str(port).strip())
        except (TypeError, ValueError):
            number = 0
        return (number, str(proto))

    @staticmethod
    def collect_by_mac() -> dict[str, list[tuple[str, str]]]:
        """Map upper-cased MAC to its sorted, unique (proto, port) pairs.

        Used by the device inventory and the JSON report to fold ports in as a
        per-device attribute alongside the addresses already collected.
        """
        from ptnetinspector.utils.ip_utils import has_additional_data

        by_mac: dict[str, list[tuple[str, str]]] = {}
        ports_file = get_csv_path("observed_ports.csv")
        if not has_additional_data(ports_file):
            return by_mac

        seen: dict[str, set] = {}
        try:
            with open(ports_file, 'r', encoding='utf-8', errors='replace', newline='') as handle:
                for row in csv.DictReader(handle):
                    mac = str(row.get("MAC", "")).strip().upper()
                    proto = str(row.get("Proto", "")).strip().lower()
                    port = str(row.get("Port", "")).strip()
                    if not mac or not port:
                        continue
                    pair = (proto, port)
                    if pair in seen.setdefault(mac, set()):
                        continue
                    seen[mac].add(pair)
                    by_mac.setdefault(mac, []).append(pair)
        except OSError:
            return by_mac

        for mac in by_mac:
            by_mac[mac].sort(key=lambda pair: Port._port_sort_key(pair[0], pair[1]))
        return by_mac

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.mac}, {self.ip}, {self.port}/{self.proto})"
