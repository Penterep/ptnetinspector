"""Base entity for discovered nodes (MAC/IP pairs).

Provides shared CSV persistence and loading utilities for specialized entities.
"""
import csv
import ipaddress
import logging
import subprocess
from ptnetinspector.utils.path import get_csv_path
from ptnetinspector.utils.ip_utils import has_additional_data
from ptnetinspector.entities._registry import registry


logger = logging.getLogger(__name__)


class Node:

    all_nodes = []

    def __init__(self, mac: str, ip: str) -> None:
        # Assign to self object
        self.mac = mac
        self.ip = ip
        Node.all_nodes.append(self)

    @classmethod
    def get_from_csv(cls) -> None:
        # Importing the information about nodes from tmp files
        csv_file = get_csv_path("addresses.csv")

        with open(csv_file, 'r', encoding='utf-8', errors='replace') as csv_file:
            reader = csv.DictReader(csv_file)
            nodes = list(reader)

            for node in nodes:
                Node(
                    mac=node.get('MAC'),
                    ip=node.get('IP')
                )

    def save_addresses(self) -> None:
        # Exporting addresses to csv files and avoid duplication
        key = (self.mac, self.ip)
        if registry.seen("node_addresses", key):
            return

        csv_file = get_csv_path("packets.csv")

        with open(csv_file, 'a', newline='') as csvfile:
            fieldnames = ['time', 'src MAC', 'des MAC', 'source IP', 'destination IP', 'protocol', 'length']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writerow({
                'source IP': self.ip,
                'src MAC': self.mac
            })

    @staticmethod
    def _clean_wire_name(value) -> str:
        """A hostname taken off the wire, or "" when it is not a usable name.

        Every caller passes attacker-controlled input: an mDNS or LLMNR answer,
        or a Node Information reply, where scapy hands back whatever followed
        the 4-octet TTL. Decoding is done here, with replacement, rather than at
        the call sites - doing it there raised UnicodeDecodeError on an answer
        that was not valid UTF-8, and aborted the whole scan.

        A name is rejected when it cannot be one: anything that is not text,
        anything with control characters, anything longer than a DNS name may
        be, and anything containing U+FFFD, which is what replacement leaves
        behind and so is evidence the bytes were never a name. Non-ASCII text
        is kept - RFC 6762 names are UTF-8, so "Muller-PC.local" is legitimate.
        """
        if isinstance(value, (bytes, bytearray, memoryview)):
            value = bytes(value).decode("utf-8", errors="replace")
        elif not isinstance(value, str):
            return ""

        name = value.strip().strip(".")
        if not name or len(name) > 253:
            return ""
        if "\ufffd" in name:
            return ""
        if any(character < " " or character == "\x7f" for character in name):
            return ""
        return name

    @staticmethod
    def save_local_name(mac, local_name) -> None:
        # Function to save local names from mdns and llmnr to a CSV file
        local_name = Node._clean_wire_name(local_name)
        if not local_name:
            return

        key = (mac, local_name)
        if registry.seen("node_local_name", key):
            return

        csv_file = get_csv_path("localname.csv")

        with open(csv_file, 'a', newline='') as csvfile:
            fieldnames = ['MAC', 'name']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writerow({
                'MAC': mac,
                'name': local_name
            })

    @staticmethod
    def save_ipv6_routing_table(Destination: str, Nexthop: str, Flag: str, Metric: str, Refcnt: str, Use: str, If: str) -> None:
        key = (Destination, Nexthop, Flag, Metric, Refcnt, Use, If)
        if registry.seen("node_ipv6_route", key):
            return

        csv_file = get_csv_path("ipv6_route_table.csv")

        with open(csv_file, 'a', newline='') as csvfile:
            fieldnames = ['Destination', 'Nexthop', 'Flag', 'Metric', 'Refcnt', 'Use', 'If']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writerow({
                'Destination': Destination,
                'Nexthop': Nexthop,
                'Flag': Flag,
                'Metric': Metric,
                'Refcnt': Refcnt,
                'Use': Use,
                'If': If
            })

    @staticmethod
    def save_ipv4_routing_table(Destination: str, Gateway: str, Genmask: str, Flags: str, Metric: str, Ref: str, Use: str, Iface: str) -> None:
        key = (Destination, Gateway, Genmask, Flags, Metric, Ref, Use, Iface)
        if registry.seen("node_ipv4_route", key):
            return

        csv_file = get_csv_path("ipv4_route_table.csv")

        with open(csv_file, 'a', newline='') as csvfile:
            fieldnames = ['Destination', 'Gateway', 'Genmask', 'Flags', 'Metric', 'Ref', 'Use', 'Iface']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writerow({
                'Destination': Destination,
                'Gateway': Gateway,
                'Genmask': Genmask,
                'Flags': Flags,
                'Metric': Metric,
                'Ref': Ref,
                'Use': Use,
                'Iface': Iface
            })

    @staticmethod
    def _run_ip_route(arguments: list[str], timeout: float) -> list[str] | None:
        """Read the routing table through iproute2.

        net-tools' `route` is not installed by default on current Debian,
        Ubuntu, Fedora or Arch. Its absence raises FileNotFoundError, which is
        neither CalledProcessError nor TimeoutExpired, so the routing tables
        silently vanished from the report on any modern host.
        """
        try:
            output = subprocess.check_output(
                ["ip"] + arguments,
                timeout=timeout,
                stderr=subprocess.DEVNULL,
            ).decode("utf-8")
        except FileNotFoundError:
            logger.debug("iproute2 ('ip') not available; skipping routing table capture")
            return None
        except subprocess.CalledProcessError as error:
            logger.debug("'ip %s' failed: %s", " ".join(arguments), error)
            return None
        except subprocess.TimeoutExpired:
            logger.debug("'ip %s' timed out", " ".join(arguments))
            return None
        return output.splitlines()

    @staticmethod
    def _parse_route_line(line: str) -> tuple[str, dict[str, str]] | None:
        """Split one `ip route` line into its destination and its key/value tail."""
        fields = line.split()
        if not fields:
            return None
        destination = fields[0]
        attributes: dict[str, str] = {}
        index = 1
        while index < len(fields):
            key = fields[index]
            if index + 1 < len(fields) and key in (
                "via", "dev", "proto", "metric", "src", "pref", "scope", "expires", "mtu"
            ):
                attributes[key] = fields[index + 1]
                index += 2
            else:
                attributes.setdefault(key, "")
                index += 1
        return destination, attributes

    @staticmethod
    def get_ipv6_route_metrics_and_addresses(timeout: float = 10.0) -> None:
        lines = Node._run_ip_route(["-6", "route", "show"], timeout)
        if lines is None:
            return

        for line in lines:
            parsed = Node._parse_route_line(line)
            if parsed is None:
                continue
            destination, attributes = parsed
            Node.save_ipv6_routing_table(
                destination,
                attributes.get("via", "::"),
                attributes.get("proto", ""),
                attributes.get("metric", ""),
                "0",
                "0",
                attributes.get("dev", ""),
            )

    @staticmethod
    def get_ipv4_route_metrics_and_addresses(timeout: float = 10.0) -> None:
        lines = Node._run_ip_route(["route", "show"], timeout)
        if lines is None:
            return

        for line in lines:
            parsed = Node._parse_route_line(line)
            if parsed is None:
                continue
            destination, attributes = parsed
            if destination == "default":
                network, genmask = "0.0.0.0", "0.0.0.0"
            elif "/" in destination:
                try:
                    net = ipaddress.IPv4Network(destination, strict=False)
                    network, genmask = str(net.network_address), str(net.netmask)
                except ValueError:
                    network, genmask = destination, ""
            else:
                network, genmask = destination, "255.255.255.255"

            Node.save_ipv4_routing_table(
                network,
                attributes.get("via", "0.0.0.0"),
                genmask,
                attributes.get("proto", ""),
                attributes.get("metric", ""),
                "0",
                "0",
                attributes.get("dev", ""),
            )

    @staticmethod
    def get_status_ip(ip):
        # Check the status of IP (SLAAC, DHCP, Manual)
        csv_file = get_csv_path("addresses.csv")
        if has_additional_data(csv_file):
            pass

    def __repr__(self):
        return f"{self.__class__.__name__}({self.mac}, {self.ip})"