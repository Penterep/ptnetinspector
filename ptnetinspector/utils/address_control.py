"""Address mapping and validation helpers.

Provides routines to read, validate, and enrich MAC/IP mappings collected
during scans; used by both passive and active flows.
"""
import ipaddress
import asyncio
import csv
import logging
import os
import time

from pathlib import Path
from typing import List, Optional, Tuple, Union
from dataclasses import dataclass
from ptlibs import ptprinthelper
from scapy.all import (
    Ether, ARP, IPv6, ICMPv6ND_NS, ICMPv6NDOptSrcLLAddr,
    AsyncSniffer
)
from scapy.arch import get_if_hwaddr, get_if_addr
from scapy.layers.inet6 import ICMPv6ND_NA
from scapy.utils6 import get_source_addr_from_candidate_set

from ptnetinspector.entities.networks import Networks
from ptnetinspector.utils.interface import Interface
from ptnetinspector.utils.ip_utils import is_llsnm_ipv6
from ptnetinspector.send.send import IPMode
from ptnetinspector.utils.path import get_csv_path
from ptnetinspector.utils.burst_control import resolve_burst_limit, sendp_adaptive


logger = logging.getLogger(__name__)


@dataclass
class AddressMapping:
    mac: str
    ip: str


def read_mappings() -> List[AddressMapping]:
    mappings = []
    csv_file = get_csv_path('addresses.csv')

    with open(csv_file, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row['IP']:
                mappings.append(AddressMapping(mac=row['MAC'], ip=row['IP']))
    return mappings


def is_valid_unicast_ip(ip: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]) -> bool:
    return not (ip.is_multicast or ip.is_unspecified or ip.is_loopback)

def check_ip_in_subnets(ip: Union[ipaddress.IPv4Address, ipaddress.IPv6Address], subnets: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]) -> bool:
    return any(ip in subnet for subnet in subnets)


_ULA_NETWORK = ipaddress.ip_network("fc00::/7")


def _is_local_ipv6(ip: ipaddress.IPv6Address, ipv6_subnets) -> bool:
    """Decide whether an observed IPv6 address belongs to a node on this link.

    Besides the scanner's own prefixes, neighbours legitimately use unique local
    addresses and prefixes advertised by other routers, so those count as local.
    """
    if ip.is_link_local or ip in _ULA_NETWORK:
        return True
    return not ipv6_subnets or check_ip_in_subnets(ip, ipv6_subnets)


def filter_unicast_addresses(
    mappings: List[AddressMapping],
    ip_mode: IPMode,
    keep_solicited_node: bool = False,
) -> List[AddressMapping]:
    """Keep only addresses that plausibly belong to a node on the local link.

    Args:
        mappings: Observed MAC/IP pairs.
        ip_mode: Enabled IP versions.
        keep_solicited_node: True under -nc, where solicited-node multicast groups
            are retained because they reveal addresses that were never confirmed
            by a reachability probe.
    """
    result = []
    ipv4_subnets, ipv6_subnets = Networks.load_networks()

    # Extend the local prefix set with prefixes advertised on the link, otherwise
    # neighbours addressed from a router prefix the scanner did not adopt are lost.
    for ra_prefix in Networks.load_ra_prefixes():
        if ra_prefix not in ipv6_subnets:
            ipv6_subnets.append(ra_prefix)

    # Dynamically check if non-JSON output should be suppressed (avoid circular import)
    try:
        from ptnetinspector.utils import runtime
        suppress = runtime._suppress_non_json
    except (ImportError, AttributeError):
        suppress = False

    if not ipv4_subnets and ip_mode.ipv4 and not suppress:
        ptprinthelper.ptprint("\033[90mAuto-detection of IPv4 subnets failed. All unicast IPv4 addresses will be kept\033[0m", "WARNING", condition=True, indent=4)
    if not ipv6_subnets and ip_mode.ipv6 and not suppress:
        ptprinthelper.ptprint("\033[90mAuto-detection of IPv6 subnets failed. All unicast IPv6 addresses will be kept\033[0m", "WARNING", condition=True, indent=4)

    for mapping in mappings:
        try:
            ip = ipaddress.ip_address(mapping.ip)
            if is_valid_unicast_ip(ip):
                if isinstance(ip, ipaddress.IPv4Address):
                    keep = ip.is_link_local or not ipv4_subnets or check_ip_in_subnets(ip, ipv4_subnets)
                else:
                    keep = _is_local_ipv6(ip, ipv6_subnets)
                if keep:
                    result.append(mapping)
            elif keep_solicited_node and ip_mode.ipv6 and isinstance(ip, ipaddress.IPv6Address):
                if is_llsnm_ipv6(mapping.ip):
                    result.append(mapping)
        except ValueError:
            # Malformed address in CSV could indicate file corruption; log for debug.
            logger.debug("Skipping invalid address mapping: MAC=%s, IP=%s (potential CSV corruption)", mapping.mac, mapping.ip)
            continue

    return result


def write_mappings(mappings: List[AddressMapping], file_path: str = None) -> None:
    if file_path is None:
        file_path = get_csv_path('addresses.csv')

    with open(file_path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['MAC', 'IP'])
        for mapping in mappings:
            writer.writerow([mapping.mac, mapping.ip])


class AddressValidator:
    __timeout = 0.2  # Seconds to wait for responses to ARP/NS probes.
    __probe_retries = 2  # How many times each probe batch is sent to improve response rate.
    __probe_burst_limit = 0  # <=0 sends all probes at once, >0 sends probes in chunks.

    def __init__(self, interface: str):
        self.interface = interface

    def ipv6_address_on_interface_check(self) -> bool:
        candidate_ipv6_src_addr = Interface.get_interface_ipv6_ips(Interface(self.interface))
        return bool(candidate_ipv6_src_addr)

    def _build_probe_packet(
        self,
        mapping: AddressMapping,
        iface_mac: str,
        iface_ipv4: str,
        candidate_ipv6_src_addr: List[str]
    ) -> Tuple[Optional[object], Optional[Tuple[str, str, str]]]:
        try:
            ip = ipaddress.ip_address(mapping.ip)
        except ValueError:
            # Invalid address in mapping could indicate file corruption; log for debug.
            logger.debug("Address verification failed: MAC=%s, IP=%s (invalid format)", mapping.mac, mapping.ip)
            return None, None

        mac_normalized = mapping.mac.lower()

        if isinstance(ip, ipaddress.IPv4Address):
            packet = (Ether(src=iface_mac, dst=mapping.mac) /
                      ARP(pdst=mapping.ip, hwdst=mapping.mac, op=1,
                          hwsrc=iface_mac, psrc=iface_ipv4))
            return packet, ("arp", mac_normalized, mapping.ip)

        if not candidate_ipv6_src_addr:
            return None, None

        try:
            ipv6_src = get_source_addr_from_candidate_set(mapping.ip, candidate_ipv6_src_addr)
        except Exception as error:
            # Source address selection may fail when interface candidates do not match target scope.
            logger.debug(
                "IPv6 source selection failed for MAC=%s, IP=%s: %s",
                mapping.mac,
                mapping.ip,
                error
            )
            return None, None

        packet = (Ether(src=iface_mac, dst=mapping.mac) /
                  IPv6(src=ipv6_src, dst=mapping.ip) /
                  ICMPv6ND_NS(tgt=mapping.ip) /
                  ICMPv6NDOptSrcLLAddr(lladdr=iface_mac))
        return packet, ("ns", mac_normalized, mapping.ip)

    def _verify_mappings_bulk(self, mappings: List[AddressMapping]) -> List[AddressMapping]:
        iface_mac = get_if_hwaddr(self.interface)
        iface_ipv4 = get_if_addr(self.interface)
        candidate_ipv6_src_addr = Interface.get_interface_ipv6_ips(Interface(self.interface))
        burst_limit = resolve_burst_limit(
            requested_limit=None,
            configured_limit=AddressValidator.__probe_burst_limit,
            interface=self.interface,
            logger=logger,
            context="address-validator",
        )

        probe_packets = []
        mapping_keys: List[Optional[Tuple[str, str, str]]] = []

        for mapping in mappings:
            packet, key = self._build_probe_packet(
                mapping,
                iface_mac=iface_mac,
                iface_ipv4=iface_ipv4,
                candidate_ipv6_src_addr=candidate_ipv6_src_addr
            )
            mapping_keys.append(key)
            if packet is not None:
                probe_packets.append(packet)

        if not probe_packets:
            return []

        sniffer = AsyncSniffer(iface=self.interface, filter="arp or icmp6", store=True)
        sniffer.start()

        try:
            for _ in range(self.__probe_retries):
                sendp_adaptive(
                    packets=probe_packets,
                    interface=self.interface,
                    logger=logger,
                    context="address-validator",
                    initial_burst=burst_limit,
                )

            # Keep sniffer active for one response window after the last send.
            time.sleep(self.__timeout)
        finally:
            captured_packets = sniffer.stop() or []

        valid_keys = set()
        for packet in captured_packets:
            if packet.haslayer(ARP):
                arp_layer = packet[ARP]
                if arp_layer.op == 2:
                    valid_keys.add(("arp", arp_layer.hwsrc.lower(), arp_layer.psrc))
                continue

            if packet.haslayer(ICMPv6ND_NA) and packet.haslayer(IPv6) and packet.haslayer(Ether):
                valid_keys.add(("ns", packet[Ether].src.lower(), packet[IPv6].src))

        return [mapping for mapping, key in zip(mappings, mapping_keys) if key in valid_keys]

    async def verify_all_mappings(self, mappings: List[AddressMapping]) -> List[AddressMapping]:
        if not self.ipv6_address_on_interface_check():
            ptprinthelper.ptprint(f"Could not validate IPv6 addresses. No IPv6 address on interface {self.interface}", "ERROR")
            def is_ipv6_address(ip_value: str) -> bool:
                try:
                    return isinstance(ipaddress.ip_address(ip_value), ipaddress.IPv6Address)
                except ValueError:
                    return False

            mappings = [
                mapping
                for mapping in mappings
                if not is_ipv6_address(mapping.ip)
            ]

        return await asyncio.to_thread(self._verify_mappings_bulk, mappings)


def validate_addresses_mapping(interface: str, ip_mode: IPMode, passive: bool = False, verify: bool = True) -> None:
    """Persist discovered MAC/IP mappings, optionally probing them for reachability.

    Args:
        interface: Interface the scan ran on.
        ip_mode: Enabled IP versions.
        passive: True for passive scans, which never emit probes.
        verify: False when -nc is used; skips the ARP/NS reachability probes so no
            extra traffic is generated and unresponsive addresses are kept.
    """
    validator = AddressValidator(interface)

    original_mappings = read_mappings()
    filtered_mapping = filter_unicast_addresses(original_mappings, ip_mode, keep_solicited_node=not verify)

    csv_file = get_csv_path('addresses.csv')
    unfiltered_file = Path(str(csv_file).replace('.csv', '_unfiltered.csv'))
    write_mappings(original_mappings, file_path=unfiltered_file)

    if not passive and verify:
        filtered_mapping = asyncio.run(validator.verify_all_mappings(filtered_mapping))

    write_mappings(filtered_mapping)


def delete_tmp_mapping_file():
    try:
        csv_file = get_csv_path('addresses.csv')
        # get_csv_path returns a Path; Path.replace() renames, so operate on the string.
        unfiltered_file = str(csv_file).replace('.csv', '_unfiltered.csv')
        os.remove(unfiltered_file)
    except FileNotFoundError:
        # Optional file may not exist on first run or after cleanup.
        pass
