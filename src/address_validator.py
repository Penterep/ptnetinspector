import ipaddress
import asyncio
import csv
import os

from typing import List
from dataclasses import dataclass
from ptlibs import ptprinthelper
from scapy.all import (
    Ether, ARP, IPv6, ICMPv6ND_NS, ICMPv6NDOptSrcLLAddr,
    srp1
)
from scapy.arch import get_if_hwaddr, get_if_addr
from scapy.layers.inet6 import ICMPv6ND_NA
from scapy.utils6 import get_source_addr_from_candidate_set
from src.device.networks import Networks
from src.interface import Interface
from src.send import IPMode

ADDR_MAPPING_FILE_PATH = 'src/tmp/addresses.csv'

@dataclass
class AddressMapping:
    mac: str
    ip: str


def read_mappings() -> List[AddressMapping]:
    """
    Read MAC-IP mappings from CSV file.

    Returns:
        List[AddressMapping]: List of mac and ip address mappings.
    """
    mappings = []

    with open(ADDR_MAPPING_FILE_PATH, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row['IP']:
                mappings.append(AddressMapping(
                    mac=row['MAC'],
                    ip=row['IP']
                ))

    return mappings


def filter_unicast_addresses(mappings: List[AddressMapping], ip_mode: IPMode) -> List[AddressMapping]:
    """
    Filter out non-unicast addresses and addresses that are not in the subnets
    defined in networks.csv (if available).

    Args:
        mappings (List[AddressMapping]): List of mac and ip address mappings.
        ip_mode (IPMode): IP mode used.

    Returns:
        List[AddressMapping]: List of mac and ip address mappings that are unicast
        and in the defined subnets (if applicable).
    """
    result = []

    ipv4_subnets, ipv6_subnets = Networks.load_networks()

    if not ipv4_subnets and ip_mode.ipv4:
        ptprinthelper.ptprint("Auto-detection of IPv4 subnets failed (no non-link-local IP address on interface). All unicast IPv4 addresses will be kept.", "WARNING")
    if not ipv6_subnets and ip_mode.ipv6:
        ptprinthelper.ptprint(
            "Auto-detection of IPv6 subnets failed (no non-link-local IP address on interface). All unicast IPv6 addresses will be kept.",
            "WARNING")

    for mapping in mappings:
        try:
            ip = ipaddress.ip_address(mapping.ip)

            # check if it's unicast and not unspecified or loopback
            if (not ip.is_multicast and
                    not ip.is_unspecified and
                    not ip.is_loopback):

                # always keep link-local addresses
                if ip.is_link_local:
                    result.append(mapping)
                    continue

                # IPv4 addresses
                if isinstance(ip, ipaddress.IPv4Address):
                    # of no IPv4 subnets defined in the file, keep all IPv4 addresses
                    if not ipv4_subnets:
                        result.append(mapping)
                    # otherwise check if the IP is in any of the defined subnets
                    else:
                        for subnet in ipv4_subnets:
                            if ip in subnet:
                                result.append(mapping)
                                break

                # IPv6 addresses
                elif isinstance(ip, ipaddress.IPv6Address):
                    # if no IPv6 subnets defined in the file, keep all IPv6 addresses
                    if not ipv6_subnets:
                        result.append(mapping)
                    # otherwise check if the IP is in any of the defined subnets
                    else:
                        for subnet in ipv6_subnets:
                            if ip in subnet:
                                result.append(mapping)
                                break

        except ValueError:
            continue

    return result


def write_mappings(mappings: List[AddressMapping], file_path: str = ADDR_MAPPING_FILE_PATH) -> None:
    """
    Write valid mappings back to CSV file.

    Args:
        mappings (List[AddressMapping]): List of mac and ip address mappings.
        file_path (str): Path to the CSV file to write to.
    """
    with open(file_path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['MAC', 'IP'])
        for mapping in mappings:
            writer.writerow([mapping.mac, mapping.ip])


class AddressValidator:
    def __init__(self, interface: str):
        self.interface = interface
        self.timeout = 0.5 # seconds

    def verify_ipv4_mapping(self, mapping: AddressMapping) -> bool:
        """
        Verify IPv4 address mapping using ARP.

        Args:
            mapping (AddressMapping): MAC-IP mapping to verify.

        Returns:
            bool: True if mapping is valid, False otherwise
        """
        arp_request = (Ether(src=get_if_hwaddr(self.interface), dst=mapping.mac) /
                       ARP(
            pdst=mapping.ip,
            hwdst=mapping.mac,
            op=1,
            hwsrc=get_if_hwaddr(self.interface),
            psrc=get_if_addr(self.interface)
        ))

        arp_reply = srp1(arp_request, timeout=self.timeout, verbose=False, iface=self.interface, filter=f"arp and ether src {mapping.mac}")

        if arp_reply:
            if arp_reply.haslayer(ARP) and arp_reply.op == 2 and arp_reply.psrc == mapping.ip and arp_reply.hwsrc == mapping.mac:
                return True

        return False

    def ipv6_address_on_interface_check(self) -> bool:
        """
        Check for presence of IPv6 address on the interface.

        Returns:
            bool: True if IPv6 address is present, False otherwise.
        """
        candidate_ipv6_src_addr = Interface.get_interface_ipv6_ips(Interface(self.interface))
        return bool(candidate_ipv6_src_addr)

    def verify_ipv6_mapping(self, mapping: AddressMapping) -> bool:
        """
        Verify IPv6 address mapping using Neighbor Solicitation.

        Args:
            mapping (AddressMapping): MAC-IP mapping to verify.

        Returns:
            bool: True if mapping is valid, False otherwise
        """
        candidate_ipv6_src_addr = Interface.get_interface_ipv6_ips(Interface(self.interface))

        ns_packet = (Ether(src=get_if_hwaddr(self.interface), dst=mapping.mac) /
                     IPv6(src=get_source_addr_from_candidate_set(mapping.ip, candidate_ipv6_src_addr), dst=mapping.ip) /
                     ICMPv6ND_NS(tgt=mapping.ip) /
                     ICMPv6NDOptSrcLLAddr(lladdr=get_if_hwaddr(self.interface)))

        advertisement = srp1(ns_packet, timeout=self.timeout, verbose=False, iface=self.interface, filter=f"icmp6 and ether src {mapping.mac}")

        if advertisement:
            if advertisement.haslayer(ICMPv6ND_NA) and advertisement[IPv6].src == mapping.ip and advertisement[Ether].src == mapping.mac:
                return True

        return False

    async def verify_mapping(self, mapping: AddressMapping) -> bool:
        """
        Verify a single MAC-IP mapping.

        Args:
            mapping (AddressMapping): MAC-IP mapping to verify.

        Returns:
            bool: True if mapping is valid, False otherwise
        """
        try:
            ip = ipaddress.ip_address(mapping.ip)
            if isinstance(ip, ipaddress.IPv4Address):
                return self.verify_ipv4_mapping(mapping)
            else:
                return self.verify_ipv6_mapping(mapping)
        except ValueError:
            return False

    async def verify_all_mappings(self, mappings: List[AddressMapping]) -> List[AddressMapping]:
        """
        Verify all mappings concurrently.

        Args:
            mappings (List[AddressMapping]): List of MAC-IP mappings to verify.

        Returns:
            List[AddressMapping]: List of MAC-IP mappings that are valid.
        """
        if not self.ipv6_address_on_interface_check():
            ptprinthelper.ptprint(f"Could not validate IPv6 addresses. No IPv6 address on interface {self.interface}", "ERROR")
            mappings = [mapping for mapping in mappings if not isinstance(ipaddress.ip_address(mapping.ip), ipaddress.IPv6Address)]

        tasks = [asyncio.create_task(self.verify_mapping(mapping)) for mapping in mappings]
        results = await asyncio.gather(*tasks)

        # list of mappings that returned True
        valid_mappings = [mapping for mapping, result in zip(mappings, results) if result]

        return valid_mappings


def validate_addresses(interface: str, ip_mode: IPMode, passive: bool = False) -> None:
    """
    Validate MAC-IP mappings editing the addresses CSV.

    Args:
        interface (str): Name of the interface to use for validation.
        ip_mode (IPMode): IP mode used.
        passive (bool): If True, do not send packets. Default is False.
    """
    validator = AddressValidator(interface)

    original_mappings = read_mappings()
    filtered_mapping = filter_unicast_addresses(original_mappings, ip_mode)

    write_mappings(original_mappings, file_path=ADDR_MAPPING_FILE_PATH[:-4] + '_unfiltered.csv')

    if not passive:
        filtered_mapping = asyncio.run(validator.verify_all_mappings(filtered_mapping))

    write_mappings(filtered_mapping)

def delete_tmp_validating_files():
    """
    Delete the unfiltered CSV file.
    """
    try:
        os.remove(ADDR_MAPPING_FILE_PATH[:-4] + '_unfiltered.csv')
    except FileNotFoundError:
        pass
