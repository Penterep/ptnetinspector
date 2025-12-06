import ipaddress
import asyncio
import csv
import os

from pathlib import Path
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

from ptnetinspector.entities.networks import Networks
from ptnetinspector.utils.interface import Interface
from ptnetinspector.send.send import IPMode
from ptnetinspector.utils.path import get_csv_path


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


from typing import Union

def is_valid_unicast_ip(ip: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]) -> bool:
    return not (ip.is_multicast or ip.is_unspecified or ip.is_loopback)

def check_ip_in_subnets(ip: Union[ipaddress.IPv4Address, ipaddress.IPv6Address], subnets: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]) -> bool:
    return any(ip in subnet for subnet in subnets)


def filter_unicast_addresses(mappings: List[AddressMapping], ip_mode: IPMode) -> List[AddressMapping]:
    result = []
    ipv4_subnets, ipv6_subnets = Networks.load_networks()

    if not ipv4_subnets and ip_mode.ipv4:
        ptprinthelper.ptprint("Auto-detection of IPv4 subnets failed. All unicast IPv4 addresses will be kept.", "WARNING")
    if not ipv6_subnets and ip_mode.ipv6:
        ptprinthelper.ptprint("Auto-detection of IPv6 subnets failed. All unicast IPv6 addresses will be kept.", "WARNING")

    for mapping in mappings:
        try:
            ip = ipaddress.ip_address(mapping.ip)
            if is_valid_unicast_ip(ip):
                if ip.is_link_local or (isinstance(ip, ipaddress.IPv4Address) and (not ipv4_subnets or check_ip_in_subnets(ip, ipv4_subnets))) or \
                   (isinstance(ip, ipaddress.IPv6Address) and (not ipv6_subnets or check_ip_in_subnets(ip, ipv6_subnets))):
                    result.append(mapping)
        except ValueError:
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
    def __init__(self, interface: str):
        self.interface = interface
        self.timeout = 0.5

    def verify_ipv4_mapping(self, mapping: AddressMapping) -> bool:
        arp_request = (Ether(src=get_if_hwaddr(self.interface), dst=mapping.mac) /
                       ARP(pdst=mapping.ip, hwdst=mapping.mac, op=1,
                           hwsrc=get_if_hwaddr(self.interface), psrc=get_if_addr(self.interface)))

        arp_reply = srp1(arp_request, timeout=self.timeout, verbose=False, iface=self.interface, filter=f"arp and ether src {mapping.mac}")

        return arp_reply and arp_reply.haslayer(ARP) and arp_reply.op == 2 and arp_reply.psrc == mapping.ip and arp_reply.hwsrc == mapping.mac

    def ipv6_address_on_interface_check(self) -> bool:
        candidate_ipv6_src_addr = Interface.get_interface_ipv6_ips(Interface(self.interface))
        return bool(candidate_ipv6_src_addr)

    def verify_ipv6_mapping(self, mapping: AddressMapping) -> bool:
        candidate_ipv6_src_addr = Interface.get_interface_ipv6_ips(Interface(self.interface))

        ns_packet = (Ether(src=get_if_hwaddr(self.interface), dst=mapping.mac) /
                     IPv6(src=get_source_addr_from_candidate_set(mapping.ip, candidate_ipv6_src_addr), dst=mapping.ip) /
                     ICMPv6ND_NS(tgt=mapping.ip) /
                     ICMPv6NDOptSrcLLAddr(lladdr=get_if_hwaddr(self.interface)))

        advertisement = srp1(ns_packet, timeout=self.timeout, verbose=False, iface=self.interface, filter=f"icmp6 and ether src {mapping.mac}")

        return advertisement and advertisement.haslayer(ICMPv6ND_NA) and advertisement[IPv6].src == mapping.ip and advertisement[Ether].src == mapping.mac

    async def verify_mapping(self, mapping: AddressMapping) -> bool:
        try:
            ip = ipaddress.ip_address(mapping.ip)
            return self.verify_ipv4_mapping(mapping) if isinstance(ip, ipaddress.IPv4Address) else self.verify_ipv6_mapping(mapping)
        except ValueError:
            return False

    async def verify_all_mappings(self, mappings: List[AddressMapping]) -> List[AddressMapping]:
        if not self.ipv6_address_on_interface_check():
            ptprinthelper.ptprint(f"Could not validate IPv6 addresses. No IPv6 address on interface {self.interface}", "ERROR")
            mappings = [mapping for mapping in mappings if not isinstance(ipaddress.ip_address(mapping.ip), ipaddress.IPv6Address)]

        tasks = [asyncio.create_task(self.verify_mapping(mapping)) for mapping in mappings]
        results = await asyncio.gather(*tasks)

        return [mapping for mapping, result in zip(mappings, results) if result]


def validate_addresses_mapping(interface: str, ip_mode: IPMode, passive: bool = False) -> None:
    validator = AddressValidator(interface)

    original_mappings = read_mappings()
    filtered_mapping = filter_unicast_addresses(original_mappings, ip_mode)

    csv_file = get_csv_path('addresses.csv')
    unfiltered_file = Path(str(csv_file).replace('.csv', '_unfiltered.csv'))
    write_mappings(original_mappings, file_path=unfiltered_file)

    if not passive:
        filtered_mapping = asyncio.run(validator.verify_all_mappings(filtered_mapping))

    write_mappings(filtered_mapping)


def delete_tmp_mapping_file():
    try:
        csv_file = get_csv_path('addresses.csv')
        unfiltered_file = csv_file.replace('.csv', '_unfiltered.csv')
        os.remove(unfiltered_file)
    except FileNotFoundError:
        pass
