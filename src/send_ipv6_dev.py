import ipaddress
import csv
import time
import random
import uuid
import socket
import sys
import struct

from scapy.all import *
from scapy.layers.dhcp6 import DUID_LL, DHCP6OptElapsedTime, DHCP6OptIA_NA, DHCP6OptOptReq, DHCP6OptClientId, DHCP6_Solicit
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import UDP
from scapy.layers.inet6 import IPv6, ICMPv6MLQuery, ICMPv6EchoRequest, IPv6ExtHdrHopByHop, RouterAlert, IPv6ExtHdrDestOpt, HBHOptUnknown, ICMPv6ND_NS, ICMPv6NDOptSrcLLAddr, ICMPv6ND_NA, ICMPv6MLQuery2, ICMPv6ND_RS, ICMPv6ND_RA, ICMPv6NDOptRDNSS, ICMPv6NDOptMTU, ICMPv6NDOptPrefixInfo, ICMPv6NDOptDstLLAddr, IPv6ExtHdrRouting, IPv6ExtHdrFragment
from scapy.layers.l2 import Ether
from scapy.layers.llmnr import LLMNRQuery, LLMNRResponse
from src.interface import Interface, reverse_IPadd
from src.device.mdns import MDNS
from src.device.llmnr import LLMNR
from libs.check import is_global_unicast_ipv6, has_additional_data
from libs.convert import generate_global_ipv6, generate_random_global_ipv6, collect_unique_items

from src.send_ipv6 import SendIPv6

class SendIPv6Dev(SendIPv6):

    @staticmethod
    def send_empty_ipv6_hbhopt(interface) -> None:
        """
        Send an IPv6 multicast packet with No Next Header and Hop-by-Hop Option Value 128 to ff02::1.
        Args:
            interface (str): Network interface to use.
        Output:
            None
        """
        exist_interface = Interface(interface).check_interface()
        if exist_interface:
            avail_ipv6 = Interface(interface).check_available_ipv6
            if avail_ipv6:
                ip_addresses = Interface(interface).get_interface_ips()
                src_mac = get_if_hwaddr(interface)
                for ip in ip_addresses:
                    try:
                        ipaddress.IPv4Address(ip)
                        continue
                    except ipaddress.AddressValueError:
                        pass
                    try:
                        ipaddress.IPv6Address(ip)
                        src_ip = ip
                        pkt = (Ether(src=src_mac, dst="33:33:00:00:00:01") /
                               IPv6(src=src_ip, dst="ff02::1") /
                               IPv6ExtHdrHopByHop(nh=59, options=[HBHOptUnknown(otype=128, optdata=b"\x00\x00\x00")]))
                        sendp(pkt, iface=interface, verbose=False)
                    except ipaddress.AddressValueError:
                        pass

    @staticmethod
    def send_empty_ipv6_dstopt(interface) -> None:
        """
        Send an IPv6 multicast packet with No Next Header and Destination Option Value 128 to ff02::1.
        Args:
            interface (str): Network interface to use.
        Output:
            None
        """
        exist_interface = Interface(interface).check_interface()
        if exist_interface:
            avail_ipv6 = Interface(interface).check_available_ipv6
            if avail_ipv6:
                ip_addresses = Interface(interface).get_interface_ips()
                src_mac = get_if_hwaddr(interface)
                for ip in ip_addresses:
                    try:
                        ipaddress.IPv4Address(ip)
                        continue
                    except ipaddress.AddressValueError:
                        pass
                    try:
                        ipaddress.IPv6Address(ip)
                        src_ip = ip
                        pkt = (Ether(src=src_mac, dst="33:33:00:00:00:01") /
                               IPv6(src=src_ip, dst="ff02::1") /
                               IPv6ExtHdrDestOpt(nh=59, options=[HBHOptUnknown(otype=128, optdata=b"\x00\x00\x00")]))
                        sendp(pkt, iface=interface, verbose=False)
                    except ipaddress.AddressValueError:
                        pass    

    @staticmethod
    def send_icmpv6_ping_hbhopt(interface) -> None:
        """
        Send an IPv6 multicast ping packet with Hop-by-Hop Option Value 128 to ff02::1.
        Args:
            interface (str): Network interface to use.
        Output:
            None
        """
        exist_interface = Interface(interface).check_interface()
        if exist_interface:
            avail_ipv6 = Interface(interface).check_available_ipv6
            if avail_ipv6:
                ip_addresses = Interface(interface).get_interface_ips()
                src_mac = get_if_hwaddr(interface)
                for ip in ip_addresses:
                    try:
                        ipaddress.IPv4Address(ip)
                        continue
                    except ipaddress.AddressValueError:
                        pass
                    try:
                        ipaddress.IPv6Address(ip)
                        src_ip = ip
                        pkt = (Ether(src=src_mac, dst="33:33:00:00:00:01") /
                               IPv6(src=src_ip, dst="ff02::1") /
                               IPv6ExtHdrHopByHop(options=[HBHOptUnknown(otype=128, optdata=b"\x00\x00\x00")]) /
                               ICMPv6EchoRequest(id=666, type=254))
                        sendp(pkt, iface=interface, verbose=False)
                    except ipaddress.AddressValueError:
                        pass

    @staticmethod
    def send_icmpv6_ping_dstopt(interface) -> None:
        """
        Send an IPv6 multicast ping packet with Destination Option Value 128 to ff02::1.
        Args:
            interface (str): Network interface to use.
        Output:
            None
        """
        exist_interface = Interface(interface).check_interface()
        if exist_interface:
            avail_ipv6 = Interface(interface).check_available_ipv6
            if avail_ipv6:
                ip_addresses = Interface(interface).get_interface_ips()
                src_mac = get_if_hwaddr(interface)
                for ip in ip_addresses:
                    try:
                        ipaddress.IPv4Address(ip)
                        continue
                    except ipaddress.AddressValueError:
                        pass
                    try:
                        ipaddress.IPv6Address(ip)
                        src_ip = ip
                        pkt = (Ether(src=src_mac, dst="33:33:00:00:00:01") /
                               IPv6(src=src_ip, dst="ff02::1") /
                               IPv6ExtHdrDestOpt(options=[HBHOptUnknown(otype=128, optdata=b"\x00\x00\x00")]) /
                               ICMPv6EchoRequest(id=777, type=254))
                        sendp(pkt, iface=interface, verbose=False)
                    except ipaddress.AddressValueError:
                        pass

    @staticmethod
    def send_invalid_ipv6_nh_hbhopt(interface) -> None:
        """
        Send an IPv6 multicast packet with Invalid Next Header and Hop-by-Hop Option Value 128 to ff02::1.
        Args:
            interface (str): Network interface to use.
        Output:
            None
        """
        exist_interface = Interface(interface).check_interface()
        if exist_interface:
            avail_ipv6 = Interface(interface).check_available_ipv6
            if avail_ipv6:
                ip_addresses = Interface(interface).get_interface_ips()
                src_mac = get_if_hwaddr(interface)
                for ip in ip_addresses:
                    try:
                        ipaddress.IPv4Address(ip)
                        continue
                    except ipaddress.AddressValueError:
                        pass
                    try:
                        ipaddress.IPv6Address(ip)
                        src_ip = ip
                        pkt = (Ether(src=src_mac, dst="33:33:00:00:00:01") /
                               IPv6(src=src_ip, dst="ff02::1") /
                               IPv6ExtHdrHopByHop(nh=255, options=[HBHOptUnknown(otype=128, optdata=b"\x00\x00\x00")]) /
                               Raw(load=b"\x00\x00\x00"))
                        sendp(pkt, iface=interface, verbose=False)
                    except ipaddress.AddressValueError:
                        pass             
    
    @staticmethod
    def send_invalid_ipv6_nh_dstopt(interface) -> None:
        """
        Send an IPv6 multicast packet with Invalid Next Header and Destination Option Value 128 to ff02::1.
        Args:
            interface (str): Network interface to use.
        Output:
            None
        """
        exist_interface = Interface(interface).check_interface()
        if exist_interface:
            avail_ipv6 = Interface(interface).check_available_ipv6
            if avail_ipv6:
                ip_addresses = Interface(interface).get_interface_ips()
                src_mac = get_if_hwaddr(interface)
                for ip in ip_addresses:
                    try:
                        ipaddress.IPv4Address(ip)
                        continue
                    except ipaddress.AddressValueError:
                        pass
                    try:
                        ipaddress.IPv6Address(ip)
                        src_ip = ip
                        pkt = (Ether(src=src_mac, dst="33:33:00:00:00:01") /
                               IPv6(src=src_ip, dst="ff02::1") /
                               IPv6ExtHdrDestOpt(nh=255, options=[HBHOptUnknown(otype=128, optdata=b"\x00\x00\x00")]) /
                               Raw(load=b"\x00\x00\x00"))
                        sendp(pkt, iface=interface, verbose=False)
                    except ipaddress.AddressValueError:
                        pass             

    @staticmethod
    def send_invalid_icmpv6_ipv6_hbhopt(interface) -> None:
        """
        Send an IPv6 multicast ping packet with Hop-by-Hop Option Value 128 to ff02::1.
        Args:
            interface (str): Network interface to use.
        Output:
            None
        """
        exist_interface = Interface(interface).check_interface()
        if exist_interface:
            avail_ipv6 = Interface(interface).check_available_ipv6
            if avail_ipv6:
                ip_addresses = Interface(interface).get_interface_ips()
                src_mac = get_if_hwaddr(interface)
                for ip in ip_addresses:
                    try:
                        ipaddress.IPv4Address(ip)
                        continue
                    except ipaddress.AddressValueError:
                        pass
                    try:
                        ipaddress.IPv6Address(ip)
                        src_ip = ip
                        pkt = (Ether(src=src_mac, dst="33:33:00:00:00:01") /
                               IPv6(src=src_ip, dst="ff02::1") /
                               IPv6ExtHdrHopByHop(options=[HBHOptUnknown(otype=128, optdata=b"\x00\x00\x00")]) /
                               ICMPv6EchoRequest(id=888, type=254))
                        sendp(pkt, iface=interface, verbose=False)
                    except ipaddress.AddressValueError:
                        pass

    @staticmethod
    def send_invalid_icmpv6_ipv6_dstopt(interface) -> None:
        """
        Send an IPv6 multicast ping packet with Destination Option Value 128 to ff02::1.
        Args:
            interface (str): Network interface to use.
        Output:
            None
        """
        exist_interface = Interface(interface).check_interface()
        if exist_interface:
            avail_ipv6 = Interface(interface).check_available_ipv6
            if avail_ipv6:
                ip_addresses = Interface(interface).get_interface_ips()
                src_mac = get_if_hwaddr(interface)
                for ip in ip_addresses:
                    try:
                        ipaddress.IPv4Address(ip)
                        continue
                    except ipaddress.AddressValueError:
                        pass
                    try:
                        ipaddress.IPv6Address(ip)
                        src_ip = ip
                        pkt = (Ether(src=src_mac, dst="33:33:00:00:00:01") /
                               IPv6(src=src_ip, dst="ff02::1") /
                               IPv6ExtHdrDestOpt(options=[HBHOptUnknown(otype=128, optdata=b"\x00\x00\x00")]) /
                               ICMPv6EchoRequest(id=999, type=254))
                        sendp(pkt, iface=interface, verbose=False)
                    except ipaddress.AddressValueError:
                        pass

    @staticmethod
    def send_ssdp_msearch_ipv6(interface) -> None:
        """
        Send an SSDP M-SEARCH (UPnP) over IPv6 multicast to discover devices.
        IPv6 multicast addr: ff02::c, UDP/1900, HLIM=1. Many devices respond unicast with device/service descriptions.
        Args:
            interface (str): Network interface to use.
        Output:
            None
        """
        exist_interface = Interface(interface).check_interface()
        if exist_interface:
            avail_ipv6 = Interface(interface).check_available_ipv6
            if avail_ipv6:
                ip_addresses = Interface(interface).get_interface_ips()
                src_mac = get_if_hwaddr(interface)
                for ip in ip_addresses:
                    try:
                        ipaddress.IPv4Address(ip)
                        continue
                    except ipaddress.AddressValueError:
                        pass
                    try:
                        ipaddress.IPv6Address(ip)
                        src_ip = ip
                        # Minimal compliant M-SEARCH (HTTPU) payload
                        payload = (
                            b"M-SEARCH * HTTP/1.1\r\n"
                            b"HOST:[FF02::C]:1900\r\n"
                            b"MAN:\"ssdp:discover\"\r\n"
                            b"MX:2\r\n"
                            b"ST:ssdp:all\r\n"
                            b"\r\n"
                        )
                        ether = Ether(src=src_mac)
                        ipv6 = IPv6(src=src_ip, dst="ff02::1", hlim=1)
                        udp = UDP(sport=random.randint(49152, 65535), dport=1900)
                        pkt = ether / ipv6 / udp / Raw(load=payload)
                        sendp(pkt, iface=interface, verbose=0)
                    except ipaddress.AddressValueError:
                        pass
    
    @staticmethod
    def send_coap_discovery_ipv6(interface) -> None:
        """
        Send a CoAP multicast discovery GET /.well-known/core to all CoAP nodes over IPv6.
        IPv6 multicast addr: ff02::fd, UDP/5683, HLIM=1. Constrained devices typically reply unicast.
        Args:
            interface (str): Network interface to use.
        Output:
            None
        """
        exist_interface = Interface(interface).check_interface()
        if exist_interface:
            avail_ipv6 = Interface(interface).check_available_ipv6
            if avail_ipv6:
                ip_addresses = Interface(interface).get_interface_ips()
                src_mac = get_if_hwaddr(interface)
                for ip in ip_addresses:
                    try:
                        ipaddress.IPv4Address(ip)
                        continue
                    except ipaddress.AddressValueError:
                        pass
                    try:
                        ipaddress.IPv6Address(ip)
                        src_ip = ip
                        # Build a very small CoAP CON GET with Token (2B), Uri-Path: ".well-known" and "core"
                        # CoAP header: Ver=1(01), Type=CON(00), TKL=2 => 0x42; Code=0.01 (GET)=>0x01; Message ID random
                        mid = random.randint(0, 0xFFFF)
                        token = random.randbytes(2) if hasattr(random, 'randbytes') else bytes([random.randint(0,255), random.randint(0,255)])
                        header = bytes([0x42, 0x01, (mid >> 8) & 0xFF, mid & 0xFF]) + token
                        # Options: Uri-Path ".well-known" (11), then "core" (4)
                        # Option number deltas accumulate from previous (start at 0)
                        # First: delta=11, len=11 -> 0xBB, value=b".well-known"
                        opt1 = bytes([0xBB]) + b".well-known"
                        # Second: delta=0 (11->11), len=4 -> 0x04, value=b"core"
                        # Correction: delta must be current(11) to next(11)=0, so delta=0; OK
                        opt2 = bytes([0x04]) + b"core"
                        coap = header + opt1 + opt2
                        ether = Ether(src=src_mac)
                        ipv6 = IPv6(src=src_ip, dst="ff02::1", hlim=1)
                        udp = UDP(sport=random.randint(49152, 65535), dport=5683)
                        pkt = ether / ipv6 / udp / Raw(load=coap)
                        sendp(pkt, iface=interface, verbose=0)
                    except ipaddress.AddressValueError:
                        pass

                    