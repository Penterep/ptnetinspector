import ipaddress
import csv
import time
import random
import uuid
import socket
import sys

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

class SendIPv6DevNOK(SendIPv6):
    # Nothing
    @staticmethod
    def send_invalid_icmpv6(interface) -> None:
        """
        Send an IPv6 multicast ping packet to ff02::1.
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
                               ICMPv6EchoRequest(id=888, type=254))
                        sendp(pkt, iface=interface, verbose=False)
                    except ipaddress.AddressValueError:
                        pass

    # Nothing
    @staticmethod
    def send_invalid_ipv6_nh_2(interface) -> None:
        """
        Send an IPv6 multicast packet with Invalid Next Header to ff02::1.
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
                               IPv6(src=src_ip, dst="ff02::1", nh=255) /
                               Raw(load=b"\x00\x00\x00"))
                        sendp(pkt, iface=interface, verbose=False)
                    except ipaddress.AddressValueError:
                        pass     

    @staticmethod
    def send_invalid_icmpv6(interface) -> None:
        """
        Send an IPv6 multicast ping packet to ff02::1.
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

    # MALFORMED
    @staticmethod
    def send_invalid_empty_ipv6_hbh(interface) -> None:
        """
        Send an IPv6 multicast packet with No Next Header and Hop-by-Hop Option Value 255 to ff02::1.
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
                               IPv6ExtHdrHopByHop(
                                   nh=59,options=[HBHOptUnknown(otype=255, optdata=b"\x00\x00\x00")]))
                        sendp(pkt, iface=interface, verbose=False)
                    except ipaddress.AddressValueError:
                        pass

    # MALFORMED
    @staticmethod
    def send_invalid_ipv6_hbh(interface) -> None:
        """
        Send an IPv6 multicast packet with No Next Header and Hop-by-Hop Option Value 255 to ff02::1.
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
                               IPv6(src=src_ip, dst="ff02::1", hlim=255) /
                               IPv6ExtHdrHopByHop(
                                   nh=59,options=[HBHOptUnknown(otype=255, optdata=b"\x00\x00\x00")]))
                        sendp(pkt, iface=interface, verbose=False)
                    except ipaddress.AddressValueError:
                        pass

    # MALFORMED
    @staticmethod
    def send_invalid_ipv6_nh(interface) -> None:
        """
        Send an IPv6 multicast packet with Invalid Next Header to ff02::1.
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
                               IPv6(src=src_ip, dst="ff02::1", nh=255))
                        sendp(pkt, iface=interface, verbose=False)
                    except ipaddress.AddressValueError:
                        pass   

    # NOTHING
    @staticmethod
    def send_invalid_ipv6_nh_ping(interface) -> None:
        """
        Send an IPv6 multicast ping packet with Invalid Next Header to ff02::1.
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
                               IPv6(src=src_ip, dst="ff02::1", nh=255) /
                               ICMPv6EchoRequest(id=666))
                        sendp(pkt, iface=interface, verbose=False)
                    except ipaddress.AddressValueError:
                        pass
    
    # NOTHING
    @staticmethod
    def send_invalid_ipv6_nh_invalid_ping(interface) -> None:
        """
        Send an IPv6 multicast ping packet with Invalid Next Header and Invalid ICMPv6 Type to ff02::1.
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
                               IPv6(src=src_ip, dst="ff02::1", nh=255) /
                               ICMPv6EchoRequest(id=888, type=254))
                        sendp(pkt, iface=interface, verbose=False)
                    except ipaddress.AddressValueError:
                        pass

    @staticmethod
    def send_empty_ipv6_routing(interface) -> None:
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
                               IPv6ExtHdrRouting(nh=59, type=128, addresses=[src_ip]))
                        sendp(pkt, iface=interface, verbose=False)
                    except ipaddress.AddressValueError:
                        pass        