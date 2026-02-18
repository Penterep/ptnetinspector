"""IPv6 active sending primitives.

Implements Scapy-based probes for IPv6 (ICMPv6, RA/RS, mDNS/LLMNR, DHCPv6,
MLD/Multicast, etc.) that complement passive capture in active/aggressive modes.
"""
import ipaddress
import csv
import time
import random
import uuid
import socket
import sys

from scapy.all import *
from scapy.layers.dhcp6 import DUID_LL, DHCP6OptElapsedTime, DHCP6OptIA_NA, DHCP6OptClientId, DHCP6_Solicit
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import UDP
from scapy.layers.inet6 import IPv6, ICMPv6MLQuery, ICMPv6EchoRequest, IPv6ExtHdrHopByHop, RouterAlert, IPv6ExtHdrDestOpt, HBHOptUnknown, ICMPv6ND_NS, ICMPv6NDOptSrcLLAddr, ICMPv6ND_NA, ICMPv6MLQuery2, ICMPv6ND_RS, ICMPv6ND_RA, ICMPv6NDOptRDNSS, ICMPv6NDOptMTU, ICMPv6NDOptPrefixInfo, ICMPv6NDOptDstLLAddr
from scapy.layers.l2 import Ether
from scapy.layers.llmnr import LLMNRQuery, LLMNRResponse

from ptnetinspector.utils.interface import Interface
from ptnetinspector.entities.mdns import MDNS
from ptnetinspector.entities.llmnr import LLMNR
from ptnetinspector.utils.ip_utils import is_global_unicast_ipv6, has_additional_data
from ptnetinspector.utils.ip_utils import generate_global_ipv6, generate_random_global_ipv6, collect_unique_items
from ptnetinspector.utils.path import get_csv_path
from ptnetinspector.utils.ip_utils import reverse_IPadd
from ptnetinspector.prototype.ipv6 import PrototypeIPv6Packet
from ptnetinspector.utils.ip_utils import send_ipv6_all_nodes_multicast, send_ipv6_all_routers_multicast, send_ipv6_from_all_addresses, send_ipv6_from_all_lla_addresses

class SendIPv6:
    @staticmethod
    def send_normal_multicast_ping(interface) -> None:
        """
        Send a standard IPv6 multicast ping (Echo Request) to ff02::1.
        Args:
            interface (str): Network interface to use.
        Output:
            None
        """
        send_ipv6_all_nodes_multicast(interface, 
            PrototypeIPv6Packet.get_l3payload_icmpv6_echo_request(id=111))

    @staticmethod
    def send_invalid_multicast_icmpv6(interface) -> None:
        """
        Send an invalid ICMPv6 multicast packet to ff02::1.
        Args:
            interface (str): Network interface to use.
        Output:
            None
        """
        send_ipv6_all_nodes_multicast(interface, 
            PrototypeIPv6Packet.get_l3payload_invalid_icmpv6_with_dest_opt(id=222))

    @staticmethod
    def send_invalid_multicast_ping(interface) -> None:
        """
        Send an invalid IPv6 multicast ping to ff02::1.
        Args:
            interface (str): Network interface to use.
        Output:
            None
        """
        send_ipv6_all_nodes_multicast(interface, 
            PrototypeIPv6Packet.get_l3payload_icmpv6_echo_request_with_dest_opt(id=333))

    @staticmethod
    def send_invalid_ipv6_hbh(interface) -> None:
        """
        Send an invalid IPv6 Hop-by-Hop packet to ff02::1.
        Args:
            interface (str): Network interface to use.
        Output:
            None
        """
        send_ipv6_all_nodes_multicast(interface,
            PrototypeIPv6Packet.get_l3payload_icmpv6_echo_request_with_hop_by_hop_opt(id=444))

    @staticmethod
    def send_multicast_ping_router(interface) -> None:
        """
        Send an IPv6 ping to the router multicast address ff02::2.
        Args:
            interface (str): Network interface to use.
        Output:
            None
        """
        send_ipv6_all_routers_multicast(interface,
            PrototypeIPv6Packet.get_l3payload_icmpv6_echo_request(id=555))

    @staticmethod
    def send_ns_router(ipv6_address, mac, interface) -> None:
        """
        Send an IPv6 Neighbor Solicitation to a router.
        Args:
            ipv6_address (str): Router IPv6 address.
            mac (str): Router MAC address.
            interface (str): Network interface to use.
        Output:
            None
        """
        src_mac = get_if_hwaddr(interface)
        send_ipv6_from_all_lla_addresses(interface,
            ICMPv6ND_NS(tgt=ipv6_address) /
            ICMPv6NDOptSrcLLAddr(lladdr=src_mac), ipv6_address, mac)

    @staticmethod
    def send_reverse_ipv6_MDNS(ipv6_address, interface) -> str | None:
        """
        Send an IPv6 mDNS PTR query and return the local name if found.
        Args:
            ipv6_address (str): Target IPv6 address.
            interface (str): Network interface to use.
        Output:
            str | None: Local name if found, else None.
        """
        exist_interface = Interface(interface).check_interface()
        if exist_interface:
            avail_ipv6 = Interface(interface).check_available_ipv6
            if avail_ipv6:
                src_mac = get_if_hwaddr(interface)
                query = reverse_IPadd(ipv6_address)
                src_ip = Interface(interface).get_interface_link_local_list()
                interface_ip_addresses = Interface(interface).get_interface_ips()
                if ipv6_address in interface_ip_addresses or ipv6_address == src_ip[:-5]:
                    return None
                pkt = []                
                pkt.append(PrototypeIPv6Packet.get_frame_mdns_ptr(src_mac, src_ip, query))
                pkt.append(PrototypeIPv6Packet.get_frame_mdns_ptr(src_mac, src_ip, query, unicastresponse=1))
                ans, uans = srp(pkt, multi=True, timeout=0.3, iface=interface, verbose=False)
                if ans:
                    try:
                        rdata = ans[0][1][DNS].an[0].rdata
                        try:
                            answer = rdata.decode()
                            return answer
                        except (IndexError, AttributeError, KeyError):
                            return None
                    except (IndexError, AttributeError, KeyError):
                        return None
                return None

    @staticmethod
    def send_mDNS_ipv6(query_name, interface) -> None:
        """
        Send an IPv6 mDNS query for the given name.
        Args:
            query_name (str): Name to query.
            interface (str): Network interface to use.
        Output:
            None
        """
        exist_interface = Interface(interface).check_interface()
        if exist_interface:
            avail_ipv6 = Interface(interface).check_available_ipv6
            if avail_ipv6:
                src_mac = get_if_hwaddr(interface)
                query_name = MDNS.full_name_MDNS(query_name)
                src_ip = Interface(interface).get_interface_link_local_list()
                pkt = PrototypeIPv6Packet.get_frame_mdns_bundle_a_aaaa_any(src_mac, src_ip, query_name)
                pkt.extend(PrototypeIPv6Packet.get_frame_mdns_bundle_a_aaaa_any(src_mac, src_ip, query_name, unicastresponse=1))
                sendp(pkt, iface=interface, verbose=False)

    @staticmethod
    def send_reverse_ipv6_llmnr(ipv6_address, interface) -> str | None:
        """
        Send an IPv6 LLMNR PTR query and return the domain name if found.
        Args:
            ipv6_address (str): Target IPv6 address.
            interface (str): Network interface to use.
        Output:
            str | None: Domain name if found, else None.
        """
        exist_interface = Interface(interface).check_interface()
        if exist_interface:
            avail_ipv6 = Interface(interface).check_available_ipv6
            if avail_ipv6:
                src_mac = get_if_hwaddr(interface)
                query = reverse_IPadd(ipv6_address)
                src_ip = Interface(interface).get_interface_link_local_list()
                interface_ip_addresses = Interface(interface).get_interface_ips()
                if ipv6_address in interface_ip_addresses or ipv6_address == src_ip[:-5]:
                    return None
                pkt = PrototypeIPv6Packet.get_frame_llmnr_ptr(src_mac, src_ip, query)
                response = AsyncSniffer(iface=interface)
                response.start()
                time.sleep(0.1)
                sendp(pkt, iface=interface, verbose=False)
                time.sleep(0.1)
                response.stop()
                for packet in response.results:
                    if packet.haslayer(UDP) and packet.haslayer(LLMNRResponse) and packet[DNSRR].rrname.decode("utf-8")[:-1] == query:
                        return packet[DNSRR].rdata.decode("utf-8")
                return None

    @staticmethod
    def send_llmnr_ipv6(name, interface) -> None:
        """
        Send an IPv6 LLMNR query for the given name.
        Args:
            name (str): Name to query.
            interface (str): Network interface to use.
        Output:
            None
        """
        exist_interface = Interface(interface).check_interface()
        if exist_interface:
            avail_ipv6 = Interface(interface).check_available_ipv6
            if avail_ipv6:
                src_mac = get_if_hwaddr(interface)
                name = LLMNR.full_name_llmnr(name)
                src_ip = Interface(interface).get_interface_link_local_list()
                pkt = PrototypeIPv6Packet.get_frame_llmnr_bundle_a_aaaa_any(src_mac, src_ip, name)
                sendp(pkt, iface=interface, verbose=False)

    def IPv6_test_mdns_llmnr(ip_address, interface) -> None:
        """
        Test mDNS and LLMNR for a given IPv6 address.
        Args:
            ip_address (str): IPv6 address to test.
            interface (str): Network interface to use.
        Output:
            None
        """
        name = SendIPv6.send_reverse_ipv6_llmnr(ip_address, interface)
        if name is not None and name.strip():
            SendIPv6.send_mDNS_ipv6(name, interface)
            SendIPv6.send_llmnr_ipv6(name, interface)
            return
        name = SendIPv6.send_reverse_ipv6_MDNS(ip_address, interface)
        if name is not None and name.strip():
            SendIPv6.send_mDNS_ipv6(name, interface)
            SendIPv6.send_llmnr_ipv6(name, interface)
            return

    @staticmethod
    def send_MLD_query(interface) -> None:
        """
        Send MLD query packets to IPv6 multicast address.
        Args:
            interface (str): Network interface to use.
        Output:
            None
        """
        exist_interface = Interface(interface).check_interface()
        if exist_interface:
            avail_ipv6 = Interface(interface).check_available_ipv6
            if avail_ipv6:                
                src_mac = get_if_hwaddr(interface)                
                ip_lla = Interface(interface).get_interface_link_local_list()
                src_ip_gua = Interface(interface).get_interface_global_unicast_list()
                # Send MLDv2 from LLA
                query_v2_lla = PrototypeIPv6Packet.get_frame_mldv2(src_mac, ip_lla)
                sendp(query_v2_lla*2, iface=interface, verbose=False)
                time.sleep(0.1)
                # Send MLDv2 from GUA
                query_v2_gua = PrototypeIPv6Packet.get_frame_mldv2(src_mac, src_ip_gua)
                sendp(query_v2_gua*2, iface=interface, verbose=False)
                time.sleep(0.1)
                # Send MLDv1 from LLA
                query_v1_lla = PrototypeIPv6Packet.get_frame_mldv1(src_mac, ip_lla)
                sendp(query_v1_lla*2, iface=interface, verbose=False)
                time.sleep(0.1)
                # Send MLDv1 from GUA
                query_v1_gua = PrototypeIPv6Packet.get_frame_mldv1(src_mac, src_ip_gua)
                sendp(query_v1_gua*2, iface=interface, verbose=False)

    @staticmethod
    def send_RS(interface) -> None:
        """
        Send Router Solicitation to discover routers.
        Args:
            interface (str): Network interface to use.
        Output:
            None
        """
        exist_interface = Interface(interface).check_interface()
        if exist_interface:
            send_ipv6_all_routers_multicast(interface,
                ICMPv6ND_RS() / ICMPv6NDOptSrcLLAddr(lladdr=get_if_hwaddr(interface)))        

    @staticmethod
    def send_RA(interface, prefix_len, network, source_mac, source_ip, rpref, chl, mtu, dns, aggressive_mode, period, duration) -> None:
        """
        Send Router Advertisement to all nodes, optionally in aggressive mode.
        Args:
            interface (str): Network interface to use.
            prefix_len, network, source_mac, source_ip, rpref, chl, mtu, dns, aggressive_mode, period, duration: RA parameters.
        Output:
            None
        """
        exist_interface = Interface(interface).check_interface()
        if exist_interface:
            layer2 = Ether(src=source_mac, dst="33:33:00:00:00:01")
            layer3 = IPv6(src=source_ip, dst="ff02::1")
            RA = ICMPv6ND_RA(prf=rpref, M=0, O=0, H=0, chlim=chl, routerlifetime=1800, reachabletime=0, retranstimer=0)
            kill_RA = ICMPv6ND_RA(prf=rpref, M=0, O=0, H=0, chlim=chl, routerlifetime=0, reachabletime=0, retranstimer=0)
            Opt_LLAddr = ICMPv6NDOptSrcLLAddr(lladdr=source_mac)
            packet1 = layer2 / layer3 / RA
            Opt_PrefixInfo = ICMPv6NDOptPrefixInfo(prefixlen=prefix_len, A=1, prefix=network, validlifetime=1800, preferredlifetime=1800)
            kill_Opt_PrefixInfo = ICMPv6NDOptPrefixInfo(prefixlen=prefix_len, A=1, prefix=network, validlifetime=0, preferredlifetime=0)
            packet1 /= Opt_PrefixInfo
            if mtu is not None:
                Opt_MTU = ICMPv6NDOptMTU(mtu=mtu)
                packet1 /= Opt_MTU
            if dns is not None:
                Opt_DNS = ICMPv6NDOptRDNSS(dns=dns, lifetime=1800)
                kill_Opt_DNS = ICMPv6NDOptRDNSS(dns=dns, lifetime=0)
                packet1 /= Opt_DNS
            kill_packet1 = layer2/layer3/kill_RA/kill_Opt_PrefixInfo
            if dns is not None:
                kill_packet1 /= kill_Opt_DNS
            packet1 /= Opt_LLAddr
            kill_packet1 /= Opt_LLAddr
            if aggressive_mode and period is not None:
                start_time = time.time()
                while time.time() - start_time <= duration+0.5:
                    sendp(packet1, verbose=False, iface=interface)
                    if time.time() - start_time >= duration:
                        sendp(kill_packet1, verbose=False, iface=interface)
                        break
                    time.sleep(period)
            else:
                sendp(packet1, verbose=False, iface=interface)

    @staticmethod
    def send_to_possible_IP(interface) -> None:
        """
        Send various probes to possible IPv6 addresses discovered.
        Args:
            interface (str): Network interface to use.
        Output:
            None
        """
        possible_global_IP = generate_more_possible_IP(interface)
        if possible_global_IP is None:
            return
        for mac, ips in possible_global_IP.items():
            send_ipv6_from_all_addresses(interface,
                PrototypeIPv6Packet.get_l3payload_icmpv6_echo_request(), ips, mac)
            send_ipv6_from_all_addresses(interface,
                PrototypeIPv6Packet.get_l3payload_invalid_icmpv6_with_dest_opt(),ips,mac)
            send_ipv6_from_all_addresses(interface,
                PrototypeIPv6Packet.get_l3payload_icmpv6_echo_request_with_dest_opt(), ips, mac)
            send_ipv6_from_all_addresses(interface,
                PrototypeIPv6Packet.get_l3payload_icmpv6_echo_request_with_hop_by_hop_opt(), ips, mac)
        for mac, ips in possible_global_IP.items():
            if ips != []:
                for dst_ip in ips:
                    try:
                        dst_ip = ipaddress.IPv6Address(dst_ip)
                        SendIPv6.IPv6_test_mdns_llmnr(dst_ip, interface)
                    except ipaddress.AddressValueError:
                        continue

    @staticmethod
    def send_NA(interface, source_mac, target_mac, source_ip, target_ip, r_flag, s_flag, o_flag) -> None:
        """
        Send an IPv6 Neighbor Advertisement.
        Args:
            interface (str): Network interface to use.
            source_mac, target_mac, source_ip, target_ip, r_flag, s_flag, o_flag: NA parameters.
        Output:
            None
        """
        exist_interface = Interface(interface).check_interface()
        if exist_interface:
            layer2 = Ether(src=source_mac, dst=target_mac)
            layer3 = IPv6(src=source_ip, dst=target_ip)
            packet1 = layer2 / layer3 / ICMPv6ND_NA(R=r_flag, S=s_flag, O=o_flag, tgt=source_ip) / ICMPv6NDOptDstLLAddr(lladdr=source_mac)
            sendp(packet1, verbose=False, iface=interface)

    @staticmethod
    def react_to_NS_RS(interface, prefix_len, network, source_mac, source_ip, rpref, chl, mtu, dns, duration) -> None:
        """
        React to NS or RS packets by sending RA or NA as appropriate.
        Args:
            interface (str): Network interface to use.
            prefix_len, network, source_mac, source_ip, rpref, chl, mtu, dns, duration: Parameters.
        Output:
            None
        """
        def custom_action(packet):
            if ICMPv6ND_RS in packet and packet[0][1].src != source_ip:
                SendIPv6.send_RA(interface, prefix_len, network, source_mac, source_ip, rpref, chl, mtu, dns, False, None, None)
            if ICMPv6ND_NS in packet and packet[0][1].src != source_ip:
                SendIPv6.send_NA(interface, source_mac, packet[0].src, source_ip, packet[0][1].src, 1, 1, 1)
        build_filter = "ip6"
        try:
            sniff(iface=interface, filter=build_filter, prn=custom_action, timeout=duration)
        except KeyboardInterrupt:
            sys.exit(0)

    @staticmethod
    def send_to_test_RA_guard(interface) -> None:
        """
        Send unicast IPv6 packets to all hosts to test RA guard.
        Args:
            interface (str): Network interface to use.
        Output:
            None
        """
        exist_interface = Interface(interface).check_interface()
        src_mac = get_if_hwaddr(interface)
        mac_ips_global = {}
        csv_file = get_csv_path("addresses.csv")
        
        with open(csv_file, 'r') as csvfile:
            reader = csv.reader(csvfile)
            headers = next(reader)
            mac_index = headers.index('MAC')
            ip_index = headers.index('IP')
            for row in reader:
                mac = row[mac_index]
                ip = row[ip_index]
                if mac == src_mac:
                    continue
                if mac not in mac_ips_global:
                    mac_ips_global[mac] = []
                try:
                    ip_address = ipaddress.IPv6Address(ip)
                    if is_global_unicast_ipv6(str(ip_address)):
                        mac_ips_global[mac].append(ip)
                except ValueError:
                    pass
        if exist_interface:
            src_mac = get_if_hwaddr(interface)
            dest_ip_list = collect_unique_items(mac_ips_global)
            sip = generate_random_global_ipv6(dest_ip_list)
            layer2 = Ether(src=src_mac)
            for mac, ips in mac_ips_global.items():
                if ips != []:
                    layer3 = IPv6(src=sip, dst=ips)
                    pkt1 = (layer2 / layer3 / 
                        PrototypeIPv6Packet.get_l3payload_icmpv6_echo_request())
                    pkt2 = (layer2 / layer3 / 
                        PrototypeIPv6Packet.get_l3payload_invalid_icmpv6_with_dest_opt())
                    pkt3 = (layer2 / layer3 / 
                        PrototypeIPv6Packet.get_l3payload_icmpv6_echo_request_with_dest_opt())
                    pkt4 = (layer2 / layer3 / 
                        PrototypeIPv6Packet.get_l3payload_icmpv6_echo_request_with_hop_by_hop_opt())
                    sendp(pkt1, iface=interface, verbose=False)
                    sendp(pkt2, iface=interface, verbose=False)
                    sendp(pkt3, iface=interface, verbose=False)
                    sendp(pkt4, iface=interface, verbose=False)

    @staticmethod
    def send_ns(address: str, interface: str, wait_for_rsp: bool = False, rsp_timeout: float = 0.1) -> None | SndRcvList:
        """
        Send an ICMPv6 Neighbor Solicitation to an IPv6 address.
        Args:
            address (str): The IPv6 address.
            interface (str): The network interface to use.
            wait_for_rsp (bool): Whether to wait for a response.
            rsp_timeout (float): Timeout for the response.
        Output:
            None or SndRcvList: Response if wait_for_rsp is True, else None.
        """
        exist_interface = Interface(interface).check_interface()
        if exist_interface:
            avail_ipv6 = Interface(interface).check_available_ipv6
            if avail_ipv6:
                ether = Ether(src=get_if_hwaddr(interface))
                ipv6 = IPv6(dst=inet_ntop(socket.AF_INET6, in6_getnsma(inet_pton(socket.AF_INET6, address))))
                ns = ICMPv6ND_NS(tgt=address)
                slla = ICMPv6NDOptSrcLLAddr(lladdr=get_if_hwaddr(interface))
                pkt = ether / ipv6 / ns / slla
                if wait_for_rsp:
                    return srp(pkt, iface=interface, verbose=0, timeout=rsp_timeout)[0]
                sendp(pkt, verbose=0, iface=interface)

    @staticmethod
    def probe_ipv6_interesting_addresses(network: ipaddress.IPv6Network, interface: str) -> None:
        """
        Probe ::0 and ::1 addresses in IPv6 network.
        Args:
            network (ipaddress.IPv6Network): The network to probe.
            interface (str): The network interface to use.
        Output:
            None
        """
        try:
            SendIPv6.send_ns('fe80::0', interface)
            SendIPv6.send_ns('fe80::1', interface)
            first_addr = network.network_address
            SendIPv6.send_ns(str(first_addr), interface)
            last_bits = network.network_address.packed[:-1] + bytes([network.network_address.packed[-1] | 1])
            second_addr = ipaddress.IPv6Address(last_bits)
            if second_addr in network:
                SendIPv6.send_ns(str(second_addr), interface)
        except:
            return

    @staticmethod
    def send_wsdiscovery_probe(interface: str) -> None:
        """
        Send a WS-Discovery probe to the multicast address.
        Args:
            interface (str): The network interface to use.
        Output:
            None
        """
        exist_interface = Interface(interface).check_interface()
        if exist_interface:
            send_ipv6_from_all_addresses(interface, 
                PrototypeIPv6Packet.get_l3payload_wsdiscovery(), dst_ip="ff02::c"),                

    @staticmethod
    def send_dns_sd_probe(interface: str) -> None:
        """
        Send a DNS-SD general probe to the multicast address.
        Args:
            interface (str): The network interface to use.
        Output:
            None
        """
        exist_interface = Interface(interface).check_interface()
        if exist_interface:
            avail_ipv6 = Interface(interface).check_available_ipv6
            if avail_ipv6:
                ipv6_addresses = Interface(interface).get_interface_ipv6_ips()
                for source_ipv6_addr in ipv6_addresses:
                    src_mac = get_if_hwaddr(interface)
                    dns_sd = []
                    dns_sd.append(PrototypeIPv6Packet.get_frame_mdns_sd(src_mac, source_ipv6_addr))
                    dns_sd.append(PrototypeIPv6Packet.get_frame_mdns_sd(src_mac, source_ipv6_addr, unicastresponse=1))
                    sendp(dns_sd, verbose=0, iface=interface)

    @staticmethod
    def send_dhcpv6_solicit(interface: str) -> None:
        """
        Send a DHCPv6 Solicit packet.
        Args:
            interface (str): Network interface to send packet on.
        Output:
            None
        """
        send_ipv6_from_all_lla_addresses(interface,
            PrototypeIPv6Packet.get_l3payload_dhcpv6_solicit(get_if_hwaddr(interface)), dst_ip="ff02::1:2")


def generate_more_possible_IP(interface) -> dict | None:
    """
    Generate possible IPv6 addresses for probing, based on link-local and global addresses.
    Args:
        interface (str): Network interface to use.
    Output:
        dict | None: Dictionary of MAC to possible IPv6 addresses, or None if not available.
    """
    src_mac = get_if_hwaddr(interface)
    mac_ips = {}
    mac_ips_global_old = {}
    prefix_list = []
    
    csv_file = get_csv_path("addresses.csv")
    with open(csv_file, 'r') as csvfile:
        reader = csv.reader(csvfile)
        headers = next(reader)
        mac_index = headers.index('MAC')
        ip_index = headers.index('IP')
        for row in reader:
            mac = row[mac_index]
            ip = row[ip_index]
            if mac == src_mac:
                continue
            if mac not in mac_ips:
                mac_ips[mac] = []
                mac_ips_global_old[mac] = []
            try:
                ip_address = ipaddress.IPv6Address(ip)
                if ip_address.is_link_local:
                    mac_ips[mac].append(ip)
                if is_global_unicast_ipv6(str(ip_address)):
                    mac_ips_global_old[mac].append(ip)
            except ValueError:
                pass
    
    ra_csv_file = get_csv_path("RA.csv")
    if has_additional_data(ra_csv_file):
        with open(ra_csv_file, 'r') as csvfile:
            reader = csv.reader(csvfile)
            headers = next(reader)
            prefix_index = headers.index('Prefix')
            for row in reader:
                if row[prefix_index] not in prefix_list:
                    prefix_list.append(row[prefix_index])
    
    flag_error = 0
    if prefix_list != []:
        for mac, ip_ll in mac_ips.items():
            if ip_ll != []:
                list_ip_generate_unit = []
                for prefix in prefix_list:
                    new_global_ip = generate_global_ipv6(prefix, ip_ll[0])
                    if new_global_ip is not None:
                        if new_global_ip not in mac_ips_global_old[mac]:
                            list_ip_generate_unit.append(new_global_ip)
                mac_ips[mac] = list_ip_generate_unit
            else:
                flag_error += 1
                continue
    if prefix_list == [] or flag_error == len(mac_ips):
        return None
    return mac_ips