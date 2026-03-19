"""IPv4 active sending primitives.

Implements Scapy-based probes for IPv4 (ICMP, mDNS/LLMNR, DHCP, IGMP, etc.)
that complement passive capture in active/aggressive modes.
"""
import ipaddress
import random
import time
import sys
import uuid
from enum import Enum

from scapy.all import *
from scapy.contrib.igmp import IGMP
from scapy.contrib.igmpv3 import IGMPv3, IGMPv3mq
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import UDP, IP, ICMP
from scapy.layers.l2 import Ether, ARP
from scapy.layers.llmnr import LLMNRQuery, LLMNRResponse

from ptnetinspector.entities.networks import Networks
from ptnetinspector.prototype.prototype_ipv4 import PrototypeIPv4Packet, IGMP_Type, IGMPV3_RType
from ptnetinspector.prototype.prototype_l4 import PrototypeL4
from ptnetinspector.utils.interface import Interface
from ptnetinspector.entities.mdns import MDNS
from ptnetinspector.entities.llmnr import LLMNR
from ptnetinspector.utils.ip_utils import reverse_IPadd


class ICMPType(Enum):
    ECHO_REQUEST = 8
    ROUTER_SOLICITATION = 10
    UNASSIGNED_255 = 255


class SendIPv4:
    __icmp_echo_request_sequence_number = 1
    @staticmethod
    def __get_next_icmp_echo_request_id() -> int:
        """
        Get the next ICMP Echo Request identifier, incrementing the internal sequence number.
        Returns:
            int: The next ICMPv6 Echo Request identifier.
        """
        current_id = SendIPv4.__icmp_echo_request_sequence_number
        SendIPv4.__icmp_echo_request_sequence_number += 1
        return current_id

    @staticmethod
    def send_reverse_ipv4_MDNS(ip_address: str, interface: str) -> str | None:
        # Function to send an IPv4 mDNS PTR query and save the response to get the local name
        # Checking the existence of the interface
        exist_interface = Interface(interface).check_interface()
        if exist_interface:
            src_ip = get_if_addr(interface)
            if ip_address != src_ip:
                src_mac = get_if_hwaddr(interface)
                # Define the IPv4 address to query
                query = reverse_IPadd(ip_address)
                pkt = []
                pkt.append(PrototypeIPv4Packet.get_frame_mdns_ptr(src_mac, src_ip, query))
                pkt.append(PrototypeIPv4Packet.get_frame_mdns_ptr(src_mac, src_ip, query, unicastresponse=1))
                # Send the mDNS packet
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
    def send_mDNS_ipv4(query_name: str, interface: str) -> None:
        # Function to send an IPv4 mDNS query after getting the name
        # Checking the existence of the interface
        exist_interface = Interface(interface).check_interface()
        if exist_interface:
            src_ip = get_if_addr(interface)
            src_mac = get_if_hwaddr(interface)
            # Create the IPv4 and UDP packets and send the mDNS query
            query_name = MDNS.full_name_MDNS(query_name)
            pkt = PrototypeIPv4Packet.get_frame_mdns_bundle_a_aaaa_any(src_mac, src_ip, query_name)
            pkt.extend(PrototypeIPv4Packet.get_frame_mdns_bundle_a_aaaa_any(src_mac, src_ip, query_name, unicastresponse=1))
            sendp(pkt, iface=interface, verbose=False)

    @staticmethod
    def send_reverse_ipv4_llmnr(ip_address: str, interface: str) -> str | None:
        # Function to send an IPv4 LLMNR PTR query and save the response to get the local name
        # Checking the existence of the interface
        exist_interface = Interface(interface).check_interface()
        if exist_interface:
            src_ip = get_if_addr(interface)
            if ip_address != src_ip:
                src_mac = get_if_hwaddr(interface)
                # Define the IPv4 address to query
                query = reverse_IPadd(ip_address)
                # Create an LLMNR PTR query packet
                pkt = PrototypeIPv4Packet.get_frame_llmnr_ptr(src_mac, src_ip, query)
                response = AsyncSniffer(iface=interface)
                response.start()
                time.sleep(0.1)
                sendp(pkt, iface=interface, verbose=False)
                time.sleep(0.5)
                # Parse the domain name from the response
                response.stop()

                for packet in response.results:
                    if packet.haslayer(UDP) and packet.haslayer(LLMNRResponse) and packet[DNSRR].rrname.decode("utf-8")[:-1] == query:
                        return packet[DNSRR].rdata.decode("utf-8")

    @staticmethod
    def send_llmnr_ipv4(name: str, interface: str) -> None:
        # Checking the existence of the interface
        exist_interface = Interface(interface).check_interface()
        if exist_interface:
            src_ip = get_if_addr(interface)
            src_mac = get_if_hwaddr(interface)
            # Create the IPv4 and UDP packets and send the LLMNR query
            name = LLMNR.full_name_llmnr(name)
            pkt = PrototypeIPv4Packet.get_frame_llmnr_bundle_a_aaaa_any(src_mac, src_ip, name)
            sendp(pkt, iface=interface, verbose=False)

    @staticmethod
    def IPv4_test_mdns_llmnr(ip_address: str, interface: str) -> None:
        # This function runs various tests on an IPv4 address, including reverse LLMNR, mDNS, and regular LLMNR
        if get_if_addr(interface) == "0.0.0.0":
            return
        name = SendIPv4.send_reverse_ipv4_llmnr(ip_address, interface)

        if name is not None and name.strip():
            SendIPv4.send_mDNS_ipv4(name, interface)
            SendIPv4.send_llmnr_ipv4(name, interface)
            return
        name = SendIPv4.send_reverse_ipv4_MDNS(ip_address, interface)

        if name is not None and name.strip():
            SendIPv4.send_mDNS_ipv4(name, interface)
            SendIPv4.send_llmnr_ipv4(name, interface)
            return

    @staticmethod
    def send_arp_request(address: str, interface: str, wait_for_rsp: bool = False, rsp_timeout: float = 0.1) -> None | SndRcvList:
        """
        Send an ARP request to an IPv4 address.

        Args:
            address (str): The IPv4 address
            interface (str): The network interface to use
            wait_for_rsp (bool): Whether to wait for a response. Defaults to False.
            rsp_timeout (float): Timeout for the response. Defaults to 0.1 seconds.
        """
        try:
            pkt = PrototypeIPv4Packet.get_frame_arp(address)
            if wait_for_rsp:
                return srp(pkt, iface=interface, verbose=0, timeout=rsp_timeout)[0]
            sendp(pkt, verbose=0, iface=interface)
        except Exception:
            pass

    @staticmethod
    def probe_ipv4_interesting_addresses(network: ipaddress.IPv4Network, interface: str) -> None:
        """
        Probe first and last usable IPv4 addresses in a network.

        Args:
            network (ipaddress.IPv4Network): The network to probe
            interface (str): The network interface to use
        """
        # skip if network has less than 4 addresses
        if network.num_addresses >= 4:
            # first usable address
            first_addr = network.network_address + 1
            SendIPv4.send_arp_request(str(first_addr), interface)
            # last usable address
            last_addr = network.broadcast_address - 1
            SendIPv4.send_arp_request(str(last_addr), interface)

    @staticmethod
    def send_wsdiscovery_probe(interface: str) -> None:
        """
        Send a WS-Discovery probe to the multicast address.

        Args:
            interface (str): The network interface to use
        """
        packets = []
        exist_interface = Interface(interface).check_interface()
        if exist_interface:
            src_mac = get_if_hwaddr(interface)
            ipv4_addresses = Interface(interface).get_interface_ipv4_ips()
            for source_ipv4_addr in ipv4_addresses:
                packets.append(PrototypeIPv4Packet.get_frame_wsdiscovery(src_mac, source_ipv4_addr))
            if len(packets) != 0:
                sendp(packets, verbose=0, iface=interface)

    @staticmethod
    def send_igmp_membership_query(version: int, interface: str, spec_group: str = "0.0.0.0") -> None:
        """
        Send an IGMP membership query to the multicast address.

        Args:
            version (int): The IGMP version (1, 2, or 3)
            interface (str): The network interface to use
            spec_group (str): The specific multicast group address to query. Defaults to "0.0.0.0"
        """
        exist_interface = Interface(interface).check_interface()

        if exist_interface:
            ipv4_addresses = Interface(interface).get_interface_ipv4_ips()
            src_mac = get_if_hwaddr(interface)
            for source_ipv4_addr in ipv4_addresses:
                query = PrototypeIPv4Packet.get_igmp_query_general(version, src_mac, source_ipv4_addr, spec_group)
                sendp(query*2, verbose=0, iface=interface)

    @staticmethod
    def send_igmp_report_join(interface, aggressive = False) -> None:
        exist_interface = Interface(interface).check_interface()
        if exist_interface:
            ipv4_addresses = Interface(interface).get_interface_ipv4_ips()
            src_mac = get_if_hwaddr(interface)
            if aggressive:
                igmpv3_join = PrototypeIPv4Packet.get_init_igmpv3_aggressive_mode(src_mac, ipv4_addresses)
            else:
                igmpv3_join = PrototypeIPv4Packet.get_init_igmpv3_active_mode(src_mac, ipv4_addresses)
            sendp(igmpv3_join*2, iface=interface, verbose=False)
            time.sleep(0.1)
            if aggressive:
                igmpv2_join = PrototypeIPv4Packet.get_init_igmpv2_aggressive_mode(src_mac, ipv4_addresses)
            else:
                igmpv2_join = PrototypeIPv4Packet.get_init_igmpv2_active_mode(src_mac, ipv4_addresses)
            sendp(igmpv2_join*2, iface=interface, verbose=False)

    @staticmethod
    def send_igmp_done_leave(interface, aggressive = False) -> None:
        exist_interface = Interface(interface).check_interface()
        if exist_interface:
            ipv4_addresses = Interface(interface).get_interface_ipv4_ips()
            src_mac = get_if_hwaddr(interface)
            if aggressive:
                igmpv3_leave = PrototypeIPv4Packet.get_finish_igmpv3_aggressive_mode(src_mac, ipv4_addresses)
            else:
                igmpv3_leave = PrototypeIPv4Packet.get_finish_igmpv3_active_mode(src_mac, ipv4_addresses)
            sendp(igmpv3_leave*2, iface=interface, verbose=False)
            time.sleep(0.1)
            if aggressive:
                igmpv2_leave = PrototypeIPv4Packet.get_finish_igmpv2_aggressive_mode(src_mac, ipv4_addresses)
            else:
                igmpv2_leave = PrototypeIPv4Packet.get_finish_igmpv2_active_mode(src_mac, ipv4_addresses)
            sendp(igmpv2_leave*2, iface=interface, verbose=False)

    @staticmethod
    def send_local_icmp(address: str, interface: str, icmp_type: ICMPType = ICMPType.ECHO_REQUEST) -> None:
        """
        Send an ICMP message to an IPv4 address with TTL 1.

        Args:
            address (str): The IPv4 address
            interface (str): The network interface to use
            icmp_type (ICMPType): The ICMP type. Defaults to ICMPType.ECHO_REQUEST
        """
        exist_interface = Interface(interface).check_interface()
        id_query = SendIPv4.__get_next_icmp_echo_request_id()

        if ipaddress.ip_address(address).is_multicast:
            if icmp_type == ICMPType.ROUTER_SOLICITATION:
                mac_dst_addr = "33:33:00:00:00:02"
            else:
                mac_dst_addr = "01:00:5e:00:00:01"
        else:
            mac_dst_addr = "ff:ff:ff:ff:ff:ff"

        if exist_interface:
            ipv4_addresses = Interface(interface).get_interface_ipv4_ips()

            for source_ipv4_addr in ipv4_addresses:

                mac = Ether(src=get_if_hwaddr(interface), dst=mac_dst_addr)
                ipv4_packet = IP(src=source_ipv4_addr, dst=address, ttl=1)
                icmp_packet = ICMP(id=id_query, type=icmp_type.value)

                icmp_message = mac / ipv4_packet / icmp_packet / "icmp echo request"

                sendp(icmp_message, verbose=0, iface=interface)

    @staticmethod
    def send_subnet_broadcast_icmp(interface: str, icmp_type: ICMPType = ICMPType.ECHO_REQUEST) -> None:
        """
        Send an ICMP message to the subnet broadcast address.

        Args:
            interface (str): The network interface to use
            icmp_type (ICMPType): The ICMP type. Defaults to ICMPType.ECHO_REQUEST
        """
        exist_interface = Interface(interface).check_interface()
        if exist_interface:
            for network in Networks.get_ipv4_subnets():
                SendIPv4.send_local_icmp(str(network.broadcast_address), interface, icmp_type)

    @staticmethod
    def send_dns_sd_probe(interface: str) -> None:
        """
        Send a DNS-SD general probe to the multicast address.

        Args:
            interface (str): The network interface to use
        """
        exist_interface = Interface(interface).check_interface()

        if exist_interface:
            ipv4_addresses = Interface(interface).get_interface_ipv4_ips()

            for source_ipv4_addr in ipv4_addresses:

                ether = Ether(src=get_if_hwaddr(interface))
                ipv4 = IP(src=source_ipv4_addr, dst="224.0.0.251", ttl=1)
                udp = UDP(sport=random.randint(49152, 65535), dport=5353)
                mdns = DNS(id=33, rd=1, qd=DNSQR(qname="_services._dns-sd._udp.local.", qtype="PTR"))

                dns_sd = ether / ipv4 / udp / mdns

                sendp(dns_sd, verbose=0, iface=interface)

    @staticmethod
    def send_dhcp_discover(interface: str) -> None:
        """
        Send a DHCPv4 Discovery packet.

        Args:
            interface (str): Network interface to send packet on
        """
        exist_interface = Interface(interface).check_interface()

        if exist_interface:
            # random transaction ID
            xid = random.randint(0, 0xFFFFFFFF)

            ether = Ether(src=get_if_hwaddr(interface), dst="ff:ff:ff:ff:ff:ff")
            ip = IP(src="0.0.0.0", dst="255.255.255.255")
            udp = UDP(sport=68, dport=67)

            mac_addr = uuid.getnode().to_bytes(6, byteorder='big')
            bootp = BOOTP(chaddr=mac_addr, xid=xid, flags=0x8000)

            dhcp = DHCP(options=[
                ("message-type", "discover"),
                "end"
            ])

            dhcp_discover = ether / ip / udp / bootp / dhcp
            sendp(dhcp_discover, iface=interface, verbose=0)

    def react_to_igmp_queries(mode: str, interface: str, duration: float|None, stop_event=None) -> None:
        """
        React to IGMP Membership Query packets by sending join reports.

        Behavior:
            1) Sends reports whenever an IGMP query is received.
            2) Sends watchdog periodic reports only if no report was sent in the last 10 seconds.

        Args:
            mode (str): Active mode selector ("a" or "a+").
            interface (str): Network interface to use.
            duration (float | None): Total run time in seconds; None means run indefinitely.
        Output:
            None
        """
        interval_s = 10.0
        poll_interval_s = 0.5
        local_mac = get_if_hwaddr(interface)
        # Do not transmit at responder startup; active/aggressive managers already do explicit joins.
        last_report_at = time.time()

        def send_reports() -> None:
            nonlocal last_report_at
            if mode == "a+":
                SendIPv4.send_igmp_report_join(interface, aggressive=True)
            elif mode == "a":
                SendIPv4.send_igmp_report_join(interface)
            last_report_at = time.time()

        def send_watchdog_report_if_due() -> None:
            if time.time() - last_report_at >= interval_s:
                send_reports()

        def custom_action(packet) -> None:
            if Ether in packet and packet[Ether].src == local_mac:
                return
            if (IGMP in packet and packet[IGMP].type == IGMP_Type.GROUP_MEMBERSHIP_QUERY.value) or \
               (IGMPv3 in packet and packet[IGMPv3].type == IGMP_Type.GROUP_MEMBERSHIP_QUERY.value):
                send_reports()

        build_filter = "ip"
        start_time = time.time()

        try:
            while True:
                if stop_event is not None and stop_event.is_set():
                    break

                if duration is None:
                    sniff_timeout = poll_interval_s if stop_event is not None else interval_s
                else:
                    elapsed = time.time() - start_time
                    remaining = duration - elapsed
                    if remaining <= 0:
                        break
                    sniff_timeout = min(interval_s, remaining)
                    if stop_event is not None:
                        sniff_timeout = min(sniff_timeout, poll_interval_s)

                sniff(iface=interface, filter=build_filter, prn=custom_action, timeout=sniff_timeout)

                if stop_event is not None and stop_event.is_set():
                    break

                # Re-announce only when there was no report in the last interval.
                send_watchdog_report_if_due()
        except KeyboardInterrupt:
            sys.exit(0)