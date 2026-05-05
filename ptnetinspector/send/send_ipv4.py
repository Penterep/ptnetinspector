"""IPv4 active sending primitives.

Implements Scapy-based probes for IPv4 (ICMP, mDNS/LLMNR, DHCP, IGMP, etc.)
that complement passive capture in active/aggressive modes.
"""
import ipaddress
import logging
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
from ptnetinspector.send._scapy_io import SCAPY_IO_LOCK

logger = logging.getLogger(__name__)

class ICMPType(Enum):
    ECHO_REQUEST = 8
    ROUTER_SOLICITATION = 10
    UNASSIGNED_255 = 255


class SendIPv4:
    __icmp_echo_request_sequence_number = 1
    __ipv4_burst_limit = 0

    @staticmethod
    def __effective_burst_limit(requested_limit: int | None) -> int:
        """Resolve burst limit with module default fallback."""
        effective = SendIPv4.__ipv4_burst_limit if requested_limit is None else requested_limit
        try:
            effective = int(effective)
        except (TypeError, ValueError):
            effective = 0
        return effective

    @staticmethod
    def __chunked(items: list[str], burst_limit: int):
        """Yield list chunks according to configured burst limit."""
        if burst_limit <= 0:
            if items:
                yield items
            return
        for idx in range(0, len(items), burst_limit):
            yield items[idx:idx + burst_limit]

    @staticmethod
    def __normalize_qname(value: str) -> str:
        """Normalize DNS name for tolerant reverse-query matching."""
        normalized = str(value).strip().rstrip(".").lower()
        return normalized

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
        result_map = SendIPv4.send_reverse_ipv4_MDNS_batch([str(ip_address)], interface)
        return result_map.get(str(ip_address))

    @staticmethod
    def send_reverse_ipv4_MDNS_batch(ip_addresses: list[str], interface: str, burst_limit: int | None = None, rsp_timeout: float = 0.2) -> dict[str, str | None]:
        """Send reverse mDNS PTR queries for a list of IPv4 targets."""
        result: dict[str, str | None] = {str(ip): None for ip in ip_addresses}
        if not ip_addresses:
            return result

        iface = Interface(interface)
        if not iface.check_interface():
            return result

        src_ip = get_if_addr(interface)
        src_mac = get_if_hwaddr(interface)
        interface_ip_addresses = set(iface.get_interface_ips())

        valid_targets: list[str] = []
        for target in ip_addresses:
            target_str = str(target)
            if target_str == src_ip or target_str in interface_ip_addresses:
                continue
            try:
                ipaddress.IPv4Address(target_str)
            except ipaddress.AddressValueError:
                continue
            valid_targets.append(target_str)

        if not valid_targets:
            return result

        burst = SendIPv4.__effective_burst_limit(burst_limit)
        for chunk in SendIPv4.__chunked(valid_targets, burst):
            packet_to_target: dict[str, str] = {}
            packets: list[Packet] = []
            for target in chunk:
                query = reverse_IPadd(target)
                p1 = PrototypeIPv4Packet.get_frame_mdns_ptr(src_mac, src_ip, query)
                p2 = PrototypeIPv4Packet.get_frame_mdns_ptr(src_mac, src_ip, query, unicastresponse=1)
                packets.append(p1)
                packets.append(p2)
                packet_to_target[SendIPv4.__normalize_qname(query)] = target

            with SCAPY_IO_LOCK:
                ans, _uans = srp(packets, multi=True, timeout=rsp_timeout, iface=interface, verbose=False, threaded=False)

            if not ans:
                continue

            for sent, received in ans:
                try:
                    query_name = SendIPv4.__normalize_qname(sent[DNS].qd.qname.decode())
                    target = packet_to_target.get(query_name)
                    if target is None:
                        continue

                    rdata = received[DNS].an[0].rdata
                    answer = rdata.decode() if hasattr(rdata, "decode") else str(rdata)
                    if answer and result.get(target) is None:
                        result[target] = answer
                except Exception:
                    logger.debug("Failed to parse IPv4 mDNS reverse response", exc_info=True)

        return result

    @staticmethod
    def send_mDNS_ipv4(query_name: str, interface: str) -> None:
        SendIPv4.send_mDNS_ipv4_batch([query_name], interface)

    @staticmethod
    def send_mDNS_ipv4_batch(query_names: list[str], interface: str, burst_limit: int | None = None) -> None:
        """Send mDNS queries for a list of names in configurable bursts."""
        if not query_names:
            return

        iface = Interface(interface)
        if not iface.check_interface():
            return

        src_ip = get_if_addr(interface)
        src_mac = get_if_hwaddr(interface)
        burst = SendIPv4.__effective_burst_limit(burst_limit)

        for chunk in SendIPv4.__chunked([str(name) for name in query_names if str(name).strip()], burst):
            packets: list[Packet] = []
            for name in chunk:
                qname = MDNS.full_name_MDNS(name)
                packets.extend(PrototypeIPv4Packet.get_frame_mdns_bundle_a_aaaa_any(src_mac, src_ip, qname))
                packets.extend(PrototypeIPv4Packet.get_frame_mdns_bundle_a_aaaa_any(src_mac, src_ip, qname, unicastresponse=1))
            if packets:
                sendp(packets, iface=interface, verbose=False)

    @staticmethod
    def send_reverse_ipv4_llmnr(ip_address: str, interface: str) -> str | None:
        result_map = SendIPv4.send_reverse_ipv4_llmnr_batch([str(ip_address)], interface)
        return result_map.get(str(ip_address))

    @staticmethod
    def send_reverse_ipv4_llmnr_batch(ip_addresses: list[str], interface: str, burst_limit: int | None = None, rsp_timeout: float = 0.2) -> dict[str, str | None]:
        """Send reverse LLMNR PTR queries for a list of IPv4 targets."""
        result: dict[str, str | None] = {str(ip): None for ip in ip_addresses}
        if not ip_addresses:
            return result

        iface = Interface(interface)
        if not iface.check_interface():
            return result

        src_ip = get_if_addr(interface)
        src_mac = get_if_hwaddr(interface)
        interface_ip_addresses = set(iface.get_interface_ips())

        valid_targets: list[str] = []
        query_to_target: dict[str, str] = {}
        for target in ip_addresses:
            target_str = str(target)
            if target_str == src_ip or target_str in interface_ip_addresses:
                continue
            try:
                ipaddress.IPv4Address(target_str)
            except ipaddress.AddressValueError:
                continue
            query = reverse_IPadd(target_str)
            valid_targets.append(target_str)
            query_to_target[SendIPv4.__normalize_qname(query)] = target_str

        if not valid_targets:
            return result

        burst = SendIPv4.__effective_burst_limit(burst_limit)
        for chunk in SendIPv4.__chunked(valid_targets, burst):
            packets: list[Packet] = []
            for target in chunk:
                packets.append(PrototypeIPv4Packet.get_frame_llmnr_ptr(src_mac, src_ip, reverse_IPadd(target)))

            response = AsyncSniffer(iface=interface)
            response.start()
            time.sleep(0.05)
            sendp(packets, iface=interface, verbose=False)
            time.sleep(rsp_timeout)
            response.stop()

            for packet in response.results:
                try:
                    if not (packet.haslayer(UDP) and packet.haslayer(LLMNRResponse) and packet.haslayer(DNSRR)):
                        continue
                    rrname = SendIPv4.__normalize_qname(packet[DNSRR].rrname.decode("utf-8"))
                    target = query_to_target.get(rrname)
                    if target is None:
                        continue
                    answer = packet[DNSRR].rdata.decode("utf-8")
                    if answer and result.get(target) is None:
                        result[target] = answer
                except Exception:
                    logger.debug("Failed to parse IPv4 LLMNR reverse response", exc_info=True)

        return result

    @staticmethod
    def send_llmnr_ipv4(name: str, interface: str) -> None:
        SendIPv4.send_llmnr_ipv4_batch([name], interface)

    @staticmethod
    def send_llmnr_ipv4_batch(names: list[str], interface: str, burst_limit: int | None = None) -> None:
        """Send LLMNR queries for a list of names in configurable bursts."""
        if not names:
            return

        iface = Interface(interface)
        if not iface.check_interface():
            return

        src_ip = get_if_addr(interface)
        src_mac = get_if_hwaddr(interface)
        burst = SendIPv4.__effective_burst_limit(burst_limit)

        for chunk in SendIPv4.__chunked([str(name) for name in names if str(name).strip()], burst):
            packets: list[Packet] = []
            for name in chunk:
                qname = LLMNR.full_name_llmnr(name)
                packets.extend(PrototypeIPv4Packet.get_frame_llmnr_bundle_a_aaaa_any(src_mac, src_ip, qname))
            if packets:
                sendp(packets, iface=interface, verbose=False)

    @staticmethod
    def IPv4_test_mdns_llmnr(ip_address: str, interface: str) -> None:
        SendIPv4.IPv4_test_mdns_llmnr_batch([str(ip_address)], interface)

    @staticmethod
    def IPv4_test_mdns_llmnr_batch(ip_addresses: list[str], interface: str, burst_limit: int | None = None) -> dict[str, str | None]:
        """Batch coordinator for reverse LLMNR/mDNS and follow-up forward queries."""
        result: dict[str, str | None] = {str(ip): None for ip in ip_addresses}
        if not ip_addresses:
            return result

        if get_if_addr(interface) == "0.0.0.0":
            return result

        llmnr_map = SendIPv4.send_reverse_ipv4_llmnr_batch(ip_addresses, interface, burst_limit=burst_limit)
        result.update(llmnr_map)

        unresolved = [ip for ip, name in result.items() if not name]
        if unresolved:
            mdns_map = SendIPv4.send_reverse_ipv4_MDNS_batch(unresolved, interface, burst_limit=burst_limit)
            for ip, name in mdns_map.items():
                if name:
                    result[ip] = name

        discovered_names = sorted({name for name in result.values() if isinstance(name, str) and name.strip()})
        if discovered_names:
            SendIPv4.send_mDNS_ipv4_batch(discovered_names, interface, burst_limit=burst_limit)
            SendIPv4.send_llmnr_ipv4_batch(discovered_names, interface, burst_limit=burst_limit)

        return result

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
                with SCAPY_IO_LOCK:
                    return srp(pkt, iface=interface, verbose=0, timeout=rsp_timeout, threaded=False)[0]
            sendp(pkt, verbose=0, iface=interface)
        except Exception as ex:
            logger.debug("IPv4 ARP probe failed for %s on %s: %s", address, interface, ex)

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
            SendIPv4.send_arp_request(str(network.network_address), interface)
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
            packets = []
            for source_ipv4_addr in ipv4_addresses:
                packets.append(PrototypeIPv4Packet.get_igmp_query_general(version, src_mac, source_ipv4_addr, spec_group))
            if packets:
                sendp(packets*2, verbose=0, iface=interface)

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
            packets = []
            for source_ipv4_addr in ipv4_addresses:

                mac = Ether(src=get_if_hwaddr(interface), dst=mac_dst_addr)
                ipv4_packet = IP(src=source_ipv4_addr, dst=address, ttl=1)
                icmp_packet = ICMP(id=id_query, type=icmp_type.value)

                icmp_message = mac / ipv4_packet / icmp_packet / "icmp echo request"
                packets.append(icmp_message)
            if packets:
                sendp(packets, verbose=0, iface=interface)

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
            packets = []
            for source_ipv4_addr in ipv4_addresses:

                ether = Ether(src=get_if_hwaddr(interface))
                ipv4 = IP(src=source_ipv4_addr, dst="224.0.0.251", ttl=1)
                udp = UDP(sport=random.randint(49152, 65535), dport=5353)
                mdns = DNS(id=33, rd=1, qd=DNSQR(qname="_services._dns-sd._udp.local.", qtype="PTR"))

                dns_sd = ether / ipv4 / udp / mdns
                packets.append(dns_sd)
            if packets:
                sendp(packets, verbose=0, iface=interface)

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