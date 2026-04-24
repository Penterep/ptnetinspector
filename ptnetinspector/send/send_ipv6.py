"""IPv6 active sending primitives.

Implements Scapy-based probes for IPv6 (ICMPv6, RA/RS, mDNS/LLMNR, DHCPv6,
MLD/Multicast, etc.) that complement passive capture in active/aggressive modes.
"""
import ipaddress
import csv
import time
import sys
import logging

from scapy.all import *
from scapy.layers.dns import DNS, DNSRR
from scapy.layers.inet import UDP
from scapy.layers.inet6 import IPv6, ICMPv6ND_NS, ICMPv6NDOptSrcLLAddr, ICMPv6ND_RS, ICMPv6MLQuery, ICMPv6MLQuery2
from scapy.layers.l2 import Ether
from scapy.layers.llmnr import LLMNRResponse

from ptnetinspector.utils.interface import Interface
from ptnetinspector.entities.mdns import MDNS
from ptnetinspector.entities.llmnr import LLMNR
from ptnetinspector.utils.ip_utils import is_global_unicast_ipv6, has_additional_data
from ptnetinspector.utils.ip_utils import generate_global_ipv6, generate_random_global_ipv6, collect_unique_items
from ptnetinspector.utils.path import get_csv_path
from ptnetinspector.utils.ip_utils import reverse_IPadd
from ptnetinspector.prototype.prototype_ipv6 import PrototypeIPv6Packet, MLDV2_RType
from ptnetinspector.prototype.prototype_l4 import PrototypeL4
from ptnetinspector.utils.ip_utils import send_ipv6_all_nodes_multicast, send_ipv6_all_routers_multicast, send_ipv6_from_all_addresses, send_ipv6_from_all_lla_addresses
from ptnetinspector.send._scapy_io import SCAPY_IO_LOCK

logger = logging.getLogger(__name__)

class SendIPv6:
    __icmpv6_echo_request_sequence_number = 1
    __ipv6_burst_limit = 0

    @staticmethod
    def __effective_burst_limit(requested_limit: int | None) -> int:
        """Resolve effective query burst limit.

        Priority:
        1) Caller-provided limit.
        2) Module constant.

        Returns:
            int: >0 chunk size, <=0 means no chunking.
        """
        if requested_limit is None:
            return SendIPv6.__ipv6_burst_limit
        return requested_limit

    @staticmethod
    def __chunked(items: list, burst_limit: int) -> list[list]:
        """Split items into chunks when a positive burst limit is configured."""
        if burst_limit <= 0 or len(items) <= burst_limit:
            return [items]
        return [items[i:i + burst_limit] for i in range(0, len(items), burst_limit)]

    @staticmethod
    def __normalize_qname(value: str) -> str:
        """Normalize DNS-style names for robust matching."""
        return str(value).strip().rstrip('.').lower()
    @staticmethod
    def __get_next_icmpv6_echo_request_id() -> int:
        """
        Get the next ICMPv6 Echo Request identifier, incrementing the internal sequence number.
        Returns:
            int: The next ICMPv6 Echo Request identifier.
        """
        current_id = SendIPv6.__icmpv6_echo_request_sequence_number
        SendIPv6.__icmpv6_echo_request_sequence_number += 1
        return current_id

    @staticmethod
    def send_empty_ipv6_hbh(interface: str) -> None:
        """
        Send an empty IPv6 packet with a Hop-by-Hop option to ff02::1.
        Args:
            interface (str): Network interface to use.
        Output:
            None
        """
        send_ipv6_all_nodes_multicast(interface, 
            PrototypeIPv6Packet.get_l3payload_empty_hop_by_hop(multicast=True))

    @staticmethod
    def send_empty_ipv6_dest_opt(interface: str) -> None:
        """
        Send an empty IPv6 packet with a Destination option to ff02::1.
        Args:
            interface (str): Network interface to use.
        Output:
            None
        """
        send_ipv6_all_nodes_multicast(interface, 
            PrototypeIPv6Packet.get_l3payload_empty_destination_option(multicast=True))

    @staticmethod
    def send_normal_multicast_ping(interface: str) -> None:
        """
        Send a standard IPv6 multicast ping (Echo Request) to ff02::1.
        Args:
            interface (str): Network interface to use.
        Output:
            None
        """
        send_ipv6_all_nodes_multicast(interface, 
            PrototypeIPv6Packet.get_l3payload_icmpv6_echo_request(
                id=SendIPv6.__get_next_icmpv6_echo_request_id()))

    @staticmethod
    def send_invalid_multicast_icmpv6(interface: str) -> None:
        """
        Send an invalid ICMPv6 multicast packet to ff02::1.
        Args:
            interface (str): Network interface to use.
        Output:
            None
        """
        send_ipv6_all_nodes_multicast(interface, 
            PrototypeIPv6Packet.get_l3payload_invalid_icmpv6_with_dest_opt(
                id=SendIPv6.__get_next_icmpv6_echo_request_id(), multicast=True))

    @staticmethod
    def send_invalid_multicast_ping(interface: str) -> None:
        """
        Send an invalid IPv6 multicast ping to ff02::1.
        Args:
            interface (str): Network interface to use.
        Output:
            None
        """
        send_ipv6_all_nodes_multicast(interface, 
            PrototypeIPv6Packet.get_l3payload_icmpv6_echo_request_with_dest_opt(
                id=SendIPv6.__get_next_icmpv6_echo_request_id(), multicast=True))

    @staticmethod
    def send_invalid_ipv6_hbh(interface: str) -> None:
        """
        Send an invalid IPv6 Hop-by-Hop packet to ff02::1.
        Args:
            interface (str): Network interface to use.
        Output:
            None
        """
        send_ipv6_all_nodes_multicast(interface,
            PrototypeIPv6Packet.get_l3payload_icmpv6_echo_request_with_hop_by_hop_opt(
                id=SendIPv6.__get_next_icmpv6_echo_request_id(), multicast=True))

    @staticmethod
    def send_multicast_ping_router(interface: str) -> None:
        """
        Send an IPv6 ping to the router multicast address ff02::2.
        Args:
            interface (str): Network interface to use.
        Output:
            None
        """
        send_ipv6_all_routers_multicast(interface,
            PrototypeIPv6Packet.get_l3payload_icmpv6_echo_request(
                id=SendIPv6.__get_next_icmpv6_echo_request_id()
            ))

    @staticmethod
    def send_ns_router(ipv6_address: str, mac: str, interface: str) -> None:
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
    def send_reverse_ipv6_MDNS(ipv6_address: str, interface: str) -> str | None:
        """
        Send an IPv6 mDNS PTR query and return the local name if found.
        Args:
            ipv6_address (str): Target IPv6 address.
            interface (str): Network interface to use.
        Output:
            str | None: Local name if found, else None.
        """
        result_map = SendIPv6.send_reverse_ipv6_MDNS_batch([str(ipv6_address)], interface)
        return result_map.get(str(ipv6_address))

    @staticmethod
    def send_reverse_ipv6_MDNS_batch(ipv6_addresses: list[str], interface: str, burst_limit: int | None = None, rsp_timeout: float = 0.3) -> dict[str, str | None]:
        """Send reverse mDNS PTR queries for a list of IPv6 targets.

        Args:
            ipv6_addresses (list[str]): Target IPv6 addresses.
            interface (str): Network interface to use.
            burst_limit (int | None): Optional query batch size. <=0 sends all at once.
            rsp_timeout (float): Response timeout in seconds.

        Returns:
            dict[str, str | None]: Mapping target IPv6 -> discovered name (or None).
        """
        result: dict[str, str | None] = {str(ip): None for ip in ipv6_addresses}
        if not ipv6_addresses:
            return result

        iface = Interface(interface)
        if not iface.check_interface() or not iface.check_available_ipv6():
            return result

        src_mac = get_if_hwaddr(interface)
        src_ip = iface.get_interface_link_local_list()
        interface_ip_addresses = set(iface.get_interface_ips())
        try:
            local_prefix_candidate = src_ip[:-5]
        except Exception:
            local_prefix_candidate = ""

        valid_targets: list[str] = []
        target_query_map: dict[str, str] = {}
        for target in ipv6_addresses:
            target_str = str(target)
            if target_str in interface_ip_addresses or target_str == local_prefix_candidate:
                continue
            try:
                ipaddress.IPv6Address(target_str)
            except ipaddress.AddressValueError:
                continue
            query = reverse_IPadd(target_str)
            valid_targets.append(target_str)
            target_query_map[target_str] = SendIPv6.__normalize_qname(query)

        if not valid_targets:
            return result

        burst = SendIPv6.__effective_burst_limit(burst_limit)
        for chunk in SendIPv6.__chunked(valid_targets, burst):
            packet_to_target: dict[str, str] = {}
            packets: list[Packet] = []
            for target in chunk:
                query = reverse_IPadd(target)
                p1 = PrototypeIPv6Packet.get_frame_mdns_ptr(src_mac, src_ip, query)
                p2 = PrototypeIPv6Packet.get_frame_mdns_ptr(src_mac, src_ip, query, unicastresponse=1)
                packets.append(p1)
                packets.append(p2)
                packet_to_target[query] = target

            with SCAPY_IO_LOCK:
                ans, _uans = srp(packets, multi=True, timeout=rsp_timeout, iface=interface, verbose=False, threaded=False)

            if not ans:
                continue

            for sent, received in ans:
                try:
                    query_name = SendIPv6.__normalize_qname(sent[DNS].qd.qname.decode())
                except Exception:
                    continue

                target = None
                for candidate_query, candidate_target in packet_to_target.items():
                    if SendIPv6.__normalize_qname(candidate_query) == query_name:
                        target = candidate_target
                        break
                if target is None:
                    continue

                try:
                    rdata = received[DNS].an[0].rdata
                    answer = rdata.decode() if hasattr(rdata, "decode") else str(rdata)
                    if answer and result.get(target) is None:
                        result[target] = answer
                except Exception:
                    logger.debug("Failed to parse IPv6 mDNS response for %s", target, exc_info=True)

        return result

    @staticmethod
    def send_mDNS_ipv6(query_name: str, interface: str) -> None:
        """
        Send an IPv6 mDNS query for the given name.
        Args:
            query_name (str): Name to query.
            interface (str): Network interface to use.
        Output:
            None
        """
        SendIPv6.send_mDNS_ipv6_batch([query_name], interface)

    @staticmethod
    def send_mDNS_ipv6_batch(query_names: list[str], interface: str, burst_limit: int | None = None) -> None:
        """Send mDNS queries for a list of names in configurable bursts."""
        if not query_names:
            return
        iface = Interface(interface)
        if not iface.check_interface() or not iface.check_available_ipv6():
            return

        src_mac = get_if_hwaddr(interface)
        src_ip = iface.get_interface_link_local_list()
        burst = SendIPv6.__effective_burst_limit(burst_limit)

        for chunk in SendIPv6.__chunked([str(name) for name in query_names if str(name).strip()], burst):
            packets: list[Packet] = []
            for name in chunk:
                qname = MDNS.full_name_MDNS(name)
                packets.extend(PrototypeIPv6Packet.get_frame_mdns_bundle_a_aaaa_any(src_mac, src_ip, qname))
                packets.extend(PrototypeIPv6Packet.get_frame_mdns_bundle_a_aaaa_any(src_mac, src_ip, qname, unicastresponse=1))
            if packets:
                sendp(packets, iface=interface, verbose=False)

    @staticmethod
    def send_reverse_ipv6_llmnr(ipv6_address: str, interface: str) -> str | None:
        """
        Send an IPv6 LLMNR PTR query and return the domain name if found.
        Args:
            ipv6_address (str): Target IPv6 address.
            interface (str): Network interface to use.
        Output:
            str | None: Domain name if found, else None.
        """
        result_map = SendIPv6.send_reverse_ipv6_llmnr_batch([str(ipv6_address)], interface)
        return result_map.get(str(ipv6_address))

    @staticmethod
    def send_reverse_ipv6_llmnr_batch(ipv6_addresses: list[str], interface: str, burst_limit: int | None = None, rsp_timeout: float = 0.2) -> dict[str, str | None]:
        """Send reverse LLMNR PTR queries for a list of IPv6 targets.

        Args:
            ipv6_addresses (list[str]): Target IPv6 addresses.
            interface (str): Network interface to use.
            burst_limit (int | None): Optional query batch size. <=0 sends all at once.

        Returns:
            dict[str, str | None]: Mapping target IPv6 -> discovered name (or None).
        """
        result: dict[str, str | None] = {str(ip): None for ip in ipv6_addresses}
        if not ipv6_addresses:
            return result

        iface = Interface(interface)
        if not iface.check_interface() or not iface.check_available_ipv6():
            return result

        src_mac = get_if_hwaddr(interface)
        src_ip = iface.get_interface_link_local_list()
        interface_ip_addresses = set(iface.get_interface_ips())
        try:
            local_prefix_candidate = src_ip[:-5]
        except Exception:
            local_prefix_candidate = ""

        valid_targets: list[str] = []
        query_to_target: dict[str, str] = {}
        for target in ipv6_addresses:
            target_str = str(target)
            if target_str in interface_ip_addresses or target_str == local_prefix_candidate:
                continue
            try:
                ipaddress.IPv6Address(target_str)
            except ipaddress.AddressValueError:
                continue
            query = reverse_IPadd(target_str)
            valid_targets.append(target_str)
            query_to_target[SendIPv6.__normalize_qname(query)] = target_str

        if not valid_targets:
            return result

        burst = SendIPv6.__effective_burst_limit(burst_limit)
        for chunk in SendIPv6.__chunked(valid_targets, burst):
            packets: list[Packet] = []
            for target in chunk:
                packets.append(PrototypeIPv6Packet.get_frame_llmnr_ptr(src_mac, src_ip, reverse_IPadd(target)))

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
                    rrname = SendIPv6.__normalize_qname(packet[DNSRR].rrname.decode("utf-8"))
                    target = query_to_target.get(rrname)
                    if target is None:
                        continue
                    answer = packet[DNSRR].rdata.decode("utf-8")
                    if answer and result.get(target) is None:
                        result[target] = answer
                except Exception:
                    logger.debug("Failed to parse IPv6 LLMNR response", exc_info=True)

        return result

    @staticmethod
    def send_llmnr_ipv6(name: str, interface: str) -> None:
        """
        Send an IPv6 LLMNR query for the given name.
        Args:
            name (str): Name to query.
            interface (str): Network interface to use.
        Output:
            None
        """
        SendIPv6.send_llmnr_ipv6_batch([name], interface)

    @staticmethod
    def send_llmnr_ipv6_batch(names: list[str], interface: str, burst_limit: int | None = None) -> None:
        """Send LLMNR queries for a list of names in configurable bursts."""
        if not names:
            return
        iface = Interface(interface)
        if not iface.check_interface() or not iface.check_available_ipv6():
            return

        src_mac = get_if_hwaddr(interface)
        src_ip = iface.get_interface_link_local_list()
        burst = SendIPv6.__effective_burst_limit(burst_limit)

        for chunk in SendIPv6.__chunked([str(name) for name in names if str(name).strip()], burst):
            packets: list[Packet] = []
            for name in chunk:
                qname = LLMNR.full_name_llmnr(name)
                packets.extend(PrototypeIPv6Packet.get_frame_llmnr_bundle_a_aaaa_any(src_mac, src_ip, qname))
            if packets:
                sendp(packets, iface=interface, verbose=False)

    @staticmethod
    def IPv6_test_mdns_llmnr(ip_address: str, interface: str) -> None:
        """
        Test mDNS and LLMNR for a given IPv6 address.
        Args:
            ip_address (str): IPv6 address to test.
            interface (str): Network interface to use.
        Output:
            None
        """
        SendIPv6.IPv6_test_mdns_llmnr_batch([str(ip_address)], interface)

    @staticmethod
    def IPv6_test_mdns_llmnr_batch(ip_addresses: list[str], interface: str, burst_limit: int | None = None) -> dict[str, str | None]:
        """Batch coordinator for reverse LLMNR/mDNS and follow-up forward queries.

        Flow:
            1) Reverse LLMNR for all targets.
            2) Reverse mDNS only for unresolved targets.
            3) Forward mDNS/LLMNR for discovered unique names.

        Returns:
            dict[str, str | None]: Mapping IPv6 target -> discovered name (if any).
        """
        result: dict[str, str | None] = {str(ip): None for ip in ip_addresses}
        if not ip_addresses:
            return result

        llmnr_map = SendIPv6.send_reverse_ipv6_llmnr_batch(ip_addresses, interface, burst_limit=burst_limit)
        result.update(llmnr_map)

        unresolved = [ip for ip, name in result.items() if not name]
        if unresolved:
            mdns_map = SendIPv6.send_reverse_ipv6_MDNS_batch(unresolved, interface, burst_limit=burst_limit)
            for ip, name in mdns_map.items():
                if name:
                    result[ip] = name

        discovered_names = sorted({name for name in result.values() if isinstance(name, str) and name.strip()})
        if discovered_names:
            SendIPv6.send_mDNS_ipv6_batch(discovered_names, interface, burst_limit=burst_limit)
            SendIPv6.send_llmnr_ipv6_batch(discovered_names, interface, burst_limit=burst_limit)

        return result

    @staticmethod
    def send_MLD_query(interface: str) -> None:
        """
        Send MLD query packets to IPv6 multicast address.
        Args:
            interface (str): Network interface to use.
        Output:
            None
        """
        exist_interface = Interface(interface).check_interface()
        if exist_interface:
            avail_ipv6 = Interface(interface).check_available_ipv6()
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
    def send_MLD_report_join(interface: str, aggressive: bool = False) -> None:
        """
        Send MLD report packets to join multicast groups, optionally for aggressive mode.
        Args:
            interface (str): Network interface to use.
            aggressive (bool): Whether to use aggressive mode.
        Output:
            None
        """
        exist_interface = Interface(interface).check_interface()
        if exist_interface:
            avail_ipv6 = Interface(interface).check_available_ipv6()
            if avail_ipv6:
                src_mac = get_if_hwaddr(interface)
                ip_lla = Interface(interface).get_interface_link_local_list()
                if aggressive:
                    mldv2_join = PrototypeIPv6Packet.get_init_mldv2_aggressive_mode(src_mac, ip_lla)
                else:
                    mldv2_join = PrototypeIPv6Packet.get_init_mldv2_active_mode(src_mac, ip_lla)
                sendp(mldv2_join*2, iface=interface, verbose=False)
                time.sleep(0.1)
                if aggressive:
                    mldv1_report = PrototypeIPv6Packet.get_init_mldv1_aggressive_mode(src_mac, ip_lla)
                else:
                    mldv1_report = PrototypeIPv6Packet.get_init_mldv1_active_mode(src_mac, ip_lla)
                sendp(mldv1_report*2, iface=interface, verbose=False)

    @staticmethod
    def send_MLD_done_leave(interface: str, aggressive: bool = False) -> None:
        """
        Send MLD done/leave packets to leave multicast groups, optionally for aggressive mode.
        Args:
            interface (str): Network interface to use.
            aggressive (bool): Whether to use aggressive mode.
        Output:
            None
        """
        exist_interface = Interface(interface).check_interface()
        if exist_interface:
            avail_ipv6 = Interface(interface).check_available_ipv6()
            if avail_ipv6:
                src_mac = get_if_hwaddr(interface)
                ip_lla = Interface(interface).get_interface_link_local_list()
                if aggressive:
                    mldv2_leave = PrototypeIPv6Packet.get_finish_mldv2_aggressive_mode(src_mac, ip_lla)
                else:
                    mldv2_leave = PrototypeIPv6Packet.get_finish_mldv2_active_mode(src_mac, ip_lla)
                sendp(mldv2_leave*2, iface=interface, verbose=False)
                time.sleep(0.1)
                if aggressive:
                    mldv1_done = PrototypeIPv6Packet.get_finish_mldv1_aggressive_mode(src_mac, ip_lla)
                else:
                    mldv1_done = PrototypeIPv6Packet.get_finish_mldv1_active_mode(src_mac, ip_lla)
                sendp(mldv1_done*2, iface=interface, verbose=False)

    @staticmethod
    def send_RS(interface: str) -> None:
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
    def send_RA(interface: str, prefix_len: int, network: str, source_mac: str, source_ip: str, rpref: int, chl: int, mtu: int, dns: list[str]|None, aggressive_mode: bool, period: float|None, duration: float) -> None:
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
            packet1 = PrototypeIPv6Packet.get_frame_ra(prefix_len, network, source_mac, source_ip, rpref, chl, mtu, dns)
            if aggressive_mode and period is not None:
                kill_packet1 = PrototypeIPv6Packet.get_frame_ra_kill(prefix_len, network, source_mac, source_ip, rpref, chl, dns)
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
    def send_to_possible_IP(interface: str) -> None:
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
        iface = Interface(interface)
        if not iface.check_interface() or not iface.check_available_ipv6():
            return

        src_mac = get_if_hwaddr(interface)
        src_ipv6 = []
        for ip in iface.get_interface_ips():
            try:
                src_ipv6.append(str(ipaddress.IPv6Address(ip)))
            except ipaddress.AddressValueError:
                # Ignore non-IPv6 interface entries while building IPv6 source list.
                continue

        if not src_ipv6:
            return

        all_packets = []
        for mac, ips in possible_global_IP.items():
            if not ips:
                continue

            valid_dst_ips = []
            for ip in ips:
                try:
                    valid_dst_ips.append(str(ipaddress.IPv6Address(ip)))
                except ipaddress.AddressValueError:
                    # Ignore malformed candidate addresses from generated target lists.
                    continue

            if not valid_dst_ips:
                continue

            payloads = [
                PrototypeIPv6Packet.get_l3payload_icmpv6_echo_request(
                    id=SendIPv6.__get_next_icmpv6_echo_request_id()
                ),
                PrototypeIPv6Packet.get_l3payload_empty_destination_option(multicast=False),
                PrototypeIPv6Packet.get_l3payload_empty_hop_by_hop(multicast=False),
                PrototypeIPv6Packet.get_l3payload_icmpv6_echo_request(
                    id=SendIPv6.__get_next_icmpv6_echo_request_id()
                ),
                PrototypeIPv6Packet.get_l3payload_invalid_icmpv6_with_dest_opt(
                    id=SendIPv6.__get_next_icmpv6_echo_request_id(), multicast=False
                ),
                PrototypeIPv6Packet.get_l3payload_icmpv6_echo_request_with_dest_opt(
                    id=SendIPv6.__get_next_icmpv6_echo_request_id(), multicast=False
                ),
                PrototypeIPv6Packet.get_l3payload_icmpv6_echo_request_with_hop_by_hop_opt(
                    id=SendIPv6.__get_next_icmpv6_echo_request_id(), multicast=False
                ),
            ]

            for payload in payloads:
                for src_ip in src_ipv6:
                    for dst_ip in valid_dst_ips:
                        all_packets.append(
                            Ether(src=src_mac, dst=mac) /
                            IPv6(src=src_ip, dst=dst_ip) /
                            payload
                        )

        if all_packets:
            sendp(all_packets, iface=interface, verbose=False)

        discovery_targets: list[str] = []
        for _mac, ips in possible_global_IP.items():
            if ips:
                for dst_ip in ips:
                    try:
                        discovery_targets.append(str(ipaddress.IPv6Address(dst_ip)))
                    except ipaddress.AddressValueError:
                        # Skip non-IPv6 generated target candidates.
                        continue
        if discovery_targets:
            SendIPv6.IPv6_test_mdns_llmnr_batch(discovery_targets, interface)

    @staticmethod
    def send_NA(interface: str, source_mac: str, target_mac: str, source_ip: str, target_ip: str, r_flag: int, s_flag: int, o_flag: int) -> None:
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
            packet1 = PrototypeIPv6Packet.get_frame_na(source_mac, target_mac, source_ip, target_ip, r_flag, s_flag, o_flag)
            sendp(packet1, verbose=False, iface=interface)

    @staticmethod
    def react_to_NS_RS(interface: str, prefix_len: int, network: str, source_mac: str, source_ip: str, rpref: int, chl: int, mtu: int, dns: list[str]|None, duration: float|None) -> None:
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
    def send_to_test_RA_guard(interface: str) -> None:
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
                    # Ignore non-IPv6 rows in shared addresses.csv input.
                    pass
        if exist_interface:
            src_mac = get_if_hwaddr(interface)
            dest_ip_list = collect_unique_items(mac_ips_global)
            sip = generate_random_global_ipv6(dest_ip_list)
            layer2 = Ether(src=src_mac)
            for mac, ips in mac_ips_global.items():
                if ips != []:
                    layer3 = IPv6(src=sip, dst=ips)                    
                    multicast_ping = (layer2 / layer3 / 
                        PrototypeIPv6Packet.get_l3payload_icmpv6_echo_request(
                            id=SendIPv6.__get_next_icmpv6_echo_request_id()
                        ))
                    empty_dest_opt = (layer2 / layer3 / 
                        PrototypeIPv6Packet.get_l3payload_empty_destination_option(multicast=False))
                    empty_hop_by_hop_opt = (layer2 / layer3 / 
                        PrototypeIPv6Packet.get_l3payload_empty_hop_by_hop(multicast=False))
                    invalid = (layer2 / layer3 / 
                        PrototypeIPv6Packet.get_l3payload_invalid_icmpv6_with_dest_opt(
                            id=SendIPv6.__get_next_icmpv6_echo_request_id(),
                            multicast=False
                        ))
                    multicast_ping_dest_opt = (layer2 / layer3 / 
                        PrototypeIPv6Packet.get_l3payload_icmpv6_echo_request_with_dest_opt(
                            id=SendIPv6.__get_next_icmpv6_echo_request_id(),
                            multicast=False
                        ))
                    multicast_ping_hop_by_hop_opt = (layer2 / layer3 / 
                        PrototypeIPv6Packet.get_l3payload_icmpv6_echo_request_with_hop_by_hop_opt(
                            id=SendIPv6.__get_next_icmpv6_echo_request_id(),
                            multicast=False
                        ))
                    sendp(multicast_ping, iface=interface, verbose=False)
                    sendp(empty_dest_opt, iface=interface, verbose=False)
                    sendp(empty_hop_by_hop_opt, iface=interface, verbose=False)
                    sendp(invalid, iface=interface, verbose=False)
                    sendp(multicast_ping_dest_opt, iface=interface, verbose=False)
                    sendp(multicast_ping_hop_by_hop_opt, iface=interface, verbose=False)

    @staticmethod
    def send_ns(address: str|list[str], interface: str, wait_for_rsp: bool = False, rsp_timeout: float|None = 0.1) -> None | SndRcvList:
        """
        Send an ICMPv6 Neighbor Solicitation to an IPv6 address.
        Args:
            address (str|list[str]): The IPv6 address or list of addresses.
            interface (str): The network interface to use.
            wait_for_rsp (bool): Whether to wait for a response.
            rsp_timeout (float|None): Timeout for the response.
        Output:
            None or SndRcvList: Response if wait_for_rsp is True, else None.
        """
        exist_interface = Interface(interface).check_interface()
        if exist_interface:
            avail_ipv6 = Interface(interface).check_available_ipv6()
            if avail_ipv6:
                src_mac = get_if_hwaddr(interface)   
                pkt = PrototypeIPv6Packet.get_frame_ns(src_mac, address)
                if wait_for_rsp:
                    with SCAPY_IO_LOCK:
                        return srp(pkt * 2, iface=interface, verbose=0, timeout=rsp_timeout, threaded=False)[0]
                sendp(pkt * 2, verbose=0, iface=interface)

    @staticmethod
    def probe_ipv6_interesting_addresses(network: ipaddress.IPv6Network, interface: str, probe_bits: int = 8, batch_size: int = 64, end_wildcard: bool = False) -> None:
        """
        Probe ::0 and ::1 addresses in IPv6 network.
        Args:
            network (ipaddress.IPv6Network): The network to probe.
            interface (str): The network interface to use.
            probe_bits (int): Number of low bits to brute-force from the network start.
            batch_size (int): Number of NS probes sent per batch.
            end_wildcard (bool): Whether to also brute-force low bits from the network end.
        Output:
            None
        """
        try:            
            IPV6_PROBE_MAX_TARGETS = 1024
            if batch_size <= 0:
                raise ValueError("batch_size must be > 0")

            def iter_probe_addresses_from_low_bits(network: ipaddress.IPv6Network, low_bits: int):
                host_bits = 128 - network.prefixlen

                if low_bits < 0:
                    raise ValueError("low_bits musí být >= 0")
                # Treat probe_bits as a maximum; clamp for narrow prefixes (e.g. /128).
                effective_low_bits = min(low_bits, host_bits)

                total = 1 << effective_low_bits
                total = min(total, IPV6_PROBE_MAX_TARGETS)

                base = int(network.network_address)
                for i in range(total):
                    yield ipaddress.IPv6Address(base | i)

            def iter_probe_addresses_from_end_bits(network: ipaddress.IPv6Network, low_bits: int):
                host_bits = 128 - network.prefixlen

                if low_bits < 0:
                    raise ValueError("low_bits musí být >= 0")
                effective_low_bits = min(low_bits, host_bits)

                total = 1 << effective_low_bits
                total = min(total, IPV6_PROBE_MAX_TARGETS)

                end = int(network.broadcast_address)
                start = end - (total - 1)
                for value in range(start, end + 1):
                    yield ipaddress.IPv6Address(value)

            def send_ns_batched(addresses: list[str]) -> None:
                for idx in range(0, len(addresses), batch_size):
                    SendIPv6.send_ns(addresses[idx:idx + batch_size], interface)

            network_targets: list[str] = []
            seen_targets: set[str] = set()

            def add_target(address: ipaddress.IPv6Address) -> None:
                address_str = str(address)
                if address_str not in seen_targets:
                    seen_targets.add(address_str)
                    network_targets.append(address_str)

            for addr in iter_probe_addresses_from_low_bits(network, probe_bits):
                if not addr in network:
                    break
                add_target(addr)

            add_target(network.broadcast_address)

            if end_wildcard:
                for addr in iter_probe_addresses_from_end_bits(network, probe_bits):
                    if not addr in network:
                        break
                    add_target(addr)

            if network_targets:
                send_ns_batched(network_targets)
            return
        except Exception as ex:
            logger.debug("IPv6 interesting-address probe failed for network %s: %s", network, ex)
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
        packets = []
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
                        # Not IPv4, keep testing as IPv6 candidate.
                        pass
                    try:
                        ipaddress.IPv6Address(ip)
                        src_ip = ip
                        packets.append(PrototypeIPv6Packet.get_frame_wsdiscovery(src_mac, src_ip))
                    except ipaddress.AddressValueError:
                        # Skip malformed interface address entries.
                        pass
                if len(packets) != 0:
                    sendp(packets, iface=interface, verbose=False)

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
            avail_ipv6 = Interface(interface).check_available_ipv6()
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
            PrototypeIPv6Packet.get_l3payload_dhcpv6_solicit(get_if_hwaddr(interface)), dst_ip=PrototypeIPv6Packet.DHCPV6_IPV6_MULTICAST_IPS)
        
    def react_to_mld_queries(mode: str, interface: str, duration: float|None, stop_event=None) -> None:
        """
        React to MLD Query packets by sending MLD join reports.

        Behavior:
            1) Sends reports whenever an MLD query is received.
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
                SendIPv6.send_MLD_report_join(interface, aggressive=True)
            elif mode == "a":
                SendIPv6.send_MLD_report_join(interface)
            last_report_at = time.time()

        def send_watchdog_report_if_due() -> None:
            if time.time() - last_report_at >= interval_s:
                send_reports()

        def custom_action(packet) -> None:
            if Ether in packet and packet[Ether].src == local_mac:
                return
            if ICMPv6MLQuery in packet or ICMPv6MLQuery2 in packet:
                send_reports()

        build_filter = "ip6"
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

def generate_more_possible_IP(interface: str) -> dict | None:
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
            ip = row[ip_index].strip()
            if mac == src_mac:
                continue
            if mac not in mac_ips:
                mac_ips[mac] = []
                mac_ips_global_old[mac] = []

            # addresses.csv can naturally contain IPv4 and empty IP values;
            # these are expected here and should not spam debug output.
            if not ip or ':' not in ip:
                continue

            try:
                ip_address = ipaddress.IPv6Address(ip)
                if ip_address.is_link_local:
                    mac_ips[mac].append(ip)
                if is_global_unicast_ipv6(str(ip_address)):
                    mac_ips_global_old[mac].append(ip)
            except ValueError as ex:
                logger.debug("Skipping invalid IPv6 candidate in addresses.csv (%s): %s", ip, ex)

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