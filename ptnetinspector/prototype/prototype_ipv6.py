
from enum import IntEnum
import random
import socket
import uuid

from scapy.all import Raw, Packet
from scapy.layers.inet6 import ICMPv6MLDMultAddrRec, IPv6, ICMPv6MLQuery, ICMPv6MLReport, ICMPv6MLReport2, ICMPv6MLDone, ICMPv6EchoRequest, IPv6ExtHdrHopByHop, RouterAlert, IPv6ExtHdrDestOpt, HBHOptUnknown, ICMPv6ND_NS, ICMPv6NDOptSrcLLAddr, ICMPv6ND_NA, ICMPv6MLQuery2, ICMPv6ND_RS, ICMPv6ND_RA, ICMPv6NDOptRDNSS, ICMPv6NDOptMTU, ICMPv6NDOptPrefixInfo, ICMPv6NDOptDstLLAddr
from scapy.layers.inet import UDP
from scapy.layers.l2 import Ether
from scapy.layers.dhcp6 import DUID_LL, DHCP6OptElapsedTime, DHCP6OptIA_NA, DHCP6OptClientId, DHCP6_Solicit
from scapy.layers.llmnr import LLMNRQuery
from scapy.layers.dns import DNS, DNSQR
from scapy.pton_ntop import inet_ntop, inet_pton
from scapy.utils6 import in6_getnsma

from ptnetinspector.prototype.prototype_l7 import *
from ptnetinspector.prototype.prototype_l4 import *

class MLDV2_RType(IntEnum):
    MODE_IS_INCLUDE = 1
    MODE_IS_EXCLUDE = 2
    CHANGE_TO_INCLUDE_MODE = 3
    CHANGE_TO_EXCLUDE_MODE = 4
    ALLOW_NEW_SOURCES = 5
    BLOCK_OLD_SOURCES = 6

class PrototypeIPv6Packet:
    # Addresses
    ALL_NODES_IPV6_MULTICAST_IP = "ff02::1"
    ALL_ROUTERS_IPV6_MULTICAST_IP = "ff02::2"
    DHCPV6_ALL_SERVERS_MULTICAST_IP = "ff02::1:2"
    LLMNR_IPV6_MULTICAST_IP = "ff02::1:3"
    MDNS_IPV6_MULTICAST_IP = "ff02::fb"
    MLDV2_IPV6_MULTICAST_IP = "ff02::16"
    WS_DISCOVERY_IPV6_MULTICAST_IP = "ff02::c"
    # Extension headers
    EXT_HDR_DESTINATION_OPTION_TYPE = 128
    EXT_HDR_DESTINATION_OPTION_DATA = b''
    EXT_HDR_HOP_BY_HOP_TYPE = 255
    EXT_HDR_HOP_BY_HOP_DATA = b"\x00\x00\x00"
    # ICMPv6
    ICMPV6_INVALID_TYPE = 254
    RA_LIFETIME = 1800

    MULTICAST_GROUPS_ACTIVE = [
        ALL_NODES_IPV6_MULTICAST_IP,
        MLDV2_IPV6_MULTICAST_IP,
        LLMNR_IPV6_MULTICAST_IP,
        MDNS_IPV6_MULTICAST_IP,
        WS_DISCOVERY_IPV6_MULTICAST_IP
    ]
    MULTICAST_GROUPS_AGGRESSIVE = [
        DHCPV6_ALL_SERVERS_MULTICAST_IP,
        ALL_ROUTERS_IPV6_MULTICAST_IP
    ]

    # 
    # L3 Payloads
    #

    @staticmethod
    def get_l3payload_empty_hop_by_hop() -> Packet:
        """
        Returns a hop-by-hop extension header with an unknown option to trigger an error response.
        Does not include L2 and L3 headers, only the hop-by-hop extension header.
        Args:
            None
        Output:
            Packet: Scapy packet representing a hop-by-hop extension header with an unknown option.
        """
        return PrototypeIPv6Packet.__get_hop_by_hop_option()

    @staticmethod
    def get_l3payload_empty_destination_option() -> Packet:
        """
        Returns a destination extension header with an unknown option to trigger an error response.
        Does not include L2 and L3 headers, only the destination extension header.
        Args:
            None
        Output:
            Packet: Scapy packet representing a destination extension header with an unknown option.
        """
        return PrototypeIPv6Packet.__get_destination_option()

    @staticmethod
    def get_l3payload_icmpv6_echo_request(id: int=0) -> Packet:
        """
        Returns ICMPv6 Echo Request packet with specified ID, without any extension headers.
        Does not include L2 and L3 headers, only the ICMPv6 payload.
        Args:
            id: Identifier field for the ICMPv6 Echo Request.
        Output:
            Packet: Scapy packet representing ICMPv6 Echo Request.
        """
        return ICMPv6EchoRequest(id=id)

    @staticmethod
    def get_l3payload_icmpv6_echo_request_with_dest_opt(id: int = 0) -> Packet:
        """
        Returns ICMPv6 Echo Request packet with destination option extension header.
        Does not include L2 and L3 headers, only the ICMPv6 payload with extension header.
        Args:
            id: Identifier field for the ICMPv6 Echo Request.
        Output:
            Packet: Scapy packet representing ICMPv6 Echo Request with destination option.
        """
        return (PrototypeIPv6Packet.__get_destination_option() /
                ICMPv6EchoRequest(id=id))

    @staticmethod
    def get_l3payload_icmpv6_echo_request_with_hop_by_hop_opt(id: int = 0) -> Packet:
        """
        Returns ICMPv6 Echo Request packet with hop-by-hop extension header.
        Does not include L2 and L3 headers, only the ICMPv6 payload with extension header.
        Args:
            id: Identifier field for the ICMPv6 Echo Request.
        Output:
            Packet: Scapy packet representing ICMPv6 Echo Request with hop-by-hop option.
        """
        return (PrototypeIPv6Packet.__get_hop_by_hop_option() /
                ICMPv6EchoRequest(id=id))

    @staticmethod
    def get_l3payload_invalid_icmpv6_with_dest_opt(id: int = 0) -> Packet:
        """
        Returns ICMPv6 Echo Request packet with invalid type and destination option extension header.
        Does not include L2 and L3 headers, only the ICMPv6 payload with extension header.
        Args:
            id: Identifier field for the ICMPv6 Echo Request.
        Output:
            Packet: Scapy packet representing ICMPv6 Echo Request with invalid type and destination option.
        """
        return (PrototypeIPv6Packet.__get_destination_option() /
                ICMPv6EchoRequest(id=id, type=PrototypeIPv6Packet.ICMPV6_INVALID_TYPE))

    @staticmethod
    def get_l3payload_dhcpv6_solicit(src_mac: str) -> Packet:
        """
        Returns DHCPv6 Solicit packet with specified source MAC address.
        Does not include L2 and L3 headers, only the DHCPv6 payload.
        Args:
            src_mac: Source MAC address for the DHCPv6 Solicit packet.
        Output:
            Packet: Scapy packet representing DHCPv6 Solicit.
        """
        trid = random.randint(0, 0xFFFFFF)
        iaid = random.randint(0, 0xFFFFFFFF)
        duid = DUID_LL(lladdr=src_mac, type=3)
        udp = UDP(sport=546, dport=547)
        dhcpv6 = DHCP6_Solicit(trid=trid)
        client_id_opt = DHCP6OptClientId(duid=duid)
        elapsed_time_opt = DHCP6OptElapsedTime(elapsedtime=0)
        ia_na_opt = DHCP6OptIA_NA(iaid=iaid, T1=0, T2=0)
        return udp / dhcpv6 / client_id_opt / elapsed_time_opt / ia_na_opt

    # 
    # L3 Builders
    #
    @staticmethod 
    def __get_hop_by_hop_option() -> Packet:
        """
        Builds a hop-by-hop extension header with an unknown option to trigger an error response.
        Args:
            None
        Output:
            Packet: Scapy packet representing a hop-by-hop extension header with an unknown option.
        """
        return (IPv6ExtHdrHopByHop(
                    options=[HBHOptUnknown(
                        otype=PrototypeIPv6Packet.EXT_HDR_HOP_BY_HOP_TYPE, 
                        optdata=PrototypeIPv6Packet.EXT_HDR_HOP_BY_HOP_DATA)]))

    @staticmethod
    def __get_destination_option() -> Packet:
        """
        Builds a destination extension header with an unknown option to trigger an error response.
        Args:
            None
        Output:
            Packet: Scapy packet representing a destination extension header with an unknown option.
        """
        return (IPv6ExtHdrDestOpt( 
                    options=[HBHOptUnknown(
                        otype=PrototypeIPv6Packet.EXT_HDR_DESTINATION_OPTION_TYPE,
                        optdata=PrototypeIPv6Packet.EXT_HDR_DESTINATION_OPTION_DATA)]))

    @staticmethod
    def __get_mldv1_packet_headers(src_mac: str|list[str]|None, src_ip: str|list[str]|None, dst_ip: str|list[str]) -> Packet:
        """
        Builds the L2 and L3 headers for MLD packets, including the Router Alert option in the hop-by-hop extension header.
        Args:
            src_mac: Source MAC address for the MLD packet.
            src_ip: Source IPv6 address for the MLD packet.
            dst_ip: Destination IPv6 address for the MLD packet.
        Output:
            Packet: Scapy packet representing the L2 and L3 headers for MLD packets.
        """
        return (Ether(src=src_mac) /
                IPv6(src=src_ip, dst=dst_ip, hlim=1) /
                IPv6ExtHdrHopByHop(options=RouterAlert(otype=5, optlen=2, value=0)))

    @staticmethod
    def __get_mldv2_packet_headers(src_mac: str|list[str]|None, src_ip: str|list[str]|None) -> Packet:
        """
        Builds the L2 and L3 headers for MLD packets, including the Router Alert option in the hop-by-hop extension header.
        Args:
            src_mac: Source MAC address for the MLD packet.
            src_ip: Source IPv6 address for the MLD packet.
            dst_ip: Destination IPv6 address for the MLD packet.
        Output:
            Packet: Scapy packet representing the L2 and L3 headers for MLD packets.
        """
        return (Ether(src=src_mac) /
                IPv6(src=src_ip, dst=PrototypeIPv6Packet.MLDV2_IPV6_MULTICAST_IP, hlim=1) /
                IPv6ExtHdrHopByHop(options=RouterAlert(otype=5, optlen=2, value=0)))

    @staticmethod
    def __get_mldv1_report(src_mac: str|list[str]|None, src_ip: str|list[str]|None, group: str) -> Packet:
        """
        Builds an MLDv1 Report packet for the specified multicast group, with appropriate L2 and L3 headers.
        Args:
            src_mac: Source MAC address for the MLDv1 Report packet.
            src_ip: Source IPv6 address for the MLDv1 Report packet.
            group: The multicast group address to report membership for.
        Output:
            Packet: Scapy packet representing the MLDv1 Report for the specified multicast group.
        """
        return (PrototypeIPv6Packet.__get_mldv1_packet_headers(src_mac, src_ip, group) /
                ICMPv6MLReport(mrd=1, mladdr=group))

    @staticmethod
    def __get_mldv1_done(src_mac: str|list[str]|None, src_ip: str|list[str]|None, group: str) -> Packet:
        """
        Builds an MLDv1 Done packet for the specified multicast group, with appropriate L2 and L3 headers.
        Args:
            src_mac: Source MAC address for the MLDv1 Done packet.
            src_ip: Source IPv6 address for the MLDv1 Done packet.
            group: The multicast group address to report leaving for.
        Output:
            Packet: Scapy packet representing the MLDv1 Done for the specified multicast group.
        """
        return (PrototypeIPv6Packet.__get_mldv1_packet_headers(src_mac, src_ip, PrototypeIPv6Packet.ALL_ROUTERS_IPV6_MULTICAST_IP) /
                ICMPv6MLDone(mladdr=group))

    @staticmethod
    def __get_mldv2_join(src_mac: str|list[str]|None, src_ip: str|list[str]|None, group: str|list[str]) -> Packet:
        """
        Builds an MLDv2 Join packet for the specified multicast group, with appropriate L2 and L3 headers.
        Args:
            src_mac: Source MAC address for the MLDv2 Join packet.
            src_ip: Source IPv6 address for the MLDv2 Join packet.
            group: The multicast group address to report membership for.
        Output:
            Packet: Scapy packet representing the MLDv2 Join for the specified multicast group.
        """
        records = []
        if type(group) is str:
            records.append(ICMPv6MLDMultAddrRec(rtype=MLDV2_RType.CHANGE_TO_EXCLUDE_MODE, dst=group))
        elif type(group) is list:
            for g in group:
                records.append(ICMPv6MLDMultAddrRec(rtype=MLDV2_RType.CHANGE_TO_EXCLUDE_MODE, dst=g))
        return (PrototypeIPv6Packet.__get_mldv2_packet_headers(src_mac, src_ip) /
            ICMPv6MLReport2(records=records))

    @staticmethod
    def __get_mldv2_leave(src_mac: str|list[str]|None, src_ip: str|list[str]|None, group: str|list[str]) -> Packet:
        """
        Builds an MLDv2 Leave packet for the specified multicast group, with appropriate L2 and L3 headers.
        Args:
            src_mac: Source MAC address for the MLDv2 Leave packet.
            src_ip: Source IPv6 address for the MLDv2 Leave packet.
            group: The multicast group address to report leaving for.
        Output:
            Packet: Scapy packet representing the MLDv2 Leave for the specified multicast group.
        """
        records = []
        if type(group) is str:
            records.append(ICMPv6MLDMultAddrRec(rtype=MLDV2_RType.CHANGE_TO_INCLUDE_MODE, dst=group))
        elif type(group) is list:
            for g in group:
                records.append(ICMPv6MLDMultAddrRec(rtype=MLDV2_RType.CHANGE_TO_INCLUDE_MODE, dst=g))
        return (PrototypeIPv6Packet.__get_mldv2_packet_headers(src_mac, src_ip) /
            ICMPv6MLReport2(records=records))

    @staticmethod
    def get_frame_llmnr_custom_payload(src_mac: str|list[str]|None, src_ip: str|list[str]|None, l4_payload: Packet, sport: int|None=None) -> Packet:
        """
        Adds L2, L3, and L4 headers to the provided L4 payload to create a complete LLMNR query packet.
        Args:
            src_mac: Source MAC address for the LLMNR packet.
            src_ip: Source IPv6 address for the LLMNR packet.
            l4_payload: The L4 payload to be included in the LLMNR packet.
        Output:
            Packet: Scapy packet representing the complete LLMNR query with L2, L3, and L4 headers.
        """
        return (Ether(src=src_mac) /
                IPv6(src=src_ip, dst=PrototypeIPv6Packet.LLMNR_IPV6_MULTICAST_IP, hlim=1) /
                UDP(sport=PrototypeL4.get_l4port_random() if sport is None else sport, dport=PrototypeL4.LLMNR_PORT) /
                l4_payload)

    @staticmethod
    def get_frame_mdns_custom_payload(src_mac: str|list[str]|None, src_ip: str|list[str]|None, l4_payload: Packet, sport: int|None=PrototypeL4.MDNS_PORT) -> Packet:
        """
        Adds L2, L3, and L4 headers to the provided L4 payload to create a complete mDNS query packet.
        Args:
            src_mac: Source MAC address for the mDNS packet.
            src_ip: Source IPv6 address for the mDNS packet.
            l4_payload: The L4 payload to be included in the mDNS packet.
        Output:
            Packet: Scapy packet representing the complete mDNS query with L2, L3, and L4 headers.
        """
        return (Ether(src=src_mac) /
                IPv6(src=src_ip, dst=PrototypeIPv6Packet.MDNS_IPV6_MULTICAST_IP, hlim=1) /
                UDP(sport=sport, dport=PrototypeL4.MDNS_PORT) /
                l4_payload)

    @staticmethod
    def get_frame_mldv1(src_mac: str|list[str]|None, src_ip: str|list[str]|None) -> Packet:
        """
        Builds an MLDv1 Query packet with the specified source MAC and IPv6 addresses.
        The packet is constructed with appropriate L2 and L3 headers, and includes a Router Alert option in the hop-by-hop extension header.
        Args:
            src_mac: Source MAC address for the MLDv1 packet.
            src_ip: Source IPv6 address for the MLDv1 packet.
        Output:
            Packet: Scapy packet representing the MLDv1 Query.
        """
        return (PrototypeIPv6Packet.__get_mldv1_packet_headers(src_mac, src_ip, PrototypeIPv6Packet.ALL_NODES_IPV6_MULTICAST_IP) /
                ICMPv6MLQuery(mrd=1, mladdr='::'))

    @staticmethod
    def get_frame_mldv2(src_mac: str|list[str]|None, src_ip: str|list[str]|None) -> Packet:
        """
        Builds an MLDv2 Query packet with the specified source MAC and IPv6 addresses.
        The packet is constructed with appropriate L2 and L3 headers, and includes a Router Alert option in the hop-by-hop extension header.
        Args:
            src_mac: Source MAC address for the MLDv2 packet.
            src_ip: Source IPv6 address for the MLDv2 packet.
        Output:
            Packet: Scapy packet representing the MLDv2 Query.
        """
        return (PrototypeIPv6Packet.__get_mldv2_packet_headers(src_mac, src_ip) /
                ICMPv6MLQuery2(type=130, mladdr="::", sources=[], mrd=1, S=0, QRV=2, QQIC=125))

    @staticmethod
    def get_frame_llmnr_bundle_a_aaaa_any(src_mac: str|list[str]|None, src_ip: str|list[str]|None, qname: str) -> list[Packet]:
        """
        Builds a bundle of LLMNR query packets for A, AAAA, and ANY record types with the specified source MAC and IPv6 addresses, and query name.
        Each packet is constructed with appropriate L2 and L3 headers, and includes a DNS query for the specified query name with the respective record type (A, AAAA, ANY).
        Args:
            src_mac: Source MAC address for the LLMNR query packets.
            src_ip: Source IPv6 address for the LLMNR query packets.
            qname: The query name to be used in the DNS queries.
        Output:
            list[Packet]: A list of Scapy packets representing the LLMNR queries for A
        """
        queries = PrototypeL7.get_dns_bundle_a_aaaa_any(qname)
        return [PrototypeIPv6Packet.get_frame_llmnr_custom_payload(src_mac, src_ip, q) for q in queries]

    @staticmethod
    def get_frame_llmnr_ptr(src_mac: str|list[str]|None, src_ip: str|list[str]|None, qname: str) -> Packet:
        """
        Builds an LLMNR PTR query packet with the specified source MAC and IPv6 addresses, and query name.
        The packet is constructed with appropriate L2 and L3 headers, and includes a DNS query for the specified query name with PTR record type.
        Args:
            src_mac: Source MAC address for the LLMNR PTR query packet.
            src_ip: Source IPv6 address for the LLMNR PTR query packet.
            qname: The query name to be used in the PTR query.
        Output:
            Packet: Scapy packet representing the LLMNR PTR query.
        """
        return (PrototypeIPv6Packet.get_frame_llmnr_custom_payload(src_mac, src_ip, 
            LLMNRQuery(qd=DNSQR(qname=qname, qtype=DNS_QType.PTR))))

    @staticmethod
    def get_frame_mdns_bundle_a_aaaa_any(src_mac: str|list[str]|None, src_ip: str|list[str]|None, qname: str, unicastresponse: int = 0, sport: int|None = PrototypeL4.MDNS_PORT) -> list[Packet]:
        """
        Builds a bundle of mDNS query packets for A, AAAA, and ANY record types with the specified source MAC and IPv6 addresses, and query name.
        Each packet is constructed with appropriate L2 and L3 headers, and includes a DNS query for the specified query name with the respective record type (A, AAAA, ANY).
        Args:
            src_mac: Source MAC address for the mDNS query packets.
            src_ip: Source IPv6 address for the mDNS query packets.
            qname: The query name to be used in the DNS queries.
            unicastresponse: Flag indicating whether to set the unicast response bit in the DNS queries (default is 0).
        Output:
            list[Packet]: A list of Scapy packets representing the mDNS queries for A, AAAA, and ANY record types.
        """
        queries = PrototypeL7.get_dns_bundle_a_aaaa_any(qname, unicastresponse)
        return [PrototypeIPv6Packet.get_frame_mdns_custom_payload(src_mac, src_ip, q, 
            PrototypeL4.get_l4port_random() if sport is None else sport) for q in queries]

    @staticmethod
    def get_frame_mdns_ptr(src_mac: str|list[str]|None, src_ip: str|list[str]|None, qname: str, unicastresponse: int = 0, sport: int|None = PrototypeL4.MDNS_PORT) -> Packet:
        """
        Builds an mDNS PTR query packet with the specified source MAC and IPv6 addresses, and query name.
        The packet is constructed with appropriate L2 and L3 headers, and includes a DNS query for the specified query name with PTR record type.
        Args:
            src_mac: Source MAC address for the mDNS PTR query packet.
            src_ip: Source IPv6 address for the mDNS PTR query packet.
            qname: The query name to be used in the PTR query.
            unicastresponse: Flag indicating whether to set the unicast response bit in the DNS query (default is 0).
        Output:
            Packet: Scapy packet representing the mDNS PTR query.
        """
        return (PrototypeIPv6Packet.get_frame_mdns_custom_payload(src_mac, src_ip,
                    DNS(rd=1, qd=DNSQR(qname=qname, qtype=DNS_QType.PTR, unicastresponse=unicastresponse)),
                    PrototypeL4.get_l4port_random() if sport is None else sport))

    @staticmethod
    def get_frame_mdns_sd(src_mac: str|list[str]|None, src_ip: str|list[str]|None, unicastresponse: int = 0, sport: int|None = PrototypeL4.MDNS_PORT) -> Packet:
        """
        Builds an mDNS Service Discovery packet with the specified source MAC and IPv6 addresses.
        The packet is constructed with appropriate L2 and L3 headers, and includes a DNS query for the _services._dns-sd._udp.local. domain.
        Args:
            src_mac: Source MAC address for the mDNS Service Discovery packet.
            src_ip: Source IPv6 address for the mDNS Service Discovery packet.
            unicastresponse: Flag indicating whether to set the unicast response bit in the DNS query (default is 0).
        Output:
            Packet: Scapy packet representing the mDNS Service Discovery query.
        """
        return (Ether(src=src_mac) /
            IPv6(src=src_ip, dst=PrototypeIPv6Packet.MDNS_IPV6_MULTICAST_IP, hlim=1) /
            UDP(sport=PrototypeL4.get_l4port_random() if sport is None else sport, dport=PrototypeL4.MDNS_PORT) /
            DNS(id=33, rd=1, qd=DNSQR(qname="_services._dns-sd._udp.local.", qtype=DNS_QType.PTR, unicastresponse=unicastresponse)))

    @staticmethod
    def get_frame_ra(prefix_len: int, network: str, source_mac: str, source_ip: str, rpref: int, chl: int, mtu: int|None, dns: list[str]|None) -> Packet:
        """
        Builds a Router Advertisement packet with the specified parameters.
        The packet is constructed with appropriate L2 and L3 headers, and includes a Router Advertisement option with the specified router preference, hop limit, and lifetime. Additionally, the packet includes a Prefix Information option with the specified prefix length, network address, and lifetimes. If an MTU value is provided, it is included in the packet with an MTU option. If DNS server addresses are provided, they are included in the packet with an RDNSS option.
        Args:
            prefix_len: Length of the prefix for the Prefix Information option.
            network: Network address for the Prefix Information option.
            source_mac: Source MAC address for the Router Advertisement packet.
            source_ip: Source IPv6 address for the Router Advertisement packet.
            rpref: Router preference for the Router Advertisement packet.
            chl: Hop limit for the Router Advertisement packet.
            mtu: MTU value to be included in the Router Advertisement packet (optional).
            dns: List of DNS server addresses to be included in the Router Advertisement packet (optional).
        Output:
            Packet: Scapy packet representing the Router Advertisement.
        """
        layer2 = Ether(src=source_mac)
        layer3 = IPv6(src=source_ip, dst=PrototypeIPv6Packet.ALL_NODES_IPV6_MULTICAST_IP)
        RA = ICMPv6ND_RA(prf=rpref, M=0, O=0, H=0, chlim=chl, routerlifetime=PrototypeIPv6Packet.RA_LIFETIME, reachabletime=0, retranstimer=0)
        Opt_LLAddr = ICMPv6NDOptSrcLLAddr(lladdr=source_mac)
        packet1 = layer2 / layer3 / RA
        Opt_PrefixInfo = ICMPv6NDOptPrefixInfo(prefixlen=prefix_len, A=1, prefix=network, validlifetime=PrototypeIPv6Packet.RA_LIFETIME, preferredlifetime=PrototypeIPv6Packet.RA_LIFETIME)
        packet1 /= Opt_PrefixInfo
        if mtu is not None:
            Opt_MTU = ICMPv6NDOptMTU(mtu=mtu)
            packet1 /= Opt_MTU
        if dns is not None:
            Opt_DNS = ICMPv6NDOptRDNSS(dns=dns, lifetime=PrototypeIPv6Packet.RA_LIFETIME)
            packet1 /= Opt_DNS
        packet1 /= Opt_LLAddr
        return packet1

    @staticmethod
    def get_frame_ra_kill(prefix_len: int, network: str, source_mac: str|None, source_ip: str|None, rpref: int, chl: int, dns: list[str]|None) -> Packet:
        """
        Builds a Router Advertisement packet with parameters set to values that would cause a denial of service condition on compliant IPv6 hosts.
        The packet is constructed with appropriate L2 and L3 headers, and includes a Router Advertisement
        option with a zero router lifetime, which would cause compliant hosts to remove the default route to the router upon receiving this packet. Additionally, the packet includes a Prefix Information option with a zero valid lifetime, which would cause compliant hosts to remove the associated prefix from their list of valid prefixes. If DNS server addresses are provided, they are included in the packet with a zero lifetime, which would cause compliant hosts to remove those DNS servers from their configuration.
        Args:
            prefix_len: Length of the prefix for the Prefix Information option.
            network: Network address for the Prefix Information option.
            source_mac: Source MAC address for the Router Advertisement packet.
            source_ip: Source IPv6 address for the Router Advertisement packet.
            rpref: Router preference for the Router Advertisement packet.
            chl: Hop limit for the Router Advertisement packet.
            dns: List of DNS server addresses for the Router Advertisement packet.
        Output:
            Packet: Scapy packet representing the Router Advertisement.
        """
        layer2 = Ether(src=source_mac)
        layer3 = IPv6(src=source_ip, dst=PrototypeIPv6Packet.ALL_NODES_IPV6_MULTICAST_IP)
        kill_RA = ICMPv6ND_RA(prf=rpref, M=0, O=0, H=0, chlim=chl, routerlifetime=0, reachabletime=0, retranstimer=0)
        Opt_LLAddr = ICMPv6NDOptSrcLLAddr(lladdr=source_mac)
        kill_Opt_PrefixInfo = ICMPv6NDOptPrefixInfo(prefixlen=prefix_len, A=1, prefix=network, validlifetime=0, preferredlifetime=0)
        if dns is not None:
            kill_Opt_DNS = ICMPv6NDOptRDNSS(dns=dns, lifetime=0)
        kill_packet1 = layer2/layer3/kill_RA/kill_Opt_PrefixInfo
        if dns is not None:
            kill_packet1 /= kill_Opt_DNS
        kill_packet1 /= Opt_LLAddr
        return kill_packet1

    @staticmethod
    def get_frame_na(source_mac: str, target_mac: str, source_ip: str, target_ip: str, r_flag: int, s_flag: int, o_flag: int) -> Packet:
        """
        Builds an IPv6 Neighbor Advertisement packet with the specified parameters.
        Args:
            source_mac: Source MAC address for the Neighbor Advertisement packet.
            target_mac: Target MAC address for the Neighbor Advertisement packet.
            source_ip: Source IPv6 address for the Neighbor Advertisement packet.
            target_ip: Target IPv6 address for the Neighbor Advertisement packet.
            r_flag: Router flag for the Neighbor Advertisement packet (0 or 1).
            s_flag: Solicited flag for the Neighbor Advertisement packet (0 or 1).
            o_flag: Override flag for the Neighbor Advertisement packet (0 or 1).
        Output:
            Packet: Scapy packet representing the Neighbor Advertisement.
        """
        return (Ether(src=source_mac, dst=target_mac) /
            IPv6(src=source_ip, dst=target_ip) /
            ICMPv6ND_NA(R=r_flag, S=s_flag, O=o_flag, tgt=source_ip) / 
            ICMPv6NDOptDstLLAddr(lladdr=source_mac))

    @staticmethod
    def get_frame_ns(src_mac: str|None, address: str) -> Packet:
        """
        Builds an IPv6 Neighbor Solicitation packet for the specified address.
        Args:
            src_mac: Source MAC address for the Neighbor Solicitation packet.
            address: Target IPv6 address for the Neighbor Solicitation packet.
        Output:
            Packet: Scapy packet representing the Neighbor Solicitation.
        """
        return (Ether(src=src_mac) /
            IPv6(dst=inet_ntop(socket.AF_INET6, in6_getnsma(inet_pton(socket.AF_INET6, address)))) /
            ICMPv6ND_NS(tgt=address) /
            ICMPv6NDOptSrcLLAddr(lladdr=src_mac))

    @staticmethod
    def get_frame_wsdiscovery(src_mac: str|list[str]|None, src_ip: str|list[str]|None, message_id: str|None = None) -> Packet:
        return (Ether(src=src_mac) /
                IPv6(src=src_ip, dst=PrototypeIPv6Packet.WS_DISCOVERY_IPV6_MULTICAST_IP, hlim=1) /
                PrototypeL4.get_l3payload_wsdiscovery(message_id))

    @staticmethod
    def get_init_mldv2_active_mode(src_mac: str|list[str]|None, src_ip: str|list[str]|None) -> list[Packet]:
        """
        Subscribes to multicast groups for active scanning mode using MLDv2 Join messages.
        Args:
            src_mac: Source MAC address for the MLDv2 Join packets.
            src_ip: Source IPv6 address for the MLDv2 Join packets.
        Output:
            list[Packet]: A list of Scapy packets representing MLDv2 Join messages for
        """
        return [PrototypeIPv6Packet.__get_mldv2_join(src_mac, src_ip, PrototypeIPv6Packet.MULTICAST_GROUPS_ACTIVE)]

    @staticmethod
    def get_init_mldv1_active_mode(src_mac: str|list[str]|None, src_ip: str|list[str]|None) -> list[Packet]:
        """
        Subscribes to multicast groups for active scanning mode using MLDv1 Report messages.
        Args:
            src_mac: Source MAC address for the MLDv1 Report packets.
            src_ip: Source IPv6 address for the MLDv1 Report packets.
        Output:
            list[Packet]: A list of Scapy packets representing MLDv1 Report messages for
        """
        return [PrototypeIPv6Packet.__get_mldv1_report(src_mac, src_ip, group) 
                for group in PrototypeIPv6Packet.MULTICAST_GROUPS_ACTIVE]

    @staticmethod
    def get_finish_mldv2_active_mode(src_mac: str|list[str]|None, src_ip: str|list[str]|None) -> list[Packet]:
        """
        Unsubscribes from multicast groups for active scanning mode using MLDv2 Leave messages.
        Args:
            src_mac: Source MAC address for the MLDv2 Leave packets.
            src_ip: Source IPv6 address for the MLDv2 Leave packets.
        Output:
            list[Packet]: A list of Scapy packets representing MLDv2 Leave messages for
        """
        return [PrototypeIPv6Packet.__get_mldv2_leave(src_mac, src_ip, PrototypeIPv6Packet.MULTICAST_GROUPS_ACTIVE)]

    @staticmethod
    def get_finish_mldv1_active_mode(src_mac: str|list[str]|None, src_ip: str|list[str]|None) -> list[Packet]:
        """
        Unsubscribes from multicast groups for active scanning mode using MLDv1 Done messages.
        Args:
            src_mac: Source MAC address for the MLDv1 Done packets.
            src_ip: Source IPv6 address for the MLDv1 Done packets.
        Output:
            list[Packet]: A list of Scapy packets representing MLDv1 Done messages for
        """
        return [PrototypeIPv6Packet.__get_mldv1_done(src_mac, src_ip, group) 
                for group in PrototypeIPv6Packet.MULTICAST_GROUPS_ACTIVE]

    @staticmethod
    def get_init_mldv2_aggressive_mode(src_mac: str|list[str]|None, src_ip: str|list[str]|None) -> list[Packet]:
        """
        Subscribes to multicast groups for aggressive scanning mode using MLDv2 Join messages.
        Args:
            src_mac: Source MAC address for the MLDv2 Join packets.
            src_ip: Source IPv6 address for the MLDv2 Join packets.
        Output:
            list[Packet]: A list of Scapy packets representing MLDv2 Join messages for
        """
        return [PrototypeIPv6Packet.__get_mldv2_join(src_mac, src_ip, PrototypeIPv6Packet.MULTICAST_GROUPS_AGGRESSIVE)]

    @staticmethod
    def get_init_mldv1_aggressive_mode(src_mac: str|list[str]|None, src_ip: str|list[str]|None) -> list[Packet]:
        """
        Subscribes to multicast groups for aggressive scanning mode using MLDv1 Report messages.
        Args:
            src_mac: Source MAC address for the MLDv1 Report packets.
            src_ip: Source IPv6 address for the MLDv1 Report packets.
        Output:
            list[Packet]: A list of Scapy packets representing MLDv1 Report messages for
        """
        return [PrototypeIPv6Packet.__get_mldv1_report(src_mac, src_ip, group) 
                for group in PrototypeIPv6Packet.MULTICAST_GROUPS_AGGRESSIVE]

    @staticmethod
    def get_finish_mldv2_aggressive_mode(src_mac: str|list[str]|None, src_ip: str|list[str]|None) -> list[Packet]:
        """
        Unsubscribes from multicast groups for aggressive scanning mode using MLDv2 Leave messages.
        Args:
            src_mac: Source MAC address for the MLDv2 Leave packets.
            src_ip: Source IPv6 address for the MLDv2 Leave packets.
        Output:
            list[Packet]: A list of Scapy packets representing MLDv2 Leave messages for
        """
        return [PrototypeIPv6Packet.__get_mldv2_leave(src_mac, src_ip, PrototypeIPv6Packet.MULTICAST_GROUPS_AGGRESSIVE)]

    @staticmethod
    def get_finish_mldv1_aggressive_mode(src_mac: str|list[str]|None, src_ip: str|list[str]|None) -> list[Packet]:
        """
        Unsubscribes from multicast groups for aggressive scanning mode using MLDv1 Done messages.
        Args:
            src_mac: Source MAC address for the MLDv1 Done packets.
            src_ip: Source IPv6 address for the MLDv1 Done packets.
        Output:
            list[Packet]: A list of Scapy packets representing MLDv1 Done messages for
        """
        return [PrototypeIPv6Packet.__get_mldv1_done(src_mac, src_ip, group) 
                for group in PrototypeIPv6Packet.MULTICAST_GROUPS_AGGRESSIVE]