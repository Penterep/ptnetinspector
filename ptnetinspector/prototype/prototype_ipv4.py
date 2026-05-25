from enum import Enum
import random

from scapy.all import Packet
from scapy.layers.inet import IP, UDP, IPOption_Router_Alert
from scapy.layers.l2 import Ether, ARP
from scapy.contrib.igmp import IGMP
from scapy.contrib.igmpv3 import IGMPv3, IGMPv3mr, IGMPv3gr, IGMPv3mq
from scapy.layers.llmnr import LLMNRQuery
from scapy.layers.dns import DNS, DNSQR

from ptnetinspector.prototype.prototype_l7 import *
from ptnetinspector.prototype.prototype_l4 import *

class IGMP_Type(Enum):
    GROUP_MEMBERSHIP_QUERY = 17
    V1_MEMBERSHIP_REPORT = 18
    V2_MEMBERSHIP_REPORT = 22
    LEAVE_GROUP = 23

class IGMPV3_RType(Enum):
    MODE_IS_INCLUDE = 1
    MODE_IS_EXCLUDE = 2
    CHANGE_TO_INCLUDE_MODE = 3
    CHANGE_TO_EXCLUDE_MODE = 4
    ALLOW_NEW_SOURCES = 5
    BLOCK_OLD_SOURCES = 6

class PrototypeIPv4Packet:
    # Addresses
    ALL_NODES_IPV4_MULTICAST_IP = "224.0.0.1"
    ALL_ROUTERS_IPV4_MULTICAST_IP = "224.0.0.2"
    DHCPV4_ALL_SERVERS_MULTICAST_IP = "224.0.0.12"
    IGMPV3_IPV4_MULTICAST_IP = "224.0.0.22"
    MDNS_IPV4_MULTICAST_IP = "224.0.0.251"
    LLMNR_IPV4_MULTICAST_IP = "224.0.0.252"
    WS_DISCOVERY_IPV4_MULTICAST_IP = "239.255.255.250"
    SSDP_IPV4_MULTICAST_IP = "239.255.255.250"
    SLP_IPV4_MULTICAST_IPS = [
        "224.0.1.22", # v1 general
        "224.0.1.35", # v1 directory agents
        "239.255.255.253", # v2
    ]

    MULTICAST_GROUPS_ACTIVE = [ 
        IGMPV3_IPV4_MULTICAST_IP,
        MDNS_IPV4_MULTICAST_IP,
        LLMNR_IPV4_MULTICAST_IP,
        # WS_DISCOVERY_IPV4_MULTICAST_IP, # Included in SSDP_IPV4_MULTICAST_IP
        SSDP_IPV4_MULTICAST_IP
    ] + SLP_IPV4_MULTICAST_IPS
    MULTICAST_GROUPS_AGGRESSIVE = [
        DHCPV4_ALL_SERVERS_MULTICAST_IP,
        ALL_ROUTERS_IPV4_MULTICAST_IP
    ]
    MULTICAST_GROUPS_KEEP = [
 
    ]

    # 
    # L3 Payloads
    #


    # 
    # L3 Builders
    #

    @staticmethod
    def get_frame_mdns_custom_payload(src_mac: str|list[str]|None, src_ip: str|list[str]|None, l4_payload: Packet, sport: int|None=PrototypeL4.MDNS_PORT) -> Packet:
        """
        Adds L2, L3, and L4 headers to the provided L4 payload to create a complete mDNS query packet.
        Args:
            src_mac: Source MAC address for the mDNS packet.
            src_ip: Source IPv4 address for the mDNS packet.
            l4_payload: The L4 payload to be included in the mDNS packet.
        Output:
            Packet: Scapy packet representing the complete mDNS query with L2, L3, and L4 headers.
        """
        return (Ether(src=src_mac) /
                IP(src=src_ip, dst=PrototypeIPv4Packet.MDNS_IPV4_MULTICAST_IP, ttl=1) /
                UDP(sport=sport, dport=PrototypeL4.MDNS_PORT) /
                l4_payload)

    @staticmethod
    def get_frame_mdns_ptr(src_mac: str|list[str]|None, src_ip: str|list[str]|None, qname: str, unicastresponse: int = 0, sport: int|None = PrototypeL4.MDNS_PORT) -> Packet:
        """
        Builds an mDNS PTR query packet with the specified source MAC and IPv4 addresses, and query name.
        The packet is constructed with appropriate L2 and L3 headers, and includes a DNS query for the specified query name with PTR record type.
        Args:
            src_mac: Source MAC address for the mDNS PTR query packet.
            src_ip: Source IPv4 address for the mDNS PTR query packet.
            qname: The query name to be used in the PTR query.
            unicastresponse: Flag indicating whether to set the unicast response bit in the DNS query (default is 0).
        Output:
            Packet: Scapy packet representing the mDNS PTR query.
        """
        return (PrototypeIPv4Packet.get_frame_mdns_custom_payload(src_mac, src_ip,
                    PrototypeL7.get_dns_ptr(qname, unicastresponse),
                    PrototypeL4.get_l4port_random() if sport is None else sport))

    @staticmethod
    def get_frame_mdns_bundle_a_aaaa_any(src_mac: str|list[str]|None, src_ip: str|list[str]|None, qname: str, unicastresponse: int = 0, sport: int|None = PrototypeL4.MDNS_PORT) -> list[Packet]:
        """
        Builds a bundle of mDNS query packets for A, AAAA, and ANY record types with the specified source MAC and IPv4 addresses, and query name.
        Each packet is constructed with appropriate L2 and L3 headers, and includes a DNS query for the specified query name with the respective record type (A, AAAA, ANY).
        Args:
            src_mac: Source MAC address for the mDNS query packets.
            src_ip: Source IPv4 address for the mDNS query packets.
            qname: The query name to be used in the DNS queries.
            unicastresponse: Flag indicating whether to set the unicast response bit in the DNS queries (default is 0).
        Output:
            list[Packet]: A list of Scapy packets representing the mDNS queries for A, AAAA, and ANY record types.
        """
        queries = PrototypeL7.get_dns_bundle_a_aaaa_any(qname, unicastresponse)
        return [PrototypeIPv4Packet.get_frame_mdns_custom_payload(src_mac, src_ip, q, 
            PrototypeL4.get_l4port_random() if sport is None else sport) for q in queries]

    @staticmethod
    def get_frame_mdns_sd(src_mac: str|list[str]|None, src_ip: str|list[str]|None, unicastresponse: int = 0, sport: int|None = PrototypeL4.MDNS_PORT) -> Packet:
        """
        Builds an mDNS Service Discovery packet with the specified source MAC and IPv4 addresses.
        The packet is constructed with appropriate L2 and L3 headers, and includes a DNS query for the _services._dns-sd._udp.local. domain.
        Args:
            src_mac: Source MAC address for the mDNS Service Discovery packet.
            src_ip: Source IPv4 address for the mDNS Service Discovery packet.
            unicastresponse: Flag indicating whether to set the unicast response bit in the DNS query (default is 0).
        Output:
            Packet: Scapy packet representing the mDNS Service Discovery query.
        """
        return (Ether(src=src_mac) /
            IP(src=src_ip, dst=PrototypeIPv4Packet.MDNS_IPV4_MULTICAST_IP, ttl=1) /
            PrototypeL4.get_l3payload_mdns_sd(unicastresponse=unicastresponse, sport=sport))

    @staticmethod
    def get_frame_llmnr_custom_payload(src_mac: str|list[str]|None, src_ip: str|list[str]|None, l4_payload: Packet, sport: int|None=None) -> Packet:
        """
        Adds L2, L3, and L4 headers to the provided L4 payload to create a complete LLMNR query packet.
        Args:
            src_mac: Source MAC address for the LLMNR packet.
            src_ip: Source IPv4 address for the LLMNR packet.
            l4_payload: The L4 payload to be included in the LLMNR packet.
        Output:
            Packet: Scapy packet representing the complete LLMNR query with L2, L3, and L4 headers.
        """
        return (Ether(src=src_mac) /
                IP(src=src_ip, dst=PrototypeIPv4Packet.LLMNR_IPV4_MULTICAST_IP, ttl=1) /
                UDP(sport=PrototypeL4.get_l4port_random() if sport is None else sport, dport=PrototypeL4.LLMNR_PORT) /
                l4_payload)

    @staticmethod
    def get_frame_llmnr_ptr(src_mac: str|list[str]|None, src_ip: str|list[str]|None, qname: str) -> Packet:
        """
        Builds an LLMNR PTR query packet with the specified source MAC and IPv4 addresses, and query name.
        The packet is constructed with appropriate L2 and L3 headers, and includes a DNS query for the specified query name with PTR record type.
        Args:
            src_mac: Source MAC address for the LLMNR PTR query packet.
            src_ip: Source IPv4 address for the LLMNR PTR query packet.
            qname: The query name to be used in the PTR query.
        Output:
            Packet: Scapy packet representing the LLMNR PTR query.
        """
        return (PrototypeIPv4Packet.get_frame_llmnr_custom_payload(src_mac, src_ip, 
            LLMNRQuery(qd=DNSQR(qname=qname, qtype=DNS_QType.PTR))))

    @staticmethod
    def get_frame_llmnr_bundle_a_aaaa_any(src_mac: str|list[str]|None, src_ip: str|list[str]|None, qname: str) -> list[Packet]:
        """
        Builds a bundle of LLMNR query packets for A, AAAA, and ANY record types with the specified source MAC and IPv6 addresses, and query name.
        Each packet is constructed with appropriate L2 and L3 headers, and includes a DNS query for the specified query name with the respective record type (A, AAAA, ANY).
        Args:
            src_mac: Source MAC address for the LLMNR query packets.
            src_ip: Source IPv4 address for the LLMNR query packets.
            qname: The query name to be used in the DNS queries.
        Output:
            list[Packet]: A list of Scapy packets representing the LLMNR queries for A, AAAA, and ANY record types.
        """
        queries = PrototypeL7.get_dns_bundle_a_aaaa_any(qname)
        return [PrototypeIPv4Packet.get_frame_llmnr_custom_payload(src_mac, src_ip, q) for q in queries]

    @staticmethod
    def get_frame_arp(address: str) -> Packet:
        """
        Builds an ARP request packet for the specified target IPv4 address.
        The packet is constructed with an Ethernet header for broadcast and an ARP layer with the target IPv4 address.
        Args: 
            address: The target IPv4 address for the ARP request.
        Output:
            Packet: Scapy packet representing the ARP request.
        """
        return (Ether(dst="ff:ff:ff:ff:ff:ff") /
            ARP(pdst=address))

    @staticmethod
    def get_frame_wsdiscovery(src_mac: str|list[str]|None, src_ip: str|list[str]|None, message_id: str|None = None) -> Packet:
        """
        Builds a WS-Discovery Probe packet with the specified source MAC and IPv4 addresses, and optional message ID.
        The packet is constructed with appropriate L2 and L3 headers, and includes a WS-Discovery Probe payload.
        Args:
            src_mac: Source MAC address for the WS-Discovery Probe packet.
            src_ip: Source IPv4 address for the WS-Discovery Probe packet.
            message_id: Optional message ID for the WS-Discovery Probe packet.
        Output:
            Packet: Scapy packet representing the WS-Discovery Probe.
        """
        return (Ether(src=src_mac) /
                IP(src=src_ip, dst=PrototypeIPv4Packet.WS_DISCOVERY_IPV4_MULTICAST_IP, ttl=1) /
                PrototypeL4.get_l3payload_wsdiscovery(message_id))

    @staticmethod
    def __get_igmpv2_packet_headers(src_mac: str|list[str]|None, src_ip: str|list[str]|None, dst_ip: str|list[str]) -> Packet:
        """
        Builds common L2 and L3 headers for IGMPv2 packets with Router Alert option.
        Args:
            src_mac: Source MAC address.
            src_ip: Source IPv4 address.
            dst_ip: Destination IPv4 address (multicast group or all-routers address).
        Output:
            Packet: Scapy packet with Ethernet and IP headers including the Router Alert option.
        """
        return (Ether(src=src_mac) /
                IP(src=src_ip, dst=dst_ip, ttl=1, options=[IPOption_Router_Alert()]))

    @staticmethod
    def get_igmp_query_general(version: int, src_mac: str|list[str]|None, src_ip: str|list[str]|None, spec_group: str = "0.0.0.0") -> Packet|None:
        """
        Builds a general IGMP Membership Query packet for the specified IGMP version.
        Args:
            version: IGMP version (1, 2, or 3).
            src_mac: Source MAC address.
            src_ip: Source IPv4 address.
            spec_group: Multicast group address for a group-specific query; defaults to "0.0.0.0" for a general query.
        Output:
            Packet: Scapy packet representing the IGMP Membership Query, or None if the version is unsupported.
        """
        mac = Ether(src=src_mac)
        ipv4_packet = IP(src=src_ip, dst=PrototypeIPv4Packet.ALL_NODES_IPV4_MULTICAST_IP, ttl=1)
        match version:
            case 1:
                igmp_query = IGMP(type=IGMP_Type.GROUP_MEMBERSHIP_QUERY, mrcode=0, gaddr=spec_group)
            case 2:
                igmp_query = IGMP(type=IGMP_Type.GROUP_MEMBERSHIP_QUERY, mrcode=2, gaddr=spec_group)
            case 3:
                igmp_query = IGMPv3(type=IGMP_Type.GROUP_MEMBERSHIP_QUERY, mrcode=2) / IGMPv3mq(gaddr=spec_group)
            case _:
                return None
        return (mac / ipv4_packet / igmp_query)

    @staticmethod
    def __get_igmpv3_packet_headers(src_mac: str|list[str]|None, src_ip: str|list[str]|None) -> Packet:
        """
        Builds common L2 and L3 headers for IGMPv3 packets with Router Alert option.
        The destination is the IGMPv3-specific multicast address (224.0.0.22).
        Args:
            src_mac: Source MAC address.
            src_ip: Source IPv4 address.
        Output:
            Packet: Scapy packet with Ethernet and IP headers including the Router Alert option.
        """
        return (Ether(src=src_mac) /
                IP(src=src_ip, dst=PrototypeIPv4Packet.IGMPV3_IPV4_MULTICAST_IP, ttl=1, options=[IPOption_Router_Alert()]))

    @staticmethod
    def __get_igmpv2_join(src_mac: str|list[str]|None, src_ip: str|list[str]|None, group: str) -> Packet:
        """
        Builds an IGMPv2 Membership Report (join) packet for the specified multicast group.
        Args:
            src_mac: Source MAC address.
            src_ip: Source IPv4 address.
            group: Multicast group address to join.
        Output:
            Packet: Scapy packet representing the IGMPv2 Membership Report.
        """
        return (PrototypeIPv4Packet.__get_igmpv2_packet_headers(src_mac, src_ip, group) /
                IGMP(type=IGMP_Type.V2_MEMBERSHIP_REPORT, gaddr=group))

    @staticmethod
    def __get_igmpv2_leave(src_mac: str|list[str]|None, src_ip: str|list[str]|None, group: str) -> Packet:
        """
        Builds an IGMPv2 Leave Group packet for the specified multicast group.
        The packet is sent to the all-routers multicast address (224.0.0.2).
        Args:
            src_mac: Source MAC address.
            src_ip: Source IPv4 address.
            group: Multicast group address to leave.
        Output:
            Packet: Scapy packet representing the IGMPv2 Leave Group message.
        """
        return (PrototypeIPv4Packet.__get_igmpv2_packet_headers(src_mac, src_ip, PrototypeIPv4Packet.ALL_ROUTERS_IPV4_MULTICAST_IP) /
                IGMP(type=IGMP_Type.LEAVE_GROUP, gaddr=group))

    @staticmethod
    def __get_igmpv3_join(src_mac: str|list[str]|None, src_ip: str|list[str]|None, group: str|list[str]) -> Packet:
        """
        Builds an IGMPv3 Membership Report (join) packet using MODE_IS_EXCLUDE for the specified group(s).
        MODE_IS_EXCLUDE with an empty source list indicates membership in the group.
        Args:
            src_mac: Source MAC address.
            src_ip: Source IPv4 address.
            group: Multicast group address or list of addresses to join.
        Output:
            Packet: Scapy packet representing the IGMPv3 Membership Report.
        """
        records = []
        if type(group) is str:
            records.append(IGMPv3gr(rtype=IGMPV3_RType.MODE_IS_EXCLUDE, maddr=group))
        elif type(group) is list:
            for g in group:
                records.append(IGMPv3gr(rtype=IGMPV3_RType.MODE_IS_EXCLUDE, maddr=g))
        return (PrototypeIPv4Packet.__get_igmpv3_packet_headers(src_mac, src_ip) /
                IGMPv3() / IGMPv3mr(records=records))

    @staticmethod
    def __get_igmpv3_leave(src_mac: str|list[str]|None, src_ip: str|list[str]|None, group: str|list[str]) -> Packet:
        """
        Builds an IGMPv3 Membership Report (leave) packet using MODE_IS_INCLUDE for the specified group(s).
        MODE_IS_INCLUDE with an empty source list indicates leaving the group.
        Args:
            src_mac: Source MAC address.
            src_ip: Source IPv4 address.
            group: Multicast group address or list of addresses to leave.
        Output:
            Packet: Scapy packet representing the IGMPv3 Membership Report signalling group departure.
        """
        records = []
        if type(group) is str:
            records.append(IGMPv3gr(rtype=IGMPV3_RType.MODE_IS_INCLUDE, maddr=group))
        elif type(group) is list:
            for g in group:
                records.append(IGMPv3gr(rtype=IGMPV3_RType.MODE_IS_INCLUDE, maddr=g))
        return (PrototypeIPv4Packet.__get_igmpv3_packet_headers(src_mac, src_ip) /
                IGMPv3() / IGMPv3mr(records=records))

    @staticmethod
    def get_init_igmpv3_active_mode(src_mac: str|list[str]|None, src_ip: str|list[str]|None) -> list[Packet]:
        """
        Builds IGMPv3 join packets for all active-mode multicast groups as a single Membership Report.
        Args:
            src_mac: Source MAC address.
            src_ip: Source IPv4 address.
        Output:
            list[Packet]: List containing the IGMPv3 Membership Report for all active-mode groups.
        """
        return [PrototypeIPv4Packet.__get_igmpv3_join(src_mac, src_ip, PrototypeIPv4Packet.MULTICAST_GROUPS_ACTIVE)]

    @staticmethod
    def get_init_igmpv2_active_mode(src_mac: str|list[str]|None, src_ip: str|list[str]|None) -> list[Packet]:
        """
        Builds IGMPv2 join packets for each active-mode multicast group individually.
        Args:
            src_mac: Source MAC address.
            src_ip: Source IPv4 address.
        Output:
            list[Packet]: List of IGMPv2 Membership Report packets, one per active-mode group.
        """
        return [PrototypeIPv4Packet.__get_igmpv2_join(src_mac, src_ip, group) 
                for group in PrototypeIPv4Packet.MULTICAST_GROUPS_ACTIVE]

    @staticmethod
    def get_finish_igmpv3_active_mode(src_mac: str|list[str]|None, src_ip: str|list[str]|None) -> list[Packet]:
        """
        Builds IGMPv3 leave packets for all active-mode multicast groups as a single Membership Report.
        Args:
            src_mac: Source MAC address.
            src_ip: Source IPv4 address.
        Output:
            list[Packet]: List containing the IGMPv3 Membership Report signalling departure from all active-mode groups.
        """
        multicast_groups = PrototypeIPv4Packet.MULTICAST_GROUPS_ACTIVE.copy()
        for keep in PrototypeIPv4Packet.MULTICAST_GROUPS_KEEP:
            if keep in multicast_groups:
                multicast_groups.remove(keep)
        return [PrototypeIPv4Packet.__get_igmpv3_leave(src_mac, src_ip, multicast_groups)]

    @staticmethod
    def get_finish_igmpv2_active_mode(src_mac: str|list[str]|None, src_ip: str|list[str]|None) -> list[Packet]:
        """
        Builds IGMPv2 Leave Group packets for each active-mode multicast group individually.
        Args:
            src_mac: Source MAC address.
            src_ip: Source IPv4 address.
        Output:
            list[Packet]: List of IGMPv2 Leave Group packets, one per active-mode group.
        """
        multicast_groups = PrototypeIPv4Packet.MULTICAST_GROUPS_ACTIVE.copy()
        for keep in PrototypeIPv4Packet.MULTICAST_GROUPS_KEEP:
            if keep in multicast_groups:
                multicast_groups.remove(keep)
        return [PrototypeIPv4Packet.__get_igmpv2_leave(src_mac, src_ip, group) 
                for group in multicast_groups]

    @staticmethod
    def get_init_igmpv3_aggressive_mode(src_mac: str|list[str]|None, src_ip: str|list[str]|None) -> list[Packet]:
        """
        Builds IGMPv3 join packets for all aggressive-mode multicast groups as a single Membership Report.
        Args:
            src_mac: Source MAC address.
            src_ip: Source IPv4 address.
        Output:
            list[Packet]: List containing the IGMPv3 Membership Report for all aggressive-mode groups.
        """
        return [PrototypeIPv4Packet.__get_igmpv3_join(src_mac, src_ip, PrototypeIPv4Packet.MULTICAST_GROUPS_AGGRESSIVE)]

    @staticmethod
    def get_init_igmpv2_aggressive_mode(src_mac: str|list[str]|None, src_ip: str|list[str]|None) -> list[Packet]:
        """
        Builds IGMPv2 join packets for each aggressive-mode multicast group individually.
        Args:
            src_mac: Source MAC address.
            src_ip: Source IPv4 address.
        Output:
            list[Packet]: List of IGMPv2 Membership Report packets, one per aggressive-mode group.
        """
        return [PrototypeIPv4Packet.__get_igmpv2_join(src_mac, src_ip, group) 
                for group in PrototypeIPv4Packet.MULTICAST_GROUPS_AGGRESSIVE]

    @staticmethod
    def get_finish_igmpv3_aggressive_mode(src_mac: str|list[str]|None, src_ip: str|list[str]|None) -> list[Packet]:
        """
        Builds IGMPv3 leave packets for all aggressive-mode multicast groups as a single Membership Report.
        Args:
            src_mac: Source MAC address.
            src_ip: Source IPv4 address.
        Output:
            list[Packet]: List containing the IGMPv3 Membership Report signalling departure from all aggressive-mode groups.
        """
        multicast_groups = PrototypeIPv4Packet.MULTICAST_GROUPS_AGGRESSIVE.copy()
        for keep in PrototypeIPv4Packet.MULTICAST_GROUPS_KEEP:
            if keep in multicast_groups:
                multicast_groups.remove(keep)
        return [PrototypeIPv4Packet.__get_igmpv3_leave(src_mac, src_ip, multicast_groups)]

    @staticmethod
    def get_finish_igmpv2_aggressive_mode(src_mac: str|list[str]|None, src_ip: str|list[str]|None) -> list[Packet]:
        """
        Builds IGMPv2 Leave Group packets for each aggressive-mode multicast group individually.
        Args:
            src_mac: Source MAC address.
            src_ip: Source IPv4 address.
        Output:
            list[Packet]: List of IGMPv2 Leave Group packets, one per aggressive-mode group.
        """
        multicast_groups = PrototypeIPv4Packet.MULTICAST_GROUPS_AGGRESSIVE.copy()
        for keep in PrototypeIPv4Packet.MULTICAST_GROUPS_KEEP:
            if keep in multicast_groups:
                multicast_groups.remove(keep)
        return [PrototypeIPv4Packet.__get_igmpv2_leave(src_mac, src_ip, group) 
                for group in multicast_groups]
