
import random
import socket
import uuid

from scapy.all import Raw, Packet
from scapy.layers.inet6 import ICMPv6MLDMultAddrRec, IPv6, ICMPv6MLQuery, ICMPv6MLReport, ICMPv6MLReport2, ICMPv6MLDone, ICMPv6EchoRequest, IPv6ExtHdrHopByHop, RouterAlert, IPv6ExtHdrDestOpt, HBHOptUnknown, ICMPv6ND_NS, ICMPv6NDOptSrcLLAddr, ICMPv6ND_NA, ICMPv6MLQuery2, ICMPv6ND_RS, ICMPv6ND_RA, ICMPv6NDOptRDNSS, ICMPv6NDOptMTU, ICMPv6NDOptPrefixInfo, ICMPv6NDOptDstLLAddr
from scapy.layers.inet import UDP
from scapy.layers.l2 import Ether
from scapy.layers.dhcp6 import DUID_LL, DHCP6OptElapsedTime, DHCP6OptIA_NA, DHCP6OptClientId, DHCP6_Solicit
from scapy.layers.llmnr import LLMNRQuery, LLMNRResponse
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.pton_ntop import inet_ntop, inet_pton
from scapy.utils6 import in6_getnsma

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

    # - ipv4 + ipv6 přihlašování do multicast skupin, pro aktivní a agresivní, -6 je pro IPv6 skupiny, -4 pouze IPv4 skupiny. -6 a -4 oboje. Odhlášení dle přihlášení. Použít MLDv2 i MLDv1 v IPv6 a v IPv4 použít IGMPv3 a IGMPv2.
    # - případně prověřit jaké další multicastové skupiny se používají (ff02::c)
    # - v případě agresivního by se měl router hlásit do skupiny všech routerů (ff02::2)

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
    def __get_l4port_random() -> int:
        """
        Returns a random ephemeral port number between 49152 and 65535.
        Args:
            None
        Output:             
            int: A random ephemeral port number.
        """
        return random.randint(49152, 65535)
    
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
    def __get_mldv1_packet_headers(src_mac: str|None, src_ip: str|None, dst_ip: str) -> Packet:
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
                IPv6(src=src_ip, dst=dst_ip, hlim=1)/
                IPv6ExtHdrHopByHop(options=RouterAlert(otype=5, optlen=2, value=0)))
    
    @staticmethod
    def __get_mldv2_packet_headers(src_mac: str|None, src_ip: str|None) -> Packet:
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
                IPv6(src=src_ip, dst=PrototypeIPv6Packet.MLDV2_IPV6_MULTICAST_IP, hlim=1)/
                IPv6ExtHdrHopByHop(options=RouterAlert(otype=5, optlen=2, value=0)))
    
    @staticmethod
    def __get_mldv1_report(src_mac: str|None, src_ip: str|None, group: str) -> Packet:
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
    def __get_mldv1_done(src_mac: str|None, src_ip: str|None, group: str) -> Packet:
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
    def __get_mldv2_join(src_mac: str|None, src_ip: str|None, group: str|list[str]) -> Packet:
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
            records.append(ICMPv6MLDMultAddrRec(rtype=4, dst=group))
        elif type(group) is list:
            for g in group:
                records.append(ICMPv6MLDMultAddrRec(rtype=4, dst=g))
        return (PrototypeIPv6Packet.__get_mldv2_packet_headers(src_mac, src_ip) /
            ICMPv6MLReport2(records=records))
    
    @staticmethod
    def __get_mldv2_leave(src_mac: str|None, src_ip: str|None, group: str|list[str]) -> Packet:
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
            records.append(ICMPv6MLDMultAddrRec(rtype=3, dst=group))
        elif type(group) is list:
            for g in group:
                records.append(ICMPv6MLDMultAddrRec(rtype=3, dst=g))
        return (PrototypeIPv6Packet.__get_mldv2_packet_headers(src_mac, src_ip) /
            ICMPv6MLReport2(records=records))

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
    def get_l3payload_icmpv6_echo_request_with_dest_opt(id: int=0) -> Packet:
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
    def get_l3payload_icmpv6_echo_request_with_hop_by_hop_opt(id: int=0) -> Packet:
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
    def get_l3payload_invalid_icmpv6_with_dest_opt(id: int=0) -> Packet:
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
        duid = DUID_LL(lladdr=src_mac, type=3)
        udp = UDP(sport=546, dport=547)
        dhcpv6 = DHCP6_Solicit(trid=trid)
        client_id_opt = DHCP6OptClientId(duid=duid)
        elapsed_time_opt = DHCP6OptElapsedTime(elapsedtime=0)
        ia_na_opt = DHCP6OptIA_NA(iaid=random.randint(0, 0xFFFFFFFF), T1=0, T2=0)
        return udp / dhcpv6 / client_id_opt / elapsed_time_opt / ia_na_opt
    
    @staticmethod
    def get_l3payload_wsdiscovery() -> Packet:
        """
        Returns WS-Discovery Probe packet.
        Does not include L2 and L3 headers, only the WS-Discovery payload.
        Args:
            None
        Output:
            Packet: Scapy packet representing WS-Discovery Probe.
        """
        message_id = str(uuid.uuid4())
        soap_payload = f"""<?xml version="1.0" ?>
<s:Envelope xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:s="http://www.w3.org/2003/05/soap-envelope">
\t<s:Header>
\t\t<a:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</a:Action>
\t\t<a:MessageID>urn:uuid:{message_id}</a:MessageID>
\t\t<a:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</a:To>
\t</s:Header>
\t<s:Body>
\t\t<d:Probe/>
\t</s:Body>
</s:Envelope>
"""
        udp = UDP(sport=PrototypeIPv6Packet.__get_l4port_random(), dport=3702)
        payload = Raw(load=soap_payload)
        return udp / payload
            
    # 
    # L3 Builders
    #
    @staticmethod
    def get_frame_llmnr_custom_payload(src_mac: str|None, src_ip: str|None, l4_payload: Packet, sport: int|None=None) -> Packet:
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
                UDP(sport=PrototypeIPv6Packet.__get_l4port_random() if sport is None else sport, dport=5355) /
                l4_payload)
    @staticmethod
    def get_frame_mdns_custom_payload(src_mac: str|None, src_ip: str|None, l4_payload: Packet, sport: int|None=5353) -> Packet:
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
                UDP(sport=sport, dport=5353) /
                l4_payload)

    @staticmethod
    def get_frame_mldv1(src_mac: str|None, src_ip: str|None) -> Packet:
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
    def get_frame_mldv2(src_mac: str|None, src_ip: str|None) -> Packet:
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
    def get_frame_llmnr_bundle_a_aaaa_any(src_mac: str|None, src_ip: str|None, qname: str) -> list[Packet]:
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
        pkt_any = PrototypeIPv6Packet.get_frame_llmnr_custom_payload(src_mac, src_ip,
            LLMNRQuery(qd=DNSQR(qname=qname, qtype=255, qclass=1)))
        pkt_a = PrototypeIPv6Packet.get_frame_llmnr_custom_payload(src_mac, src_ip,
            LLMNRQuery(qd=DNSQR(qname=qname, qtype=1, qclass=1)))
        pkt_aaaa = PrototypeIPv6Packet.get_frame_llmnr_custom_payload(src_mac, src_ip,
                    LLMNRQuery(qd=DNSQR(qname=qname, qtype=28, qclass=1)))
        return [pkt_a, pkt_aaaa, pkt_any]
    
    @staticmethod
    def get_frame_llmnr_ptr(src_mac: str|None, src_ip: str|None, qname: str) -> Packet:
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
            LLMNRQuery(qd=DNSQR(qname=qname, qtype="PTR"))))

    @staticmethod
    def get_frame_mdns_bundle_a_aaaa_any(src_mac: str|None, src_ip: str|None, qname: str, unicastresponse: int = 0, sport: int|None = 5353) -> list[Packet]:
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
        pkt_any = (PrototypeIPv6Packet.get_frame_mdns_custom_payload(src_mac, src_ip, 
            DNS(rd=1, qd=DNSQR(qname=qname, qtype=255, qclass=1, unicastresponse=unicastresponse)),
            PrototypeIPv6Packet.__get_l4port_random() if sport is None else sport
            ))
        pkt_a = (PrototypeIPv6Packet.get_frame_mdns_custom_payload(src_mac, src_ip, 
            DNS(rd=1, qd=DNSQR(qname=qname, qtype=1, qclass=1, unicastresponse=unicastresponse)),
            PrototypeIPv6Packet.__get_l4port_random() if sport is None else sport
            ))
        pkt_aaaa = (PrototypeIPv6Packet.get_frame_mdns_custom_payload(src_mac, src_ip, 
            DNS(rd=1, qd=DNSQR(qname=qname, qtype=28, qclass=1, unicastresponse=unicastresponse)),
            PrototypeIPv6Packet.__get_l4port_random() if sport is None else sport
            ))
        return [pkt_a, pkt_aaaa, pkt_any]
    
    @staticmethod
    def get_frame_mdns_ptr(src_mac: str|None, src_ip: str|None, qname: str, unicastresponse: int = 0, sport: int|None = 5353) -> Packet:
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
                    DNS(rd=1, qd=DNSQR(qname=qname, qtype="PTR", unicastresponse=unicastresponse)),
                    PrototypeIPv6Packet.__get_l4port_random() if sport is None else sport))
    
    @staticmethod
    def get_frame_mdns_sd(src_mac: str|None, src_ip: str|None, unicastresponse: int = 0, sport: int|None = 5353) -> Packet:
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
            UDP(sport=PrototypeIPv6Packet.__get_l4port_random() if sport is None else sport, dport=5353) /
            DNS(id=33, rd=1, qd=DNSQR(qname="_services._dns-sd._udp.local.", qtype="PTR", unicastresponse=unicastresponse)))
    
    @staticmethod
    def get_frame_ra(prefix_len: int, network: str, source_mac: str, source_ip: str, rpref: int, chl: int, mtu: int|None, dns: list[str]|None) -> Packet:
        layer2 = Ether(src=source_mac)
        layer3 = IPv6(src=source_ip, dst=PrototypeIPv6Packet.ALL_NODES_IPV6_MULTICAST_IP)
        RA = ICMPv6ND_RA(prf=rpref, M=0, O=0, H=0, chlim=chl, routerlifetime=1800, reachabletime=0, retranstimer=0)
        Opt_LLAddr = ICMPv6NDOptSrcLLAddr(lladdr=source_mac)
        packet1 = layer2 / layer3 / RA
        Opt_PrefixInfo = ICMPv6NDOptPrefixInfo(prefixlen=prefix_len, A=1, prefix=network, validlifetime=1800, preferredlifetime=1800)
        packet1 /= Opt_PrefixInfo
        if mtu is not None:
            Opt_MTU = ICMPv6NDOptMTU(mtu=mtu)
            packet1 /= Opt_MTU
        if dns is not None:
            Opt_DNS = ICMPv6NDOptRDNSS(dns=dns, lifetime=1800)
            packet1 /= Opt_DNS
        packet1 /= Opt_LLAddr
        return packet1        
        
    @staticmethod
    def get_frame_ra_kill(prefix_len: int, network: str, source_mac: str|None, source_ip: str|None, rpref: int, chl: int, dns: list[str]|None) -> Packet:
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
    def get_init_mldv2_active_mode(src_mac: str|None, src_ip: str|None) -> list[Packet]:
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
    def get_init_mldv1_active_mode(src_mac: str|None, src_ip) -> list[Packet]:
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
    def get_finish_mldv2_active_mode(src_mac: str|None, src_ip: str|None) -> list[Packet]:
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
    def get_finish_mldv1_active_mode(src_mac: str|None, src_ip: str|None) -> list[Packet]:
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
    def get_init_mldv2_aggressive_mode(src_mac: str|None, src_ip: str|None) -> list[Packet]:
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
    def get_init_mldv1_aggressive_mode(src_mac: str|None, src_ip: str|None) -> list[Packet]:
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
    def get_finish_mldv2_aggressive_mode(src_mac: str|None, src_ip: str|None) -> list[Packet]:
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
    def get_finish_mldv1_aggressive_mode(src_mac: str|None, src_ip: str|None) -> list[Packet]:
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