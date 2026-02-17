
import random
import uuid

from scapy.all import Raw, Packet
from scapy.layers.inet6 import IPv6, ICMPv6MLQuery, ICMPv6EchoRequest, IPv6ExtHdrHopByHop, RouterAlert, IPv6ExtHdrDestOpt, HBHOptUnknown, ICMPv6ND_NS, ICMPv6NDOptSrcLLAddr, ICMPv6ND_NA, ICMPv6MLQuery2, ICMPv6ND_RS, ICMPv6ND_RA, ICMPv6NDOptRDNSS, ICMPv6NDOptMTU, ICMPv6NDOptPrefixInfo, ICMPv6NDOptDstLLAddr
from scapy.layers.inet import UDP
from scapy.layers.l2 import Ether
from scapy.layers.dhcp6 import DUID_LL, DHCP6OptElapsedTime, DHCP6OptIA_NA, DHCP6OptClientId, DHCP6_Solicit
from scapy.layers.llmnr import LLMNRQuery, LLMNRResponse
from scapy.layers.dns import DNS, DNSQR, DNSRR

class PrototypeIPv6Packet:
    # Extension headers
    EXT_HDR_DESTINATION_OPTION_TYPE = 128
    EXT_HDR_DESTINATION_OPTION_DATA = b''
    EXT_HDR_HOP_BY_HOP_TYPE = 255
    EXT_HDR_HOP_BY_HOP_DATA = b"\x00\x00\x00"
    # ICMPv6
    ICMPV6_INVALID_TYPE = 254

    # 
    # L3 Payloads
    #

    def get_l3payload_icmpv6_echo_request(id) -> Packet:
        """
        Returns ICMPv6 Echo Request packet with specified ID, without any extension headers.
        Does not include L2 and L3 headers, only the ICMPv6 payload.
        Args:
            id: Identifier field for the ICMPv6 Echo Request.
        Output:
            Packet: Scapy packet representing ICMPv6 Echo Request.
        """
        return ICMPv6EchoRequest(id=id)    
    
    def get_l3payload_icmpv6_echo_request_with_dest_opt(id) -> Packet:
        """
        Returns ICMPv6 Echo Request packet with destination option extension header.
        Does not include L2 and L3 headers, only the ICMPv6 payload with extension header.
        Args:
            id: Identifier field for the ICMPv6 Echo Request.
        Output:
            Packet: Scapy packet representing ICMPv6 Echo Request with destination option.
        """
        return (IPv6ExtHdrDestOpt(nh=58, 
                    options=[HBHOptUnknown(
                        otype=PrototypeIPv6Packet.EXT_HDR_DESTINATION_OPTION_TYPE,
                        optdata=PrototypeIPv6Packet.EXT_HDR_DESTINATION_OPTION_DATA)]) /
                ICMPv6EchoRequest(id=id))
        
    def get_l3payload_icmpv6_echo_request_with_hop_by_hop_opt(id) -> Packet:
        """
        Returns ICMPv6 Echo Request packet with hop-by-hop extension header.
        Does not include L2 and L3 headers, only the ICMPv6 payload with extension header.
        Args:
            id: Identifier field for the ICMPv6 Echo Request.
        Output:
            Packet: Scapy packet representing ICMPv6 Echo Request with hop-by-hop option.
        """
        return (IPv6ExtHdrHopByHop(
                    options=[HBHOptUnknown(
                        otype=PrototypeIPv6Packet.EXT_HDR_HOP_BY_HOP_TYPE, 
                        optdata=PrototypeIPv6Packet.EXT_HDR_HOP_BY_HOP_DATA)]) /
                ICMPv6EchoRequest(id=id))

    def get_l3payload_invalid_icmpv6_with_dest_opt(id) -> Packet:
        """
        Returns ICMPv6 Echo Request packet with invalid type and destination option extension header.
        Does not include L2 and L3 headers, only the ICMPv6 payload with extension header.
        Args:
            id: Identifier field for the ICMPv6 Echo Request.
        Output:
            Packet: Scapy packet representing ICMPv6 Echo Request with invalid type and destination option.
        """
        return (IPv6ExtHdrDestOpt(nh=58, 
                    options=[HBHOptUnknown(
                        otype=PrototypeIPv6Packet.EXT_HDR_DESTINATION_OPTION_TYPE,
                        optdata=PrototypeIPv6Packet.EXT_HDR_DESTINATION_OPTION_DATA)]) /
                ICMPv6EchoRequest(id=id, type=PrototypeIPv6Packet.ICMPV6_INVALID_TYPE))
    
    def get_l3payload_dhcpv6_solicit(src_mac) -> Packet:
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
        udp = UDP(sport=random.randint(49152, 65535), dport=3702)
        payload = Raw(load=soap_payload)
        return udp / payload
            
    # 
    # L3 Builders
    #

    def get_frame_llmnr_custom_payload(src_mac, src_ip, l4_payload) -> Packet:
        """
        Adds L2, L3, and L4 headers to the provided L4 payload to create a complete LLMNR query packet.
        Args:
            src_mac: Source MAC address for the LLMNR packet.
            src_ip: Source IPv6 address for the LLMNR packet.
            l4_payload: The L4 payload to be included in the LLMNR packet.
        Output:
            Packet: Scapy packet representing the complete LLMNR query with L2, L3, and L4 headers.
        """
        return (Ether(src=src_mac, dst="33:33:00:01:00:03") /
                IPv6(src=src_ip, dst="ff02::1:3", hlim=1) /
                UDP(sport=5355, dport=5355) /
                l4_payload)

    def get_frame_mdns_custom_payload(src_mac, src_ip, l4_payload) -> Packet:
        """
        Adds L2, L3, and L4 headers to the provided L4 payload to create a complete mDNS query packet.
        Args:
            src_mac: Source MAC address for the mDNS packet.
            src_ip: Source IPv6 address for the mDNS packet.
            l4_payload: The L4 payload to be included in the mDNS packet.
        Output:
            Packet: Scapy packet representing the complete mDNS query with L2, L3, and L4 headers.
        """
        return (Ether(src=src_mac, dst="33:33:00:00:00:fb") /
                IPv6(src=src_ip, dst="ff02::fb", hlim=1) /
                UDP(sport=5353, dport=5353) /
                l4_payload)

    def get_frame_mldv1(src_mac, src_ip) -> Packet:
        """
        Builds an MLDv1 Query packet with the specified source MAC and IPv6 addresses.
        The packet is constructed with appropriate L2 and L3 headers, and includes a Router Alert option in the hop-by-hop extension header.
        Args:
            src_mac: Source MAC address for the MLDv1 packet.
            src_ip: Source IPv6 address for the MLDv1 packet.
        Output:
            Packet: Scapy packet representing the MLDv1 Query.
        """
        return (Ether(src=src_mac, dst="33:33:00:00:00:01") /
                IPv6(src=src_ip, dst="ff02::1", hlim=1)/
                IPv6ExtHdrHopByHop(options=RouterAlert(otype=5, optlen=2, value=0)) /
                ICMPv6MLQuery(mrd=1, mladdr='::'))

    def get_frame_mldv2(src_mac, src_ip) -> Packet:
        """
        Builds an MLDv2 Query packet with the specified source MAC and IPv6 addresses.
        The packet is constructed with appropriate L2 and L3 headers, and includes a Router Alert option in the hop-by-hop extension header.
        Args:
            src_mac: Source MAC address for the MLDv2 packet.
            src_ip: Source IPv6 address for the MLDv2 packet.
        Output:
            Packet: Scapy packet representing the MLDv2 Query.
        """
        return (Ether(src=src_mac, dst="33:33:00:00:00:01") /
                IPv6(src=src_ip, dst="ff02::1", hlim=1)/
                IPv6ExtHdrHopByHop(options=RouterAlert(otype=5, optlen=2, value=0)) /
                ICMPv6MLQuery2(type=130, mladdr="::", sources=[], mrd=1, S=0, QRV=2, QQIC=125))
    
    def get_frame_llmnr_bundle_a_aaaa_any(src_mac, src_ip, qname) -> list[Packet]:
        pkt_any = PrototypeIPv6Packet.get_frame_llmnr_custom_payload(src_mac, src_ip,
            LLMNRQuery(qd=DNSQR(qname=qname, qtype=255, qclass=1)))
        pkt_a = PrototypeIPv6Packet.get_frame_llmnr_custom_payload(src_mac, src_ip,
            LLMNRQuery(qd=DNSQR(qname=qname, qtype=1, qclass=1)))
        pkt_aaaa = PrototypeIPv6Packet.get_frame_llmnr_custom_payload(src_mac, src_ip,
                    LLMNRQuery(qd=DNSQR(qname=qname, qtype=28, qclass=1)))
        return [pkt_a, pkt_aaaa, pkt_any]
    
    def get_frame_llmnr_ptr(src_mac, src_ip, qname) -> Packet:
        return (PrototypeIPv6Packet.get_frame_llmnr_custom_payload(src_mac, src_ip, 
            LLMNRQuery(qd=DNSQR(qname=qname, qtype="PTR"))))

    def get_frame_mdns_bundle_a_aaaa_any(src_mac, src_ip, qname, unicastresponse = 0) -> list[Packet]:
        pkt_any = (PrototypeIPv6Packet.get_frame_mdns_custom_payload(src_mac, src_ip, 
            DNS(rd=1, qd=DNSQR(qname=qname, qtype=255, qclass=1, unicastresponse=unicastresponse))))
        pkt_a = (PrototypeIPv6Packet.get_frame_mdns_custom_payload(src_mac, src_ip, 
            DNS(rd=1, qd=DNSQR(qname=qname, qtype=1, qclass=1, unicastresponse=unicastresponse))))
        pkt_aaaa = (PrototypeIPv6Packet.get_frame_mdns_custom_payload(src_mac, src_ip, 
            DNS(rd=1, qd=DNSQR(qname=qname, qtype=28, qclass=1, unicastresponse=unicastresponse))))
        return [pkt_a, pkt_aaaa, pkt_any]
    
    def get_frame_mdns_ptr(src_mac, src_ip, qname, unicastresponse = 0) -> Packet:
        return (PrototypeIPv6Packet.get_frame_mdns_custom_payload(src_mac, src_ip,
                    DNS(rd=1, qd=DNSQR(qname=qname, qtype="PTR", unicastresponse=unicastresponse))))