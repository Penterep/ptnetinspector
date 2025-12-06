import ipaddress
import random
import time
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
from ptnetinspector.utils.interface import Interface
from ptnetinspector.entities.mdns import MDNS
from ptnetinspector.entities.llmnr import LLMNR
from ptnetinspector.utils.ip_utils import reverse_IPadd


class ICMPType(Enum):
    ECHO_REQUEST = 8
    ROUTER_SOLICITATION = 10
    UNASSIGNED_255 = 255


class SendIPv4:
    @staticmethod
    def send_reverse_ipv4_MDNS(ip_address, interface):
        # Function to send an IPv4 mDNS PTR query and save the response to get the local name
        # Checking the existence of the interface
        exist_interface = Interface(interface).check_interface()

        if exist_interface:
            src_ip = get_if_addr(interface)
            if ip_address != src_ip:
                src_mac = get_if_hwaddr(interface)
                # Define the IPv4 address to query
                query = reverse_IPadd(ip_address)

                # Create an mDNS PTR query packet
                pkt = (Ether(src=src_mac, dst="01:00:5e:00:00:fb") /
                       IP(src=src_ip, dst="224.0.0.251", ttl=1) /
                       UDP(sport=5353, dport=5353) /
                       DNS(rd=1, qd=DNSQR(qname=query, qtype=12)))

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
    def send_mDNS_ipv4(query_name, interface):
        # Function to send an IPv4 mDNS query after getting the name
        # Checking the existence of the interface
        exist_interface = Interface(interface).check_interface()

        if exist_interface:
            src_ip = get_if_addr(interface)
            src_mac = get_if_hwaddr(interface)
            # Create the IPv4 and UDP packets and send the mDNS query
            query_name = MDNS.full_name_MDNS(query_name)
            pkt_any = (Ether(src=src_mac, dst="01:00:5e:00:00:fb") /
                       IP(src=src_ip, dst='224.0.0.251', ttl=1) /
                       UDP(sport=5353, dport=5353) /
                       DNS(rd=1, qd=DNSQR(qname=query_name, qtype=255, qclass=1)))
            pkt_a = (Ether(src=src_mac, dst="01:00:5e:00:00:fb") /
                     IP(src=src_ip, dst='224.0.0.251', ttl=1) /
                     UDP(sport=5353, dport=5353) /
                     DNS(rd=1, qd=DNSQR(qname=query_name, qtype=1, qclass=1)))
            pkt_aaaa = (Ether(src=src_mac, dst="01:00:5e:00:00:fb") /
                        IP(src=src_ip, dst='224.0.0.251', ttl=1) /
                        UDP(sport=5353, dport=5353) /
                        DNS(rd=1, qd=DNSQR(qname=query_name, qtype=28, qclass=1)))
            pkt = [pkt_a, pkt_aaaa, pkt_any]
            sendp(pkt, iface=interface, verbose=False)

    @staticmethod
    def send_reverse_ipv4_llmnr(ip_address, interface):
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
                pkt = (Ether(src=src_mac, dst="01:00:5e:00:00:fc") /
                       IP(src=src_ip, dst="224.0.0.252", ttl=1) /
                       UDP(sport=5355, dport=5355) /
                       LLMNRQuery(qd=DNSQR(qname=query, qtype="PTR")))

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
    def send_llmnr_ipv4(name, interface):
        # Checking the existence of the interface
        exist_interface = Interface(interface).check_interface()

        if exist_interface:
            src_ip = get_if_addr(interface)
            src_mac = get_if_hwaddr(interface)
            # Create the IPv4 and UDP packets and send the LLMNR query
            name = LLMNR.full_name_llmnr(name)

            pkt_any = (Ether(src=src_mac, dst="01:00:5e:00:00:fc") /
                       IP(src=src_ip, dst="224.0.0.252", ttl=1) /
                       UDP(sport=53550, dport=5355) /
                       DNS(rd=1, qd=DNSQR(qname=name, qtype=255, qclass=1)))

            pkt_a = (Ether(src=src_mac, dst="01:00:5e:00:00:fc") /
                     IP(src=src_ip, dst="224.0.0.252", ttl=1) /
                     UDP(sport=53550, dport=5355) /
                     DNS(rd=1, qd=DNSQR(qname=name, qtype=1, qclass=1)))

            pkt_aaaa = (Ether(src=src_mac, dst="01:00:5e:00:00:fc") /
                        IP(src=src_ip, dst="224.0.0.252", ttl=1) /
                        UDP(sport=53550, dport=5355) /
                        DNS(rd=1, qd=DNSQR(qname=name, qtype=28, qclass=1)))

            pkt = [pkt_a, pkt_aaaa, pkt_any]
            sendp(pkt, iface=interface, verbose=False)

    @staticmethod
    def IPv4_test_mdns_llmnr(ip_address, interface):
        # This function runs various tests on an IPv4 address, including reverse LLMNR, mDNS, and regular LLMNR
        if get_if_addr(interface) == "0.0.0.0":
            return
        name = SendIPv4.send_reverse_ipv4_llmnr(ip_address, interface)

        if name is not None:
            SendIPv4.send_mDNS_ipv4(name, interface)
            SendIPv4.send_llmnr_ipv4(name, interface)
            return
        name = SendIPv4.send_reverse_ipv4_MDNS(ip_address, interface)

        if name is not None:
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
            arp_request = ARP(pdst=address)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")

            pkt = ether / arp_request

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
        exist_interface = Interface(interface).check_interface()

        if exist_interface:
            ipv4_addresses = Interface(interface).get_interface_ipv4_ips()

            for source_ipv4_addr in ipv4_addresses:
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
                ether = Ether(src=get_if_hwaddr(interface))
                ipv4 = IP(src=source_ipv4_addr, dst="239.255.255.250", ttl=1)
                udp = UDP(sport=random.randint(49152, 65535), dport=3702)
                payload = Raw(load=soap_payload)
                wsd_packet = ether / ipv4 / udp / payload

                sendp(wsd_packet, verbose=0, iface=interface)

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

            for source_ipv4_addr in ipv4_addresses:

                mac = Ether(src=get_if_hwaddr(interface), dst="01:00:5e:00:00:01")
                ipv4_packet = IP(src=source_ipv4_addr, dst="224.0.0.1", ttl=1)

                match version:
                    case 1:
                        igmp_query = IGMP(type=0x11, mrcode=0, gaddr=spec_group)
                    case 2:
                        igmp_query = IGMP(type=0x11, mrcode=2, gaddr=spec_group)
                    case 3:
                        igmp_query = IGMPv3(type=0x11, mrcode=2) / IGMPv3mq(gaddr=spec_group)

                query = mac / ipv4_packet / igmp_query

                sendp(query*2, verbose=0, iface=interface)

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
        id_query = 111

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