from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import UDP, IP
from scapy.layers.l2 import Ether, ARP
from scapy.layers.llmnr import LLMNRQuery, LLMNRResponse
from src.interface import Interface, reverse_IPadd
from src.device.mdns import mDNS
from src.device.llmnr import LLMNR


class SendIPv4:
    @staticmethod
    def send_reverse_ipv4_mDNS(ip_address, interface):
        # Function to send an IPv4 mDNS PTR query and save the response to get the local name
        # Checking the existence of the interface
        exist_interface = Interface(interface).check_interface()

        if exist_interface:
            src_ip = get_if_addr(
                interface)  # It will return 0.0.0.0 if there is no IPv4 address on interface, so no need to check the availability
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
                        except (IndexError, AttributeError, KeyError) as e:
                            return None
                    except (IndexError, AttributeError, KeyError) as e:
                        return None
                return None

    @staticmethod
    def send_mDNS_ipv4(query_name, interface):
        # Function to send an IPv6 mDNS query after getting the name
        # Checking the existence of the interface
        exist_interface = Interface(interface).check_interface()

        if exist_interface:
            src_ip = get_if_addr(interface) # It will return 0.0.0.0 if there is no IPv4 address on interface, so no need to check the availability
            src_mac = get_if_hwaddr(interface)
            # Create the IPv6 and UDP packets and send the mDNS query
            query_name = mDNS.full_name_mdns(query_name)
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
        # Function to send an IPv4 mDNS PTR query and save the response to get the local name
        # Checking the existence of the interface
        exist_interface = Interface(interface).check_interface()

        if exist_interface:
            src_ip = get_if_addr(
                interface)  # It will return 0.0.0.0 if there is no IPv4 address on interface, so no need to check the availability
            if ip_address != src_ip:
                src_mac = get_if_hwaddr(interface)
                # Define the IPv4 address to query
                query = reverse_IPadd(ip_address)

                # Create an mDNS PTR query packet
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
                    if packet.haslayer(UDP) and packet.haslayer(LLMNRResponse) and packet[DNSRR].rrname.decode("utf-8")[
                                                                                   :-1] == query:
                        # print(packet[DNSRR].rdata.decode("utf-8"))
                        return packet[DNSRR].rdata.decode("utf-8")

    @staticmethod
    def send_llmnr_ipv4(name, interface):
        # Checking the existence of the interface
        exist_interface = Interface(interface).check_interface()

        if exist_interface:
            src_ip = get_if_addr(
                interface)  # It will return 0.0.0.0 if there is no IPv4 address on interface, so no need to check the availability
            src_mac = get_if_hwaddr(interface)
            # Create the IPv6 and UDP packets and send the mDNS query
            name = LLMNR.full_name_llmnr(name)

            pkt_any = (Ether(src=src_mac, dst="01:00:5e:00:00:fc") /
                       IP(src=src_ip, dst="224.0.0.252", ttl=1) /  # LLMNR multicast IP address
                       UDP(sport=53550, dport=5355) /
                       DNS(rd=1, qd=DNSQR(qname=name, qtype=255, qclass=1))
                       )

            pkt_a = (Ether(src=src_mac, dst="01:00:5e:00:00:fc") /
                     IP(src=src_ip, dst="224.0.0.252", ttl=1) /  # LLMNR multicast IP address
                     UDP(sport=53550, dport=5355) /
                     DNS(rd=1, qd=DNSQR(qname=name, qtype=1, qclass=1))
                     )

            pkt_aaaa = (Ether(src=src_mac, dst="01:00:5e:00:00:fc") /
                        IP(src=src_ip, dst="224.0.0.252", ttl=1) /  # LLMNR multicast IP address
                        UDP(sport=53550, dport=5355) /
                        DNS(rd=1, qd=DNSQR(qname=name, qtype=28, qclass=1))
                        )

            pkt = [pkt_a, pkt_aaaa, pkt_any]
            sendp(pkt, iface=interface, verbose=False)

    @staticmethod
    def IPv4_test_mdns_llmnr(ip_address, interface):
        # This function runs various tests on an IPv4 address, including reverse LLMNR, mDNS, and regular LLMNR
        if get_if_addr(interface) == "0.0.0.0":
            return
        name = SendIPv4.send_reverse_ipv4_llmnr(ip_address, interface)
        # print(f"IPv4 LLMNR: {name}")

        if name != None:
            SendIPv4.send_mDNS_ipv4(name, interface)
            SendIPv4.send_llmnr_ipv4(name, interface)
            return
        name = SendIPv4.send_reverse_ipv4_mDNS(ip_address, interface)
        # print(f"IPv4 mDNS: {name}")

        if name != None:
            SendIPv4.send_mDNS_ipv4(name, interface)
            SendIPv4.send_llmnr_ipv4(name, interface)
            return

    @staticmethod
    def send_arp_request(address: str, interface: str) -> None:
        """
        Send an ARP request to an IPv4 address.

        Args:
            address (str): The IPv4 address
            interface (str): The network interface to use
        """
        try:
            arp_request = ARP(pdst=address)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")

            pkt = ether / arp_request

            sendp(pkt, verbose=0, iface=interface)

        except Exception:
            pass
