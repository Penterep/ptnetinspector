import ipaddress
import csv

from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.eap import EAPOL
from scapy.layers.inet import UDP, IP
from scapy.layers.inet6 import IPv6, ICMPv6MLQuery, ICMPv6EchoRequest, IPv6ExtHdrHopByHop, RouterAlert, \
    IPv6ExtHdrDestOpt, HBHOptUnknown, ICMPv6EchoReply, ICMPv6ND_NS, ICMPv6NDOptSrcLLAddr, ICMPv6ND_NA, ICMPv6MLQuery2, \
    ICMPv6MLReport2, ICMPv6MLDMultAddrRec, ICMPv6MLReport, ICMPv6MLDone, ICMPv6ND_RS, ICMPv6ND_RA, ICMPv6NDOptRDNSS, \
    ICMPv6NDOptMTU, ICMPv6NDOptPrefixInfo, ICMPv6NDOptDstLLAddr, ICMPv6ParamProblem
from scapy.layers.l2 import Ether, ARP
from scapy.layers.llmnr import LLMNRQuery, LLMNRResponse
from src.interface import Interface
from src.device.mdns import mDNS
from src.device.llmnr import LLMNR
from libs.check import is_global_unicast_ipv6, is_ipv6_ula, is_valid_ipv6, is_link_local_ipv6, has_additional_data
from libs.convert import generate_global_ipv6, generate_random_global_ipv6, collect_unique_items

class Send:
    
    def reverse_IPadd(ip_address):
        # Function to create a reverse pointer record from an IP address
        return ipaddress.ip_address(ip_address).reverse_pointer
    
    def send_8021x_security(interface):
        # Checking the existence of the interface
        # This function tests 802.1x security by sending an EAPOL packet and looking for a response
        exist_interface = Interface(interface).check_interface()

        if exist_interface:
            src_mac = get_if_hwaddr(interface)
            # Create an EAPOL packet
            eapol = Ether(src=src_mac, dst="01:80:c2:00:00:03") / EAPOL(version=1, type=1)

            # Send the EAPOL packet on the specified interface
            sendp(eapol, iface=interface, verbose=False)

    def send_normal_multicast_ping(interface):
        # Checking the existence of the interface
        exist_interface = Interface(interface).check_interface()

        if exist_interface:
            avail_ipv6 = Interface(interface).check_available_ipv6
            if avail_ipv6:
                # Function to test IPv6 ping
                ip_addresses = Interface(interface).get_interface_ips()
                src_mac = get_if_hwaddr(interface)
                for ip in ip_addresses:
                    try:
                        ipaddress.IPv4Address(ip)
                        continue
                    except ipaddress.AddressValueError:
                        pass
                    try:
                        ipaddress.IPv6Address(ip)
                        src_ip = ip
                        pkt = (Ether(src=src_mac, dst="33:33:00:00:00:01") /
                            IPv6(src=src_ip, dst="ff02::1") /
                            ICMPv6EchoRequest())
                        sendp(pkt, iface=interface, verbose=False)
                    except ipaddress.AddressValueError:
                        pass
    
    def send_invalid_multicast_icmpv6(interface):
        # Checking the existence of the interface
        exist_interface = Interface(interface).check_interface()

        if exist_interface:
            avail_ipv6 = Interface(interface).check_available_ipv6
            if avail_ipv6:

                # Function to send invalid ICMPv6 packets
                ip_addresses = Interface(interface).get_interface_ips()
                src_mac = get_if_hwaddr(interface)
           
                for ip in ip_addresses:
                    try:
                        ipaddress.IPv4Address(ip)
                        continue
                    except ipaddress.AddressValueError:
                        pass
                    try:
                        ipaddress.IPv6Address(ip)
                        src_ip = ip
                        pkt = (Ether(src=src_mac, dst="33:33:00:00:00:01") /
                            IPv6(src=src_ip, dst="ff02::1") /
                            IPv6ExtHdrDestOpt(nh=58, options=[HBHOptUnknown(otype=128)]) /
                            ICMPv6EchoRequest(type=254))
                        sendp(pkt, iface=interface, verbose=False)
                    except ipaddress.AddressValueError:
                        pass
    
    def send_invalid_multicast_ping(interface):
        # Checking the existence of the interface
        exist_interface = Interface(interface).check_interface()

        if exist_interface:
            avail_ipv6 = Interface(interface).check_available_ipv6
            if avail_ipv6:
                # Function to send invalid Ipv6 ping
                ip_addresses = Interface(interface).get_interface_ips()
                src_mac = get_if_hwaddr(interface)
            
                for ip in ip_addresses:
                    try:
                        ipaddress.IPv4Address(ip)
                        continue
                    except ipaddress.AddressValueError:
                        pass
                    try:
                        ipaddress.IPv6Address(ip)
                        src_ip = ip
                        pkt = (Ether(src=src_mac, dst="33:33:00:00:00:01") /
                            IPv6(src=src_ip, dst="ff02::1") /
                            IPv6ExtHdrDestOpt(nh=58, options=[HBHOptUnknown(otype=128)]) /
                            ICMPv6EchoRequest())
                        sendp(pkt, iface=interface, verbose=False)
                    except ipaddress.AddressValueError:
                        pass

    def send_invalid_ipv6_hbh(interface):
        # Checking the existence of the interface
        exist_interface = Interface(interface).check_interface()

        if exist_interface:
            avail_ipv6 = Interface(interface).check_available_ipv6
            if avail_ipv6:
                # Function to send invalid IPv6 HBH packet
                ip_addresses = Interface(interface).get_interface_ips()
                src_mac = get_if_hwaddr(interface)

                for ip in ip_addresses:
                    try:
                        ipaddress.IPv4Address(ip)
                        continue
                    except ipaddress.AddressValueError:
                        pass
                    try:
                        ipaddress.IPv6Address(ip)
                        src_ip = ip
                        pkt = (Ether(src=src_mac, dst="33:33:00:00:00:01") /
                               IPv6(src=src_ip, dst="ff02::1", hlim=255) /
                               IPv6ExtHdrHopByHop(
                                   options=[HBHOptUnknown(otype=255, optdata=b"\x00\x00\x00")]) /
                               ICMPv6EchoRequest())
                        sendp(pkt, iface=interface, verbose=False)
                    except ipaddress.AddressValueError:
                        pass
    
    def send_multicast_ping_router(interface):
        # Function to send an IPv6 ping to a router multicast address
        # Checking the existence of the interface
        exist_interface = Interface(interface).check_interface()

        if exist_interface:
            avail_ipv6 = Interface(interface).check_available_ipv6
            if avail_ipv6:
                # Function to send invalid Ipv6 ping
                ip_addresses = Interface(interface).get_interface_link_local_list()
                src_mac = get_if_hwaddr(interface)
            
                pkt = (Ether(src=src_mac, dst="33:33:00:00:00:02") /
                    IPv6(src=ip_addresses, dst="ff02::2") /
                    ICMPv6EchoRequest())
                sendp(pkt, iface=interface, verbose=False)
    
    def send_ns_router(ipv6_address, mac, interface):
        # Function to send an IPv6 Neighbor Solicitation to a router
        # Checking the existence of the interface
        exist_interface = Interface(interface).check_interface()

        if exist_interface:
            avail_ipv6 = Interface(interface).check_available_ipv6
            if avail_ipv6:
                # Function to send invalid Ipv6 ping
                ip_addresses = Interface(interface).get_interface_link_local_list()
                src_mac = get_if_hwaddr(interface)

                pkt = (Ether(src=src_mac, dst=mac) /
                    IPv6(src=ip_addresses, dst=ipv6_address) /
                    ICMPv6ND_NS(tgt=ipv6_address) /
                    ICMPv6NDOptSrcLLAddr(lladdr=src_mac))
                sendp(pkt, iface=interface, verbose=False)
    
    def send_reverse_ipv6_mDNS(ipv6_address, interface):
        # Function to send an IPv6 mDNS PTR query and save the response to get the local name
        # Checking the existence of the interface
        exist_interface = Interface(interface).check_interface()

        if exist_interface:
            avail_ipv6 = Interface(interface).check_available_ipv6
            if avail_ipv6:
                src_mac = get_if_hwaddr(interface)
                query = Send.reverse_IPadd(ipv6_address)
                src_ip = Interface(interface).get_interface_link_local_list()
                interface_ip_addresses = Interface(interface).get_interface_ips()

                if ipv6_address in interface_ip_addresses or ipv6_address == src_ip[:-5]:
                    pass
                else:
                    # Construct the mDNS packet with the PTR query
                    pkt = (Ether(src=src_mac, dst="33:33:00:00:00:fb") /
                        IPv6(src=src_ip, dst="ff02::fb", hlim=1) /
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

    def send_reverse_ipv4_mDNS(ip_address, interface):
        # Function to send an IPv4 mDNS PTR query and save the response to get the local name
        # Checking the existence of the interface
        exist_interface = Interface(interface).check_interface()

        if exist_interface:
            src_ip = get_if_addr(interface) # It will return 0.0.0.0 if there is no IPv4 address on interface, so no need to check the availability
            if ip_address != src_ip:
                src_mac = get_if_hwaddr(interface)
                # Define the IPv4 address to query
                query = Send.reverse_IPadd(ip_address)
                
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
    
    def send_mDNS_ipv6(query_name, interface):
        # Function to send an IPv6 mDNS query after getting the name
        # Checking the existence of the interface
        exist_interface = Interface(interface).check_interface()

        if exist_interface:
            avail_ipv6 = Interface(interface).check_available_ipv6
            if avail_ipv6:
                src_mac = get_if_hwaddr(interface)
                # Create the IPv6 and UDP packets and send the mDNS query
                query_name = mDNS.full_name_mdns(query_name)
                src_ip = Interface(interface).get_interface_link_local_list()
                pkt_any = (Ether(src=src_mac, dst="33:33:00:00:00:fb") /
                        IPv6(src=src_ip, dst="ff02::fb", hlim=1) /
                        UDP(sport=5353, dport=5353) /
                        DNS(rd=1, qd=DNSQR(qname=query_name, qtype=255, qclass=1)))

                pkt_a = (Ether(src=src_mac, dst="33:33:00:00:00:fb") /
                        IPv6(src=src_ip, dst="ff02::fb", hlim=1) /
                        UDP(sport=5353, dport=5353) /
                        DNS(rd=1, qd=DNSQR(qname=query_name, qtype=1, qclass=1)))

                pkt_aaaa = (Ether(src=src_mac, dst="33:33:00:00:00:fb") /
                            IPv6(src=src_ip, dst="ff02::fb", hlim=1) /
                            UDP(sport=5353, dport=5353) /
                            DNS(rd=1, qd=DNSQR(qname=query_name, qtype=28, qclass=1)))

                pkt = [pkt_a, pkt_aaaa, pkt_any]
                sendp(pkt, iface=interface, verbose=False)
  
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
    
    def send_reverse_ipv6_llmnr(ipv6_address, interface):
        # This function sends an IPv6 LLMNR request to reverse lookup the domain name associated with the IP address on a given interface
        # Checking the existence of the interface
        exist_interface = Interface(interface).check_interface()

        if exist_interface:
            avail_ipv6 = Interface(interface).check_available_ipv6
            if avail_ipv6:
                src_mac = get_if_hwaddr(interface)
                query = Send.reverse_IPadd(ipv6_address)
                src_ip = Interface(interface).get_interface_link_local_list()
                interface_ip_addresses = Interface(interface).get_interface_ips()

                if ipv6_address in interface_ip_addresses or ipv6_address == src_ip[:-5]:
                    pass
                else:
                    # Construct the mDNS packet with the PTR query
                    pkt = (Ether(src=src_mac, dst="33:33:00:01:00:03") /
                            IPv6(src=src_ip, dst="ff02::1:3", hlim=1) /
                            UDP(sport=5355, dport=5355) /
                            LLMNRQuery(qd=DNSQR(qname=query, qtype="PTR")))
                    
                    response = AsyncSniffer(iface=interface)
                    response.start()
                    time.sleep(0.1)
                    sendp(pkt, iface=interface, verbose=False)
                    time.sleep(0.1)
                    # Parse the domain name from the response
                    response.stop()
                    for packet in response.results:
                        if packet.haslayer(UDP) and packet.haslayer(LLMNRResponse) and packet[DNSRR].rrname.decode("utf-8")[:-1] == query:
                            return packet[DNSRR].rdata.decode("utf-8")
    
    def send_reverse_ipv4_llmnr(ip_address, interface):
        # Function to send an IPv4 mDNS PTR query and save the response to get the local name
        # Checking the existence of the interface
        exist_interface = Interface(interface).check_interface()

        if exist_interface:
            src_ip = get_if_addr(interface) # It will return 0.0.0.0 if there is no IPv4 address on interface, so no need to check the availability
            if ip_address != src_ip:
                src_mac = get_if_hwaddr(interface)
                # Define the IPv4 address to query
                query = Send.reverse_IPadd(ip_address)
                
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
                    if packet.haslayer(UDP) and packet.haslayer(LLMNRResponse) and packet[DNSRR].rrname.decode("utf-8")[:-1] == query:
                        # print(packet[DNSRR].rdata.decode("utf-8"))
                        return packet[DNSRR].rdata.decode("utf-8")

    def send_llmnr_ipv4(name, interface):
        # Checking the existence of the interface
        exist_interface = Interface(interface).check_interface()

        if exist_interface:
            src_ip = get_if_addr(interface) # It will return 0.0.0.0 if there is no IPv4 address on interface, so no need to check the availability
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
    
    def send_llmnr_ipv6(name, interface):
        # Checking the existence of the interface
        exist_interface = Interface(interface).check_interface()

        if exist_interface:
            avail_ipv6 = Interface(interface).check_available_ipv6
            if avail_ipv6:
                src_mac = get_if_hwaddr(interface)
                # Create the IPv6 and UDP packets and send the mDNS query
                name = LLMNR.full_name_llmnr(name)
                src_ip = Interface(interface).get_interface_link_local_list()
                pkt_any = (Ether(src=src_mac, dst="33:33:00:01:00:03") /
                        IPv6(src=src_ip, dst="ff02::1:3", hlim=1) /  # LLMNR multicast IPv6 address
                        UDP(sport=53550, dport=5355) /
                        DNS(rd=1, qd=DNSQR(qname=name, qtype=255, qclass=1))
                        )

                pkt_a = (Ether(src=src_mac, dst="33:33:00:01:00:03") /
                        IPv6(src=src_ip, dst="ff02::1:3", hlim=1) /  # LLMNR multicast IPv6 address
                        UDP(sport=53550, dport=5355) /
                        DNS(rd=1, qd=DNSQR(qname=name, qtype=1, qclass=1))
                        )

                pkt_aaaa = (Ether(src=src_mac, dst="33:33:00:01:00:03") /
                            IPv6(src=src_ip, dst="ff02::1:3", hlim=1) /  # LLMNR multicast IPv6 address
                            UDP(sport=53550, dport=5355) /
                            DNS(rd=1, qd=DNSQR(qname=name, qtype=28, qclass=1))
                            )

                pkt = [pkt_a, pkt_aaaa, pkt_any]
                sendp(pkt, iface=interface, verbose=False)

    def IPv4_test_mdns_llmnr(ip_address, interface):
        # This function runs various tests on an IPv4 address, including reverse LLMNR, mDNS, and regular LLMNR
        if get_if_addr(interface) == "0.0.0.0":
            return
        name = Send.send_reverse_ipv4_llmnr(ip_address, interface)
        # print(f"IPv4 LLMNR: {name}")

        if name != None:
            Send.send_mDNS_ipv4(name, interface)
            Send.send_llmnr_ipv4(name, interface)
            return
        name = Send.send_reverse_ipv4_mDNS(ip_address, interface)
        # print(f"IPv4 mDNS: {name}")

        if name != None:
            Send.send_mDNS_ipv4(name, interface)
            Send.send_llmnr_ipv4(name, interface)
            return
    
    def IPv6_test_mdns_llmnr(ip_address, interface):
        name = Send.send_reverse_ipv6_llmnr(ip_address, interface)
        # print(f"IPv6 LLMNR: {name}")
        if name != None:
            Send.send_mDNS_ipv6(name, interface)
            Send.send_llmnr_ipv6(name, interface)
            return
        name = Send.send_reverse_ipv6_mDNS(ip_address, interface)
        # print(f"IPv6 mDNS: {name}")
        if name != None:
            Send.send_mDNS_ipv6(name, interface)
            Send.send_llmnr_ipv6(name, interface)
            return
    
    def send_llmnr_mdns(interface):
        # Function to send LLMNR and mDNS to find the addresses both in layer IP and Payload
        with open('src/tmp/addresses.csv', newline='') as csvfile:
            # Create a CSV reader object
            reader = csv.reader(csvfile, delimiter=',')
            next(reader)
            
            # Loop over each row in the CSV file
            for row in reader:

                if len(row) < 2: # Avoid the situation like this [':fffb:8']
                    continue
                ip_address = row[1]

                if is_valid_ipv6(ip_address):
                    if is_link_local_ipv6(ip_address):
                        Send.IPv6_test_mdns_llmnr(ip_address, interface)
                        
                    elif is_global_unicast_ipv6(ip_address):
                        Send.IPv6_test_mdns_llmnr(ip_address, interface)
                        
                    elif is_ipv6_ula(ip_address):
                        Send.IPv6_test_mdns_llmnr(ip_address, interface)
                       
                else:
                    try:
                        ipv4_address = ipaddress.IPv4Address(ip_address)

                        if ipv4_address.is_link_local:
                            continue
                        elif ipv4_address.is_unspecified:
                            continue
                        else:
                            Send.IPv4_test_mdns_llmnr(ip_address, interface)
                    except ipaddress.AddressValueError:
                        continue

    def send_MLD_query(interface):
        # Checking the existence of the interface
        exist_interface = Interface(interface).check_interface()

        if exist_interface:
            avail_ipv6 = Interface(interface).check_available_ipv6
            if avail_ipv6:
                src_mac = get_if_hwaddr(interface)
                src_ip = Interface(interface).get_interface_link_local_list()
                # Function to send an MLD query (two versions) to an IPv6 multicast address
                mac = Ether(src=src_mac, dst="33:33:00:00:00:01")
                # Create an IPv6 packet with a hop limit of 1 and a multicast source address
                ipv6_packet = IPv6(src=src_ip, dst="ff02::1", hlim=1)

                # Create an IPv6 Extension Header for Hop-by-Hop options with Router Alert
                hbh_header = IPv6ExtHdrHopByHop(options=RouterAlert(otype=5, optlen=2, value=0))

                # Create an MLD query message with a maximum response delay of 10 seconds, querying for the specific multicast group
                mld_query_v1 = ICMPv6MLQuery(mrd=1, mladdr='::')
                mld_query_v2 = ICMPv6MLQuery2(type=130, mladdr="::", sources=[], mrd=1, S=0, QRV=2, QQIC=125)

                # Add the Hop-by-Hop Options header to the IPv6 packet
                query_v1 = mac / ipv6_packet / hbh_header / mld_query_v1
                query_v2 = mac / ipv6_packet / hbh_header / mld_query_v2

                # Send the MLD query packet
                sendp(query_v2*2, iface=interface, verbose=False)
                time.sleep(0.1)
                sendp(query_v1*2, iface=interface, verbose=False)
     
    def send_RS(interface):
        # Sending RS to find out about router and its information
        # Checking the existence of the interface
        exist_interface = Interface(interface).check_interface()

        if exist_interface:
            avail_ipv6 = Interface(interface).check_available_ipv6
            if avail_ipv6:
                src_mac = get_if_hwaddr(interface)
                src_ip = Interface(interface).get_interface_link_local_list()               
                mac = Ether(src=src_mac, dst="33:33:00:00:00:02")

                # Create an RS packet
                ipv6_packet = IPv6(src=src_ip, dst="ff02::2", hlim=255)
                pkt = mac / ipv6_packet / ICMPv6ND_RS() / ICMPv6NDOptSrcLLAddr(lladdr=src_mac)

                # Send the RS packet 
                sendp(pkt, iface=interface, verbose=False)
      
    def send_RA(interface, prefix_len, network, source_mac, source_ip, rpref, chl, mtu, dns, aggressive_mode, period, duration):
        # Function to be a fake router and send Router Advertisement to all nodes
        # Checking the existence of the interface
        exist_interface = Interface(interface).check_interface()

        if exist_interface:
            # Build the layers in protocol
            layer2 = Ether(src=source_mac, dst="33:33:00:00:00:01")
            layer3 = IPv6(src=source_ip, dst="ff02::1")

            RA = ICMPv6ND_RA(prf=rpref, M=0, O=0, H=0, chlim=chl, routerlifetime=1800, reachabletime=0, retranstimer=0)
            
            kill_RA = ICMPv6ND_RA(prf=rpref, M=0, O=0, H=0, chlim=chl, routerlifetime=0, reachabletime=0, retranstimer=0)

            Opt_LLAddr = ICMPv6NDOptSrcLLAddr(lladdr=source_mac)

            packet1 = layer2 / layer3 / RA

            Opt_PrefixInfo = ICMPv6NDOptPrefixInfo(prefixlen=prefix_len, A=1, prefix=network,
                                                    validlifetime=1800, preferredlifetime=1800)
            
            kill_Opt_PrefixInfo = ICMPv6NDOptPrefixInfo(prefixlen=prefix_len, A=1, prefix=network,
                                                    validlifetime=0, preferredlifetime=0)
                
            # Add the prefix layer to protocol
            packet1 /= Opt_PrefixInfo

            if mtu is not None:
                Opt_MTU = ICMPv6NDOptMTU(mtu=mtu)
                packet1 /= Opt_MTU

            if dns is not None:
                Opt_DNS = ICMPv6NDOptRDNSS(dns=dns, lifetime=1800)
                kill_Opt_DNS = ICMPv6NDOptRDNSS(dns=dns, lifetime=0)
                packet1 /= Opt_DNS

            # Last packet is killing router to reset the role of sender
            kill_packet1 = layer2/layer3/kill_RA/kill_Opt_PrefixInfo
            if dns is not None:
                kill_packet1 /= kill_Opt_DNS

            # Add the link-layer information to protocol
            packet1 /= Opt_LLAddr
            kill_packet1 /= Opt_LLAddr

            
            if aggressive_mode and period is not None:
                # Send Router Advertisement periodically
                start_time = time.time()
                # Loop until 10 seconds have passed
                while time.time() - start_time <= duration+0.5:
                    # Send the packet
                    sendp(packet1, verbose=False, iface=interface)

                    if time.time() - start_time >= duration:
                        sendp(kill_packet1, verbose=False, iface=interface)
                        break

                    # Wait for the period before sending the next packet
                    time.sleep(period)      
                
              
            else:
                # Send Router Advertisement
                sendp(packet1, verbose=False, iface=interface)
    

    def generate_more_possible_IP(interface):
        # Generate possible IP and store in a dictionary
        src_mac = get_if_hwaddr(interface)
        mac_ips = {}  # Create a dictionary to store MAC:IPs for link-local address and then replacing by new global IP
        mac_ips_global_old = {}  # Create a dictionary to store MAC:IPs for global address
        prefix_list = []

        # Find all link-local addresses in the file
        with open("src/tmp/addresses.csv", 'r') as csv_file:
            reader = csv.reader(csv_file)
            headers = next(reader)  # Read the header row

            # Get the index of 'MAC' and 'IP' columns
            mac_index = headers.index('MAC')
            ip_index = headers.index('IP')

            # Loop through each row in the CSV file
            for row in reader:
                mac = row[mac_index]
                ip = row[ip_index]
                if mac == src_mac:  # Skip if MAC is the same as the source MAC
                    continue
                if mac not in mac_ips:  # If MAC is not in the dictionary, add it
                    mac_ips[mac] = []
                    mac_ips_global_old[mac] = []

                try:  # Convert IP to IP address object and validate
                    ip_address = ipaddress.IPv6Address(ip)
                    if ip_address.is_link_local:  # Filter out link-local IPv6 addresses
                        mac_ips[mac].append(ip)
                    if is_global_unicast_ipv6(str(ip_address)):
                        mac_ips_global_old[mac].append(ip)
                except ValueError:  # If IP is not valid, skip this row
                    pass

        # Find all prefix to match with link-local addresses
        if has_additional_data("src/tmp/RA.csv") is True:

            with open("src/tmp/RA.csv", 'r') as csv_file:
                reader = csv.reader(csv_file)
                headers = next(reader)  # Read the header row
                prefix_index = headers.index('Prefix')

                # Loop through each row in the CSV file
                for row in reader:
                    if row[prefix_index] not in prefix_list:
                        prefix_list.append(row[prefix_index])
                    else:
                        continue

        flag_error = 0
        # Generate new IPv6 addresses that can be client's IP
        if prefix_list != []:
            for mac, ip_ll in mac_ips.items():
                if ip_ll != []:
                    list_ip_generate_unit = []
                    for prefix in prefix_list:
                        new_global_ip = generate_global_ipv6(prefix, ip_ll[0])
                        # Check if this global IP is already detected before
                        if new_global_ip is not None:
                            if new_global_ip not in mac_ips_global_old[mac]:
                                list_ip_generate_unit.append(new_global_ip)
                    mac_ips[mac] = list_ip_generate_unit
                else:
                    flag_error = flag_error + 1
                    continue
        if prefix_list == [] or flag_error == len(mac_ips):
            return None

        return mac_ips
    
    def send_to_possible_IP(interface):
        # Getting all IP from scanner
        ip_addresses = Interface(interface).get_interface_ips()
        src_mac = get_if_hwaddr(interface)

        # Dictionary storing possible IP
        possible_global_IP = Send.generate_more_possible_IP(interface)
        if possible_global_IP is None:
            return

        # Sending normal unicast ping, invalid ICMP, invalid IPv6 ping 
        for ip in ip_addresses:
            try:
                ipaddress.IPv4Address(ip)
                continue
            except ipaddress.AddressValueError:
                pass
            
            try:
                ipaddress.IPv6Address(ip)
                src_ip = ip

                for mac, ips in possible_global_IP.items():
                    if ips != []:
                        for dst_ip in ips:
                            pkt1 = (Ether(src=src_mac, dst=mac) /
                                IPv6(src=src_ip, dst=dst_ip) /
                                ICMPv6EchoRequest())
                            pkt2 = (Ether(src=src_mac, dst=mac) /
                                IPv6(src=src_ip, dst=dst_ip) /
                                IPv6ExtHdrDestOpt(nh=58, options=[HBHOptUnknown(otype=128)]) /
                                ICMPv6EchoRequest(type=254))
                            pkt3 = (Ether(src=src_mac, dst=mac) /
                                IPv6(src=src_ip, dst=dst_ip) /
                                IPv6ExtHdrDestOpt(nh=58, options=[HBHOptUnknown(otype=128)]) /
                                ICMPv6EchoRequest())

                            sendp(pkt1, iface=interface, verbose=False)
                            sendp(pkt2, iface=interface, verbose=False)
                            sendp(pkt3, iface=interface, verbose=False)

            except ipaddress.AddressValueError:
                pass

        # Sending LLMNR and mDNS
        for mac, ips in possible_global_IP.items():
            if ips != []:
                for dst_ip in ips:
                    try:
                        dst_ip = ipaddress.IPv6Address(dst_ip)
                        Send.IPv6_test_mdns_llmnr(dst_ip, interface)
                    except ipaddress.AddressValueError:
                        continue

    def send_NA(interface, source_mac, target_mac, source_ip, target_ip, r_flag, s_flag, o_flag):
        # Checking the existence of the interface
        exist_interface = Interface(interface).check_interface()

        if exist_interface:
            # Build layers and send packet
            layer2 = Ether(src=source_mac, dst=target_mac)
            layer3 = IPv6(src=source_ip, dst=target_ip)
            packet1 = layer2 / layer3 / ICMPv6ND_NA(R=r_flag, S=s_flag, O=o_flag,
                                                    tgt=source_ip) / ICMPv6NDOptDstLLAddr(
                lladdr=source_mac)
            sendp(packet1, verbose=False, iface=interface)
    
    def react_to_NS_RS(interface, prefix_len, network, source_mac, source_ip, rpref, chl, mtu, dns, duration):
        # Becoming fake router and reacts to every NS or RS from other hosts
        def custom_action(packet):

            # Set option when dealing with Router Solicitation
            if ICMPv6ND_RS in packet and packet[0][1].src != source_ip:
                Send.send_RA(interface, prefix_len, network, source_mac, source_ip, rpref, chl, mtu, dns, False, None, None)

            # Set option when dealing with Neighbor Solicitation
            if ICMPv6ND_NS in packet and packet[0][1].src != source_ip:
                Send.send_NA(interface, source_mac, packet[0].src, source_ip, packet[0][1].src, 1, 1, 1)

        # Setup sniff, filtering for IP traffic to see the result
        build_filter = "ip6"

        try:
            sniff(iface=interface, filter=build_filter, prn=custom_action, timeout=duration)
        except KeyboardInterrupt:
            sys.exit(0)
    
    def send_to_test_RA_guard(interface):
        # Send unicast IPv6 packets to all hosts in the list from a remote host to check if there are any responses through attacker
        # Checking the existence of the interface
        exist_interface = Interface(interface).check_interface()

        # Generate possible IP and store in a dictionary
        src_mac = get_if_hwaddr(interface)
        mac_ips_global = {}  # Create a dictionary to store MAC:IPs for global address

        # Find all link-local addresses in the file
        with open("src/tmp/addresses.csv", 'r') as csv_file:
            reader = csv.reader(csv_file)
            headers = next(reader)  # Read the header row

            # Get the index of 'MAC' and 'IP' columns
            mac_index = headers.index('MAC')
            ip_index = headers.index('IP')

            # Loop through each row in the CSV file
            for row in reader:
                mac = row[mac_index]
                ip = row[ip_index]
                if mac == src_mac:  # Skip if MAC is the same as the source MAC
                    continue
                if mac not in mac_ips_global:  # If MAC is not in the dictionary, add it
                    mac_ips_global[mac] = []

                try:  # Convert IP to IP address object and validate
                    ip_address = ipaddress.IPv6Address(ip)
                    if is_global_unicast_ipv6(str(ip_address)):
                        mac_ips_global[mac].append(ip)
                except ValueError:  # If IP is not valid, skip this row
                    pass
        
        if exist_interface:
            src_mac = get_if_hwaddr(interface)
            dest_ip_list = collect_unique_items(mac_ips_global)
            sip = generate_random_global_ipv6(dest_ip_list)

            layer2 = Ether(src=src_mac)
            for mac, ips in mac_ips_global.items():
                if ips != []:
                    for dip in ips:
                        layer3 = IPv6(src=sip, dst=dip)
                        pkt1 = (layer2 /
                                layer3 /
                                ICMPv6EchoRequest())
                        pkt2 = (layer2 /
                                layer3 /
                                IPv6ExtHdrDestOpt(nh=58, options=[HBHOptUnknown(otype=128)]) /
                                ICMPv6EchoRequest(type=254))
                        pkt3 = (layer2 /
                                layer3 /
                                IPv6ExtHdrDestOpt(nh=58, options=[HBHOptUnknown(otype=128)]) /
                                ICMPv6EchoRequest())
                        
                        sendp(pkt1, iface=interface, verbose=False)
                        sendp(pkt2, iface=interface, verbose=False)
                        sendp(pkt3, iface=interface, verbose=False)


    def probe_gateways(interface: str, ip_version: int = 0) -> None:
        """
        Retrieve all gateways for the specified interface and send probes.

        Args:
            interface (str): Network interface to check
            ip_version (int): IP version to probe (0 = both, 4 = IPv4, 6 = IPv6)
        """
        gateway_addresses = get_gateway_addresses(interface, ip_version)

        for address in gateway_addresses:
            send_neighbor_discovery(address, interface)

def get_gateway_addresses(interface: str, ip_version: int = 0) -> List[str]:
    """
    Extract gateway addresses from routing table for the specified interface.

    Args:
        interface (str): The network interface to check

    Returns:
        List[str]: List of gateway IP addresses (both IPv4 and IPv6)
    """
    gateways = []

    if ip_version == 0:
        ip_versions = [4, 6]
    else:
        ip_versions = [ip_version]

    for ip_version in ip_versions:
        try:
            result = subprocess.run(['ip', f'-{ip_version}', 'route'],
                                    capture_output=True,
                                    text=True,
                                    check=True)

            for line in result.stdout.splitlines():
                if line.startswith('default via') and f"dev {interface}" in line:
                    parts = line.split()
                    if len(parts) >= 5 and parts[0] == 'default' and parts[1] == 'via':
                        gateway_ip = parts[2]
                        gateways.append(gateway_ip)
        except subprocess.CalledProcessError:
            pass

    return gateways


def send_neighbor_discovery(address: str, interface: str) -> None:
    """
    Send appropriate neighbor discovery packet based on IP version.

    Args:
        address (str): IP address (IPv4 or IPv6)
        interface (str): The network interface to use
    """
    try:
        socket.inet_pton(socket.AF_INET, address)
        send_arp_request(address, interface)
    except socket.error:
        try:
            socket.inet_pton(socket.AF_INET6, address)
            send_ns(address, interface)
        except socket.error:
            pass


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


def send_ns(address: str, interface: str) -> None:
    """
    Send an ICMPv6 Neighbor Solicitation to an IPv6 address.

    Args:
        address (str): The IPv6 address
        interface (str): The network interface to use
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

            sendp(pkt, verbose=0, iface=interface)
