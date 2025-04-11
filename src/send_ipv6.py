import ipaddress
import csv

from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import UDP
from scapy.layers.inet6 import IPv6, ICMPv6MLQuery, ICMPv6EchoRequest, IPv6ExtHdrHopByHop, RouterAlert, \
    IPv6ExtHdrDestOpt, HBHOptUnknown, ICMPv6ND_NS, ICMPv6NDOptSrcLLAddr, ICMPv6ND_NA, ICMPv6MLQuery2, \
    ICMPv6ND_RS, ICMPv6ND_RA, ICMPv6NDOptRDNSS, \
    ICMPv6NDOptMTU, ICMPv6NDOptPrefixInfo, ICMPv6NDOptDstLLAddr
from scapy.layers.l2 import Ether
from scapy.layers.llmnr import LLMNRQuery, LLMNRResponse
from src.interface import Interface, reverse_IPadd
from src.device.mdns import mDNS
from src.device.llmnr import LLMNR
from libs.check import is_global_unicast_ipv6, has_additional_data
from libs.convert import generate_global_ipv6, generate_random_global_ipv6, collect_unique_items


class SendIPv6:
    @staticmethod
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

    @staticmethod
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

    @staticmethod
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

    @staticmethod
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

    @staticmethod
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

    @staticmethod
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

    @staticmethod
    def send_reverse_ipv6_mDNS(ipv6_address, interface):
        # Function to send an IPv6 mDNS PTR query and save the response to get the local name
        # Checking the existence of the interface
        exist_interface = Interface(interface).check_interface()

        if exist_interface:
            avail_ipv6 = Interface(interface).check_available_ipv6
            if avail_ipv6:
                src_mac = get_if_hwaddr(interface)
                query = reverse_IPadd(ipv6_address)
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

    @staticmethod
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

    @staticmethod
    def send_reverse_ipv6_llmnr(ipv6_address, interface):
        # This function sends an IPv6 LLMNR request to reverse lookup the domain name associated with the IP address on a given interface
        # Checking the existence of the interface
        exist_interface = Interface(interface).check_interface()

        if exist_interface:
            avail_ipv6 = Interface(interface).check_available_ipv6
            if avail_ipv6:
                src_mac = get_if_hwaddr(interface)
                query = reverse_IPadd(ipv6_address)
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

    @staticmethod
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

    @staticmethod
    def IPv6_test_mdns_llmnr(ip_address, interface):
        name = SendIPv6.send_reverse_ipv6_llmnr(ip_address, interface)
        # print(f"IPv6 LLMNR: {name}")
        if name != None:
            SendIPv6.send_mDNS_ipv6(name, interface)
            SendIPv6.send_llmnr_ipv6(name, interface)
            return
        name = SendIPv6.send_reverse_ipv6_mDNS(ip_address, interface)
        # print(f"IPv6 mDNS: {name}")
        if name != None:
            SendIPv6.send_mDNS_ipv6(name, interface)
            SendIPv6.send_llmnr_ipv6(name, interface)
            return

    @staticmethod
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

    @staticmethod
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

    @staticmethod
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

    @staticmethod
    def send_to_possible_IP(interface):
        # Getting all IP from scanner
        ip_addresses = Interface(interface).get_interface_ips()
        src_mac = get_if_hwaddr(interface)

        # Dictionary storing possible IP
        possible_global_IP = generate_more_possible_IP(interface)
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
                        SendIPv6.IPv6_test_mdns_llmnr(dst_ip, interface)
                    except ipaddress.AddressValueError:
                        continue

    @staticmethod
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

    @staticmethod
    def react_to_NS_RS(interface, prefix_len, network, source_mac, source_ip, rpref, chl, mtu, dns, duration):
        # Becoming fake router and reacts to every NS or RS from other hosts
        def custom_action(packet):

            # Set option when dealing with Router Solicitation
            if ICMPv6ND_RS in packet and packet[0][1].src != source_ip:
                SendIPv6.send_RA(interface, prefix_len, network, source_mac, source_ip, rpref, chl, mtu, dns, False, None, None)

            # Set option when dealing with Neighbor Solicitation
            if ICMPv6ND_NS in packet and packet[0][1].src != source_ip:
                SendIPv6.send_NA(interface, source_mac, packet[0].src, source_ip, packet[0][1].src, 1, 1, 1)

        # Setup sniff, filtering for IP traffic to see the result
        build_filter = "ip6"

        try:
            sniff(iface=interface, filter=build_filter, prn=custom_action, timeout=duration)
        except KeyboardInterrupt:
            sys.exit(0)

    @staticmethod
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

    @staticmethod
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

    @staticmethod
    def probe_ipv6_interesting_addresses(network: ipaddress.IPv6Network, interface: str) -> None:
        """
        Probe ::0 and ::1 addresses in IPv6 network.

        Args:
            network (ipaddress.IPv4Network): The network to probe
            interface (str): The network interface to use
        """
        try:
            # fe80::0
            SendIPv6.send_ns('fe80::0', interface)

            # fe80::1
            SendIPv6.send_ns('fe80::1', interface)

            # ::0
            first_addr = network.network_address
            SendIPv6.send_ns(str(first_addr), interface)

            # ::1
            last_bits = network.network_address.packed[:-1] + bytes([network.network_address.packed[-1] | 1])
            second_addr = ipaddress.IPv6Address(last_bits)

            # verify the address is in the network
            if second_addr in network:
                SendIPv6.send_ns(str(second_addr), interface)
            else:
                return
        except:
            return

    @staticmethod
    def send_wsdiscovery_probe(interface: str) -> None:
        """
        Send a WS-Discovery probe to the multicast address.

        Args:
            interface (str): The network interface to use
        """
        exist_interface = Interface(interface).check_interface()

        if exist_interface:
            avail_ipv6 = Interface(interface).check_available_ipv6
            if avail_ipv6:
                ipv6_addresses = Interface(interface).get_interface_ipv6_ips()

                for source_ipv6_addr in ipv6_addresses:
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
                    ipv6 = IPv6(src=source_ipv6_addr, dst="ff02::c", hlim=1)
                    udp = UDP(sport=random.randint(49152, 65535), dport=3702)
                    payload = Raw(load=soap_payload)
                    wsd_packet = ether / ipv6 / udp / payload

                    sendp(wsd_packet, verbose=0, iface=interface)


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
