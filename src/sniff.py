import csv
import multiprocessing
import pandas as pd

from scapy.all import *
from scapy.contrib.igmp import IGMP
from scapy.contrib.igmpv3 import IGMPv3, IGMPv3mr
from scapy.layers.eap import EAP, EAPOL
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6, ICMPv6ND_RA, ICMPv6NDOptRDNSS, ICMPv6NDOptMTU, ICMPv6NDOptPrefixInfo, \
    ICMPv6MLReport2, ICMPv6MLDMultAddrRec, ICMPv6MLReport, ICMPv6MLDone, ICMPv6EchoReply, ICMPv6EchoRequest, \
    ICMPv6ND_NA, ICMPv6DestUnreach, ICMPv6ParamProblem, ICMPv6ND_Redirect
from scapy.layers.dhcp6 import DHCP6OptIAAddress, DHCP6_Request, DHCP6_Rebind, DHCP6_Release, \
    DHCP6_Renew, DHCP6_Decline, DHCP6_Confirm, DHCP6_Advertise, DHCP6OptServerId
from scapy.layers.dhcp import DHCP
from scapy.layers.dns import DNSRR, DNS
from scapy.layers.l2 import Ether, Dot3, ARP
from scapy.layers.dot11 import Dot11
from scapy.layers.llmnr import LLMNRQuery, LLMNRResponse
from src.device.remote_node import Remote_node
from libs.check import belongs_to_any_prefix, check_ipv6_addresses_generated_from_prefix, is_global_unicast_ipv6, \
    find_requested_addr, extract_mac_from_duid
from src.create_csv import sort_csv_role_node, delete_middle_content_csv
from src.device.wsdiscovery import parse_wsdiscovery, WSDiscovery
from src.interface import Interface
from src.device.router import Router
from src.device.node import Node
from src.device.dhcp import DHCP as DHCP_ptnet
from src.device.igmpv1v2 import IGMPv1v2
from src.device.igmpv3 import IGMPv3 as IGMPv3_ptnet
from src.device.mldv2 import MLDv2
from src.device.mldv1 import MLDv1
from src.device.llmnr import LLMNR
from src.device.mdns import mDNS
from src.device.time import Time
from src.device.eap import EAP
from src.send_ipv4 import SendIPv4
from src.send_ipv6 import SendIPv6
from src.send import Send, IPMode
from libs.convert import convert_OnOff, convert_preferenceRA, convert_mldv2_igmpv3_rtype, convert_timestamp_to_date
from libs.sort import sort


class Sniff:

    @staticmethod
    def type (pkt):
        # Function to classify packet types based on protocols
        if IPv6 in pkt:
            return 0
        elif IP in pkt:
            return 1
        elif Dot3 in pkt:
            return 2
        elif Ether in pkt:
            return 3
        elif Dot11 in pkt:
            if IPv6 in pkt:
                return 0
            elif IP in pkt:
                return 1
        else:
            return 4

    @staticmethod
    def scan_EAP(interface, timeout):
        # Function to sniff for EAP packets
        def check_for_eap(pkt):
            if pkt.haslayer(EAP):
                return True
            elif pkt.haslayer(EAPOL):
                if pkt.type != 1:
                    return True
            else:
                return False

        # Start sniffing for EAP packets
        sniffed_packet = sniff(prn=check_for_eap, timeout=timeout, iface=interface)

        # Check if an EAP packet is captured
        if sniffed_packet:
            return True
        else:
            return False

    @staticmethod
    def save_async(packets):
        # Function to save sniffed packets from asynchronous sniffing to a CSV file, no filter for address duplication because of the time
        with open("src/tmp/packets.csv", 'a', newline='') as csvfile:
            fieldnames = ['time', 'src MAC', 'des MAC', 'source IP', 'destination IP', 'protocol', 'length']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            for packet in packets:
                i = type(packet)
                # Depending on the packet type, write the relevant data to CSV
                # Different packet types have different properties, so they are handled separately
                if i == 0:
                    writer.writerow({
                        'time': packet.time,
                        'source IP': packet[IPv6].src,
                        'destination IP': packet[IPv6].dst,
                        'src MAC': packet[Ether].src,
                        'des MAC': packet[Ether].dst,
                        'protocol': packet[IPv6].nh
                    })
                elif i == 1:
                    writer.writerow({
                        'time': packet.time,
                        'source IP': packet[IP].src,
                        'destination IP': packet[IP].dst,
                        'src MAC': packet[Ether].src,
                        'des MAC': packet[Ether].dst,
                        'protocol': packet[IP].proto
                    })
                elif i == 2:
                    writer.writerow({
                        'time': packet.time,
                        'src MAC': packet[Dot3].src,
                        'des MAC': packet[Dot3].dst,
                    })
                elif i == 3:
                    writer.writerow({
                        'time': packet.time,
                        'src MAC': packet[Ether].src,
                        'des MAC': packet[Ether].dst,
                    })
                elif i == 4:
                    writer.writerow({
                        'time': packet.time,
                        'src MAC': packet[Dot11].src,
                        'des MAC': packet[Dot11].dst,
                    })

    @staticmethod
    def get_filter(ip_mode: IPMode) -> str:
        if ip_mode.ipv4 and ip_mode.ipv6:
            return ""
        elif ip_mode.ipv4:
            return "not ip6"
        elif ip_mode.ipv6:
            return "not ip and not arp"

    @staticmethod
    def scan_async(interface, ip_mode):
        # Function to start asynchronous sniffing
        packets = AsyncSniffer(iface=interface, filter=Sniff.get_filter(ip_mode))
        return packets

    # Function to sniff packets for a certain time period
    @staticmethod
    def scan_time(interface, ip_mode, time):
        packets = sniff(iface=interface, timeout=time, filter=Sniff.get_filter(ip_mode))
        return packets

    @staticmethod
    def remove_duplicates_from_csv(input_csv):
        # Read the CSV file into a DataFrame
        data = pd.read_csv(input_csv)
        
        # Remove duplicates
        data.drop_duplicates(inplace=True)
        
        # Write the cleaned DataFrame to a new CSV file
        data.to_csv(input_csv, index=False)

    @staticmethod
    def detect_RA_guard_missing(interface, prefix_len, network, duration_aggressive):
        """  
        Check if the attacker becomes the fake router. RA guard is missed.

        Returns:
            True (RA guard missing) or False
        """
        if float(duration_aggressive) <= 0:
            return False
        
        # Read the CSV file
        df_ra = pd.read_csv("src/tmp/RA.csv")

        if network != "fe80::":
            # Check if the prefix exists in the "Prefix" column
            prefix = network + str(prefix_len)
            if prefix not in df_ra['Prefix'].to_list():
                # Check if any host use the attacker's prefix to configure addresses
                address_match = check_ipv6_addresses_generated_from_prefix("src/tmp/addresses.csv", network, prefix_len)
                if address_match != []:
                    return True
        
        df_remote_node = pd.read_csv("src/tmp/remote_node.csv")
        # Extract unique source IPs and destination IPs
        unique_src_ips = df_remote_node['src IP'].drop_duplicates().tolist()
        unique_dst_ips = df_remote_node['dst IP'].drop_duplicates().tolist()

        # Filter the lists for global unicast IPv6 addresses
        global_unicast_src_ips = [ip for ip in unique_src_ips if is_global_unicast_ipv6(ip)]
        global_unicast_dst_ips = [ip for ip in unique_dst_ips if is_global_unicast_ipv6(ip)]
        
        # Check if the global unicast IPv6 addresses belong to any of the specified prefixes
        for ip in global_unicast_src_ips + global_unicast_dst_ips:
            if not belongs_to_any_prefix(ip, df_ra['Prefix'].to_list()):
                return True
            
        # # Check if the preference flag
        # rpref_list = df_ra['Preference'].values
        # if "High" not in rpref_list:
        #     if convert_preferenceRA(rpref) == "High":
        #         return True
        # if "Medium" not in rpref_list and "High" not in rpref_list:
        #     if convert_preferenceRA(rpref) == "Medium":
        #         return True
        # else:
        #     return False

    @staticmethod
    def save_packets (interface, ip_mode, packets):
        # Storing all packets into csv files
        Sniff.save_async(packets)
        src_mac = get_if_hwaddr(interface)

        for packet in packets:
            
            # Storing all packets to time
            Time(convert_timestamp_to_date(packet.time), packet[0].src, str(packet.summary())).save_time()

            if packet[0].src != src_mac:
                Time(convert_timestamp_to_date(packet.time), packet[0].src, str(packet.summary())).save_time_incoming()
            if packet[0].src == src_mac:
                Time(convert_timestamp_to_date(packet.time), packet[0].src, str(packet.summary())).save_time_outgoing()

            # EAP responses
            if packet is not None:
                if packet.haslayer(EAPOL) and packet[0].src != src_mac:    
                    # if packet[EAPOL].code == 1 or packet[EAPOL].code == 3 or packet[EAPOL].code == 4:  # EAP code 1 for Request, 3 for Success, 4 for Failure
                    EAP(packet[0].src, str(packet.summary())).save_eap()
                
            # Packet with 2 layers
            if packet is not None and IP not in packet and IPv6 not in packet:
                Node(packet[0].src, "").save_addresses()
                
            # IPv4 responses
            if packet is not None and IP in packet:
                Node(packet[0].src, packet[IP].src).save_addresses()
            
            # IPv6 responses
            if packet is not None and IPv6 in packet:
                Node(packet[0].src, packet[0][1].src).save_addresses()   

            # Checking RA guard bypassing
            if packet is not None and IPv6 in packet:
                if packet[0].dst == src_mac:
                    if is_global_unicast_ipv6(packet[0][1].src) and is_global_unicast_ipv6(packet[0][1].dst):
                        Remote_node(packet[0].src, packet[0][1].src, packet[0].dst, packet[0][1].dst).save_remote_node()
        
            # RA responses
            if packet is not None and ICMPv6ND_RA in packet:            
                dns = []  # Set to [] if not present
                mtu = []  # Set to [] if not present
                prefix = []  # Set to [] if not present
                valid_lft = []  # Set to [] if not present
                preferred_lft = []  # Set to [] if not present
                A_flag = "Not exist"
                L_flag = "Not exist"

                if ICMPv6NDOptRDNSS in packet:
                    dns = str(packet[ICMPv6NDOptRDNSS].dns)
                if ICMPv6NDOptMTU in packet:
                    mtu = str(packet[ICMPv6NDOptMTU].mtu)
                if ICMPv6NDOptPrefixInfo in packet:
                    prefix = packet[ICMPv6NDOptPrefixInfo].prefix + "/" + str(packet[ICMPv6NDOptPrefixInfo].prefixlen)
                    valid_lft = str(packet[ICMPv6NDOptPrefixInfo].validlifetime)
                    preferred_lft = str(packet[ICMPv6NDOptPrefixInfo].preferredlifetime)
                    A_flag = packet[ICMPv6ND_RA].A
                    L_flag = packet[ICMPv6ND_RA].L


                Router(packet[0].src, packet[0][1].src, convert_OnOff(packet[ICMPv6ND_RA].M),
                        convert_OnOff(packet[ICMPv6ND_RA].O), convert_OnOff(packet[ICMPv6ND_RA].H),
                        convert_OnOff(A_flag), convert_OnOff(L_flag),
                        convert_preferenceRA(packet[ICMPv6ND_RA].prf), str(packet[ICMPv6ND_RA].routerlifetime),
                        str(packet[ICMPv6ND_RA].reachabletime), str(packet[ICMPv6ND_RA].retranstimer),
                        dns, mtu, prefix, valid_lft, preferred_lft).save_RA()
                Node(packet[0].src, packet[0][1].src).save_addresses()
                Router.save_router_address(packet[0].src)
                
            # MLD responses
            if packet is not None and ICMPv6MLReport2 in packet:            
                for i in range(packet[0][ICMPv6MLReport2].records_number):
                    MLDv2(packet[0].src, packet[0][1].src, 'Report v2',
                          convert_mldv2_igmpv3_rtype(packet[0][ICMPv6MLDMultAddrRec][i].rtype),
                          packet[0][ICMPv6MLDMultAddrRec][i].dst,
                          packet[0][ICMPv6MLDMultAddrRec][i].sources).save_MLDv2()
                    if in6_isllsnmaddr(packet[0][ICMPv6MLDMultAddrRec][i].dst):
                        Node(packet[0].src, packet[0][ICMPv6MLDMultAddrRec][i].dst).save_addresses()

            if packet is not None and ICMPv6MLReport in packet:
                MLDv1(packet[0].src, packet[0][1].src, 'Report v1', packet[0].mladdr).save_MLDv1()
                if in6_isllsnmaddr(packet[0].mladdr):
                    Node(packet[0].src, packet[0].mladdr).save_addresses()

            if packet is not None and ICMPv6MLDone in packet:
                MLDv1(packet[0].src, packet[0][1].src, 'Done v1', packet[0].mladdr).save_MLDv1()
                if in6_isllsnmaddr(packet[0].mladdr):
                    Node(packet[0].src, packet[0].mladdr).save_addresses()

            # IGMP responses
            if packet is not None and (IGMPv3 in packet and packet[IGMPv3].type == 0x22):
                for i in range(packet[IGMPv3mr].numgrp):
                    IGMPv3_ptnet(packet[0].src, packet[IP].src, 'Report v3',
                           convert_mldv2_igmpv3_rtype(packet[IGMPv3mr].records[i].rtype),
                           packet[IGMPv3mr].records[i].maddr,
                           packet[IGMPv3mr].records[i].srcaddrs).save()

            if packet is not None and (IGMP in packet and packet[IGMP].type == 0x16):
                IGMPv1v2(packet[0].src, packet[IP].src, 'Report v2', packet[IGMP].gaddr).save()

            if packet is not None and (IGMP in packet and packet[IGMP].type == 0x12):
                IGMPv1v2(packet[0].src, packet[IP].src, 'Report v1', packet[IGMP].gaddr).save()

            # Router responses
            if packet is not None and ICMPv6ND_NA in packet:
                Node(packet[0].src, packet[0][1].src).save_addresses()
                if packet[ICMPv6ND_NA].R == 1:
                    Router.save_router_address(packet[0].src)
        
            # LLMNR responses
            if packet is not None and UDP in packet:
                if packet[UDP].sport == 5355:
                    if ICMPv6ParamProblem not in packet and ICMPv6DestUnreach not in packet:
                        if packet.haslayer(LLMNRResponse) and DNSRR in packet:
                            Node(packet[0].src, packet[0][1].src).save_addresses()
                            LLMNR(packet[0].src, packet[0][1].src).save_LLMNR()
                            for i in range(packet[LLMNRResponse].ancount):
                                try:
                                    if ip_mode.ipv4:
                                        if packet[LLMNRResponse].an[i].type == 1:
                                            LLMNR(packet[0].src, packet[LLMNRResponse].an[i].rdata).save_LLMNR()
                                            Node(packet[0].src, packet[LLMNRResponse].an[i].rdata).save_addresses()
                                    if ip_mode.ipv6:
                                        if packet[LLMNRResponse].an[i].type == 28:
                                            LLMNR(packet[0].src, packet[LLMNRResponse].an[i].rdata).save_LLMNR()
                                            Node(packet[0].src, packet[LLMNRResponse].an[i].rdata).save_addresses()
                                    if packet.an[i].type == 12:
                                        Node.save_local_name(packet[0].src, packet[LLMNRResponse].an[i].rdata.decode())
                                except:
                                    pass
        
            # mDNS responses or DNS
            if packet is not None and DNSRR in packet and DNS in packet:
                Node(packet[0].src, packet[0][1].src).save_addresses()
                mDNS(packet[0].src, packet[0][1].src).save_mDNS()
                for i in range(packet[1][DNS].ancount):
                    if ip_mode.ipv4:
                        if packet.an[i].type == 1:
                            Node(packet[0].src, packet[0].an[i].rdata).save_addresses()
                            mDNS(packet[0].src, packet[0].an[i].rdata).save_mDNS()
                    if ip_mode.ipv6:
                        if packet.an[i].type == 28:
                            Node(packet[0].src, packet[0].an[i].rdata).save_addresses()
                            mDNS(packet[0].src, packet[0].an[i].rdata).save_mDNS()
                    if packet.an[i].type == 12:
                        Node.save_local_name(packet[0].src, packet.an[i].rdata.decode())
            
            # DHCPv6 Request, Renew, Release, Decline, Confirm, Rebind (If they include address)
            if packet is not None and (DHCP6_Request in packet or DHCP6_Renew in packet or DHCP6_Release in packet or DHCP6_Decline in packet or DHCP6_Confirm in packet or DHCP6_Rebind in packet):
                if DHCP6OptIAAddress in packet:
                    DHCP_ptnet(packet[0].src, packet[0][DHCP6OptIAAddress].addr, "client").save_addresses()
                    Node(packet[0].src, packet[0][DHCP6OptIAAddress].addr).save_addresses()

            # DHCPv6 Advertise
            if packet is not None and DHCP6_Advertise in packet:
                if DHCP6OptServerId in packet:
                    try:
                        duid_mac = extract_mac_from_duid(bytes(packet[0][DHCP6OptServerId].duid))
                        if packet[0].src == duid_mac:
                            DHCP_ptnet(packet[0].src, packet[IPv6].src, "server").save_addresses()
                            Node(packet[0].src, packet[IPv6].src).save_addresses()
                    except:
                        pass

            # DHCP Request
            if packet is not None and DHCP in packet and packet[DHCP].options[0][1] == 3:
                if find_requested_addr(packet[0][DHCP].options):
                    DHCP_ptnet(packet[0].src, find_requested_addr(packet[0][DHCP].options), "client").save_addresses()
                    Node(packet[0].src, find_requested_addr(packet[0][DHCP].options)).save_addresses()

            # DHCP Offer
            if packet is not None and DHCP in packet and packet[DHCP].options[0][1] == 2:
                DHCP_ptnet(packet[0].src, packet[IP].src, "server").save_addresses()
                Node(packet[0].src, packet[IP].src).save_addresses()
                for option in packet[0][DHCP].options:
                    if isinstance(option, tuple) and option[0] == 'server_id':
                        DHCP_ptnet(packet[0].src, option[1], "server").save_addresses()
                        Node(packet[0].src, option[1]).save_addresses()

            # ARP responses
            if packet is not None and ARP in packet:
                Node(packet[0].src, packet[ARP].psrc).save_addresses()

            # WS-Discovery responses
            if UDP in packet and (packet[UDP].sport == 3702 or packet[UDP].dport == 3702):
                WSDiscovery(packet[0].src, packet[0][1].src).save_addresses()
                if Raw in packet:
                    found_addresses = parse_wsdiscovery(packet)
                    for address in found_addresses:
                        WSDiscovery(packet[0].src, address).save_addresses()
                        Node(packet[0].src, address).save_addresses()

        sort('src/tmp/packets.csv', 'src/tmp/addresses.csv')

    @staticmethod
    def run_normal_mode(interface, mode, ip_mode, timeout):
        # Checking the existence of the interface
        exist_interface = Interface(interface).check_interface()

        if exist_interface:  
            
            # Start time
            start_time = str(datetime.now())
            Time.save_start_end(start_time)
            
            # Scanning 802.1x security
            if mode == "802.1x":
                pkts = Sniff.scan_async(interface, ip_mode)
                pkts.start()

                # Send EAPOL-Start packet and wait for any Request messages
                Send.send_8021x_security(interface)
                time.sleep(timeout)
                pkts.stop()
                Sniff.save_packets(interface, ip_mode, pkts.results)

                # Finish time
                finish_time = str(datetime.now())
                Time.save_start_end(finish_time)

            if mode == "p":
                # Loop until 10 seconds have passed
                pkts = Sniff.scan_time(interface, ip_mode, timeout)

                # Finish time
                finish_time = str(datetime.now())
                Time.save_start_end(finish_time)
                Sniff.save_packets(interface, ip_mode, pkts)

            if mode == "a":
                pkts = Sniff.scan_async(interface, ip_mode)
                pkts.start()

                # Sending normal packets
                if ip_mode.ipv6:
                    SendIPv6.send_MLD_query(interface)
                    SendIPv6.send_normal_multicast_ping(interface)
                    SendIPv6.send_invalid_multicast_icmpv6(interface)
                    SendIPv6.send_invalid_multicast_ping(interface)
                    SendIPv6.send_invalid_ipv6_hbh(interface)
                    # Send.send_multicast_ping_router(interface)
                    SendIPv6.send_RS(interface)

                if ip_mode.ipv4:
                    SendIPv4.send_igmp_membership_query(3, interface)
                    SendIPv4.send_igmp_membership_query(3, interface, "224.0.0.1")
                    time.sleep(1)
                    SendIPv4.send_igmp_membership_query(2, interface)
                    SendIPv4.send_igmp_membership_query(2, interface, "224.0.0.1")
                    time.sleep(1)
                    SendIPv4.send_igmp_membership_query(1, interface)
                    SendIPv4.send_igmp_membership_query(1, interface, "224.0.0.1")
                    SendIPv4.send_local_icmp_ping("224.0.0.1", interface)
                    SendIPv4.send_local_icmp_ping("255.255.255.255", interface)
                    SendIPv4.send_subnet_broadcast_ping(interface)

                Send.probe_gateways(interface, ip_mode)
                Send.probe_interesting_network_addresses(interface, ip_mode)
                Send.send_dhcp_probe(interface, ip_mode)
                Send.send_wsdiscovery_probe(interface, ip_mode)
                Send.send_dns_sd_probe(interface, ip_mode)

                time.sleep(2.5) # Sleeping to make the tool capture packets
                pkts.stop()
                Sniff.save_packets(interface, ip_mode, pkts.results)

                pkts.start()

                Send.send_llmnr_mdns(interface, ip_mode)

                time.sleep(1.5)
                pkts.stop()
                Sniff.save_packets(interface, ip_mode, pkts.results)

                pkts.start()

                # Generating possible addresses and scan again (normal packets and mdns + llmnr in IPv6)
                if ip_mode.ipv6:
                    SendIPv6.send_to_possible_IP(interface)
                    SendIPv6.send_to_test_RA_guard(interface)

                time.sleep(1)
                pkts.stop()
                Sniff.save_packets(interface, ip_mode, pkts.results)

                # Finish time
                finish_time = str(datetime.now())
                Time.save_start_end(finish_time)

                # Getting the routing table for more information related to route
                Node.get_ipv6_route_metrics_and_addresses()
                Node.get_ipv4_route_metrics_and_addresses()
            
            # # Finish time
            # finish_time = str(datetime.now())
            # Time.save_start_end(finish_time)

            # Removing duplciated rows, this is needed in MLDv1 and MLDv2 since another file when capturing add packets to them
            Sniff.remove_duplicates_from_csv("src/tmp/mDNS.csv")
            Sniff.remove_duplicates_from_csv("src/tmp/LLMNR.csv")
            Sniff.remove_duplicates_from_csv("src/tmp/MLDv1.csv")
            Sniff.remove_duplicates_from_csv("src/tmp/MLDv2.csv")
            Sniff.remove_duplicates_from_csv("src/tmp/RA.csv")
            Sniff.remove_duplicates_from_csv("src/tmp/localname.csv")

            sort_csv_role_node(interface, "src/tmp/role_node.csv")

    @staticmethod
    def run_aggressive_mode(interface, ip_mode, prefix_len, network, source_mac, source_ip, rpref, duration, period, chl, mtu, dns):
        
        p1 = multiprocessing.Process(target=SendIPv6.send_RA,
                                     args=[interface, prefix_len, network, source_mac, source_ip, rpref, chl, mtu, dns, True, period, duration])
        p2 = multiprocessing.Process(target=SendIPv6.react_to_NS_RS,
                                     args=[interface, prefix_len, network, source_mac, source_ip, rpref, chl, mtu, dns, duration])
        p3 = multiprocessing.Process(target=Sniff.run_normal_mode, args=[interface, "a", ip_mode, duration])
        p4 = multiprocessing.Process(target=Sniff.run_normal_mode, args=[interface, "p", ip_mode, duration])

        p2.start()
        p1.start()
        p4.start()

        time.sleep(0.5)
        p3.start()

        p1.join()
        p2.join()
        p3.join()
        p4.join()
