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
from src.create_csv import remove_duplicates_from_csv, sort_csv_role_node, delete_middle_content_csv
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
from src.device.mdns import MDNS
from src.device.time import Time
from src.device.eap import EAP
from src.send_ipv4 import SendIPv4, ICMPType
from src.send_ipv6 import SendIPv6
from src.send import Send, IPMode
from libs.convert import convert_OnOff, convert_preferenceRA, convert_mldv2_igmpv3_rtype, convert_timestamp_to_date
from libs.sort import sort

class Sniff:
    @staticmethod
    def type(pkt):
        """
        Classify packet types based on protocols.

        input: pkt (scapy packet)
        output: int (type code)
        """
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
        """
        Sniff for EAP packets.

        input: interface (str), timeout (int)
        output: bool (True if EAP packet captured, else False)
        """
        def check_for_eap(pkt):
            if pkt.haslayer(EAP):
                return True
            elif pkt.haslayer(EAPOL):
                if pkt.type != 1:
                    return True
            else:
                return False

        sniffed_packet = sniff(prn=check_for_eap, timeout=timeout, iface=interface)
        return bool(sniffed_packet)

    @staticmethod
    def save_async(packets):
        """
        Save sniffed packets from asynchronous sniffing to a CSV file.

        input: packets (list of scapy packets)
        output: None (writes to file)
        """
        with open("src/tmp/packets.csv", 'a', newline='') as csvfile:
            fieldnames = ['time', 'src MAC', 'des MAC', 'source IP', 'destination IP', 'protocol', 'length']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            for packet in packets:
                i = Sniff.type(packet)
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
        """
        Get BPF filter string based on IP mode.

        input: ip_mode (IPMode)
        output: str (filter string)
        """
        if ip_mode.ipv4 and ip_mode.ipv6:
            return ""
        elif ip_mode.ipv4:
            return "not ip6"
        elif ip_mode.ipv6:
            return "not ip and not arp"

    @staticmethod
    def scan_async(interface, ip_mode):
        """
        Start asynchronous sniffing.

        input: interface (str), ip_mode (IPMode)
        output: AsyncSniffer object
        """
        packets = AsyncSniffer(iface=interface, filter=Sniff.get_filter(ip_mode))
        return packets

    @staticmethod
    def scan_time(interface, ip_mode, time):
        """
        Sniff packets for a certain time period.

        input: interface (str), ip_mode (IPMode), time (int)
        output: list of scapy packets
        """
        packets = sniff(iface=interface, timeout=time, filter=Sniff.get_filter(ip_mode))
        return packets

    @staticmethod    
    def packet_to_one_line(packet):
        """
        Convert packet details to a single line string.

        input: packet (scapy packet)
        output: str (one-line packet details)
        """
        details = packet.show(dump=True)
        one_line = ' '.join(details.replace('\r', '').replace('\n', ' ').split())
        return one_line

    @staticmethod
    def save_packets(interface, ip_mode, packets):
        """
        Store all packets into CSV files and update device/address info.

        input: interface (str), ip_mode (IPMode), packets (list of scapy packets)
        output: None (writes to files, updates objects)
        """
        Sniff.save_async(packets)
        src_mac = get_if_hwaddr(interface)

        for packet in packets:
            Time(convert_timestamp_to_date(packet.time), packet[0].src, str(packet.summary())).save_time()

            if packet[0].src != src_mac:
                Time(convert_timestamp_to_date(packet.time), packet[0].src, Sniff.packet_to_one_line(packet)).save_time_incoming()
            if packet[0].src == src_mac:
                Time(convert_timestamp_to_date(packet.time), packet[0].src, Sniff.packet_to_one_line(packet)).save_time_outgoing()

            if packet is not None:
                if packet.haslayer(EAPOL) and packet[0].src != src_mac:    
                    EAP(packet[0].src, str(packet.summary())).save_eap()
            
            if packet is not None and IP not in packet and IPv6 not in packet:
                Node(packet[0].src, "").save_addresses()
            if packet is not None and IP in packet:
                Node(packet[0].src, packet[IP].src).save_addresses()
            if packet is not None and IPv6 in packet:
                Node(packet[0].src, packet[0][1].src).save_addresses()   

            if packet is not None and IPv6 in packet:
                if packet[0].dst == src_mac:
                    if is_global_unicast_ipv6(packet[0][1].src) and is_global_unicast_ipv6(packet[0][1].dst):
                        Remote_node(packet[0].src, packet[0][1].src, packet[0].dst, packet[0][1].dst).save_remote_node()
        
            if packet is not None and ICMPv6ND_RA in packet:            
                dns, mtu, prefix, valid_lft, preferred_lft = [], [], [], [], []
                A_flag, L_flag = "Not exist", "Not exist"
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

            if packet is not None and ICMPv6ND_NA in packet:
                Node(packet[0].src, packet[0][1].src).save_addresses()
                if packet[ICMPv6ND_NA].R == 1:
                    Router.save_router_address(packet[0].src)
        
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
        
            if packet is not None and DNSRR in packet and DNS in packet:
                Node(packet[0].src, packet[0][1].src).save_addresses()
                MDNS(packet[0].src, packet[0][1].src).save_MDNS()
                if hasattr(packet[1][DNS], 'an') and packet[1][DNS].an is not None:
                    for i in range(packet[1][DNS].ancount):
                        try:
                            if hasattr(packet.an[i], 'type'):
                                if ip_mode.ipv4 and packet.an[i].type == 1:
                                    Node(packet[0].src, packet.an[i].rdata).save_addresses()
                                    MDNS(packet[0].src, packet.an[i].rdata).save_MDNS()
                                elif ip_mode.ipv6 and packet.an[i].type == 28:
                                    Node(packet[0].src, packet.an[i].rdata).save_addresses()
                                    MDNS(packet[0].src, packet.an[i].rdata).save_MDNS()
                                elif packet.an[i].type == 12:
                                    Node.save_local_name(packet[0].src, packet.an[i].rdata.decode())
                        except AttributeError:
                            continue
                        except IndexError:
                            break
                else:
                    print("No DNS answer section found in packet.")
            
            if packet is not None and (DHCP6_Request in packet or DHCP6_Renew in packet or DHCP6_Release in packet or DHCP6_Decline in packet or DHCP6_Confirm in packet or DHCP6_Rebind in packet):
                if DHCP6OptIAAddress in packet:
                    DHCP_ptnet(packet[0].src, packet[0][DHCP6OptIAAddress].addr, "client").save_addresses()
                    Node(packet[0].src, packet[0][DHCP6OptIAAddress].addr).save_addresses()

            if packet is not None and DHCP6_Advertise in packet:
                if DHCP6OptServerId in packet:
                    try:
                        duid_mac = extract_mac_from_duid(bytes(packet[0][DHCP6OptServerId].duid))
                        if packet[0].src == duid_mac:
                            DHCP_ptnet(packet[0].src, packet[IPv6].src, "server").save_addresses()
                            Node(packet[0].src, packet[IPv6].src).save_addresses()
                    except:
                        pass

            if packet is not None and DHCP in packet and packet[DHCP].options[0][1] == 3:
                if find_requested_addr(packet[0][DHCP].options):
                    DHCP_ptnet(packet[0].src, find_requested_addr(packet[0][DHCP].options), "client").save_addresses()
                    Node(packet[0].src, find_requested_addr(packet[0][DHCP].options)).save_addresses()

            if packet is not None and DHCP in packet and packet[DHCP].options[0][1] == 2:
                DHCP_ptnet(packet[0].src, packet[IP].src, "server").save_addresses()
                Node(packet[0].src, packet[IP].src).save_addresses()
                for option in packet[0][DHCP].options:
                    if isinstance(option, tuple) and option[0] == 'server_id':
                        DHCP_ptnet(packet[0].src, option[1], "server").save_addresses()
                        Node(packet[0].src, option[1]).save_addresses()

            if packet is not None and ARP in packet:
                Node(packet[0].src, packet[ARP].psrc).save_addresses()

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
        """
        Run normal sniffing and sending mode.

        input: interface (str), mode (str), ip_mode (IPMode), timeout (int)
        output: None (writes to files, updates objects)
        """
        exist_interface = Interface(interface).check_interface()
        if exist_interface:  
            start_time = str(datetime.now())
            Time.save_start_end(start_time)
            
            if mode == "802.1x":
                pkts = Sniff.scan_async(interface, ip_mode)
                pkts.start()
                Send.send_8021x_security(interface)
                time.sleep(timeout)
                pkts.stop()
                Sniff.save_packets(interface, ip_mode, pkts.results)
                finish_time = str(datetime.now())
                Time.save_start_end(finish_time)

            if mode == "p":
                pkts = Sniff.scan_time(interface, ip_mode, timeout)
                finish_time = str(datetime.now())
                Time.save_start_end(finish_time)
                Sniff.save_packets(interface, ip_mode, pkts)

            if mode == "a":
                pkts = Sniff.scan_async(interface, ip_mode)
                pkts.start()
                if ip_mode.ipv6:
                    SendIPv6.send_MLD_query(interface)
                    SendIPv6.send_normal_multicast_ping(interface)
                    SendIPv6.send_invalid_multicast_icmpv6(interface)
                    SendIPv6.send_invalid_multicast_ping(interface)
                    SendIPv6.send_invalid_ipv6_hbh(interface)
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
                    for icmp_type in ICMPType:
                        if icmp_type == ICMPType.ROUTER_SOLICITATION:
                            SendIPv4.send_local_icmp("224.0.0.2", interface, icmp_type)
                        else:
                            SendIPv4.send_local_icmp("224.0.0.1", interface, icmp_type)
                        SendIPv4.send_local_icmp("255.255.255.255", interface, icmp_type)
                        SendIPv4.send_subnet_broadcast_icmp(interface, icmp_type)
                Send.probe_gateways(interface, ip_mode)
                Send.probe_interesting_network_addresses(interface, ip_mode)
                Send.send_dhcp_probe(interface, ip_mode)
                Send.send_wsdiscovery_probe(interface, ip_mode)
                Send.send_dns_sd_probe(interface, ip_mode)
                time.sleep(2.5)
                pkts.stop()
                Sniff.save_packets(interface, ip_mode, pkts.results)
                pkts.start()
                Send.send_llmnr_mdns(interface, ip_mode)
                time.sleep(1.5)
                pkts.stop()
                Sniff.save_packets(interface, ip_mode, pkts.results)
                pkts.start()
                if ip_mode.ipv6:
                    SendIPv6.send_to_possible_IP(interface)
                    SendIPv6.send_to_test_RA_guard(interface)
                time.sleep(1)
                pkts.stop()
                Sniff.save_packets(interface, ip_mode, pkts.results)
                finish_time = str(datetime.now())
                Time.save_start_end(finish_time)
                Node.get_ipv6_route_metrics_and_addresses()
                Node.get_ipv4_route_metrics_and_addresses()

            remove_duplicates_from_csv("src/tmp/MDNS.csv")
            remove_duplicates_from_csv("src/tmp/LLMNR.csv")
            remove_duplicates_from_csv("src/tmp/MLDv1.csv")
            remove_duplicates_from_csv("src/tmp/MLDv2.csv")
            remove_duplicates_from_csv("src/tmp/RA.csv")
            remove_duplicates_from_csv("src/tmp/localname.csv")
            sort_csv_role_node(interface, "src/tmp/role_node.csv")

    @staticmethod
    def run_aggressive_mode(interface, ip_mode, prefix_len, network, source_mac, source_ip, rpref, duration, period, chl, mtu, dns):
        """
        Run aggressive sniffing and sending mode.

        input: interface (str), ip_mode (IPMode), prefix_len (int), network (str), source_mac (str), source_ip (str),
               rpref (str), duration (int), period (int), chl (str), mtu (int), dns (str)
        output: None (runs processes)
        """
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
