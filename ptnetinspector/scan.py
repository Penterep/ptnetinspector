"""Packet capture, analysis, and active probing utilities.

This module contains sniffing logic and protocol parsers that extract network
facts into CSV artifacts, used later for both human-readable and JSON outputs.
"""
import csv
import ipaddress
import multiprocessing
import logging
from contextlib import contextmanager, nullcontext
import pandas as pd
from scapy.all import *
from scapy.contrib.igmp import IGMP
from scapy.contrib.igmpv3 import IGMPv3, IGMPv3mr, IGMPv3mq
from scapy.layers.eap import EAP, EAPOL
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6, ICMPv6ND_RA, ICMPv6NDOptRDNSS, ICMPv6NDOptMTU, ICMPv6NDOptPrefixInfo, \
    ICMPv6MLReport2, ICMPv6MLDMultAddrRec, ICMPv6MLReport, ICMPv6MLDone, ICMPv6EchoReply, ICMPv6EchoRequest, \
    ICMPv6ND_NA, ICMPv6ND_NS, ICMPv6DestUnreach, ICMPv6ParamProblem, ICMPv6ND_Redirect, \
    ICMPv6MLQuery2, ICMPv6MLQuery, ICMPv6NDOptDNSSL, ICMPv6NDOptRouteInfo, ICMPv6NDOptPREF64, \
    ICMPv6NDOptCaptivePortal, ICMPv6NDOptAdvInterval, \
    ICMPv6NIReplyName, ICMPv6NIReplyIPv6, ICMPv6NIReplyIPv4, ICMPv6NIReplyNOOP, \
    ICMPv6NIReplyRefuse, ICMPv6NIReplyUnknown, ICMPv6NIQueryNOOP, ICMPv6NIQueryName, \
    ICMPv6NIQueryIPv6, ICMPv6NIQueryIPv4
from scapy.layers.dhcp6 import DHCP6OptIAAddress, DHCP6_Request, DHCP6_Rebind, DHCP6_Release, \
    DHCP6_Renew, DHCP6_Decline, DHCP6_Confirm, DHCP6_Advertise, DHCP6OptServerId, DHCP6_Reply, \
    DHCP6OptDNSServers, DHCP6OptDNSDomains, DHCP6OptSNTPServers, DHCP6OptNTPServer, \
    DHCP6OptSIPDomains, DHCP6OptSIPServers, DHCP6OptBootFileUrl, DHCP6OptVendorClass, \
    DHCP6OptVendorSpecificInfo
from scapy.layers.dhcp import DHCP
from scapy.layers.dns import DNSRR, DNS
from scapy.layers.l2 import Ether, Dot3, ARP
from scapy.layers.dot11 import Dot11
from scapy.layers.llmnr import LLMNRQuery, LLMNRResponse

from ptnetinspector.utils.path import get_csv_path
from ptnetinspector.entities.remote_node import Remote_node
from ptnetinspector.utils.ip_utils import belongs_to_any_prefix, check_ipv6_addresses_generated_from_prefix, is_global_unicast_ipv6, \
    find_requested_addr, extract_mac_from_duid
from ptnetinspector.utils.csv_helpers import remove_duplicates_from_csv, sort_csv_role_node, delete_middle_content_csv
from ptnetinspector.entities.wsdiscovery import parse_wsdiscovery, WSDiscovery
from ptnetinspector.entities.dnssd import DNSSD
from ptnetinspector.entities.fingerprint import Fingerprint, guess_os_from_hop_limit
from ptnetinspector.entities.querier import Querier
from ptnetinspector.entities.dhcpv6_options import DHCPv6Options
from ptnetinspector.entities.ra_options import RAOption
from ptnetinspector.entities.node_info import NodeInfo
from ptnetinspector.utils.interface import Interface
from ptnetinspector.entities.router import Router
from ptnetinspector.entities.node import Node
from ptnetinspector.entities.dhcp import DHCP as DHCP_ptnet
from ptnetinspector.entities.igmpv1v2 import IGMPv1v2
from ptnetinspector.entities.igmpv3 import IGMPv3 as IGMPv3_ptnet
from ptnetinspector.entities.mldv2 import MLDv2
from ptnetinspector.entities.mldv1 import MLDv1
from ptnetinspector.entities.llmnr import LLMNR
from ptnetinspector.entities.mdns import MDNS
from ptnetinspector.entities.time import Time
from ptnetinspector.entities.eap import EAP
from ptnetinspector.send.send_ipv4 import SendIPv4, ICMPType
from ptnetinspector.send.send_ipv6 import SendIPv6
from ptnetinspector.send.send import Send, IPMode
from ptnetinspector.utils.ip_utils import convert_OnOff, convert_preferenceRA, convert_mldv2_igmpv3_rtype, convert_timestamp_to_date, classify_ipv6_iid
from ptnetinspector.utils.csv_helpers import sort_csv


logger = logging.getLogger(__name__)


@contextmanager
def _protocol_guard(protocol, mac):
    """Isolate one protocol parser so a malformed frame cannot abort the scan.

    The record counts and option lists below come straight off the wire, so a
    truncated or crafted packet used to raise out of save_packets and discard
    every result the mode had collected. Each block now absorbs its own errors
    and the remaining protocols still get parsed.
    """
    try:
        yield
    except Exception as ex:
        logger.debug("Skipping malformed %s data from %s: %s", protocol, mac, ex)


def _iter_layers(packet, layer_cls, limit=None):
    """Yield every instance of a layer, not just the first one Scapy indexes.

    ``packet[cls]`` returns only the first match, which silently dropped every
    prefix after the first in a multi-prefix RA.
    """
    count = 0
    layer = packet.getlayer(layer_cls)
    while layer is not None:
        yield layer
        count += 1
        if limit is not None and count >= limit:
            return
        layer = layer.payload.getlayer(layer_cls)


# Protocols that pin the hop limit by specification, so the value in the header
# is the RFC's choice and not the sender's default.
_FIXED_HOP_LIMIT_LAYERS = (
    ICMPv6ND_RA, ICMPv6ND_RS, ICMPv6ND_NA, ICMPv6ND_NS, ICMPv6ND_Redirect,
    ICMPv6MLReport2, ICMPv6MLReport, ICMPv6MLDone, ICMPv6MLQuery2, ICMPv6MLQuery,
    ICMPv6NIQueryNOOP, ICMPv6NIQueryName, ICMPv6NIQueryIPv6, ICMPv6NIQueryIPv4,
    ICMPv6NIReplyNOOP, ICMPv6NIReplyName, ICMPv6NIReplyIPv6, ICMPv6NIReplyIPv4,
    ICMPv6NIReplyRefuse, ICMPv6NIReplyUnknown,
    IGMP, IGMPv3,
)

# mDNS and LLMNR mandate 255 even on unicast responses (RFC 6762 s. 11,
# RFC 4795 s. 2.1), so port alone is enough to disqualify the reading.
_FIXED_HOP_LIMIT_PORTS = (5353, 5355)


def _is_link_scoped_multicast(address) -> bool:
    """True for a multicast address whose scope does not leave the link.

    Everything scoped to the link pins its hop limit, so the destination is a
    stronger test than naming individual protocols: it keeps holding for the
    ones nobody thought to enumerate.
    """
    try:
        parsed = ipaddress.ip_address(str(address))
    except ValueError:
        return False
    if not parsed.is_multicast:
        return False
    if parsed.version == 6:
        return (parsed.packed[1] & 0x0F) <= 2
    # IPv4's local network control block is the same idea, and mandates TTL 1.
    return parsed in ipaddress.IPv4Network("224.0.0.0/24")


def _hop_limit_is_stack_default(packet) -> bool:
    """True when the hop limit in the header is the sender's own default.

    Reading a hop limit as an OS fingerprint only works for traffic the stack
    emitted with its configured default. Neighbour Discovery and Node
    Information Queries mandate 255, MLD and IGMP mandate 1, and mDNS and
    LLMNR mandate 255 even when they answer by unicast. Treating any of those
    as an OS default put "network device (Cisco/router-class default)" on
    every host that merely answered a solicitation.
    """
    if any(packet.haslayer(layer) for layer in _FIXED_HOP_LIMIT_LAYERS):
        return False

    if UDP in packet:
        udp = packet[UDP]
        if udp.sport in _FIXED_HOP_LIMIT_PORTS or udp.dport in _FIXED_HOP_LIMIT_PORTS:
            return False

    if IPv6 in packet:
        return not _is_link_scoped_multicast(packet[IPv6].dst)
    if IP in packet:
        return not _is_link_scoped_multicast(packet[IP].dst)
    return False


def _dhcp_message_type(packet):
    """Return the DHCPv4 message-type option value, or None when absent.

    RFC 2131 does not require message-type to be the first option, and a
    truncated packet can carry the magic cookie with no options at all, so the
    list is searched instead of being indexed positionally.
    """
    options = getattr(packet[DHCP], "options", None) or []
    for option in options:
        if isinstance(option, tuple) and len(option) >= 2 and option[0] == "message-type":
            return option[1]
    return None


def _close_inherited_scapy_sockets():
    """Close Scapy SuperSocket instances inherited from the parent process on fork.

    When multiprocessing.Process is started with the default 'fork' method on Linux,
    the child inherits all open file descriptors including raw Scapy sockets.  If the
    child later reallocates those fd numbers, the parent's sockets become invalid,
    causing ``OSError: [Errno 9] Bad file descriptor`` in subsequent sendp/srp calls.
    Running this as the Process initializer ensures the child starts with a clean
    socket state before opening its own Scapy sockets.
    """
    import gc
    try:
        from scapy.supersocket import SuperSocket
        for obj in gc.get_objects():
            if isinstance(obj, SuperSocket):
                try:
                    obj.close()
                except Exception:
                    # Best-effort cleanup; failing to close one inherited socket is non-fatal.
                    pass
    except Exception:
        logger.debug("Failed to close inherited Scapy sockets", exc_info=True)


def _forked_target(fn, args):
    """Wrapper for multiprocessing.Process targets that clears inherited Scapy sockets."""
    _close_inherited_scapy_sockets()
    fn(*args)


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
    def scan_async(interface):
        """
        Start asynchronous sniffing.

        input: interface (str)
        output: AsyncSniffer object
        """
        packets = AsyncSniffer(iface=interface)

        # # Store original stop method
        # original_stop = packets.stop

        # def filtered_stop():
        #     # Call original stop
        #     original_stop()

        #     # Filter packets based on ip_mode
        #     if not (ip_mode.ipv4 and ip_mode.ipv6):
        #         filtered_results = []
        #         for pkt in packets.results:
        #             if ip_mode.ipv4 and not ip_mode.ipv6:
        #                 # Remove IPv6 packets
        #                 if IPv6 not in pkt:
        #                     filtered_results.append(pkt)
        #             elif ip_mode.ipv6 and not ip_mode.ipv4:
        #                 # Remove IPv4 packets
        #                 if IP not in pkt:
        #                     filtered_results.append(pkt)
        #         packets.results = filtered_results

        # # Replace stop method with filtered version
        # packets.stop = filtered_stop

        return packets

    @staticmethod
    def scan_time(interface, time):
        """
        Sniff packets for a certain time period.

        input: interface (str), time (int)
        output: list of scapy packets
        """
        packets = sniff(iface=interface, timeout=time)
        return packets


class Save:
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
    def save_async(packets):
        """
        Save sniffed packets from asynchronous sniffing to a CSV file.

        input: packets (list of scapy packets)
        output: None (writes to file)
        """
        packets_file = get_csv_path("packets.csv")
        with open(packets_file, 'a', newline='') as csvfile:
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
                        'protocol': packet[IPv6].nh,
                        'length': len(packet)
                    })
                elif i == 1:
                    writer.writerow({
                        'time': packet.time,
                        'source IP': packet[IP].src,
                        'destination IP': packet[IP].dst,
                        'src MAC': packet[Ether].src,
                        'des MAC': packet[Ether].dst,
                        'protocol': packet[IP].proto,
                        'length': len(packet)
                    })
                elif i == 2:
                    writer.writerow({
                        'time': packet.time,
                        'src MAC': packet[Dot3].src,
                        'des MAC': packet[Dot3].dst,
                        'length': len(packet)
                    })
                elif i == 3:
                    writer.writerow({
                        'time': packet.time,
                        'src MAC': packet[Ether].src,
                        'des MAC': packet[Ether].dst,
                        'length': len(packet)
                    })
                elif i == 4:
                    writer.writerow({
                        'time': packet.time,
                        'src MAC': packet[Dot11].src,
                        'des MAC': packet[Dot11].dst,
                        'length': len(packet)
                    })

    @staticmethod
    def save_packets(interface, ip_mode, packets):
        """
        Store all packets into CSV files and update device/address info.

        input: interface (str), ip_mode (IPMode), packets (list of scapy packets)
        output: None (writes to files, updates objects)
        """
        Save.save_async(packets)
        src_mac = get_if_hwaddr(interface)

        for packet in packets:
            # Cooked (SLL) and "any" captures carry no Ethernet header, so the
            # link-layer source is empty and every row would be keyed on "".
            if not packet.haslayer(Ether) and not packet.haslayer(Dot3):
                logger.debug("Skipping packet without a link-layer header (cooked capture?)")
                continue

            mac_src = packet[0].src
            if not mac_src:
                logger.debug("Skipping packet with an empty source MAC")
                continue

            packet_time = convert_timestamp_to_date(packet.time)
            packet_line = Save.packet_to_one_line(packet)

            time_entity = Time(packet_time, mac_src, packet_line)
            time_entity.save_time()

            if mac_src != src_mac:
                time_entity.save_time_incoming()
            else:
                time_entity.save_time_outgoing()

            if packet is not None:
                if packet.haslayer(EAPOL) and mac_src != src_mac:
                    EAP(mac_src, str(packet.summary())).save_eap()

            if packet is not None and IP not in packet and IPv6 not in packet:
                Node(mac_src, "").save_addresses()
            if packet is not None and IP in packet:
                Node(mac_src, packet[IP].src).save_addresses()
            if packet is not None and IPv6 in packet:
                Node(mac_src, packet[0][1].src).save_addresses()

            if packet is not None and IPv6 in packet:
                if packet[0].dst == src_mac:
                    if is_global_unicast_ipv6(packet[0][1].src) and is_global_unicast_ipv6(packet[0][1].dst):
                        Remote_node(packet[0].src, packet[0][1].src, packet[0].dst, packet[0][1].dst).save_remote_node()

            if packet is not None and ICMPv6ND_RA in packet:
                with _protocol_guard("RA", mac_src):
                    Save.save_router_advertisement(packet)

            if packet is not None and ICMPv6MLReport2 in packet:
                with _protocol_guard("MLDv2 report", mac_src):
                    # records_number is attacker-controlled; the parsed record list
                    # is the only trustworthy bound.
                    for record in packet[ICMPv6MLReport2].records or []:
                        MLDv2(packet[0].src, packet[0][1].src, 'Report v2',
                              convert_mldv2_igmpv3_rtype(record.rtype),
                              record.dst,
                              record.sources).save_MLDv2()
                        if in6_isllsnmaddr(record.dst):
                            Node(packet[0].src, record.dst).save_addresses()

            if packet is not None and ICMPv6MLReport in packet:
                with _protocol_guard("MLDv1 report", mac_src):
                    MLDv1(packet[0].src, packet[0][1].src, 'Report v1', packet[0].mladdr).save_MLDv1()
                    if in6_isllsnmaddr(packet[0].mladdr):
                        Node(packet[0].src, packet[0].mladdr).save_addresses()

            if packet is not None and ICMPv6MLDone in packet:
                with _protocol_guard("MLDv1 done", mac_src):
                    MLDv1(packet[0].src, packet[0][1].src, 'Done v1', packet[0].mladdr).save_MLDv1()
                    if in6_isllsnmaddr(packet[0].mladdr):
                        Node(packet[0].src, packet[0].mladdr).save_addresses()

            if packet is not None and ICMPv6MLQuery2 in packet:
                with _protocol_guard("MLDv2 query", mac_src):
                    Save.save_mld_querier(packet)

            if packet is not None and (IGMPv3 in packet and packet[IGMPv3].type == 0x22):
                with _protocol_guard("IGMPv3 report", mac_src):
                    # numgrp is attacker-controlled the same way records_number is.
                    for record in packet[IGMPv3mr].records or []:
                        IGMPv3_ptnet(packet[0].src, packet[IP].src, 'Report v3',
                               convert_mldv2_igmpv3_rtype(record.rtype),
                               record.maddr,
                               record.srcaddrs).save()

            if packet is not None and (IGMP in packet and packet[IGMP].type == 0x16):
                with _protocol_guard("IGMPv2 report", mac_src):
                    IGMPv1v2(packet[0].src, packet[IP].src, 'Report v2', packet[IGMP].gaddr).save()

            if packet is not None and (IGMP in packet and packet[IGMP].type == 0x12):
                with _protocol_guard("IGMPv1 report", mac_src):
                    IGMPv1v2(packet[0].src, packet[IP].src, 'Report v1', packet[IGMP].gaddr).save()

            # An IGMPv3 query dissects as IGMPv3/IGMPv3mq with no IGMP layer,
            # so gating on IGMP alone missed every IGMPv3 querier.
            if packet is not None and ((IGMP in packet and packet[IGMP].type == 0x11)
                                       or (IGMPv3 in packet and packet[IGMPv3].type == 0x11)):
                with _protocol_guard("IGMP query", mac_src):
                    Save.save_igmp_querier(packet)

            if packet is not None and ICMPv6ND_NA in packet:
                Node(packet[0].src, packet[0][1].src).save_addresses()
                if packet[ICMPv6ND_NA].R == 1:
                    Router.save_router_address(packet[0].src)

            if packet is not None and (ICMPv6NIReplyName in packet
                                       or ICMPv6NIReplyIPv6 in packet
                                       or ICMPv6NIReplyIPv4 in packet):
                with _protocol_guard("Node Information reply", mac_src):
                    Save.save_node_information(packet)

            if packet is not None and ICMPv6ND_NS in packet:
                with _protocol_guard("DAD", mac_src):
                    # An unspecified source marks Duplicate Address Detection: the
                    # target is an address the sender is claiming right now.
                    if packet[0][1].src == "::" and in6_isllsnmaddr(packet[0][1].dst):
                        Node(packet[0].src, packet[ICMPv6ND_NS].tgt).save_addresses()

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
                                except Exception as ex:
                                    logger.debug("Failed to parse LLMNR answer for %s: %s", packet[0].src, ex)

            # mDNS runs on UDP/5353. Without the port check every ordinary unicast
            # DNS response matched here, so answers about remote hosts were recorded
            # as addresses of whichever device relayed them (LLMNR guards on 5355).
            if (packet is not None and DNSRR in packet and DNS in packet
                    and UDP in packet and 5353 in (packet[UDP].sport, packet[UDP].dport)):
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
                                    if not Save._is_service_discovery_ptr(packet.an[i]):
                                        Node.save_local_name(packet[0].src, packet.an[i].rdata.decode())
                        except AttributeError as ex:
                            logger.debug("Skipping malformed mDNS answer for %s: %s", packet[0].src, ex)
                            continue
                        except IndexError as ex:
                            logger.debug("mDNS answer index out of range for %s: %s", packet[0].src, ex)
                            break

                with _protocol_guard("DNS-SD", mac_src):
                    Save.save_dnssd_records(packet)


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
                    except Exception as ex:
                        logger.debug("Failed to parse DHCPv6 server DUID for %s: %s", packet[0].src, ex)

            if packet is not None and (DHCP6_Reply in packet or DHCP6_Advertise in packet):
                with _protocol_guard("DHCPv6 options", mac_src):
                    Save.save_dhcpv6_options(packet)

            if packet is not None and DHCP in packet:
                with _protocol_guard("DHCP", mac_src):
                    message_type = _dhcp_message_type(packet)
                    if message_type == 3:
                        requested = find_requested_addr(packet[0][DHCP].options)
                        if requested:
                            DHCP_ptnet(packet[0].src, requested, "client").save_addresses()
                            Node(packet[0].src, requested).save_addresses()
                    # OFFER announces the server, ACK is what confirms the lease;
                    # a capture that only caught the ACK used to miss the server.
                    elif message_type in (2, 5):
                        DHCP_ptnet(packet[0].src, packet[IP].src, "server").save_addresses()
                        Node(packet[0].src, packet[IP].src).save_addresses()
                        for option in packet[0][DHCP].options or []:
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

            with _protocol_guard("fingerprint", mac_src):
                Save.save_fingerprint(packet, src_mac)
        sort_csv(get_csv_path('packets.csv'), get_csv_path('addresses.csv'))

    @staticmethod
    def save_router_advertisement(packet):
        """Record every option an RA carries, not only the first of each kind.

        ``packet[ICMPv6NDOptPrefixInfo]`` returns the first Prefix Information
        option only, so a router advertising a GUA and a ULA prefix in one RA -
        or renumbering - had everything after the first silently dropped. One
        RA.csv row is written per advertised prefix, and the options the parser
        never looked at land in ra_options.csv.
        """
        mac = packet[0].src
        ip = packet[0][1].src
        ra = packet[ICMPv6ND_RA]

        dns_servers = []
        for opt in _iter_layers(packet, ICMPv6NDOptRDNSS):
            for server in (opt.dns or []):
                if server not in dns_servers:
                    dns_servers.append(server)
                RAOption(mac, ip, "RDNSS", str(server), str(opt.lifetime)).save()

        mtu = ""
        for opt in _iter_layers(packet, ICMPv6NDOptMTU):
            mtu = str(opt.mtu)
            RAOption(mac, ip, "MTU", mtu).save()
            break

        prefixes = []
        for opt in _iter_layers(packet, ICMPv6NDOptPrefixInfo):
            prefixes.append((f"{opt.prefix}/{opt.prefixlen}", str(opt.validlifetime),
                             str(opt.preferredlifetime), opt.A, opt.L))
            RAOption(mac, ip, "Prefix Information", f"{opt.prefix}/{opt.prefixlen}",
                     str(opt.validlifetime), f"A={opt.A} L={opt.L}").save()

        # DNS search domains leak internal domain names (RFC 8106).
        for opt in _iter_layers(packet, ICMPv6NDOptDNSSL):
            for domain in (opt.searchlist or []):
                value = Save._decode_dns_name(domain)
                if value:
                    RAOption(mac, ip, "DNSSL", value, str(opt.lifetime)).save()

        # More-specific routes reveal internal segments (RFC 4191).
        for opt in _iter_layers(packet, ICMPv6NDOptRouteInfo):
            RAOption(mac, ip, "Route Information", f"{opt.prefix}/{opt.plen}",
                     str(opt.rtlifetime), convert_preferenceRA(opt.prf)).save()

        # Presence of a NAT64/DNS64 prefix (RFC 8781).
        for opt in _iter_layers(packet, ICMPv6NDOptPREF64):
            RAOption(mac, ip, "PREF64", str(opt.prefix), str(opt.scaledlifetime)).save()

        # Captive portal URL (RFC 8910).
        for opt in _iter_layers(packet, ICMPv6NDOptCaptivePortal):
            uri = opt.URI
            value = uri.decode(errors="replace") if isinstance(uri, bytes) else str(uri)
            RAOption(mac, ip, "Captive Portal", value).save()

        for opt in _iter_layers(packet, ICMPv6NDOptAdvInterval):
            RAOption(mac, ip, "Advertisement Interval", str(opt.advint)).save()

        dns = str(dns_servers) if dns_servers else ""

        if not prefixes:
            prefixes = [("", "", "", "Not exist", "Not exist")]

        for prefix, valid_lft, preferred_lft, a_flag, l_flag in prefixes:
            Router(mac, ip, convert_OnOff(ra.M), convert_OnOff(ra.O), convert_OnOff(ra.H),
                   convert_OnOff(a_flag), convert_OnOff(l_flag),
                   convert_preferenceRA(ra.prf), str(ra.routerlifetime),
                   str(ra.reachabletime), str(ra.retranstimer),
                   dns, mtu, prefix, valid_lft, preferred_lft).save_RA()

        Node(mac, ip).save_addresses()
        Router.save_router_address(mac)

    @staticmethod
    def save_node_information(packet):
        """Record a node's own answer about its name and its addresses.

        The address list is the valuable half: it contains addresses the node
        never advertised, so each one is also folded into the address inventory.
        """
        mac = packet[0].src
        ip = packet[0][1].src if IPv6 in packet else ""

        if ICMPv6NIReplyName in packet:
            for entry in (packet[ICMPv6NIReplyName].data or []):
                # Scapy yields [ttl, name]; only the name is of interest.
                if isinstance(entry, bytes):
                    name = entry.decode(errors="replace").rstrip(".")
                    if name:
                        NodeInfo(mac, ip, "Node name", name).save()
                        Node.save_local_name(mac, name)

        for layer, label in ((ICMPv6NIReplyIPv6, "IPv6 address"),
                             (ICMPv6NIReplyIPv4, "IPv4 address")):
            if layer not in packet:
                continue
            for entry in (packet[layer].data or []):
                address = entry[1] if isinstance(entry, (tuple, list)) and len(entry) > 1 else entry
                address = str(address).strip()
                if not address:
                    continue
                NodeInfo(mac, ip, label, address).save()
                Node(mac, address).save_addresses()

    @staticmethod
    def save_mld_querier(packet):
        """Record the sender of an MLDv2 General Query as the elected querier."""
        query = packet[ICMPv6MLQuery2]
        Querier(packet[0].src, packet[0][1].src, "MLDv2",
                str(query.mladdr), str(query.QRV), str(query.QQIC), str(query.mrd)).save()

    @staticmethod
    def save_igmp_querier(packet):
        """Record the sender of an IGMP General Query as the elected querier.

        The group and the max-response time live on a different layer in each
        version: IGMPv1/v2 keep them on `IGMP`, while an IGMPv3 query is
        dissected as IGMPv3/IGMPv3mq with no `IGMP` layer at all. Reading them
        off `IGMP` unconditionally raised an IndexError on every IGMPv3 query,
        which the protocol guard then swallowed - so the querier a modern
        segment actually elects was never recorded.
        """
        if IGMPv3mq in packet:
            query = packet[IGMPv3mq]
            protocol = "IGMPv3"
            group = str(query.gaddr)
            qrv = str(query.qrv)
            qqic = str(query.qqic)
            max_response = str(packet[IGMPv3].mrcode)
        else:
            protocol = "IGMPv2" if packet[IGMP].mrcode else "IGMPv1"
            group = str(packet[IGMP].gaddr)
            qrv = qqic = ""
            max_response = str(packet[IGMP].mrcode)

        Querier(packet[0].src, packet[IP].src, protocol, group, qrv, qqic,
                max_response).save()

    @staticmethod
    def save_dnssd_records(packet):
        """Extract the DNS-SD service tree from an mDNS response.

        PTR answers name service types and instances, SRV gives the host and
        port an instance actually listens on, and TXT carries the model/version
        strings that turn "a host is up" into a named device.
        """
        mac = packet[0].src
        ip = packet[0][1].src
        dns = packet[DNS]

        sections = []
        for name, count in (("an", dns.ancount), ("ar", getattr(dns, "arcount", 0))):
            records = getattr(dns, name, None)
            if records is None:
                continue
            for index in range(count or 0):
                try:
                    sections.append(records[index])
                except (IndexError, AttributeError):
                    break

        for record in sections:
            rrname = Save._decode_dns_name(getattr(record, "rrname", b""))
            rtype = getattr(record, "type", None)

            if rtype == 12:  # PTR: service type -> instance
                target = Save._decode_dns_name(getattr(record, "rdata", b""))
                if rrname.startswith("_services._dns-sd._udp"):
                    DNSSD(mac, ip, service=target).save()
                elif rrname.startswith("_"):
                    DNSSD(mac, ip, service=rrname, instance=target).save()
            elif rtype == 33:  # SRV: instance -> host:port
                target = Save._decode_dns_name(getattr(record, "target", b""))
                DNSSD(mac, ip, instance=rrname, target=target,
                      port=str(getattr(record, "port", ""))).save()
            elif rtype == 16:  # TXT: instance metadata
                text = getattr(record, "rdata", b"")
                if isinstance(text, list):
                    parts = [t.decode(errors="replace") if isinstance(t, bytes) else str(t) for t in text]
                    value = "; ".join(p for p in parts if p)
                else:
                    value = text.decode(errors="replace") if isinstance(text, bytes) else str(text)
                if value:
                    DNSSD(mac, ip, instance=rrname, txt=value[:500]).save()

    @staticmethod
    def _is_service_discovery_ptr(record) -> bool:
        """True when a PTR answer names a DNS-SD service rather than a host.

        Service-type and service-instance PTRs are what the DNS-SD walk asks
        for; they belong in the service inventory, not in the device's hostname.
        """
        rrname = Save._decode_dns_name(getattr(record, "rrname", b""))
        return rrname.startswith("_") or "._dns-sd._" in rrname

    @staticmethod
    def _decode_dns_name(value) -> str:
        if isinstance(value, bytes):
            value = value.decode(errors="replace")
        return str(value).rstrip(".")

    @staticmethod
    def save_dhcpv6_options(packet):
        """Record the configuration a DHCPv6 server hands out, plus its identity."""
        mac = packet[0].src
        ip = packet[IPv6].src if IPv6 in packet else ""

        for opt in _iter_layers(packet, DHCP6OptDNSServers):
            for server in (opt.dnsservers or []):
                DHCPv6Options(mac, ip, "DNS server", str(server)).save()

        for opt in _iter_layers(packet, DHCP6OptDNSDomains):
            for domain in (opt.dnsdomains or []):
                value = Save._decode_dns_name(domain)
                if value:
                    DHCPv6Options(mac, ip, "Domain search list", value).save()

        for opt in _iter_layers(packet, DHCP6OptSNTPServers):
            for server in (opt.sntpservers or []):
                DHCPv6Options(mac, ip, "SNTP server", str(server)).save()

        for opt in _iter_layers(packet, DHCP6OptNTPServer):
            DHCPv6Options(mac, ip, "NTP server", str(opt.ntpserver)).save()

        for opt in _iter_layers(packet, DHCP6OptSIPServers):
            for server in (opt.sipservers or []):
                DHCPv6Options(mac, ip, "SIP server", str(server)).save()

        for opt in _iter_layers(packet, DHCP6OptSIPDomains):
            for domain in (opt.sipdomains or []):
                value = Save._decode_dns_name(domain)
                if value:
                    DHCPv6Options(mac, ip, "SIP domain", value).save()

        for opt in _iter_layers(packet, DHCP6OptBootFileUrl):
            url = opt.optdata
            value = url.decode(errors="replace") if isinstance(url, bytes) else str(url)
            DHCPv6Options(mac, ip, "Boot file URL", value).save()

        for opt in _iter_layers(packet, DHCP6OptVendorClass):
            DHCPv6Options(mac, ip, "Vendor class", f"enterprise {opt.enterprisenum}").save()

        for opt in _iter_layers(packet, DHCP6OptVendorSpecificInfo):
            DHCPv6Options(mac, ip, "Vendor specific", f"enterprise {opt.enterprisenum}").save()

        for opt in _iter_layers(packet, DHCP6OptServerId):
            DHCPv6Options(mac, ip, "Server DUID", bytes(opt.duid).hex()).save()

    @staticmethod
    def save_fingerprint(packet, src_mac):
        """Derive a passive host fingerprint from fields already in the packet.

        Costs no extra traffic: the hop limit is in every IPv6 header, the
        interface-identifier style follows from the address itself, and the RA
        timers are read from RAs the scan already stores.
        """
        mac = packet[0].src
        if mac == src_mac:
            return

        hop_limit = ""
        iid_type = ""
        os_guess = ""

        hop_limit_is_meaningful = _hop_limit_is_stack_default(packet)

        if IPv6 in packet:
            iid_type = classify_ipv6_iid(packet[IPv6].src, mac)
            if hop_limit_is_meaningful:
                hop_limit = str(packet[IPv6].hlim)
                os_guess = guess_os_from_hop_limit(packet[IPv6].hlim)
        elif IP in packet:
            if hop_limit_is_meaningful:
                hop_limit = str(packet[IP].ttl)
                os_guess = guess_os_from_hop_limit(packet[IP].ttl)

        reachable_time = retrans_time = router_lft = ""
        if ICMPv6ND_RA in packet:
            ra = packet[ICMPv6ND_RA]
            reachable_time = str(ra.reachabletime)
            retrans_time = str(ra.retranstimer)
            router_lft = str(ra.routerlifetime)

        if not any((hop_limit, iid_type, reachable_time)):
            return

        # One row per MAC per distinct observation is enough; the registry keys
        # on the full tuple, so an unchanged repeat is dropped.

        Fingerprint(mac, hop_limit, os_guess, iid_type,
                    reachable_time, retrans_time, router_lft).save()

class Run:
    @staticmethod
    def run_normal_mode(interface, mode, ip_mode, timeout, csv_lock=None):
        """Run normal (passive/active/802.1x) scanning workflow.

        Args:
            interface (str): Network interface name.
            mode (str): One of "802.1x", "p", "a".
            ip_mode (IPMode): Enabled IP versions.
            timeout (int | None): Duration for passive capture or 802.1x wait.
            csv_lock (multiprocessing.Lock | None): Optional shared lock used
                to serialize CSV writes across processes.
        Returns:
            None. Writes CSV artifacts and updates derived files.
        """
        def _csv_guard():
            return csv_lock if csv_lock is not None else nullcontext()

        def stop_responder(process, stop_event, graceful_timeout=2.0):
            if process is None:
                return
            if stop_event is not None:
                stop_event.set()
            process.join(timeout=graceful_timeout)
            if process.is_alive():
                process.terminate()
                process.join()

        exist_interface = Interface(interface).check_interface()
        if exist_interface:
            start_time = str(datetime.now())
            with _csv_guard():
                Time.save_start_end(start_time)

            if mode == "802.1x":
                pkts = Sniff.scan_async(interface)
                pkts.start()
                time.sleep(1)
                Send.send_8021x_security(interface)
                time.sleep(timeout)
                pkts.stop()
                with _csv_guard():
                    Save.save_packets(interface, ip_mode, pkts.results)
                finish_time = str(datetime.now())
                with _csv_guard():
                    Time.save_start_end(finish_time)

            if mode == "p":
                pkts = Sniff.scan_time(interface, timeout)
                finish_time = str(datetime.now())
                with _csv_guard():
                    Time.save_start_end(finish_time)
                    Save.save_packets(interface, ip_mode, pkts)

            if mode == "a":
                multicast_ipv6_responder = None
                multicast_ipv4_responder = None
                multicast_ipv6_stop_event = None
                multicast_ipv4_stop_event = None
                pkts = Sniff.scan_async(interface)
                pkts.start()
                time.sleep(1)
                if ip_mode.ipv6:
                    SendIPv6.send_MLD_report_join(interface)
                if ip_mode.ipv4:
                    SendIPv4.send_igmp_report_join(interface)
                time.sleep(1)
                if ip_mode.ipv6:
                    multicast_ipv6_stop_event = multiprocessing.Event()
                    multicast_ipv6_responder = multiprocessing.Process(
                        target=_forked_target,
                        args=(SendIPv6.react_to_mld_queries, ["a", interface, None, multicast_ipv6_stop_event]))
                    multicast_ipv6_responder.start()
                if ip_mode.ipv4:
                    multicast_ipv4_stop_event = multiprocessing.Event()
                    multicast_ipv4_responder = multiprocessing.Process(
                        target=_forked_target,
                        args=(SendIPv4.react_to_igmp_queries, ["a", interface, None, multicast_ipv4_stop_event]))
                    multicast_ipv4_responder.start()
                if ip_mode.ipv6:
                    SendIPv6.send_MLD_query(interface)
                    SendIPv6.send_normal_multicast_ping(interface)
                    SendIPv6.send_empty_ipv6_dest_opt(interface)
                    SendIPv6.send_empty_ipv6_hbh(interface)
                    SendIPv6.send_invalid_multicast_icmpv6(interface)
                    SendIPv6.send_invalid_multicast_ping(interface)
                    SendIPv6.send_invalid_ipv6_hbh(interface)
                    SendIPv6.send_RS(interface)
                if ip_mode.ipv4:
                    SendIPv4.send_igmp_membership_query(3, interface)
                    #SendIPv4.send_igmp_membership_query(3, interface, "224.0.0.1")
                    time.sleep(1)
                    SendIPv4.send_igmp_membership_query(2, interface)
                    #SendIPv4.send_igmp_membership_query(2, interface, "224.0.0.1")
                    time.sleep(1)
                    SendIPv4.send_igmp_membership_query(1, interface)
                    #SendIPv4.send_igmp_membership_query(1, interface, "224.0.0.1")
                    for icmp_type in ICMPType:
                        if icmp_type == ICMPType.ROUTER_SOLICITATION:
                            SendIPv4.send_local_icmp("224.0.0.2", interface, icmp_type)
                        else:
                            SendIPv4.send_local_icmp("224.0.0.1", interface, icmp_type)
                        SendIPv4.send_local_icmp("255.255.255.255", interface, icmp_type)
                        SendIPv4.send_subnet_broadcast_icmp(interface, icmp_type)
                with _csv_guard():
                    Send.probe_gateways(interface, ip_mode)
                    Send.probe_interesting_network_addresses(interface, ip_mode)
                    Send.send_dhcp_probe(interface, ip_mode)
                    Send.send_wsdiscovery_probe(interface, ip_mode)
                    Send.send_dns_sd_probe(interface, ip_mode)
                time.sleep(2.5)
                pkts.stop()
                with _csv_guard():
                    Save.save_packets(interface, ip_mode, pkts.results)
                pkts = Sniff.scan_async(interface) # Fix for closing of the socket
                pkts.start()
                Send.send_llmnr_mdns(interface, ip_mode)
                time.sleep(1.5)
                pkts.stop()
                with _csv_guard():
                    Save.save_packets(interface, ip_mode, pkts.results)

                # Follow-ups that need what the previous window revealed: the
                # service tree can only be walked once the service types are
                # known, and NI queries are aimed at the nodes already found.
                pkts = Sniff.scan_async(interface)
                pkts.start()
                with _csv_guard():
                    Send.send_dnssd_walk(interface, ip_mode)
                    Send.send_node_information_queries(
                        interface, ip_mode, Send.collect_known_addresses(ip_mode)
                    )
                    Send.send_snooping_probes(interface, ip_mode)
                time.sleep(2)
                pkts.stop()
                with _csv_guard():
                    Save.save_packets(interface, ip_mode, pkts.results)
                pkts = Sniff.scan_async(interface) # Fix for closing of the socket
                pkts.start()
                if ip_mode.ipv6:
                    SendIPv6.send_to_possible_IP(interface)
                    SendIPv6.send_to_test_RA_guard(interface)
                time.sleep(1)
                stop_responder(multicast_ipv6_responder, multicast_ipv6_stop_event)
                stop_responder(multicast_ipv4_responder, multicast_ipv4_stop_event)
                if ip_mode.ipv6:
                    SendIPv6.send_MLD_done_leave(interface)
                if ip_mode.ipv4:
                    SendIPv4.send_igmp_done_leave(interface)
                time.sleep(1)
                pkts.stop()
                with _csv_guard():
                    Save.save_packets(interface, ip_mode, pkts.results)
                finish_time = str(datetime.now())
                with _csv_guard():
                    Time.save_start_end(finish_time)
                    Node.get_ipv6_route_metrics_and_addresses()
                    Node.get_ipv4_route_metrics_and_addresses()

            with _csv_guard():
                remove_duplicates_from_csv(get_csv_path("MDNS.csv"))
                remove_duplicates_from_csv(get_csv_path("LLMNR.csv"))
                remove_duplicates_from_csv(get_csv_path("MLDv1.csv"))
                remove_duplicates_from_csv(get_csv_path("MLDv2.csv"))
                remove_duplicates_from_csv(get_csv_path("RA.csv"))
                remove_duplicates_from_csv(get_csv_path("localname.csv"))
                sort_csv_role_node(interface, get_csv_path("role_node.csv", interface))

    @staticmethod
    def run_aggressive_mode(interface, ip_mode, prefix_len, network, source_mac, source_ip, rpref, duration, period, chl, mtu, dns):
        """Run aggressive scanning workflow (active senders + parallel capture).

        Spawns multiple processes to flood RA/NS/RS and concurrently run normal
        active and passive flows.

        Args:
            interface (str): Network interface name.
            ip_mode (IPMode): Enabled IP versions.
            prefix_len (int): IPv6 prefix length for RA.
            network (str): IPv6 network/prefix for RA.
            source_mac (str): Source MAC to use in frames.
            source_ip (str): Source IP to use where applicable.
            rpref (str): Router preference for RA.
            duration (int): Duration for aggressive run.
            period (int): Period for repeating sends.
            chl (str): Channel or auxiliary param used by senders.
            mtu (int): MTU to advertise.
            dns (str | list[str]): DNS server(s) to advertise.
        Returns:
            None. Coordinates subprocesses and writes CSV artifacts.
        """
        def stop_responder(process, stop_event, graceful_timeout=2.0):
            if process is None:
                return
            if stop_event is not None:
                stop_event.set()
            process.join(timeout=graceful_timeout)
            if process.is_alive():
                process.terminate()
                process.join()

        # Scan jobs
        csv_lock = multiprocessing.Lock()
        send_ra = multiprocessing.Process(
            target=_forked_target,
            args=(SendIPv6.send_RA, [interface, prefix_len, network, source_mac, source_ip, rpref, chl, mtu, dns, True, period, duration]))
        react_to_ns_rs = multiprocessing.Process(
            target=_forked_target,
            args=(SendIPv6.react_to_NS_RS, [interface, prefix_len, network, source_mac, source_ip, rpref, chl, mtu, dns, duration]))
        active_scan = multiprocessing.Process(
            target=_forked_target, args=(Run.run_normal_mode, [interface, "a", ip_mode, duration, csv_lock]))
        passive_scan = multiprocessing.Process(
            target=_forked_target, args=(Run.run_normal_mode, [interface, "p", ip_mode, duration, csv_lock]))

        # Multicast helpers
        multicast_ipv6_responder = None
        multicast_ipv4_responder = None
        multicast_ipv6_stop_event = None
        multicast_ipv4_stop_event = None
        if ip_mode.ipv6:
            multicast_ipv6_stop_event = multiprocessing.Event()
            multicast_ipv6_unsubscribe = multiprocessing.Process(
                target=_forked_target, args=(SendIPv6.send_MLD_done_leave, [interface, True]))
            multicast_ipv6_responder = multiprocessing.Process(
                target=_forked_target,
                args=(SendIPv6.react_to_mld_queries, ["a+", interface, duration, multicast_ipv6_stop_event]))
        if ip_mode.ipv4:
            multicast_ipv4_stop_event = multiprocessing.Event()
            multicast_ipv4_unsubscribe = multiprocessing.Process(
                target=_forked_target, args=(SendIPv4.send_igmp_done_leave, [interface, True]))
            multicast_ipv4_responder = multiprocessing.Process(
                target=_forked_target,
                args=(SendIPv4.react_to_igmp_queries, ["a+", interface, duration, multicast_ipv4_stop_event]))

        # Cleanup jobs
        flush_router_flag_from_cache = multiprocessing.Process(
            target=_forked_target,
            args=(SendIPv6.send_NA, [interface, source_mac, None, source_ip, "ff02::1", 0, 0, 1]))

        # Force multicast joins for aggressive mode, then keep responders running.
        if ip_mode.ipv6:
            SendIPv6.send_MLD_report_join(interface, True)
        if ip_mode.ipv4:
            SendIPv4.send_igmp_report_join(interface, True)

        # Start multicast responders
        if ip_mode.ipv6:
            multicast_ipv6_responder.start()
        if ip_mode.ipv4:
            multicast_ipv4_responder.start()

        # Start scan jobs
        if ip_mode.ipv6:
            react_to_ns_rs.start()
            send_ra.start()
        passive_scan.start()
        time.sleep(0.5)
        active_scan.start()

        # Join scan threads
        if ip_mode.ipv6:
            send_ra.join()
            react_to_ns_rs.join()
        active_scan.join()
        passive_scan.join()

        # Stop multicast responders after scan workload is done.
        stop_responder(multicast_ipv6_responder, multicast_ipv6_stop_event)
        stop_responder(multicast_ipv4_responder, multicast_ipv4_stop_event)

        # Start cleanup jobs
        if ip_mode.ipv6:
            multicast_ipv6_unsubscribe.start()
            flush_router_flag_from_cache.start()
        if ip_mode.ipv4:
            multicast_ipv4_unsubscribe.start()

        # Join cleanup threads
        if ip_mode.ipv6:
            multicast_ipv6_unsubscribe.join()
            flush_router_flag_from_cache.join()
        if ip_mode.ipv4:
            multicast_ipv4_unsubscribe.join()