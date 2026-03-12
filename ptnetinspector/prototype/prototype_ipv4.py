from scapy.all import Packet
from scapy.layers.inet import IP, IPOption_Router_Alert
from scapy.layers.l2 import Ether
from scapy.contrib.igmp import IGMP
from scapy.contrib.igmpv3 import IGMPv3, IGMPv3mr, IGMPv3gr

class PrototypeIPv4Packet:
    ALL_NODES_IPV4_MULTICAST_IP = "224.0.0.1"
    ALL_ROUTERS_IPV4_MULTICAST_IP = "224.0.0.2"
    DHCPV4_ALL_SERVERS_MULTICAST_IP = "224.0.0.12"
    IGMPV3_IPV4_MULTICAST_IP = "224.0.0.22"
    MDNS_IPV4_MULTICAST_IP = "224.0.0.251"
    LLMNR_IPV4_MULTICAST_IP = "224.0.0.252"
    WS_DISCOVERY_IPV4_MULTICAST_IP = "239.255.255.250"

    MULTICAST_GROUPS_ACTIVE = [
        ALL_NODES_IPV4_MULTICAST_IP,
        IGMPV3_IPV4_MULTICAST_IP,
        MDNS_IPV4_MULTICAST_IP,
        LLMNR_IPV4_MULTICAST_IP,
        WS_DISCOVERY_IPV4_MULTICAST_IP,
    ]
    MULTICAST_GROUPS_AGGRESSIVE = [
        DHCPV4_ALL_SERVERS_MULTICAST_IP,
        ALL_ROUTERS_IPV4_MULTICAST_IP
    ]

    @staticmethod
    def __get_igmpv2_packet_headers(src_mac: str|None, src_ip: str|None, dst_ip: str) -> Packet:
        return (Ether(src=src_mac) /
                IP(src=src_ip, dst=dst_ip, ttl=1, options=[IPOption_Router_Alert()]))

    def __get_igmpv3_packet_headers(src_mac: str|None, src_ip: str|None) -> Packet:
        return (Ether(src=src_mac) /
                IP(src=src_ip, dst=PrototypeIPv4Packet.IGMPV3_IPV4_MULTICAST_IP, ttl=1, options=[IPOption_Router_Alert()]))

    @staticmethod
    def __get_igmpv2_join(src_mac: str|None, src_ip: str|None, group: str) -> Packet:
        return (PrototypeIPv4Packet.__get_igmpv2_packet_headers(src_mac, src_ip, group) /
                IGMP(type=0x16, gaddr=group))

    @staticmethod
    def __get_igmpv2_leave(src_mac: str|None, src_ip: str|None, group: str) -> Packet:
        return (PrototypeIPv4Packet.__get_igmpv2_packet_headers(src_mac, src_ip, PrototypeIPv4Packet.ALL_ROUTERS_IPV4_MULTICAST_IP) /
                IGMP(type=0x17, gaddr=group))

    @staticmethod
    def __get_igmpv3_join(src_mac: str|None, src_ip: str|None, group: str|list[str]) -> Packet:
        return (PrototypeIPv4Packet.__get_igmpv3_packet_headers(src_mac, src_ip) /
                IGMPv3() / IGMPv3mr(records=[IGMPv3gr(rtype=4, maddr=group)]))

    @staticmethod
    def __get_igmpv3_leave(src_mac: str|None, src_ip: str|None, group: str|list[str]) -> Packet:
        return (PrototypeIPv4Packet.__get_igmpv3_packet_headers(src_mac, src_ip) /
                IGMPv3() / IGMPv3mr(records=[IGMPv3gr(rtype=3, maddr=group)]))

    @staticmethod
    def get_init_igmpv3_active_mode(src_mac: str|None, src_ip: str|None) -> list[Packet]:
        return [PrototypeIPv4Packet.__get_igmpv3_join(src_mac, src_ip, PrototypeIPv4Packet.MULTICAST_GROUPS_ACTIVE)]

    @staticmethod
    def get_init_igmpv2_active_mode(src_mac: str|None, src_ip: str|None) -> list[Packet]:
        return [PrototypeIPv4Packet.__get_igmpv2_join(src_mac, src_ip, group) 
                for group in PrototypeIPv4Packet.MULTICAST_GROUPS_ACTIVE]

    @staticmethod
    def get_finish_igmpv3_active_mode(src_mac: str|None, src_ip: str|None) -> list[Packet]:
        return [PrototypeIPv4Packet.__get_igmpv3_leave(src_mac, src_ip, PrototypeIPv4Packet.MULTICAST_GROUPS_ACTIVE)]

    @staticmethod
    def get_finish_igmpv2_active_mode(src_mac: str|None, src_ip: str|None) -> list[Packet]:
        return [PrototypeIPv4Packet.__get_igmpv2_leave(src_mac, src_ip, group) 
                for group in PrototypeIPv4Packet.MULTICAST_GROUPS_ACTIVE]

    @staticmethod
    def get_init_igmpv3_aggressive_mode(src_mac: str|None, src_ip: str|None) -> list[Packet]:
        return [PrototypeIPv4Packet.__get_igmpv3_join(src_mac, src_ip, PrototypeIPv4Packet.MULTICAST_GROUPS_AGGRESSIVE)]

    @staticmethod
    def get_init_igmpv2_aggressive_mode(src_mac: str|None, src_ip: str|None) -> list[Packet]:
        return [PrototypeIPv4Packet.__get_igmpv2_join(src_mac, src_ip, group) 
                for group in PrototypeIPv4Packet.MULTICAST_GROUPS_AGGRESSIVE]

    @staticmethod
    def get_finish_igmpv3_aggressive_mode(src_mac: str|None, src_ip: str|None) -> list[Packet]:
        return [PrototypeIPv4Packet.__get_igmpv3_leave(src_mac, src_ip, PrototypeIPv4Packet.MULTICAST_GROUPS_AGGRESSIVE)]

    @staticmethod
    def get_finish_igmpv2_aggressive_mode(src_mac: str|None, src_ip: str|None) -> list[Packet]:
        return [PrototypeIPv4Packet.__get_igmpv2_leave(src_mac, src_ip, group) 
                for group in PrototypeIPv4Packet.MULTICAST_GROUPS_AGGRESSIVE]
