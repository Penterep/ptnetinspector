import ipaddress
import csv
import socket
import subprocess
from dataclasses import dataclass
from typing import List

from scapy.all import *
from scapy.layers.eap import EAPOL
from scapy.layers.inet6 import ICMPv6ND_NA, ICMPv6NDOptDstLLAddr
from scapy.layers.l2 import Ether, ARP

from ptnetinspector.entities.default_gw import DefaultGateway
from ptnetinspector.utils.interface import Interface
from ptnetinspector.utils.ip_utils import is_global_unicast_ipv6, is_ipv6_ula, is_valid_ipv6, is_link_local_ipv6
from ptnetinspector.utils.path import get_csv_path
from ptnetinspector.send.send_ipv4 import SendIPv4
from ptnetinspector.send.send_ipv6 import SendIPv6


@dataclass
class IPMode:
    def __init__(self, ipv4: bool, ipv6: bool) -> None:
        self.ipv4 = ipv4
        self.ipv6 = ipv6


class Send:
    @staticmethod
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

    @staticmethod
    def send_llmnr_mdns(interface, ip_mode):
        # Function to send LLMNR and mDNS to find the addresses both in layer IP and Payload
        csv_file = get_csv_path('addresses.csv')
        with open(csv_file, newline='') as csvfile:
            # Create a CSV reader object
            reader = csv.reader(csvfile, delimiter=',')
            next(reader)

            # Loop over each row in the CSV file
            for row in reader:

                if len(row) < 2:  # Avoid the situation like this [':fffb:8']
                    continue
                ip_address = row[1]

                if is_valid_ipv6(ip_address) and ip_mode.ipv6:
                    if is_link_local_ipv6(ip_address):
                        SendIPv6.IPv6_test_mdns_llmnr(ip_address, interface)

                    elif is_global_unicast_ipv6(ip_address):
                        SendIPv6.IPv6_test_mdns_llmnr(ip_address, interface)

                    elif is_ipv6_ula(ip_address):
                        SendIPv6.IPv6_test_mdns_llmnr(ip_address, interface)

                elif ip_mode.ipv4:
                    try:
                        ipv4_address = ipaddress.IPv4Address(ip_address)

                        if ipv4_address.is_link_local:
                            continue
                        elif ipv4_address.is_unspecified:
                            continue
                        else:
                            SendIPv4.IPv4_test_mdns_llmnr(ip_address, interface)
                    except ipaddress.AddressValueError:
                        continue

    @staticmethod
    def probe_gateways(interface: str, ip_mode: IPMode) -> None:
        """
        Retrieve all gateways for the specified interface and send probes.

        Args:
            interface (str): Network interface to check
            ip_mode (IPMode): IP version to probe
        """
        gateway_addresses = get_gateway_addresses(interface, ip_mode)

        for address in gateway_addresses:
            try:
                socket.inet_pton(socket.AF_INET, address)
                ans = SendIPv4.send_arp_request(address, interface, True)
                for _, packet in ans:
                    if ARP in packet and packet[ARP].op == 2 and packet[ARP].psrc == address:
                        DefaultGateway(packet[ARP].hwsrc, address).save_addresses()

            except socket.error:
                try:
                    socket.inet_pton(socket.AF_INET6, address)
                    ans = SendIPv6.send_ns(address, interface, True)
                    for _, packet in ans:
                        if ICMPv6ND_NA in packet and ICMPv6NDOptDstLLAddr in packet:
                            if packet[ICMPv6ND_NA].tgt == address:
                                DefaultGateway(packet[ICMPv6NDOptDstLLAddr].lladdr, address).save_addresses()
                except:
                    pass
            except:
                pass

    @staticmethod
    def probe_interesting_network_addresses(interface: str, ip_mode: IPMode) -> None:
        """
        Read networks from networks.csv and send ARP or NS probes to first and last addresses
        in each network depending on IP version.

        For IPv4: Sends to first and last usable address in the network
        For IPv6: Sends to network address with ::0 and ::1

        Args:
            interface (str): Network interface to use for sending probes
            ip_mode (IPMode): IP version to probe
        """
        networks = []

        csv_file = get_csv_path('networks.csv')
        with open(csv_file, 'r') as csvfile:
            reader = csv.reader(csvfile)
            next(reader)  # skip header
            for row in reader:
                if len(row) >= 2:
                    network_prefix, prefix_length = row[0], int(row[1])
                    try:
                        network = ipaddress.ip_network(f"{network_prefix}/{prefix_length}", strict=False)
                        networks.append(network)
                    except:
                        pass

        for network in networks:
            if isinstance(network, ipaddress.IPv4Network) and ip_mode.ipv4:
                SendIPv4.probe_ipv4_interesting_addresses(network, interface)
            elif isinstance(network, ipaddress.IPv6Network) and ip_mode.ipv6:
                SendIPv6.probe_ipv6_interesting_addresses(network, interface)

    @staticmethod
    def send_wsdiscovery_probe(interface: str, ip_mode: IPMode) -> None:
        """
        Send WS-Discovery probe to multicast address on the specified interface.

        Args:
            interface (str): Network interface to use for sending probe
            ip_mode (IPMode): IP version to probe
        """
        if ip_mode.ipv4:
            SendIPv4.send_wsdiscovery_probe(interface)
        if ip_mode.ipv6:
            SendIPv6.send_wsdiscovery_probe(interface)

    @staticmethod
    def send_dns_sd_probe(interface: str, ip_mode: IPMode) -> None:
        """
        Send DNS-SD probe to multicast address on the specified interface.

        Args:
            interface (str): Network interface to use for sending probe
            ip_mode (IPMode): IP version to probe
        """
        if ip_mode.ipv4:
            SendIPv4.send_dns_sd_probe(interface)
        if ip_mode.ipv6:
            SendIPv6.send_dns_sd_probe(interface)

    @staticmethod
    def send_dhcp_probe(interface: str, ip_mode: IPMode) -> None:
        """
        Send DHCP probe on the specified interface. For IPv4, it sends a DHCP discovery packet,
        and for IPv6, it sends a DHCPv6 solicit packet.

        Args:
            interface (str): Network interface to use for sending probe
            ip_mode (IPMode): IP version to probe
        """
        if ip_mode.ipv4:
            SendIPv4.send_dhcp_discover(interface)
        if ip_mode.ipv6:
            SendIPv6.send_dhcpv6_solicit(interface)


def get_gateway_addresses(interface: str, ip_mode: IPMode) -> List[str]:
    """
    Extract gateway addresses from routing table for the specified interface.

    Args:
        interface (str): The network interface to check
        ip_mode (IPMode): IP version to probe

    Returns:
        List[str]: List of gateway IP addresses (both IPv4 and IPv6)
    """
    gateways = []

    if ip_mode.ipv4 and ip_mode.ipv6:
        ip_versions = [4, 6]
    else:
        ip_versions = [4] if ip_mode.ipv4 else [6]

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