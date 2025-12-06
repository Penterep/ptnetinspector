import csv
import re
import socket

from urllib.parse import urlparse
from scapy.packet import Raw
from ptnetinspector.utils.path import get_csv_path


def parse_wsdiscovery(packet: bytes) -> list:
    """
    Parse WS-Discovery packets to extract XAddrs.

    Args:
        packet (bytes): The packet data.

    Returns:
        list: A list of extracted addresses.
    """

    found_addresses = []

    xml_data = packet[Raw].load.decode('utf-8', errors='ignore')
    xaddrs_pattern = r'<wsd:XAddrs>(.*?)</wsd:XAddrs>'
    xaddrs_match = re.search(xaddrs_pattern, xml_data, re.DOTALL)

    if xaddrs_match:
        xaddrs_content = xaddrs_match.group(1).strip()
        addresses = xaddrs_content.split()

        for address in addresses:
            parsed_url = urlparse(address)
            host = parsed_url.netloc

            if not host:
                continue

            # remove port from IPv4 address
            if ':' in host:
                if host.count(':') == 1:
                    host = host.split(':')[0]

            # extract host from IPv6 address
            if host.startswith('['):
                host = host[1:host.index(']')]

            # validate if it's IP address
            try:
                socket.inet_pton(socket.AF_INET, host)
                found_addresses.append(host)
                continue
            except socket.error:
                pass
            try:
                socket.inet_pton(socket.AF_INET6, host)
                found_addresses.append(host)
                continue
            except socket.error:
                pass

    return found_addresses


class WSDiscovery:
    all_nodes = []

    def __init__(self, mac: str, ip: str):
        self.mac = mac
        self.ip = ip
        WSDiscovery.all_nodes.append(self)

    def save_addresses(self):
        csv_file = get_csv_path("wsdiscovery.csv")
        
        with open(csv_file, 'a+', newline='') as csvfile:
            csvfile.seek(0)
            for row in csv.DictReader(csvfile):
                if row and row['MAC'] == self.mac and row['IP'] == self.ip:
                    return

            fieldnames = ['MAC', 'IP']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writerow({
                'IP': self.ip,
                'MAC': self.mac
            })

    def __repr__(self):
        return f"{self.__class__.__name__}({self.mac}, {self.ip})"