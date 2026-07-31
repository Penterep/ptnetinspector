"""Helpers for network prefix discovery and persistence.

Loads and writes local IPv4/IPv6 network information used by probes/filters.
"""
import csv
import ipaddress
import logging
import netifaces
from ptnetinspector.utils.path import get_csv_path

logger = logging.getLogger(__name__)


class Networks:
    @staticmethod
    def load_networks() -> tuple[list[ipaddress.IPv4Network], list[ipaddress.IPv6Network]]:
        """Load network prefixes from CSV and return IPv4/IPv6 subnets.

        Returns:
            tuple: (list of IPv4 networks, list of IPv6 networks).
        """
        ipv4_subnets = []
        ipv6_subnets = []

        networks_file = get_csv_path("networks.csv")

        with open(networks_file, 'r') as csvfile:
            reader = csv.reader(csvfile)
            next(reader)  # skip header
            for row in reader:
                if len(row) >= 2:
                    network_prefix, prefix_length = row[0], int(row[1])
                    try:
                        network = ipaddress.ip_network(f"{network_prefix}/{prefix_length}")
                        if isinstance(network, ipaddress.IPv4Network):
                            ipv4_subnets.append(network)
                        elif isinstance(network, ipaddress.IPv6Network):
                            ipv6_subnets.append(network)
                    except Exception as ex:
                        logger.debug("Skipping invalid network row %s/%s: %s", network_prefix, prefix_length, ex)

        return ipv4_subnets, ipv6_subnets

    @staticmethod
    def load_ra_prefixes() -> list[ipaddress.IPv6Network]:
        """Load on-link IPv6 prefixes advertised in observed Router Advertisements.

        The scanner's own addresses only reveal the prefixes it configured itself.
        Routers commonly advertise several prefixes on one link, so RA-derived
        prefixes are needed to recognise neighbour addresses as local.

        Returns:
            list: IPv6 networks advertised on the link (empty if none were seen).
        """
        prefixes: list[ipaddress.IPv6Network] = []

        ra_file = get_csv_path("RA.csv")
        try:
            with open(ra_file, 'r') as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    raw = (row.get('Prefix') or '').strip()
                    if not raw or '/' not in raw:
                        continue
                    try:
                        network = ipaddress.ip_network(raw, strict=False)
                    except ValueError as ex:
                        logger.debug("Skipping invalid RA prefix %s: %s", raw, ex)
                        continue
                    if isinstance(network, ipaddress.IPv6Network) and network not in prefixes:
                        prefixes.append(network)
        except FileNotFoundError:
            logger.debug("RA.csv not present; no RA-derived prefixes available")
        except Exception as ex:
            logger.debug("Failed to read RA prefixes from %s: %s", ra_file, ex)

        return prefixes

    @staticmethod
    def get_ipv4_subnets() -> list[ipaddress.IPv4Network]:
        """
        Load and return a list of IPv4 subnets.

        Returns:
            list: A list of IPv4 subnets (ipaddress.IPv4Network objects).
        """
        ipv4_subnets, _ = Networks.load_networks()
        return ipv4_subnets

    @staticmethod
    def get_ipv6_subnets() -> list[ipaddress.IPv6Network]:
        """
        Load and return a list of IPv6 subnets.

        Returns:
            list: A list of IPv6 subnets (ipaddress.IPv6Network objects).
        """
        _, ipv6_subnets = Networks.load_networks()
        return ipv6_subnets

    @staticmethod
    def extract_available_subnets(interface: str) -> None:
        """
        Extract all available subnets (excluding link-local) from a network interface
        and save them to a CSV file.

        Args:
            interface (str): Name of the network interface to extract subnets from.
        """
        subnets = []

        addresses = netifaces.ifaddresses(interface)

        # process IPv4 addresses
        if netifaces.AF_INET in addresses:
            for addr_info in addresses[netifaces.AF_INET]:
                if 'addr' in addr_info and 'netmask' in addr_info:
                    ip = addr_info['addr']
                    netmask = addr_info['netmask']

                    # convert IP and netmask to subnet
                    try:
                        ip_obj = ipaddress.IPv4Address(ip)

                        if not ip_obj.is_link_local:
                            netmask_obj = ipaddress.IPv4Address(netmask)
                            prefix_len = bin(int(netmask_obj)).count('1')
                            network = ipaddress.IPv4Network(f"{ip}/{prefix_len}", strict=False)
                            subnets.append((str(network.network_address), prefix_len))
                    except Exception as ex:
                        logger.debug("Failed to parse IPv4 subnet for %s/%s: %s", ip, netmask, ex)

        # process IPv6 addresses
        if netifaces.AF_INET6 in addresses:
            for addr_info in addresses[netifaces.AF_INET6]:
                if 'addr' in addr_info:
                    ip = addr_info['addr']

                    # remove scope ID if present
                    if '%' in ip:
                        ip = ip.split('%')[0]

                    # get prefix length
                    prefix_len = 128
                    if 'prefixlen' in addr_info:
                        prefix_len = int(addr_info['prefixlen'])
                    elif 'netmask' in addr_info:
                        netmask = addr_info['netmask']
                        if '/' in netmask:
                            prefix_len = int(netmask.split('/')[1])
                        else:
                            try:
                                prefix_len = bin(int(ipaddress.IPv6Address(netmask))).count('1')
                            except Exception as ex:
                                logger.debug("Failed to parse IPv6 netmask %s: %s", netmask, ex)

                    try:
                        ip_obj = ipaddress.IPv6Address(ip)

                        if not ip_obj.is_link_local:
                            network = ipaddress.IPv6Network(f"{ip}/{prefix_len}", strict=False)
                            subnets.append((str(network.network_address), prefix_len))
                    except Exception as ex:
                        logger.debug("Failed to parse IPv6 subnet for %s/%s: %s", ip, prefix_len, ex)

        networks_file = get_csv_path("networks.csv")

        with open(networks_file, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['network_prefix', 'prefix_length'])
            for subnet in subnets:
                writer.writerow(subnet)