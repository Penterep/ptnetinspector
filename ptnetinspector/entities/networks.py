import csv
import ipaddress
import netifaces
from ptnetinspector.utils.path import get_csv_path


class Networks:
    @staticmethod
    def load_networks() -> tuple[list[ipaddress.IPv4Network], list[ipaddress.IPv6Network]]:
        """
        Load networks from a CSV file and return lists of IPv4 and IPv6 subnets.

        Returns:
            tuple: A tuple containing two lists:
                - List of IPv4 subnets (ipaddress.IPv4Network objects)
                - List of IPv6 subnets (ipaddress.IPv6Network objects)
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
                    except:
                        pass

        return ipv4_subnets, ipv6_subnets

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
                    except:
                        pass

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
                            except:
                                pass

                    try:
                        ip_obj = ipaddress.IPv6Address(ip)

                        if not ip_obj.is_link_local:
                            network = ipaddress.IPv6Network(f"{ip}/{prefix_len}", strict=False)
                            subnets.append((str(network.network_address), prefix_len))
                    except Exception as e:
                        pass

        networks_file = get_csv_path("networks.csv")
        
        with open(networks_file, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['network_prefix', 'prefix_length'])
            for subnet in subnets:
                writer.writerow(subnet)