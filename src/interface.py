import ipaddress
import netifaces
import subprocess
import random
from scapy.all import *

class Interface:
    """
    Interface class for network interface operations.
    """

    def __init__(self, interface: str):
        """
        Initialize the Interface object.

        Args:
            interface (str): Name of the network interface.
        """
        self.interface = interface

    def get_interface_ips(self) -> list:
        """
        Retrieve all IP addresses (IPv4 and IPv6) of the network interface.

        Returns:
            list: List of IP addresses assigned to the interface.
        """
        interface_ips = []
        if self.interface in netifaces.interfaces():
            interface_addrs = netifaces.ifaddresses(self.interface)
            for addr_type in (netifaces.AF_INET, netifaces.AF_INET6):
                if addr_type in interface_addrs:
                    for addr_info in interface_addrs[addr_type]:
                        interface_ips.append(addr_info['addr'])
        return interface_ips

    def get_interface_ipv4_ips(self) -> list:
        """
        Retrieve IPv4 addresses of the network interface.

        Returns:
            list: List of IPv4 addresses assigned to the interface.
        """
        interface_ips = []
        if self.interface in netifaces.interfaces():
            interface_addrs = netifaces.ifaddresses(self.interface)
            if netifaces.AF_INET in interface_addrs:
                for addr_info in interface_addrs[netifaces.AF_INET]:
                    interface_ips.append(addr_info['addr'])
        return interface_ips

    def get_interface_ipv6_ips(self) -> list:
        """
        Retrieve IPv6 addresses of the network interface.

        Returns:
            list: List of IPv6 addresses assigned to the interface.
        """
        interface_ips = []
        if self.interface in netifaces.interfaces():
            interface_addrs = netifaces.ifaddresses(self.interface)
            if netifaces.AF_INET6 in interface_addrs:
                for addr_info in interface_addrs[netifaces.AF_INET6]:
                    if '%' in addr_info['addr']:
                        interface_ips.append(addr_info['addr'].split('%')[0])
                    else:
                        interface_ips.append(addr_info['addr'])
        return interface_ips

    def get_interface_link_local_list(self) -> list:
        """
        Retrieve link-local IPv6 addresses of the network interface.

        Returns:
            list: List of link-local IPv6 addresses (starting with 'fe80').
        """
        ips = self.get_interface_ips()
        list_ll = []
        for ipv6 in ips:
            if ipv6.startswith("fe80"):
                list_ll.append(ipv6)
        return list_ll

    def check_interface(self) -> bool:
        """
        Check if the network interface exists.

        Returns:
            bool: True if interface exists, False otherwise.
        """
        if not self.interface or self.interface is None:
            return False
        interface_list = netifaces.interfaces()
        return self.interface in interface_list

    def check_available_ipv6(self) -> bool:
        """
        Check if the network interface has any IPv6 addresses.

        Returns:
            bool: True if IPv6 addresses are available, False otherwise.
        """
        try:
            ip_output = subprocess.check_output(
                ["ip", "-6", "addr", "show", self.interface],
                universal_newlines=True
            )
        except subprocess.CalledProcessError as e:
            print(f"Error: {e}")
            exit(1)

        addresses = ip_output.split("\n")
        ipv6_addresses = [line.split()[1] for line in addresses if "inet6" in line]
        return bool(ipv6_addresses)

    @staticmethod
    def generate_ipv6_address(prefix: str) -> str:
        """
        Generate a random IPv6 address using the provided prefix.

        Args:
            prefix (str): IPv6 prefix (e.g., '2001:db8::').

        Returns:
            str: Generated IPv6 address.
        """
        first_half = random.randint(0, 2**64 - 1)
        ipv6_prefix = prefix
        full_address = ipaddress.IPv6Address(ipv6_prefix) + first_half
        return str(full_address)

    def set_ipv6_address(self, ipv6_address: str) -> None:
        """
        Set an IPv6 address on the network interface.

        Args:
            ipv6_address (str): IPv6 address to assign.
        """
        try:
            subprocess.run(
                ["ip", "addr", "add", f"{ipv6_address}/64", "dev", self.interface],
                check=True
            )
        except subprocess.CalledProcessError:
            pass

def reverse_IPadd(ip_address: str) -> str:
    """
    Create a reverse pointer record from an IP address.

    Args:
        ip_address (str): IP address.

    Returns:
        str: Reverse pointer record.
    """
    return ipaddress.ip_address(ip_address).reverse_pointer
