import ipaddress
import netifaces
import subprocess
from scapy.all import *

class Interface:
    def __init__(self, interface:str):
        self.interface = interface
    
    def get_interface_ips(self):
        # Function to retrieve IPs of a given network interface
        interface_ips = []
        if self.interface in netifaces.interfaces():
            interface_addrs = netifaces.ifaddresses(self.interface)
            for addr_type in (netifaces.AF_INET, netifaces.AF_INET6):
                if addr_type in interface_addrs:
                    for addr_info in interface_addrs[addr_type]:
                        interface_ips.append(addr_info['addr'])
        return interface_ips

    def get_interface_ipv6_ips(self):
        # Function to retrieve IPv6 IPs of a given network interface
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

    def get_interface_link_local_list(self):
        # Function to retrieve link-local address's list of a given network interface (if there are more than one LL address)
        ips = self.get_interface_ips()
        list_ll = []
        for ipv6 in ips:
            if ipv6.startswith("fe80"):
                list_ll.append(ipv6)
        return list_ll
    
    def check_interface(self):
        # Checking the existence of the inserted interface
        if not self.interface or self.interface is None:
            return False
        interface_list = netifaces.interfaces()

        if self.interface in interface_list:
            return True
        else:
            return False
   
    def check_available_ipv6(self):
        # Run the 'ip' command to get the IPv6 addresses on the specified interface
        try:
            ip_output = subprocess.check_output(["ip", "-6", "addr", "show", self.interface], universal_newlines=True)
        except subprocess.CalledProcessError as e:
            print(f"Error: {e}")
            exit(1)

        # Parse the output to check for IPv6 addresses
        addresses = ip_output.split("\n")
        ipv6_addresses = [line.split()[1] for line in addresses if "inet6" in line]

        # Check if there are no IPv6 addresses
        if not ipv6_addresses:
            return False
        else:
            return True
    
    def generate_ipv6_address(prefix):
        # Generate the first 64 bits
        first_half = random.randint(0, 2**64-1)
        
        # Concatenate with the Global Unicast Address prefix
        ipv6_prefix = prefix  # Example prefix, you can replace it with any valid prefix
        full_address = ipaddress.IPv6Address(ipv6_prefix) + first_half
        
        return str(full_address)

    def set_ipv6_address(self, ipv6_address):
        try:
            # Execute the ip command to set the IPv6 address
            subprocess.run(["ip", "addr", "add", f"{ipv6_address}/64", "dev", self.interface], check=True)
        except subprocess.CalledProcessError as e:
            pass
    
    








