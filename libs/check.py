import csv
import ipaddress
import re
import socket
import subprocess

import netifaces
from netaddr import IPNetwork
import pandas as pd
from scapy.pton_ntop import inet_pton, inet_ntop
from scapy.utils6 import in6_and, in6_or


def is_non_negative_float(value):
    try:
        float_value = float(value)
        return float_value >= 0
    except ValueError:
        return False

def is_valid_integer(value):
    try:
        # Try to convert the input to an integer
        value = int(value)

        # Check if it's a non-negative integer and smaller than 255
        if 0 <= value <= 255:
            return True
        else:
            return False
    except ValueError:
        # If the conversion to an integer fails, it's not a valid parameter
        return False
    
def is_valid_MTU(value):
    try:
        # Try to convert the input to an integer
        value = int(value)

        # Check if it's a non-negative integer and smaller than 255
        if 0 <= value <= 65535:
            return True
        else:
            return False
    except ValueError:
        # If the conversion to an integer fails, it's not a valid parameter
        return False
    
def is_valid_ipv6(ip):
    """Validates IPv6 addresses.
    """
    if ip is None or type(ip) is float or type(ip) is int:
        return False
    else:
        pattern = re.compile(r"""
            ^
            \s*                         # Leading whitespace
            (?!.*::.*::)                # Only a single whildcard allowed
            (?:(?!:)|:(?=:))            # Colon if it would be part of a wildcard
            (?:                         # Repeat 6 times:
                [0-9a-f]{0,4}           #   A group of at most four hexadecimal digits
                (?:(?<=::)|(?<!::):)    #   Colon unless preceeded by wildcard
            ){6}                        #
            (?:                         # Either
                [0-9a-f]{0,4}           #   Another group
                (?:(?<=::)|(?<!::):)    #   Colon unless preceeded by wildcard
                [0-9a-f]{0,4}           #   Last group
                (?: (?<=::)             #   Colon if preceeded by exacly one colon
                 |  (?<!:)              #
                 |  (?<=:) (?<!::) :    #
                 )                      # OR
             |                          #   A v4 address with NO leading zeros
                (?:25[0-4]|2[0-4]\d|1\d\d|[1-9]?\d)
                (?: \.
                    (?:25[0-4]|2[0-4]\d|1\d\d|[1-9]?\d)
                ){3}
            )
            \s*                         # Trailing whitespace
            $
        """, re.VERBOSE | re.IGNORECASE | re.DOTALL)
        return pattern.match(ip) is not None

def check_prefix(prefix):
    if not is_valid_ipv6(prefix) and not is_valid_ipv6(str(IPNetwork(prefix).network)):
        return False
    else:
        return True

def is_valid_mac(str):
    # Regex to check valid
    # MAC address
    regex = ("^([0-9A-Fa-f]{2}[:-])" +
             "{5}([0-9A-Fa-f]{2})|" +
             "([0-9a-fA-F]{4}\\." +
             "[0-9a-fA-F]{4}\\." +
             "[0-9a-fA-F]{4})$")
    # Compile the ReGex
    p = re.compile(regex)
    # If the string is empty
    # return false
    if (str == None):
        return False
    # Return if the string
    # matched the ReGex
    if (re.search(p, str)):
        return True
    else:
        return False

def is_global_unicast_ipv6(ipv6_address):
    try:
        # Split the address by colons to separate the components, but need to expand for checking
        addr = ipaddress.ip_address(ipv6_address)
        ipv6_address = addr.exploded

        components = ipv6_address.split(':')

        # Check if it has the required number of components for a valid IPv6 address
        if len(components) != 8:
            return False

        # Check for global unicast prefix and discard addresses starting with reserved prefixes
        global_unicast_prefixes = ['2001', '2002', '2003', '2004', '2005', '2006', '2007', '2008', '2009']
        return components[0][:4] in global_unicast_prefixes

    except IndexError:
        return False

def is_link_local_ipv6(address):
    try:
        ip = ipaddress.ip_address(address)
        return ip.version == 6 and ip.is_link_local
    except ValueError:
        return False
    
def is_ipv6_ula(address):
    try:
        ip = ipaddress.ip_address(address)
        return ip.version == 6 and ip.is_private and not ip.is_link_local and not ip.is_global
    except ValueError:
        return False

def is_llsnm_ipv6(str):
    # type: (str) -> bool
    """
    Return True if provided address is a link-local solicited node
    multicast address, i.e. belongs to ff02::1:ff00:0/104. False is
    returned otherwise.
    """
    temp = in6_and(b"\xff" * 13 + b"\x00" * 3, inet_pton(socket.AF_INET6, str))
    temp2 = b'\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xff\x00\x00\x00'
    return temp == temp2

def is_valid_ipv6_prefix(prefix):
    try:
        # Attempt to create an IPv6 network object from the input
        ipv6_network = ipaddress.IPv6Network(prefix, strict=False)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False

def check_prefRA(pref_flag):
    valid_inputs = ["High", "Low", "Reserved", "Medium"]
    
    if pref_flag in valid_inputs:
        return True
    else:
        return False

def has_additional_data(file_path):
    if file_path is None:
        return False
    
    # This function checks if a file has additional data rows other than the header
    with open(file_path, 'r') as csv_file:
        reader = csv.reader(csv_file)

        # Skip the first line (header)
        next(reader)

        # Check if there are any additional lines
        for row in reader:
            if row:  # If a row is not empty, return True
                return True

        return False  # Return False if all rows were empty

def check_ipv6_addresses_generated_from_prefix(file_path, ipv6_network_str, prefix_length):
    """
    Checks if any IPv6 global unicast address in the specified CSV file
    is generated from the specified prefix length and network.

    Args:
        file_path (str): The path to the CSV file.
        ipv6_network_str (str): The base IPv6 network address as a string.
        prefix_length (int): The prefix length of the IPv6 network.

    Returns:
        list: A list of IPv6 addresses that match the specified network prefix.
    """
    matching_addresses = []

    try:
        # Read the CSV file
        df = pd.read_csv(file_path)

        # Create an IPv6 network object
        ipv6_network = ipaddress.IPv6Network(f"{ipv6_network_str}/{prefix_length}", strict=False)

        # Iterate through the IP addresses in the DataFrame
        for index, row in df.iterrows():
            try:
                ipv6_address = ipaddress.IPv6Address(row['IP'])
                if ipv6_address in ipv6_network:
                    # print(f"Address {row['IP']} is in the specified network {ipv6_network_str}/{prefix_length}.")
                    matching_addresses.append(row['IP'])
            except ipaddress.AddressValueError:
                pass
    
    except FileNotFoundError:
        # print(f"ERROR: The file {file_path} was not found.")
        pass
    except pd.errors.EmptyDataError:
        # print(f"ERROR: The file {file_path} is empty.")
        pass
    except Exception as e:
        pass
        # print(f"ERROR: An error occurred while processing the file {file_path}. Error details: {e}")

    return matching_addresses


def belongs_to_any_prefix(ipv6_address, prefixes):
    # Function to check if an IPv6 address belongs to any of the specified prefixes
    try:
        ip = ipaddress.ip_address(ipv6_address)
        for prefix in prefixes:
            network = ipaddress.ip_network(prefix, strict=False)
            if ip in network:
                return True
        return False
    except ValueError:
        return False

# Check response of DHCP
def find_requested_addr(data):
    # Function to find if 'requested_addr' exists and get its value
    for item in data:
        if isinstance(item, tuple) and item[0] == 'requested_addr':
            return item[1]
    return None

# Check the status of IP (if it has)
def get_status_ip(mac, ip):

    role_file_path = 'src/tmp/role_node.csv'
    if has_additional_data(role_file_path):
        with open(role_file_path, 'r') as csv_file:
            reader = csv.DictReader(csv_file)
            for row in reader:
                if row['MAC'] == mac and row['Role'] != 'Host':
                    return None

    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return None
    
    if ip_obj.version == 4:
        file_path = "src/tmp/dhcp.csv"
        if has_additional_data(file_path):
            with open(file_path, 'r') as csv_file:
                reader = csv.DictReader(csv_file)
                for row in reader:
                    if row['MAC'] == mac and row['IP'] == ip:
                        return "probably DHCP assigned"
        return None
    
    
    elif ip_obj.version == 6 and is_global_unicast_ipv6(ip):
        dhcp_file_path = 'src/tmp/dhcp.csv'
        if has_additional_data(dhcp_file_path):
            with open(dhcp_file_path, 'r') as csv_file:
                reader = csv.DictReader(csv_file)
                for row in reader:
                    if row['MAC'] == mac and row['IP'] == ip:
                        return "probably DHCPv6 assigned"
        
        ra_file_path = 'src/tmp/RA.csv'
        if has_additional_data(ra_file_path):
            with open(ra_file_path, 'r') as csv_file:
                reader = csv.DictReader(csv_file)
                for row in reader:
                    if row['M'] == "Yes" and row['A'] == "No":
                        prefix = row['Prefix']
                        if is_valid_ipv6_prefix(prefix):
                            network, prefix_length = prefix.split('/')
                            network_obj = ipaddress.ip_network(f"{network}/{prefix_length}", strict=False)
                            if ipaddress.ip_address(ip) in network_obj:
                                return "probably DHCPv6 assigned"
                    if row['A'] == 'Yes' or (row['M'] == "Yes" and row['A'] == "No"):
                        prefix = row['Prefix']
                        if is_valid_ipv6_prefix(prefix):
                            network, prefix_length = prefix.split('/')
                            network_obj = ipaddress.ip_network(f"{network}/{prefix_length}", strict=False)
                            if ipaddress.ip_address(ip) in network_obj:
                                return "probably SLAAC generated"
        return None

def is_dhcp_slaac()-> list:
    '''Check if DHCP, DHCPv6 server and SLAAC are available. Return the list of results'''
    dhcp_file_path = "src/tmp/dhcp.csv"
    ra_file_path = "src/tmp/RA.csv"
    lst_result = []

    if has_additional_data(dhcp_file_path):
        with open(dhcp_file_path, 'r') as csv_file:
            reader = csv.DictReader(csv_file)
            for row in reader:
                try:
                    ip_obj = ipaddress.ip_address(row['IP'])
                    if ip_obj.version == 4:
                        status = "DHCP server"
                        if status not in lst_result:
                            lst_result.append(status)
                    if ip_obj.version == 6:
                        if is_global_unicast_ipv6(row['IP']):
                            status = "DHCPv6 server"
                            if status not in lst_result:
                                lst_result.append(status) 
                except:
                    continue

    if has_additional_data(ra_file_path):
        with open(ra_file_path, 'r') as csv_file:
            reader = csv.DictReader(csv_file)
            for row in reader:
                if row['M'] == "Yes" and row['A'] == "No":
                    prefix = row['Prefix']
                    if is_valid_ipv6_prefix(prefix):
                        status = "DHCPv6 server"
                        if status not in lst_result:
                            lst_result.append(status)
                if row['A'] == 'Yes':
                    prefix = row['Prefix']
                    if is_valid_ipv6_prefix(prefix):
                        status = "SLAAC"
                        if status not in lst_result:
                            lst_result.append(status)
    return lst_result