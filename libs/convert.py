import datetime
import ipaddress
import re
import socket
import subprocess
import csv

import binascii
import random
import netifaces
from netaddr import IPNetwork
from scapy.pton_ntop import inet_pton, inet_ntop
from scapy.utils6 import in6_and, in6_or
from libs.check import check_prefix, is_valid_ipv6_prefix

def convert_mldv2_igmpv3_rtype(rtype):
    if rtype == 1:
        return "MODE_IS_INCLUDE"
    elif rtype == 2:
        return "MODE_IS_EXCLUDE"
    elif rtype == 3:
        return "CHANGE_TO_INCLUDE_MODE"
    elif rtype == 4:
        return "CHANGE_TO_EXCLUDE_MODE"
    elif rtype == 5:
        return "ALLOW_NEW_SOURCES"
    elif rtype == 6:
        return "BLOCK_OLD_SOURCES"
    else:
        return "UNKNOWN"

def convert_OnOff(flag):
    if flag == 1:
        return "Yes"
    if flag == 0:
        return "No"
    else:
        return "Unknown"

def convert_preferenceRA(prf):
    if prf == 1:
        return "High"
    elif prf == 0:
        return "Medium"
    elif prf == 3:
        return "Low"
    else:
        return "Reserved"

def convert_preferenceRA_to_numeric(input_flag):
    if input_flag == "High":
        return 1
    elif input_flag == "Medium":
        return 0
    elif input_flag == "Low":
        return 3
    elif input_flag == "Reserved":
        return 2
    else:
        # Handle invalid input
        raise ValueError("Invalid input. Please enter High, Medium, Low, or Reserved.")

def convert_addr_to_llsnm_ipv6(a):
    # type: (str) -> str
    """
    Return link-local solicited-node multicast address for given
    address.
    """
    a = inet_pton(socket.AF_INET6, a)  # Convert string to bytes

    r = in6_and(a, inet_pton(socket.AF_INET6, '::ff:ffff'))
    r = in6_or(inet_pton(socket.AF_INET6, 'ff02::1:ff00:0'), r)

    r = inet_ntop(socket.AF_INET6, r)  # Convert bytes to string
    return r

def convert_llsnm_to_vaddr_ipv6(a):
    # type: (str) -> str
    """
    Return virtual address resolved from link-local solicited-node multicast address. If a has the same ending as b (
    main address), address b is returned.
    """
    a = str(ipaddress.ip_address(a).exploded)
    addr = "XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XX" + a[-7:]

    return addr

def extract_interface_id(link_local_address):
    try:
        # Parse the link-local address as an IPv6 address
        link_local_address = ipaddress.IPv6Address(link_local_address)

        # Extract the interface ID (lower 64 bits)
        interface_id = link_local_address.exploded.split(":", 4)[-1]

        return interface_id
    except ipaddress.AddressValueError as e:
        return str(e)

def count_octets(ipv6_part):
    octets = ipv6_part.split(':')
    octet_count = 0

    for octet in octets:
        if octet != '':
            octet_count += 1

    return octet_count

def generate_global_ipv6(prefix, link_local_address):
    # Generate the global address based on prefix and interface ID of link local address
    try:
        # Getting the interface ID
        interface_id = extract_interface_id(link_local_address)
        if check_prefix(prefix): # When prefix is available in RA
            # Getting the network part from prefix
            if is_valid_ipv6_prefix(prefix):
                network = str(IPNetwork(prefix).network)
            
            # Combine two parts to make global address
            if count_octets(network) >= 4:
                global_ipv6 = ipaddress.IPv6Address(network[:-1] + interface_id)
            else:
                global_ipv6 = ipaddress.IPv6Address(network + interface_id)
            return str(global_ipv6)
        else:
            return
    except Exception:
        return

def get_ips_from_other_macs(target_mac, mac_ip_dict):
    other_ips = []
    for mac, ips in mac_ip_dict.items():
        if mac != target_mac:
            other_ips.extend(ips)
    return other_ips

def nb(i, length=False):
    # converts integer to bytes
    # function takes an integer i and an optional length parameter
    # and returns a bytes object that represents the integer.
    # length specifies the number of bytes in the returned bytes object.
    b = b''
    if length == False:
        length = (i.bit_length() + 7) // 8
    for _ in range(length):
        b = bytes([i & 0xff]) + b
        i >>= 8
    return b


def bn(b):
    # converts bytes to integer
    # function takes a bytes object b and returns the integer
    # that the bytes object represents.
    i = 0
    for byte in b:
        i <<= 8
        i |= byte
    return i


def create_ipv6_prefix(address, prefix_length):
    # Function to create an IPv6 prefix given an address and prefix length
    # Convert the IPv6 address to a bytes object
    bytes_address = socket.inet_pton(socket.AF_INET6, address)
    mask = shift_bytes(bytes_address, prefix_length)
    # Convert the masked address back to a hex string
    prefix = bytes_to_hex_string(mask)
    return prefix


def shift_bytes(data, shift):
    # Function to shift bytes
    # Convert the bytes to an integer
    value = bn(data)
    # Perform the right shift operation
    shifted_value = value >> (128 - shift)
    # Perform the left shift operation to get back specific length
    shifted_value = shifted_value << (128 - shift)
    # Convert the result back to bytes
    result = nb(shifted_value)
    return result


def shift_bytes_sufix(data, shift):
    # Function to shift bytes for suffix
    # Convert the bytes to an integer
    value = bn(data)
    # Perform the right shift operation
    shifted_value = value >> (shift)
    # Convert the result back to bytes
    result = nb(shifted_value)
    return result


def bytes_to_hex_string(data):
    # Function to convert bytes to hex string
    # Convert each byte to a two-digit hexadecimal string
    hex_list = [hex(byte)[2:].zfill(2) for byte in data]
    hex_str = ''.join(hex_list)
    n = 4
    hex_string = [hex_str[i:i + n] for i in range(0, len(hex_str), n)]
    return ':'.join(hex_string)


def bytes_to_bitstring(data):
    # Function to convert bytes to bitstring
    # Convert the bytes to a hexadecimal string
    hex_string = binascii.hexlify(data).decode('utf-8')
    # Convert the hexadecimal string to a binary string
    binary_string = bin(int(hex_string, 16))[2:].zfill(len(data) * 8)
    return binary_string


def locate_addres(new_address):
    # Function to check if address already exists in the csv file
    with open('src/tmp/ipv6.csv', 'r') as file:
        reader = csv.reader(file)

        # Iterate over each row in the CSV file
        for row in reader:
            # Check if the IPv6 address is in the row
            if new_address in row:
                return False
    return True


def generate_address(prefix, prefix_length):
    # Function to generate an IPv6 address based on the given prefix and prefix length
    # Create suffix in specific length given by prefix length
    suffix = shift_bytes_sufix(bytes.fromhex(format(random.getrandbits(128), '032x')), prefix_length)
    # make or operation with prefix and suffix and create address int
    new_address_int = nb(bn(ipaddress.IPv6Address(prefix).packed) | bn(suffix))
    # convert int to hex string
    new_address_str = bytes_to_hex_string(new_address_int)
    # create ipv6 object from new_address_string
    new_address = ipaddress.IPv6Address(new_address_str)
    return new_address


def generate_random_global_ipv6(exclude_addresses):
    """
    Generate a random IPv6 global unicast address within the range 2000::/3 and must 
    be different from the list of excluded addresses.

    The first 16 bits of the address are set to a value between 2000 and 3FFF,
    ensuring that the address falls within the global unicast range. The remaining
    112 bits are generated randomly.

    Returns:
        str: A randomly generated IPv6 global unicast address.
    """
    # Convert the list of IPv6 addresses to IPv6Address objects
    exclude_addresses = [ipaddress.IPv6Address(addr) for addr in exclude_addresses]

    while True:
        # The first 16 bits should be in the range 2000 to 3FFF
        first_part = random.randint(0x2000, 0x3FFF)
        # Generate the remaining 7 groups of 4 hexadecimal digits
        remaining_parts = [f"{random.randint(0, 0xFFFF):04x}" for _ in range(7)]
        # Combine the first part with the remaining parts
        rand_ipv6 = ipaddress.IPv6Address(f"{first_part:04x}:" + ":".join(remaining_parts))

        # Ensure it is a global unicast address and not in the exclude addresses
        if rand_ipv6.is_global and rand_ipv6 not in exclude_addresses:
            return str(rand_ipv6)
    
def create_IPv6_add(input_filename):
    # Function to create an IPv6 address based on an input CSV file
    # Open the input CSV file
    with open(input_filename, 'r') as input_file:
        # Create a CSV reader for the input file
        reader = csv.DictReader(input_file)

        # Initialize the first IP address
        first_ip_str = next(reader)['IP']
        first_ip = ipaddress.IPv6Address(first_ip_str)
        # Convert the first IP address to a bit string
        first_ip_bits = bin(int(first_ip))[2:].zfill(128)
        # Initialize the mask and prefix length
        mask_bits = first_ip_bits
        prefix_length = first_ip.max_prefixlen

        # Loop over the remaining IP addresses
        for row in reader:
            ip_str = row['IP']
            ip = ipaddress.IPv6Address(ip_str)

            # Convert the current IP address to a bit string
            ip_bits = bin(int(ip))[2:].zfill(128)

            # Update the mask to include the common bits between the current IP and the mask
            mask_bits = ''.join(['1' if b1 == b2 else '0' for b1, b2 in zip(first_ip_bits, ip_bits)])
            # Update the prefix length to the length of the common bits between the current IP and the mask
            common_bits_length = mask_bits.find('0')
            prefix_length = min(prefix_length, common_bits_length)

        # Create the prefix from the mask and prefix length
        prefix = create_ipv6_prefix(first_ip_str, prefix_length)

    new_address = generate_address(prefix, prefix_length)
    address_existence = locate_addres(new_address)

    while address_existence == False:
        new_address = generate_address(prefix, prefix_length)
        address_existence = locate_addres(new_address)

    return new_address, prefix_length

def in6_getnsma(a):
    # type: (str) -> str
    """
    Return link-local solicited-node multicast address for given
    address.
    """
    a = inet_pton(socket.AF_INET6, a)  # Convert string to bytes

    r = in6_and(a, inet_pton(socket.AF_INET6, '::ff:ffff'))
    r = in6_or(inet_pton(socket.AF_INET6, 'ff02::1:ff00:0'), r)

    r = inet_ntop(socket.AF_INET6, r)  # Convert bytes to string
    return r

def in6_getansma(a):
    # type: (str) -> str
    """
    Return virtual address resolved from link-local solicited-node multicast address. If a has the same ending as b (
    main address), address b is returned.
    """
    a = str(ipaddress.ip_address(a).exploded)
    addr = "XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XX" + a[-7:]

    return addr

def convert_timestamp_to_date(timestamp):
    # type: (float) -> str
    """
    Convert timestamp in float to date object in string
    """

    date = datetime.datetime.fromtimestamp(timestamp)
    return str(date)

def collect_unique_items(dictionary):
    """
    Retrieve items from dictionary and store as a list (no duplicates)
    """
    unique_items = set()

    for key, value_list in dictionary.items():
        # Assuming each value is a list
        for item in value_list:
            unique_items.add(item)

    # Convert the set to a list
    unique_list = list(unique_items)
    return unique_list