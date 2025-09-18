import datetime
import ipaddress
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

# --- Conversion Functions ---

def convert_mldv2_igmpv3_rtype(rtype: int) -> str:
    """
    Convert MLDv2/IGMPv3 report type integer to string description.

    Args:
        rtype (int): Report type integer.

    Returns:
        str: Description of report type.
    """
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

def convert_OnOff(flag: int) -> str:
    """
    Convert integer flag to 'Yes', 'No', or 'Unknown'.

    Args:
        flag (int): Flag value (0 or 1).

    Returns:
        str: 'Yes', 'No', or 'Unknown'.
    """
    if flag == 1:
        return "Yes"
    if flag == 0:
        return "No"
    else:
        return "Unknown"

def convert_preferenceRA(prf: int) -> str:
    """
    Convert RA preference integer to string.

    Args:
        prf (int): Preference value.

    Returns:
        str: Preference description.
    """
    if prf == 1:
        return "High"
    elif prf == 0:
        return "Medium"
    elif prf == 3:
        return "Low"
    else:
        return "Reserved"

def convert_preferenceRA_to_numeric(input_flag: str) -> int:
    """
    Convert RA preference string to numeric value.

    Args:
        input_flag (str): Preference string.

    Returns:
        int: Numeric value of preference.

    Raises:
        ValueError: If input is invalid.
    """
    if input_flag == "High":
        return 1
    elif input_flag == "Medium":
        return 0
    elif input_flag == "Low":
        return 3
    elif input_flag == "Reserved":
        return 2
    else:
        raise ValueError("Invalid input. Please enter High, Medium, Low, or Reserved.")

def convert_addr_to_llsnm_ipv6(a: str) -> str:
    """
    Return link-local solicited-node multicast address for given IPv6 address.

    Args:
        a (str): IPv6 address.

    Returns:
        str: Solicited-node multicast address.
    """
    a_bytes = inet_pton(socket.AF_INET6, a)
    r = in6_and(a_bytes, inet_pton(socket.AF_INET6, '::ff:ffff'))
    r = in6_or(inet_pton(socket.AF_INET6, 'ff02::1:ff00:0'), r)
    return inet_ntop(socket.AF_INET6, r)

def convert_llsnm_to_vaddr_ipv6(a: str) -> str:
    """
    Return virtual address resolved from link-local solicited-node multicast address.

    Args:
        a (str): IPv6 address.

    Returns:
        str: Virtual address.
    """
    a = str(ipaddress.ip_address(a).exploded)
    addr = "XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XX" + a[-7:]
    return addr

def convert_timestamp_to_date(timestamp: float) -> str:
    """
    Convert timestamp to date string.

    Args:
        timestamp (float): Timestamp.

    Returns:
        str: Date string.
    """
    date = datetime.datetime.fromtimestamp(timestamp)
    return str(date)

# --- Address Manipulation Functions ---

def extract_interface_id(link_local_address: str) -> str:
    """
    Extract interface ID (lower 64 bits) from IPv6 link-local address.

    Args:
        link_local_address (str): IPv6 link-local address.

    Returns:
        str: Interface ID or error message.
    """
    try:
        link_local_address = ipaddress.IPv6Address(link_local_address)
        interface_id = link_local_address.exploded.split(":", 4)[-1]
        return interface_id
    except ipaddress.AddressValueError as e:
        return str(e)

def count_octets(ipv6_part: str) -> int:
    """
    Count non-empty octets in IPv6 address part.

    Args:
        ipv6_part (str): IPv6 address part.

    Returns:
        int: Number of octets.
    """
    octets = ipv6_part.split(':')
    return sum(1 for octet in octets if octet != '')

def generate_global_ipv6(prefix: str, link_local_address: str) -> str | None:
    """
    Generate global IPv6 address from prefix and link-local address.

    Args:
        prefix (str): IPv6 prefix.
        link_local_address (str): Link-local address.

    Returns:
        str | None: Global IPv6 address or None.
    """
    try:
        interface_id = extract_interface_id(link_local_address)
        if check_prefix(prefix):
            if is_valid_ipv6_prefix(prefix):
                network = str(IPNetwork(prefix).network)
            if count_octets(network) >= 4:
                global_ipv6 = ipaddress.IPv6Address(network[:-1] + interface_id)
            else:
                global_ipv6 = ipaddress.IPv6Address(network + interface_id)
            return str(global_ipv6)
        else:
            return None
    except Exception:
        return None

def get_ips_from_other_macs(target_mac: str, mac_ip_dict: dict) -> list:
    """
    Get IPs from all MACs except the target MAC.

    Args:
        target_mac (str): Target MAC address.
        mac_ip_dict (dict): Dictionary of MAC to IPs.

    Returns:
        list: List of IPs from other MACs.
    """
    other_ips = []
    for mac, ips in mac_ip_dict.items():
        if mac != target_mac:
            other_ips.extend(ips)
    return other_ips

def nb(i: int, length: int = False) -> bytes:
    """
    Convert integer to bytes.

    Args:
        i (int): Integer value.
        length (int, optional): Number of bytes.

    Returns:
        bytes: Bytes representation.
    """
    b = b''
    if length == False:
        length = (i.bit_length() + 7) // 8
    for _ in range(length):
        b = bytes([i & 0xff]) + b
        i >>= 8
    return b

def bn(b: bytes) -> int:
    """
    Convert bytes to integer.

    Args:
        b (bytes): Bytes object.

    Returns:
        int: Integer value.
    """
    i = 0
    for byte in b:
        i <<= 8
        i |= byte
    return i

def create_ipv6_prefix(address: str, prefix_length: int) -> str:
    """
    Create IPv6 prefix from address and prefix length.

    Args:
        address (str): IPv6 address.
        prefix_length (int): Prefix length.

    Returns:
        str: IPv6 prefix.
    """
    bytes_address = socket.inet_pton(socket.AF_INET6, address)
    mask = shift_bytes(bytes_address, prefix_length)
    prefix = bytes_to_hex_string(mask)
    return prefix

def shift_bytes(data: bytes, shift: int) -> bytes:
    """
    Shift bytes for prefix masking.

    Args:
        data (bytes): Data bytes.
        shift (int): Shift amount.

    Returns:
        bytes: Shifted bytes.
    """
    value = bn(data)
    shifted_value = value >> (128 - shift)
    shifted_value = shifted_value << (128 - shift)
    result = nb(shifted_value)
    return result

def shift_bytes_sufix(data: bytes, shift: int) -> bytes:
    """
    Shift bytes for suffix.

    Args:
        data (bytes): Data bytes.
        shift (int): Shift amount.

    Returns:
        bytes: Shifted bytes.
    """
    value = bn(data)
    shifted_value = value >> shift
    result = nb(shifted_value)
    return result

def bytes_to_hex_string(data: bytes) -> str:
    """
    Convert bytes to hex string with colons.

    Args:
        data (bytes): Data bytes.

    Returns:
        str: Hex string.
    """
    hex_list = [hex(byte)[2:].zfill(2) for byte in data]
    hex_str = ''.join(hex_list)
    n = 4
    hex_string = [hex_str[i:i + n] for i in range(0, len(hex_str), n)]
    return ':'.join(hex_string)

def bytes_to_bitstring(data: bytes) -> str:
    """
    Convert bytes to bitstring.

    Args:
        data (bytes): Data bytes.

    Returns:
        str: Bitstring.
    """
    hex_string = binascii.hexlify(data).decode('utf-8')
    binary_string = bin(int(hex_string, 16))[2:].zfill(len(data) * 8)
    return binary_string

def locate_addres(new_address: str) -> bool:
    """
    Check if address exists in CSV file.

    Args:
        new_address (str): IPv6 address.

    Returns:
        bool: True if not found, False if found.
    """
    with open('src/tmp/ipv6.csv', 'r') as file:
        reader = csv.reader(file)
        for row in reader:
            if new_address in row:
                return False
    return True

# --- Address Generation Functions ---

def generate_address(prefix: str, prefix_length: int) -> ipaddress.IPv6Address:
    """
    Generate IPv6 address based on prefix and prefix length.

    Args:
        prefix (str): IPv6 prefix.
        prefix_length (int): Prefix length.

    Returns:
        ipaddress.IPv6Address: Generated IPv6 address.
    """
    suffix = shift_bytes_sufix(bytes.fromhex(format(random.getrandbits(128), '032x')), prefix_length)
    new_address_int = nb(bn(ipaddress.IPv6Address(prefix).packed) | bn(suffix))
    new_address_str = bytes_to_hex_string(new_address_int)
    new_address = ipaddress.IPv6Address(new_address_str)
    return new_address

def generate_random_global_ipv6(exclude_addresses: list[str]) -> str:
    """
    Generate random global unicast IPv6 address not in exclude list.

    Args:
        exclude_addresses (list[str]): List of addresses to exclude.

    Returns:
        str: Random global IPv6 address.
    """
    exclude_addresses = [ipaddress.IPv6Address(addr) for addr in exclude_addresses]
    while True:
        first_part = random.randint(0x2000, 0x3FFF)
        remaining_parts = [f"{random.randint(0, 0xFFFF):04x}" for _ in range(7)]
        rand_ipv6 = ipaddress.IPv6Address(f"{first_part:04x}:" + ":".join(remaining_parts))
        if rand_ipv6.is_global and rand_ipv6 not in exclude_addresses:
            return str(rand_ipv6)

def create_IPv6_add(input_filename: str) -> tuple[ipaddress.IPv6Address, int]:
    """
    Create IPv6 address based on input CSV file.

    Args:
        input_filename (str): Input CSV filename.

    Returns:
        tuple[ipaddress.IPv6Address, int]: New address and prefix length.
    """
    with open(input_filename, 'r') as input_file:
        reader = csv.DictReader(input_file)
        first_ip_str = next(reader)['IP']
        first_ip = ipaddress.IPv6Address(first_ip_str)
        first_ip_bits = bin(int(first_ip))[2:].zfill(128)
        mask_bits = first_ip_bits
        prefix_length = first_ip.max_prefixlen
        for row in reader:
            ip_str = row['IP']
            ip = ipaddress.IPv6Address(ip_str)
            ip_bits = bin(int(ip))[2:].zfill(128)
            mask_bits = ''.join(['1' if b1 == b2 else '0' for b1, b2 in zip(first_ip_bits, ip_bits)])
            common_bits_length = mask_bits.find('0')
            prefix_length = min(prefix_length, common_bits_length)
        prefix = create_ipv6_prefix(first_ip_str, prefix_length)
    new_address = generate_address(prefix, prefix_length)
    address_existence = locate_addres(str(new_address))
    while address_existence == False:
        new_address = generate_address(prefix, prefix_length)
        address_existence = locate_addres(str(new_address))
    return new_address, prefix_length

# --- Multicast Address Functions ---

def in6_getnsma(a: str) -> str:
    """
    Return link-local solicited-node multicast address for given IPv6 address.

    Args:
        a (str): IPv6 address.

    Returns:
        str: Solicited-node multicast address.
    """
    a_bytes = inet_pton(socket.AF_INET6, a)
    r = in6_and(a_bytes, inet_pton(socket.AF_INET6, '::ff:ffff'))
    r = in6_or(inet_pton(socket.AF_INET6, 'ff02::1:ff00:0'), r)
    return inet_ntop(socket.AF_INET6, r)

def in6_getansma(a: str) -> str:
    """
    Return virtual address resolved from link-local solicited-node multicast address.

    Args:
        a (str): IPv6 address.

    Returns:
        str: Virtual address.
    """
    a = str(ipaddress.ip_address(a).exploded)
    addr = "XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XX" + a[-7:]
    return addr

# --- Utility Functions ---

def collect_unique_items(dictionary: dict) -> list:
    """
    Retrieve unique items from dictionary values.

    Args:
        dictionary (dict): Dictionary with lists as values.

    Returns:
        list: List of unique items.
    """
    unique_items = set()
    for key, value_list in dictionary.items():
        for item in value_list:
            unique_items.add(item)
    return list(unique_items)