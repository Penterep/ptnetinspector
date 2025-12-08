import datetime
import ipaddress
import socket
import subprocess
import csv
import binascii
import random
import re
import netifaces

from netaddr import IPNetwork
from scapy.pton_ntop import inet_pton, inet_ntop
from scapy.utils6 import in6_and, in6_or

from ptnetinspector.utils.csv_helpers import has_additional_data
from ptnetinspector.utils.path import get_csv_path


# ============================================================================
# VALIDATION FUNCTIONS
# ============================================================================

def is_non_negative_float(value: str) -> bool:
    """Check if the value is a non-negative float."""
    try:
        return float(value) >= 0
    except ValueError:
        return False

def is_valid_integer(value: str) -> bool:
    """Check if the value is a non-negative integer <= 255."""
    try:
        value = int(value)
        return 0 <= value <= 255
    except ValueError:
        return False

def is_valid_MTU(value: str) -> bool:
    """Check if the value is a non-negative integer <= 65535."""
    try:
        value = int(value)
        return 0 <= value <= 65535
    except ValueError:
        return False

def is_valid_ipv4(ip: str) -> bool:
    """Validate IPv4 address."""
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ipaddress.AddressValueError:
        return False

def is_multicast_ipv4(addr: str) -> bool:
    """Validate multicast IPv4 address."""
    try:
        return ipaddress.IPv4Address(addr).is_multicast
    except:
        return False

def is_broadcast_ipv4(addr: str) -> bool:
    """Validate broadcast IPv4 address."""
    return addr in ['255.255.255.255'] or addr.endswith('.255')
        
def is_valid_ipv6(ip: str) -> bool:
    """Validate IPv6 address using regex."""
    if ip is None or isinstance(ip, (float, int)):
        return False
    pattern = re.compile(r"""
        ^
        \s*
        (?!.*::.*::)
        (?:(?!:)|:(?=:))
        (?:[0-9a-f]{0,4}(?:(?<=::)|(?<!::):)){6}
        (?:
            [0-9a-f]{0,4}(?:(?<=::)|(?<!::):)[0-9a-f]{0,4}
            (?: (?<=::)|(?<!:)|(?<=:)(?<!::): )
         |
            (?:25[0-4]|2[0-4]\d|1\d\d|[1-9]?\d)
            (?:\.(?:25[0-4]|2[0-4]\d|1\d\d|[1-9]?\d)){3}
        )
        \s*
        $
    """, re.VERBOSE | re.IGNORECASE | re.DOTALL)
    return pattern.match(ip) is not None

def is_valid_ipv6_prefix(prefix: str) -> bool:
    """Validate IPv6 prefix."""
    try:
        ipaddress.IPv6Network(prefix, strict=False)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False

def is_valid_mac(mac: str) -> bool:
    """Validate MAC address (exactly 6 octets in colon or dash format, or Cisco format)."""
    if mac is None or not isinstance(mac, str):
        return False
    # Standard format: XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX (exactly 6 pairs)
    # Cisco format: XXXX.XXXX.XXXX (exactly 3 groups of 4 hex digits)
    regex = (
        r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$|"  # Colon or dash separated
        r"^([0-9A-Fa-f]{4}\.){2}([0-9A-Fa-f]{4})$"      # Cisco format
    )
    return re.match(regex, mac) is not None

def check_prefix(prefix: str) -> bool:
    """Check if prefix is a valid IPv6 prefix."""
    if not is_valid_ipv6(prefix) and not is_valid_ipv6(str(IPNetwork(prefix).network)):
        return False
    return True

def check_prefRA(pref_flag: str) -> bool:
    """Check if preference flag is valid for RA."""
    valid_inputs = ["High", "Low", "Reserved", "Medium"]
    return pref_flag in valid_inputs


# ============================================================================
# IPv6 ADDRESS TYPE CHECKING FUNCTIONS
# ============================================================================

def is_global_unicast_ipv6(ipv6_address: str) -> bool:
    """Check if IPv6 address is global unicast."""
    try:
        addr = ipaddress.IPv6Address(ipv6_address)
        return addr.is_global and not addr.is_multicast
    except ipaddress.AddressValueError:
        return False

def is_link_local_ipv6(address: str) -> bool:
    """Check if IPv6 address is link-local."""
    try:
        ip = ipaddress.ip_address(address)
        return ip.version == 6 and ip.is_link_local
    except ValueError:
        return False

def is_ipv6_ula(address: str) -> bool:
    """Check if IPv6 address is ULA (Unique Local Address: fc00::/7)."""
    try:
        ip = ipaddress.IPv6Address(address)
        # ULA: fc00::/7 (fc00::0 - fdff:ffff:...)
        return ip.version == 6 and (0xfc00 <= int(ip) >> 112 <= 0xfdff)
    except (ipaddress.AddressValueError, ValueError):
        return False

def is_llsnm_ipv6(ipv6: str) -> bool:
    """Check if IPv6 is link-local solicited node multicast (ff02::1:ff00:0/104)."""
    temp = in6_and(b"\xff" * 13 + b"\x00" * 3, inet_pton(socket.AF_INET6, ipv6))
    temp2 = b'\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xff\x00\x00\x00'
    return temp == temp2

def is_ipv6_predictable(ip: str, mac: str) -> bool:
    """Check if IPv6 address is predictable based on patterns and MAC address."""
    def check_eui64(ipv6: str, mac: str) -> bool:
        try:
            ipv6_full = ipaddress.ip_address(ipv6).exploded
        except ValueError:
            return False
        last_64_bits = "".join(ipv6_full.split(":")[4:])
        if last_64_bits[6:10] != 'fffe':
            return False
        eui64_mac = last_64_bits[:6] + last_64_bits[10:]
        first_byte = int(eui64_mac[:2], 16) ^ 0x02
        mac_address = "{:02x}{}".format(first_byte, eui64_mac[2:])
        mac_address = ":".join(mac_address[i:i+2] for i in range(0, 12, 2))
        return mac_address.lower() == mac.lower()

    if check_eui64(ip, mac):
        return True

    zero_sequences = ip.split(':')
    zero_count = sum(1 for part in zero_sequences if part == '' or part == '0000')
    if zero_count >= 4:
        return True

    if "::" in ip:
        double_colon_count = ip.count("::")
        if double_colon_count == 1:
            expanded_zero_count = 8 - len([part for part in zero_sequences if part])
            if expanded_zero_count >= 4:
                return True

    octet_count = {}
    for part in zero_sequences:
        if part and part != '0000':
            octet_count[part] = octet_count.get(part, 0) + 1
            if octet_count[part] >= 4:
                return True

    predictable_patterns_last_octet = [
        "::1", "::2", "::3", "::4", "::5", "::6", "::7", "::8", "::9", "::a", "::b", "::c", "::d", "::e", "::f"
    ]
    predictable_patterns_anywhere = [
        "1111", "2222", "3333", "4444", "5555", "6666", "7777", "8888", "9999",
        "aaaa", "bbbb", "cccc", "dddd", "eeee", "ffff"
    ]

    if any(ip.lower().endswith(pattern) for pattern in predictable_patterns_last_octet):
        return True

    for pattern in predictable_patterns_anywhere:
        if ip.lower().count(pattern) >= 3:
            return True

    return False


# ============================================================================
# IPv6 PREFIX & NETWORK CHECKING FUNCTIONS
# ============================================================================

def check_ipv6_addresses_generated_from_prefix(ip: str, prefix: str) -> bool:
    """Check if IPv6 address is generated from the specified prefix."""
    try:
        ipv6_network = ipaddress.IPv6Network(prefix, strict=False)
        ipv6_address = ipaddress.IPv6Address(ip)
        return ipv6_address in ipv6_network
    except ValueError:
        return False

def belongs_to_any_prefix(ipv6_address: str, prefixes: list) -> bool:
    """Check if IPv6 address belongs to any of the specified prefixes."""
    try:
        ip = ipaddress.ip_address(ipv6_address)
        for prefix in prefixes:
            network = ipaddress.ip_network(prefix, strict=False)
            if ip in network:
                return True
        return False
    except ValueError:
        return False


# ============================================================================
# CONVERSION FUNCTIONS
# ============================================================================

def convert_mldv2_igmpv3_rtype(rtype: int) -> str:
    """Convert MLDv2/IGMPv3 report type integer to string description."""
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
    """Convert integer flag to 'Yes', 'No', or 'Unknown'."""
    if flag == 1:
        return "Yes"
    if flag == 0:
        return "No"
    else:
        return "Unknown"

def convert_preferenceRA(prf: int) -> str:
    """Convert RA preference integer to string."""
    if prf == 1:
        return "High"
    elif prf == 0:
        return "Medium"
    elif prf == 3:
        return "Low"
    else:
        return "Reserved"

def convert_preferenceRA_to_numeric(input_flag: str) -> int:
    """Convert RA preference string to numeric value."""
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

def convert_timestamp_to_date(timestamp: float) -> str:
    """Convert timestamp to date string."""
    date = datetime.datetime.fromtimestamp(timestamp)
    return str(date)

def reverse_IPadd(ip_address: str) -> str:
    """Create a reverse pointer record from an IP address."""
    return ipaddress.ip_address(ip_address).reverse_pointer


# ============================================================================
# BYTE & BIT MANIPULATION FUNCTIONS
# ============================================================================

def nb(i: int, length: int = False) -> bytes:
    """Convert integer to bytes."""
    b = b''
    if length == False:
        length = (i.bit_length() + 7) // 8
    for _ in range(length):
        b = bytes([i & 0xff]) + b
        i >>= 8
    return b

def bn(b: bytes) -> int:
    """Convert bytes to integer."""
    i = 0
    for byte in b:
        i <<= 8
        i |= byte
    return i

def shift_bytes(data: bytes, shift: int) -> bytes:
    """Shift bytes for prefix masking."""
    value = bn(data)
    shifted_value = value >> (128 - shift)
    shifted_value = shifted_value << (128 - shift)
    result = nb(shifted_value)
    return result

def shift_bytes_sufix(data: bytes, shift: int) -> bytes:
    """Shift bytes for suffix."""
    value = bn(data)
    shifted_value = value >> shift
    result = nb(shifted_value)
    return result

def bytes_to_hex_string(data: bytes) -> str:
    """Convert bytes to hex string with colons."""
    hex_list = [hex(byte)[2:].zfill(2) for byte in data]
    hex_str = ''.join(hex_list)
    n = 4
    hex_string = [hex_str[i:i + n] for i in range(0, len(hex_str), n)]
    return ':'.join(hex_string)

def bytes_to_bitstring(data: bytes) -> str:
    """Convert bytes to bitstring."""
    hex_string = binascii.hexlify(data).decode('utf-8')
    binary_string = bin(int(hex_string, 16))[2:].zfill(len(data) * 8)
    return binary_string


# ============================================================================
# IPv6 PREFIX MANIPULATION FUNCTIONS
# ============================================================================

def create_ipv6_prefix(address: str, prefix_length: int) -> str:
    """Create IPv6 prefix from address and prefix length."""
    bytes_address = socket.inet_pton(socket.AF_INET6, address)
    mask = shift_bytes(bytes_address, prefix_length)
    prefix = bytes_to_hex_string(mask)
    return prefix

def extract_interface_id(link_local_address: str) -> str:
    """Extract interface ID (lower 64 bits) from IPv6 link-local address."""
    try:
        link_local_address = ipaddress.IPv6Address(link_local_address)
        interface_id = link_local_address.exploded.split(":", 4)[-1]
        return interface_id
    except ipaddress.AddressValueError as e:
        return str(e)

def count_octets(ipv6_part: str) -> int:
    """Count non-empty octets in IPv6 address part."""
    octets = ipv6_part.split(':')
    return sum(1 for octet in octets if octet != '')

def generate_global_ipv6(prefix: str, link_local_address: str) -> str | None:
    """Generate global IPv6 address from prefix and link-local address."""
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


# ============================================================================
# MULTICAST ADDRESS FUNCTIONS
# ============================================================================

def convert_addr_to_llsnm_ipv6(a: str) -> str:
    """Return link-local solicited-node multicast address for given IPv6 address."""
    a_bytes = inet_pton(socket.AF_INET6, a)
    r = in6_and(a_bytes, inet_pton(socket.AF_INET6, '::ff:ffff'))
    r = in6_or(inet_pton(socket.AF_INET6, 'ff02::1:ff00:0'), r)
    return inet_ntop(socket.AF_INET6, r)

def convert_llsnm_to_vaddr_ipv6(a: str) -> str:
    """Return virtual address resolved from link-local solicited-node multicast address."""
    a = str(ipaddress.ip_address(a).exploded)
    addr = "XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XX" + a[-7:]
    return addr

def in6_getnsma(a: str) -> str:
    """Return link-local solicited-node multicast address for given IPv6 address."""
    a_bytes = inet_pton(socket.AF_INET6, a)
    r = in6_and(a_bytes, inet_pton(socket.AF_INET6, '::ff:ffff'))
    r = in6_or(inet_pton(socket.AF_INET6, 'ff02::1:ff00:0'), r)
    return inet_ntop(socket.AF_INET6, r)

def in6_getansma(a: str) -> str:
    """Return virtual address resolved from link-local solicited-node multicast address."""
    a = str(ipaddress.ip_address(a).exploded)
    addr = "XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XX" + a[-7:]
    return addr


# ============================================================================
# IPv6 ADDRESS GENERATION FUNCTIONS
# ============================================================================

def generate_address(prefix: str, prefix_length: int) -> ipaddress.IPv6Address:
    """Generate IPv6 address based on prefix and prefix length."""
    suffix = shift_bytes_sufix(bytes.fromhex(format(random.getrandbits(128), '032x')), prefix_length)
    new_address_int = nb(bn(ipaddress.IPv6Address(prefix).packed) | bn(suffix))
    new_address_str = bytes_to_hex_string(new_address_int)
    new_address = ipaddress.IPv6Address(new_address_str)
    return new_address

def generate_random_global_ipv6(exclude_addresses: list[str]) -> str:
    """Generate random global unicast IPv6 address not in exclude list."""
    exclude_addresses = [ipaddress.IPv6Address(addr) for addr in exclude_addresses]
    while True:
        first_part = random.randint(0x2000, 0x3FFF)
        remaining_parts = [f"{random.randint(0, 0xFFFF):04x}" for _ in range(7)]
        rand_ipv6 = ipaddress.IPv6Address(f"{first_part:04x}:" + ":".join(remaining_parts))
        if is_global_unicast_ipv6(rand_ipv6) and rand_ipv6 not in exclude_addresses:
            return str(rand_ipv6)

def generate_ipv6_address(prefix: str) -> str:
    """Generate a random IPv6 address using the provided prefix."""
    first_half = random.randint(0, 2**64 - 1)
    ipv6_prefix = prefix
    full_address = ipaddress.IPv6Address(ipv6_prefix) + first_half
    return str(full_address)

def locate_addres(new_address: str) -> bool:
    """Check if address exists in CSV file."""
    csv_file = get_csv_path('ipv6.csv')
    with open(csv_file, 'r') as file:
        reader = csv.reader(file)
        for row in reader:
            if new_address in row:
                return False
    return True

def create_IPv6_add(input_filename: str) -> tuple[ipaddress.IPv6Address, int]:
    """Create IPv6 address based on input CSV file."""
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


# ============================================================================
# DHCP/SLAAC STATUS FUNCTIONS
# ============================================================================

def find_requested_addr(data: list) -> str:
    """Find 'requested_addr' in DHCP data."""
    for item in data:
        if isinstance(item, tuple) and item[0] == 'requested_addr':
            return item[1]
    return None

def extract_mac_from_duid(duid_data: bytes) -> str:
    """Extract MAC address from DUID data."""
    if len(duid_data) >= 6:
        return ":".join(f"{b:02x}" for b in duid_data[-6:])
    return None

def get_status_ip(mac: str, ip: str) -> str:
    """Get status of IP (DHCP, DHCPv6, SLAAC)."""
    role_file_path = get_csv_path('role_node.csv')
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
        dhcp_file_path = get_csv_path('dhcp.csv')
        if has_additional_data(dhcp_file_path):
            with open(dhcp_file_path, 'r') as csv_file:
                reader = csv.DictReader(csv_file)
                for row in reader:
                    if row['MAC'] == mac and row['IP'] == ip:
                        return "probably DHCP assigned"
        return None

    elif ip_obj.version == 6 and is_global_unicast_ipv6(ip):
        dhcp_file_path = get_csv_path('dhcp.csv')
        if has_additional_data(dhcp_file_path):
            with open(dhcp_file_path, 'r') as csv_file:
                reader = csv.DictReader(csv_file)
                for row in reader:
                    if row['MAC'] == mac and row['IP'] == ip:
                        return "probably DHCPv6 assigned"

        ra_file_path = get_csv_path('RA.csv')
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

def is_dhcp_slaac() -> list:
    """Check if DHCP, DHCPv6 server and SLAAC are available."""
    dhcp_file_path = get_csv_path('dhcp.csv')
    ra_file_path = get_csv_path('RA.csv')
    lst_result = []

    if has_additional_data(dhcp_file_path):
        with open(dhcp_file_path, 'r') as csv_file:
            reader = csv.DictReader(csv_file)
            for row in reader:
                try:
                    ip_obj = ipaddress.ip_address(row['IP'])
                    if ip_obj.version == 4 and row['Role'] == 'server':
                        status = "DHCP server"
                        if status not in lst_result:
                            lst_result.append(status)
                    if ip_obj.version == 6 and row['Role'] == 'server':
                        if is_global_unicast_ipv6(row['IP']):
                            status = "DHCPv6 server"
                            if status not in lst_result:
                                lst_result.append(status)
                except Exception:
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


# ============================================================================
# CSV FILTERING FUNCTIONS
# ============================================================================

def IPv4_IPv6_filter(input_filename: str) -> None:
    """Filter IPv6 addresses from a CSV file containing IP addresses."""
    ipv6_output_filename = get_csv_path('ipv6.csv')

    with open(input_filename, 'r') as input_file, open(ipv6_output_filename, 'a') as ipv6_output_file:
        reader = csv.DictReader(input_file)
        ipv6_writer = csv.writer(ipv6_output_file)

        for row in reader:
            ip_str = row['IP']
            try:
                ip = ipaddress.ip_address(ip_str)
                if ip.version == 4:
                    pass
                elif ip.version == 6:
                    if not ip.is_link_local and not ip.is_multicast and not ip.is_unspecified:
                        ipv6_writer.writerow([ip_str])
            except ValueError:
                pass


# ============================================================================
# EXTRACTION & PARSING FUNCTIONS
# ============================================================================

def extract_ipv6_addresses(config_string: str) -> list:
    """Extract valid IPv6 addresses from string (e.g., RDNS of RA message)."""
    match = re.search(r'\[\s*(.*?)\s*\]', config_string)
    if not match:
        return []
    potential_ips = [ip.strip() for ip in match.group(1).split(',') if ip.strip()]
    valid_ipv6 = []
    for ip in potential_ips:
        try:
            ipaddress.IPv6Address(ip)
            valid_ipv6.append(ip)
        except ValueError:
            continue
    return valid_ipv6

def extract_domains(config_string: str) -> list:
    """Extract domain names from string."""
    match = re.search(r'\[\s*(.*?)\s*\]', config_string)
    if not match:
        return []
    raw_entries = match.group(1).split(',')
    domains = []
    for entry in raw_entries:
        cleaned = entry.strip().strip("'\"")
        if cleaned:
            domains.append(cleaned)
    return domains


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def get_ips_from_other_macs(target_mac: str, mac_ip_dict: dict) -> list:
    """Get IPs from all MACs except the target MAC."""
    other_ips = []
    for mac, ips in mac_ip_dict.items():
        if mac != target_mac:
            other_ips.extend(ips)
    return other_ips

def collect_unique_items(dictionary: dict) -> list:
    """Retrieve unique items from dictionary values."""
    unique_items = set()
    for key, value_list in dictionary.items():
        for item in value_list:
            unique_items.add(item)
    return list(unique_items)
