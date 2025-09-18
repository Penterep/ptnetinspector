import csv
import ipaddress
import re
import socket

from netaddr import IPNetwork
from scapy.pton_ntop import inet_pton
from scapy.utils6 import in6_and

file_path = "src/tmp/"

def is_non_negative_float(value: str) -> bool:
    """
    Check if the value is a non-negative float.

    Args:
        value (str): The value to check.

    Returns:
        bool: True if non-negative float, False otherwise.
    """
    try:
        return float(value) >= 0
    except ValueError:
        return False

def is_valid_integer(value: str) -> bool:
    """
    Check if the value is a non-negative integer <= 255.

    Args:
        value (str): The value to check.

    Returns:
        bool: True if valid integer, False otherwise.
    """
    try:
        value = int(value)
        return 0 <= value <= 255
    except ValueError:
        return False

def is_valid_MTU(value: str) -> bool:
    """
    Check if the value is a non-negative integer <= 65535.

    Args:
        value (str): The value to check.

    Returns:
        bool: True if valid MTU, False otherwise.
    """
    try:
        value = int(value)
        return 0 <= value <= 65535
    except ValueError:
        return False

def is_valid_ipv6(ip: str) -> bool:
    """
    Validate IPv6 address using regex.

    Args:
        ip (str): IPv6 address.

    Returns:
        bool: True if valid, False otherwise.
    """
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

def is_valid_ipv4(ip: str) -> bool:
    """
    Validate IPv4 address.

    Args:
        ip (str): IPv4 address.

    Returns:
        bool: True if valid, False otherwise.
    """
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ipaddress.AddressValueError:
        return False

def check_prefix(prefix: str) -> bool:
    """
    Check if prefix is a valid IPv6 prefix.

    Args:
        prefix (str): IPv6 prefix.

    Returns:
        bool: True if valid, False otherwise.
    """
    if not is_valid_ipv6(prefix) and not is_valid_ipv6(str(IPNetwork(prefix).network)):
        return False
    return True

def is_valid_mac(mac: str) -> bool:
    """
    Validate MAC address.

    Args:
        mac (str): MAC address.

    Returns:
        bool: True if valid, False otherwise.
    """
    regex = (
        "^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})|"
        "([0-9a-fA-F]{4}\\.[0-9a-fA-F]{4}\\.[0-9a-fA-F]{4})$"
    )
    if mac is None:
        return False
    return re.search(re.compile(regex), mac) is not None

def is_global_unicast_ipv6(ipv6_address: str) -> bool:
    """
    Check if IPv6 address is global unicast.

    Args:
        ipv6_address (str): IPv6 address.

    Returns:
        bool: True if global unicast, False otherwise.
    """
    try:
        addr = ipaddress.IPv6Address(ipv6_address)
        return addr.is_global
    except ipaddress.AddressValueError:
        return False

def is_link_local_ipv6(address: str) -> bool:
    """
    Check if IPv6 address is link-local.

    Args:
        address (str): IPv6 address.

    Returns:
        bool: True if link-local, False otherwise.
    """
    try:
        ip = ipaddress.ip_address(address)
        return ip.version == 6 and ip.is_link_local
    except ValueError:
        return False

def is_ipv6_ula(address: str) -> bool:
    """
    Check if IPv6 address is ULA (Unique Local Address).

    Args:
        address (str): IPv6 address.

    Returns:
        bool: True if ULA, False otherwise.
    """
    try:
        ip = ipaddress.ip_address(address)
        return ip.version == 6 and ip.is_private and not ip.is_link_local and not ip.is_global
    except ValueError:
        return False

def is_llsnm_ipv6(ipv6: str) -> bool:
    """
    Check if IPv6 address is link-local solicited node multicast (ff02::1:ff00:0/104).

    Args:
        ipv6 (str): IPv6 address.

    Returns:
        bool: True if solicited node multicast, False otherwise.
    """
    temp = in6_and(b"\xff" * 13 + b"\x00" * 3, inet_pton(socket.AF_INET6, ipv6))
    temp2 = b'\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xff\x00\x00\x00'
    return temp == temp2

def is_valid_ipv6_prefix(prefix: str) -> bool:
    """
    Validate IPv6 prefix.

    Args:
        prefix (str): IPv6 prefix.

    Returns:
        bool: True if valid, False otherwise.
    """
    try:
        ipaddress.IPv6Network(prefix, strict=False)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False

def check_prefRA(pref_flag: str) -> bool:
    """
    Check if preference flag is valid for RA.

    Args:
        pref_flag (str): Preference flag.

    Returns:
        bool: True if valid, False otherwise.
    """
    valid_inputs = ["High", "Low", "Reserved", "Medium"]
    return pref_flag in valid_inputs

def has_additional_data(file_path: str) -> bool:
    """
    Check if CSV file has additional data rows beyond header.

    Args:
        file_path (str): Path to CSV file.

    Returns:
        bool: True if additional data exists, False otherwise.
    """
    if file_path is None:
        return False
    with open(file_path, 'r') as csv_file:
        reader = csv.reader(csv_file)
        next(reader, None)
        for row in reader:
            if row:
                return True
    return False

def check_ipv6_addresses_generated_from_prefix(ip: str, prefix: str) -> bool:
    """
    Check if IPv6 address is generated from the specified prefix.

    Args:
        ip (str): IPv6 address.
        prefix (str): IPv6 network prefix.

    Returns:
        bool: True if address is in network, False otherwise.
    """
    try:
        ipv6_network = ipaddress.IPv6Network(prefix, strict=False)
        ipv6_address = ipaddress.IPv6Address(ip)
        return ipv6_address in ipv6_network
    except ValueError:
        return False

def belongs_to_any_prefix(ipv6_address: str, prefixes: list) -> bool:
    """
    Check if IPv6 address belongs to any of the specified prefixes.

    Args:
        ipv6_address (str): IPv6 address.
        prefixes (list): List of IPv6 prefixes.

    Returns:
        bool: True if belongs, False otherwise.
    """
    try:
        ip = ipaddress.ip_address(ipv6_address)
        for prefix in prefixes:
            network = ipaddress.ip_network(prefix, strict=False)
            if ip in network:
                return True
        return False
    except ValueError:
        return False

def find_requested_addr(data: list) -> str:
    """
    Find 'requested_addr' in DHCP data.

    Args:
        data (list): DHCP data.

    Returns:
        str: Requested address if found, else None.
    """
    for item in data:
        if isinstance(item, tuple) and item[0] == 'requested_addr':
            return item[1]
    return None

def extract_mac_from_duid(duid_data: bytes) -> str:
    """
    Extract MAC address from DUID data.

    Args:
        duid_data (bytes): DUID data.

    Returns:
        str: MAC address if found, else None.
    """
    if len(duid_data) >= 6:
        return ":".join(f"{b:02x}" for b in duid_data[-6:])
    return None

def get_status_ip(mac: str, ip: str) -> str:
    """
    Get status of IP (DHCP, DHCPv6, SLAAC).

    Args:
        mac (str): MAC address.
        ip (str): IP address.

    Returns:
        str: Status string or None.
    """
    role_file_path = f'{file_path}role_node.csv'
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
        file_path = f"{file_path}dhcp.csv"
        if has_additional_data(file_path):
            with open(file_path, 'r') as csv_file:
                reader = csv.DictReader(csv_file)
                for row in reader:
                    if row['MAC'] == mac and row['IP'] == ip:
                        return "probably DHCP assigned"
        return None

    elif ip_obj.version == 6 and is_global_unicast_ipv6(ip):
        dhcp_file_path = f'{file_path}dhcp.csv'
        if has_additional_data(dhcp_file_path):
            with open(dhcp_file_path, 'r') as csv_file:
                reader = csv.DictReader(csv_file)
                for row in reader:
                    if row['MAC'] == mac and row['IP'] == ip:
                        return "probably DHCPv6 assigned"

        ra_file_path = f'{file_path}RA.csv'
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
    """
    Check if DHCP, DHCPv6 server and SLAAC are available.

    Returns:
        list: List of available services.
    """
    dhcp_file_path = f"{file_path}dhcp.csv"
    ra_file_path = f"{file_path}RA.csv"
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

def extract_ipv6_addresses(config_string: str) -> list:
    """
    Extract valid IPv6 addresses from string (e.g., RDNS of RA message).

    Args:
        config_string (str): String containing IPv6 addresses.

    Returns:
        list: List of valid IPv6 addresses.
    """
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
    """
    Extract domain names from string.

    Args:
        config_string (str): String containing domain names.

    Returns:
        list: List of domain names.
    """
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

def is_ipv6_predictable(ip: str, mac: str) -> bool:
    """
    Check if IPv6 address is predictable based on patterns and MAC address.

    Args:
        ip (str): IPv6 address.
        mac (str): MAC address.

    Returns:
        bool: True if predictable, False otherwise.
    """
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