"""Shared output helpers for JSON and terminal formatting.

Centralizes IP filtering, role/code transformation, and other helpers used
by both output modules to avoid duplication.
"""
import ipaddress
import pandas as pd
from ptnetinspector.send.send import IPMode
from ptnetinspector.utils.ip_utils import is_valid_ipv6


def filter_ips_by_mode(df: pd.DataFrame, ipver: IPMode) -> pd.DataFrame:
    """Filter DataFrame rows by enabled IP versions.

    Args:
        df: DataFrame with 'IP' column.
        ipver (IPMode): Enabled IP versions.

    Returns:
        DataFrame: Filtered rows matching enabled IP versions.
    """
    if 'IP' not in df.columns or (ipver.ipv4 and ipver.ipv6):
        return df

    def is_allowed(ip: str) -> bool:
        if is_valid_ipv6(ip):
            return ipver.ipv6
        try:
            ipaddress.IPv4Address(ip)
            return ipver.ipv4
        except (ipaddress.AddressValueError, ValueError, TypeError):
            return False

    return df[df['IP'].apply(is_allowed)].reset_index(drop=True)


def convert_role_to_list(role: str) -> list:
    """Convert semicolon-separated role string to list.

    Args:
        role (str): Role string.

    Returns:
        list: List of role components.
    """
    return role.split(";")


def transform_role_print(role: str) -> str:
    """Transform role string to human-readable format for terminal output.

    Args:
        role (str): Role string (semicolon-separated components).

    Returns:
        str: Formatted role description.
    """
    parts = role.split(';')
    if len(parts) == 1:
        return parts[0]
    result = []
    if "Preferred router" in parts:
        result.append("Preferred router")
    elif "Router" in parts:
        result.append("Router")
    has_ipv4_gw = "IPv4 default GW" in parts
    has_ipv6_gw = "IPv6 default GW" in parts
    if has_ipv4_gw and has_ipv6_gw:
        result.append("IPv4+IPv6 default GW")
    elif has_ipv4_gw:
        result.append("IPv4 default GW")
    elif has_ipv6_gw:
        result.append("IPv6 default GW")
    has_dhcp = "DHCP server" in parts
    has_dhcpv6 = "DHCPv6 server" in parts
    if has_dhcp and has_dhcpv6:
        result.append("DHCP+DHCPv6 server")
    elif has_dhcp:
        result.append("DHCP server")
    elif has_dhcpv6:
        result.append("DHCPv6 server")
    return " | ".join(result)


def extract_short_code(code: str) -> str:
    """Extract short vulnerability code format.

    Extracts the part starting from '4-' or '6-' (e.g., '6-MLDV1' from
    'PTV-NET-IDENT-ACTIVE-6-MLDV1'). Returns original code if not found.

    Args:
        code (str): Full vulnerability code.

    Returns:
        str: Short code format or original code.
    """
    parts = code.split('-')
    for i, part in enumerate(parts):
        if part in ['4', '6'] and i + 1 < len(parts):
            return '-'.join(parts[i:])
    return code
