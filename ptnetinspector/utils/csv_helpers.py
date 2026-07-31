"""CSV creation, mutation, and utility helpers for ptnetinspector.

Centralizes creation of tmp CSVs, sorting/cleanup, and simple analytics used by
both the terminal (non-JSON) and JSON outputs.
"""
import csv
import logging
import os
import socket

import pandas as pd
import numpy as np
from scapy.all import get_if_hwaddr
from ptnetinspector.entities._registry import registry as entity_registry
from ptnetinspector.utils.path import get_csv_path, get_tmp_path


logger = logging.getLogger(__name__)


def create_csv(interface: str | None = None) -> None:
    """
    Creates multiple CSV files with predefined headers in the temporary directory.

    Args:
        interface (str | None): Network interface name. If provided, creates CSVs in tmp/<interface>/ folder.

    Output:
        None
    """
    directory = get_tmp_path(interface)
    entity_registry.clear()
    with open(f"{directory}/addresses.csv", 'w', newline='') as csvfile:
        fieldnames = ['MAC', 'IP']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
    with open(f"{directory}/addresses_unfiltered.csv", 'w', newline='') as csvfile:
        fieldnames = ['MAC', 'IP']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
    with open(f"{directory}/packets.csv", 'w', newline='') as csvfile:
        fieldnames = ['time', 'src MAC', 'des MAC', 'source IP', 'destination IP', 'protocol', 'length']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
    with open(f"{directory}/routers.csv", 'w', newline='') as csvfile:
        fieldnames = ['MAC']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
    with open(f"{directory}/MDNS.csv", 'w', newline='') as csvfile:
        fieldnames = ['MAC', 'IP']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
    with open(f"{directory}/LLMNR.csv", 'w', newline='') as csvfile:
        fieldnames = ['MAC', 'IP']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
    with open(f"{directory}/MLDv1.csv", 'w', newline='') as csvfile:
        fieldnames = ['MAC', 'IP', 'protocol', 'mulip']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
    with open(f"{directory}/MLDv2.csv", 'w', newline='') as csvfile:
        fieldnames = ['MAC', 'IP', 'protocol', 'rtype', 'mulip', 'sources']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
    with open(f"{directory}/IGMPv1v2.csv", 'w', newline='') as csvfile:
        fieldnames = ['MAC', 'IP', 'protocol', 'mulip']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
    with open(f"{directory}/IGMPv3.csv", 'w', newline='') as csvfile:
        fieldnames = ['MAC', 'IP', 'protocol', 'rtype', 'mulip', 'sources']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
    with open(f"{directory}/RA.csv", 'w', newline='') as csvfile:
        fieldnames = ['MAC', 'IP', 'M', 'O', 'H', 'A', 'L', 'Preference', 'Router_lft', 'Reachable_time', 'Retrans_time',
                    'DNS', 'MTU', 'Prefix', 'Valid_lft', 'Preferred_lft']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
    with open(f"{directory}/localname.csv", 'w', newline='') as csvfile:
        fieldnames = ['MAC', 'name']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
    with open(f"{directory}/role_node.csv", 'w', newline='') as csvfile:
        fieldnames = ['MAC', 'Device_Number', 'Role']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
    with open(f"{directory}/ipv6_route_table.csv", 'w', newline='') as csvfile:
        fieldnames = ['Destination', 'Nexthop', 'Flag', 'Metric', 'Refcnt', 'Use', 'If']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
    with open(f"{directory}/ipv4_route_table.csv", 'w', newline='') as csvfile:
        fieldnames = ['Destination', 'Gateway', 'Genmask', 'Flags', 'Metric', 'Ref', 'Use', 'Iface']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
    with open(f"{directory}/time_all.csv", 'w', newline='') as csvfile:
        fieldnames = ['time', 'MAC', 'packet']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
    with open(f"{directory}/time_incoming.csv", 'w', newline='') as csvfile:
        fieldnames = ['time', 'MAC', 'packet']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
    with open(f"{directory}/time_outgoing.csv", 'w', newline='') as csvfile:
        fieldnames = ['time', 'MAC', 'packet']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
    with open(f"{directory}/start_end_mode.csv", 'w', newline='') as csvfile:
        fieldnames = ['time']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
    with open(f"{directory}/eap.csv", 'w', newline='') as csvfile:
        fieldnames = ['MAC', 'packet']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
    with open(f"{directory}/remote_node.csv", 'w', newline='') as csvfile:
        fieldnames = ['src MAC', 'dst MAC', 'src IP', 'dst IP']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
    with open(f"{directory}/dhcp.csv", 'w', newline='') as csvfile:
        fieldnames = ['MAC', 'IP', 'Role']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
    with open(f"{directory}/wsdiscovery.csv", 'w', newline='') as csvfile:
        fieldnames = ['MAC', 'IP']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
    with open(f"{directory}/default_gw.csv", 'w', newline='') as csvfile:
        fieldnames = ['MAC', 'IP']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
    with open(f"{directory}/vulnerability_mac.csv", 'w', newline='') as csvfile:
        fieldnames = ['ID', 'MAC', 'Mode', 'IPver', 'Code', 'Description', 'Label']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
    with open(f"{directory}/vulnerability_ip.csv", 'w', newline='') as csvfile:
        fieldnames = ['ID', 'IP', 'Mode', 'IPver', 'Code', 'Description', 'Label']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
    with open(f"{directory}/vulnerability_net.csv", 'w', newline='') as csvfile:
        fieldnames = ['ID', 'Mode', 'IPver', 'Code', 'Description', 'Label']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
    with open(f"{directory}/networks.csv", 'w', newline='') as csvfile:
        fieldnames = ['network_prefix', 'prefix_length']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

def sort_csv_based_MAC(interface: str, file_name: str) -> None:
    """
    Sorts a CSV file by MAC address in ascending order, removes entries with the sender's MAC,
    and saves the result back to the file.

    Args:
        interface (str): Network interface to get MAC address.
        file_name (str): Path to the CSV file.

    Output:
        None
    """
    if has_additional_data(file_name):
        df = pd.read_csv(file_name)
        specified_mac = get_if_hwaddr(interface)
        df_filtered = df[df['MAC'] != specified_mac]
        df_sorted = df_filtered.sort_values(by='MAC')
        if 'IP' in df_sorted.columns:
            df_sorted['IP'] = df_sorted.groupby('MAC')['IP'].transform(lambda x: x.sort_values().values)
        df_sorted.to_csv(file_name, index=False)

def sort_csv_role_node(interface: str, file_name: str) -> None:
    """
    Assigns device numbers and roles to MAC addresses from CSV files and stores them in role_node.csv.

    Args:
        interface (str): Network interface to get MAC address.
        file_name (str): Path to the role_node CSV file.

    Output:
        None
    """
    addresses_csv = get_csv_path('addresses.csv', interface)
    if has_additional_data(addresses_csv):
        ra_csv = get_csv_path('RA.csv', interface)
        sort_csv_based_MAC(interface, addresses_csv)
        sort_csv_based_MAC(interface, ra_csv)
        df1 = pd.read_csv(addresses_csv)
        device_numbers = {}
        for _, row in df1.iterrows():
            mac_address = row['MAC']
            if mac_address not in device_numbers:
                device_numbers[mac_address] = len(device_numbers) + 1
        new_df = pd.DataFrame({'MAC': list(device_numbers.keys()), 'Device_Number': list(device_numbers.values())})
        new_df.to_csv(file_name, index=False)
        df2 = pd.read_csv(ra_csv)
        device_roles = {}
        for _, row in df2.iterrows():
            mac_address = row['MAC']
            preference = row['Preference']
            router_lft = row['Router_lft']
            valid_lft = row['Valid_lft']
            if preference == "High" and int(router_lft) > 0:
                device_roles[mac_address] = "Preferred router"
            elif preference == "Medium" and int(router_lft) > 0:
                higher_preference_devices = df2[(df2['MAC'] != mac_address) & (df2['Preference'].isin(['High', 'Reserved']))]
                if higher_preference_devices.empty:
                    device_roles[mac_address] = "Preferred router"
                else:
                    device_roles[mac_address] = "Router"
            elif preference == "Low" and int(router_lft) > 0:
                higher_preference_devices = df2[(df2['MAC'] != mac_address) & (df2['Preference'].isin(['High', 'Medium', 'Reserved']))]
                if higher_preference_devices.empty:
                    device_roles[mac_address] = "Preferred router"
                else:
                    device_roles[mac_address] = "Router"
            else:
                device_roles[mac_address] = "Router"
        default_gw_csv = get_csv_path('default_gw.csv', interface)
        df_gateway = pd.read_csv(default_gw_csv)
        for _, row in df_gateway.iterrows():
            mac_address = row['MAC']
            ip_addr = row['IP']
            ip_version = ""
            try:
                socket.inet_pton(socket.AF_INET, ip_addr)
                ip_version = "4"
            except socket.error:
                try:
                    socket.inet_pton(socket.AF_INET6, ip_addr)
                    ip_version = "6"
                except socket.error:
                    # Malformed IP in gateway CSV could indicate file corruption; log for debug.
                    logger.debug("Malformed gateway IP in CSV: MAC=%s, IP=%s (skipping)", mac_address, ip_addr)
                    pass
            if mac_address in device_roles and "Router" not in device_roles[mac_address] and "Preferred router" not in device_roles[mac_address]:
                device_roles[mac_address] += f";Router;IPv{ip_version} default GW"
            elif mac_address in device_roles:
                device_roles[mac_address] += f";IPv{ip_version} default GW"
            else:
                device_roles[mac_address] = f"Router;IPv{ip_version} default GW"
        dhcp_csv = get_csv_path('dhcp.csv', interface)
        df_gateway = pd.read_csv(dhcp_csv)
        for _, row in df_gateway.iterrows():
            mac_address = row['MAC']
            ip_addr = row['IP']
            role = row['Role']
            if role != "server":
                continue
            dhcp_version = ""
            try:
                socket.inet_pton(socket.AF_INET, ip_addr)
                dhcp_version = "DHCP"
            except socket.error:
                try:
                    socket.inet_pton(socket.AF_INET6, ip_addr)
                    dhcp_version = "DHCPv6"
                except socket.error:
                    # Malformed DHCP server IP in CSV could indicate file corruption; log for debug.
                    logger.debug("Malformed DHCP server IP in CSV: MAC=%s, IP=%s (skipping)", mac_address, ip_addr)
                    pass
            if mac_address in device_roles:
                device_roles[mac_address] += f";{dhcp_version} server"
            else:
                device_roles[mac_address] = f"{dhcp_version} server"
        new_df = pd.DataFrame({'MAC': list(device_roles.keys()), 'Role': list(device_roles.values())})
        if has_additional_data(file_name):
            existing_df = pd.read_csv(file_name)
            final_df = pd.merge(existing_df, new_df, on='MAC', how='left')
            final_df.to_csv(file_name, index=False)
            final_df = pd.read_csv(file_name)
            final_df['Role'] = final_df['Role'].astype('object')
            blank_role_rows = final_df[final_df['Role'].isna() | (final_df['Role'] == '')]
            host_str = 'Host'
            final_df.loc[blank_role_rows.index, 'Role'] = host_str
            final_df.to_csv(file_name, index=False)

def read_role_node_csv(filename):
    """Return the dictionary of sorted devices with their corresponding MAC"""
    result = {}
    if not has_additional_data(filename):
        return
    with open(filename, newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            try:
                device_number = int(row['Device_Number'].strip())
                mac = row['MAC'].strip()
                result[device_number] = mac
            except (ValueError, KeyError):
                # Malformed role-node row could indicate file corruption; log for debug.
                logger.debug("Malformed role-node CSV row (skipping): %s", row)
                continue
    return dict(sorted(result.items()))

def delete_middle_content_csv(filename: str) -> None:
    """
    If the CSV file has more than 3 rows, keeps only the first and last row, removing the middle content.

    Args:
        filename (str): Path to the CSV file.

    Output:
        None
    """
    try:
        df = pd.read_csv(filename)
        if len(df) > 3:
            df = df[df.index.isin([0, -1]) | ~df.index.isin(range(1, len(df) - 1))]
            df.to_csv(filename, index=False)
    except FileNotFoundError:
        # Optional file may not exist yet.
        pass

def sort_all_csv(interface: str) -> None:
    """
    Sorts all relevant CSV files by MAC address and removes entries with the sender's MAC.

    Args:
        interface (str): Network interface to get MAC address.

    Output:
        None
    """
    sort_csv_based_MAC(interface, get_csv_path('dhcp.csv'))
    sort_csv_based_MAC(interface, get_csv_path('eap.csv'))
    sort_csv_based_MAC(interface, get_csv_path('IGMPv1v2.csv'))
    sort_csv_based_MAC(interface, get_csv_path('IGMPv3.csv'))
    sort_csv_based_MAC(interface, get_csv_path('LLMNR.csv'))
    sort_csv_based_MAC(interface, get_csv_path('localname.csv'))
    sort_csv_based_MAC(interface, get_csv_path('MDNS.csv'))
    sort_csv_based_MAC(interface, get_csv_path('MLDv1.csv'))
    sort_csv_based_MAC(interface, get_csv_path('MLDv2.csv'))
    sort_csv_based_MAC(interface, get_csv_path('RA.csv'))
    sort_csv_based_MAC(interface, get_csv_path('wsdiscovery.csv'))
    sort_csv_based_MAC(interface, get_csv_path('default_gw.csv'))

def sort_and_deduplicate_vul_csv(filepath: str) -> None:
    """
    Sorts a vulnerability CSV by device ID (numeric first, network rows last) and
    removes duplicates. When rows are identical except for Label, keeps the one with
    Label=1. When rows differ only in Description, keeps the longest Description.

    Columns are resolved from the header rather than by position, because the three
    vulnerability files have different shapes: vulnerability_mac.csv is keyed by MAC,
    vulnerability_ip.csv by IP, and vulnerability_net.csv has no identity column at all.

    Args:
        filepath (str): Path to the CSV file.

    Output:
        None
    """
    with open(filepath, newline='') as f:
        reader = csv.reader(f)
        header = next(reader)
        rows = list(reader)

    def column(name: str) -> int | None:
        return header.index(name) if name in header else None

    label_idx = column('Label')
    desc_idx = column('Description')
    id_idx = column('ID')
    # MAC or IP, whichever this file uses to identify the finding; absent for net rows.
    identity_idx = column('MAC') if 'MAC' in header else column('IP')
    ipver_idx = column('IPver')
    code_idx = column('Code')

    if label_idx is None or desc_idx is None or id_idx is None:
        # Unknown layout: leave the file untouched rather than reshuffling it blindly.
        return

    def field(row: list, idx: int | None) -> str:
        return row[idx] if idx is not None and idx < len(row) else ""

    # Collapse rows that differ only in Label, keeping the most recent verdict.
    # Rows are appended in evaluation order and every pass re-assesses the whole
    # packet timeline, so a later row was computed from a superset of the evidence
    # the earlier one saw — including the modes that ran in between.
    row_dict = {}
    for row in rows:
        if not row or len(row) < len(header):
            continue
        key = tuple(value for i, value in enumerate(row) if i != label_idx)
        row_dict[key] = row

    # Collapse rows that differ only in Description, keeping the most detailed one.
    # The identity column stays in the key: without it vulnerability_ip.csv would
    # fold every address of a device into a single row.
    code_dict = {}
    for row in row_dict.values():
        code_key = tuple(
            value for i, value in enumerate(row) if i not in (label_idx, desc_idx)
        )
        existing = code_dict.get(code_key)
        if existing is None or len(row[desc_idx]) > len(existing[desc_idx]):
            code_dict[code_key] = row

    # Device rows first, ordered by device number; network rows after them.
    numeric_rows = []
    network_rows = []
    for row in code_dict.values():
        (numeric_rows if field(row, id_idx).isdigit() else network_rows).append(row)

    numeric_rows.sort(key=lambda r: (
        int(field(r, id_idx)),
        field(r, identity_idx),
        field(r, ipver_idx),
        field(r, code_idx),
        field(r, desc_idx),
    ))
    network_rows.sort(key=lambda r: (field(r, code_idx), field(r, desc_idx)))

    with open(filepath, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(numeric_rows + network_rows)

def remove_duplicates_from_csv(input_csv: str) -> None:
    """
    Removes duplicate rows from a CSV file.

    Args:
        input_csv (str): Path to the CSV file.

    Output:
        None
    """
    data = pd.read_csv(input_csv)
    data.drop_duplicates(inplace=True)
    data.to_csv(input_csv, index=False)

def delete_contents_except_headers(csv_path: str) -> None:
    """
    Remove all rows except the header from a CSV file.

    Args:
        csv_path (str): Path to the CSV file.

    Output:
        None

    Description:
        Keeps only the header row in the CSV file.
    """
    if not csv_path.endswith('.csv'):
        print(f"{csv_path} is not a CSV file.")
        return

    df = pd.read_csv(csv_path)
    if len(df.index) > 1:
        header_row = df.iloc[0]
        df = pd.DataFrame(columns=df.columns)
        df = pd.concat([df, header_row.to_frame().T], ignore_index=True)
        df.to_csv(csv_path, index=False)

def sort_csv(input_file, output_file):
    """
    Description:
        Reads a CSV file containing 'src MAC' and 'source IP' columns,
        maps each MAC address to its associated IP addresses,
        and writes the results to an output CSV file with columns 'MAC' and 'IP'.

    Args:
        input_file (str): Path to the input CSV file.
        output_file (str): Path to the output CSV file.

    Output:
        Writes a CSV file with columns 'MAC' and 'IP', listing each MAC address
        and its associated IP addresses.
    """
    mac_to_ips = {}

    with open(input_file, 'r', newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            mac = row['src MAC']
            ip = row['source IP']
            if mac not in mac_to_ips:
                mac_to_ips[mac] = set()
            mac_to_ips[mac].add(ip)

    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['MAC', 'IP'])
        for mac, ips in mac_to_ips.items():
            for ip in ips:
                writer.writerow([mac, ip])

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