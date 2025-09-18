import csv
import os
import pandas as pd
from scapy.all import *
from libs.check import has_additional_data
import numpy as np
import socket

# Get the directory of the currently running Python script
current_directory = os.path.dirname(os.path.realpath(__file__))

def create_csv(directory: str) -> None:
    """
    Creates multiple CSV files with predefined headers in the specified directory.

    Args:
        directory (str): The directory where CSV files will be created.

    Output:
        None
    """
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
    with open(f"{directory}/vulnerability.csv", 'w', newline='') as csvfile:
        fieldnames = ['ID', 'MAC', 'Mode', 'IPver', 'Code', 'Description', 'Label']
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
    if has_additional_data("src/tmp/addresses.csv"):
        sort_csv_based_MAC(interface, "src/tmp/addresses.csv")
        sort_csv_based_MAC(interface, "src/tmp/RA.csv")
        df1 = pd.read_csv('src/tmp/addresses.csv')
        device_numbers = {}
        for _, row in df1.iterrows():
            mac_address = row['MAC']
            if mac_address not in device_numbers:
                device_numbers[mac_address] = len(device_numbers) + 1
        new_df = pd.DataFrame({'MAC': list(device_numbers.keys()), 'Device_Number': list(device_numbers.values())})
        new_df.to_csv(file_name, index=False)
        df2 = pd.read_csv('src/tmp/RA.csv')
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
        df_gateway = pd.read_csv('src/tmp/default_gw.csv')
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
                    pass
            if mac_address in device_roles and "Router" not in device_roles[mac_address] and "Preferred router" not in device_roles[mac_address]:
                device_roles[mac_address] += f";Router;IPv{ip_version} default GW"
            elif mac_address in device_roles:
                device_roles[mac_address] += f";IPv{ip_version} default GW"
            else:
                device_roles[mac_address] = f"Router;IPv{ip_version} default GW"
        df_gateway = pd.read_csv('src/tmp/dhcp.csv')
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
            blank_role_rows = final_df[final_df['Role'].isna() | (final_df['Role'] == '')]
            host_str = 'Host'
            final_df.loc[blank_role_rows.index, 'Role'] = host_str
            final_df.to_csv(file_name, index=False)

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
        pass

def sort_all_csv(interface: str) -> None:
    """
    Sorts all relevant CSV files by MAC address and removes entries with the sender's MAC.

    Args:
        interface (str): Network interface to get MAC address.

    Output:
        None
    """
    sort_csv_based_MAC(interface, "src/tmp/dhcp.csv")
    sort_csv_based_MAC(interface, "src/tmp/eap.csv")
    sort_csv_based_MAC(interface, "src/tmp/IGMPv1v2.csv")
    sort_csv_based_MAC(interface, "src/tmp/IGMPv3.csv")
    sort_csv_based_MAC(interface, "src/tmp/LLMNR.csv")
    sort_csv_based_MAC(interface, "src/tmp/localname.csv")
    sort_csv_based_MAC(interface, "src/tmp/MDNS.csv")
    sort_csv_based_MAC(interface, "src/tmp/MLDv1.csv")
    sort_csv_based_MAC(interface, "src/tmp/MLDv2.csv")
    sort_csv_based_MAC(interface, "src/tmp/RA.csv")
    sort_csv_based_MAC(interface, "src/tmp/wsdiscovery.csv")
    sort_csv_based_MAC(interface, "src/tmp/default_gw.csv")

def sort_and_deduplicate_csv(filepath: str) -> None:
    """
    Sorts a CSV file based on the first column (ID, assumed numeric), then by Code, then Description.
    Removes duplicate rows.

    Args:
        filepath (str): Path to the CSV file.

    Output:
        None
    """
    with open(filepath, newline='') as f:
        reader = csv.reader(f)
        header = next(reader)
        rows = set(tuple(row) for row in reader)
    numeric_rows = []
    network_rows = []
    for row in rows:
        if row and row[0].isdigit():
            numeric_rows.append(row)
        else:
            network_rows.append(row)
    numeric_rows.sort(key=lambda r: (int(r[0]), r[3], r[4], r[5]))
    network_rows.sort(key=lambda r: (r[4], r[5]))
    sorted_rows = numeric_rows + network_rows
    with open(filepath, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(sorted_rows)

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
