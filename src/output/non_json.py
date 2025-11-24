import csv
import ipaddress
import pandas as pd
from tabulate import tabulate
from src.send import IPMode
from src.create_csv import sort_csv_based_MAC, delete_middle_content_csv
from libs.check import (
    has_additional_data, is_global_unicast_ipv6, is_ipv6_ula, is_link_local_ipv6,
    is_valid_ipv6, is_llsnm_ipv6, get_status_ip, is_dhcp_slaac
)
from ptlibs import ptprinthelper
from libs.convert import in6_getansma, in6_getnsma
from src.output.oui import lookup_vendor_from_csv

file_path = "src/tmp/"

class Non_json:
    @staticmethod
    def transform_role_print(role: str) -> str:
        """
        Transform the role string into a more readable format.

        Args:
            role (str): The role string to be transformed.

        Returns:
            str: Human-readable role description.
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

    @staticmethod
    def print_box(string: str):
        """
        Print a string inside a box for emphasis.

        Args:
            string (str): The string to print.
        """
        box_char = '='
        ptprinthelper.ptprint(box_char*(len(string)+4))
        ptprinthelper.ptprint(f"{box_char} {string} {box_char}")
        ptprinthelper.ptprint(box_char*(len(string)+4))

    @staticmethod
    def get_unique_mac_addresses(csv_file: str):
        """
        Get a list of unique MAC addresses from a CSV file.

        Args:
            csv_file (str): Path to the CSV file.

        Returns:
            list: List of unique MAC addresses.
        """
        data = pd.read_csv(csv_file)
        mac_addresses = data['MAC']
        unique_mac_addresses = mac_addresses.drop_duplicates().tolist()
        return unique_mac_addresses

    @staticmethod
    def read_vulnerability_table(
        mode: str,
        ipver: IPMode,
        csv_file_path: str = f"{file_path}vulnerability.csv"
    ):
        """
        Read vulnerability CSV file and create formatted tables for IPv4 and IPv6,
        showing vulnerabilities across different node IDs and Network.

        Args:
            mode (str): Scan mode.
            ipver (IPMode): IP version object.
            csv_file_path (str): Path to vulnerability CSV file.
        """
        vulnerabilities_ipv4 = {}
        vulnerabilities_ipv6 = {}
        vulnerabilities_net_ipv4 = {}
        vulnerabilities_net_ipv6 = {}
        node_ids_ipv4 = set()
        node_ids_ipv6 = set()
        net_ids_ipv4 = set()
        net_ids_ipv6 = set()

        with open(csv_file_path, 'r', newline='', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                if mode in row['Mode']:
                    ipver_value = row.get('IPver', '').strip()
                    # IPv4
                    if ipver.ipv4 and ipver_value in ['4', 'both']:
                        if row['ID'] != 'Network':
                            node_id = row['ID']
                            code = row['Code']
                            label = int(row['Label'])
                            node_ids_ipv4.add(node_id)
                            vulnerabilities_ipv4.setdefault(code, {})[node_id] = label
                        else:
                            net_id = 'Network'
                            code = row['Code']
                            label = int(row['Label'])
                            net_ids_ipv4.add(net_id)
                            vulnerabilities_net_ipv4.setdefault(code, {})[net_id] = label
                    # IPv6
                    if ipver.ipv6 and ipver_value in ['6', 'both']:
                        if row['ID'] != 'Network':
                            node_id = row['ID']
                            code = row['Code']
                            label = int(row['Label'])
                            node_ids_ipv6.add(node_id)
                            vulnerabilities_ipv6.setdefault(code, {})[node_id] = label
                        else:
                            net_id = 'Network'
                            code = row['Code']
                            label = int(row['Label'])
                            net_ids_ipv6.add(net_id)
                            vulnerabilities_net_ipv6.setdefault(code, {})[net_id] = label

        GREEN = '\033[92m'
        RED = '\033[91m'
        WHITE = '\033[97m'
        END = '\033[0m'

        def build_table_data(vulnerabilities_dict, sorted_ids):
            table_data = []
            sorted_codes = sorted(vulnerabilities_dict.keys())
            for code in sorted_codes:
                row = [code]
                for node_id in sorted_ids:
                    symbol = 'N/A'
                    if node_id in vulnerabilities_dict[code]:
                        if vulnerabilities_dict[code][node_id] == 1 and (mode not in ['802.1x']):
                            symbol = f"{RED}X{END}"
                        elif vulnerabilities_dict[code][node_id] == 0 and (mode not in ['802.1x']):
                            symbol = f"{GREEN}✓{END}"
                        elif vulnerabilities_dict[code][node_id] == 2 and (mode not in ['802.1x']):
                            symbol = f"{WHITE}N/A{END}"
                    row.append(symbol)
                table_data.append(row)
            return table_data, sorted_codes

        def print_device_stats(vulnerabilities_dict, sorted_ids, sorted_codes, ip_version):
            ptprinthelper.ptprint(f"Vulnerability Count per Device (IPv{ip_version}):")
            for node_id in sorted_ids:
                vulnerable_count = sum(
                    vulnerabilities_dict[code].get(node_id, 0) == 1 for code in sorted_codes
                )
                total_tests = sum(
                    node_id in vulnerabilities_dict[code] for code in sorted_codes
                )
                ptprinthelper.ptprint(f"Device number {node_id}: {vulnerable_count}/{total_tests} vulnerabilities", "INFO")

        def print_network_stats(vulnerabilities_dict, net_ids, sorted_codes, ip_version):
            ptprinthelper.ptprint(f"Vulnerability Count for Network (IPv{ip_version}):")
            for net_id in net_ids:
                vulnerable_count = sum(
                    vulnerabilities_dict[code].get(net_id, 0) == 1 for code in sorted_codes
                )
                total_tests = sum(
                    net_id in vulnerabilities_dict[code] for code in sorted_codes
                )
                ptprinthelper.ptprint(f"{net_id}: {vulnerable_count}/{total_tests} vulnerabilities", "INFO")

        # IPv4 output
        if ipver.ipv4 and (vulnerabilities_ipv4 or vulnerabilities_net_ipv4):
            Non_json.print_box("Vulnerability Analysis Table (IPv4)")
            ptprinthelper.ptprint(f"Legend: {RED}X{END} = Vulnerable (Label=1), {GREEN}✓{END} = Not Vulnerable (Label=0), N/A = No Answer")
            if vulnerabilities_ipv4:
                sorted_node_ids_ipv4 = sorted(node_ids_ipv4, key=lambda x: int(x))
                table_data_ipv4, sorted_codes_ipv4 = build_table_data(vulnerabilities_ipv4, sorted_node_ids_ipv4)
                headers_node_ipv4 = ['Vulnerability'] + [f'Dev {id}' for id in sorted_node_ids_ipv4]
                table_node_ipv4 = tabulate(table_data_ipv4, headers=headers_node_ipv4, tablefmt='grid', stralign='center')
                ptprinthelper.ptprint(table_node_ipv4)
                print_device_stats(vulnerabilities_ipv4, sorted_node_ids_ipv4, sorted_codes_ipv4, "4")
            if vulnerabilities_net_ipv4:
                sorted_codes_net_ipv4 = sorted(vulnerabilities_net_ipv4.keys())
                table_data_net_ipv4 = []
                for code in sorted_codes_net_ipv4:
                    row = [code]
                    for net_id in net_ids_ipv4:
                        symbol = 'N/A'
                        if net_id in vulnerabilities_net_ipv4[code]:
                            if vulnerabilities_net_ipv4[code][net_id] == 1 and (mode not in ['802.1x']):
                                symbol = f"{RED}X{END}"
                            elif vulnerabilities_net_ipv4[code][net_id] == 0 and (mode not in ['802.1x', 'p']):
                                symbol = f"{GREEN}✓{END}"
                            elif vulnerabilities_net_ipv4[code][net_id] == 2:
                                symbol = f"{WHITE}N/A{END}"
                        row.append(symbol)
                    table_data_net_ipv4.append(row)
                headers_net_ipv4 = ['Vulnerability'] + [f'{id}' for id in net_ids_ipv4]
                table_net_ipv4 = tabulate(table_data_net_ipv4, headers=headers_net_ipv4, tablefmt='grid', stralign='center')
                ptprinthelper.ptprint(table_net_ipv4)
                print_network_stats(vulnerabilities_net_ipv4, net_ids_ipv4, sorted_codes_net_ipv4, "4")

        # IPv6 output
        if ipver.ipv6 and (vulnerabilities_ipv6 or vulnerabilities_net_ipv6):
            Non_json.print_box("Vulnerability Analysis Table (IPv6)")
            ptprinthelper.ptprint(f"Legend: {RED}X{END} = Vulnerable (Label=1), {GREEN}✓{END} = Not Vulnerable (Label=0), N/A = No Answer")
            if vulnerabilities_ipv6:
                sorted_node_ids_ipv6 = sorted(node_ids_ipv6, key=lambda x: int(x))
                table_data_ipv6, sorted_codes_ipv6 = build_table_data(vulnerabilities_ipv6, sorted_node_ids_ipv6)
                headers_node_ipv6 = ['Vulnerability'] + [f'Dev {id}' for id in sorted_node_ids_ipv6]
                table_node_ipv6 = tabulate(table_data_ipv6, headers=headers_node_ipv6, tablefmt='grid', stralign='center')
                ptprinthelper.ptprint(table_node_ipv6)
                print_device_stats(vulnerabilities_ipv6, sorted_node_ids_ipv6, sorted_codes_ipv6, "6")
            if vulnerabilities_net_ipv6:
                sorted_codes_net_ipv6 = sorted(vulnerabilities_net_ipv6.keys())
                table_data_net_ipv6 = []
                for code in sorted_codes_net_ipv6:
                    row = [code]
                    for net_id in net_ids_ipv6:
                        symbol = 'N/A'
                        if net_id in vulnerabilities_net_ipv6[code]:
                            if vulnerabilities_net_ipv6[code][net_id] == 1 and (mode not in ['802.1x']):
                                symbol = f"{RED}X{END}"
                            elif vulnerabilities_net_ipv6[code][net_id] == 0 and (mode not in ['802.1x', 'p']):
                                symbol = f"{GREEN}✓{END}"
                            elif vulnerabilities_net_ipv6[code][net_id] == 2:
                                symbol = f"{WHITE}N/A{END}"
                        row.append(symbol)
                    table_data_net_ipv6.append(row)
                headers_net_ipv6 = ['Vulnerability'] + [f'{id}' for id in net_ids_ipv6]
                table_net_ipv6 = tabulate(table_data_net_ipv6, headers=headers_net_ipv6, tablefmt='grid', stralign='center')
                ptprinthelper.ptprint(table_net_ipv6)
                print_network_stats(vulnerabilities_net_ipv6, net_ids_ipv6, sorted_codes_net_ipv6, "6")

    @staticmethod
    def output_general(mode: str, addresses_file_name: str = f"{file_path}addresses.csv"):
        """
        Output general device and network information, including vulnerabilities.

        Args:
            mode (str): Scan mode.
            addresses_file_name (str): Path to addresses CSV file.
        """
        if has_additional_data(addresses_file_name) and has_additional_data(f"{file_path}role_node.csv"):
            role_node_df = pd.read_csv(f"{file_path}role_node.csv")
            addresses_df = pd.read_csv(addresses_file_name)
            try:
                vuln_df = pd.read_csv(f"{file_path}vulnerability.csv")
                net_vulns = vuln_df[vuln_df['ID'] == "Network"]
                for _, vuln_row in net_vulns.iterrows():
                    code = vuln_row.get('Code', '')
                    desc = vuln_row.get('Description', '')
                    label = vuln_row.get('Label', '')
                    if label == 1 and (mode in vuln_row['Mode']):
                        ptprinthelper.ptprint(f"{code}: {desc}", "VULN", colortext=True)
            except Exception:
                pass
            num_devices = len(role_node_df)
            ptprinthelper.ptprint(f"Number of devices found: {num_devices}", "OK")
            all_ip = addresses_df['IP'].to_list()
            for index, row in role_node_df.iterrows():
                mac_address = row['MAC']
                device_number = row['Device_Number']
                role = row['Role']
                ptprinthelper.ptprint(f"Device number {device_number}: ({Non_json.transform_role_print(role)} - {lookup_vendor_from_csv(mac_address)})", "INFO")
                ptprinthelper.ptprint(f"    MAC   {mac_address}")
                ip_addresses = addresses_df.loc[addresses_df['MAC'] == mac_address, 'IP'].tolist()
                list_solicited_ip = []
                for ip in ip_addresses:
                    if is_valid_ipv6(ip):
                        if is_link_local_ipv6(ip) or is_global_unicast_ipv6(ip) or is_ipv6_ula(ip):
                            list_solicited_ip.append(in6_getnsma(ip))
                if ip_addresses:
                    for ip in ip_addresses:
                        if is_valid_ipv6(ip):
                            if is_llsnm_ipv6(ip):
                                if ip not in list_solicited_ip:
                                    ptprinthelper.ptprint("    IPv6  " + in6_getansma(ip) + " (possible address)")
                            elif is_global_unicast_ipv6(ip) or is_link_local_ipv6(ip) or is_ipv6_ula(ip):
                                if all_ip.count(ip) >= 2:
                                    ptprinthelper.ptprint("    IPv6  " + ip + " (duplicated address, probably not owned)")
                                else:
                                    ptprinthelper.ptprint("    IPv6  " + ip)
                        else:
                            try:
                                ipv4_address = ipaddress.IPv4Address(ip)
                                if all_ip.count(ip) >= 2:
                                    ptprinthelper.ptprint("    IPv4  " + ip + " (duplicated address, probably not owned)")
                                else:
                                    ptprinthelper.ptprint("    IPv4  " + ip)
                            except ipaddress.AddressValueError:
                                continue
                else:
                    ptprinthelper.ptprint("    No IP addresses found for this device.")
                try:
                    vuln_df = pd.read_csv(f"{file_path}vulnerability.csv")
                    device_vulns = vuln_df[vuln_df['ID'] == str(device_number)]
                    for _, vuln_row in device_vulns.iterrows():
                        code = vuln_row.get('Code', '')
                        desc = vuln_row.get('Description', '')
                        label = vuln_row.get('Label', '')
                        if label == 1 and (mode in vuln_row['Mode']):
                            ptprinthelper.ptprint(f"    {code}: {desc}", "VULN", colortext=True)
                except Exception:
                    pass

    @staticmethod
    def output_protocol(
        interface,
        mode,
        protocol,
        file_name,
        less_detail=False
    ):
        """
        Output protocol-specific scan results.

        Args:
            interface: Network interface.
            mode (str): Scan mode.
            protocol (str): Protocol name.
            file_name (str): Path to protocol CSV file.
            less_detail (bool): If True, output less detail.
        """
        delete_middle_content_csv(f"{file_path}start_end_mode.csv")
        if protocol == "time":
            Non_json.print_box("Time running")
            if has_additional_data(f"{file_path}start_end_mode.csv"):
                df_time = pd.read_csv(f"{file_path}start_end_mode.csv")
                time_list = df_time['time'].tolist()
                ptprinthelper.ptprint(f"Scanning starts at:         {time_list[0]} (from the first mode if multiple modes inserted)", "INFO")
                ptprinthelper.ptprint(f"Scanning ends at:           {time_list[-1]}", "INFO")
            if has_additional_data(file_name):
                df_time = pd.read_csv(file_name)
                time_list = df_time['time'].tolist()
                ptprinthelper.ptprint(f"First packet captured at:   {time_list[0]} (from the first mode if multiple modes inserted)", "INFO")
                ptprinthelper.ptprint(f"Last packet captured at:    {time_list[-1]}", "INFO")
                ptprinthelper.ptprint(f"Number of packets captured: {len(time_list)} (counting from the first mode if multiple modes inserted)", "INFO")
        if protocol == "802.1x":
            Non_json.print_box("802.1x scan running")
            if has_additional_data(file_name):
                ptprinthelper.ptprint("802.1x is active", "INFO")
            else:
                ptprinthelper.ptprint("PTV-NET-NET-MISCONF-8021X: Network does not have 802.1x deployed", "VULN", colortext=True)
        if protocol in ["MDNS", "LLMNR", "MLDv1", "MLDv2", "IGMPv1/v2", "IGMPv3", "RA", "WS-Discovery"]:
            if has_additional_data(file_name) and has_additional_data(f"{file_path}role_node.csv"):
                if protocol == "MDNS" and not less_detail:
                    Non_json.print_box("MDNS scan")
                if protocol == "LLMNR" and not less_detail:
                    Non_json.print_box("LLMNR scan")
                if protocol == "MLDv1" and not less_detail:
                    Non_json.print_box("MLDv1 scan")
                if protocol == "MLDv2" and not less_detail:
                    Non_json.print_box("MLDv2 scan")
                if protocol == "IGMPv1/v2" and not less_detail:
                    Non_json.print_box("IGMPv1/v2 scan")
                if protocol == "IGMPv3" and not less_detail:
                    Non_json.print_box("IGMPv3 scan")
                if protocol == "RA" and not less_detail:
                    Non_json.print_box("Router scan")
                if protocol == "WS-Discovery" and not less_detail:
                    Non_json.print_box("WS-Discovery scan")
                try:
                    vuln_df = pd.read_csv(f"{file_path}vulnerability.csv")
                    if protocol in ["MDNS", "LLMNR"]:
                        network_vulns = vuln_df[(vuln_df['ID'] == "Network") & (vuln_df['Code'].str.contains(protocol, case=False, na=False))]
                    elif protocol in ["MLDv1", "MLDv2"]:
                        network_vulns = vuln_df[(vuln_df['ID'] == "Network") & (vuln_df['Description'].str.contains(protocol, case=False, na=False))]
                    else:
                        network_vulns = pd.DataFrame()
                    for _, vuln_row in network_vulns.iterrows():
                        code = vuln_row.get('Code', '')
                        desc = vuln_row.get('Description', '')
                        label = vuln_row.get('Label', '')
                        if label == 1 and (mode in vuln_row['Mode']):
                            ptprinthelper.ptprint(f"{code}: {desc}", "VULN", colortext=True)
                except Exception:
                    pass
                if protocol == "IGMPv1/v2":
                    ptprinthelper.ptprint("Vulnerable: IGMPv1/v2 is active", "VULN", colortext=True)
                if protocol == "WS-Discovery":
                    ptprinthelper.ptprint("Vulnerable: WS-Discovery is active", "VULN", colortext=True)
                if protocol == "RA" and is_dhcp_slaac() != []:
                    for item in is_dhcp_slaac():
                        ptprinthelper.ptprint(f"{item} is discovered", "INFO")
                df = pd.read_csv(file_name)
                list_mac_protocol = Non_json.get_unique_mac_addresses(file_name)
                unique_devices = df.groupby('MAC')['IP'].nunique()
                num_devices = unique_devices.count()
                ptprinthelper.ptprint(f"Number of devices found: {num_devices}", "OK")
                role_node_df = pd.read_csv(f"{file_path}role_node.csv")
                for index, row in role_node_df.iterrows():
                    mac_address = row['MAC']
                    device_number = row['Device_Number']
                    role = row['Role']
                    if (protocol == "RA" and role != "Host") or (protocol != "RA" and mac_address in list_mac_protocol):
                        ptprinthelper.ptprint(f"Device number {device_number}: ({Non_json.transform_role_print(role)} - {lookup_vendor_from_csv(mac_address)})", "INFO")
                        if not less_detail:
                            ptprinthelper.ptprint(f"    MAC   {mac_address}")
                            ip_addresses = df.loc[df['MAC'] == mac_address, 'IP'].tolist()
                            if protocol in ["MDNS", "LLMNR"]:
                                try:
                                    local_name_df = pd.read_csv(f"{file_path}localname.csv")
                                    list_local_names = local_name_df.loc[local_name_df['MAC'] == mac_address, 'name'].tolist()
                                    ptprinthelper.ptprint(f"    Local name   {list_local_names[0]}")
                                except:
                                    pass
                            if protocol in ["MLDv1", "IGMPv1/v2"]:
                                filtered_rows = df[df['MAC'] == mac_address]
                                other_info_list = filtered_rows[['protocol', 'mulip']].values.tolist()
                            if protocol in ["MLDv2", "IGMPv3"]:
                                filtered_rows = df[df['MAC'] == mac_address]
                                other_info_list = filtered_rows[['protocol', 'rtype', 'mulip', 'sources']].values.tolist()
                            if protocol == "RA":
                                filtered_rows = df[df['MAC'] == mac_address]
                                other_info_list = filtered_rows[['M', 'O', 'H', 'A', 'L', 'Preference', 'Router_lft', 'Reachable_time', 'Retrans_time', 'DNS', 'MTU', 'Prefix', 'Valid_lft', 'Preferred_lft']].values.tolist()
                            if ip_addresses:
                                i = 0
                                ip_previous = 0
                                for ip in ip_addresses:
                                    if ip_previous != ip:
                                        if is_valid_ipv6(ip):
                                            if is_global_unicast_ipv6(ip) or is_link_local_ipv6(ip) or is_ipv6_ula(ip):
                                                ptprinthelper.ptprint("    IPv6  " + ip)
                                        else:
                                            try:
                                                ipv4_address = ipaddress.IPv4Address(ip)
                                                ptprinthelper.ptprint("    IPv4  " + ip)
                                            except ipaddress.AddressValueError:
                                                continue
                                    ip_previous = ip
                                    if protocol in ["MLDv1", "IGMPv1/v2"]:
                                        ptprinthelper.ptprint("    " + other_info_list[i][0] + " with group: " + other_info_list[i][1])
                                        i += 1
                                    if protocol in ["MLDv2", "IGMPv3"]:
                                        ptprinthelper.ptprint("    " + other_info_list[i][0] + " with group: " +
                                                            other_info_list[i][1] + " and sources: " +
                                                            other_info_list[i][2])
                                        i += 1
                                    if protocol == "RA":
                                        ptprinthelper.ptprint("    Flag  " + "M-" + other_info_list[i][0] + ", O-" + other_info_list[i][1] +
                                                            ", H-" + other_info_list[i][2] + ", A-" + other_info_list[i][3] +
                                                            ", L-" + other_info_list[i][4] + ", Preference-" + other_info_list[i][5])
                                        ptprinthelper.ptprint(f"    Router lifetime: {other_info_list[i][6]}s, Reachable time: {other_info_list[i][7]}ms, Retransmission time: {other_info_list[i][8]} ms")
                                        if other_info_list[i][11] != "[]":
                                            ptprinthelper.ptprint("    Prefix: " + other_info_list[i][11])
                                        if other_info_list[i][13] != "[]" and other_info_list[i][12] != "[]":
                                            ptprinthelper.ptprint(f"    Preferred lifetime: {other_info_list[i][13]}s, Valid lifetime: {other_info_list[i][12]}s")
                                        ptprinthelper.ptprint(f"    MTU: {other_info_list[i][10]}, DNS: {other_info_list[i][9]}")
                                        i += 1
                    if protocol != "RA":
                        try:
                            vuln_df = pd.read_csv(f"{file_path}vulnerability.csv")
                            device_vulns = vuln_df[
                                (vuln_df['ID'] == str(device_number)) &
                                (vuln_df['Description'].str.contains(protocol, case=True, na=False)) &
                                (vuln_df['MAC'].isin(df['MAC']))
                            ]
                            for _, vuln_row in device_vulns.iterrows():
                                code = vuln_row.get('Code', '')
                                desc = vuln_row.get('Description', '')
                                label = vuln_row.get('Label', '')
                                if label == 1 and (mode in vuln_row['Mode']):
                                    ptprinthelper.ptprint(f"    {code}: {desc}", "VULN", colortext=True)
                        except Exception:
                            pass