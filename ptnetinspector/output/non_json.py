"""Human-readable terminal output helpers for ptnetinspector.

Provides functions to print scan summaries and protocol-specific details in a
consistent, readable format using the accumulated CSV data.
"""
import csv
import ipaddress
import pandas as pd
from tabulate import tabulate
from ptlibs import ptprinthelper
from ptnetinspector.send.send import IPMode
from ptnetinspector.utils.path import get_csv_path
from ptnetinspector.utils.csv_helpers import delete_middle_content_csv
from ptnetinspector.utils.output_helpers import filter_ips_by_mode, transform_role_print, extract_short_code
from ptnetinspector.utils.ip_utils import (
    has_additional_data, is_global_unicast_ipv6, is_ipv6_ula, is_link_local_ipv6,
    is_valid_ipv6, is_llsnm_ipv6, is_dhcp_slaac
)
from ptnetinspector.utils.ip_utils import in6_getansma, in6_getnsma
from ptnetinspector.utils.oui import lookup_vendor_from_csv
from ptnetinspector.utils.vuln_catalog import load_vuln_catalog_by_test, load_vuln_catalog


class Non_json:
    @staticmethod
    def print_box(string: str):
        """
        Print a highlighted heading without box characters.

        Args:
            string (str): The string to print.
        """
        ORANGE_BOLD = "\033[1;38;5;208m"
        END = "\033[0m"

        # Indent and bold the heading to stand out in place of the old boxed style
        ptprinthelper.ptprint(f"{ORANGE_BOLD}[*] {string}{END}")

    @staticmethod
    def format_bullet(text: str, indent: int = 2, bullet: str = "-") -> str:
        """Return a consistently indented bullet line for terminal output."""
        return f"{' ' * indent}{bullet} {text}"

    @staticmethod
    def indent_line(text: str, indent: int = 5) -> str:
        """Return text with leading spaces to visually nest ptprinthelper prefixes."""
        return f"{' ' * indent}{text}"

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
        csv_file_path: str = None,
        target_codes: set[str] | None = None,
        target_macs: set[str] | None = None,
    ):
        """
        Read vulnerability CSV file and create individual tables for each vulnerability,
        showing device/network status with descriptions instead of codes.

        Args:
            mode (str): Scan mode.
            ipver (IPMode): IP version object.
            csv_file_path (str): Path to vulnerability CSV file.
            target_codes (set[str] | None): Optional Test codes to filter by (e.g., {'4-MDNS', '6-MLDV1'}).
            target_macs (set[str] | None): Optional target MAC addresses to filter devices.
        """
        if csv_file_path is None:
            csv_file_path = get_csv_path("vulnerability.csv")

        # Load vulnerability catalog for descriptions
        try:
            vuln_catalog = load_vuln_catalog()
        except Exception:
            vuln_catalog = {}

        # Convert Test codes to vulnerability Codes
        target_codes_set = None
        if target_codes:
            try:
                test_catalog = load_vuln_catalog_by_test()
                vuln_codes = set()
                for test_code in target_codes:
                    test_code_upper = test_code.upper()
                    if test_code_upper in test_catalog:
                        for entry in test_catalog[test_code_upper]:
                            vuln_codes.add(entry["Code"].upper())
                target_codes_set = vuln_codes if vuln_codes else None
            except Exception:
                # If catalog load fails, treat as no filter
                target_codes_set = None
        
        # Structure: {code: {description: str, ipver: str, entities: {entity_id: label}}}
        vulnerabilities = {}
        
        # Prepare target MACs set (uppercase)
        target_macs_set = {mac.upper() for mac in target_macs} if target_macs else None
        
        # Collect device vulnerability codes for network correlation (when target MACs specified)
        target_device_vuln_codes = set()

        with open(csv_file_path, 'r', newline='', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                if mode in row['Mode']:
                    code = row.get('Code', '').strip().upper()
                    if target_codes_set and code not in target_codes_set:
                        continue
                    
                    # Filter by target MACs if specified (skip non-target devices)
                    entity_id = row['ID']
                    if target_macs_set and entity_id != 'Network':
                        mac = row.get('MAC', '').strip().upper()
                        if mac not in target_macs_set:
                            continue
                        # Collect device vulnerability codes for network correlation
                        if code.endswith('DEV'):
                            net_code = code[:-3]  # Remove 'DEV' suffix
                            target_device_vuln_codes.add(net_code)
                        target_device_vuln_codes.add(code)
                    
                    # Do not filter out network vulnerabilities when target MACs are specified
                    
                    ipver_value = row.get('IPver', '').strip()
                    description = row.get('Description', code)
                    label = int(row['Label'])
                    
                    # Check if this vulnerability applies to selected IP versions (handles -4, -6, or both)
                    allowed_versions = set()
                    if ipver.ipv4:
                        allowed_versions.add('4')
                    if ipver.ipv6:
                        allowed_versions.add('6')
                    # Always include 'both'
                    allowed_versions.add('both')
                    # If neither is explicitly selected, default to allowing all
                    if not (ipver.ipv4 or ipver.ipv6):
                        allowed_versions.update({'4', '6'})
                    if ipver_value not in allowed_versions:
                        continue
                    
                    if code not in vulnerabilities:
                        # Get description from catalog if available
                        catalog_desc = vuln_catalog.get(code, {}).get('Description', description)
                        vulnerabilities[code] = {
                            'description': catalog_desc,
                            'ipver': ipver_value,
                            'entities': {}
                        }
                    
                    vulnerabilities[code]['entities'][entity_id] = label

        GREEN = '\033[92m'
        RED = '\033[91m'
        WHITE = '\033[97m'
        END = '\033[0m'

        def get_status_symbol(label):
            """Return colored symbol based on label value."""
            if mode in ['802.1x']:
                return f"{WHITE}●{END}"
            if label == 1:
                return f"{RED}✕{END}"
            elif label == 0:
                return f"{GREEN}✓{END}"
            elif label == 2:
                return f"{WHITE}●{END}"
            return f"{WHITE}●{END}"

        # Sort vulnerabilities by code for consistent ordering
        sorted_codes = sorted(vulnerabilities.keys())
        
        if not sorted_codes:
            return  # No vulnerabilities to display
        
        # Print header
        Non_json.print_box("Vulnerability Analysis")
        ptprinthelper.ptprint(f"Legend: {RED}✕{END} = Vulnerable | {GREEN}✓{END} = Not Vulnerable | {WHITE}●{END} = N/A", condition=True, indent=4)
        ptprinthelper.ptprint("")  # Empty line for readability
        
        # Print each vulnerability as a separate table
        for idx, code in enumerate(sorted_codes, 1):
            vuln_data = vulnerabilities[code]
            description = vuln_data['description']
            
            # Print vulnerability header with yellow order indicator
            YELLOW = '\033[93m'
            END = '\033[0m'
            order_text = f"[{idx}/{len(sorted_codes)}]"
            ptprinthelper.ptprint(f"\n    {YELLOW}{order_text}{END} {description}", condition=True, indent=4)
            ptprinthelper.ptprint(f"    ({code})", condition=True, indent=4)
            
            # Separate entities into devices and network
            devices = {}
            network_status = None
            
            for entity_id, label in vuln_data['entities'].items():
                if entity_id == 'Network':
                    network_status = label
                else:
                    devices[entity_id] = label
            
            # Build table data with each entity as separate column
            headers = []
            table_row = []
            
            # Add Network column if present
            if network_status is not None:
                headers.append('Network')
                table_row.append(get_status_symbol(network_status))
            
            # Add Device columns
            if devices:
                sorted_device_ids = sorted(devices.keys(), key=lambda x: int(x) if x.isdigit() else x)
                for device_id in sorted_device_ids:
                    headers.append(f'Device {device_id}')
                    table_row.append(get_status_symbol(devices[device_id]))
            
            # Build table data with single row
            table_data = []
            if table_row:
                table_data.append(table_row)
            
            # Print table
            if table_data:
                table = tabulate(table_data, headers=headers, tablefmt='grid', colalign=('center',) * len(headers))
                # Indent each line of the table
                for line in table.split('\n'):
                    ptprinthelper.ptprint(line, condition=True, indent=8)
            else:
                ptprinthelper.ptprint("No entities tested for this vulnerability.", condition=True, indent=8)
        
        # Print summary statistics
        # ptprinthelper.ptprint("\n")
        Non_json.print_box("Vulnerability Summary")
        
        # Aggregate counts by entity and status
        network_vuln_count = 0
        network_not_vuln_count = 0
        network_na_count = 0
        device_vuln_counts = {}  # {device_id: {vuln: count, not_vuln: count, na: count}}
        
        for code in sorted_codes:
            vuln_data = vulnerabilities[code]
            
            for entity_id, label in vuln_data['entities'].items():
                if entity_id == 'Network':
                    if label == 1:
                        network_vuln_count += 1
                    elif label == 0:
                        network_not_vuln_count += 1
                    else:
                        network_na_count += 1
                else:
                    if entity_id not in device_vuln_counts:
                        device_vuln_counts[entity_id] = {'vuln': 0, 'not_vuln': 0, 'na': 0}
                    
                    if label == 1:
                        device_vuln_counts[entity_id]['vuln'] += 1
                    elif label == 0:
                        device_vuln_counts[entity_id]['not_vuln'] += 1
                    else:
                        device_vuln_counts[entity_id]['na'] += 1
        
        # Build summary table data
        summary_table_data = []
        
        # Add Network row
        if network_vuln_count > 0 or network_not_vuln_count > 0 or network_na_count > 0:
            summary_table_data.append([
                'Network',
                f'{RED}{network_vuln_count}{END}',
                f'{GREEN}{network_not_vuln_count}{END}',
                f'{WHITE}{network_na_count}{END}'
            ])
        
        # Add Device rows
        sorted_device_ids = sorted(device_vuln_counts.keys(), key=lambda x: int(x) if x.isdigit() else x)
        for device_id in sorted_device_ids:
            counts = device_vuln_counts[device_id]
            summary_table_data.append([
                f'Device {device_id}',
                f'{RED}{counts["vuln"]}{END}',
                f'{GREEN}{counts["not_vuln"]}{END}',
                f'{WHITE}{counts["na"]}{END}'
            ])
        
        # Print summary table
        if summary_table_data:
            headers = ['Entity', f'{RED}Vulnerable{END}', f'{GREEN}Not Vulnerable{END}', f'{WHITE}N/A{END}']
            table = tabulate(summary_table_data, headers=headers, tablefmt='grid', colalign=('left', 'center', 'center', 'center'))
            # Indent each line of the summary table
            for line in table.split('\n'):
                ptprinthelper.ptprint(line, condition=True, indent=4)

    @staticmethod
    def output_general(mode: str, ipver: IPMode, addresses_file_name: str = None, target_codes: set[str] | None = None, target_macs: set[str] | None = None):
        """
        Output general device and network information, including vulnerabilities.

        Args:
            mode (str): Scan mode.
            ipver (IPMode): Enabled IP versions.
            addresses_file_name (str): Path to addresses CSV file.
            target_codes (set[str] | None): Optional filter for vulnerability codes.
            target_macs (set[str] | None): Optional filter for target MAC addresses.
        """
        if addresses_file_name is None:
            addresses_file_name = get_csv_path("addresses.csv")
        
        role_node_file = get_csv_path("role_node.csv")
        vulnerability_file = get_csv_path("vulnerability.csv")
        target_codes_set = {code.upper() for code in target_codes} if target_codes else None
        target_macs_set = {mac.upper() for mac in target_macs} if target_macs else None
        
        
        if has_additional_data(addresses_file_name) and has_additional_data(role_node_file):
            role_node_df_full = pd.read_csv(role_node_file)
            role_node_df = role_node_df_full.copy()
            addresses_df = pd.read_csv(addresses_file_name)
            addresses_df = filter_ips_by_mode(addresses_df, ipver)
            
            # Filter by target MACs if specified - apply to BOTH addresses and role_node DataFrames
            if target_macs_set:
                addresses_df = addresses_df[addresses_df['MAC'].str.upper().isin(target_macs_set)]
                role_node_df = role_node_df[role_node_df['MAC'].str.upper().isin(target_macs_set)]
            
            # Network and device vulnerability testing section
            try:
                vuln_df = pd.read_csv(vulnerability_file)
                
                # Convert Test codes to vulnerability Codes if target_codes_set is provided
                target_vuln_codes_set = None
                if target_codes_set:
                    try:
                        test_catalog = load_vuln_catalog_by_test()
                        vuln_codes = set()
                        for test_code in target_codes_set:
                            test_code_upper = test_code.upper()
                            if test_code_upper in test_catalog:
                                for entry in test_catalog[test_code_upper]:
                                    vuln_codes.add(entry["Code"].upper())
                        target_vuln_codes_set = vuln_codes if vuln_codes else None
                    except Exception:
                        target_vuln_codes_set = None
                
                # Collect ALL vulnerabilities (network + device) to determine overall test status
                all_vuln_results = []
                
                # Process network vulnerabilities
                net_vulns = vuln_df[vuln_df['ID'] == "Network"]
                
                # If target MACs specified, collect device vulnerabilities to correlate with network vulns
                target_device_vuln_codes = set()
                if target_macs_set:
                    device_vulns = vuln_df[vuln_df['MAC'].str.upper().isin(target_macs_set)]
                    for _, dev_vuln_row in device_vulns.iterrows():
                        dev_code = dev_vuln_row.get('Code', '').strip().upper()
                        # Map device vuln code to its network counterpart (e.g., MLDV1DEV -> MLDV1)
                        if dev_code.endswith('DEV'):
                            net_code = dev_code[:-3]  # Remove 'DEV' suffix
                            target_device_vuln_codes.add(net_code)
                        target_device_vuln_codes.add(dev_code)
                
                # Collect network vulnerabilities matching criteria
                network_vuln_results = []
                for _, vuln_row in net_vulns.iterrows():
                    code = vuln_row.get('Code', '')
                    if target_vuln_codes_set and code.strip().upper() not in target_vuln_codes_set:
                        continue
                    # No filtering by target device vulns: always show all network vulns
                    desc = vuln_row.get('Description', '')
                    label = vuln_row.get('Label', '')
                    short_code = extract_short_code(code)
                    if mode in vuln_row['Mode']:
                        network_vuln_results.append((desc, short_code, label, code))
                        all_vuln_results.append(label)
                
                # Collect device vulnerabilities matching criteria for overall test status
                if target_vuln_codes_set:
                    # Filter device vulnerabilities based on target_vuln_codes and target_macs
                    for _, vuln_row in vuln_df.iterrows():
                        if vuln_row['ID'] == "Network":
                            continue
                        code = vuln_row.get('Code', '')
                        if code.strip().upper() not in target_vuln_codes_set:
                            continue
                        # If target MACs specified, filter by MAC
                        if target_macs_set:
                            mac = vuln_row.get('MAC', '').strip().upper()
                            if mac not in target_macs_set:
                                continue
                        label = vuln_row.get('Label', '')
                        if mode in vuln_row.get('Mode', ''):
                            all_vuln_results.append(label)
                
                # Print overall test summary
                if all_vuln_results:
                    has_any_vuln = any(label == 1 for label in all_vuln_results)
                    if target_codes_set:
                        # -ts mode: show test codes
                        test_codes_display = ', '.join(sorted(target_codes_set))
                        if has_any_vuln:
                            ptprinthelper.ptprint(f"There is security problem(s) found from the Test ({test_codes_display})", "ERROR", colortext=True, condition=True, indent=4)
                        else:
                            ptprinthelper.ptprint(f"No security problem(s) found from the Test ({test_codes_display})", "OK", colortext=True, condition=True, indent=4)
                    else:
                        # No -ts: generic message
                        if has_any_vuln:
                            ptprinthelper.ptprint("Security problem(s) found", "ERROR", colortext=True, condition=True, indent=4)
                        else:
                            ptprinthelper.ptprint("No security problem(s) found", "OK", colortext=True, condition=True, indent=4)
                
                # Print network vulnerabilities if any exist
                if network_vuln_results:
                    all_na = all(label not in (0, 1) for _, _, label, _ in network_vuln_results)
                    header_text = "Network vulnerability test results:" if not all_na else "Network vulnerability test results: N/A"
                    ptprinthelper.ptprint(header_text, "INFO", condition=True, indent=4)
                    
                    # Print individual network vulnerability results
                    for desc, short_code, label, code in network_vuln_results:
                        if label == 1:
                            ptprinthelper.ptprint(f"{desc} (...{short_code})", "VULN", colortext=True, condition=True, indent=8)
                        elif label == 0:
                            ptprinthelper.ptprint(f"{desc} (...{short_code})", "OK", colortext=True, condition=True, indent=8)
            except Exception:
                pass
            
            if target_macs_set:
                resolved_targets = []
                missing_targets = []
                for mac in sorted(target_macs_set):
                    display_mac = mac.lower()
                    matches = role_node_df_full[role_node_df_full['MAC'].str.upper() == mac]
                    if matches.empty:
                        missing_targets.append(display_mac)
                        continue
                    device_numbers = sorted(matches['Device_Number'].tolist(), key=lambda x: int(x) if str(x).isdigit() else str(x))
                    resolved_targets.append(f"{display_mac} -> Device {', '.join(map(str, device_numbers))}")
                if resolved_targets:
                    ptprinthelper.ptprint("Targets matched to devices:", "INFO", condition=True, indent=4)
                    for entry in resolved_targets:
                        ptprinthelper.ptprint(entry, "INFO", condition=True, indent=8)
                if missing_targets:
                    ptprinthelper.ptprint("Targets not present in results:", "INFO", condition=True, indent=4)
                    for mac in missing_targets:
                        ptprinthelper.ptprint(mac, "INFO", condition=True, indent=8)

            num_devices = len(role_node_df)
            ptprinthelper.ptprint(f"Number of devices: {num_devices}", "INFO", condition=True, indent=4)
            all_ip = addresses_df['IP'].to_list()
            for index, row in role_node_df.iterrows():
                mac_address = row['MAC']
                device_number = row['Device_Number']
                role = row['Role']
                ptprinthelper.ptprint(f"Device number {device_number}: ({transform_role_print(role)} - {lookup_vendor_from_csv(mac_address)})", "INFO", condition=True, indent=4)
                ptprinthelper.ptprint(f"MAC   {mac_address}", condition=True, indent=8)
                ip_addresses = addresses_df.loc[addresses_df['MAC'] == mac_address, 'IP'].tolist()
                list_solicited_ip = []
                if ipver.ipv6:
                    for ip in ip_addresses:
                        if is_valid_ipv6(ip):
                            if not is_llsnm_ipv6(ip):
                                list_solicited_ip.append(in6_getnsma(ip))
                if ip_addresses:
                    for ip in ip_addresses:
                        if ipver.ipv6 and is_valid_ipv6(ip):
                            if is_llsnm_ipv6(ip):
                                if ip not in list_solicited_ip:
                                    ptprinthelper.ptprint(f"IPv6  {in6_getansma(ip)} (possible address)", condition=True, indent=8)
                            elif not is_llsnm_ipv6(ip):
                                if all_ip.count(ip) >= 2:
                                    ptprinthelper.ptprint(f"IPv6  {ip} (duplicated address, probably not owned)", condition=True, indent=8)
                                else:
                                    ptprinthelper.ptprint(f"IPv6  {ip}", condition=True, indent=8)
                        elif ipver.ipv4:
                            try:
                                ipv4_address = ipaddress.IPv4Address(ip)
                                if all_ip.count(ip) >= 2:
                                    ptprinthelper.ptprint(f"IPv4  {ip} (duplicated address, probably not owned)", condition=True, indent=8)
                                else:
                                    ptprinthelper.ptprint(f"IPv4  {ip}", condition=True, indent=8)
                            except ipaddress.AddressValueError:
                                continue
                         

                vuln_df = pd.read_csv(vulnerability_file)
                device_vulns = vuln_df[vuln_df['ID'].astype(str) == str(device_number)]
                # Respect -ts filters for device vulnerabilities as well
                if target_vuln_codes_set:
                    device_vulns = device_vulns[device_vulns['Code'].str.upper().isin(target_vuln_codes_set)]
                for _, vuln_row in device_vulns.iterrows():
                    code = vuln_row.get('Code', '')
                    desc = vuln_row.get('Description', '')
                    ipver_vuln = vuln_row.get('IPver', '')
                    label = vuln_row.get('Label', '')
                    short_code = extract_short_code(code)
                    if mode in vuln_row.get('Mode', ''):
                        if label == 1:
                            ptprinthelper.ptprint(f"{desc} (...{short_code})", "VULN", colortext=True, condition=True, indent=8)
                        elif label == 0:
                            ptprinthelper.ptprint(f"{desc} (...{short_code})", "OK", colortext=True, condition=True, indent=8)

    @staticmethod
    def output_protocol(
        interface,
        ipver: IPMode,
        mode,
        protocol,
        file_name,
        less_detail=False,
        target_macs=None
    ):
        """Print human-readable results for a specific protocol.

        Args:
            interface: Network interface.
            ipver (IPMode): Enabled IP versions.
            mode (str): Scan mode.
            protocol (str): Protocol name (e.g., "MDNS", "LLMNR").
            file_name (str): Path to protocol CSV file.
            less_detail (bool): If True, show reduced details.
            target_macs (set[str] | None): Optional MAC filter.
        """
        start_end_file = get_csv_path("start_end_mode.csv")
        role_node_file = get_csv_path("role_node.csv")
        vulnerability_file = get_csv_path("vulnerability.csv")
        localname_file = get_csv_path("localname.csv")
        target_macs_set = {mac.upper() for mac in target_macs} if target_macs else None
        
        delete_middle_content_csv(start_end_file)
        if protocol == "time":
            Non_json.print_box("Time running")
            if has_additional_data(start_end_file):
                df_time = pd.read_csv(start_end_file)
                time_list = df_time['time'].tolist()
                ptprinthelper.ptprint(f"Scanning starts at:         {time_list[0]} (from the first mode if multiple modes inserted)", "INFO", condition=True, indent=4)
                ptprinthelper.ptprint(f"Scanning ends at:           {time_list[-1]}", "INFO", condition=True, indent=4)
            if has_additional_data(file_name):
                df_time = pd.read_csv(file_name)
                time_list = df_time['time'].tolist()
                ptprinthelper.ptprint(f"First packet captured at:   {time_list[0]} (from the first mode if multiple modes inserted)", "INFO", condition=True, indent=4)
                ptprinthelper.ptprint(f"Last packet captured at:    {time_list[-1]}", "INFO", condition=True, indent=4)
                ptprinthelper.ptprint(f"Number of packets captured: {len(time_list)} (counting from the first mode if multiple modes inserted)", "INFO", condition=True, indent=4)
        if protocol == "802.1x":
            Non_json.print_box("802.1x scan running")
            try:
                vuln_df = pd.read_csv(vulnerability_file)
                network_vulns = vuln_df[(vuln_df['ID'] == "Network") & (vuln_df['Code'].str.contains("PTV-NET-NET-MISCONF-8021X"))]
                for _, vuln_row in network_vulns.iterrows():
                    code = vuln_row.get('Code', '')
                    desc = vuln_row.get('Description', '')
                    label = vuln_row.get('Label', '')
                    short_code = extract_short_code(code)
                    if mode in vuln_row['Mode']:
                        if label == 1:
                            ptprinthelper.ptprint(f"{desc} (...{short_code})", "VULN", colortext=True, condition=True, indent=4)
                        elif label == 0:
                            ptprinthelper.ptprint(f"{desc} (...{short_code})", "OK", colortext=True, condition=True, indent=4)
            except Exception:
                pass
        if protocol in ["MDNS", "LLMNR", "MLDv1", "MLDv2", "IGMPv1/v2", "IGMPv3", "RA", "WS-Discovery"]:
            if has_additional_data(file_name) and has_additional_data(role_node_file):
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
                    vuln_df = pd.read_csv(vulnerability_file)
                    if protocol in ["MDNS", "LLMNR"]:
                        network_vulns = vuln_df[(vuln_df['ID'] == "Network") & (vuln_df['Code'].str.contains(protocol, case=False, na=False))]
                    elif protocol in ["MLDv1", "MLDv2", "WS-Discovery", "IGMPv1/v2", "IGMPv3"]:
                        network_vulns = vuln_df[(vuln_df['ID'] == "Network") & (vuln_df['Description'].str.contains(protocol, case=False, na=False))]
                    else:
                        network_vulns = pd.DataFrame()
                    
                    # If target MACs specified, collect device vulnerabilities to correlate with network vulns
                    target_device_vuln_codes = set()
                    if target_macs_set:
                        device_vulns = vuln_df[vuln_df['MAC'].str.upper().isin(target_macs_set)]
                        for _, dev_vuln_row in device_vulns.iterrows():
                            dev_code = dev_vuln_row.get('Code', '').strip().upper()
                            # Map device vuln code to its network counterpart (e.g., MLDV1DEV -> MLDV1)
                            if dev_code.endswith('DEV'):
                                net_code = dev_code[:-3]  # Remove 'DEV' suffix
                                target_device_vuln_codes.add(net_code)
                            target_device_vuln_codes.add(dev_code)
                    
                    for _, vuln_row in network_vulns.iterrows():
                        code = vuln_row.get('Code', '')
                        desc = vuln_row.get('Description', '')
                        ipver_vuln = vuln_row.get('IPver', '')
                        label = vuln_row.get('Label', '')
                        
                        # If target MACs specified, only show network vulns related to target device vulns
                        if target_macs_set:
                            code_upper = code.strip().upper()
                            # Check if this network vuln correlates with any target device vuln
                            if not any(code_upper in tcode or tcode in code_upper for tcode in target_device_vuln_codes):
                                continue
                        
                        short_code = extract_short_code(code)
                        if mode in vuln_row['Mode']:
                            if label == 1:
                                ptprinthelper.ptprint(f"{desc} (...{short_code})", "VULN", colortext=True, condition=True, indent=4)
                            elif label == 0:
                                ptprinthelper.ptprint(f"{desc} (...{short_code})", "OK", colortext=True, condition=True, indent=4)
                except Exception:
                    pass
                if protocol == "RA" and is_dhcp_slaac() != []:
                    for item in is_dhcp_slaac():
                        ptprinthelper.ptprint(f"{item} is discovered", "INFO", condition=True, indent=4)
                df = pd.read_csv(file_name)
                df = filter_ips_by_mode(df, ipver)
                
                # Filter by target MACs if specified
                if target_macs_set and 'MAC' in df.columns:
                    df = df[df['MAC'].str.upper().isin(target_macs_set)]
                
                list_mac_protocol = df['MAC'].drop_duplicates().tolist()
                unique_devices = df.groupby('MAC')['IP'].nunique()
                num_devices = unique_devices.count()
                ptprinthelper.ptprint(f"Number of devices: {num_devices}", "INFO", condition=True, indent=4)
                role_node_df = pd.read_csv(role_node_file)
                
                # Filter role_node by target MACs if specified
                if target_macs_set:
                    role_node_df = role_node_df[role_node_df['MAC'].str.upper().isin(target_macs_set)]
                for index, row in role_node_df.iterrows():
                    mac_address = row['MAC']
                    device_number = row['Device_Number']
                    role = row['Role']
                    if (protocol == "RA" and role != "Host") or (protocol != "RA" and mac_address in list_mac_protocol):
                        ptprinthelper.ptprint(f"Device number {device_number}: ({transform_role_print(role)} - {lookup_vendor_from_csv(mac_address)})", "INFO", condition=True, indent=4)
                        if not less_detail:
                            ptprinthelper.ptprint(f"MAC   {mac_address}", condition=True, indent=8)
                            ip_addresses = df.loc[df['MAC'] == mac_address, 'IP'].tolist()
                            if protocol in ["MDNS", "LLMNR"]:
                                try:
                                    local_name_df = pd.read_csv(localname_file)
                                    list_local_names = local_name_df.loc[local_name_df['MAC'] == mac_address, 'name'].tolist()
                                    ptprinthelper.ptprint(f"Local name   {list_local_names[0]}", condition=True, indent=8)
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
                                ip_previous = None
                                for idx, ip in enumerate(ip_addresses):
                                    if ip_previous != ip:
                                        if ipver.ipv6 and is_valid_ipv6(ip):
                                            if not is_llsnm_ipv6(ip):
                                                ptprinthelper.ptprint(f"IPv6  {ip}", condition=True, indent=8)
                                        elif ipver.ipv4:
                                            try:
                                                ipaddress.IPv4Address(ip)
                                                ptprinthelper.ptprint(f"IPv4  {ip}", condition=True, indent=8)
                                            except ipaddress.AddressValueError:
                                                ip_previous = ip
                                                continue
                                    ip_previous = ip
                                    if protocol in ["MLDv1", "IGMPv1/v2"]:
                                        ptprinthelper.ptprint(f"{other_info_list[idx][0]} with group: {other_info_list[idx][1]}", condition=True, indent=8)
                                    if protocol in ["MLDv2", "IGMPv3"]:
                                        ptprinthelper.ptprint(f"{other_info_list[idx][0]} with group: {other_info_list[idx][1]} and sources: {other_info_list[idx][2]}", condition=True, indent=8)
                                    if protocol == "RA":
                                        ptprinthelper.ptprint(f"Flag  M-{other_info_list[idx][0]}, O-{other_info_list[idx][1]}, H-{other_info_list[idx][2]}, A-{other_info_list[idx][3]}, L-{other_info_list[idx][4]}, Preference-{other_info_list[idx][5]}", condition=True, indent=8)
                                        ptprinthelper.ptprint(f"Router lifetime: {other_info_list[idx][6]}s, Reachable time: {other_info_list[idx][7]}ms, Retransmission time: {other_info_list[idx][8]} ms", condition=True, indent=8)
                                        if other_info_list[idx][11] != "[]":
                                            ptprinthelper.ptprint(f"Prefix: {other_info_list[idx][11]}", condition=True, indent=8)
                                        if other_info_list[idx][13] != "[]" and other_info_list[idx][12] != "[]":
                                            ptprinthelper.ptprint(f"Preferred lifetime: {other_info_list[idx][13]}s, Valid lifetime: {other_info_list[idx][12]}s", condition=True, indent=8)
                                        ptprinthelper.ptprint(f"MTU: {other_info_list[idx][10]}, DNS: {other_info_list[idx][9]}", condition=True, indent=8)
                    if protocol != "RA":
                        try:
                            vuln_df = pd.read_csv(vulnerability_file)
                            device_vulns = vuln_df[
                                (vuln_df['ID'] == str(device_number)) &
                                (vuln_df['Description'].str.contains(protocol, case=True, na=False)) &
                                (vuln_df['MAC'].isin(df['MAC']))
                            ]
                            for _, vuln_row in device_vulns.iterrows():
                                code = vuln_row.get('Code', '')
                                desc = vuln_row.get('Description', '')
                                ipver_vuln = vuln_row.get('IPver', '')
                                label = vuln_row.get('Label', '')
                                short_code = extract_short_code(code)
                                if mode in vuln_row['Mode']:
                                    if label == 1:
                                        ptprinthelper.ptprint(f"{desc} (...{short_code})", "VULN", colortext=True, condition=True, indent=8)
                                    elif label == 0:
                                        ptprinthelper.ptprint(f"{desc} (...{short_code})", "OK", colortext=True, condition=True, indent=8)
                        except Exception:
                            pass
