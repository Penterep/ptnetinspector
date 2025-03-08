import ipaddress
import pandas as pd
from src.create_csv import sort_csv_based_MAC, delete_middle_content_csv
from libs.check import has_additional_data, is_global_unicast_ipv6, is_ipv6_ula, is_link_local_ipv6, is_valid_ipv6, is_llsnm_ipv6, get_status_ip, is_dhcp_slaac
from ptlibs import ptprinthelper
from libs.convert import in6_getansma, in6_getnsma
from src.output.oui import lookup_vendor_from_csv

class Non_json:
    def print_box(string):
        box_char = '='
        print(box_char*(len(string)+4))
        print(box_char, string, box_char)
        print(box_char*(len(string)+4))

    def get_unique_mac_addresses(csv_file):
        # Read the CSV file into a DataFrame
        data = pd.read_csv(csv_file)
        
        # Extract the MAC addresses from the 'MAC' column
        mac_addresses = data['MAC']
        
        # Remove duplicates and convert to a list
        unique_mac_addresses = mac_addresses.drop_duplicates().tolist()
        
        return unique_mac_addresses

    def output_general(addresses_file_name="src/tmp/addresses.csv"):
        if has_additional_data(addresses_file_name) and has_additional_data("src/tmp/role_node.csv"):
            # Read the role_node.csv file
            role_node_df = pd.read_csv('src/tmp/role_node.csv')

            # Read the addresses.csv file
            addresses_df = pd.read_csv(addresses_file_name)

            # Check the vulnerability of PVLAN missing
            # Merge the dataframes on the 'MAC' column
            merged_df = pd.merge(role_node_df, addresses_df, on='MAC')

            # Check for devices with role 'Host' and link-local IPv6 addresses
            link_local_ipv6_prefix = 'fe80::'

            try:
                # Ensure the 'IP' column is of string type
                merged_df['IP'] = merged_df['IP'].fillna('').astype(str)

                # Filter the dataframe for the required condition
                host_with_link_local_ipv6 = merged_df[
                    (merged_df['Role'] == 'Host') &
                    (merged_df['IP'].str.startswith(link_local_ipv6_prefix))
                ]

                # Print error if such a device is found
                if not host_with_link_local_ipv6.empty:
                    ptprinthelper.ptprint("Vulnerable: PVLAN or similar configuration missing", "VULN", colortext=True)
            except Exception:
                pass

            # Count the number of devices found based on the number of rows in role_node.csv
            num_devices = len(role_node_df)  # Excluding header row

            ptprinthelper.ptprint(f"Number of devices found: {num_devices}", "OK")

            # Get the list of all IP addresses
            all_ip = addresses_df['IP'].to_list()

            # Iterate through each device in role_node.csv
            for index, row in role_node_df.iterrows():
                mac_address = row['MAC']
                device_number = row['Device_Number']
                role = row['Role']

                ptprinthelper.ptprint(f"Device number {device_number}: ({role} - {lookup_vendor_from_csv(mac_address)})", "INFO")
                ptprinthelper.ptprint(f"    MAC   {mac_address}")
                
                # Find IP addresses associated with this MAC address
                ip_addresses = addresses_df.loc[addresses_df['MAC'] == mac_address, 'IP'].tolist()
                
                # Converting several types of IPv6 addresses to solicited multicast for checking possible address
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
                
            
    
    def output_protocol(interface, protocol, file_name, mac_db, less_detail=False):
        # Printing the timestamp
        delete_middle_content_csv("src/tmp/start_end_mode.csv")
        if protocol == "time":
            Non_json.print_box("Time running")

            if has_additional_data("src/tmp/start_end_mode.csv"):
                df_time = pd.read_csv("src/tmp/start_end_mode.csv")
                time_list = df_time['time'].tolist()
                ptprinthelper.ptprint(f"Scanning starts at:         {time_list[0]} (from the first mode if multiple modes inserted)", "INFO")
                ptprinthelper.ptprint(f"Scanning ends at:           {time_list[len(time_list)-1]}", "INFO")

            if has_additional_data(file_name):       
                df_time = pd.read_csv(file_name)
                time_list = df_time['time'].tolist()
                ptprinthelper.ptprint(f"First packet captured at:   {time_list[0]} (from the first mode if multiple modes inserted)", "INFO")
                ptprinthelper.ptprint(f"Last packet captured at:    {time_list[len(time_list)-1]}", "INFO")
                ptprinthelper.ptprint(f"Number of packets captured: {len(time_list)} (counting from the first mode if multiple modes inserted)", "INFO")

        # Printing the EAP checking
        if protocol == "802.1x":
            Non_json.print_box("802.1x scan")
            if has_additional_data(file_name):
                ptprinthelper.ptprint("802.1x is active", "INFO")
            else:
                ptprinthelper.ptprint("Vulnerable: 802.1x is not active", "VULN", colortext=True)
                
        if protocol in ["mDNS", "LLMNR", "MLDv1", "MLDv2", "RA"]:
            if has_additional_data(file_name) and has_additional_data("src/tmp/role_node.csv"):
                if protocol == "mDNS":
                    if not less_detail:                
                        Non_json.print_box("mDNS scan")
                    ptprinthelper.ptprint("Vulnerable: mDNS is active", "VULN", colortext=True)
                if protocol == "LLMNR":
                    if not less_detail:
                        Non_json.print_box("LLMNR scan")
                    ptprinthelper.ptprint("Vulnerable: LLMNR is active", "VULN", colortext=True)
                if has_additional_data("src/tmp/localname.csv"):
                    local_name_df = pd.read_csv("src/tmp/localname.csv")
                if protocol == "MLDv1":
                    if not less_detail:
                        Non_json.print_box("MLDv1 scan")
                    ptprinthelper.ptprint("Vulnerable: MLDv1 is active", "VULN", colortext=True)
                
                if protocol == "MLDv2" and not less_detail:
                    Non_json.print_box("MLDv2 scan")
                if protocol == "RA" and not less_detail:
                    Non_json.print_box("Router scan")
                    if is_dhcp_slaac() != []:
                        for item in is_dhcp_slaac():
                            ptprinthelper.ptprint(f"{item} is discovered", "INFO")
            
                # Read the CSV file
                sort_csv_based_MAC(interface, file_name)
                df = pd.read_csv(file_name)

                list_mac_protocol = Non_json.get_unique_mac_addresses(file_name)

                # Group by MAC address and count unique IP addresses for each MAC
                unique_devices = df.groupby('MAC')['IP'].nunique()

                # Count the number of unique MAC addresses
                num_devices = unique_devices.count()

                ptprinthelper.ptprint(f"Number of devices found: {num_devices}", "OK")

                # Iterate through each device in role_node.csv
                # Read the role_node.csv file
                role_node_df = pd.read_csv('src/tmp/role_node.csv')
                for index, row in role_node_df.iterrows():
                    mac_address = row['MAC']
                    device_number = row['Device_Number']
                    role = row['Role']
                    
                    # Need to skip the situation of Host when printing router scan, and situation when device in role_node but not in specified file name
                    if (protocol == "RA" and role != "Host") or (protocol != "RA" and mac_address in list_mac_protocol):
                        ptprinthelper.ptprint(f"Device number {device_number}: ({role} - {lookup_vendor_from_csv(mac_address)})", "INFO")

                        if less_detail:
                            continue

                        ptprinthelper.ptprint(f"    MAC   {mac_address}")
                    
                        # Find IP addresses associated with this MAC address
                        ip_addresses = df.loc[df['MAC'] == mac_address, 'IP'].tolist()

                        # Getting the local name from mDNS or LLMNR
                        if protocol == "mDNS" or protocol == "LLMNR":
                            # Using try to avoid the case when we have IP but do not have the local name
                            try:
                                list_local_names = local_name_df.loc[local_name_df['MAC'] == mac_address, 'name'].tolist()
                                ptprinthelper.ptprint(f"    Local name   {list_local_names[0]}")
                            except:
                                pass
                        
                        # Getting other information for printing the rest
                        if protocol == "MLDv1":
                            # Filter rows for the specific MAC address
                            filtered_rows = df[df['MAC'] == mac_address]
                            # Create a list of lists containing values
                            other_info_list = filtered_rows[['protocol', 'mulip']].values.tolist()
                        
                        if protocol == "MLDv2":                   
                            # Filter rows for the specific MAC address
                            filtered_rows = df[df['MAC'] == mac_address]
                            # Create a list of lists containing values
                            other_info_list = filtered_rows[['protocol', 'rtype', 'mulip', 'sources']].values.tolist()
                        
                        if protocol == "RA":        
                            # Filter rows for the specific MAC address
                            filtered_rows = df[df['MAC'] == mac_address]
                            # Create a list of lists containing values
                            other_info_list = filtered_rows[['M', 'O', 'H', 'A', 'L', 'Preference', 'Router_lft', 'Reachable_time', 'Retrans_time', 'DNS', 'MTU', 'Prefix', 'Valid_lft', 'Preferred_lft']].values.tolist()

                        # Printing addresses
                        if ip_addresses:
                            i = 0
                            ip_previous = 0
                            for ip in ip_addresses:
                                # Avoiding looping IP, this happens when one IP maps to many different attributes
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

                                if protocol == "MLDv1":
                                    ptprinthelper.ptprint("    " + other_info_list[i][0] + " with group: " + other_info_list[i][1])
                                    i += 1
                                
                                if protocol == "MLDv2":
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

                
 













            






        


                

    