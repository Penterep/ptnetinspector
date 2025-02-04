import ipaddress
import pandas as pd
from src.sniff import Sniff
from src.create_csv import delete_middle_content_csv
from libs.check import has_additional_data, is_global_unicast_ipv6, is_ipv6_ula, is_link_local_ipv6, is_valid_ipv6, is_llsnm_ipv6, get_status_ip, is_dhcp_slaac
from libs.convert import in6_getansma, in6_getnsma
from src.output.oui import get_vendor

# Creating an instance of the PtJsonLib class
from src.parameters import ptjsonlib_object

class Json:
    def output_property():
        if has_additional_data("src/tmp/RA.csv"):
            df = pd.read_csv("src/tmp/RA.csv")
            list_prefix = df['Prefix'].unique().tolist()
            list_dns = df['DNS'].unique().tolist()
            list_mtu = df['MTU'].unique().tolist()

            for prefix in list_prefix:
                if prefix != "[]":
                    ptjsonlib_object.add_properties(properties={"IPv6 prefix": prefix})
            
            for dns in list_dns:
                if dns != "[]":
                    ptjsonlib_object.add_properties(properties={"DNS server": dns})
                   
        if is_dhcp_slaac() != []:
            for item in is_dhcp_slaac():
                ptjsonlib_object.add_properties(properties={"Address configuration method discovered": item})
                       
        ptjsonlib_object.get_result_json()

    def output_vul_net(interface, mode=None, prefix_len=None, network=None, duration_aggressive=None):
        if has_additional_data("src/tmp/addresses.csv") and has_additional_data("src/tmp/role_node.csv"):
            # Read the role_node.csv file
            role_node_df = pd.read_csv('src/tmp/role_node.csv')

            # Read the addresses.csv file
            addresses_df = pd.read_csv('src/tmp/addresses.csv')

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
                    if any(v['vulnCode'] == 'PVLAN' for v in ptjsonlib_object.json_object['results']['vulnerabilities']):
                        pass
                    else:
                        ptjsonlib_object.add_vulnerability(vuln_code="PVLAN", description="PVLAN or similar configuration missing")
            except Exception:
                pass
        
            # ptjsonlib_object.get_result_json()
        
        if prefix_len is not None and network is not None and duration_aggressive is not None:
            if Sniff.detect_RA_guard_missing(interface, prefix_len, network, duration_aggressive):
                if any(v['vulnCode'] == 'RA guard' for v in ptjsonlib_object.json_object['results']['vulnerabilities']):
                    pass
                else:
                    ptjsonlib_object.add_vulnerability(vuln_code="RA guard", description="RA guard missing or misconfigured")

        if not has_additional_data("src/tmp/eap.csv") and "802.1x" in mode:
            if not ptjsonlib_object.vuln_code_in_vulnerabilities("802.1x"):
                if any(v['vulnCode'] == '802.1x' for v in ptjsonlib_object.json_object['results']['vulnerabilities']):
                    pass
                else:
                    ptjsonlib_object.add_vulnerability(vuln_code="802.1x", description="802.1x is not enabled")     

        # ptjsonlib_object.json_object["results"]["vulnerabilities"] = list(dict.fromkeys(ptjsonlib_object.json_object["results"]["vulnerabilities"]))  
        
        ptjsonlib_object.get_result_json()


    def output_object(interface, mode, mac_db, prefix_len=None, network=None, duration_aggressive=None, extract_to_json=True):
        
        delete_middle_content_csv("src/tmp/start_end_mode.csv")
        # Generate information to property
        Json.output_property()

        # Generate information to vulnearabilities
        Json.output_vul_net(interface, mode, prefix_len, network, duration_aggressive)

        if not extract_to_json:
            return

        # Generate information to node
        if has_additional_data("src/tmp/addresses.csv") and has_additional_data("src/tmp/role_node.csv"):

            # Read the role_node.csv file
            role_node_df = pd.read_csv('src/tmp/role_node.csv')

            # Read the addresses.csv file
            addresses_df = pd.read_csv('src/tmp/addresses.csv')

            # Reading all csv files containing protocols
            if has_additional_data("src/tmp/mDNS.csv"):
                mdns_df = pd.read_csv('src/tmp/mDNS.csv')
            else:
                mdns_df = None
            
            if has_additional_data("src/tmp/LLMNR.csv"):
                llmnr_df = pd.read_csv('src/tmp/LLMNR.csv')
            else:
                llmnr_df = None
            
            if has_additional_data("src/tmp/MLDv1.csv"):
                mldv1_df = pd.read_csv('src/tmp/MLDv1.csv')
            else:
                mldv1_df = None

            # Count the number of devices found based on the number of rows in role_node.csv
            num_devices = len(role_node_df)  # Excluding header row

            # Get the list of all IP addresses
            all_ip = addresses_df['IP'].to_list()

            # Iterate through each device in role_node.csv
            for index, row in role_node_df.iterrows():
                mac_address = row['MAC']
                device_number = row['Device_Number']
                role = row['Role']
                vul = []

                # Check the vulnearbility related to mDNS
                if mdns_df is not None:
                    mdns_entry = mdns_df[mdns_df['MAC'] == mac_address]
                    if not mdns_entry.empty:
                        # If the MAC address exists, check if there is an associated IP
                        if 'IP' in mdns_entry.columns and not mdns_entry['IP'].isnull().all():
                            vul.append("mDNS is active")
                
                # Check the vulnearbility related to LLMNR
                if llmnr_df is not None:
                    llmnr_entry = llmnr_df[llmnr_df['MAC'] == mac_address]
                    if not llmnr_entry.empty:
                        # If the MAC address exists, check if there is an associated IP
                        if 'IP' in llmnr_entry.columns and not llmnr_entry['IP'].isnull().all():
                            vul.append("LLMNR is active")
                
                # Check the vulnearbility related to MLDv1
                if mldv1_df is not None:
                    mldv1_entry = mldv1_df[mldv1_df['MAC'] == mac_address]
                    if not mldv1_entry.empty:
                        # If the MAC address exists, check if there is an associated IP
                        if 'IP' in mldv1_entry.columns and not mldv1_entry['IP'].isnull().all():
                            vul.append("MLDv1 is active")
                
                node_ele = ptjsonlib_object.create_node_object(node_type=f"Device {device_number}", parent_type="Site", parent=None, properties={"name": f"Device {device_number}", "type": role, "MAC": mac_address, "description": get_vendor(mac_address, mac_db), "vulnerabilities": vul})
                key_node_ele = node_ele["key"]
                ptjsonlib_object.add_node(node_ele)

                # Only applying for the older verison of ptlibs
                # key = ptjsonlib_object.node_duplicity_check(parent_type="Site", properties={"name": f"Device {device_number}", "type": role, "MAC": mac_address, "vulnerabilities": vul}, known_nodes=[])
                
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
                                    node_ele_child = ptjsonlib_object.create_node_object(node_type="Address", parent_type=f"Device {device_number}", parent=key_node_ele, properties={"IP": in6_getansma(ip), "protocol": "IPv6", "description": "possible address"})
                                    if (type(node_ele_child)) == dict:
                                        ptjsonlib_object.add_node(node_ele_child)
                            elif is_global_unicast_ipv6(ip) or is_link_local_ipv6(ip) or is_ipv6_ula(ip):
                                if all_ip.count(ip) >= 2:                                  
                                    node_ele_child = ptjsonlib_object.create_node_object(node_type="Address", parent_type=f"Device {device_number}", parent=key_node_ele, properties={"IP": ip, "protocol": "IPv6", "description": "duplicated address, probably not owned"})
                                    if (type(node_ele_child)) == dict:
                                        ptjsonlib_object.add_node(node_ele_child)
                                else:
                                    node_ele_child = ptjsonlib_object.create_node_object(node_type="Address", parent_type=f"Device {device_number}", parent=key_node_ele, properties={"IP": ip, "protocol": "IPv6", "description": "normal address"})
                                    if (type(node_ele_child)) == dict:
                                        ptjsonlib_object.add_node(node_ele_child)
                        else:
                            try:
                                ipv4_address = ipaddress.IPv4Address(ip)
                                if all_ip.count(ip) >= 2:
                                    node_ele_child = ptjsonlib_object.create_node_object(node_type="Address", parent_type=f"Device {device_number}", parent=key_node_ele, properties={"IP": ip, "protocol": "IPv4", "description": "duplicated address, probably not owned"})
                                    if (type(node_ele_child)) == dict:
                                        ptjsonlib_object.add_node(node_ele_child)
                                else:                                 
                                    node_ele_child = ptjsonlib_object.create_node_object(node_type="Address", parent_type=f"Device {device_number}", parent=key_node_ele, properties={"IP": ip, "protocol": "IPv4", "description": "normal address"})
                                    if (type(node_ele_child)) == dict:
                                        ptjsonlib_object.add_node(node_ele_child)
                            except ipaddress.AddressValueError:
                                continue
            
        ptjsonlib_object.set_status("finished")
        return ptjsonlib_object.get_result_json()

