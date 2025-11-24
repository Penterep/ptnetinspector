import csv
import ipaddress
import json
import pandas as pd
from src.sniff import Sniff
from src.create_csv import delete_middle_content_csv
from libs.check import (
    has_additional_data, is_global_unicast_ipv6, is_ipv6_ula, is_link_local_ipv6,
    is_valid_ipv6, is_llsnm_ipv6, get_status_ip, is_dhcp_slaac
)
from libs.convert import in6_getansma, in6_getnsma
from src.output.oui import lookup_vendor_from_csv
from src.device.vulnerability import Vulnerability

file_path = "src/tmp/"
from src.parameters import ptjsonlib_object

class Json:
    @staticmethod
    def convert_role_to_list(role: str) -> list:
        """
        Convert the role string to a list by splitting it at the semicolon.

        Args:
            role (str): The role string to be converted

        Returns:
            list: A list of roles
        """
        return role.split(";")

    @staticmethod
    def output_property() -> dict:
        """
        Extracts network properties from CSV files and adds them to the JSON object.

        Returns:
            dict: The updated JSON object with network properties.
        """
        if has_additional_data(f"{file_path}RA.csv"):
            df = pd.read_csv(f"{file_path}RA.csv")
            list_prefix = df['Prefix'].unique().tolist()
            list_dns = df['DNS'].unique().tolist()
            list_mtu = df['MTU'].unique().tolist()

            for prefix in list_prefix:
                if prefix != "[]":
                    ptjsonlib_object.add_properties(properties={"IPv6 prefix": prefix})

            for dns in list_dns:
                if dns != "[]":
                    ptjsonlib_object.add_properties(properties={"DNS server": dns})

        dhcp_slaac_methods = is_dhcp_slaac()
        if dhcp_slaac_methods:
            for item in dhcp_slaac_methods:
                ptjsonlib_object.add_properties(properties={"Address configuration method discovered": item})

        return ptjsonlib_object.get_result_json()

    @staticmethod
    def output_vul_net(vul_file: str = f"{file_path}vulnerability.csv") -> dict:
        """
        Extracts network vulnerabilities from CSV and adds them to the JSON object.

        Args:
            vul_file (str): Path to the vulnerability CSV file.

        Returns:
            dict: The updated JSON object with network vulnerabilities.
        """
        if has_additional_data(vul_file):
            try:
                vuln_df = pd.read_csv(vul_file)
                net_vulns = vuln_df[vuln_df['ID'] == "Network"]
                for _, vuln_row in net_vulns.iterrows():
                    code = vuln_row.get('Code', '')
                    desc = vuln_row.get('Description', '')
                    label = vuln_row.get('Label', '')
                    if label == 1:
                        if not any(v['vulnCode'] == f"{code}" for v in ptjsonlib_object.json_object['results']['vulnerabilities']):
                            ptjsonlib_object.add_vulnerability(vuln_code=f"{code}", description=f"{desc}")
            except Exception:
                pass
        return ptjsonlib_object.get_result_json()

    @staticmethod
    def output_object(extract_to_json: bool = True) -> dict:
        """
        Main function to extract all network information and output as JSON.

        Args:
            extract_to_json (bool): Whether to write the output to a JSON file.

        Returns:
            dict: The final JSON object with all extracted information.
        """
        delete_middle_content_csv(f"{file_path}start_end_mode.csv")
        Json.output_property()
        Json.output_vul_net()

        if not extract_to_json:
            return ptjsonlib_object.get_result_json()

        if (has_additional_data(f"{file_path}addresses.csv") or has_additional_data(f"{file_path}addresses_unfiltered.csv")) and has_additional_data(f"{file_path}role_node.csv"):
            role_node_df = pd.read_csv(f"{file_path}role_node.csv")
            if has_additional_data(f"{file_path}addresses.csv"):
                addresses_df = pd.read_csv(f"{file_path}addresses.csv")
            else:
                addresses_df = pd.read_csv(f"{file_path}addresses_unfiltered.csv")
            all_ip = addresses_df['IP'].to_list()

            for index, row in role_node_df.iterrows():
                mac_address = row['MAC']
                device_number = row['Device_Number']
                role = row['Role']
                vul = []

                roles = Json.convert_role_to_list(role)

                try:
                    vuln_df = pd.read_csv(f"{file_path}vulnerability.csv")
                    device_vulns = vuln_df[vuln_df['ID'] == str(device_number)]
                    for _, vuln_row in device_vulns.iterrows():
                        code = vuln_row.get('Code', '')
                        desc = vuln_row.get('Description', '')
                        label = vuln_row.get('Label', '')
                        if label == 1:
                            vul.append(f"{code}: {desc}")
                except Exception:
                    pass

                node_ele = ptjsonlib_object.create_node_object(
                    node_type=f"Device {device_number}",
                    parent_type="Site",
                    parent=None,
                    properties={
                        "name": f"Device {device_number}",
                        "type": roles,
                        "MAC": mac_address,
                        "description": lookup_vendor_from_csv(mac_address)
                    },
                    vulnerabilities=vul
                )
                key_node_ele = node_ele["key"]
                ptjsonlib_object.add_node(node_ele)

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
                                    node_ele_child = ptjsonlib_object.create_node_object(
                                        node_type="Address",
                                        parent_type=f"Device {device_number}",
                                        parent=key_node_ele,
                                        properties={
                                            "IP": in6_getansma(ip),
                                            "protocol": "IPv6",
                                            "description": "possible address"
                                        }
                                    )
                                    if isinstance(node_ele_child, dict):
                                        ptjsonlib_object.add_node(node_ele_child)
                            elif is_global_unicast_ipv6(ip) or is_link_local_ipv6(ip) or is_ipv6_ula(ip):
                                desc = "duplicated address, probably not owned" if all_ip.count(ip) >= 2 else "normal address"
                                node_ele_child = ptjsonlib_object.create_node_object(
                                    node_type="Address",
                                    parent_type=f"Device {device_number}",
                                    parent=key_node_ele,
                                    properties={
                                        "IP": ip,
                                        "protocol": "IPv6",
                                        "description": desc
                                    }
                                )
                                if isinstance(node_ele_child, dict):
                                    ptjsonlib_object.add_node(node_ele_child)
                        else:
                            try:
                                ipv4_address = ipaddress.IPv4Address(ip)
                                desc = "duplicated address, probably not owned" if all_ip.count(ip) >= 2 else "normal address"
                                node_ele_child = ptjsonlib_object.create_node_object(
                                    node_type="Address",
                                    parent_type=f"Device {device_number}",
                                    parent=key_node_ele,
                                    properties={
                                        "IP": ip,
                                        "protocol": "IPv4",
                                        "description": desc
                                    }
                                )
                                if isinstance(node_ele_child, dict):
                                    ptjsonlib_object.add_node(node_ele_child)
                            except ipaddress.AddressValueError:
                                continue

        ptjsonlib_object.set_status("finished")

        output_json = ptjsonlib_object.get_result_json()
        if extract_to_json:
            with open(f"{file_path}ptnetinspector-output.json", "w", encoding="utf-8") as f:
                f.write(output_json)

        return output_json
