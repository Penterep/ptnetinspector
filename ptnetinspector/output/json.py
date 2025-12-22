"""JSON output builder for ptnetinspector.

Reads the accumulated CSV artifacts produced by scan modes, builds a normalized
graph-style JSON (nodes, properties, vulnerabilities), optionally filters by
IP version and vulnerability codes, and writes the final `ptnetinspector-output.json`.
"""
import ipaddress
import pandas as pd
from ptlibs.app_dirs import AppDirs
from ptnetinspector.utils.path import get_csv_path, get_output_dir
from ptnetinspector.utils.csv_helpers import delete_middle_content_csv
from ptnetinspector.utils.output_helpers import filter_ips_by_mode, convert_role_to_list
from ptnetinspector.utils.ip_utils import (
    has_additional_data, is_global_unicast_ipv6, is_ipv6_ula, is_link_local_ipv6,
    is_valid_ipv6, is_llsnm_ipv6, is_dhcp_slaac
)
from ptnetinspector.utils.ip_utils import in6_getansma, in6_getnsma
from ptnetinspector.utils.oui import lookup_vendor_from_csv
from ptnetinspector.utils.cli import ptjsonlib_object
from ptnetinspector.utils.vuln_catalog import load_vuln_catalog_by_test
from ptnetinspector.send.send import IPMode


class Json:
    @staticmethod
    def _get_vulnerabilities_for_id(vuln_df: pd.DataFrame, id_value: str, mode: str = None, target_codes: set[str] | None = None) -> list:
        """Extract vulnerabilities for a given ID, optionally filtered by mode or target codes."""
        vulns = []
        device_vulns = vuln_df[vuln_df['ID'].astype(str) == id_value]
        for _, vuln_row in device_vulns.iterrows():
            # Filter by mode if provided
            if mode is not None and mode not in vuln_row.get('Mode', ''):
                continue
            code = vuln_row.get('Code', '')
            if target_codes and code.strip().upper() not in target_codes:
                continue
            if vuln_row.get('Label', 0) == 1:
                desc = vuln_row.get('Description', '')
                vulns.append(f"{code}: {desc}")
        return vulns

    @staticmethod
    def output_property(ipver: IPMode) -> dict:
        """Extracts network properties from CSV files and adds them to the JSON object."""
        ra_file = get_csv_path("RA.csv")
        
        if ipver.ipv6 and has_additional_data(ra_file):
            df = pd.read_csv(ra_file)
            for value in df['Prefix'].unique():
                if value != "[]":
                    ptjsonlib_object.add_properties(properties={"IPv6 prefix": value})

            for value in df['DNS'].unique():
                if value != "[]":
                    ptjsonlib_object.add_properties(properties={"DNS server": value})

        dhcp_slaac_methods = is_dhcp_slaac()
        if dhcp_slaac_methods:
            for item in dhcp_slaac_methods:
                ptjsonlib_object.add_properties(properties={"Address configuration method discovered": item})

        return ptjsonlib_object.get_result_json()

    @staticmethod
    def output_vul_net(mode: str = None, vul_file: str = None, target_codes: set[str] | None = None) -> dict:
        """Extracts network vulnerabilities from CSV and adds them to the JSON object."""
        if vul_file is None:
            vul_file = get_csv_path("vulnerability.csv")

        target_codes_set = {code.upper() for code in target_codes} if target_codes else None
        
        if has_additional_data(vul_file):
            try:
                vuln_df = pd.read_csv(vul_file)
                vulns = Json._get_vulnerabilities_for_id(vuln_df, "Network", mode, target_codes_set)
                for code, desc in [v.split(": ") for v in vulns]:
                    if not any(v['vulnCode'] == code for v in ptjsonlib_object.json_object['results']['vulnerabilities']):
                        ptjsonlib_object.add_vulnerability(vuln_code=code, description=desc)
            except Exception:
                pass
        return ptjsonlib_object.get_result_json()

    @staticmethod
    def _create_address_node(ip: str, device_number: int, key_node_ele: str, all_ip: list) -> bool:
        """Create and add an address node. Returns True if added."""
        if is_valid_ipv6(ip):
            return Json._create_ipv6_address_node(ip, device_number, key_node_ele, all_ip)
        else:
            return Json._create_ipv4_address_node(ip, device_number, key_node_ele, all_ip)

    @staticmethod
    def _create_ipv6_address_node(ip: str, device_number: int, key_node_ele: str, all_ip: list) -> bool:
        """Create and add an IPv6 address node."""
        if is_llsnm_ipv6(ip):
            list_solicited_ip = [in6_getnsma(addr) for addr in [ip] if not is_llsnm_ipv6(addr)]
            if ip not in list_solicited_ip:
                node = ptjsonlib_object.create_node_object(
                    node_type="Address", parent_type=f"Device {device_number}",
                    parent=key_node_ele, properties={
                        "IP": in6_getansma(ip), "protocol": "IPv6", "description": "possible address"
                    }
                )
                if isinstance(node, dict):
                    ptjsonlib_object.add_node(node)
                    return True
        elif not is_llsnm_ipv6(ip):
            desc = "duplicated address, probably not owned" if all_ip.count(ip) >= 2 else "normal address"
            node = ptjsonlib_object.create_node_object(
                node_type="Address", parent_type=f"Device {device_number}",
                parent=key_node_ele, properties={
                    "IP": ip, "protocol": "IPv6", "description": desc
                }
            )
            if isinstance(node, dict):
                ptjsonlib_object.add_node(node)
                return True
        return False

    @staticmethod
    def _create_ipv4_address_node(ip: str, device_number: int, key_node_ele: str, all_ip: list) -> bool:
        """Create and add an IPv4 address node."""
        try:
            ipaddress.IPv4Address(ip)
            desc = "duplicated address, probably not owned" if all_ip.count(ip) >= 2 else "normal address"
            node = ptjsonlib_object.create_node_object(
                node_type="Address", parent_type=f"Device {device_number}",
                parent=key_node_ele, properties={
                    "IP": ip, "protocol": "IPv4", "description": desc
                }
            )
            if isinstance(node, dict):
                ptjsonlib_object.add_node(node)
                return True
        except ipaddress.AddressValueError:
            pass
        return False

    @staticmethod
    def output_object(extract_to_json: bool = True, mode: str = None, target_codes: set[str] | None = None, ipver: IPMode | None = None, target_macs: set[str] | None = None) -> dict:
        """Build and return the final JSON report from CSV artifacts.

        Args:
            extract_to_json: When True, reads CSVs and constructs the JSON graph.
            mode: Optional mode filter for vulnerability entries ("802.1x", "p", "a", "a+").
            target_codes: Optional set of Test codes to include; mapped to vuln codes.
            ipver: Optional IPMode to filter addresses by IP family.
            target_macs: Optional set of target MAC addresses to filter devices.
        Returns:
            dict: JSON structure (stringified when written to file).
        """
        if ipver is None:
            ipver = IPMode(True, True)

        if not isinstance(ptjsonlib_object.json_object, dict):
            # Ensure json object is in a clean state (covers repeated calls in tests)
            ptjsonlib_object.__init__()
        
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
        
        # Normalize target MACs to uppercase
        target_macs_set = {mac.upper() for mac in target_macs} if target_macs else None
        
        start_end_file = get_csv_path("start_end_mode.csv")
        delete_middle_content_csv(start_end_file)

        Json.output_property(ipver)
        Json.output_vul_net(mode, target_codes=target_codes_set)

        if not extract_to_json:
            return ptjsonlib_object.get_result_json()

        addresses_file = get_csv_path("addresses.csv")
        addresses_unfiltered_file = get_csv_path("addresses_unfiltered.csv")
        role_node_file = get_csv_path("role_node.csv")
        vulnerability_file = get_csv_path("vulnerability.csv")

        if (has_additional_data(addresses_file) or has_additional_data(addresses_unfiltered_file)) and has_additional_data(role_node_file):
            role_node_df = pd.read_csv(role_node_file)
            addresses_df = pd.read_csv(addresses_file) if has_additional_data(addresses_file) else pd.read_csv(addresses_unfiltered_file)
            addresses_df = filter_ips_by_mode(addresses_df, ipver)
            
            # Filter by target MACs if specified
            if target_macs_set:
                role_node_df = role_node_df[role_node_df['MAC'].str.upper().isin(target_macs_set)]
                addresses_df = addresses_df[addresses_df['MAC'].str.upper().isin(target_macs_set)]
            
            all_ip = addresses_df['IP'].to_list()
            vuln_df = pd.read_csv(vulnerability_file) if has_additional_data(vulnerability_file) else None

            for _, row in role_node_df.iterrows():
                mac_address, device_number, role = row['MAC'], row['Device_Number'], row['Role']
                roles = convert_role_to_list(role)
                vul = Json._get_vulnerabilities_for_id(vuln_df, str(device_number), mode, target_codes_set) if vuln_df is not None else []

                node_ele = ptjsonlib_object.create_node_object(
                    node_type=f"Device {device_number}", parent_type="Site", parent=None,
                    properties={
                        "name": f"Device {device_number}", "type": roles, "MAC": mac_address,
                        "description": lookup_vendor_from_csv(mac_address)
                    },
                    vulnerabilities=vul
                )
                ptjsonlib_object.add_node(node_ele)

                ip_addresses = addresses_df.loc[addresses_df['MAC'] == mac_address, 'IP'].tolist()
                for ip in ip_addresses:
                    Json._create_address_node(ip, device_number, node_ele["key"], all_ip)

        ptjsonlib_object.set_status("finished")
        output_json = ptjsonlib_object.get_result_json()
        
        if extract_to_json:
            output_file = get_output_dir() / "ptnetinspector-output.json"
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(output_json)

        return output_json
