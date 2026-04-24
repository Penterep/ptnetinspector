"""JSON output builder for ptnetinspector.

Reads the accumulated CSV artifacts produced by scan modes, builds a normalized
graph-style JSON (nodes, properties, vulnerabilities), optionally filters by
IP version and vulnerability codes, and writes the final `ptnetinspector-output.json`.
"""
import ipaddress
import json
import logging
import pandas as pd
from ptlibs.app_dirs import AppDirs
from ptnetinspector.utils.path import get_csv_path, get_output_dir, get_tmp_path
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


logger = logging.getLogger(__name__)


class Json:
    @staticmethod
    def _resolve_vulnerability_file(preferred_name: str, fallback_name: str | None = None) -> str:
        preferred = get_csv_path(preferred_name)
        if has_additional_data(preferred):
            return preferred
        if fallback_name:
            return get_csv_path(fallback_name)
        return preferred

    @staticmethod
    def _load_scanner_mac_from_run_params() -> str | None:
        """Load scanner MAC from run_params.json if available."""
        try:
            run_params_path = get_tmp_path() / "run_params.json"
            if not run_params_path.exists():
                return None
            with open(run_params_path, encoding="utf-8") as f:
                run_params = json.load(f)
            smac = str(run_params.get("smac") or "").strip().upper()
            return smac or None
        except Exception as ex:
            logger.debug("Failed to load scanner MAC from run_params.json: %s", ex)
            return None

    @staticmethod
    def _get_vulnerabilities_for_id(vuln_df: pd.DataFrame, id_value: str, mode: str = None, target_codes: set[str] | None = None) -> list[str]:
        """Extract vulnerability codes for a given ID, optionally filtered by mode or target codes."""
        vuln_codes: list[str] = []
        device_vulns = vuln_df[vuln_df['ID'].astype(str) == id_value]
        for _, vuln_row in device_vulns.iterrows():
            if mode is not None and mode not in vuln_row.get('Mode', ''):
                continue
            code = vuln_row.get('Code', '')
            if not code:
                continue
            if target_codes and code.strip().upper() not in target_codes:
                continue
            if vuln_row.get('Label', 0) == 1:
                vuln_codes.append(code.strip())
        return vuln_codes

    @staticmethod
    def _get_vulnerabilities_for_ip(
        vuln_ip_df: pd.DataFrame,
        ip_value: str,
        id_value: str | None = None,
        mode: str = None,
        target_codes: set[str] | None = None,
    ) -> list[str]:
        """Extract vulnerability codes for a given IP, optionally constrained by device ID/mode/codes."""
        if vuln_ip_df is None or 'IP' not in vuln_ip_df.columns:
            return []

        ip_vulns = vuln_ip_df[vuln_ip_df['IP'].astype(str) == str(ip_value)]
        if id_value is not None and 'ID' in vuln_ip_df.columns:
            ip_vulns = ip_vulns[ip_vulns['ID'].astype(str) == str(id_value)]

        vuln_codes: list[str] = []
        for _, vuln_row in ip_vulns.iterrows():
            if mode is not None and mode not in vuln_row.get('Mode', ''):
                continue
            code = vuln_row.get('Code', '')
            if not code:
                continue
            if target_codes and code.strip().upper() not in target_codes:
                continue
            if vuln_row.get('Label', 0) == 1:
                code_clean = code.strip()
                if code_clean not in vuln_codes:
                    vuln_codes.append(code_clean)
        return vuln_codes

    @staticmethod
    def _ip_matches_mode(ip: str, ipver: IPMode) -> bool:
        """Return True if the IP family is enabled by selected mode."""
        try:
            is_v6 = is_valid_ipv6(ip)
            if is_v6:
                return bool(ipver.ipv6)
            ipaddress.IPv4Address(ip)
            return bool(ipver.ipv4)
        except Exception as ex:
            logger.debug("Invalid IP while matching mode (%s): %s", ip, ex)
            return False

    @staticmethod
    def _get_device_vulnerabilities_from_ips(
        vuln_ip_df: pd.DataFrame,
        ip_values: list[str],
        id_value: str,
        mode: str = None,
        target_codes: set[str] | None = None,
    ) -> list[str]:
        """Build cumulative device vulnerabilities from its real IP-level findings."""
        device_codes: list[str] = []
        if vuln_ip_df is None:
            return device_codes

        for ip in ip_values:
            # Possible IPv6 addresses are derived from solicited-node multicast.
            # Keep them in output structure, but do not treat them as real evidence.
            if is_valid_ipv6(ip) and is_llsnm_ipv6(ip):
                continue

            ip_codes = Json._get_vulnerabilities_for_ip(
                vuln_ip_df,
                ip,
                id_value,
                mode,
                target_codes,
            )
            for code in ip_codes:
                if code not in device_codes:
                    device_codes.append(code)

        return device_codes

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
            vul_file = Json._resolve_vulnerability_file("vulnerability_net.csv")

        target_codes_set = {code.upper() for code in target_codes} if target_codes else None

        if has_additional_data(vul_file):
            try:
                vuln_df = pd.read_csv(vul_file)
                vulns = Json._get_vulnerabilities_for_id(vuln_df, "Network", mode, target_codes_set)
                for code in vulns:
                    if not any(v['vulnCode'] == code for v in ptjsonlib_object.json_object['results']['vulnerabilities']):
                        ptjsonlib_object.add_vulnerability(vuln_code=code)
            except Exception as ex:
                logger.debug("Failed to process network vulnerabilities from %s: %s", vul_file, ex)
        return ptjsonlib_object.get_result_json()

    @staticmethod
    def _create_address_node(
        ip: str,
        device_number: int,
        key_node_ele: str,
        all_ip: list,
        address_vuln_codes: list[str] | None = None,
        check_addresses: bool = True,
        device_ips: list[str] | None = None,
    ) -> bool:
        """Create and add an address node. Returns True if added."""
        if is_valid_ipv6(ip):
            return Json._create_ipv6_address_node(
                ip,
                device_number,
                key_node_ele,
                all_ip,
                address_vuln_codes,
                check_addresses=check_addresses,
                device_ips=device_ips,
            )
        else:
            return Json._create_ipv4_address_node(ip, device_number, key_node_ele, all_ip, address_vuln_codes)

    @staticmethod
    def _create_ipv6_address_node(
        ip: str,
        device_number: int,
        key_node_ele: str,
        all_ip: list,
        address_vuln_codes: list[str] | None = None,
        check_addresses: bool = True,
        device_ips: list[str] | None = None,
    ) -> bool:
        """Create and add an IPv6 address node."""
        if is_llsnm_ipv6(ip):
            # Keep parity with non-JSON output: show possible addresses only in -nc mode.
            if check_addresses:
                return False

            source_ips = device_ips if device_ips is not None else all_ip
            list_solicited_ip = [
                in6_getnsma(addr)
                for addr in source_ips
                if is_valid_ipv6(addr) and not is_llsnm_ipv6(addr)
            ]

            if ip not in list_solicited_ip:
                node = ptjsonlib_object.create_node_object(
                    node_type="Address", parent_type=None,
                    parent=key_node_ele, properties={
                        "IP": in6_getansma(ip), "protocol": "IPv6", "description": "possible address"
                    }
                )
                if isinstance(node, dict):
                    # Possible addresses must keep the node structure, but remain without vulnerabilities.
                    ptjsonlib_object.add_node(node)
                    return True
        elif not is_llsnm_ipv6(ip):
            desc = "duplicated address, probably not owned" if all_ip.count(ip) >= 2 else "normal address"
            node = ptjsonlib_object.create_node_object(
                node_type="Address", parent_type=None,
                parent=key_node_ele, properties={
                    "IP": ip, "protocol": "IPv6", "description": desc
                }
            )
            if isinstance(node, dict):
                for code in (address_vuln_codes or []):
                    if not any(v.get("vulnCode") == code for v in node.get("vulnerabilities", [])):
                        node.setdefault("vulnerabilities", []).append({"vulnCode": code})
                ptjsonlib_object.add_node(node)
                return True
        return False

    @staticmethod
    def _create_ipv4_address_node(
        ip: str,
        device_number: int,
        key_node_ele: str,
        all_ip: list,
        address_vuln_codes: list[str] | None = None,
    ) -> bool:
        """Create and add an IPv4 address node."""
        try:
            ipaddress.IPv4Address(ip)
            desc = "duplicated address, probably not owned" if all_ip.count(ip) >= 2 else "normal address"
            node = ptjsonlib_object.create_node_object(
                node_type="Address", parent_type=None,
                parent=key_node_ele, properties={
                    "IP": ip, "protocol": "IPv4", "description": desc
                }
            )
            if isinstance(node, dict):
                for code in (address_vuln_codes or []):
                    if not any(v.get("vulnCode") == code for v in node.get("vulnerabilities", [])):
                        node.setdefault("vulnerabilities", []).append({"vulnCode": code})
                ptjsonlib_object.add_node(node)
                return True
        except ipaddress.AddressValueError:
            logger.debug("Skipping invalid IPv4 address node candidate: %s", ip)
            pass
        return False

    @staticmethod
    def output_object(
        extract_to_json: bool = True,
        mode: str = None,
        target_codes: set[str] | None = None,
        ipver: IPMode | None = None,
        target_macs: set[str] | None = None,
        target_ips: set[str] | None = None,
        check_addresses: bool = True,
    ) -> dict:
        """Build and return the final JSON report from CSV artifacts.

        Args:
            extract_to_json: When True, reads CSVs and constructs the JSON graph.
            mode: Optional mode filter for vulnerability entries ("802.1x", "p", "a", "a+").
            target_codes: Optional set of Test codes to include; mapped to vuln codes.
            ipver: Optional IPMode to filter addresses by IP family.
            target_macs: Optional set of target MAC addresses to filter devices.
            target_ips: Optional set of target IP addresses to filter addresses.
            check_addresses: True when address validation is enabled (default behavior without -nc).
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
                logger.debug("Failed to load vulnerability test catalog; disabling target code filter", exc_info=True)
                target_codes_set = None

        # Normalize target MACs to uppercase
        target_macs_set = {mac.upper() for mac in target_macs} if target_macs else None
        target_ips_set = {str(ip).strip() for ip in target_ips} if target_ips else None
        has_target_filter = bool(target_macs_set or target_ips_set)

        start_end_file = get_csv_path("start_end_mode.csv")
        delete_middle_content_csv(start_end_file)

        if not has_target_filter:
            Json.output_property(ipver)
            Json.output_vul_net(mode, target_codes=target_codes_set)

        if not extract_to_json:
            return ptjsonlib_object.get_result_json()

        addresses_file = get_csv_path("addresses.csv")
        addresses_unfiltered_file = get_csv_path("addresses_unfiltered.csv")
        role_node_file = get_csv_path("role_node.csv")
        vulnerability_ip_file = Json._resolve_vulnerability_file("vulnerability_ip.csv")

        if (has_additional_data(addresses_file) or has_additional_data(addresses_unfiltered_file)) and has_additional_data(role_node_file):
            role_node_df = pd.read_csv(role_node_file)
            addresses_df = pd.read_csv(addresses_file) if has_additional_data(addresses_file) else pd.read_csv(addresses_unfiltered_file)
            addresses_df = filter_ips_by_mode(addresses_df, ipver)

            # Always ignore scanner device and all its addresses.
            scanner_mac = Json._load_scanner_mac_from_run_params()
            if scanner_mac:
                role_node_df = role_node_df[role_node_df['MAC'].str.upper() != scanner_mac]
                addresses_df = addresses_df[addresses_df['MAC'].str.upper() != scanner_mac]

            # Filter by targets (MAC and/or IP) if specified.
            if has_target_filter:
                address_mask = pd.Series(False, index=addresses_df.index)
                if target_macs_set:
                    address_mask = address_mask | addresses_df['MAC'].str.upper().isin(target_macs_set)
                if target_ips_set:
                    address_mask = address_mask | addresses_df['IP'].astype(str).isin(target_ips_set)
                addresses_df = addresses_df[address_mask]
                selected_macs = set(addresses_df['MAC'].astype(str).str.upper().unique().tolist())
                role_node_df = role_node_df[role_node_df['MAC'].str.upper().isin(selected_macs)]

            all_ip = addresses_df['IP'].to_list()
            vuln_ip_df = pd.read_csv(vulnerability_ip_file) if has_additional_data(vulnerability_ip_file) else None

            for _, row in role_node_df.iterrows():
                mac_address, device_number, role = row['MAC'], row['Device_Number'], row['Role']
                roles = convert_role_to_list(role)
                # Derive primary type and role-based flags
                is_preferred_router = "Preferred router" in roles
                is_router = ("Router" in roles) or is_preferred_router
                device_type = "Preferred router" if is_preferred_router else ("Router" if is_router else "Host")
                ipv4_default_gw = "IPv4 default GW" in roles
                ipv6_default_gw = "IPv6 default GW" in roles
                dhcpv4_server = "DHCP server" in roles
                dhcpv6_server = "DHCPv6 server" in roles

                node_ele = ptjsonlib_object.create_node_object(
                    node_type="Device", parent_type="Site", parent=None,
                    properties={
                        "name": f"Device {device_number}",
                        "type": device_type,
                        "MAC": mac_address,
                        "MAC_description": lookup_vendor_from_csv(mac_address),
                        "IPv4_default_GW": ipv4_default_gw,
                        "IPv6_default_GW": ipv6_default_gw,
                        "DHCPv4_server": dhcpv4_server,
                        "DHCPv6_server": dhcpv6_server
                    }
                )
                ptjsonlib_object.add_node(node_ele)

                ip_addresses = addresses_df.loc[addresses_df['MAC'] == mac_address, 'IP'].tolist()
                if vuln_ip_df is not None:
                    ip_rows = vuln_ip_df[vuln_ip_df['ID'].astype(str) == str(device_number)]
                    for _, ip_row in ip_rows.iterrows():
                        ip_val = str(ip_row.get('IP', '')).strip()
                        if not ip_val:
                            continue
                        if mode is not None and mode not in str(ip_row.get('Mode', '')):
                            continue
                        code_val = str(ip_row.get('Code', '')).strip().upper()
                        if target_codes_set and code_val and code_val not in target_codes_set:
                            continue
                        if target_ips_set and ip_val not in target_ips_set:
                            continue
                        if ip_val not in ip_addresses and Json._ip_matches_mode(ip_val, ipver):
                            ip_addresses.append(ip_val)

                device_vul = Json._get_device_vulnerabilities_from_ips(
                    vuln_ip_df,
                    ip_addresses,
                    str(device_number),
                    mode,
                    target_codes_set,
                ) if vuln_ip_df is not None else []

                for code in device_vul:
                    if not any(v.get("vulnCode") == code for v in node_ele.get("vulnerabilities", [])):
                        node_ele.setdefault("vulnerabilities", []).append({"vulnCode": code})

                for ip in ip_addresses:
                    ip_vul = Json._get_vulnerabilities_for_ip(
                        vuln_ip_df,
                        ip,
                        str(device_number),
                        mode,
                        target_codes_set,
                    ) if vuln_ip_df is not None else []
                    Json._create_address_node(
                        ip,
                        device_number,
                        node_ele["key"],
                        all_ip,
                        ip_vul,
                        check_addresses=check_addresses,
                        device_ips=ip_addresses,
                    )

        ptjsonlib_object.set_status("finished")
        output_json = ptjsonlib_object.get_result_json()

        if extract_to_json:
            output_file = get_tmp_path() / "ptnetinspector-output.json"
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(output_json)

        return output_json
