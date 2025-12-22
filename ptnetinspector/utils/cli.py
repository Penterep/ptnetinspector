"""CLI parsing, validation, and normalization for ptnetinspector.

Exposes argument parsing, normalization to internal types, and convenience
helpers to validate network-related inputs and drive scan configuration.
"""
import argparse
import logging
import os
import subprocess
import sys
import difflib

import netifaces
import pandas as pd
from netaddr import IPNetwork
from ptlibs import ptprinthelper
from ptlibs.ptjsonlib import PtJsonLib
from scapy.all import get_if_hwaddr

from ptnetinspector.output.non_json import Non_json
from ptnetinspector.send.send import IPMode
from ptnetinspector.utils.interface import Interface
from ptnetinspector.utils.ip_utils import (
    check_prefRA,
    convert_preferenceRA,
    convert_preferenceRA_to_numeric,
    is_non_negative_float,
    is_valid_integer,
    is_valid_ipv6,
    is_valid_ipv6_prefix,
    is_valid_mac,
    is_valid_MTU,
)
from ptnetinspector.utils.path import get_tmp_path
from ptnetinspector.utils.vuln_catalog import load_vuln_catalog, load_vuln_catalog_by_test
from ptnetinspector._version import __version__

ptjsonlib_object = PtJsonLib()
SCRIPTNAME = "ptnetinspector"
# ============================================================================
# SECTION 1: ARGUMENT PARSER CLASS & PARSING FUNCTIONS
# ============================================================================

class CustomArgumentParser(argparse.ArgumentParser):
    """
    Custom ArgumentParser to handle specific error messages.
    
    Output:
        Error message printed and exits on error.
    """
    def error(self, message: str) -> None:
        error_msgs = [
            "argument -t: expected at least one argument",
            "argument -i: expected one argument",
            "argument -d: expected one argument",
            "argument -da+: expected one argument",
            "argument -prefix: expected one argument",
            "argument -smac: expected one argument",
            "argument -sip: expected one argument",
            "argument -rpref: expected one argument",
            "argument -period: expected one argument",
            "argument -chl: expected one argument",
            "argument -dns: expected at least one argument",
            "argument -mtu: expected one argument"
        ]
        for err in error_msgs:
            if err in message:
                msg = "Expected argument after the prefix or the argument is invalid. Try ptnetinspector -h for help"
                if '-j' in sys.argv:
                    print(ptjsonlib_object.end_error(msg, ptjsonlib_object))
                else:
                    ptprinthelper.ptprint(msg, "ERROR")
                sys.exit(2)


def parse_args() -> argparse.Namespace:
    """
    Parse command-line arguments for ptnetinspector.
    
    Returns:
        argparse.Namespace: Object with parsed arguments.
    """
    parser = CustomArgumentParser(description='start ptnetinspector')
    parser.add_argument("-t", nargs='+', choices=["802.1x", "p", "a", "a+"], help="first mandatory argument")
    parser.add_argument("-i", dest="interface", help="second mandatory argument")
    parser.add_argument("-j", action="store_true")
    parser.add_argument("-target", dest="target_macs", nargs="+", action="append", help="target device MAC address(es) for results filtering (space-separated; -target can be repeated)")
    parser.add_argument("-vv", action="store_true", default=False)
    parser.add_argument("-less", action="store_true", default=False)
    parser.add_argument("-nc", action="store_false", default=True)
    parser.add_argument("-4", dest="ipv4", action="store_true", default=False)
    parser.add_argument("-6", dest="ipv6", action="store_true", default=False)
    parser.add_argument("-d", action="store")
    parser.add_argument("-da+", dest="duration_router", action="store")
    parser.add_argument("-prefix", action="store")
    parser.add_argument("-smac", action="store", help="the MAC address of sender (resolved from the interface if skipping).")
    parser.add_argument("-sip", action="store", help="the MAC address of sender (resolved from the interface if skipping).")
    parser.add_argument("-rpref", action="store", help="the preference flag of RA in aggressive mode (High if skipping).")
    parser.add_argument("-period", action="store", help="the sending rate of RA in aggressive mode.")
    parser.add_argument("-chl", action="store", help="the current of RA in aggressive mode.")
    parser.add_argument("-dns", dest="dns", action="store", nargs="+", help="the IPv6 address of DNS server (separated by space if more than 1 address is inserted).")
    parser.add_argument("-mtu", action="store", help="the MTU of RA in aggressive mode.")
    parser.add_argument("-nofwd", action="store_true", default=False)
    parser.add_argument("-ts", dest="target_codes", nargs="+", help="filter vulnerabilities by code (space-separated)")
    parser.add_argument("-tmpret", dest="tmp_retention", type=float, default=1800.0, help="temporary file retention in seconds (default: 1800)")

    # Print help message if no arguments provided or "-h" is used
    if len(sys.argv) == 1 or "-h" in sys.argv:
        ptprinthelper.help_print(get_help(), SCRIPTNAME, __version__)
        sys.exit(0)

    args, unknown_args = parser.parse_known_args()

    if unknown_args:
        msg = "Unexpected arguments found. Try ptnetinspector -h for help"
        if "-j" in unknown_args or args.j:
            print(ptjsonlib_object.end_error(msg, ptjsonlib_object))
            sys.exit(0)
        else:
            ptprinthelper.ptprint(msg, "ERROR")
            sys.exit(0)

    return args


# ============================================================================
# SECTION 2: HELP & DOCUMENTATION FUNCTIONS
# ============================================================================

def get_help() -> list:
    """
    Returns help information for the script.

    output: list of help sections and examples.
    description: Provides usage, options, and examples for ptnetinspector.
    """
    return [
        {"description": [
            "Network reconnaissance scanner for local IPv6 and IPv4 networks"
        ]},
        {"usage": ["ptnetinspector -t <mode> -i <interface> [options]"]},
        {"options": [
            ["-t              ", "Type of scan (mandatory, multiple choices allowed):"],
            ["                ", "   802.1x    Test for 802.1x protocol"],
            ["                ", "   p         Passive mode - sniff incoming packets"],
            ["                ", "   a         Active mode - test vulnerabilities with various packets"],
            ["                ", "   a+        Aggressive mode - perform tests as fake router"],
            ["-i              ", "Interface (mandatory)"],
            ["-j              ", "Output in JSON format"],
            ["-target         ", "Target device MAC address(es) for filtering (space-separated; only show results for these devices)"],
            ["-vv             ", "Show full details of network scan"],
            ["-less           ", "Show minimum details of network scan"],
            ["-nc             ", "Do not check if found addresses are valid"],
            ["-4              ", "Only IPv4 traffic (cannot be used alone for a+ mode)"],
            ["-6              ", "Only IPv6 traffic"],
            ["-ts             ", "Filter vulnerabilities by Test code (space-separated, e.g., -ts 4-MDNS 6-LLMNR)"],
            ["-tmpret         ", "Temporary file retention in seconds (default: 1800; set small for dev reset)"],
            ["-h              ", "Show this help message and exit"]
        ]},
        {"passive scan options (mode p)": [
            ["-d       <seconds>     ", "Duration of passive scan (float allowed, default: 30)"]
        ]},
        {"active scan options (mode a)": [
            ["-smac    <mac_address> ", "Source MAC address (default: from interface)"]
        ]},
        {"aggressive scan options (mode a+)": [
            ["-da+     <seconds>     ", "Duration of aggressive scan (float allowed, default: 30)"],
            ["-prefix  <ipv6/prefix> ", "IPv6 prefix to advertise (default: fe80::/64)"],
            ["-smac    <mac_address> ", "Source MAC address (default: from interface)"],
            ["-sip     <ipv6>        ", "Source IPv6 address (default: link-local from interface)"],
            ["-rpref   <preference>  ", "Router preference: Reserved/Low/Medium/High (default: High)"],
            ["-period  <seconds>     ", "RA sending rate (float allowed, default: duration/10)"],
            ["-chl     <hop_limit>   ", "Current hop limit in RA message (default: 0)"],
            ["-mtu     <mtu>         ", "MTU to broadcast on the link"],
            ["-dns     <ipv6> ...    ", "DNS server IPv6 address(es), space-separated if multiple"],
            ["-nofwd                 ", "Do not forward packets (disable MiTM)"]
        ]},
        {"examples": [
            ["802.1x mode:"],
            ["   Send EAPOL-Start and wait for responses"],
            ["      ptnetinspector -t 802.1x -i eth0 -j"],
            ["      ptnetinspector -t 802.1x -i eth0 -less -j"],
            [""],
            ["Passive mode:"],
            ["   Deactivate outgoing traffic and sniff incoming packets"],
            ["      ptnetinspector -t p -i eth0 -less"],
            ["      ptnetinspector -t p -i eth0 -d 60 -j"],
            [""],
            ["Active mode:"],
            ["   Test vulnerabilities such as IPv4/IPv6, MLD/IGMP, ICMPv6/ICMP, LLMNR, mDNS, DHCPv6/DHCP, WS-Discovery"],
            ["      ptnetinspector -t a -i eth0 -vv"],
            ["      ptnetinspector -t a -i eth0 -less -j"],
            [""],
            ["Aggressive mode:"],
            ["   Perform active tests plus fake router attacks"],
            ["      ptnetinspector -t a+ -i eth0 -j -da+ 35 -prefix 2001::/64 -smac 00:01:02:03:04:05 -sip fe80::1 -period 5"],
            ["      ptnetinspector -t a+ -i eth0 -less -j -prefix 2001:a:b:1::/64"],
            [""],
            ["Combined modes:"],
            ["   Run multiple scan modes in sequence"],
            ["      ptnetinspector -t 802.1x a a+ -i eth0 -vv"],
            [""],
            ["Test code filtering (-ts):"],
            ["   Run only specific tests by Test code (auto-infers mode and IP version)"],
            ["      ptnetinspector -ts 4-MDNS 6-LLMNR -i eth0 -j"],
            ["      ptnetinspector -ts 6-MLDV1 -i eth0"],
            ["      ptnetinspector -ts 6-OUTRANGE -i eth0"],
            ["      ptnetinspector -ts 6-FAKERA -i eth0 -prefix 2001:db8::/64 -dns 2001:4860:4860::8888 (FAKERA requires prefix and DNS)"],
        ]}
    ]


# ============================================================================
# SECTION 3: OUTPUT CONTROL FUNCTIONS
# ============================================================================

# Global variable to store original stdout
_original_stdout = None


def blockPrint() -> None:
    """
    Disables printing to stdout.

    output: None
    description: Redirects sys.stdout to os.devnull to suppress output.
    """
    global _original_stdout
    _original_stdout = sys.stdout
    sys.stdout = open(os.devnull, 'w')


def enablePrint() -> None:
    """
    Restores printing to stdout.

    output: None
    description: Restores sys.stdout to its previously saved value.
    """
    global _original_stdout
    if _original_stdout is not None:
        # Close the devnull file handle
        if sys.stdout != _original_stdout:
            sys.stdout.close()
        sys.stdout = _original_stdout
        _original_stdout = None


# ============================================================================
# SECTION 4: PARAMETER VALIDATION FUNCTIONS
# ============================================================================

def _validate_mandatory_args(type, interface, json_output, more_detail, target_codes=None) -> None:
    """Validate mandatory arguments (type and interface)."""
    # When -ts is provided, allow omitting -t (type) and infer later
    missing_type = (not type) and (not target_codes)
    if missing_type or not interface:
        if not json_output or more_detail:
            ptprinthelper.ptprint("Missing compulsory parameters (type, interface)", "ERROR")
        if json_output:
            print(ptjsonlib_object.end_error("Missing compulsory parameters (type, interface)", ptjsonlib_object))
        ptprinthelper.help_print(get_help(), SCRIPTNAME, __version__)
        sys.exit(1)


def _validate_type_combination(type, json_output, more_detail) -> None:
    """Validate scan type combinations."""
    # Allow missing type when it will be inferred from -ts later
    if not type:
        return
    if len(type) == 2:
        if "p" in type and "a" in type:
            if not json_output or more_detail:
                ptprinthelper.ptprint("Passive mode is also a part of active mode. Choose again!", "ERROR")
            if json_output:
                print(ptjsonlib_object.end_error("Passive mode is also a part of active mode. Choose again!", ptjsonlib_object))
            sys.exit(1)
        if "p" in type and "a+" in type:
            if not json_output or more_detail:
                ptprinthelper.ptprint("Passive mode is also a part of aggressive mode. Choose again!", "ERROR")
            if json_output:
                print(ptjsonlib_object.end_error("Passive mode is also a part of aggressive mode. Choose again!", ptjsonlib_object))
            sys.exit(1)
        if type[0] == type[1]:
            if not json_output or more_detail:
                ptprinthelper.ptprint("Duplicated choices. Choose again!", "ERROR")
            if json_output:
                print(ptjsonlib_object.end_error("Duplicated choices. Choose again!", ptjsonlib_object))
            sys.exit(1)

    if len(type) >= 3:
        if "802.1x" in type and "a" in type and "a+" in type and len(type) == 3:
            pass
        else:
            if not json_output or more_detail:
                ptprinthelper.ptprint("Invalid choice. Choose again!", "ERROR")
            if json_output:
                print(ptjsonlib_object.end_error("Invalid choice. Choose again!", ptjsonlib_object))
            sys.exit(1)


def _validate_interface(interface, json_output, more_detail) -> None:
    """Validate network interface exists."""
    if interface is not None:
        valid_interface = netifaces.interfaces()
        if interface not in valid_interface:
            err = f"Invalid inserted interface: {interface}. Program exits!"
            if not json_output or more_detail:
                ptprinthelper.ptprint(err, "ERROR")
            if json_output:
                print(ptjsonlib_object.end_error(err, ptjsonlib_object))
            sys.exit(1)


def _validate_detail_flags(more_detail, less_detail, json_output) -> None:
    """Validate detail display flags."""
    if more_detail and less_detail:
        err = "Showing full detail and less detail can not be set at the same time. Program exits!"
        if not json_output or more_detail:
            ptprinthelper.ptprint(err, "ERROR")
        if json_output:
            print(ptjsonlib_object.end_error(err, ptjsonlib_object))
        sys.exit(1)


def _normalize_target_codes(target_codes: list[str] | None) -> list[str] | None:
    """Normalize user-provided Test codes to uppercase and de-duplicate."""
    if not target_codes:
        return None
    cleaned: list[str] = []
    for code in target_codes:
        code_clean = code.strip().upper()
        if code_clean:
            cleaned.append(code_clean)
    if not cleaned:
        return None
    # Preserve order while removing duplicates
    seen = set()
    unique_codes = []
    for code in cleaned:
        if code not in seen:
            seen.add(code)
            unique_codes.append(code)
    return unique_codes


def _validate_target_codes(target_codes, scan_types, ip_mode, ipv4, ipv6, list_error, list_warning):
    """Validate target Test codes and infer appropriate Mode/IPver if not explicitly provided.
    
    Returns:
        - tuple of (validated_test_codes, inferred_scan_types, inferred_ip_mode, auto_filled_params)
        - or None if validation fails
    """
    normalized = _normalize_target_codes(target_codes)
    if normalized is None:
        return None

    try:
        test_catalog = load_vuln_catalog_by_test()
    except FileNotFoundError:
        list_error.append("Vulnerability catalog not found; unable to apply -ts filter. Program exits!")
        return None
    except Exception:
        list_error.append("Unable to load vulnerability catalog; unable to apply -ts filter. Program exits!")
        return None

    # Check unknown test codes and suggest closest matches
    missing = []
    for test_code in normalized:
        if test_code not in test_catalog:
            suggestions = difflib.get_close_matches(test_code, test_catalog.keys(), n=3, cutoff=0.55)
            suggestion_text = f". Nearest correct option(s): {', '.join(suggestions)}" if suggestions else ""
            missing.append(f"{test_code}{suggestion_text}")
    if missing:
        list_error.append(f"Unknown target Test code(s): {', '.join(missing)}. Program exits!")
        return None

    # Collect all vulnerability codes associated with selected Test codes
    associated_vulns: dict[str, dict[str, str]] = {}
    for test_code in normalized:
        for entry in test_catalog[test_code]:
            code = entry["Code"]
            if code not in associated_vulns:
                associated_vulns[code] = entry

    # Infer Mode and IPver based on test codes if not explicitly provided by user
    inferred_scan_types = scan_types if scan_types else None
    inferred_ip_mode = IPMode(ip_mode.ipv4, ip_mode.ipv6) if (ip_mode.ipv4 or ip_mode.ipv6) else None
    auto_filled_params = {}

    # If user didn't specify scan types, infer from Test codes using custom rules
    if not inferred_scan_types:
        # Gather modes per entry to check exclusivity and compose a combined scan plan
        modes_per_entry: list[list[str]] = []
        for entry in associated_vulns.values():
            mode_field = entry.get("Mode", "")
            modes = [m.strip() for m in mode_field.split(',') if m.strip()]
            if modes:
                modes_per_entry.append(modes)

        if not modes_per_entry:
            list_error.append("Cannot infer scan mode from Test code(s). Please specify -t explicitly. Program exits!")
            return None

        has_eap = False
        has_passive = False
        has_active = False
        has_aggressive = False
        aggressive_only = False

        for modes in modes_per_entry:
            if modes == ["802.1x"]:
                has_eap = True
            if "p" in modes:
                has_passive = True
            if modes == ["a+"]:
                aggressive_only = True
            if "a" in modes:
                has_active = True
            if "a+" in modes:
                has_aggressive = True

        inferred_scan_types = []

        if has_eap:
            inferred_scan_types.append("802.1x")
        if has_passive:
            inferred_scan_types.append("p")

        # Prefer the least intrusive option unless a+ is mandatory
        if aggressive_only:
            inferred_scan_types.append("a+")
        elif has_active:
            inferred_scan_types.append("a")
        elif has_aggressive:
            inferred_scan_types.append("a+")

        if not inferred_scan_types:
            list_error.append("Cannot infer scan mode from Test code(s). Please specify -t explicitly. Program exits!")
            return None

    # If user didn't specify IP version, infer from test codes
    # Check if user explicitly specified -4 or -6 (not just using defaults)
    user_specified_ipver = ipv4 or ipv6
    
    if not user_specified_ipver:
        # User didn't specify IP version, so infer from test codes
        allowed_ipvers = set()
        for entry in associated_vulns.values():
            ipver = entry.get("IPver", "").strip()
            if ipver:
                allowed_ipvers.add(ipver)
        
        # Enable only the IP versions that appear in the selected test codes
        ipv4_enabled = "4" in allowed_ipvers
        ipv6_enabled = "6" in allowed_ipvers
        
        inferred_ip_mode = IPMode(ipv4_enabled, ipv6_enabled)
    else:
        # User explicitly specified IP version(s), use that
        inferred_ip_mode = ip_mode

    # Validate that at least one vulnerability matches the inferred mode/ipver
    valid_codes = set()
    for code, entry in associated_vulns.items():
        mode_field = entry.get("Mode", "")
        ipver_field = entry.get("IPver", "").strip()
        
        # Check mode compatibility
        if inferred_scan_types:
            mode_match = False
            if mode_field:
                modes = [m.strip() for m in mode_field.split(',') if m.strip()]
                mode_match = any(m in modes for m in inferred_scan_types)
            if not mode_match:
                continue
        
        # Check IP version compatibility
        ipver_match = True
        if ipver_field == "4" and not inferred_ip_mode.ipv4:
            ipver_match = False
        elif ipver_field == "6" and not inferred_ip_mode.ipv6:
            ipver_match = False
        
        if ipver_match:
            valid_codes.add(code)

    if not valid_codes:
        list_error.append(
            f"No vulnerabilities match the inferred scan mode(s) {inferred_scan_types} and/or IP version(s). "
            f"Consider specifying -t and/or -4/-6 explicitly. Program exits!"
        )
        return None

    return (normalized, inferred_scan_types, inferred_ip_mode, auto_filled_params)


def _require_fakera_params(validated_target_codes, prefix, dns, list_error) -> None:
    """Ensure FAKERA-related tests have required RA parameters."""
    if not validated_target_codes:
        return
    if not any("FAKERA" in code for code in validated_target_codes):
        return

    if prefix is None or not is_valid_ipv6_prefix(prefix):
        list_error.append("Test code FAKERA requires -prefix with a valid IPv6 prefix. Program exits!")

    if not dns:
        list_error.append("Test code FAKERA requires -dns with at least one IPv6 address. Program exits!")
    else:
        invalid_dns = [addr for addr in dns if not is_valid_ipv6(addr)]
        if invalid_dns:
            list_error.append(
                f"Test code FAKERA requires IPv6 DNS address(es); invalid: {', '.join(invalid_dns)}. Program exits!"
            )


def _validate_passive_mode(duration_passive, duration_aggressive, prefix, smac, sip, rpref, period, chl, mtu, dns, nofwd, list_error, list_warning) -> float:
    """Validate and process passive mode parameters."""
    if duration_passive is None:
        duration_passive = 30
        war = f"Missing passive duration, so the default value is chosen: {duration_passive} s"
        list_warning.append(war)
    if duration_passive is not None and not is_non_negative_float(duration_passive):
        err = "Invalid passive duration. Program exits!"
        list_error.append(err)
    else:
        duration_passive = float(duration_passive)
    
    for param, msg in [
        (duration_aggressive, "Aggressive duration is not applied in this mode. Program exits!"),
        (prefix, "Network prefix is not applied in this mode. Program exits!"),
        (smac, "Source MAC is not applied in this mode. Program exits!"),
        (sip, "Source IP is not applied in this mode. Program exits!"),
        (rpref, "Preference flag in RA is not applied in this mode. Program exits!"),
        (period, "Period (RA sending rate) is not applied in this mode. Program exits!"),
        (chl, "Current hop limit is not applied in this mode. Program exits!"),
        (mtu, "MTU is not applied in this mode. Program exits!"),
        (dns, "DNS address is not applied in this mode. Program exits!"),
    ]:
        if param is not None:
            list_error.append(msg)
    if nofwd:
        list_error.append("No forwarding is not applied in this mode. Program exits!")
    
    return duration_passive


def _validate_802_1x_mode(duration_passive, duration_aggressive, prefix, smac, sip, rpref, period, chl, mtu, dns, nofwd, list_error) -> None:
    """Validate and process 802.1x mode parameters."""
    for param, msg in [
        (duration_passive, "Passive duration is not applied in this mode. Program exits!"),
        (duration_aggressive, "Aggressive duration is not applied in this mode. Program exits!"),
        (prefix, "Network prefix is not applied in this mode. Program exits!"),
        (smac, "Source MAC is not applied in this mode. Program exits!"),
        (sip, "Source IP is not applied in this mode. Program exits!"),
        (rpref, "Preference flag in RA is not applied in this mode. Program exits!"),
        (period, "Period (RA sending rate) is not applied in this mode. Program exits!"),
        (chl, "Current hop limit is not applied in this mode. Program exits!"),
        (mtu, "MTU is not applied in this mode. Program exits!"),
        (dns, "DNS address is not applied in this mode. Program exits!"),
    ]:
        if param is not None:
            list_error.append(msg)
    if nofwd:
        list_error.append("No forwarding is not applied in this mode. Program exits!")


def _validate_active_mode(interface, duration_passive, duration_aggressive, prefix, sip, rpref, period, chl, mtu, dns, smac, nofwd, list_error, list_warning) -> str:
    """Validate and process active mode parameters."""
    for param, msg in [
        (duration_passive, "Passive duration is not applied in this mode. Program exits!"),
        (duration_aggressive, "Aggressive duration is not applied in this mode. Program exits!"),
        (prefix, "Network prefix is not applied in this mode. Program exits!"),
        (sip, "Source IP is not applied in this mode. Program exits!"),
        (rpref, "Preference flag in RA is not applied in this mode. Program exits!"),
        (period, "Period (RA sending rate) is not applied in this mode. Program exits!"),
        (chl, "Current hop limit is not applied in this mode. Program exits!"),
        (mtu, "MTU is not applied in this mode. Program exits!"),
        (dns, "DNS address is not applied in this mode. Program exits!"),
    ]:
        if param is not None:
            list_error.append(msg)
    if nofwd:
        list_error.append("No forwarding is not applied in this mode. Program exits!")
    
    # MAC address for active mode
    if smac is None:
        smac = get_if_hwaddr(interface)
        war = f"Missing source MAC, so scanner's MAC is resolved from interface: {smac}"
        list_warning.append(war)
    elif smac is not None and not is_valid_mac(smac):
        err = "Invalid inserted MAC address. Program exits!"
        list_error.append(err)
    
    if not Interface(interface).check_available_ipv6():
        err = f"No available IP on the interface: {interface}. Program exits!"
        list_error.append(err)
    
    return smac


def _validate_aggressive_mode(interface, ip_mode, duration_passive, duration_aggressive, prefix, smac, sip, rpref, period, chl, mtu, dns, nofwd, list_error, list_warning) -> tuple:
    """Validate and process aggressive mode parameters."""
    if not ip_mode.ipv6:
        err = "IPv6 mode is required for aggressive mode. Program exits!"
        list_error.append(err)
    if duration_passive is not None:
        list_error.append("Passive duration is not applied in this mode. Program exits!")
    
    # Duration
    if duration_aggressive is None:
        duration_aggressive = 30
        war = f"Missing aggressive duration, so the default value is chosen: {duration_aggressive} s"
        list_warning.append(war)
    if duration_aggressive is not None and not is_non_negative_float(duration_aggressive):
        err = "Invalid aggressive duration. Program exits!"
        list_error.append(err)
    else:
        duration_aggressive = float(duration_aggressive)
    
    # Prefix
    if not is_valid_ipv6_prefix(prefix):
        if prefix is None:
            war = "Missing prefix, so the prefix is set to: fe80::/64"
            list_warning.append(war)
            prefix_len = 64
            network = "fe80::"
        else:
            err = "Invalid inserted network prefix. Program exits!"
            list_error.append(err)
            prefix_len = None
            network = None
    else:
        prefix_len = IPNetwork(prefix).prefixlen
        network = str(IPNetwork(prefix).network)
    
    # MAC address
    if smac is None:
        smac = get_if_hwaddr(interface)
        war = f"Missing source MAC, so scanner's MAC is resolved from interface: {smac}"
        list_warning.append(war)
    elif smac is not None and not is_valid_mac(smac):
        err = "Invalid inserted MAC address. Program exits!"
        list_error.append(err)
    
    # IPv6 address
    if sip is not None and not is_valid_ipv6(sip):
        if Interface(interface).check_available_ipv6():
            err = "Invalid inserted IPv6 address. Program exits!"
            list_error.append(err)
        else:
            err = f"No available IP on the interface: {interface}. Program exits!"
            list_error.append(err)
    if sip is None:
        if Interface(interface).check_available_ipv6():
            sip_list = Interface(interface).get_interface_link_local_list()
            sip_list_new = []
            for s in sip_list:
                sip_list_new.append(s.split('%', 1)[0])
            war = f"Missing source IP, so scanner's IP is resolved from interface: {sip_list_new}"
            list_warning.append(war)
            sip = sip_list_new
        else:
            err = f"No available IP on the interface: {interface}. Program exits!"
            list_error.append(err)
    
    # Preference flag
    if rpref is not None:
        if not check_prefRA(rpref):
            err = "Invalid inserted preference flag. Program exits!"
            list_error.append(err)
        else:
            rpref = convert_preferenceRA_to_numeric(rpref)
    if rpref is None:
        war = "Missing preference flag, so scanner's flag is set to High"
        list_warning.append(war)
        rpref = convert_preferenceRA_to_numeric("High")
    
    # Period
    if is_non_negative_float(duration_aggressive):
        if period is None:
            period = duration_aggressive / 10
            war = f"Missing period (RA sending rate), so it is set to: 1 RA /{period} s"
            list_warning.append(war)
        if period is not None:
            if not is_non_negative_float(period):
                err = "Invalid period (RA sending rate). Program exits!"
                list_error.append(err)
            elif float(period) > float(duration_aggressive):
                err = "Period (RA sending rate) must be smaller than aggressive duration. Program exits!"
                list_error.append(err)
    if not is_non_negative_float(duration_aggressive) and period is not None and not is_non_negative_float(period):
        err = "Invalid period (RA sending rate). Program exits!"
        list_error.append(err)
    
    # Current hop limit
    if chl is None:
        chl = 0
        war = "Missing current hop limit, so it is set to: 0"
        list_warning.append(war)
    if chl is not None:
        if is_valid_integer(chl):
            chl = int(chl)
        else:
            err = "Invalid current hop limit. Program exits!"
            list_error.append(err)
    
    # MTU
    if mtu is None:
        mtu = None
        war = "Missing MTU, so this option is ignored"
        list_warning.append(war)
    if mtu is not None:
        if is_valid_MTU(mtu):
            mtu = int(mtu)
        else:
            err = "Invalid MTU. Program exits!"
            list_error.append(err)
    
    # DNS
    if dns is None:
        dns = None
        war = "Missing DNS address, so this option is ignored"
        list_warning.append(war)
    if dns is not None:
        for i in range(len(dns)):
            if not is_valid_ipv6(dns[i]):
                err = "Invalid DNS address. Program exits!"
                list_error.append(err)
                break
    
    return duration_aggressive, prefix_len, network, smac, sip, rpref, period, chl, mtu, dns


def _print_errors(list_error, json_output, more_detail) -> None:
    """Print accumulated errors and exit."""
    # Ensure stdout is restored (in case blockPrint was applied earlier)
    enablePrint()
    # JSON mode: if -vv (more_detail), print both terminal errors and JSON object
    if json_output:
        if more_detail:
            Non_json.print_box("Errors about inserted parameters")
            for info in list_error:
                ptprinthelper.ptprint(info, "ERROR", condition=True, indent=4)
            # Print JSON error next
            print(ptjsonlib_object.end_error(list_error, ptjsonlib_object))
            # Then show help
            ptprinthelper.help_print(get_help(), SCRIPTNAME, __version__)
            sys.exit(0)
        else:
            # -j without -vv: emit only JSON error payload
            print(ptjsonlib_object.end_error(list_error, ptjsonlib_object))
            sys.exit(0)

    # Text mode only
    Non_json.print_box("Errors about inserted parameters")
    for info in list_error:
        ptprinthelper.ptprint(info, "ERROR", condition=True, indent=4)
    ptprinthelper.help_print(get_help(), SCRIPTNAME, __version__)
    sys.exit(0)


def _print_warnings(list_warning, json_output, more_detail, less_detail) -> None:
    """Print accumulated warnings."""
    GREY = "\033[90m"
    END = "\033[0m"
    if (not json_output or more_detail) and not less_detail:
        if len(list_warning) >= 1:
            Non_json.print_box("Warning about inserted parameters")
            for info in list_warning:
                ptprinthelper.ptprint(f"{GREY}{info}{END}", "WARNING", condition=True, indent=4)


def _print_parameter_info(interface, ip_mode, json_output, type, more_detail, less_detail, check_addresses, duration_passive, duration_aggressive, network, prefix_len, smac, sip, rpref, period, chl, mtu, dns, nofwd, target_codes, target_macs, tmp_retention) -> None:
    """Print information about inserted parameters."""
    if not less_detail:
        Non_json.print_box("Information about inserted parameters")
        ptprinthelper.ptprint(f"Interface: {interface}", "INFO", condition=True, indent=4)
        if ip_mode.ipv4 and ip_mode.ipv6:
            ptprinthelper.ptprint("IPv4 and IPv6 mode", "INFO", condition=True, indent=4)
        elif ip_mode.ipv4 and not ip_mode.ipv6:
            ptprinthelper.ptprint("IPv4-only mode", "INFO", condition=True, indent=4)
        elif ip_mode.ipv6 and not ip_mode.ipv4:
            ptprinthelper.ptprint("IPv6-only mode", "INFO", condition=True, indent=4)
        if json_output:
            ptprinthelper.ptprint("Allowing json output", "INFO", condition=True, indent=4)
        if not json_output:
            ptprinthelper.ptprint("Disabling json output", "INFO", condition=True, indent=4)
        ptprinthelper.ptprint("Temporary files are deleted after all", "INFO", condition=True, indent=4)
        
        for ele in type:
            if ele == "802.1x":
                ptprinthelper.ptprint(f"Using mode {ele}", "INFO", condition=True, indent=4)
            if ele == "p":
                ptprinthelper.ptprint(f"Using mode passive", "INFO", condition=True, indent=4)
            if ele == "a":
                ptprinthelper.ptprint(f"Using mode active", "INFO", condition=True, indent=4)
            if ele == "a+":
                ptprinthelper.ptprint(f"Using mode aggressive", "INFO", condition=True, indent=4)
        
        if more_detail:
            ptprinthelper.ptprint("Displaying full detail (except for mode 802.1x)", "INFO", condition=True, indent=4)
        if not more_detail:
            ptprinthelper.ptprint("Displaying only basic detail (except for mode 802.1x)", "INFO", condition=True, indent=4)
        if check_addresses:
            ptprinthelper.ptprint("Checking the found addresses if they are valid or not", "INFO", condition=True, indent=4)
        if not check_addresses:
            ptprinthelper.ptprint("Not checking the found addresses if they are valid or not", "INFO", condition=True, indent=4)
        
        if "p" in type:
            ptprinthelper.ptprint(f"Passive duration: {duration_passive}s", "INFO", condition=True, indent=4)
        if "a" in type:
            ptprinthelper.ptprint(f"Source MAC used in active mode: {smac}", "INFO", condition=True, indent=4)
        if "a+" in type:
            ptprinthelper.ptprint(f"Aggressive duration (time being the fake router): {duration_aggressive}s", "INFO", condition=True, indent=4)
            ptprinthelper.ptprint(f"Network prefix used in aggressive mode: {network}/{prefix_len}", "INFO", condition=True, indent=4)
            ptprinthelper.ptprint(f"Source MAC used in aggressive mode: {smac}", "INFO", condition=True, indent=4)
            ptprinthelper.ptprint(f"Source IP used in aggressive mode: {sip}", "INFO", condition=True, indent=4)
            ptprinthelper.ptprint(f"Preference flag of RA used in aggressive mode: {convert_preferenceRA(rpref)}", "INFO", condition=True, indent=4)
            ptprinthelper.ptprint(f"Sending rate of RA used in aggressive mode: 1 packet per {period}s", "INFO", condition=True, indent=4)
            ptprinthelper.ptprint(f"Current hop limit of RA used in aggressive mode: {chl}", "INFO", condition=True, indent=4)
            ptprinthelper.ptprint(f"MTU of RA used in aggressive mode: {mtu}", "INFO", condition=True, indent=4)
            ptprinthelper.ptprint(f"DNS of RA used in aggressive mode: {dns}", "INFO", condition=True, indent=4)
            if not nofwd:
                ptprinthelper.ptprint("Packets to remote network will be forwarded through the scanner in aggressive mode", "INFO", condition=True, indent=4)
            if nofwd:
                ptprinthelper.ptprint("Packets to remote network will be dropped at the scanner in aggressive mode", "INFO", condition=True, indent=4)
        if target_codes:
            ptprinthelper.ptprint(f"Target vulnerability test(s): {sorted(target_codes)}", "INFO", condition=True, indent=4)

        if target_macs:
            ptprinthelper.ptprint(f"Target devices (MAC addresses): {sorted(m.lower() for m in target_macs)}", "INFO", condition=True, indent=4)

        ptprinthelper.ptprint(f"Temporary file retention: {tmp_retention}s", "INFO", condition=True, indent=4)


# ============================================================================
# SECTION 5: MAIN PARAMETER CONTROL FUNCTION
# ============================================================================

def parameter_control(
    interface,
    json_output,
    type,
    more_detail,
    less_detail,
    check_addresses,
    ipv4,
    ipv6,
    duration_passive,
    duration_aggressive,
    prefix,
    smac,
    sip,
    rpref,
    period,
    chl,
    mtu,
    dns,
    nofwd,
    target_codes,
    tmp_retention,
    target_macs,
) -> tuple:
    """
    Checks and validates inserted parameters. Returns all variables if no error, otherwise prints errors and exits.

    output: tuple of validated parameters
    description: Validates arguments for scan modes, prints warnings/errors, and returns standardized parameter set.
    """
    list_error: list[str] = []
    list_warning: list[str] = []

    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

    _validate_mandatory_args(type, interface, json_output, more_detail, target_codes)
    _validate_type_combination(type, json_output, more_detail)
    _validate_interface(interface, json_output, more_detail)

    ip_mode = IPMode(ipv4, ipv6) if (ipv4 or ipv6) else IPMode(False, True)

    _validate_detail_flags(more_detail, less_detail, json_output)

    try:
        tmp_retention = float(tmp_retention) if tmp_retention is not None else 1800.0
        if tmp_retention <= 0:
            raise ValueError
    except (TypeError, ValueError):
        tmp_retention = 1800.0
        list_warning.append("Temporary file retention must be > 0; using default 1800s")

    validated_target_codes = None
    inferred_type = type
    inferred_ip_mode = ip_mode

    if target_codes:
        validation_result = _validate_target_codes(target_codes, type, ip_mode, ipv4, ipv6, list_error, list_warning)
        if validation_result is not None:
            test_codes, inferred_type, inferred_ip_mode, _ = validation_result
            validated_target_codes = test_codes
            if not type:
                type = inferred_type
            if not (ipv4 or ipv6) and inferred_ip_mode:
                ip_mode = inferred_ip_mode

    _require_fakera_params(validated_target_codes, prefix, dns, list_error)

    if type is None:
        type = inferred_type if inferred_type else ["a"]

    prefix_len = None
    network = None

    if type == ["p"] or ("p" in type and "802.1x" in type):
        duration_passive = _validate_passive_mode(duration_passive, duration_aggressive, prefix, smac, sip, rpref, period, chl, mtu, dns, nofwd, list_error, list_warning)
    elif type == ["802.1x"]:
        _validate_802_1x_mode(duration_passive, duration_aggressive, prefix, smac, sip, rpref, period, chl, mtu, dns, nofwd, list_error)
    elif type == ["a"] or ("a" in type and "802.1x" in type and len(type) == 2):
        smac = _validate_active_mode(interface, duration_passive, duration_aggressive, prefix, sip, rpref, period, chl, mtu, dns, smac, nofwd, list_error, list_warning)
    if type == ["a+"] or ("a+" in type and ("802.1x" in type or "a" in type)):
        duration_aggressive, prefix_len, network, smac, sip, rpref, period, chl, mtu, dns = _validate_aggressive_mode(
            interface, ip_mode, duration_passive, duration_aggressive, prefix, smac, sip, rpref, period, chl, mtu, dns, nofwd, list_error, list_warning
        )

    if list_error:
        _print_errors(list_error, json_output, more_detail)

    if duration_aggressive is not None:
        duration_aggressive = float(duration_aggressive)
    if period is not None:
        period = float(period)

    validated_target_macs = None
    if target_macs:
        # Flatten when -target provided multiple times with nargs+ (list of lists)
        flat_targets = []
        for item in target_macs:
            if isinstance(item, list):
                flat_targets.extend(item)
            else:
                flat_targets.append(item)
        normalized = set()
        for mac in flat_targets:
            mac_upper = mac.upper()
            if not is_valid_mac(mac_upper):
                list_error.append(f"Invalid MAC address: {mac}")
            else:
                normalized.add(mac_upper)
        if list_error:
            _print_errors(list_error, json_output, more_detail)
        if normalized:
            validated_target_macs = normalized

    if json_output and not (more_detail or less_detail):
        blockPrint()

    if not list_error:
        _print_warnings(list_warning, json_output, more_detail, less_detail)

    _print_parameter_info(
        interface,
        ip_mode,
        json_output,
        type,
        more_detail,
        less_detail,
        check_addresses,
        duration_passive,
        duration_aggressive,
        network,
        prefix_len,
        smac,
        sip,
        rpref,
        period,
        chl,
        mtu,
        dns,
        nofwd,
        validated_target_codes,
        validated_target_macs,
        tmp_retention,
    )

    return (
        interface,
        json_output,
        type,
        more_detail,
        less_detail,
        check_addresses,
        ip_mode,
        duration_passive,
        duration_aggressive,
        prefix_len,
        network,
        smac,
        sip,
        rpref,
        period,
        chl,
        mtu,
        dns,
        nofwd,
        validated_target_codes,
        tmp_retention,
        validated_target_macs,
    )
