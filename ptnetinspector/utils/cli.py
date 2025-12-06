import argparse
import logging
import os
import subprocess
import sys

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
    parser.add_argument("-n", action="store_false")
    parser.add_argument("-more", action="store_true", default=False)
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
        {"description": ["Scanner for IPv6 networks"]},
        {"usage": ["ptnetinspector -t 802.1x/a/a+/p -i eth0 -j -less"]},
        {"General options (applied to all)": [
            ["-t", "     Type of scan (first mandatory argument, user can choose more than 1 option):"],
            [" => 802.1x", "", "       Network test for 802.1x protocol"],
            [" => a", "", "       Active mode for scanning of network"],
            [" => a+", "", "       Aggressive mode for scanning of network"],
            [" => p", "", "       Passive mode for scanning of network"],
            ["-i", "     Interface (second mandatory argument)"],
            ["-j", "     Output in JSON format. If being used without option more, only json output is printed (+ errors if there are errors)."],
            ["-n", "     Does not delete .csv files in tmp folder"],
            ["-more", "     Shows full details of network scan. Only default data is displayed if not used. If being used together with option j, details output + json output are given."],
            ["-less", "     Shows minimum details of network scan. Default data is displayed if not used. If being used together with option j, minimum details output + json output are given."],
            ["-nc", "     Does not check the found addresses if they are valid or not. Default is checking if not used by filtering addresses from unknown subnets or non-unicast addresses and probing them using neighbour discovery"],
            ["-4", "     Only IPv4 traffic is allowed. Results are limited only to IPv4 addresses. Cannot be applied for aggressive mode if parameter '-6' not used. Default is both IPv4 and IPv6 traffic when IP version not specified"],
            ["-6", "     Only IPv6 traffic is allowed. Results are limited only to IPv6 addresses. Default is both IPv4 and IPv6 traffic when IP version not specified"],
            ["-h", "     Shows this help message and exits"]
        ]},
        {"Specific options (for Passive scan)": [
            ["-d", "             The duration of passive scan (in second, float number allowed). Default value: 30 seconds"]
        ]},
        {"Specific options (for Aggressive scan)": [
            ["-da+", "        The duration of aggressive scan (in second, float number allowed). Default value: 30 seconds"],
            ["-prefix", "        The prefix advertised by scanner in aggressive mode. Default value: fe80::/64"],
            ["-smac", "        The scanner's MAC in aggressive mode. Default value: Scanner's MAC taken from interface determined by -i argument"],
            ["-sip", "        The scanner's IPv6 in aggressive mode. Default value: Scanner's IP taken from interface determined by -i argument. Link-local address is preferred the most"],
            ["-rpref", "        The router preference flag (Reserved, Low, Medium, High) in aggressive mode. Default value: High"],
            ["-period",
             "        The RA sending rate (1 packet per [-period] second, float number allowed). Default value: Aggressive duration /10"],
            ["-chl", "        The current hop limit in RA message. Default value: 0"],
            ["-mtu", "        The MTU broadcasting on the link. This option is not included if not used"],
            ["-dns", "        The IPv6 address of DNS server. If user wants more than one address, just write addresses separated by spaces. This option is not included if not used"],
            ["-nofwd", "        Does not allow the scanner to forward packets through him in aggressive mode. Allowing to forward (MiTM) if not used"]

        ]},
        {"Examples for all modes": [
            ["802.1x:",
             "   The attacker first sends EAPOL-Start and wait for any responses"],
            ["", "   Example: Running 802.1x mode from scanner with interface eth0, json output is allowed"],
            ["", "       => ptnetinspector -t 802.1x -i eth0 -j"],
            ["", "   Example: Running 802.1x mode from scanner with interface eth0, json output is allowed with minimum details of scanning"],
            ["", "       => ptnetinspector -t 802.1x -i eth0 -less -j"],
            ["Passive:",
             "   The attacker deactivates outgoing traffic from assigned interface, disables IP and sniffs incoming packets"],
            ["", "   Example: Running passive mode from scanner with interface eth0, with minimum details of scanning"],
            ["", "       => ptnetinspector -t p -i eth0 -less"],
            ["", "   Example: Running passive mode from scanner with interface eth0, json output is allowed with minimum details of scanning"],
            ["", "       => ptnetinspector -t p -i eth0 -less -j"],
            ["Active:",
            "   The attacker performs testing vulnerabilities with several types of packets (MLD, ICMPv6, LLMNR, mDNS, IGMP, ICMP, DHCP, DHCPv6, WS-Discovery...)"],
            ["", "   Example: Running active mode from scanner with interface eth0, with full details of network scan"],
            ["", "       => ptnetinspector -t a -i eth0 -more"],
            ["", "   Example: Running active mode from scanner with interface eth0, json output is allowed with minimum details of scanning"],
            ["", "       => ptnetinspector -t a -i eth0 -less -j"],
            ["Aggressive:",
             "   More than active scanning, the attacker does several tests as a fake router"],
            ["", "   Example: Running aggressive mode from scanner with interface eth0, json output is allowed. Other information such as prefix, MAC, IPv6... are set as shown below"],
            ["", "       => ptnetinspector -t a+ -i eth0 -j -da+ 35 -prefix 2001::/64 -smac 00:01:02:03:04:05 -sip fe80::1 -period 5"],
            ["", "   Example: Running aggressive mode from scanner with interface eth0, json output is allowed with minimum details about scanning. Prefix is set to 2001:a:b:1::/64"],
            ["", "       => ptnetinspector -t a+ -i eth0 -less -j -da+ 5 -prefix 2001:a:b:1::/64"],
            ["Combination:",
            "   Several modes can be combined to make a more complex scan (802.1x and passive in this example)"],
            ["",
             "   Example: Running 802.1x and passive mode from scanner with interface eth0, json output is allowed. Passive duration is set to 10s"],
            ["","       => ptnetinspector -t 802.1x p -i eth0 -j -d 10"]
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

def _validate_mandatory_args(type, interface, json_output, more_detail) -> None:
    """Validate mandatory arguments (type and interface)."""
    if not type or not interface:
        if not json_output or more_detail:
            ptprinthelper.ptprint("Missing compulsory parameters (type, interface)", "ERROR")
        if json_output:
            print(ptjsonlib_object.end_error("Missing compulsory parameters (type, interface)", ptjsonlib_object))
        ptprinthelper.help_print(get_help(), SCRIPTNAME, __version__)
        sys.exit(1)


def _validate_type_combination(type, json_output, more_detail) -> None:
    """Validate scan type combinations."""
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
    if not json_output or more_detail:
        Non_json.print_box("Errors about inserted parameters")
        for info in list_error:
            ptprinthelper.ptprint(info, "ERROR")
    if json_output:
        print(ptjsonlib_object.end_error(list_error, ptjsonlib_object))
    ptprinthelper.help_print(get_help(), SCRIPTNAME, __version__)
    sys.exit(0)


def _print_warnings(list_warning, json_output, more_detail, less_detail) -> None:
    """Print accumulated warnings."""
    if (not json_output or more_detail) and not less_detail:
        if len(list_warning) >= 1:
            Non_json.print_box("Warning about inserted parameters")
            for info in list_warning:
                ptprinthelper.ptprint(info, "WARNING")


def _print_parameter_info(interface, ip_mode, json_output, del_tmp, type, more_detail, less_detail, check_addresses, duration_passive, duration_aggressive, network, prefix_len, smac, sip, rpref, period, chl, mtu, dns, nofwd) -> None:
    """Print information about inserted parameters."""
    if not less_detail:
        Non_json.print_box("Information about inserted parameters")
        ptprinthelper.ptprint("Interface: " + interface, "INFO")
        if ip_mode.ipv4 and ip_mode.ipv6:
            ptprinthelper.ptprint("IPv4 and IPv6 mode", "INFO")
        elif ip_mode.ipv4 and not ip_mode.ipv6:
            ptprinthelper.ptprint("IPv4-only mode", "INFO")
        elif ip_mode.ipv6 and not ip_mode.ipv4:
            ptprinthelper.ptprint("IPv6-only mode", "INFO")
        if json_output:
            ptprinthelper.ptprint("Allowing json output", "INFO")
        if not json_output:
            ptprinthelper.ptprint("Disabling json output", "INFO")
        if not del_tmp:
            ptprinthelper.ptprint("Temporary files are not deleted after all", "INFO")
        if del_tmp:
            ptprinthelper.ptprint("Temporary files are deleted after all", "INFO")
        
        for ele in type:
            if ele == "802.1x":
                ptprinthelper.ptprint(f"Using mode {ele}", "INFO")
            if ele == "p":
                ptprinthelper.ptprint(f"Using mode passive", "INFO")
            if ele == "a":
                ptprinthelper.ptprint(f"Using mode active", "INFO")
            if ele == "a+":
                ptprinthelper.ptprint(f"Using mode aggressive", "INFO")
        
        if more_detail:
            ptprinthelper.ptprint(f"Displaying full detail (except for mode 802.1x)", "INFO")
        if not more_detail:
            ptprinthelper.ptprint(f"Displaying only basic detail (except for mode 802.1x)", "INFO")
        if check_addresses:
            ptprinthelper.ptprint("Checking the found addresses if they are valid or not", "INFO")
        if not check_addresses:
            ptprinthelper.ptprint("Not checking the found addresses if they are valid or not", "INFO")
        
        if "p" in type:
            ptprinthelper.ptprint(f"Passive duration: {duration_passive}s", "INFO")
        if "a" in type:
            ptprinthelper.ptprint(f"Source MAC used in active mode: {smac}", "INFO")
        if "a+" in type:
            ptprinthelper.ptprint(f"Aggressive duration (time being the fake router): {duration_aggressive}s", "INFO")
            ptprinthelper.ptprint(f"Network prefix used in aggressive mode: {network}/{prefix_len}", "INFO")
            ptprinthelper.ptprint(f"Source MAC used in aggressive mode: {smac}", "INFO")
            ptprinthelper.ptprint(f"Source IP used in aggressive mode: {sip}", "INFO")
            ptprinthelper.ptprint(f"Preference flag of RA used in aggressive mode: {convert_preferenceRA(rpref)}", "INFO")
            ptprinthelper.ptprint(f"Sending rate of RA used in aggressive mode: 1 packet per {period}s", "INFO")
            ptprinthelper.ptprint(f"Current hop limit of RA used in aggressive mode: {chl}", "INFO")
            ptprinthelper.ptprint(f"MTU of RA used in aggressive mode: {mtu}", "INFO")
            ptprinthelper.ptprint(f"DNS of RA used in aggressive mode: {dns}", "INFO")
            if not nofwd:
                ptprinthelper.ptprint(f"Packets to remote network will be forwarded through the scanner in aggressive mode", "INFO")
            if nofwd:
                ptprinthelper.ptprint(f"Packets to remote network will be dropped at the scanner in aggressive mode", "INFO")


# ============================================================================
# SECTION 5: MAIN PARAMETER CONTROL FUNCTION
# ============================================================================

def parameter_control(
    interface,
    json_output,
    del_tmp,
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
    nofwd
) -> tuple:
    """
    Checks and validates inserted parameters. Returns all variables if no error, otherwise prints errors and exits.

    output: tuple of validated parameters
    description: Validates arguments for scan modes, prints warnings/errors, and returns standardized parameter set.
    """
    list_error = []
    list_warning = []

    # Turning off logging
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

    # Validate mandatory arguments
    _validate_mandatory_args(type, interface, json_output, more_detail)
    _validate_type_combination(type, json_output, more_detail)
    _validate_interface(interface, json_output, more_detail)

    # Setup IP mode
    if not ipv4 and not ipv6:
        ip_mode = IPMode(True, True)
    else:
        ip_mode = IPMode(ipv4, ipv6)

    _validate_detail_flags(more_detail, less_detail, json_output)

    # Validate mode-specific parameters
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

    # Print errors and exit if any
    if len(list_error) >= 1:
        _print_errors(list_error, json_output, more_detail)

    if json_output and not (more_detail or less_detail):
        blockPrint()

    _print_warnings(list_warning, json_output, more_detail, less_detail)

    if duration_aggressive is not None:
        duration_aggressive = float(duration_aggressive)
    if period is not None:
        period = float(period)

    _print_parameter_info(interface, ip_mode, json_output, del_tmp, type, more_detail, less_detail, check_addresses, duration_passive, duration_aggressive, network, prefix_len, smac, sip, rpref, period, chl, mtu, dns, nofwd)

    return (
        interface, json_output, del_tmp, type, more_detail, less_detail, check_addresses,
        ip_mode, duration_passive, duration_aggressive, prefix_len, network, smac, sip,
        rpref, period, chl, mtu, dns, nofwd
    )