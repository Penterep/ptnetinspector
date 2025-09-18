from netaddr import IPNetwork
import netifaces
import logging
import sys
import os
from src.interface import Interface
from libs.convert import convert_preferenceRA_to_numeric, convert_preferenceRA
from ptlibs import ptprinthelper
from libs.check import check_prefRA, is_non_negative_float, is_valid_MTU, is_valid_integer, is_valid_ipv6, is_valid_ipv6_prefix, is_valid_mac
from scapy.all import get_if_hwaddr

from src.output.non_json import Non_json
from src.send import IPMode

from ptlibs.ptjsonlib import PtJsonLib
ptjsonlib_object = PtJsonLib()

__version__ = "0.1.5"
SCRIPTNAME = "ptnetinspector"

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

def blockPrint() -> None:
    """
    Disables printing to stdout.

    output: None
    description: Redirects sys.stdout to os.devnull to suppress output.
    """
    sys.stdout = open(os.devnull, 'w')

def enablePrint() -> None:
    """
    Restores printing to stdout.

    output: None
    description: Restores sys.stdout to its original value.
    """
    sys.stdout = sys.__stdout__

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

    # Check if mandatory arguments are empty
    if not type or not interface:
        if not json_output or more_detail:
            ptprinthelper.ptprint("Missing compulsory parameters (type, interface)", "ERROR")
        if json_output:
            print(ptjsonlib_object.end_error("Missing compulsory parameters (type, interface)", ptjsonlib_object))
        ptprinthelper.help_print(get_help(), SCRIPTNAME, __version__)
        sys.exit(1)

    # Check if suitable combination
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

    if interface is not None:
        valid_interface = netifaces.interfaces()
        if interface not in valid_interface:
            err = f"Invalid inserted interface: {interface}. Program exits!"
            list_error.append(err)
            if not json_output or more_detail:
                ptprinthelper.ptprint(err, "ERROR")
            if json_output:
                print(ptjsonlib_object.end_error(err, ptjsonlib_object))
            sys.exit(1)

    if not ipv4 and not ipv6:
        ip_mode = IPMode(True, True)
    else:
        ip_mode = IPMode(ipv4, ipv6)

    if more_detail and less_detail:
        err = "Showing full detail and less detail can not be set at the same time. Program exits!"
        list_error.append(err)
        if not json_output or more_detail:
            ptprinthelper.ptprint(err, "ERROR")
        if json_output:
            print(ptjsonlib_object.end_error(err, ptjsonlib_object))
        sys.exit(1)

    # Control parameter type: passive, active, aggressive, and combination
    if type == ["p"] or ("p" in type and "802.1x" in type):
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
        prefix_len = None
        network = None

    elif type == ["802.1x"]:
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
        prefix_len = None
        network = None

    elif type == ["a"] or ("a" in type and "802.1x" in type and len(type) == 2):
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
        prefix_len = None
        network = None
        if not Interface(interface).check_available_ipv6():
            err = f"No available IP on the interface: {interface}. Program exits!"
            list_error.append(err)

    if type == ["a+"] or ("a+" in type and ("802.1x" in type or "a" in type)):
        if not ip_mode.ipv6:
            err = "IPv6 mode is required for aggressive mode. Program exits!"
            list_error.append(err)
        if duration_passive is not None:
            list_error.append("Passive duration is not applied in this mode. Program exits!")
        if duration_aggressive is None:
            duration_aggressive = 30
            war = f"Missing aggressive duration, so the default value is chosen: {duration_aggressive} s"
            list_warning.append(war)
        if duration_aggressive is not None and not is_non_negative_float(duration_aggressive):
            err = "Invalid aggressive duration. Program exits!"
            list_error.append(err)
        else:
            duration_aggressive = float(duration_aggressive)
        if not is_valid_ipv6_prefix(prefix):
            if prefix is None:
                war = "Missing prefix, so the prefix is set to: fe80::/64"
                list_warning.append(war)
                prefix_len = 64
                network = "fe80::"
            else:
                err = "Invalid inserted network prefix. Program exits!"
                list_error.append(err)
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

    # Exit program if any error happens
    if len(list_error) >= 1:
        if not json_output or more_detail:
            Non_json.print_box("Errors about inserted parameters")
            for info in list_error:
                ptprinthelper.ptprint(info, "ERROR")
        if json_output:
            print(ptjsonlib_object.end_error(list_error, ptjsonlib_object))
        ptprinthelper.help_print(get_help(), SCRIPTNAME, __version__)
        sys.exit(0)

    if json_output and not (more_detail or less_detail):
        blockPrint()

    if (not json_output or more_detail) and not less_detail:
        if len(list_warning) >= 1:
            Non_json.print_box("Warning about inserted parameters")
            for info in list_warning:
                ptprinthelper.ptprint(info, "WARNING")

    if duration_aggressive is not None:
        duration_aggressive = float(duration_aggressive)
    if period is not None:
        period = float(period)

    # Informing about true inserted parameters
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

    return (
        interface, json_output, del_tmp, type, more_detail, less_detail, check_addresses,
        ip_mode, duration_passive, duration_aggressive, prefix_len, network, smac, sip,
        rpref, period, chl, mtu, dns, nofwd
    )
