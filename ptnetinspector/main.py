#!/usr/bin/env python3
"""ptnetinspector main entrypoint.

This module orchestrates CLI parsing, scan execution (802.1x/passive/active/aggressive),
tmp/cache management, and final JSON/text output. It wires together utilities from
`utils`, emits human-friendly terminal output via `output.non_json`, and produces the
final normalized JSON via `output.json` by reading the accumulated CSVs.
"""
import signal
import sys
import warnings
import json

from ptnetinspector.output.json import Json
from ptnetinspector.output.non_json import Non_json
from ptnetinspector.scan import Run
from ptnetinspector.utils.address_control import delete_tmp_mapping_file
from ptnetinspector.utils.cli import enablePrint, parameter_control, parse_args
from ptnetinspector.utils.csv_helpers import create_csv, sort_all_csv, has_additional_data
from ptnetinspector.utils.interface import Interface, IptablesRule
from ptnetinspector.utils.oui import create_vendor_csv
from ptnetinspector.utils.path import del_tmp_path, get_csv_path, get_output_dir, get_tmp_path, set_current_interface
from ptnetinspector.utils.lock import acquire_global_lock
from ptnetinspector.utils.runtime import (
    build_run_signature,
    check_interface_status,
    delete_json_output,
    configure_output_flags,
    delete_text_output,
    handle_addresses,
    handle_output,
    prepare_networks_file,
    prepare_tmp_files,
    print_message,
    ptprint_info_warning,
    start_output_logging,
    stop_output_logging,
    terminate_child_processes,
    write_run_signature,
    load_run_signature,
    _suppress_non_json,
)
from ptnetinspector.vulnerability import Vulnerability
from ptlibs import ptprinthelper
from ptlibs.ptjsonlib import PtJsonLib

warnings.simplefilter(action="ignore", category=FutureWarning)
warnings.filterwarnings("ignore")

ptjsonlib_object = PtJsonLib()
args = parse_args()

# Determine lock verbosity: suppress if -j and not -vv
lock_verbose = not (getattr(args, 'j', False) and not getattr(args, 'vv', False))
# Acquire global lock - will wait and queue if another instance is running
acquire_global_lock(verbose=lock_verbose)


def custom_signal_handler(sig, frame):
    raise KeyboardInterrupt()


signal.signal(signal.SIGINT, custom_signal_handler)

(
    interface,
    json_output,
    scanning_type,
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
    target_codes,
    tmp_retention,
    target_macs,
) = parameter_control(
    args.interface,
    args.j,
    args.t,
    args.vv,
    args.less,
    args.nc,
    args.ipv4,
    args.ipv6,
    args.d,
    args.duration_router,
    args.prefix,
    args.smac,
    args.sip,
    args.rpref,
    args.period,
    args.chl,
    args.mtu,
    args.dns,
    args.nofwd,
    args.target_codes,
    args.tmp_retention,
    args.target_macs,
)

REUSE_EXISTING_DATA = False

Interface_object = Interface(interface)
Vulnerability_object = None  # Will be initialized in main() after setting interface context

# Global accumulator for JSON results when running multiple modes
_accumulated_json_result = None


def setup_iptables(rule_type):
    if not IptablesRule.check(rule_type, ip_mode.ipv4, ip_mode.ipv6, nofwd if rule_type == "a+" else False):
        IptablesRule.add(rule_type, ip_mode.ipv4, ip_mode.ipv6, nofwd if rule_type == "a+" else False)
        if rule_type == "a":
            print_message("Adding rules in configuration to perform active scanning", condition=True, indent=4)
        elif rule_type == "a+":
            print_message("Adding rules in configuration to perform aggressive scanning", condition=True, indent=4)


def cleanup_iptables(rule_type):
    if IptablesRule.check(rule_type, ip_mode.ipv4, ip_mode.ipv6, nofwd if rule_type == "a+" else False):
        IptablesRule.remove(True, rule_type, ip_mode.ipv4, ip_mode.ipv6)
        if rule_type == "a":
            print_message("Removing rules in configuration after scanning", condition=True, indent=0)


def check_eap_detected():
    eap_file = get_csv_path("eap.csv", interface)
    if has_additional_data(eap_file):
        ptprinthelper.ptprint("\033[90m802.1x is detected, so scan will be cancelled\033[0m", "WARNING", condition=True, indent=4)
        if json_output:
            Non_json.print_box("Json output")
            print(Json.output_object(True, "802.1x", target_codes=target_codes, ipver=ip_mode))
        sys.exit(0)


def cleanup_and_exit():
    sys.exit()


def ptnet_eap(combine=False):
    from ptnetinspector.utils.runtime import _suppress_non_json
    global _accumulated_json_result
    if REUSE_EXISTING_DATA:
        print_message("Reusing cached 802.1x results (within retention window)", indent=4)
        if not _suppress_non_json:
            eap_file = get_csv_path("eap.csv", interface)
            Non_json.output_protocol(interface, ip_mode, "802.1x", "802.1x", eap_file, less_detail)
            if more_detail:
                ptprint_info_warning("802.1x scan (cached)", "INFO", condition=True)
        if json_output and not combine:
            enablePrint()
        return

    Run.run_normal_mode(interface, "802.1x", ip_mode, 3)
    create_vendor_csv()
    Vulnerability_object.handle_vulnerabilities("802.1x")

    if not _suppress_non_json:
        eap_file = get_csv_path("eap.csv", interface)
        Non_json.output_protocol(interface, ip_mode, "802.1x", "802.1x", eap_file, less_detail)
        if more_detail:
            ptprint_info_warning("802.1x scan (cached)", "INFO", condition=True)

    # Accumulate JSON result (don't print yet if multiple modes)
    if json_output:
        if not combine:
            enablePrint()
        _accumulated_json_result = Json.output_object(True, "802.1x", target_codes=target_codes, ipver=ip_mode)


def ptnet_passive():
    from ptnetinspector.utils.runtime import _suppress_non_json
    if not _suppress_non_json:
        Non_json.print_box("Passive scan running")

    if not REUSE_EXISTING_DATA:
        check_interface_status(Interface_object, interface)
        prepare_networks_file(interface, get_csv_path("networks.csv", interface))
        Run.run_normal_mode(interface, "p", ip_mode, duration_passive)
        handle_addresses(interface, ip_mode, passive=True)
        create_vendor_csv()
        sort_all_csv(interface)
        Vulnerability_object.handle_vulnerabilities("p")
    else:
        print_message("Reusing cached passive results (within retention window)", indent=4)

    protocols_basic = ["MDNS", "LLMNR", "WS-Discovery", "MLDv1", "MLDv2", "IGMPv1/v2", "IGMPv3"]
    protocols_detailed = ["RA"]
    handle_output(
        "p",
        protocols_basic,
        protocols_detailed,
        json_output,
        more_detail,
        less_detail,
        check_addresses,
        interface,
        ip_mode,
        target_codes,
        lambda fname: get_csv_path(fname, interface),
        target_macs,
    )

    # Accumulate JSON result (don't print yet if multiple modes)
    if json_output:
        global _accumulated_json_result
        _accumulated_json_result = Json.output_object(True, "p", target_codes=target_codes, ipver=ip_mode)


def ptnet_active():
    from ptnetinspector.utils.runtime import _suppress_non_json
    if not _suppress_non_json:
        Non_json.print_box("Active scan running")

    if not REUSE_EXISTING_DATA:
        check_interface_status(Interface_object, interface)
        prepare_networks_file(interface, get_csv_path("networks.csv", interface))
        setup_iptables("a")
        Run.run_normal_mode(interface, "a", ip_mode, None)
        handle_addresses(interface, ip_mode)
        create_vendor_csv()
        sort_all_csv(interface)
        Vulnerability_object.handle_vulnerabilities("a")
    else:
        print_message("Reusing cached active results (within retention window)", indent=4)

    protocols_basic = ["MDNS", "LLMNR", "WS-Discovery", "MLDv1", "MLDv2", "IGMPv1/v2", "IGMPv3"]
    protocols_detailed = ["RA"]
    handle_output(
        "a",
        protocols_basic,
        protocols_detailed,
        json_output,
        more_detail,
        less_detail,
        check_addresses,
        interface,
        ip_mode,
        target_codes,
        lambda fname: get_csv_path(fname, interface),
        target_macs,
    )


def ptnet_aggressive():
    from ptnetinspector.utils.runtime import _suppress_non_json
    if not _suppress_non_json:
        Non_json.print_box("Aggressive scan running")

    if not REUSE_EXISTING_DATA:
        check_interface_status(Interface_object, interface)
        prepare_networks_file(interface, get_csv_path("networks.csv", interface))
        setup_iptables("a")
        setup_iptables("a+")

        if not Interface_object.check_available_ipv6():
            generated_ip = Interface.generate_ipv6_address("fe80::")
            Interface_object.set_ipv6_address(generated_ip)
            print_message("No IP available on interface, so a random IP is generated", condition=True, indent=4)

        Run.run_aggressive_mode(
            interface,
            ip_mode,
            prefix_len,
            network,
            smac,
            sip,
            rpref,
            duration_aggressive,
            period,
            chl,
            mtu,
            dns,
        )
        handle_addresses(interface, ip_mode)
        create_vendor_csv()
        sort_all_csv(interface)
        Vulnerability_object.handle_vulnerabilities("a+")
    else:
        print_message("Reusing cached aggressive results (within retention window)", indent=4)

    protocols_basic = ["MDNS", "LLMNR", "WS-Discovery", "MLDv1", "MLDv2", "IGMPv1/v2"]
    protocols_detailed = ["MLDv2", "IGMPv3", "RA"]
    handle_output(
        "a+",
        protocols_basic,
        protocols_detailed,
        json_output,
        more_detail,
        less_detail,
        check_addresses,
        interface,
        ip_mode,
        target_codes,
        lambda fname: get_csv_path(fname, interface),
        target_macs,
    )

    if not REUSE_EXISTING_DATA:
        cleanup_iptables("a")
        cleanup_iptables("a+")
        print_message("Aggressive scan ended", condition=True)
    else:
        print_message("Reused scan data and performed analysis", condition=True)


def execute_scan(scan_types):
    has_eap = "802.1x" in scan_types
    has_passive = "p" in scan_types
    has_active = "a" in scan_types
    has_aggressive = "a+" in scan_types

    if has_eap:
        ptnet_eap(combine=len(scan_types) > 1)
        if len(scan_types) > 1:
            check_eap_detected()
            if json_output:
                Json.output_object(False, "802.1x", target_codes=target_codes, ipver=ip_mode)

    if has_passive:
        Interface_object.shutdown_traffic()
        print_message("Interface traffic shutdown", condition=True, indent=4)
        ptnet_passive()
        Interface_object.restore_traffic()
        print_message("The interface is restored", condition=True, indent=4)
        if not REUSE_EXISTING_DATA:
            print_message("Passive scan ended", condition=True)
        else:
            print_message("Reused scan data and performed analysis", condition=True)
    elif has_active or has_aggressive:
        Interface_object.restore_traffic()

    if has_active and not has_aggressive:
        ptnet_active()
        cleanup_iptables("a")
        if not REUSE_EXISTING_DATA:
            print_message("Active scan ended", condition=True)
        else:
            print_message("Reused scan data and performed analysis", condition=True)
    elif has_aggressive:
        if has_active:
            ptnet_active()
        ptnet_aggressive()


def main():
    global REUSE_EXISTING_DATA, Vulnerability_object

    # Set interface context for all tmp/csv operations during this scan
    set_current_interface(interface)

    # Initialize Vulnerability_object after setting interface context
    Vulnerability_object = Vulnerability(
        interface,
        scanning_type,
        ip_mode,
        smac,
        network,
        prefix_len,
        rpref,
        dns,
        target_codes=set(target_codes) if target_codes else None,
        target_macs=set(target_macs) if target_macs else None,
    )

    json_output_path = get_output_dir() / "ptnetinspector-output.json"
    text_output_path = get_output_dir() / "ptnetinspector-output.txt"

    current_signature = build_run_signature(
        interface,
        json_output,
        scanning_type,
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
        target_codes,
        target_macs,
    )

    required_files = ["addresses.csv", "addresses_unfiltered.csv", "networks.csv"]

    # Configure terminal output policy based on flags
    configure_output_flags(json_output, more_detail, less_detail)

    REUSE_EXISTING_DATA = prepare_tmp_files(
        interface,
        tmp_retention,
        current_signature,
        lambda iface=interface: get_tmp_path(iface),
        lambda iface=interface: create_csv(iface),
        lambda iface=interface: del_tmp_path(iface),
        lambda: (delete_json_output(json_output_path), delete_text_output(text_output_path)),
        write_run_signature,
        load_run_signature,
        required_files,
        less_detail,
    )

    # Start logging terminal output to text file after tmp prep/cleanup
    start_output_logging(text_output_path)

    try:
        execute_scan(scanning_type)
        
        # Print final JSON output at the end
        if json_output:
            enablePrint()
            if more_detail:
                Non_json.print_box("Json output")
            # Final output reads accumulated CSVs; avoid mode filtering
            print(Json.output_object(True, None, target_codes=target_codes, ipver=ip_mode, target_macs=target_macs))
    except KeyboardInterrupt:
        has_active = "a" in scanning_type
        has_aggressive = "a+" in scanning_type
        has_passive = "p" in scanning_type

        terminate_child_processes()
        if has_active or has_aggressive:
            cleanup_iptables("a")
        if has_aggressive:
            cleanup_iptables("a+")
        if has_passive:
            try:
                Interface_object.restore_traffic()
            except Exception:
                pass
        print_message("Scan interrupted by user", "WARNING")
    except Exception as e:
        has_active = "a" in scanning_type
        has_aggressive = "a+" in scanning_type
        has_passive = "p" in scanning_type

        terminate_child_processes()
        if has_active or has_aggressive:
            cleanup_iptables("a")
        if has_aggressive:
            cleanup_iptables("a+")
        if has_passive:
            try:
                Interface_object.restore_traffic()
            except Exception:
                pass
        print_message(f"An error occurred: {str(e)}", "ERROR")
        print_message("Terminating ptnetinspector", "INFO", indent=0)
        sys.exit(1)
    finally:
        # Stop logging output to file
        stop_output_logging()


if __name__ == "__main__":
    main()
