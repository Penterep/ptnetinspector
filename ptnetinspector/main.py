#!/usr/bin/env python3
"""ptnetinspector main entrypoint.

This module orchestrates CLI parsing, scan execution (802.1x/passive/active/aggressive),
tmp/cache management, and final JSON/text output. It wires together utilities from
`utils`, emits human-friendly terminal output via `output.non_json`, and produces the
final normalized JSON via `output.json` by reading the accumulated CSVs.
"""
import atexit
import signal
import sys
import warnings
import json
import logging

# Suppress Scapy runtime warnings early, before importing modules that load Scapy.
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from ptnetinspector.output.json import Json
from ptnetinspector.output.devices import write_device_inventory
from ptnetinspector.output.intel import print_report as print_intel_report, write_report as write_intel_report
from ptnetinspector.send.reverse_dns import resolve_discovered_addresses
from ptnetinspector.output.non_json import Non_json
from ptnetinspector.scan import Run
from ptnetinspector.utils.address_control import delete_tmp_mapping_file
from ptnetinspector.utils.cli import enablePrint, parameter_control, parse_args
from ptnetinspector.utils.csv_helpers import create_csv, sort_all_csv, has_additional_data
from ptnetinspector.utils.interface import Interface, IptablesRule, flush_tagged_rules, restore_forwarding_state
from ptnetinspector.utils.oui import create_vendor_csv
from ptnetinspector.utils.path import del_tmp_path, get_csv_path, get_output_dir, get_tmp_path, set_current_interface
from ptnetinspector.utils.lock import acquire_global_lock
from ptnetinspector.utils.runtime import (
    build_run_signature,
    check_interface_status,
    configure_debug_logging,
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
verbose_output = args.v or args.vv

# Display logo at startup unless -j without -v/-vv
from ptnetinspector.utils.cli import display_logo
display_logo(args.j, verbose_output)

# Configure chatty DEBUG diagnostics only for -vv.
configure_debug_logging(args.vv, args.j, verbose_output)

# Validate and process parameters FIRST (before acquiring lock)
# This ensures invalid parameters cause immediate errors without waiting in queue
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
    target_ips,
    reverse_dns,
) = parameter_control(
    args.interface,
    args.j,
    args.t,
    verbose_output,
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
    args.targets,
    args.reverse_dns,
)

# Determine lock verbosity: suppress if -j and not -vv
lock_verbose = not (json_output and not more_detail)
# Acquire global lock - will wait and queue if another instance is running
# This is done AFTER parameter validation to avoid queueing with invalid parameters
acquire_global_lock(verbose=lock_verbose)

# The tmp directory is scoped per interface, and the recovery below reads the
# forwarding state recorded in it, so the context has to be set first.
set_current_interface(interface)

# SIGKILL is untrappable, so a previous run can have left tagged DROP rules on
# the interface, and aggressive mode can have left the host forwarding. The lock
# above guarantees no other instance is live, which makes this the safe moment to
# clear anything left behind. With no recorded state the restore is a no-op, so a
# host that always forwarded is not changed.
flush_tagged_rules()
restore_forwarding_state()


_TERMINATING_SIGNAL = None


def custom_signal_handler(sig, frame):
    global _TERMINATING_SIGNAL
    _TERMINATING_SIGNAL = sig
    raise KeyboardInterrupt()


# SIGINT alone was trapped, so a `kill`, a timeout wrapper, a systemd stop or a
# session hangup during a passive scan skipped every restore path and left the
# interface with DROP rules on INPUT/OUTPUT/FORWARD - the operator's box off the
# network until they flushed iptables by hand. Route the catchable termination
# signals through the same cleanup as Ctrl-C.
signal.signal(signal.SIGINT, custom_signal_handler)
signal.signal(signal.SIGTERM, custom_signal_handler)
signal.signal(signal.SIGHUP, custom_signal_handler)

REUSE_EXISTING_DATA = False

Interface_object = Interface(interface)
Vulnerability_object = None  # Will be initialized in main() after setting interface context

# Tracks whether this run has state on the host that must be undone. Registered
# once; a no-op when nothing was changed.
_HOST_STATE_DIRTY = False


def _restore_host_state():
    """Undo every firewall/forwarding change this run made.

    Runs from the signal path, the exception path and atexit, so any exit short
    of SIGKILL leaves the host as it was found. Each step is independent: one
    failing must not skip the rest.
    """
    global _HOST_STATE_DIRTY
    if not _HOST_STATE_DIRTY:
        return
    _HOST_STATE_DIRTY = False

    for step in (
        lambda: cleanup_iptables("a") if ("a" in scanning_type or "a+" in scanning_type) else None,
        lambda: cleanup_iptables("a+") if "a+" in scanning_type else None,
        lambda: Interface_object.restore_traffic() if "p" in scanning_type else None,
    ):
        try:
            step()
        except Exception:
            # Best-effort: a failing restore must not prevent the others.
            logging.getLogger(__name__).debug("Host state restore step failed", exc_info=True)


atexit.register(_restore_host_state)


def setup_iptables(rule_type):
    global _HOST_STATE_DIRTY
    if not IptablesRule.check(rule_type, ip_mode.ipv4, ip_mode.ipv6, nofwd if rule_type == "a+" else False):
        _HOST_STATE_DIRTY = True
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
            print(Json.output_object(True, "802.1x", target_codes=target_codes, ipver=ip_mode, target_macs=target_macs, target_ips=target_ips, check_addresses=check_addresses))
        sys.exit(0)


def cleanup_and_exit():
    sys.exit()


def output_802_1x_results():
    """Render the 802.1x results the same way every other mode renders its own.

    The verdict is network-scoped and the devices are whatever the short EAPOL
    capture saw; both were stored and returned in JSON while the terminal printed
    nothing but the scan heading.
    """
    Non_json.output_general(
        "802.1x",
        ip_mode,
        get_csv_path("addresses.csv", interface),
        check_addresses=check_addresses,
        target_codes=target_codes,
        target_macs=target_macs,
        target_ips=target_ips,
    )
    Non_json.read_vulnerability_table(
        "802.1x",
        ip_mode,
        target_codes=target_codes,
        target_macs=target_macs,
        target_ips=target_ips,
    )


def ptnet_eap(combine=False):
    from ptnetinspector.utils.runtime import _suppress_non_json
    if REUSE_EXISTING_DATA:
        print_message("Reusing cached 802.1x results (within retention window)", indent=4)
        if not _suppress_non_json:
            eap_file = get_csv_path("eap.csv", interface)
            Non_json.output_protocol(interface, ip_mode, "802.1x", "802.1x", eap_file, less_detail)
            output_802_1x_results()
            if more_detail:
                ptprint_info_warning("802.1x scan (cached)", "INFO", condition=True)
        if json_output and not combine:
            enablePrint()
        return

    # The local prefixes are what tells an on-link neighbour from a host merely
    # routed through the gateway, so they are needed before any filtering.
    prepare_networks_file(interface, get_csv_path("networks.csv", interface))
    Run.run_normal_mode(interface, "802.1x", ip_mode, 3)
    # Sniffing for EAPOL also records every address seen in transit, so the
    # local-scope filter has to run here too; without it the report would list
    # remote hosts as addresses of the gateway. Probing stays off (passive):
    # 802.1x is tested before authentication, so the scan must stay quiet.
    handle_addresses(interface, ip_mode, passive=True, check_addresses=check_addresses)
    create_vendor_csv()
    Vulnerability_object.handle_vulnerabilities("802.1x")

    if not _suppress_non_json:
        eap_file = get_csv_path("eap.csv", interface)
        Non_json.output_protocol(interface, ip_mode, "802.1x", "802.1x", eap_file, less_detail)
        output_802_1x_results()

    if json_output and not combine:
        enablePrint()


def ptnet_passive():
    from ptnetinspector.utils.runtime import _suppress_non_json
    if not _suppress_non_json:
        Non_json.print_box("Passive scan running")

    if not REUSE_EXISTING_DATA:
        check_interface_status(Interface_object, interface)
        prepare_networks_file(interface, get_csv_path("networks.csv", interface))
        Run.run_normal_mode(interface, "p", ip_mode, duration_passive)
        handle_addresses(interface, ip_mode, passive=True, check_addresses=check_addresses)
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
        target_ips,
    )


def ptnet_active():
    from ptnetinspector.utils.runtime import _suppress_non_json
    if not _suppress_non_json:
        Non_json.print_box("Active scan running")

    if not REUSE_EXISTING_DATA:
        check_interface_status(Interface_object, interface)
        prepare_networks_file(interface, get_csv_path("networks.csv", interface))
        setup_iptables("a")
        Run.run_normal_mode(interface, "a", ip_mode, None)
        handle_addresses(interface, ip_mode, check_addresses=check_addresses)
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
        target_ips,
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
        handle_addresses(interface, ip_mode, check_addresses=check_addresses)
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
        target_ips,
    )

    if not REUSE_EXISTING_DATA:
        cleanup_iptables("a")
        cleanup_iptables("a+")
        print_message("Aggressive scan ended", condition=True)
    else:
        print_message("Reused scan data and performed analysis", condition=True)


def execute_scan(scan_types):
    global _HOST_STATE_DIRTY
    has_eap = "802.1x" in scan_types
    has_passive = "p" in scan_types
    has_active = "a" in scan_types
    has_aggressive = "a+" in scan_types

    if has_eap:
        ptnet_eap(combine=len(scan_types) > 1)
        if len(scan_types) > 1:
            check_eap_detected()
            if json_output:
                Json.output_object(False, "802.1x", target_codes=target_codes, ipver=ip_mode, target_macs=target_macs, target_ips=target_ips, check_addresses=check_addresses)

    if has_passive:
        _HOST_STATE_DIRTY = True
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
        target_ips=set(target_ips) if target_ips else None,
        sip=sip,
        check_addresses=check_addresses,
    )

    json_output_path = get_tmp_path(interface) / "ptnetinspector-output.json"
    text_output_path = get_tmp_path(interface) / "ptnetinspector-output.txt"

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
        target_ips,
        reverse_dns,
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

        # -rdns is the one probe that leaves the link, so it is opt-in.
        if reverse_dns:
            resolved = resolve_discovered_addresses(ip_mode)
            print_message(
                f"Reverse DNS resolved {resolved} name(s) from the discovered resolvers",
                "INFO",
                indent=4,
            )

        # Recon detail the extended parsers collected: RA options, discovered
        # services, node information, the querier, DHCPv6 options, fingerprints.
        from ptnetinspector.utils.runtime import _suppress_non_json as suppress_output
        if not suppress_output:
            print_intel_report(detailed=more_detail)
        intel_path, _ = write_intel_report()
        if intel_path:
            print_message(f"Network intelligence written: {intel_path}", "INFO", indent=4)

        # A flat device list, written separately from the per-device findings.
        # On a segment with many hosts the interleaved report is unreadable, and
        # an operator usually wants "what is out there" before "what is wrong".
        device_count, inventory_dir = write_device_inventory(
            ip_mode,
            include_solicited_node=not check_addresses,
            target_macs=target_macs,
            target_ips=target_ips,
        )
        if device_count and inventory_dir:
            # One path per line: three on one line ran to 250 characters.
            print_message(f"Device inventory written for {device_count} device(s):", "INFO", indent=4)
            for name in ("devices.csv", "devices.txt", "device_addresses.csv"):
                print_message(f"{inventory_dir}/{name}", "INFO", indent=8)

        # Print final JSON output at the end
        if json_output:
            enablePrint()
            if more_detail:
                Non_json.print_box("Json output")
            # Final output reads accumulated CSVs; avoid mode filtering
            print(Json.output_object(True, None, target_codes=target_codes, ipver=ip_mode, target_macs=target_macs, target_ips=target_ips, check_addresses=check_addresses))
    except KeyboardInterrupt:
        terminate_child_processes()
        _restore_host_state()
        print_message("Scan interrupted by user", "WARNING")
        # 128 + signal number is what a shell reports for a signalled process.
        sys.exit(128 + (_TERMINATING_SIGNAL or signal.SIGINT))
    except Exception as e:
        terminate_child_processes()
        _restore_host_state()
        print_message(f"An error occurred: {str(e)}", "ERROR")
        print_message("Terminating ptnetinspector", "INFO", indent=0)
        sys.exit(1)
    finally:
        # Stop logging output to file
        stop_output_logging()

        # Clean up text output file if JSON-only mode (no -vv)
        if json_output and not more_detail:
            if text_output_path.exists():
                try:
                    text_output_path.unlink()
                except OSError:
                    # Ignore cleanup failures for optional text output artifact.
                    pass


if __name__ == "__main__":
    main()
