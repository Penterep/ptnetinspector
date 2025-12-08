#!/usr/bin/env python3
import signal
import sys
import warnings

from ptnetinspector.output.json import Json
from ptnetinspector.output.non_json import Non_json
from ptnetinspector.entities.networks import Networks
from ptnetinspector.scan import Run
from ptnetinspector.utils.address_control import delete_tmp_mapping_file, validate_addresses_mapping
from ptnetinspector.utils.cli import enablePrint, parameter_control, parse_args
from ptnetinspector.utils.csv_helpers import create_csv, sort_all_csv, has_additional_data
from ptnetinspector.utils.interface import Interface, IptablesRule
from ptnetinspector.utils.oui import create_vendor_csv
from ptnetinspector.utils.path import del_tmp_path, get_csv_path
from ptnetinspector.vulnerability import Vulnerability
from ptlibs import ptprinthelper
from ptlibs.ptjsonlib import PtJsonLib

# Suppress warnings
warnings.simplefilter(action='ignore', category=FutureWarning)
warnings.filterwarnings("ignore")

# OVERRIDE ptlibs signal handler before it gets called
# This must be done BEFORE ptlibs registers its handler
original_signal_handler = None

def custom_signal_handler(sig, frame):
    """Custom signal handler to override ptlibs default behavior."""
    raise KeyboardInterrupt()

# Register our custom signal handler to override ptlibs
signal.signal(signal.SIGINT, custom_signal_handler)

# Global objects and configuration
ptjsonlib_object = PtJsonLib()
args = parse_args()
create_csv()

# Parse parameters
interface, json_output, del_tmp_para, scanning_type, more_detail, less_detail, check_addresses, ip_mode, duration_passive, duration_aggressive, prefix_len, network, smac, sip, rpref, period, chl, mtu, dns, nofwd = parameter_control(
    args.interface, args.j, args.n, args.t, args.more, args.less, args.nc, args.ipv4, args.ipv6, args.d, args.duration_router, args.prefix, args.smac, args.sip, args.rpref, args.period, args.chl, args.mtu, args.dns, args.nofwd
)

Networks.extract_available_subnets(interface)
Interface_object = Interface(interface)
Vulnerability_object = Vulnerability(interface, scanning_type, ip_mode, smac, network, prefix_len, rpref, dns)


def print_message(message, msg_type="INFO"):
    """Conditional print based on verbosity settings."""
    if (not json_output or more_detail) and not less_detail:
        ptprinthelper.ptprint(message, msg_type)


def handle_json_error(error_msg):
    """Handle JSON error output."""
    if json_output:
        enablePrint()
        print(ptjsonlib_object.end_error(error_msg, ptjsonlib_object))


def check_interface_status():
    """Check interface status and exit if down."""
    if_status = Interface_object.check_interface()
    if if_status == "Interface down":
        error_msg = f"Interface {interface} is currently off. No incoming or outcoming traffic on this interface"
        print_message(error_msg, "ERROR")
        handle_json_error(error_msg)
        sys.exit(0)


def handle_addresses():
    """Handle address validation or cleanup."""
    if check_addresses:
        print_message("Checking found addresses if they are responsive and valid")
        validate_addresses_mapping(interface, ip_mode, scanning_type == "p")
    else:
        delete_tmp_mapping_file()


def output_protocols(scan_type, protocols, show_all=False):
    """Output protocol information for multiple protocols."""
    protocol_files = {
        "MDNS": "MDNS.csv",
        "LLMNR": "LLMNR.csv",
        "MLDv1": "MLDv1.csv",
        "IGMPv1/v2": "IGMPv1v2.csv",
        "WS-Discovery": "wsdiscovery.csv",
        "MLDv2": "MLDv2.csv",
        "IGMPv3": "IGMPv3.csv",
        "RA": "RA.csv"
    }
    
    for protocol in protocols:
        if protocol in protocol_files:
            file_path = get_csv_path(protocol_files[protocol])
            Non_json.output_protocol(interface, scan_type, protocol, file_path, less_detail)


def handle_output(scan_type, protocols_basic, protocols_detailed=None):
    """Unified output handling for different scan types."""
    if not json_output or (more_detail or less_detail):
        Non_json.output_general(scan_type)
        Non_json.read_vulnerability_table(scan_type, ip_mode)
        
        if more_detail:
            time_file = get_csv_path("time_incoming.csv")
            Non_json.output_protocol(interface, scan_type, "time", time_file, less_detail)
            if check_addresses:
                Non_json.print_box("Unfiltered found addresses")
                addr_file = get_csv_path("addresses_unfiltered.csv")
                Non_json.output_general(scan_type, addr_file)
        
        output_protocols(scan_type, protocols_basic)
        
        if more_detail and protocols_detailed:
            output_protocols(scan_type, protocols_detailed)


def setup_iptables(rule_type):
    """Setup iptables rules based on mode and IP versions enabled."""
    if not IptablesRule.check(rule_type, ip_mode.ipv4, ip_mode.ipv6, nofwd if rule_type == "a+" else False):
        IptablesRule.add(rule_type, ip_mode.ipv4, ip_mode.ipv6, nofwd if rule_type == "a+" else False)
        print_message("Adding rules in configuration to perform scanning")


def cleanup_iptables(rule_type):
    """Clean up iptables rules based on IP versions."""
    if IptablesRule.check(rule_type, ip_mode.ipv4, ip_mode.ipv6, nofwd if rule_type == "a+" else False):
        IptablesRule.remove(True, rule_type, ip_mode.ipv4, ip_mode.ipv6)
        if rule_type == "a":
            print_message("Removing rules in configuration after scanning")


def ptnet_eap(combine=False):
    """Run 802.1x (EAP) scan and handle output."""
    Run.run_normal_mode(interface, "802.1x", ip_mode, 3)
    create_vendor_csv()
    Vulnerability_object.handle_vulnerabilities("802.1x")

    if not json_output or (more_detail or less_detail):
        eap_file = get_csv_path("eap.csv")
        Non_json.output_protocol(interface, "802.1x", "802.1x", eap_file, less_detail)
        if more_detail:
            ptprinthelper.ptprint("802.1x scan ended", "INFO")
    
    if json_output and not combine:
        enablePrint()


def ptnet_passive():
    """Run passive scan and handle output."""
    if not json_output or (more_detail or less_detail):
        Non_json.print_box("Passive scan running")

    check_interface_status()
    Run.run_normal_mode(interface, "p", ip_mode, duration_passive)
    handle_addresses()
    create_vendor_csv()
    sort_all_csv(interface)
    Vulnerability_object.handle_vulnerabilities("p")

    protocols_basic = ["MDNS", "LLMNR", "MLDv1", "IGMPv1/v2", "WS-Discovery", "MLDv2", "IGMPv3"]
    protocols_detailed = ["RA"]
    handle_output("p", protocols_basic, protocols_detailed)


def ptnet_active():
    """Run active scan and handle output."""
    if not json_output or (more_detail or less_detail):
        Non_json.print_box("Active scan running")

    check_interface_status()
    setup_iptables("a")
    Run.run_normal_mode(interface, "a", ip_mode, None)
    handle_addresses()
    create_vendor_csv()
    sort_all_csv(interface)
    Vulnerability_object.handle_vulnerabilities("a")

    protocols_basic = ["MDNS", "LLMNR", "MLDv1", "IGMPv1/v2", "WS-Discovery", "MLDv2", "IGMPv3"]
    protocols_detailed = ["RA"]
    handle_output("a", protocols_basic, protocols_detailed)


def ptnet_aggressive():
    """Run aggressive scan and handle output."""
    if not json_output or (more_detail or less_detail):
        Non_json.print_box("Aggressive scan running")

    check_interface_status()
    setup_iptables("a")
    setup_iptables("a+")

    if not Interface_object.check_available_ipv6():
        generated_ip = Interface.generate_ipv6_address("fe80::")
        Interface_object.set_ipv6_address(generated_ip)
        print_message("No IP available on interface, so a random IP is generated")

    Run.run_aggressive_mode(interface, ip_mode, prefix_len, network, smac, sip, rpref, duration_aggressive, period, chl, mtu, dns)
    handle_addresses()
    create_vendor_csv()
    sort_all_csv(interface)
    Vulnerability_object.handle_vulnerabilities("a+")

    protocols_basic = ["MDNS", "LLMNR", "MLDv1", "IGMPv1/v2", "WS-Discovery"]
    protocols_detailed = ["MLDv2", "IGMPv3", "RA"]
    handle_output("a+", protocols_basic, protocols_detailed)

    if json_output:
        enablePrint()
        if more_detail:
            Non_json.print_box("Json output")
        print(Json.output_object(True, "a+"))

    cleanup_iptables("a")
    cleanup_iptables("a+")
    print_message("Aggressive scan ended")


def check_eap_detected():
    """Check if 802.1x is detected and should cancel scan."""
    eap_file = get_csv_path("eap.csv")
    if has_additional_data(eap_file):
        ptprinthelper.ptprint("802.1x is detected, so scan will be cancelled", "WARNING")
        if json_output:
            Non_json.print_box("Json output")
            print(Json.output_object(True, "802.1x"))
        sys.exit(0)


def cleanup_and_exit():
    """Common cleanup operations before exit."""
    if del_tmp_para:
        del_tmp_path()
    sys.exit()


def execute_scan(scan_types):
    """Execute scans based on provided types."""
    has_eap = "802.1x" in scan_types
    has_passive = "p" in scan_types
    has_active = "a" in scan_types
    has_aggressive = "a+" in scan_types

    if has_eap:
        ptnet_eap(combine=len(scan_types) > 1)
        if len(scan_types) > 1:
            check_eap_detected()
            if json_output:
                Json.output_object(False, "802.1x")

    if has_passive:
        Interface_object.shutdown_traffic()
        print_message("Interface traffic shutdown")
        ptnet_passive()
        Interface_object.restore_traffic()
        print_message("The interface is restored")
        print_message("Passive scan ended")
    elif has_active or has_aggressive:
        Interface_object.restore_traffic()

    if has_active and not has_aggressive:
        ptnet_active()
        cleanup_iptables("a")
        print_message("Active scan ended")
    elif has_aggressive:
        if has_active:
            ptnet_active()
        ptnet_aggressive()

    if json_output and not has_aggressive:
        enablePrint()
        if more_detail:
            Non_json.print_box("Json output")
        if has_active:
            print(Json.output_object(True, "a"))
        elif has_passive:
            print(Json.output_object(True, "p"))

    cleanup_and_exit()


def main():
    """Main execution logic for scan types.""" 
    try:
        execute_scan(args.t)
    except KeyboardInterrupt:
        has_active = "a" in args.t
        has_aggressive = "a+" in args.t
        has_passive = "p" in args.t
        
        # Cleanup on keyboard interrupt
        if has_active or has_aggressive:
            cleanup_iptables("a")
        if has_aggressive:
            cleanup_iptables("a+")
        if has_passive:
            try:
                Interface_object.restore_traffic()
            except:
                pass   
        if del_tmp_para:
            del_tmp_path()
        print_message("Scan interrupted by user", "WARNING")
    except Exception as e:
        has_active = "a" in args.t
        has_aggressive = "a+" in args.t
        has_passive = "p" in args.t
        
        # Cleanup on exception
        if has_active or has_aggressive:
            cleanup_iptables("a")
        if has_aggressive:
            cleanup_iptables("a+")
        if has_passive:
            try:
                Interface_object.restore_traffic()
            except:
                pass   
        if del_tmp_para:
            del_tmp_path()
        print_message(f"An error occurred: {str(e)}", "ERROR")
        print_message("Terminating ptnetinspector", "INFO")        
        sys.exit(1)


if __name__ == "__main__":
    main()
