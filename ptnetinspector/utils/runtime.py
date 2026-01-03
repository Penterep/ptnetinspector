#!/usr/bin/env python3
"""Runtime and output policy helpers used by main execution flow.

Provides: global output suppression flags, unified printing helpers that respect
CLI verbosity policies, and stdout dual-writing for logging to file while
streaming to the terminal.
"""
import csv
import json
import multiprocessing
import os
import sys
import time
from io import StringIO
from pathlib import Path
from typing import Callable, Iterable

from ptlibs import ptprinthelper

from ptnetinspector.entities.networks import Networks
from ptnetinspector.output.non_json import Non_json
from ptnetinspector.utils.address_control import validate_addresses_mapping
from ptnetinspector.utils.vuln_catalog import load_vuln_catalog_by_test


# Global variable to capture terminal output
_output_capture = None
_original_stdout = None


def start_output_capture(output_file_path: Path) -> None:
    """Start capturing stdout to both terminal and file."""
    global _output_capture, _original_stdout
    _original_stdout = sys.stdout
    _output_capture = open(output_file_path, 'w', encoding='utf-8')


def stop_output_capture() -> None:
    """Stop capturing stdout and close the file."""
    global _output_capture, _original_stdout
    if _output_capture and not _output_capture.closed:
        sys.stdout = _original_stdout
        _output_capture.close()
        _output_capture = None
        _original_stdout = None


class DualWriter:
    """Write to both terminal and file simultaneously."""
    def __init__(self, terminal, file_handle):
        self.terminal = terminal
        self.file = file_handle
    
    def write(self, message):
        self.terminal.write(message)
        self.terminal.flush()
        if self.file and not self.file.closed:
            self.file.write(message)
            self.file.flush()
    
    def flush(self):
        self.terminal.flush()
        if self.file and not self.file.closed:
            self.file.flush()
    
    def isatty(self):
        return self.terminal.isatty()

    def close(self):
        # Provide close() so callers like enablePrint() can safely call it.
        try:
            self.flush()
        except Exception:
            pass
        # Do not close underlying file/terminal here; stop_output_logging handles it.


def start_output_logging(output_file_path: Path) -> None:
    """Start logging all stdout to file while keeping terminal output.

    Uses sys.__stdout__ for the terminal stream to avoid being impacted by
    prior stdout redirections (e.g., blockPrint()).
    """
    global _output_capture, _original_stdout
    _original_stdout = sys.stdout
    terminal_stream = sys.__stdout__
    _output_capture = open(output_file_path, 'w', encoding='utf-8')
    sys.stdout = DualWriter(terminal_stream, _output_capture)


def stop_output_logging() -> None:
    """Stop logging stdout and restore normal operation."""
    global _output_capture, _original_stdout
    if isinstance(sys.stdout, DualWriter):
        sys.stdout = _original_stdout
    if _output_capture and not _output_capture.closed:
        _output_capture.close()
    _output_capture = None
    _original_stdout = None


def _should_suppress(level: str) -> bool:
    """Return True if message at level should be suppressed under current policy."""
    try:
        return bool(_suppress_non_json and level in ("INFO", "WARNING"))
    except NameError:
        return False


def _format_message(level: str, message: str) -> str:
    """Apply level-specific formatting (e.g., grey for WARNING)."""
    if level == "WARNING":
        GREY = "\033[90m"
        END = "\033[0m"
        return f"{GREY}{message}{END}"
    return message


def _emit(message: str, level: str, indent: int, condition: bool) -> None:
    ptprinthelper.ptprint(message, level, condition=condition, indent=indent)


def print_message(message: str, level: str = "INFO", indent: int = 0, condition: bool = True) -> None:
    """Unified printing wrapper for general messages respecting -j policy."""
    if _should_suppress(level):
        return
    _emit(_format_message(level, message), level, indent, condition)


# Output policy flags set from main/CLI to control terminal verbosity when -j/-less/-vv
_suppress_info_when_json_less = False
_suppress_non_json = False


def configure_output_flags(json_output: bool, more_detail: bool, less_detail: bool) -> None:
    """Configure runtime output policy based on CLI flags.

    - If -j without -vv: suppress all non-JSON output and INFO/WARNING chatter.
    - If -j with -vv: show both non-JSON and JSON.
    - If -j with -less: suppress non-JSON; only show JSON.
    - If no -j: show all by default.
    """
    global _suppress_info_when_json_less, _suppress_non_json
    # Suppress INFO/WARNING when -j -less (no -vv)
    _suppress_info_when_json_less = bool(json_output and less_detail and not more_detail)
    # Suppress all non-JSON output when -j but not -vv
    _suppress_non_json = bool(json_output and not more_detail)


def ptprint_info_warning(message: str, level: str = "INFO", condition: bool = True, indent: int = 0) -> None:
    """Compatibility wrapper for historical callsites; same behavior as print_message."""
    if _should_suppress(level):
        return
    _emit(_format_message(level, message), level, indent, condition)


def build_run_signature(
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
) -> dict:
    """Construct a signature of current run parameters used for tmp reuse.
    
    Note: Excludes json_output, more_detail and less_detail flags so tmp cache 
    is reused regardless of output format (-j) or verbosity level (-vv / -less).
    """
    return {
        "interface": interface,
        "scanning_type": list(scanning_type) if scanning_type is not None else [],
        "check_addresses": bool(check_addresses),
        "ip_mode": {"ipv4": bool(getattr(ip_mode, "ipv4", False)), "ipv6": bool(getattr(ip_mode, "ipv6", False))},
        "duration_passive": duration_passive,
        "duration_aggressive": duration_aggressive,
        "prefix_len": prefix_len,
        "network": network,
        "smac": smac,
        "sip": sip,
        "rpref": rpref,
        "period": period,
        "chl": chl,
        "mtu": mtu,
        "dns": sorted(dns) if dns else [],
        "nofwd": bool(nofwd),
        "target_codes": sorted(target_codes) if target_codes else [],
        "target_macs": sorted(target_macs) if target_macs else [],
    }


def write_run_signature(tmp_dir: Path, signature: dict) -> None:
    sig_path = tmp_dir / "run_params.json"
    try:
        tmp_dir.mkdir(parents=True, exist_ok=True)
        with open(sig_path, "w", encoding="utf-8") as f:
            json.dump(signature, f, sort_keys=True)
    except Exception:
        pass


def load_run_signature(tmp_dir: Path):
    sig_path = tmp_dir / "run_params.json"
    try:
        with open(sig_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def delete_json_output(json_file: Path) -> None:
    if json_file.exists():
        try:
            json_file.unlink()
        except OSError:
            pass


def delete_text_output(text_file: Path) -> None:
    """Delete text output file if it exists."""
    if text_file.exists():
        try:
            text_file.unlink()
        except OSError:
            pass


def check_interface_status(interface_obj, interface_name: str) -> None:
    status = interface_obj.check_status()
    if status == "Interface down":
        ptprinthelper.ptprint(f"Interface {interface_name} is down", "ERROR")
        raise SystemExit(1)


def prepare_networks_file(interface_name: str, networks_path: Path) -> None:
    """Populate networks.csv with current interface subnets, or create empty if failed."""
    try:
        Networks.extract_available_subnets(interface_name)
    except Exception:
        if not networks_path.exists():
            networks_path.parent.mkdir(parents=True, exist_ok=True)
            networks_path.write_text("network_prefix,prefix_length\n", encoding="utf-8")


def terminate_child_processes(timeout: float = 1.0) -> None:
    """Terminate any active multiprocessing children to avoid hung processes on interrupt."""
    for proc in multiprocessing.active_children():
        try:
            proc.terminate()
        except Exception:
            pass
    for proc in multiprocessing.active_children():
        try:
            proc.join(timeout=timeout)
        except Exception:
            pass


def _check_macs_in_role_node(tmp_path: Path, target_macs: set[str]) -> bool:
    """Check if all target MACs exist in saved role_node.csv.
    
    Args:
        tmp_path: Path to tmp directory containing role_node.csv
        target_macs: Set of MAC addresses (uppercase) to check
        
    Returns:
        bool: True if all target MACs exist in role_node.csv, False otherwise
    """
    role_node_file = tmp_path / "role_node.csv"
    if not role_node_file.exists():
        return False
    
    try:
        with open(role_node_file, 'r', newline='') as f:
            reader = csv.DictReader(f)
            saved_macs = {row['MAC'].upper() for row in reader if 'MAC' in row}
        return target_macs.issubset(saved_macs)
    except Exception:
        return False


def _check_test_codes_in_vulnerability(tmp_path: Path, target_test_codes: set[str]) -> bool:
    """Check if all target test codes have vulnerability data in saved vulnerability.csv.
    
    Args:
        tmp_path: Path to tmp directory containing vulnerability.csv
        target_test_codes: Set of test codes (uppercase) to check
        
    Returns:
        bool: True if all test codes have corresponding vulnerabilities in saved data, False otherwise
    """
    vulnerability_file = tmp_path / "vulnerability.csv"
    if not vulnerability_file.exists():
        return False
    
    try:
        # Load catalog to map vuln codes to test codes
        test_catalog = load_vuln_catalog_by_test()
        code_to_test: dict[str, str] = {}
        for test_code, entries in test_catalog.items():
            for entry in entries:
                vuln_code = entry.get("Code", "").strip().upper()
                if vuln_code:
                    code_to_test[vuln_code] = test_code
        
        # Read saved vulnerability data and collect test codes found
        with open(vulnerability_file, 'r', newline='') as f:
            reader = csv.DictReader(f)
            saved_test_codes = set()
            for row in reader:
                vuln_code = row.get('Code', '').strip().upper()
                test_code = code_to_test.get(vuln_code, '')
                if test_code:
                    saved_test_codes.add(test_code.upper())
        
        # Check if all target test codes are in saved data
        return target_test_codes.issubset(saved_test_codes)
    except Exception:
        return False


def can_reuse_tmp_data(current_sig: dict, saved_sig: dict, tmp_path: Path | None = None) -> bool:
    """Check if saved tmp data can be reused for current run.
    
    Args:
        current_sig: Current run signature with parameters
        saved_sig: Saved run signature from previous run
        tmp_path: Path to tmp directory (needed for MAC and test code validation)
        
    Returns:
        bool: True if tmp data can be reused, False if fresh scan needed
    
    Rules for reuse:
    - All core parameters must match (interface, scan types, modes, durations, etc.)
    - target_macs:
      * Previous NO target, current HAS target: Can reuse IF target MACs exist in saved role_node.csv
      * Previous HAS target, current NO target: Cannot reuse (saved data is filtered, need full scan)
      * Both have targets: Can reuse IF current is subset of saved
      * Neither has targets: Can reuse (both are full scans)
    - target_codes:
      * Previous NO test filter, current HAS test filter: Can reuse IF test codes exist in saved vulnerability.csv
      * Previous HAS test filter, current NO test filter: Cannot reuse (saved data is filtered, need full test run)
      * Both have test filters: Can reuse IF current is subset of saved
      * Neither has test filters: Can reuse (both run all tests)
    """
    # List of parameters that must match exactly
    must_match_keys = {
        "interface", "scanning_type", "check_addresses", "ip_mode",
        "duration_passive", "duration_aggressive", "prefix_len", "network",
        "smac", "sip", "rpref", "period", "chl", "mtu", "dns", "nofwd"
    }
    
    # Check exact match for core parameters
    for key in must_match_keys:
        if current_sig.get(key) != saved_sig.get(key):
            return False
    
    # Check target_macs with corrected logic
    current_macs = set(current_sig.get("target_macs", []))
    saved_macs = set(saved_sig.get("target_macs", []))
    
    if saved_macs and not current_macs:
        # Previous run HAD target, current run has NO target
        # Cannot reuse: saved data only has filtered devices, not all devices
        return False
    elif not saved_macs and current_macs:
        # Previous run had NO target (full scan), current run HAS target
        # Can reuse IF target MACs exist in saved role_node.csv
        if tmp_path is None or not _check_macs_in_role_node(tmp_path, current_macs):
            return False
    elif saved_macs and current_macs:
        # Both have targets: current must be subset of saved
        if not current_macs.issubset(saved_macs):
            return False
    # else: neither has targets (both full scans), can reuse
    
    # Check target_codes with corrected logic (same pattern as target_macs)
    current_codes = set(current_sig.get("target_codes", []))
    saved_codes = set(saved_sig.get("target_codes", []))
    
    if saved_codes and not current_codes:
        # Previous run HAD test filter, current run has NO test filter
        # Cannot reuse: saved data only has filtered tests, not all tests
        return False
    elif not saved_codes and current_codes:
        # Previous run had NO test filter (all tests), current run HAS test filter
        # Can reuse IF target test codes exist in saved vulnerability.csv
        if tmp_path is None or not _check_test_codes_in_vulnerability(tmp_path, current_codes):
            return False
    elif saved_codes and current_codes:
        # Both have test filters: current must be subset of saved
        if not current_codes.issubset(saved_codes):
            return False
    # else: neither has test filters (both run all tests), can reuse
    
    return True


def prepare_tmp_files(
    interface: str,
    retention_seconds: float,
    current_signature: dict,
    get_tmp_path_fn: Callable[[], Path],
    create_csv_fn: Callable[[], None],
    del_tmp_path_fn: Callable[[], None],
    delete_json_output_fn: Callable[[], None],
    write_run_signature_fn: Callable[[Path, dict], None],
    load_run_signature_fn: Callable[[Path], dict | None],
    required_files: Iterable[str],
    less_detail: bool = False,
) -> bool:
    """Prepare tmp folder scoped to interface; return True if existing data should be reused.
    
    Args:
        interface (str): Network interface name (e.g. 'eth0'). Scopes tmp folder to tmp/<interface>/.
        retention_seconds (float): Age threshold in seconds; files older are discarded.
        current_signature (dict): Run parameters signature to compare against saved.
        get_tmp_path_fn (Callable): Function to retrieve tmp path (should accept interface).
        create_csv_fn (Callable): Function to create fresh CSV files (should accept interface).
        del_tmp_path_fn (Callable): Function to delete tmp folder contents (should accept interface).
        delete_json_output_fn (Callable): Function to delete JSON output file.
        write_run_signature_fn (Callable): Function to write run_params.json.
        load_run_signature_fn (Callable): Function to load run_params.json.
        required_files (Iterable[str]): List of required file names.
        
    Returns:
        bool: True if existing cached data can be reused, False if fresh scan needed.
    """
    delete_json_output_fn()
    tmp_dir = get_tmp_path_fn(interface)

    try:
        files = list(tmp_dir.iterdir())
        mtimes = [(p, p.stat().st_mtime) for p in files if p.is_file()]
    except FileNotFoundError:
        mtimes = []

    if not mtimes:
        if not less_detail:
            ptprinthelper.ptprint("\033[90mNo tmp files found; creating new temporary files\033[0m", "WARNING", condition=True, indent=4)
        create_csv_fn(interface)
        write_run_signature_fn(tmp_dir, current_signature)
        return False

    missing_required = []
    for fname in required_files:
        if not (tmp_dir / fname).exists():
            missing_required.append(fname)

    if missing_required:
        missing_list = ", ".join(missing_required)
        if not less_detail:
            ptprinthelper.ptprint(
                f"\033[90mMissing required tmp files ({missing_list}); recreating temporary files\033[0m",
                "WARNING",
                condition=True,
                indent=4,
            )
        del_tmp_path_fn(interface)
        create_csv_fn(interface)
        write_run_signature_fn(tmp_dir, current_signature)
        return False

    current_time = time.time()
    newest_mtime = max(mtime for _, mtime in mtimes)
    age_of_newest = current_time - newest_mtime

    if age_of_newest > retention_seconds:
        del_tmp_path_fn(interface)
        create_csv_fn(interface)
        write_run_signature_fn(tmp_dir, current_signature)
        return False

    saved_signature = load_run_signature_fn(tmp_dir)
    if saved_signature is None:
        if not less_detail:
            ptprinthelper.ptprint("\033[90mTmp files found but missing run_params.json; recreating temporary files\033[0m", "WARNING", condition=True, indent=4)
        del_tmp_path_fn(interface)
        create_csv_fn(interface)
        write_run_signature_fn(tmp_dir, current_signature)
        return False

    if not can_reuse_tmp_data(current_signature, saved_signature, tmp_dir):
        if not less_detail:
            ptprinthelper.ptprint("\033[90mTmp files parameters differ from current run; recreating temporary files\033[0m", "WARNING", condition=True, indent=4)
        del_tmp_path_fn(interface)
        create_csv_fn(interface)
        write_run_signature_fn(tmp_dir, current_signature)
        return False

    return True


def output_protocols(scan_type, protocols, ip_mode, interface, less_detail, target_codes, get_csv_path_fn, target_macs=None):
    protocol_files = {
        "MDNS": "MDNS.csv",
        "LLMNR": "LLMNR.csv",
        "MLDv1": "MLDv1.csv",
        "IGMPv1/v2": "IGMPv1v2.csv",
        "WS-Discovery": "wsdiscovery.csv",
        "MLDv2": "MLDv2.csv",
        "IGMPv3": "IGMPv3.csv",
        "RA": "RA.csv",
    }

    def is_protocol_allowed(proto: str) -> bool:
        if proto in ["MLDv1", "MLDv2", "RA"]:
            return ip_mode.ipv6
        if proto in ["IGMPv1/v2", "IGMPv3"]:
            return ip_mode.ipv4
        return ip_mode.ipv4 or ip_mode.ipv6

    def filter_protocols_by_tests(protocols_list, target_tests):
        if not target_tests:
            return protocols_list
        allowed = set()
        for t in target_tests:
            t_up = t.upper()
            if "MLDV1" in t_up:
                allowed.add("MLDv1")
            if "MLDV2" in t_up:
                allowed.add("MLDv2")
            if "MDNS" in t_up:
                allowed.add("MDNS")
            if "LLMNR" in t_up:
                allowed.add("LLMNR")
            if "WS" in t_up:
                allowed.add("WS-Discovery")
            if "RA" in t_up or "FAKERA" in t_up or "FAKERADNS" in t_up:
                allowed.add("RA")
            if "IGMP" in t_up:
                allowed.add("IGMPv1/v2")
                allowed.add("IGMPv3")
        if not allowed:
            return []
        return [p for p in protocols_list if p in allowed]

    protocols = filter_protocols_by_tests(protocols, target_codes)

    for protocol in protocols:
        if protocol in protocol_files and is_protocol_allowed(protocol):
            file_path = get_csv_path_fn(protocol_files[protocol])
            Non_json.output_protocol(interface, ip_mode, scan_type, protocol, file_path, less_detail, target_macs=target_macs)


def handle_output(
    scan_type,
    protocols_basic,
    protocols_detailed,
    json_output,
    more_detail,
    less_detail,
    check_addresses,
    interface,
    ip_mode,
    target_codes,
    get_csv_path_fn,
    target_macs=None,
):
    # Skip all non-JSON output if -j is used without -vv
    if _suppress_non_json:
        return
    
    if (not json_output) or more_detail:
        Non_json.output_general(scan_type, ip_mode, target_codes=target_codes, target_macs=target_macs)
        Non_json.read_vulnerability_table(scan_type, ip_mode, target_codes=target_codes, target_macs=target_macs)

        if more_detail:
            time_file = get_csv_path_fn("time_incoming.csv")
            Non_json.output_protocol(interface, ip_mode, scan_type, "time", time_file, less_detail, target_macs=target_macs)
            if check_addresses:
                Non_json.print_box("Unfiltered found addresses")
                addr_file = get_csv_path_fn("addresses_unfiltered.csv")
                Non_json.output_general(scan_type, ip_mode, addr_file, target_codes=target_codes, target_macs=target_macs)

            output_protocols(scan_type, protocols_basic, ip_mode, interface, less_detail, target_codes, get_csv_path_fn, target_macs)

            if protocols_detailed:
                output_protocols(scan_type, protocols_detailed, ip_mode, interface, less_detail, target_codes, get_csv_path_fn, target_macs)


def handle_addresses(interface, ip_mode, passive: bool = False) -> None:
    try:
        validate_addresses_mapping(interface, ip_mode, passive=passive)
    except Exception:
        ptprinthelper.ptprint("\033[90mFailed to validate addresses mapping\033[0m", "WARNING", condition=True, indent=4)
