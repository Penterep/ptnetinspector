"""Device inventory output.

The per-device sections of the report interleave addresses with vulnerability
findings, which is unreadable once a segment has more than a handful of hosts -
a wifi network, typically. This writes the plain inventory on its own: one row
per device, its MAC, its addresses and the little that identifies it, with no
findings mixed in.

Two artifacts are produced next to the other output files:

* ``devices.csv``  - one row per device, for scripting.
* ``devices.txt``  - the same data rendered as an aligned table, for reading.
"""
import csv
import ipaddress
import logging

import pandas as pd
from tabulate import tabulate

from ptnetinspector.send.send import IPMode
from ptnetinspector.utils.ip_utils import has_additional_data, is_llsnm_ipv6, is_valid_ipv6
from ptnetinspector.utils.oui import lookup_vendor_from_csv
from ptnetinspector.utils.output_helpers import transform_role_print
from ptnetinspector.utils.path import get_csv_path, get_tmp_path


logger = logging.getLogger(__name__)

FIELDS = ['Device', 'MAC', 'Vendor', 'Role', 'Hostname', 'IPv4', 'IPv6', 'IP_count']


def _sort_key(ip: str) -> tuple:
    """Order addresses numerically so ``fe80::2`` precedes ``fe80::10``."""
    try:
        address = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return (2, 0, str(ip))
    return (0 if address.version == 4 else 1, int(address), "")


def _load_hostnames() -> dict[str, str]:
    """Map MAC to the local name learned over mDNS/LLMNR, when one was seen."""
    names: dict[str, str] = {}
    localname_file = get_csv_path("localname.csv")
    if not has_additional_data(localname_file):
        return names
    try:
        with open(localname_file, newline="") as handle:
            for row in csv.DictReader(handle):
                mac = str(row.get("MAC", "")).strip().upper()
                name = str(row.get("name", "")).strip()
                if mac and name and mac not in names:
                    names[mac] = name
    except OSError as error:
        logger.debug("Could not read local names: %s", error)
    return names


def collect_devices(ipver: IPMode, include_solicited_node: bool = False) -> list[dict]:
    """Build the device inventory from the addresses and roles already collected.

    Args:
        ipver: Enabled IP versions; addresses of a disabled family are omitted.
        include_solicited_node: True under -nc, where solicited-node groups are
            kept because they stand in for addresses that were never confirmed.
    """
    addresses_file = get_csv_path("addresses.csv")
    role_file = get_csv_path("role_node.csv")

    if not (has_additional_data(addresses_file) and has_additional_data(role_file)):
        return []

    try:
        addresses_df = pd.read_csv(addresses_file)
        role_df = pd.read_csv(role_file)
    except (OSError, ValueError, pd.errors.ParserError) as error:
        logger.debug("Could not read device inventory sources: %s", error)
        return []

    hostnames = _load_hostnames()
    devices = []

    for _, row in role_df.iterrows():
        mac = str(row.get("MAC", "")).strip()
        if not mac:
            continue

        device_ips = addresses_df.loc[addresses_df["MAC"] == mac, "IP"].astype(str).tolist()

        ipv4_addresses, ipv6_addresses = [], []
        for ip in device_ips:
            ip = ip.strip()
            if not ip:
                continue
            if is_valid_ipv6(ip):
                if not ipver.ipv6:
                    continue
                if is_llsnm_ipv6(ip) and not include_solicited_node:
                    continue
                ipv6_addresses.append(ip)
            else:
                try:
                    ipaddress.IPv4Address(ip)
                except ipaddress.AddressValueError:
                    continue
                if ipver.ipv4:
                    ipv4_addresses.append(ip)

        ipv4_addresses = sorted(set(ipv4_addresses), key=_sort_key)
        ipv6_addresses = sorted(set(ipv6_addresses), key=_sort_key)

        devices.append({
            "Device": str(row.get("Device_Number", "")).strip(),
            "MAC": mac,
            "Vendor": lookup_vendor_from_csv(mac),
            "Role": transform_role_print(str(row.get("Role", ""))),
            "Hostname": hostnames.get(mac.upper(), ""),
            "IPv4": " ".join(ipv4_addresses),
            "IPv6": " ".join(ipv6_addresses),
            "IP_count": str(len(ipv4_addresses) + len(ipv6_addresses)),
        })

    devices.sort(key=lambda d: int(d["Device"]) if d["Device"].isdigit() else 0)
    return devices


def _render_table(devices: list[dict]) -> str:
    """Render the inventory with one row per address, so nothing is truncated.

    A device with six addresses would otherwise produce an unreadably wide cell;
    repeating the address column keeps every value on its own line while the
    identifying columns are printed once per device.
    """
    rows = []
    for device in devices:
        addresses = [ip for ip in device["IPv4"].split() + device["IPv6"].split() if ip]
        if not addresses:
            rows.append([device["Device"], device["MAC"], device["Vendor"],
                         device["Role"], device["Hostname"], "-"])
            continue
        for index, ip in enumerate(addresses):
            if index == 0:
                rows.append([device["Device"], device["MAC"], device["Vendor"],
                             device["Role"], device["Hostname"], ip])
            else:
                rows.append(["", "", "", "", "", ip])

    headers = ["#", "MAC", "Vendor", "Role", "Hostname", "IP address"]
    return tabulate(rows, headers=headers, tablefmt="simple", disable_numparse=True)


def write_device_inventory(ipver: IPMode, include_solicited_node: bool = False) -> tuple[int, str | None]:
    """Write devices.csv and devices.txt next to the other output artifacts.

    Returns:
        tuple[int, str | None]: How many devices were written, and the directory
        they were written to (None when nothing was written).
    """
    devices = collect_devices(ipver, include_solicited_node=include_solicited_node)
    if not devices:
        return 0, None

    output_dir = get_tmp_path()

    try:
        with open(output_dir / "devices.csv", "w", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=FIELDS)
            writer.writeheader()
            writer.writerows(devices)
    except OSError as error:
        logger.debug("Could not write devices.csv: %s", error)
        return 0, None

    try:
        address_count = sum(int(device["IP_count"]) for device in devices)
        header = (
            f"ptnetinspector device inventory\n"
            f"{len(devices)} device(s), {address_count} address(es)\n\n"
        )
        (output_dir / "devices.txt").write_text(header + _render_table(devices) + "\n",
                                                encoding="utf-8")
    except OSError as error:
        logger.debug("Could not write devices.txt: %s", error)

    return len(devices), str(output_dir)
