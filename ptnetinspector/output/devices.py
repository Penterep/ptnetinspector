"""Device inventory output.

The per-device sections of the report interleave addresses with vulnerability
findings, which is unreadable once a segment has more than a handful of hosts -
a wifi network, typically. This writes the plain inventory on its own: one row
per device, its MAC, its addresses and the little that identifies it, with no
findings mixed in.

Three artifacts are produced next to the other output files:

* ``devices.csv``           - one row per device, for scripting.
* ``devices.txt``           - the same data rendered as an aligned table, for reading.
* ``device_addresses.csv``  - one row per *address*, for searching. The
  per-device form keeps a host's addresses together in one cell, which reads
  well but cannot be split on the delimiter; this form gives every address its
  own row with the device's identity repeated alongside, so a segment can be
  grepped, filtered by family, or joined against another list.
"""
import csv
import ipaddress
import logging

import pandas as pd
from tabulate import tabulate

from ptnetinspector.utils.csv_helpers import read_csv_text
from ptnetinspector.send.send import IPMode
from ptnetinspector.utils.ip_utils import has_additional_data, is_llsnm_ipv6, is_valid_ipv6
from ptnetinspector.utils.oui import lookup_vendor_from_csv
from ptnetinspector.utils.output_helpers import transform_role_print
from ptnetinspector.utils.path import get_csv_path, get_tmp_path


logger = logging.getLogger(__name__)

FIELDS = ['Device', 'MAC', 'Vendor', 'Role', 'Hostname', 'IPv4', 'IPv6', 'IP_count']

# Leading MAC/IP matches every other artifact this tool writes, so the flat
# inventory can be read by the same helpers and eyeballed the same way.
ADDRESS_FIELDS = ['MAC', 'IP', 'IP_version', 'Device', 'Vendor', 'Role', 'Hostname']


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
        with open(localname_file, 'r', encoding='utf-8', errors='replace', newline='') as handle:
            for row in csv.DictReader(handle):
                mac = str(row.get("MAC", "")).strip().upper()
                name = str(row.get("name", "")).strip()
                if mac and name and mac not in names:
                    names[mac] = name
    except OSError as error:
        logger.debug("Could not read local names: %s", error)
    return names


def collect_devices(
    ipver: IPMode,
    include_solicited_node: bool = False,
    target_macs: list[str] | None = None,
    target_ips: list[str] | None = None,
) -> list[dict]:
    """Build the device inventory from the addresses and roles already collected.

    Args:
        ipver: Enabled IP versions; addresses of a disabled family are omitted.
        include_solicited_node: True under -nc, where solicited-node groups are
            kept because they stand in for addresses that were never confirmed.
        target_macs: -target MAC values. A matching device is kept with all of
            its addresses.
        target_ips: -target IP values. Only the named address is kept, and only
            the device that holds it.

    The target semantics mirror the findings output exactly: the inventory used
    to ignore -target entirely, so asking for one device still produced the
    whole segment while every other output was scoped.
    """
    addresses_file = get_csv_path("addresses.csv")
    role_file = get_csv_path("role_node.csv")

    if not (has_additional_data(addresses_file) and has_additional_data(role_file)):
        return []

    try:
        addresses_df = read_csv_text(addresses_file)
        role_df = read_csv_text(role_file)
    except (OSError, ValueError, pd.errors.ParserError) as error:
        logger.debug("Could not read device inventory sources: %s", error)
        return []

    target_macs_set = {str(mac).strip().upper() for mac in target_macs} if target_macs else None
    target_ips_set = {str(ip).strip() for ip in target_ips} if target_ips else None

    selected_macs = None
    if target_macs_set or target_ips_set:
        mask = pd.Series(False, index=addresses_df.index)
        if target_macs_set:
            mask = mask | addresses_df["MAC"].astype(str).str.upper().isin(target_macs_set)
        if target_ips_set:
            mask = mask | addresses_df["IP"].astype(str).isin(target_ips_set)
        addresses_df = addresses_df[mask]
        selected_macs = set(addresses_df["MAC"].astype(str).str.upper().tolist())

    hostnames = _load_hostnames()
    devices = []

    for _, row in role_df.iterrows():
        mac = str(row.get("MAC", "")).strip()
        if not mac:
            continue
        if selected_macs is not None and mac.upper() not in selected_macs:
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


def flatten_devices(devices: list[dict]) -> list[dict]:
    """One row per address, carrying the identity of the device that owns it.

    A device with no confirmed address still gets a row with an empty ``IP``,
    so a MAC discovered during the scan cannot disappear from the inventory
    just because none of its addresses answered a probe.
    """
    rows: list[dict] = []
    for device in devices:
        addresses = ([(ip, "4") for ip in device["IPv4"].split() if ip]
                     + [(ip, "6") for ip in device["IPv6"].split() if ip])
        if not addresses:
            addresses = [("", "")]
        for ip, version in addresses:
            rows.append({
                "MAC": device["MAC"],
                "IP": ip,
                "IP_version": version,
                "Device": device["Device"],
                "Vendor": device["Vendor"],
                "Role": device["Role"],
                "Hostname": device["Hostname"],
            })
    return rows


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


def write_device_inventory(
    ipver: IPMode,
    include_solicited_node: bool = False,
    target_macs: list[str] | None = None,
    target_ips: list[str] | None = None,
) -> tuple[int, str | None]:
    """Write devices.csv and devices.txt next to the other output artifacts.

    Returns:
        tuple[int, str | None]: How many devices were written, and the directory
        they were written to (None when nothing was written).
    """
    devices = collect_devices(
        ipver,
        include_solicited_node=include_solicited_node,
        target_macs=target_macs,
        target_ips=target_ips,
    )
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
        with open(output_dir / "device_addresses.csv", "w", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=ADDRESS_FIELDS)
            writer.writeheader()
            writer.writerows(flatten_devices(devices))
    except OSError as error:
        # The per-device form is the primary artifact; losing the flat one must
        # not lose the inventory.
        logger.debug("Could not write device_addresses.csv: %s", error)

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
