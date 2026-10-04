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
import textwrap

import pandas as pd

from ptnetinspector.utils.csv_helpers import read_csv_text
from ptnetinspector.send.send import IPMode
from ptnetinspector.utils.ip_utils import (
    has_additional_data,
    in6_getansma,
    in6_getnsma,
    is_llsnm_ipv6,
    is_valid_ipv6,
    normalize_ipv6,
)
from ptnetinspector.utils.oui import lookup_vendor_from_csv
from ptnetinspector.utils.output_helpers import transform_role_print
from ptnetinspector.utils.path import get_csv_path, get_tmp_path


logger = logging.getLogger(__name__)

FIELDS = ['Device', 'MAC', 'Vendor', 'Role', 'Hostname', 'IPv4', 'IPv6', 'IP_count', 'Ports']

# Leading MAC/IP matches every other artifact this tool writes, so the flat
# inventory can be read by the same helpers and eyeballed the same way.
ADDRESS_FIELDS = ['Device', 'MAC', 'IP', 'IP_version', 'Vendor', 'Role', 'Hostname']


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
    role_file = get_csv_path("role_node.csv")

    # role_node.csv is the authoritative device list, so it alone gates the
    # inventory. addresses.csv is where the addresses come from, but it can be
    # empty at output time even when devices were found - under -nc it is
    # rewritten from whatever mappings survived, and an aggressive IPv6 run can
    # leave it empty while the devices still exist in role_node.csv. When that
    # happens the unfiltered file is the next-best address source; if both are
    # empty the devices are still reported, just without addresses, rather than
    # the whole summary disappearing.
    if not has_additional_data(role_file):
        return []

    addresses_file = get_csv_path("addresses.csv")
    if not has_additional_data(addresses_file):
        unfiltered_file = get_csv_path("addresses_unfiltered.csv")
        if has_additional_data(unfiltered_file):
            addresses_file = unfiltered_file

    try:
        role_df = read_csv_text(role_file)
    except (OSError, ValueError, pd.errors.ParserError) as error:
        logger.debug("Could not read device inventory sources: %s", error)
        return []

    try:
        addresses_df = (read_csv_text(addresses_file)
                        if has_additional_data(addresses_file)
                        else pd.DataFrame(columns=["MAC", "IP"]))
    except (OSError, ValueError, pd.errors.ParserError) as error:
        logger.debug("Could not read device addresses, continuing without them: %s", error)
        addresses_df = pd.DataFrame(columns=["MAC", "IP"])

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
    from ptnetinspector.entities.port import Port
    ports_by_mac = Port.collect_by_mac()
    devices = []

    for _, row in role_df.iterrows():
        mac = str(row.get("MAC", "")).strip()
        if not mac:
            continue
        if selected_macs is not None and mac.upper() not in selected_macs:
            continue

        device_ips = addresses_df.loc[addresses_df["MAC"] == mac, "IP"].astype(str).tolist()

        ipv4_addresses, ipv6_addresses = [], []
        solicited_groups = []
        for ip in device_ips:
            ip = ip.strip()
            if not ip:
                continue
            if is_valid_ipv6(ip):
                if not ipver.ipv6:
                    continue
                address = ipaddress.IPv6Address(ip)
                # The unspecified address "::" is observed on the wire (e.g. as a
                # DAD source) and recorded under -nc, but it is never a host's
                # own address, so it has no place in the inventory.
                if address.is_unspecified:
                    continue
                # A solicited-node group is a multicast address the host listens
                # on, not an address it owns; it stands in for a unicast address
                # that was never confirmed, so it is derived into a "possible"
                # address below rather than listed as the host's own.
                if is_llsnm_ipv6(ip):
                    solicited_groups.append(ip)
                    continue
                if address.is_multicast:
                    continue
                ipv6_addresses.append(ip)
            else:
                try:
                    ipv4 = ipaddress.IPv4Address(ip)
                except ipaddress.AddressValueError:
                    continue
                if ipv4.is_unspecified:
                    continue
                if ipver.ipv4:
                    ipv4_addresses.append(ip)

        ipv4_addresses = sorted(set(ipv4_addresses), key=_sort_key)
        ipv6_addresses = sorted(set(ipv6_addresses), key=_sort_key)

        # Under -nc, turn the solicited-node groups that no confirmed address
        # already accounts for into the "possible" unicast addresses they imply,
        # matching the derivation the verbose per-device view and JSON use.
        possible_ipv6 = []
        if include_solicited_node and solicited_groups:
            confirmed = {normalize_ipv6(in6_getnsma(ip)) for ip in ipv6_addresses}
            for group in solicited_groups:
                if normalize_ipv6(group) not in confirmed:
                    possible_ipv6.append(in6_getansma(group))
            possible_ipv6 = sorted(set(possible_ipv6))

        devices.append({
            "Device": str(row.get("Device_Number", "")).strip(),
            "MAC": mac,
            "Vendor": lookup_vendor_from_csv(mac),
            "Role": transform_role_print(str(row.get("Role", ""))),
            "Hostname": hostnames.get(mac.upper(), ""),
            "IPv4": " ".join(ipv4_addresses),
            "IPv6": " ".join(ipv6_addresses),
            "IPv6_possible": " ".join(possible_ipv6),
            "IP_count": str(len(ipv4_addresses) + len(ipv6_addresses)),
            "Ports": " ".join(f"{port}/{proto}"
                              for proto, port in ports_by_mac.get(mac.upper(), [])),
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
                "Device": device["Device"],
                "MAC": device["MAC"],
                "IP": ip,
                "IP_version": version,
                "Vendor": device["Vendor"],
                "Role": device["Role"],
                "Hostname": device["Hostname"],
            })

    # Keep flat output aligned with the project-wide CSV ordering convention:
    # MAC first, then numeric IP ordering (IPv4 before IPv6, then value).
    rows.sort(key=lambda row: (
        str(row.get("MAC", "")).upper(),
        *_sort_key(str(row.get("IP", ""))),
        str(row.get("Device", "")),
    ))
    return rows


# Fixed width used when rendering to a file, where there is no terminal to
# measure. 100 columns comfortably holds an IPv6 address plus the table framing
# while staying readable when pasted into a ticket or diffed.
_FILE_WIDTH = 100


def _device_table_row(device: dict) -> list[str]:
    """One grid row per device: identity, then its addresses and ports stacked.

    Device, MAC and Vendor identify the device and appear once. The vendor comes
    from the MAC's OUI, so unlike the OS guess it is reliable and worth showing.
    The addresses and ports are packed into their own cells, one per line, so a
    device with many of either grows its cell downward rather than widening the
    row - the table never has to span to the right to show everything, and the
    grid rule falls between devices, not between every address.
    """
    addresses = [ip for ip in device.get("IPv4", "").split() + device.get("IPv6", "").split() if ip]
    # Derived, unconfirmed addresses (from -nc solicited-node groups) follow the
    # confirmed ones, each marked so it is not mistaken for a real address.
    addresses += [f"{ip} (possible)" for ip in device.get("IPv6_possible", "").split() if ip]
    ports = [port for port in (device.get("Ports", "") or "").split() if port]

    return [
        device.get("Device", ""),
        device.get("MAC", ""),
        (device.get("Vendor", "") or "").strip() or "-",
        "\n".join(addresses) if addresses else "-",
        "\n".join(ports) if ports else "-",
    ]


def _render_device_table(devices: list[dict], width: int = 0) -> str:
    """Render the Device / MAC / IP / Port table as a bordered grid.

    Each device is a single grid row whose IP and Port cells stack their values
    one per line, so the box rule separates devices (matching the other reports)
    while the table still only grows downward: an address never shares a line
    with another, and the width is bounded by one IPv6 column, not by how many
    addresses or ports a device has. ``width`` is unused - the grid sizes itself
    to its content - but kept so callers can pass the terminal width uniformly.
    """
    from tabulate import tabulate

    rows = [_device_table_row(device) for device in devices]
    if not rows:
        return ""

    return tabulate(rows, headers=["Device", "MAC", "Vendor", "IP", "Port"],
                    tablefmt="grid", disable_numparse=True,
                    colalign=("left", "left", "left", "left", "left"))


def _render_table(devices: list[dict]) -> str:
    """Render the inventory for ``devices.txt``, at a fixed readable width.

    Kept under its historical name because the file writer and tests call it.
    """
    return _render_device_table(devices, _FILE_WIDTH)


def print_device_summary(
    ipver: IPMode,
    include_solicited_node: bool = False,
    target_macs: list[str] | None = None,
    target_ips: list[str] | None = None,
) -> None:
    """Print the final device summary to the operator-facing terminal."""
    from ptnetinspector.output.non_json import Non_json
    from ptlibs import ptprinthelper

    devices = collect_devices(
        ipver,
        include_solicited_node=include_solicited_node,
        target_macs=target_macs,
        target_ips=target_ips,
    )
    if not devices:
        return

    address_count = sum(int(device["IP_count"]) for device in devices)
    port_count = sum(len(device.get("Ports", "").split()) for device in devices)

    Non_json.print_box("Device Summary")
    summary = f"{len(devices)} device(s), {address_count} address(es), {port_count} port(s)"
    ptprinthelper.ptprint(summary, condition=True, indent=4)
    ptprinthelper.ptprint("", condition=True, indent=0)

    # Fit the table to the live terminal, leaving room for the indent the
    # printer adds so the columns never wrap off the right edge.
    width = Non_json._terminal_width() - 4
    table = _render_device_table(devices, width)
    for line in table.splitlines():
        if line:
            ptprinthelper.ptprint(line, condition=True, indent=4)
        else:
            ptprinthelper.ptprint("", condition=True, indent=0)


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
            # IPv6_possible is a render-time detail for the summary, not a column
            # of the flat inventory, so it is dropped rather than written here.
            writer = csv.DictWriter(handle, fieldnames=FIELDS, extrasaction="ignore")
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
        port_count = sum(len(device.get("Ports", "").split()) for device in devices)
        # The file carries the same Device / MAC / IP / Port table shown on the
        # terminal, so it stands on its own.
        header = (
            f"Device Summary\n"
            f"{len(devices)} device(s), {address_count} address(es), "
            f"{port_count} port(s)\n\n"
        )
        content = header + _render_table(devices) + "\n"
        (output_dir / "devices.txt").write_text(content, encoding="utf-8")
    except OSError as error:
        logger.debug("Could not write devices.txt: %s", error)

    return len(devices), str(output_dir)
