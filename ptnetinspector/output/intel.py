"""Reporting for the data the extended parsers and probes collect.

These are the facts that were previously either thrown away (RA options past the
first prefix) or never asked for (the DNS-SD service tree, node information,
the multicast querier, the DHCPv6 option set). They are recon detail rather than
findings, so they are reported as their own section instead of being mixed into
the vulnerability output, and written to a file so a large result stays readable.
"""
import csv
import logging

from ptlibs import ptprinthelper
from tabulate import tabulate

import ipaddress
import textwrap

from ptnetinspector.utils.interface import get_joined_multicast_groups
from ptnetinspector.utils.ip_utils import has_additional_data
from ptnetinspector.utils.path import get_csv_path, get_current_interface, get_tmp_path


logger = logging.getLogger(__name__)

# How many rows of one kind to print to the terminal before pointing at the file.
TERMINAL_ROW_LIMIT = 12


def _read(name: str) -> list[dict]:
    path = get_csv_path(name)
    if not has_additional_data(path):
        return []
    try:
        with open(path, 'r', encoding='utf-8', errors='replace', newline='') as handle:
            return [row for row in csv.DictReader(handle)]
    except OSError as error:
        logger.debug("Could not read %s: %s", name, error)
        return []


def _section(title: str, headers: list[str], rows: list[list[str]]) -> str:
    if not rows:
        return ""
    return f"{title}\n" + tabulate(rows, headers=headers, tablefmt="simple",
                                   disable_numparse=True) + "\n\n"


def _ra_option_rows() -> list[list[str]]:
    # Prefix Information and MTU are already reported with the router itself.
    interesting = {"DNSSL", "Route Information", "PREF64", "Captive Portal",
                   "RDNSS", "Advertisement Interval"}
    return [
        [row.get("IP", ""), row.get("Option", ""), row.get("Value", ""),
         row.get("Lifetime", ""), row.get("Flags", "")]
        for row in _read("ra_options.csv")
        if row.get("Option", "") in interesting
    ]


def _service_rows() -> list[list[str]]:
    rows = []
    for row in _read("dnssd.csv"):
        instance = row.get("Instance", "")
        target = row.get("Target", "")
        port = row.get("Port", "")
        where = f"{target}:{port}" if target and port else target
        rows.append([row.get("MAC", ""), row.get("Service", ""), instance, where,
                     (row.get("TXT", "") or "")[:60]])
    return rows


def _node_info_rows() -> list[list[str]]:
    return [[row.get("MAC", ""), row.get("Type", ""), row.get("Value", "")]
            for row in _read("node_info.csv")]


def _querier_rows() -> list[list[str]]:
    return [[row.get("MAC", ""), row.get("IP", ""), row.get("Protocol", ""),
             row.get("QRV", ""), row.get("QQIC", "")]
            for row in _read("querier.csv")]


def _dhcpv6_rows() -> list[list[str]]:
    return [[row.get("MAC", ""), row.get("Option", ""), row.get("Value", "")]
            for row in _read("dhcpv6_options.csv")]


def _fingerprint_rows() -> list[list[str]]:
    """One row per device, merging the separate observations made about it.

    A device is observed many times during a scan; listing each observation
    separately made the same MAC appear repeatedly with conflicting guesses.
    """
    merged: dict[str, dict[str, list[str]]] = {}

    for row in _read("fingerprint.csv"):
        mac = str(row.get("MAC", "")).strip()
        if not mac:
            continue
        entry = merged.setdefault(mac, {"hop": [], "os": [], "iid": []})
        for key, column in (("hop", "Hop_limit"), ("os", "OS_guess"), ("iid", "IID_type")):
            value = str(row.get(column, "")).strip()
            if value and value not in entry[key]:
                entry[key].append(value)

    rows = []
    for mac, entry in merged.items():
        if not (entry["os"] or entry["iid"]):
            continue
        rows.append([mac, ", ".join(entry["hop"]), ", ".join(entry["os"]),
                     ", ".join(entry["iid"])])
    return rows


def _reverse_dns_rows() -> list[list[str]]:
    return [[row.get("MAC", ""), row.get("IP", ""), row.get("Name", ""),
             row.get("Resolver", "")]
            for row in _read("reverse_dns.csv")]


# IPv4's local network control block is flooded by design - IGMP snooping
# explicitly does not filter 224.0.0.0/24 - so its groups are not evidence of
# anything and are left out.
_ALWAYS_FLOODED_V4 = ipaddress.ip_network("224.0.0.0/24")


def _unjoined_multicast_rows(interface: str | None = None) -> list[list[str]]:
    """Groups whose traffic arrived here that this host never joined.

    A switch that snoops MLD/IGMP forwards a group only to ports that asked for
    it, so this is flooding evidence, and it is the half of the snooping
    question a single port can answer. It stays an observation rather than a
    verdict: some link-local groups are flooded by design in many switches.
    """
    rows = _read("multicast_groups.csv")
    if not rows:
        return []

    iface = interface or get_current_interface()
    if not iface:
        return []
    joined = get_joined_multicast_groups(iface)

    # Compare in canonical form, so a differently spelled address still matches.
    def canonical(value: str) -> str:
        try:
            return str(ipaddress.ip_address(str(value).strip()))
        except ValueError:
            return str(value).strip()

    joined_canonical = {canonical(group) for group in joined}

    observed: dict[str, dict] = {}
    for row in rows:
        group = canonical(row.get("Group", ""))
        if not group or group in joined_canonical:
            continue
        try:
            address = ipaddress.ip_address(group)
        except ValueError:
            continue
        # The recorder only stores multicast, but this file is read back from
        # disk, so a unicast address must never be reported as a flooded group.
        if not address.is_multicast:
            continue
        if address.version == 4 and address in _ALWAYS_FLOODED_V4:
            continue
        entry = observed.setdefault(group, {"version": row.get("Version", ""), "senders": set()})
        sender = str(row.get("Source_MAC", "")).strip()
        if sender:
            entry["senders"].add(sender)

    return [[group, data["version"], str(len(data["senders"])),
             ", ".join(sorted(data["senders"])[:3])
             + (" ..." if len(data["senders"]) > 3 else "")]
            for group, data in sorted(observed.items())]


_SECTIONS = (
    ("Router Advertisement options", ["Router", "Option", "Value", "Lifetime", "Flags"], _ra_option_rows),
    ("Discovered services (DNS-SD)", ["MAC", "Service", "Instance", "Host:Port", "TXT"], _service_rows),
    ("Node information replies", ["MAC", "Type", "Value"], _node_info_rows),
    ("Multicast querier", ["MAC", "IP", "Protocol", "QRV", "QQIC"], _querier_rows),
    ("DHCPv6 options offered", ["MAC", "Option", "Value"], _dhcpv6_rows),
    ("Passive fingerprints (heuristic, likely not certain)",
     ["MAC", "Hop limit", "Likely OS", "Interface identifier"], _fingerprint_rows),
    ("Reverse DNS", ["MAC", "IP", "Name", "Resolver"], _reverse_dns_rows),
    ("Multicast received without joining (L2 flooding evidence, not a verdict)",
     ["Group", "Version", "Senders", "Sending MACs"], _unjoined_multicast_rows),
)


def build_report() -> tuple[str, dict[str, int]]:
    """Render every populated section, and count the rows each one holds."""
    report = ""
    counts: dict[str, int] = {}
    for title, headers, collect in _SECTIONS:
        rows = collect()
        if not rows:
            continue
        counts[title] = len(rows)
        report += _section(title, headers, rows)
    return report, counts


def write_report() -> tuple[str | None, dict[str, int]]:
    """Write network-intel.txt next to the other artifacts.

    Returns:
        tuple[str | None, dict[str, int]]: The file written (None if there was
        nothing to write) and the per-section row counts.
    """
    report, counts = build_report()
    if not report:
        return None, counts

    path = get_tmp_path() / "network-intel.txt"
    try:
        path.write_text("ptnetinspector network intelligence\n\n" + report, encoding="utf-8")
    except OSError as error:
        logger.debug("Could not write network-intel.txt: %s", error)
        return None, counts

    return str(path), counts


def _is_prose(value: str) -> bool:
    """True for a value that can be wrapped at a space without losing meaning.

    A MAC, an address, a hostname or a URL has no spaces and must not be
    broken; a TXT record or a list of senders has and can be.
    """
    return " " in value.strip()


def _fit_table(rows: list[list[str]], headers: list[str], available: int) -> str:
    """Render a table no wider than `available` without breaking identifiers.

    These tables carry values taken off the wire - a TXT record, a captive
    portal URL, a list of sending MACs - and were rendered at their natural
    width, so one long value made every row wider than the terminal. A
    terminal that reflows on resize then rewrapped the whole table, which is
    what a broken report looks like.

    Only prose columns are wrapped, widest first, down to a floor. If the
    table still does not fit - a row of identifiers that is simply too wide
    for a narrow terminal - it is rendered stacked, one block per row, so an
    address is never cut in half to make a column fit.
    """
    columns = len(headers)
    cells = [[str(c) for c in row] + [""] * (columns - len(row)) for row in rows]
    natural = [max([len(headers[i])] + [len(r[i]) for r in cells]) for i in range(columns)]
    separators = 2 * (columns - 1)
    floor = 12

    if sum(natural) + separators <= available:
        return tabulate(cells, headers=headers, tablefmt="simple", disable_numparse=True)

    wrappable = {i for i in range(columns) if any(_is_prose(r[i]) for r in cells)}

    def shrink(budget):
        limits = list(natural)
        while sum(limits) + separators > budget:
            candidates = [i for i in wrappable if limits[i] > floor]
            if not candidates:
                return None
            widest = max(candidates, key=lambda i: limits[i])
            excess = sum(limits) + separators - budget
            limits[widest] = max(floor, limits[widest] - excess)
        return limits

    # tabulate wraps at spaces, so a single word longer than a column's limit
    # keeps the column wider than asked. Measure the result rather than trust
    # the estimate, and tighten the budget a few times before giving up.
    budget = available
    for _ in range(4):
        limits = shrink(budget)
        if limits is None:
            break
        maxcolwidths = [w if w < n else None for w, n in zip(limits, natural)]
        table = tabulate(cells, headers=headers, tablefmt="simple",
                         disable_numparse=True, maxcolwidths=maxcolwidths)
        widest = max(len(line) for line in table.splitlines())
        if widest <= available:
            return table
        budget -= widest - available

    # Stacked: label column, then the value wrapped at the remaining width.
    label_width = max(len(h) for h in headers) + 2
    value_width = max(20, available - label_width)
    blocks = []
    for row in cells:
        lines = []
        for header, value in zip(headers, row):
            if not value:
                continue
            wrapped = textwrap.wrap(value, width=value_width) or [""]
            lines.append(f"{header:<{label_width}}{wrapped[0]}")
            lines.extend(" " * label_width + more for more in wrapped[1:])
        blocks.append("\n".join(lines))
    return "\n\n".join(blocks)


def print_report(detailed: bool = False) -> None:
    """Print the sections to the terminal, truncating long ones to the file.

    Args:
        detailed: True under -v/-vv, where full tables are printed instead of
            the first few rows.
    """
    from ptnetinspector.output.non_json import Non_json

    _, counts = build_report()
    if not counts:
        return

    Non_json.print_box("Network intelligence")

    for title, headers, collect in _SECTIONS:
        rows = collect()
        if not rows:
            continue

        shown = rows if detailed else rows[:TERMINAL_ROW_LIMIT]
        ptprinthelper.ptprint(title, "INFO", condition=True, indent=4)
        # Read the width per table, so a terminal resized during the scan is
        # honoured by everything printed after it.
        available = max(40, Non_json._terminal_width() - 8)
        table = _fit_table(shown, headers, available)
        for line in table.splitlines():
            if line:
                ptprinthelper.ptprint(line, condition=True, indent=8)
            else:
                ptprinthelper.ptprint("", condition=True, indent=0)
        if len(shown) < len(rows):
            ptprinthelper.ptprint(
                f"... {len(rows) - len(shown)} more row(s); full table in network-intel.txt",
                condition=True,
                indent=8,
            )
        ptprinthelper.ptprint("", condition=True, indent=0)
