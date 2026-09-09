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

from ptnetinspector.utils.ip_utils import has_additional_data
from ptnetinspector.utils.path import get_csv_path, get_tmp_path


logger = logging.getLogger(__name__)

# How many rows of one kind to print to the terminal before pointing at the file.
TERMINAL_ROW_LIMIT = 12


def _read(name: str) -> list[dict]:
    path = get_csv_path(name)
    if not has_additional_data(path):
        return []
    try:
        with open(path, newline="") as handle:
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


_SECTIONS = (
    ("Router Advertisement options", ["Router", "Option", "Value", "Lifetime", "Flags"], _ra_option_rows),
    ("Discovered services (DNS-SD)", ["MAC", "Service", "Instance", "Host:Port", "TXT"], _service_rows),
    ("Node information replies", ["MAC", "Type", "Value"], _node_info_rows),
    ("Multicast querier", ["MAC", "IP", "Protocol", "QRV", "QQIC"], _querier_rows),
    ("DHCPv6 options offered", ["MAC", "Option", "Value"], _dhcpv6_rows),
    ("Passive fingerprints (heuristic, likely not certain)",
     ["MAC", "Hop limit", "Likely OS", "Interface identifier"], _fingerprint_rows),
    ("Reverse DNS", ["MAC", "IP", "Name", "Resolver"], _reverse_dns_rows),
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
        table = tabulate(shown, headers=headers, tablefmt="simple", disable_numparse=True)
        for line in table.splitlines():
            ptprinthelper.ptprint(line, condition=True, indent=8)
        if len(shown) < len(rows):
            ptprinthelper.ptprint(
                f"... {len(rows) - len(shown)} more row(s); full table in network-intel.txt",
                condition=True,
                indent=8,
            )
        ptprinthelper.ptprint("", condition=True, indent=0)
