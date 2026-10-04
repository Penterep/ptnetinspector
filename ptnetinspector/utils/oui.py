"""OUI/vendor lookup utilities for MAC addresses.

Handles reading the local manuf database and resolving MAC prefixes to vendor
names, and exposes helpers used during CSV/JSON enrichment.
"""
import csv
import logging
from collections import OrderedDict
from pathlib import Path

from ptnetinspector.utils.path import get_csv_path


logger = logging.getLogger(__name__)


def get_manuf_path() -> Path:
    """
    Get the path to the manuf database file.

    Returns:
        Path: Path to the manuf file in the data directory.
    """
    # Get the project root directory (parent of utils)
    project_root = Path(__file__).parent.parent
    return project_root / 'data' / 'manuf'


def _mac_nibbles(mac_address: str) -> str:
    """The hex digits of a MAC, upper-cased, with separators removed."""
    return mac_address.upper().replace(":", "").replace("-", "")


def _is_locally_administered(nibbles: str) -> bool:
    """True when the U/L bit is set: a randomized or hand-assigned MAC.

    Such an address was never allocated to a manufacturer (virtual NICs, MAC
    randomization, many routers' synthetic addresses), so an OUI lookup can only
    ever miss on it - saying so is more honest than "Unknown Vendor".
    """
    try:
        first_octet = int(nibbles[:2], 16)
    except ValueError:
        return False
    return bool(first_octet & 0x02)


def load_mac_database(filename: str | Path) -> dict:
    """
    Loads the MAC-to-vendor mapping from the manuf file.

    The file mixes MA-L (/24), MA-M (/28) and MA-S (/36) allocations - the two
    smaller ones are over half the entries. Each is keyed by the hex nibbles its
    mask actually covers (6, 7 or 9), so a MAC can be matched against the right
    prefix length. Keying by colon-groups, as before, silently dropped every
    /28 and /36 vendor because their 3.5- and 4.5-octet prefixes never lined up
    on a group boundary.

    Args:
        filename (str | Path): The path to the manuf file.

    Returns:
        dict: A dictionary mapping MAC hex-nibble prefixes to vendor names.
    """
    mac_db = {}

    with open(filename, 'r', encoding='utf-8', errors='ignore') as file:
        for line in file:
            # skip comments and empty lines
            if line.startswith('#') or not line.strip():
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            token = parts[0]
            if '/' in token:
                address, _, mask = token.partition('/')
                try:
                    bits = int(mask)
                except ValueError:
                    bits = 24
            else:
                address, bits = token, 24
            key = _mac_nibbles(address)[: max(0, bits // 4)]
            if not key:
                continue
            # The long name (columns 3+) is preferred; fall back to the short
            # name when a line has no long form.
            vendor = ' '.join(parts[2:]) if len(parts) >= 3 else parts[1]
            mac_db[key] = vendor

    return mac_db

# Prefix lengths, in hex nibbles, for the IEEE allocation sizes in the manuf
# file: MA-S (/36), MA-M (/28), MA-L (/24). Longest first so the most specific
# registration wins.
_PREFIX_NIBBLES = (9, 7, 6)


def get_vendor(mac_address: str, mac_db: dict) -> str:
    """
    Returns the vendor name for a given MAC address.

    Args:
        mac_address (str): The MAC address to look up.
        mac_db (dict): The MAC-to-vendor mapping.

    Returns:
        str: The vendor name, "Locally administered (no vendor)" for a MAC that
        carries no manufacturer, or "Unknown Vendor" when it is globally unique
        but absent from the database.
    """
    nibbles = _mac_nibbles(mac_address)

    # A locally administered address was never assigned to a vendor, so there is
    # nothing to look up; naming that is more accurate than an empty lookup.
    if len(nibbles) >= 2 and _is_locally_administered(nibbles):
        return "Locally administered (no vendor)"

    for length in _PREFIX_NIBBLES:
        if nibbles[:length] in mac_db:
            return mac_db[nibbles[:length]]

    return "Unknown Vendor"


def process_mac_addresses_to_vendors(mac_db: dict) -> None:
    """
    Processes MAC addresses from the input CSV file, removes duplicates,
    identifies vendors and writes them to the output CSV file.

    Args:
        mac_db (dict): The MAC-to-vendor mapping dictionary.
    """
    role_node_csv = get_csv_path('role_node.csv')
    vendors_csv = get_csv_path('vendors.csv')

    # read MAC addresses from input file, removing duplicates
    unique_macs = OrderedDict()
    try:
        with open(role_node_csv, 'r', encoding='utf-8') as infile:
            # skip header row
            reader = csv.reader(infile)
            header = next(reader)

            # get index of MAC column
            mac_index = header.index('MAC') if 'MAC' in header else 0

            # Process each line
            for row in reader:
                if len(row) > mac_index:
                    mac = row[mac_index].strip()
                    unique_macs[mac] = None
    except Exception as e:
        logger.debug("Failed to read role_node.csv for vendor generation: %s", e)
        return

    # write MAC addresses with their vendors to output file
    try:
        with open(vendors_csv, 'w', encoding='utf-8', newline='') as outfile:
            writer = csv.writer(outfile)
            writer.writerow(['MAC', 'Vendor_Name'])

            for mac in unique_macs:
                vendor = get_vendor(mac, mac_db)
                writer.writerow([mac, vendor])
    except Exception as e:
        logger.debug("Failed to write vendors.csv: %s", e)
        return


def lookup_vendor_from_csv(mac_address: str) -> str:
    """
    Looks up the vendor name for a given MAC address in the vendors CSV file.

    Args:
        mac_address (str): The MAC address to look up.

    Returns:
        str: The vendor name or "Unknown Vendor" if not found.
    """
    vendors_csv = get_csv_path('vendors.csv')

    try:
        with open(vendors_csv, 'r', encoding='utf-8') as file:
            reader = csv.reader(file)
            # skip header
            next(reader)

            for row in reader:
                if len(row) >= 2 and row[0] == mac_address:
                    return row[1]
    except Exception as e:
        logger.debug("Vendor lookup failed for %s: %s", mac_address, e)
        return "Unknown Vendor"

    # Not pre-computed into vendors.csv: still name a locally administered MAC
    # rather than calling it unknown.
    if _is_locally_administered(_mac_nibbles(mac_address)):
        return "Locally administered (no vendor)"
    return "Unknown Vendor"

def create_vendor_csv() -> None:
    """
    Loads the MAC-to-vendor mapping from the manuf file, processes MAC addresses
    from the input CSV file, removes duplicates, identifies vendors and writes
    them to the output CSV file.
    """
    manuf_path = get_manuf_path()
    mac_db = load_mac_database(manuf_path)
    process_mac_addresses_to_vendors(mac_db)