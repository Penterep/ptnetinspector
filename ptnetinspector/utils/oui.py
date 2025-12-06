import csv
from collections import OrderedDict
from pathlib import Path

from ptnetinspector.utils.path import get_csv_path


def get_manuf_path() -> Path:
    """
    Get the path to the manuf database file.
    
    Returns:
        Path: Path to the manuf file in the data directory.
    """
    # Get the project root directory (parent of utils)
    project_root = Path(__file__).parent.parent
    return project_root / 'data' / 'manuf'


def load_mac_database(filename: str | Path) -> dict:
    """
    Loads the MAC-to-vendor mapping from the manuf file.

    Args:
        filename (str | Path): The path to the manuf file.

    Returns:
        dict: A dictionary mapping MAC prefixes to vendor names.
    """
    mac_db = {}

    with open(filename, 'r', encoding='utf-8', errors='ignore') as file:
        for line in file:
            # skip comments and empty lines
            if line.startswith('#') or not line.strip():
                continue
            parts = line.split()
            if len(parts) < 3:
                continue
            oui = parts[0].split('/')[0].upper()
            vendor = ' '.join(parts[2:])
            mac_db[oui] = vendor

    return mac_db

def get_vendor(mac_address: str, mac_db: dict) -> str:
    """
    Returns the vendor name for a given MAC address.

    Args:
        mac_address (str): The MAC address to look up.
        mac_db (dict): The MAC-to-vendor mapping.

    Returns:
        str: The vendor name or "Unknown Vendor" if not found.
    """
    mac_address = mac_address.upper().replace("-", ":")

    # check longer prefixes first with 5 groups, then 4, then 3
    for i in [5, 4, 3]:
        mac_prefix = ":".join(mac_address.split(":")[:i])
        if mac_prefix in mac_db:
            return mac_db[mac_prefix]

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
        return "Unknown Vendor"

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