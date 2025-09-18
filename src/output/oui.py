import csv
from collections import OrderedDict


def load_mac_database(filename: str) -> dict:
    """
    Loads the MAC-to-vendor mapping from the manuf file.

    Args:
        filename (str): The path to the manuf file.

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
    # read MAC addresses from input file, removing duplicates
    unique_macs = OrderedDict()
    try:
        with open('src/tmp/role_node.csv', 'r', encoding='utf-8') as infile:
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
        with open('src/tmp/vendors.csv', 'w', encoding='utf-8', newline='') as outfile:
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
    try:
        with open('src/tmp/vendors.csv', 'r', encoding='utf-8') as file:
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

    mac_db = load_mac_database('libs/manuf')
    process_mac_addresses_to_vendors(mac_db)
