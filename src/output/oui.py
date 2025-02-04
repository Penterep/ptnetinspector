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