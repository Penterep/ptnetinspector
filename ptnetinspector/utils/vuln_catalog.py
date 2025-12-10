import csv
from pathlib import Path

CATALOG_FILENAME = "vuln_catalog.csv"


def get_vuln_catalog_path() -> Path:
    """Return the path to the vulnerability catalog shipped with the package."""
    return Path(__file__).parent.parent / "data" / CATALOG_FILENAME


def load_vuln_catalog() -> dict[str, dict[str, str]]:
    """Load the vulnerability catalog into a dictionary keyed by code."""
    catalog_path = get_vuln_catalog_path()
    catalog: dict[str, dict[str, str]] = {}

    with open(catalog_path, newline="", encoding="utf-8") as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            code = row.get("Code", "").strip().upper()
            if not code:
                continue
            catalog[code] = {
                "ID": row.get("ID", "").strip(),
                "Mode": row.get("Mode", "").strip(),
                "IPver": row.get("IPver", "").strip(),
                "Description": row.get("Description", "").strip(),
            }

    return catalog
