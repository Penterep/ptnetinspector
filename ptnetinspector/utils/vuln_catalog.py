"""Vulnerability catalog access utilities.

Loads the static vulnerability catalog shipped with the package and exposes
helpers to look up by code or by Test, used to filter/report vulnerabilities.
"""
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
                "Test": row.get("Test", "").strip(),
            }

    return catalog


def load_vuln_catalog_by_test() -> dict[str, list[dict[str, str]]]:
    """Load the vulnerability catalog into a dictionary keyed by Test code.
    Each Test code maps to a list of vulnerability entries with that Test value."""
    catalog_path = get_vuln_catalog_path()
    test_index: dict[str, list[dict[str, str]]] = {}

    with open(catalog_path, newline="", encoding="utf-8") as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            test_code = row.get("Test", "").strip().upper()
            if not test_code:
                continue
            
            entry = {
                "ID": row.get("ID", "").strip(),
                "Mode": row.get("Mode", "").strip(),
                "IPver": row.get("IPver", "").strip(),
                "Code": row.get("Code", "").strip().upper(),
                "Description": row.get("Description", "").strip(),
                "Test": test_code,
            }
            
            if test_code not in test_index:
                test_index[test_code] = []
            test_index[test_code].append(entry)

    return test_index
