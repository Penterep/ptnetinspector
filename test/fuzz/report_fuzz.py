"""Fuzz the report path with adversarial CSV content.

Everything in these files came off the wire: hostnames from mDNS, addresses
from Neighbour Discovery, TXT records from DNS-SD. The report runs at the very
end of a scan, so a crash here throws away the whole run's work.
"""
import csv
import io
import os
import random
import signal
import sys
import tempfile
import traceback
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path

REPO = Path(os.environ.get("PTNET_REPO", Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(REPO))

import ptnetinspector.utils.path as pathmod

TMP = Path(tempfile.mkdtemp(prefix="fuzz-report-"))
pathmod.get_output_dir = lambda base_path=None: TMP

from ptnetinspector.utils.csv_helpers import create_csv, sort_all_csv
from ptnetinspector.utils.path import set_current_interface, get_csv_path, get_tmp_path
from ptnetinspector.send.send import IPMode
from ptnetinspector.output import devices as devmod
from ptnetinspector.output import intel as intelmod
from ptnetinspector.output import json as jsonmod
from ptnetinspector.output.non_json import Non_json
from ptnetinspector.utils import csv_helpers

# no real interface here
csv_helpers.get_if_hwaddr = lambda _i: "ff:ff:ff:ff:ff:ff"

set_current_interface("fuzz")

# Hostile values, all of which can arrive in a real answer off the wire.
NASTY = [
    "", " ", "\t", "\x00", "\x00\x01\x02", "\x7f", "\r\n", "\n\ninjected",
    "a" * 300, "a" * 5000, "=cmd|'/c calc'!A1", '"quoted"', "semi;colon",
    "comma,inside", "'apostrophe", "\\backslash", "%s%n%x", "../../etc/passwd",
    "ünïcödé", "🔥emoji", "NaN", "nan", "inf", "-1", "1e999",
    "255.0", "0.0", "None", "null", "true",
]
BAD_MACS = ["", "not-a-mac", "aa:bb", "AA:BB:CC:DD:EE:FF", "aa:bb:cc:dd:ee:ff:gg",
            "00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "aa-bb-cc-dd-ee-ff", "🔥"]
BAD_IPS = ["", "not-an-ip", "999.999.999.999", "::", "::1", "0.0.0.0",
           "fe80::1%eth0", "2001:db8::/64", "192.168.1.1/24", "-1", "1.2.3",
           "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "224.0.0.1", "ff02::1"]
BAD_NUMS = ["", "0", "-1", "abc", "1.5", "999999999999999999999", "NaN", "inf", "0x10", "1e5"]

SCHEMAS = {
    "addresses.csv": ["MAC", "IP"],
    "addresses_unfiltered.csv": ["MAC", "IP"],
    "role_node.csv": ["MAC", "Device_Number", "Role"],
    "localname.csv": ["MAC", "name"],
    "ra_options.csv": ["MAC", "IP", "Option", "Value", "Lifetime", "Flags"],
    "fingerprint.csv": ["MAC", "Hop_limit", "OS_guess", "IID_type", "Reachable_time", "Retrans_time", "Router_lft"],
    "dnssd.csv": ["MAC", "IP", "Service", "Instance", "Target", "Port", "TXT"],
    "querier.csv": ["MAC", "IP", "Protocol", "Group", "QRV", "QQIC", "Max_response"],
    "node_info.csv": ["MAC", "IP", "Type", "Value"],
    "dhcpv6_options.csv": ["MAC", "IP", "Option", "Value"],
    "reverse_dns.csv": ["MAC", "IP", "Name", "Resolver"],
    "multicast_groups.csv": ["Group", "Version", "Source_MAC"],
    "vulnerability_ip.csv": ["ID", "IP", "Mode", "IPver", "Code", "Description", "Label"],
    "vulnerability_mac.csv": ["ID", "MAC", "Mode", "Code", "Description", "Label"],
    "vulnerability_net.csv": ["ID", "Mode", "Code", "Description", "Label"],
    "networks.csv": ["network_prefix", "prefix_length"],
    "default_gw.csv": ["MAC", "IP"],
    "dhcp.csv": ["MAC", "IP", "Type", "Server"],
}


def value_for(column, rng):
    c = column.lower()
    if "mac" in c:
        return rng.choice(BAD_MACS + NASTY)
    if c in ("ip", "group", "resolver", "target", "network_prefix"):
        return rng.choice(BAD_IPS + NASTY)
    if any(k in c for k in ("id", "number", "port", "lifetime", "limit", "time", "lft",
                            "qrv", "qqic", "label", "length", "response")):
        return rng.choice(BAD_NUMS + NASTY)
    return rng.choice(NASTY)


def seed_files(rng):
    create_csv("fuzz")
    for name, cols in SCHEMAS.items():
        mode = rng.random()
        path = get_csv_path(name)
        if mode < 0.10:
            continue                                    # leave it header-only
        if mode < 0.15:
            path.write_text("")                         # truncate to nothing
            continue
        if mode < 0.20:
            path.write_text(",".join(cols) + "\n" + "garbage without commas\n")
            continue
        if mode < 0.23:
            # bytes that are not valid UTF-8 - the tool reads these files as text
            with open(path, "wb") as h:
                h.write(",".join(cols).encode() + b"\n")
                h.write(b"\xff\xfe" + b"," .join([b"\x80\x81"] * (len(cols) - 1)) + b"\n")
            continue
        if mode < 0.25:
            # a row with too few / too many fields
            with open(path, "w", newline="") as h:
                h.write(",".join(cols) + "\n")
                h.write(",".join(["x"] * max(1, len(cols) - 2)) + "\n")
                h.write(",".join(["y"] * (len(cols) + 3)) + "\n")
            continue
        rows = []
        for _ in range(rng.randint(1, 6)):
            rows.append({c: value_for(c, rng) for c in cols})
        with open(path, "w", newline="", errors="replace") as h:
            w = csv.DictWriter(h, fieldnames=cols)
            w.writeheader()
            w.writerows(rows)


class Timeout(Exception):
    pass


def _alarm(_s, _f):
    raise Timeout("report did not finish in 15s")


def exercise(rng):
    """Every output entry point main.py drives at the end of a scan."""
    ipver = rng.choice([IPMode(True, True), IPMode(False, True), IPMode(True, False)])
    detail = rng.random() < 0.5
    steps = [
        ("sort_all_csv", lambda: sort_all_csv("fuzz")),
        ("devices.write_device_inventory",
         lambda: devmod.write_device_inventory(ipver, include_solicited_node=rng.random() < 0.5)),
        ("devices.write_device_inventory+target",
         lambda: devmod.write_device_inventory(ipver, target_macs=["aa:bb:cc:00:00:01"], target_ips=["fe80::1"])),
        ("intel.build_report", lambda: intelmod.build_report()),
        ("intel.write_report", lambda: intelmod.write_report()),
        ("intel.print_report", lambda: intelmod.print_report(detailed=detail)),
        ("json.output_object",
         lambda: jsonmod.Json.output_object(False, "a", ipver=ipver, check_addresses=True)),
        ("json.output_object+target",
         lambda: jsonmod.Json.output_object(False, "a", ipver=ipver,
                                            target_macs=["aa:bb:cc:00:00:01"],
                                            target_ips=["fe80::1"], check_addresses=False)),
        ("non_json.output_general",
         lambda: Non_json.output_general("a", ipver)),
    ]
    problems = []
    for label, call in steps:
        signal.alarm(15)
        try:
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                call()
        except Timeout as exc:
            problems.append((label, "HANG", str(exc), ""))
        except Exception as exc:
            tb = traceback.extract_tb(exc.__traceback__)
            ours = [f for f in tb if "ptnetinspector" in f.filename]
            # name the caller, not the shared helper it died inside
            callers = [f for f in ours if "csv_helpers.py" not in f.filename]
            site = (callers or ours or tb)[-1]
            where = f"{Path(site.filename).name}:{site.lineno} in {site.name}"
            full = "".join(traceback.format_exception(exc)).strip().splitlines()
            problems.append((label, type(exc).__name__, str(exc)[:180], where + "\n       || " + "\n       || ".join(l.strip() for l in full[-8:])))
        finally:
            signal.alarm(0)
    return problems


def main():
    iterations = int(sys.argv[1]) if len(sys.argv) > 1 else 300
    signal.signal(signal.SIGALRM, _alarm)
    rng = random.Random(1234)
    unique = {}
    for i in range(iterations):
        seed_files(rng)
        for label, kind, msg, where in exercise(rng):
            key = (kind, where, label)
            if key not in unique:
                unique[key] = {"msg": msg, "count": 0, "iteration": i}
            unique[key]["count"] += 1
        if i and i % 100 == 0:
            print(f"  ... {i} iterations, {len(unique)} unique failures", flush=True)

    print(f"\n{iterations} adversarial report runs")
    print(f"unique failure sites: {len(unique)}\n")
    for (kind, where, label), info in sorted(unique.items(), key=lambda kv: -kv[1]["count"]):
        print(f"=== {kind} in {label}  (x{info['count']}) ===")
        print(f"    {where}")
        print(f"    {info['msg']}")
        print()
    return 1 if unique else 0


if __name__ == "__main__":
    sys.exit(main())
