"""Mutation fuzzer for ptnetinspector's packet parse path.

An exception anywhere in the analysis of one frame aborts the whole scan, so
any crash here is a denial-of-service on the scan from a single hostile or
malformed frame - the H1 class of defect.

Frames are dissected before being handed over, and samples scapy itself cannot
dissect are counted separately: those never reach the tool from sniff() and are
scapy's business, not the tool's.
"""
import argparse
import os
import random
import sys
import tempfile
import traceback
from pathlib import Path

REPO = Path(os.environ.get("PTNET_REPO", Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(REPO))          # the working tree, never the installed copy
sys.path.insert(1, str(Path(__file__).parent))

import ptnetinspector.utils.path as pathmod

TMP = Path(tempfile.mkdtemp(prefix="fuzz-"))
pathmod.get_output_dir = lambda base_path=None: TMP

from scapy.all import conf
from corpus import seeds
from ptnetinspector.utils.csv_helpers import create_csv
from ptnetinspector.utils.path import set_current_interface, get_csv_path
from ptnetinspector import scan as scanmod
from ptnetinspector.scan import Save
from ptnetinspector.send.send import IPMode

SCANNER_MAC = "ff:ff:ff:ff:ff:ff"

conf.verb = 0

# There is no real interface here; the scanner's own MAC is all the analysis
# needs it for.
scanmod.get_if_hwaddr = lambda _interface: SCANNER_MAC

set_current_interface("fuzz")
create_csv("fuzz")

IP_MODES = [IPMode(True, True), IPMode(False, True), IPMode(True, False)]


# ----------------------------------------------------------------- mutators --
def m_bitflip(data, rng):
    out = bytearray(data)
    for _ in range(rng.randint(1, 6)):
        i = rng.randrange(len(out))
        out[i] ^= 1 << rng.randrange(8)
    return bytes(out)


def m_byteset(data, rng):
    out = bytearray(data)
    for _ in range(rng.randint(1, 6)):
        i = rng.randrange(len(out))
        out[i] = rng.choice([0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF, rng.randrange(256)])
    return bytes(out)


def m_truncate(data, rng):
    if len(data) <= 15:
        return data
    return data[:rng.randrange(14, len(data))]


def m_extend(data, rng):
    return data + bytes(rng.randrange(256) for _ in range(rng.randint(1, 64)))


def m_splice(data, rng, pool):
    other = rng.choice(pool)
    cut = rng.randrange(1, len(data))
    return data[:cut] + other[min(cut, len(other) - 1):]


def m_counter_smash(data, rng):
    """Set a 1- or 2-byte field to a large value.

    Record and option counts (records_number, numgrp, ancount, an option's
    len) are the fields that turn one frame into an unbounded loop or an
    out-of-range index.
    """
    out = bytearray(data)
    if len(out) <= 15:
        return bytes(out)
    i = rng.randrange(14, len(out))
    out[i] = 0xFF
    if rng.random() < 0.5 and i + 1 < len(out):
        out[i + 1] = 0xFF
    return bytes(out)


MUTATORS = [m_bitflip, m_byteset, m_truncate, m_extend, m_counter_smash]


def mutate(data, rng, pool):
    for _ in range(rng.randint(1, 3)):
        fn = rng.choice(MUTATORS + [m_splice])
        data = fn(data, rng, pool) if fn is m_splice else fn(data, rng)
        if not data:
            return b"\x00" * 14
    return data


# ------------------------------------------------------------------- driver --
def signature(exc: BaseException) -> tuple:
    """Key a crash by the deepest frame inside ptnetinspector."""
    tb = traceback.extract_tb(exc.__traceback__)
    ours = [f for f in tb if "ptnetinspector" in f.filename and "/fuzz/" not in f.filename]
    site = ours[-1] if ours else (tb[-1] if tb else None)
    where = f"{Path(site.filename).name}:{site.lineno} in {site.name}" if site else "?"
    return (type(exc).__name__, where)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-n", "--iterations", type=int, default=20000)
    ap.add_argument("-s", "--seed", type=int, default=0)
    args = ap.parse_args()

    rng = random.Random(args.seed)
    corpus = seeds()
    names = sorted(corpus)
    pool = [corpus[n][0] for n in names]

    crashes = {}
    undissectable = 0
    fed = 0

    for i in range(args.iterations):
        name = rng.choice(names)
        raw, cls = corpus[name]
        data = mutate(raw, rng, pool)

        try:
            packet = cls(data)
            repr(packet)                      # force full dissection
        except Exception:
            undissectable += 1
            continue

        ip_mode = rng.choice(IP_MODES)
        fed += 1
        for label, call in (("save_async", lambda: Save.save_async([packet])),
                            ("save_packets", lambda: Save.save_packets("fuzz", ip_mode, [packet]))):
            try:
                call()
            except Exception as exc:
                key = signature(exc) + (label,)
                if key not in crashes:
                    crashes[key] = {
                        "seed_name": name,
                        "hex": data.hex(),
                        "message": f"{type(exc).__name__}: {exc}"[:200],
                        "count": 0,
                        "trace": "".join(traceback.format_exception(exc)).strip().splitlines()[-6:],
                    }
                crashes[key]["count"] += 1

        if i and i % 5000 == 0:
            # keep the artifacts from growing without bound
            create_csv("fuzz")
            print(f"  ... {i} samples, {len(crashes)} unique crashes", flush=True)

    print(f"\nfed {fed} dissectable samples ({undissectable} rejected by scapy itself)")
    print(f"unique crash sites: {len(crashes)}\n")
    for (exc_type, where, entry_point), info in sorted(crashes.items(), key=lambda kv: -kv[1]["count"]):
        print(f"=== {exc_type} at {where}  (via {entry_point}, x{info['count']}) ===")
        print(f"    seed: {info['seed_name']}")
        print(f"    {info['message']}")
        for line in info["trace"]:
            print(f"      {line.strip()}")
        print(f"    repro hex: {info['hex'][:160]}{'...' if len(info['hex']) > 160 else ''}")
        print()
    return 1 if crashes else 0


if __name__ == "__main__":
    sys.exit(main())
