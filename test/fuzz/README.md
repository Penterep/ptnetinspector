# Fuzzing

An exception anywhere in the analysis of one frame aborts the whole scan, and
an exception in the report throws away a completed run's work. Both inputs come
off the wire, so both are fuzzed.

Nothing here needs root or a network.

    python3 test/fuzz/structured.py            # adversarial frames, built by hand
    python3 test/fuzz/fuzz.py -n 25000 -s 1    # byte-level mutation of a seed corpus
    python3 test/fuzz/report_fuzz.py 400       # hostile CSV content through the report

Each exits non-zero if it finds a crash or a hang, so they can be wired into CI.

## What each one covers

`corpus.py` holds 43 seed frames, one per protocol the tool parses: every
Neighbour Discovery message with the full option set, MLDv1/v2, IGMPv1/v2/v3,
mDNS and the DNS-SD service tree, LLMNR, Node Information Queries, DHCPv4,
DHCPv6, EAPOL, WS-Discovery, SSDP, and the odd framings - VLAN, QinQ, 802.3
with LLC/SNAP, 802.11 from a monitor-mode capture.

`fuzz.py` mutates those bytes: bit flips, byte substitution with edge values,
truncation, extension, splicing two seeds together, and smashing a
self-describing count or length field to 0xFF. Samples scapy itself cannot
dissect are counted separately - those never reach the tool from `sniff()`.

`structured.py` builds ~90 frames that lie in the places byte mutation rarely
reaches with a plausible packet: a record count larger than the records
present, an option length of zero, a prefix length of 255, a name that runs
past its buffer, nested and repeated layers. Each is given five seconds, so an
infinite loop is reported as a hang rather than hanging the run.

`report_fuzz.py` fills every artifact with hostile content - control
characters, lone quotes, embedded commas and newlines, 5000-character values,
formula injection, invalid UTF-8, ragged rows, missing headers, files truncated
to nothing - and then drives every output path a scan ends with: the sort pass,
the device inventory, the intelligence report, the JSON, and the terminal
report.

## Bugs these found

- IP or IPv6 framed in anything but Ethernet aborted the scan, because the
  packet log chose its branch from the network layer before the framing.
- A byte that is not valid UTF-8 in any artifact aborted the whole report.
- A ragged row - a scan killed mid-write - aborted the sort pass.
- An artifact truncated to nothing aborted the report, and once that was
  handled at the reader, the crash simply moved downstream to a caller
  indexing a column that was no longer there. That is why `create_csv` and
  `read_csv_text` now share one schema table.
