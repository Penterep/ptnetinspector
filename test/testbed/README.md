# Local testbed

Runs ptnetinspector against a simulated LAN on a real link, so the capture,
parse and report path is exercised by frames that actually crossed an
interface rather than by packets handed straight to a parser.

No root and no second machine. An unprivileged user namespace supplies
`CAP_NET_ADMIN` and `CAP_NET_RAW` inside a private network namespace, and every
firewall rule, sysctl and address the tool touches applies only in there - so
the aggressive mode and the host-state save/restore path can be exercised
without putting the host's networking at risk.

## Layout

    scan0  <--- veth --->  lan0
    (scanner namespace)    (simulated LAN namespace)

`lan_sim.py` emulates four devices on `lan0`, each with its own MAC:

| Device | MAC | What it exercises |
| --- | --- | --- |
| Router | `00:50:56:c0:00:02` | RA with every option the scanner parses, DHCPv4/DHCPv6 replies |
| Workstation | `08:00:27:aa:bb:01` | hop limit 128, mDNS and LLMNR, MLDv2 and IGMPv3 reports |
| Printer | `b8:27:eb:11:22:33` | hop limit 64, DNS-SD service tree, Node Information replies |
| Switch | `00:1b:21:33:44:55` | MLDv2 and IGMPv3 general queries (querier election) |

The kernel in the LAN namespace is a fifth, genuinely real host: it runs its
own Duplicate Address Detection, answers Neighbour Solicitations and joins
multicast groups in response to the simulated router's advertisements.

## Running

    ./testbed.sh -t p -i scan0 -d 15          # passive
    ./testbed.sh -t a -i scan0 -vv            # active, verbose
    ./testbed.sh -t a+ -i scan0 -da+ 20       # aggressive (contained in the namespace)

Environment variables:

| Variable | Default | Purpose |
| --- | --- | --- |
| `SIM_DURATION` | `45` | how long the simulated LAN keeps transmitting |
| `BEACON_INTERVAL` | `2` | seconds between unsolicited bursts; raise it to keep the responder idle and quick to answer probes |
| `PCAP` | unset | write a capture of `scan0` to this path |
| `EXTRA_HOSTS` | `0` | emulate this many additional generic hosts, to see the report at the size of a real segment |

Results land in the usual place, under `tmp/scan0/` in the tool's data
directory.

## Reading the result

`lan_sim.py` prints what it sent, which is the baseline to compare the report
against. Note that the responder is single-threaded Python: under a fast beacon
rate it can take several hundred milliseconds to answer a Neighbour
Solicitation, which is longer than the address validator waits, so addresses
may be missing from `addresses.csv` while present in
`addresses_unfiltered.csv`. Raise `BEACON_INTERVAL` before reading anything
into that. A real host answers in well under a millisecond.
