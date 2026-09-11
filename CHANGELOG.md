## Version History

Version 0.1.0
-------------
- Initial release.

Version 0.1.1
-------------
- Adding network and device vulnerability related to Response to ICMPv6.

Version 0.1.2
-------------
- Adding device vulnerability summary table for the devices.
- Updating the structure of vulnerability analysis.
- Fixing bugs.

Version 0.1.3
-------------
- Adding device vulnerability summary table for the network.
- Separating vulnerabilities among modes.
- Showing how devices respond to each packet (IPv6 only).

Version 0.1.4
-------------
- Separating vulnerabilities for the case of IP version mode (-4 or -6)

Version 0.1.5
-------------
- Separating vulnerabilities tables for the case of IP version mode (-4 or -6)

Version 0.1.6
-------------
- Adding more vulnerabilities related to DNS-SD, WS-Discovery, IPv6 addresses
- Fixing N/A output of vulnerabilities

Version 0.1.7
-------------
- Added target vulnerability filtering (-ts) with strict mode/IP validation and fuzzy suggestions
- Added vulnerability catalog data file and packaging
- Deduplicated vulnerability outputs (keep longest description per code)
- Differentiated iptables setup messages for active vs aggressive scans
- Ensured JSON output prints for 802.1x-only runs
- Updated README for PyPI install and -ts usage

Version 0.1.8
-------------
- Improved JSON output structure: flattened device type, added gateway/DHCP flags
- Enhanced error handling and output persistence
- Standardized error output format across all validation scenarios

Version 0.1.9
-------------
- Updated IPv6 address predictability detection logic
- Enhanced version management and release process

Version 0.2.0
-------------
- Refactored vulnerability outputs into split MAC/IP/NET model with per-IP deduplication
- Paralelized requests of multiple tests
- Added MLD/IGMP subscription
- Improved IPv6 discovery: bruteforce of first 8 address bits and timing fixes
- Added detection of PTV-NET-IDENT-IP-6-INVEMPTYHBH/DEV and INVEMPTYDO/DEV; renamed ICMP-6-INVEMPTY* to IP-6-INVEMPTY*
- Added ICMPv6 ID counter
- Added target filtering by MAC/IP into parameter -target and hid network-level vulnerabilities for individual targets when filtered
- Made DNS-SD behavior consistent between IPv4 and IPv6; added mDNS unicast-response handling and per-query source ports
- Added burst control and send retry
- Explicit dst_mac to avoid neighbor solicitation in later tests
- Added counter of vulnerable devices per vulnerability
- Numerous bugfixes (scapy locking, race conditions, socket handling)
- Documentation and example Wireshark captures/filters updated
- Removed transitive dependencies

Version 0.2.1
-------------
- Improved query-response pairing

Version 0.2.2
-------------
- Fixed analysis of every mode after the first in a multi-mode run: the packet timeline
  was cached for the whole run, so later modes assessed only the packets captured before
  they started (`-t 802.1x a` reported 1 of 9 network findings)
- Findings re-evaluated by a later mode now supersede the earlier verdict
- Fixed mode filtering treating `a` as a prefix of `a+`, which showed aggressive-only
  findings inside the active-scan results
- 802.1x results are now displayed: the verdict was stored and returned in JSON while the
  terminal printed nothing (wrong source file, no analysis tables, findings without an IP
  family dropped by the `-4`/`-6` filter, and the verdict forced to N/A)
- Network-scoped findings are printed even when no device was discovered
- Added a vulnerability matrix table: codes as rows, network and devices as columns, with
  entities the finding does not apply to marked distinctly from a tested N/A result
- Fixed the dynamic burst limit being recomputed and re-logged on every send batch under
  `-vvv`; it is now resolved once per interface and reported once per sender
- Fixed duplicated devices and addresses in JSON output for passive and 802.1x modes
- JSON output no longer falls back to the unfiltered capture, which could report remote
  hosts seen in transit as addresses of a local device
- 802.1x mode now applies the local-network address filter, so remote hosts are no longer
  reported as gateway addresses
- Network vulnerabilities are no longer appended once per evaluation pass, and the network
  file is sorted and deduplicated like the MAC and IP files
- Network-scoped rows are no longer copied into the device-scoped file
- mDNS parsing now requires UDP port 5353; ordinary unicast DNS responses were recorded as
  mDNS, attributing answered addresses to whichever device relayed them
- `-nc` reworked: no ARP/Neighbour-Solicitation probes are sent and every observed address
  is reported, with solicited-node groups retained to reveal unconfirmed addresses
- Local-scope address filtering now also accepts RA-advertised prefixes and unique local
  addresses, so on-link neighbours are no longer discarded
- Dual-stack is the default; a single-stack interface now skips the missing family with a
  warning instead of failing
- Vulnerability tables adapt to the terminal width instead of overflowing on large subnets
- The raw address capture is shown under `-vv` in all modes
- Error exits now return a non-zero status
- Reachability-check status is reported only in modes that actually probe
- Fixed "Destionation" typo in ICMPv6 and IPv6 option-header findings
- Documentation updated for `-nc`, `-4`/`-6` defaults, and IP-version behaviour
Robustness
- A malformed MLDv2 or IGMPv3 report no longer aborts the scan: the record loops are
  bounded by the parsed record list instead of the attacker-controlled `records_number`
  / `numgrp` header field, and every per-protocol parser now absorbs its own errors so
  one bad frame cannot discard the results collected so far
- DHCPv4 parsing no longer indexes `options[0]`: the message-type option is searched for,
  a packet carrying no options is handled, and ACK (5) is recognised alongside OFFER (2)
  as identifying the server
- `SIGTERM` and `SIGHUP` are trapped alongside `SIGINT`, and firewall/forwarding
  restoration is registered with `atexit`, so any exit short of `SIGKILL` leaves the
  interface as it was found
- Blocking rules are tagged (`-m comment --comment ptnetinspector`) and added only when
  absent, so an interrupted run no longer stacks duplicate DROP rules; a later run flushes
  anything a `SIGKILL` left behind
- Aggressive mode records the host's forwarding sysctls before changing them and restores
  the original values instead of forcing them to 0
- iptables rule detection asks `iptables -C` for the tagged rule instead of string-matching
  `-S` output, which differs between iptables versions and the legacy/nft backends
- The global lock is no longer removed while another process holds its `flock`, closing a
  race in which two runs could mutate iptables concurrently; waiting for a previous run is
  now bounded rather than indefinite
- Routing tables are read with iproute2 (`ip route`) instead of the deprecated net-tools
  `route`, whose absence silently dropped both tables from the report

Correctness
- `is_valid_ipv6` uses the standard library; the previous regex matched embedded IPv4
  octets as `25[0-4]`, so any address containing 255 (`::ffff:192.168.1.255`) was judged
  invalid and dropped from the output
- Router Advertisements: every advertised prefix is recorded, not only the first, so a
  router announcing a GUA and a ULA prefix is reported in full
- Vulnerability findings are written only against addresses of the family they were tested
  on; IPv4 findings (mDNS among them) were being recorded against a device's IPv6
  addresses and the reverse
- `-nc` now also reports neighbours on a private range outside the auto-detected subnets
  (a host-only or secondary interface range), which the on-link filter removed even when
  checking was disabled. Publicly routable addresses seen in transit are still excluded,
  because they belong to hosts beyond the router rather than to the device that relayed
  the frame
- JSON no longer collapses repeated properties: multiple IPv6 prefixes and DNS servers are
  reported as lists rather than overwriting each other
- DNS-SD PTR answers are no longer recorded as a device's hostname
- The declared Python floor is `>=3.10`, matching the pinned numpy/pandas and the PEP 604
  annotations already used in runtime signatures; installing on 3.8/3.9 previously failed
  during dependency resolution
- `packets.csv` populates its `length` column; captures without a link-layer header
  (cooked/`any`) are skipped instead of producing empty-MAC rows
- Addresses sort numerically, IPv4 before IPv6, instead of lexicographically
- Interrupted runs exit with 128 + signal number instead of 0
- Usage errors (unknown flag, invalid choice, missing value) exit 2 and validation errors
  exit 1, in both text and `-j` mode; previously the same invalid invocation reported a
  different status depending on `-j`, which a script could not act on

New output
- `devices.csv` and `devices.txt`: a plain device inventory (MAC, vendor, role, hostname,
  addresses) written separately from the findings, so a segment with many hosts stays
  readable
- `network-intel.txt` and a matching terminal section collecting the recon detail below

New data collected
- Router Advertisement options that were previously discarded: DNSSL search domains
  (RFC 8106), Route Information (RFC 4191), PREF64/NAT64 (RFC 8781), Captive Portal
  (RFC 8910), every Prefix Information and RDNSS option
- Passive host fingerprints from fields already captured: initial hop limit and the
  interface-identifier scheme (EUI-64, low-bit, or randomized stable-privacy/temporary),
  reported as likely rather than certain, and never derived from the protocol-fixed hop
  limits of Neighbour Discovery or MLD
- ICMPv6 Node Information Queries (RFC 4620): hostnames and full address lists from stacks
  that answer them
- The DNS-SD service tree: service types, instances, and the SRV host/port and TXT
  metadata for each instance
- DHCPv6 Information-Request and its option set: resolvers, domain search list, NTP/SNTP
  and SIP servers, boot-file URL, vendor class and server DUID
- The elected MLD/IGMP querier, an L2 snooping probe, and addresses observed being claimed
  through Duplicate Address Detection
- `-rdns` (opt-in): reverse-resolves discovered addresses via PTR against the resolvers
  found on the link. Off by default because it is the only probe that leaves the link

Fixes found by running the scanner against a live link
- CSV values are no longer reinterpreted on the round-trip through pandas: a hop limit of
  255 was written back and reported as "255.0", a QRV of 2 as "2.0", and an absent
  hostname as the literal string "nan"
- Sorting an artifact by MAC no longer moves the address column independently of the rest
  of the row: a device that was both the MLDv2 and the IGMPv3 querier was listed at the
  wrong address for each protocol. Affected every artifact with an `IP` column and more
  than two columns
- The hop-limit fingerprint is taken only from traffic whose hop limit the sender chose.
  mDNS, LLMNR and Node Information Queries also pin it to 255, which was not accounted
  for, so every device that answered one was additionally reported as a router-class
  network device
- An IGMPv3 General Query is recognised. Scapy dissects it as IGMPv3/IGMPv3mq with no
  IGMP layer, so the querier a modern segment elects was never recorded; the query's
  robustness and interval are read from whichever layer carries them
- Hostnames taken off the wire are validated before being stored, so a malformed mDNS,
  LLMNR or Node Information reply can no longer carry NUL bytes and DNS length prefixes
  into the hostname column and the device inventory
- Repeated network properties survive in `-j` output. `add_properties()` merges with
  `dict.update()`, so publishing one value at a time meant only the last DNS search
  domain, advertised route and multicast querier reached the JSON; each is now emitted
  as a list when more than one was seen
- A run killed with SIGKILL during aggressive mode left the host forwarding. The tagged
  firewall rules were already flushed by the next run; the forwarding sysctls are now
  recovered the same way, and still left untouched on a host that was forwarding anyway

Fixes
- `-4` and `-6` no longer put the other family on the wire. The filtered address list is
  also the list the reachability probe sends to, and it was not gated on the requested
  family, so `-6` emitted ARP for observed IPv4 addresses and `-4` emitted Neighbour
  Solicitations for IPv6 ones. The raw view is unchanged: `addresses_unfiltered.csv` is
  written before the filter runs
- The IP family a scan can actually use is now reconciled against the interface for every
  scan type, not only active mode, and each branch enables the family the interface does
  have instead of only clearing the one it lacks, so no combination ends with nothing to
  scan
- An interface with no IPv6 address no longer reports an error for addresses it was never
  going to verify; the message now names how many addresses were actually affected
- `-target` now scopes the device inventory as well. It filtered the findings and the JSON
  but not `devices.csv`, `devices.txt` or `device_addresses.csv`, so asking for one device
  still produced the whole segment there. A target MAC keeps that device with all of its
  addresses and a target IP keeps only the named address, matching the findings output

- The L2 snooping probe now produces a result. It announced membership of an unused
  multicast group and nothing read the outcome, because whether that group reaches ports
  which never joined it is only visible from one of those ports. The half a single port
  can measure is reported instead: every multicast group whose traffic arrived here is
  recorded in `multicast_groups.csv`, compared against this host's own memberships as
  read from the kernel, and the groups that arrived without being joined are reported as
  flooding evidence. IPv4's `224.0.0.0/24` is excluded, being flooded by design. It stays
  an observation, not a verdict: some link-local groups are flooded by design too

- A frame framed in anything but Ethernet no longer aborts the scan. The packet log chose
  its branch from a classifier that tested the network layer before the framing, so IP or
  IPv6 carried over 802.3 with LLC/SNAP, or in an 802.11 data frame from a monitor-mode
  capture, reached a branch that read `packet[Ether]` and raised `IndexError` - the same
  class of failure as a malformed MLDv2 report. The 802.11 branch meant to catch the
  latter was unreachable and read `.src`/`.dst`, which `Dot11` does not provide, and an
  unclassifiable frame was routed to it. Link addresses are now read from whichever
  framing the frame actually carries; VLAN-tagged and 802.3 frames such as STP were
  already handled and still are

Fixes found by fuzzing the parse and report paths
- An mDNS or LLMNR answer whose record data is not valid UTF-8 ended the scan. It was
  decoded at the call site, before the hostname sanitiser ran, so `UnicodeDecodeError`
  propagated out of the analysis loop - a denial of service any host on the segment could
  trigger with one frame. The bytes now reach the sanitiser undecoded
- The hostname sanitiser itself accepted things that cannot be a name: a `bytearray` or
  `memoryview` was stringified as its repr, `None` became "None", and bytes that were not
  text at all became a row of replacement characters. Non-ASCII names are still kept, as
  RFC 6762 names are UTF-8
- A byte that is not valid UTF-8 anywhere in an artifact aborted the whole report at the
  end of a scan. Every read of these files now decodes with replacement, including
  `has_additional_data`, which is the guard every other read is gated on and so must not
  be the thing that raises
- A ragged row - what a scan killed mid-write leaves behind - aborted the sort pass; such
  rows are now dropped
- An artifact truncated to nothing aborted the report. Handling that at the reader alone
  only moved the crash to a caller indexing a column that was no longer there, so
  `create_csv` and `read_csv_text` now share one schema table and a truncated file reads
  back as no rows with its proper columns

JSON output reported no vulnerabilities (regression fix)
- The `-j` output was emitting an empty vulnerability list and no per-device findings,
  even when the scan had found plenty. Reading the CSV artifacts as strings - the fix that
  stopped a hop limit of 255 being written back as "255.0" - also made the `Label` column
  a string, and the verdict test compared it to the integer 1, which is always false. Every
  finding was silently dropped from the JSON, and from the detailed network sections of the
  terminal report; the main analysis, summary and matrix tables were unaffected because
  they coerce the label to an int. Verdicts are now normalized to an int at every comparison
  through one helper, and a regression test drives the JSON path and asserts the vulnerable
  codes are present and the not-vulnerable and N/A ones are not

Terminal width
- Every table is rendered to the terminal width read at the moment it is
  printed, so a report is no longer left as shattered box-drawing after the
  window is resized, maximized, or zoomed. The intelligence tables carried
  values taken off the wire - a TXT record, a captive portal URL, a list of
  MACs - and were drawn at their natural width, so one long value pushed every
  row past the edge; they now wrap their prose columns, never their
  identifiers (a MAC or address is never split), and stack one block per row
  on a very narrow terminal. The per-finding status grid and the matrix
  estimated their width and the estimate ran short, so tables the estimate
  passed still overflowed; both now measure the rendered result and fall back
  when it does not fit. The matrix legend and the device-inventory paths, which
  ran to 250 characters on one line, are split across lines.
  (Already-printed lines cannot reflow when a terminal is resized - that is the
  terminal's own behaviour - but the program no longer emits a table wider than
  the window for the terminal to mangle.)
- The ASCII banner is 64 columns wide; on a narrower terminal it wrapped into
  fragments. Below that width a compact one-line title with the version and URL is
  shown instead, on every path that prints the banner, including the -h help screen.

Large segments
- Past ten devices the terminal report is condensed, as asked for in the review, and the
  output file keeps the full version. Measured on a 35-device scan: 1,799 terminal lines
  became 812, and the matrix went from nine 116-line blocks to one table per family
- The vulnerability matrix puts devices on rows once there are more than ten. With codes
  as rows and devices as columns it split into one block per four devices - fifty blocks
  at two hundred devices. Devices are the unbounded dimension, so they scroll; the columns
  are the finding numbers from the analysis above, with a key printed under the tables.
  Network-scoped and device-scoped findings are separated, and device findings are split
  by IP family so each table is narrow enough to read at once and IPv4 and IPv6 verdicts
  are not interleaved. Below ten devices the layout is unchanged
- Each finding lists the vulnerable devices in full - they are the finding - and gives the
  not-vulnerable and N/A devices as a count rather than a list of two hundred numbers. The
  full lists still go to `ptnetinspector-output.txt`
- The summary opens with the one line an operator wants first, "N of M devices have at
  least one vulnerability", and past ten devices drops the boxed grid for one line per
  device
- The matrix legend is split across lines so it fits a narrow terminal

Behaviour change
- With neither `-4` nor `-6`, the scan is now IPv6 only; IPv4 is opt-in with `-4`. Scanning
  both families by default was a change from the tool's earlier behaviour and was reported
  as such. On an interface with no IPv6 address the scan falls back to IPv4 with a warning,
  so a single-stack IPv4 interface still scans rather than scanning nothing

New output
- `device_addresses.csv`: the device inventory flattened to one row per address, with the
  owning device repeated on each row, so a segment can be searched by address or filtered
  by family. The per-device form keeps a host's addresses in one cell, which reads well but
  cannot be split on the delimiter

Testing
- `test/fuzz/` fuzzes both paths that take untrusted input: the packet parser, where one
  frame's exception aborts the scan, and the report, where one bad byte throws away a
  completed run. 43 seed frames covering every protocol parsed, byte-level mutation,
  ~90 hand-built frames that lie in their own count and length fields, and hostile CSV
  content through every output path. No root and no network; each exits non-zero on a
  crash or a hang, so they can be wired into CI
- `test/testbed/` gained `EXTRA_HOSTS=N` to emulate a segment of any size, which is how
  the large-segment layout was measured
- `test/testbed/` runs the scanner against a simulated four-device LAN over a real veth
  link, in an unprivileged user namespace: no root, no second machine, and any firewall
  rule or sysctl the tool changes applies only inside that namespace
