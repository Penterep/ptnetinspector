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