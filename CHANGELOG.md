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