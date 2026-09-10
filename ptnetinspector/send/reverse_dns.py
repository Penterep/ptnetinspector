"""Reverse-DNS resolution against the resolvers the scan discovered.

Reverse lookups otherwise ride mDNS and LLMNR, both of which are link-local: a
host that does not speak either is invisible to them. Once RDNSS or DHCPv6 has
named the site's resolvers, an ordinary ``PTR`` query in ``ip6.arpa`` /
``in-addr.arpa`` will name every host whose reverse zone is populated.

This is the one probe here that leaves the link - it is unicast DNS to a real
resolver, which is louder and arguably outside "local recon" - so it runs only
when the operator asks for it with ``-rdns``.
"""
import csv
import ipaddress
import logging

from scapy.all import DNS, DNSQR, IP, IPv6, UDP, sr1

from ptnetinspector.entities._registry import registry
from ptnetinspector.send.send import IPMode
from ptnetinspector.utils.ip_utils import has_additional_data, reverse_IPadd
from ptnetinspector.utils.path import get_csv_path


logger = logging.getLogger(__name__)

# Bounds so a large segment cannot turn this into a long unicast storm.
MAX_ADDRESSES = 256
QUERY_TIMEOUT = 1.0


def discover_resolvers(ip_mode: IPMode) -> list[str]:
    """Collect resolver addresses learned from RA (RDNSS) and DHCPv6.

    Only resolvers the scan actually observed are used; nothing is guessed and
    no system resolver is consulted.
    """
    resolvers: list[str] = []

    def _add(value: str) -> None:
        candidate = str(value).strip().strip("[]'\"")
        if not candidate or candidate in resolvers:
            return
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            return
        if address.version == 6 and not ip_mode.ipv6:
            return
        if address.version == 4 and not ip_mode.ipv4:
            return
        resolvers.append(candidate)

    ra_options = get_csv_path("ra_options.csv")
    if has_additional_data(ra_options):
        try:
            with open(ra_options, 'r', encoding='utf-8', errors='replace', newline='') as handle:
                for row in csv.DictReader(handle):
                    if str(row.get("Option", "")).strip() == "RDNSS":
                        _add(row.get("Value", ""))
        except OSError as error:
            logger.debug("Could not read RA options for resolvers: %s", error)

    dhcpv6_options = get_csv_path("dhcpv6_options.csv")
    if has_additional_data(dhcpv6_options):
        try:
            with open(dhcpv6_options, 'r', encoding='utf-8', errors='replace', newline='') as handle:
                for row in csv.DictReader(handle):
                    if str(row.get("Option", "")).strip() == "DNS server":
                        _add(row.get("Value", ""))
        except OSError as error:
            logger.debug("Could not read DHCPv6 options for resolvers: %s", error)

    return resolvers


def _collect_addresses(ip_mode: IPMode) -> list[tuple[str, str]]:
    """Discovered MAC/IP pairs worth a reverse lookup.

    Link-local and multicast addresses have no reverse zone, so they are skipped.
    """
    addresses_file = get_csv_path("addresses.csv")
    if not has_additional_data(addresses_file):
        return []

    pairs: list[tuple[str, str]] = []
    try:
        with open(addresses_file, 'r', encoding='utf-8', errors='replace', newline='') as handle:
            for row in csv.DictReader(handle):
                mac = str(row.get("MAC", "")).strip()
                ip = str(row.get("IP", "")).strip()
                if not ip:
                    continue
                try:
                    address = ipaddress.ip_address(ip)
                except ValueError:
                    continue
                if address.is_link_local or address.is_multicast or address.is_loopback:
                    continue
                if address.version == 6 and not ip_mode.ipv6:
                    continue
                if address.version == 4 and not ip_mode.ipv4:
                    continue
                if (mac, ip) not in pairs:
                    pairs.append((mac, ip))
    except OSError as error:
        logger.debug("Could not read addresses for reverse lookup: %s", error)

    return pairs[:MAX_ADDRESSES]


def _save(mac: str, ip: str, name: str, resolver: str) -> None:
    key = (mac, ip, name, resolver)
    if registry.seen("reverse_dns", key):
        return
    with open(get_csv_path("reverse_dns.csv"), "a", newline="") as handle:
        csv.DictWriter(handle, fieldnames=["MAC", "IP", "Name", "Resolver"]).writerow(
            {"MAC": mac, "IP": ip, "Name": name, "Resolver": resolver}
        )


def _query_ptr(resolver: str, ip: str) -> str | None:
    """Ask one resolver for the PTR of one address."""
    try:
        resolver_address = ipaddress.ip_address(resolver)
    except ValueError:
        return None

    layer3 = IPv6(dst=resolver) if resolver_address.version == 6 else IP(dst=resolver)
    query = layer3 / UDP(sport=0, dport=53) / DNS(rd=1, qd=DNSQR(qname=reverse_IPadd(ip), qtype="PTR"))

    try:
        answer = sr1(query, timeout=QUERY_TIMEOUT, verbose=0)
    except Exception as error:
        logger.debug("Reverse lookup of %s via %s failed: %s", ip, resolver, error)
        return None

    if answer is None or DNS not in answer or not answer[DNS].ancount:
        return None

    for index in range(answer[DNS].ancount):
        try:
            record = answer[DNS].an[index]
        except (IndexError, AttributeError):
            break
        if getattr(record, "type", None) != 12:
            continue
        name = getattr(record, "rdata", b"")
        if isinstance(name, bytes):
            name = name.decode(errors="replace")
        name = str(name).rstrip(".")
        if name:
            return name
    return None


def resolve_discovered_addresses(ip_mode: IPMode) -> int:
    """Reverse-resolve every discovered address against the discovered resolvers.

    Returns:
        int: How many names were resolved.
    """
    resolvers = discover_resolvers(ip_mode)
    if not resolvers:
        logger.debug("No resolvers were discovered; skipping reverse DNS")
        return 0

    resolved = 0
    for mac, ip in _collect_addresses(ip_mode):
        for resolver in resolvers:
            name = _query_ptr(resolver, ip)
            if name:
                _save(mac, ip, name, resolver)
                resolved += 1
                break

    return resolved
