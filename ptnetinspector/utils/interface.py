#!/usr/bin/env python3
"""Network interface helpers.

Encapsulates detecting/manipulating interface addresses and iptables rule state
required by passive/active/aggressive scan modes.
"""
import ipaddress
import json
import logging
import os
import subprocess
import sys
import netifaces
from ptlibs import ptprinthelper
from ptnetinspector.utils.path import get_tmp_path


logger = logging.getLogger(__name__)

# Every rule this tool inserts carries this comment. Matching on the comment
# instead of on the canonical form iptables prints for `-S` keeps detection
# working across iptables versions and across the legacy and nft backends, and
# it lets a later run identify and flush rules a hard kill left behind.
RULE_TAG = "ptnetinspector"
_COMMENT = ["-m", "comment", "--comment", RULE_TAG]

_FORWARDING_SYSCTLS = ("net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding")


def _run(command: list[str], check: bool = False) -> subprocess.CompletedProcess | None:
    """Run a firewall command, swallowing the noise but not the diagnostics."""
    try:
        return subprocess.run(
            command,
            check=check,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        logger.debug("Command not available: %s", command[0])
        return None
    except subprocess.CalledProcessError as error:
        logger.debug("Command failed: %s (%s)", " ".join(command), error)
        return None


def _rule_exists(binary: str, chain: str, rule: list[str]) -> bool:
    """Ask iptables itself whether a rule is present, instead of parsing `-S`."""
    result = _run([binary, "-C", chain] + rule)
    return result is not None and result.returncode == 0


def _add_rule(binary: str, chain: str, rule: list[str]) -> None:
    """Append a tagged rule once.

    `shutdown_traffic` used to append unconditionally, so a run killed before
    restore stacked a second identical DROP that one `-D` pass could not clear.
    """
    tagged = rule + _COMMENT
    if _rule_exists(binary, chain, tagged):
        return
    _run([binary, "-A", chain] + tagged)


def _delete_rule(binary: str, chain: str, rule: list[str]) -> None:
    """Remove every instance of a tagged rule, not just the first."""
    tagged = rule + _COMMENT
    while _rule_exists(binary, chain, tagged):
        if _run([binary, "-D", chain] + tagged) is None:
            break
    # Rules written by an older version carried no comment; clear those too.
    while _rule_exists(binary, chain, rule):
        if _run([binary, "-D", chain] + rule) is None:
            break


def _read_sysctl(name: str) -> str | None:
    try:
        output = subprocess.check_output(
            ["sysctl", "-n", name], stderr=subprocess.DEVNULL, universal_newlines=True
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        logger.debug("Could not read sysctl %s", name)
        return None
    return output.strip()


def _write_sysctl(name: str, value: str) -> None:
    _run(["sysctl", "-w", f"{name}={value}"])


def _sysctl_state_file():
    return get_tmp_path() / "sysctl_state.json"


def save_forwarding_state() -> None:
    """Remember the host's forwarding settings before aggressive mode changes them.

    Restoring blindly to 0 turned forwarding off on routers and lab gateways
    that had it on before the scan ran.
    """
    path = _sysctl_state_file()
    if path.exists():
        return
    state = {name: _read_sysctl(name) for name in _FORWARDING_SYSCTLS}
    try:
        path.write_text(json.dumps(state), encoding="utf-8")
    except OSError as error:
        logger.debug("Could not persist sysctl state: %s", error)


def restore_forwarding_state() -> None:
    """Put the forwarding sysctls back the way the host had them."""
    path = _sysctl_state_file()
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        # save_forwarding_state() runs before the first sysctl write, so no
        # recorded state means this run never enabled forwarding. Writing 0 here
        # would disable it on a host that had it on all along.
        logger.debug("No recorded forwarding state; leaving the sysctls untouched")
        return

    for name in _FORWARDING_SYSCTLS:
        value = state.get(name)
        if value is not None:
            _write_sysctl(name, value)
    try:
        path.unlink()
    except OSError:
        # The state file is advisory; a stale copy is harmless.
        pass


def _parse_igmp6(text: str, interface: str) -> set[str]:
    """Groups from /proc/net/igmp6, whose lines are `idx name hexaddr users flags timer`."""
    groups: set[str] = set()
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 3 or fields[1] != interface:
            continue
        raw = fields[2]
        if len(raw) != 32:
            continue
        try:
            packed = bytes.fromhex(raw)
        except ValueError:
            continue
        groups.add(str(ipaddress.IPv6Address(packed)))
    return groups


def _parse_igmp(text: str, interface: str) -> set[str]:
    """Groups from /proc/net/igmp.

    The file is grouped by interface: an unindented header names the device and
    the indented lines that follow list its groups, little-endian hex.
    """
    groups: set[str] = set()
    current = None
    for line in text.splitlines():
        if not line or line.startswith(("Idx", "\t\t")):
            if not line.startswith("\t\t"):
                continue
        if not line.startswith(("\t", " ")):
            # "4\tscan0     :     1      V3"
            head = line.split(":", 1)[0].split()
            current = head[1] if len(head) > 1 else None
            continue
        if current != interface:
            continue
        fields = line.split()
        if not fields:
            continue
        raw = fields[0]
        if len(raw) != 8:
            continue
        try:
            packed = bytes.fromhex(raw)[::-1]        # stored little-endian
        except ValueError:
            continue
        groups.add(str(ipaddress.IPv4Address(packed)))
    return groups


def get_joined_multicast_groups(interface: str) -> set[str]:
    """Multicast groups this host has actually joined on `interface`.

    Read from the kernel rather than inferred, so it includes the memberships
    the stack takes out on its own - all-nodes, the solicited-node group of
    every local address, the IGMP all-hosts group. Without those the comparison
    in the flooding report would call ordinary traffic unexpected.
    """
    groups: set[str] = set()
    for path, parser in (("/proc/net/igmp6", _parse_igmp6), ("/proc/net/igmp", _parse_igmp)):
        try:
            with open(path, encoding="utf-8") as handle:
                groups |= parser(handle.read(), interface)
        except OSError as error:
            logger.debug("Could not read %s: %s", path, error)
    return groups


def flush_tagged_rules() -> None:
    """Delete every rule this tool ever tagged, in both tables.

    SIGKILL cannot be trapped, so a previous run can leave DROP rules behind and
    take the operator's interface off the network. This is the self-heal a later
    run (or an explicit cleanup) uses to recover.
    """
    for binary in ("iptables", "ip6tables"):
        for chain in ("INPUT", "OUTPUT", "FORWARD"):
            try:
                output = subprocess.check_output(
                    [binary, "-S", chain], stderr=subprocess.DEVNULL, universal_newlines=True
                )
            except (subprocess.CalledProcessError, FileNotFoundError):
                continue
            for line in output.splitlines():
                if RULE_TAG not in line or not line.startswith("-A "):
                    continue
                arguments = line.split()[2:]
                _run([binary, "-D", chain] + arguments)


class Interface:
    """
    Interface class for network interface operations.
    """

    def __init__(self, interface: str):
        """
        Initialize the Interface object.

        Args:
            interface (str): Name of the network interface.
        """
        self.interface = interface

    def get_interface_ips(self) -> list:
        """
        Retrieve all IP addresses (IPv4 and IPv6) of the network interface.

        Returns:
            list: List of IP addresses assigned to the interface.
        """
        interface_ips = []
        if self.interface in netifaces.interfaces():
            interface_addrs = netifaces.ifaddresses(self.interface)
            for addr_type in (netifaces.AF_INET, netifaces.AF_INET6):
                if addr_type in interface_addrs:
                    for addr_info in interface_addrs[addr_type]:
                        interface_ips.append(addr_info['addr'])
        return interface_ips

    def get_interface_ipv4_ips(self) -> list:
        """
        Retrieve IPv4 addresses of the network interface.

        Returns:
            list: List of IPv4 addresses assigned to the interface.
        """
        interface_ips = []
        if self.interface in netifaces.interfaces():
            interface_addrs = netifaces.ifaddresses(self.interface)
            if netifaces.AF_INET in interface_addrs:
                for addr_info in interface_addrs[netifaces.AF_INET]:
                    interface_ips.append(addr_info['addr'])
        return interface_ips

    def get_interface_ipv6_ips(self) -> list:
        """
        Retrieve IPv6 addresses of the network interface.

        Returns:
            list: List of IPv6 addresses assigned to the interface.
        """
        interface_ips = []
        if self.interface in netifaces.interfaces():
            interface_addrs = netifaces.ifaddresses(self.interface)
            if netifaces.AF_INET6 in interface_addrs:
                for addr_info in interface_addrs[netifaces.AF_INET6]:
                    if '%' in addr_info['addr']:
                        interface_ips.append(addr_info['addr'].split('%')[0])
                    else:
                        interface_ips.append(addr_info['addr'])
        return interface_ips

    def get_interface_link_local_list(self) -> list:
        """
        Retrieve link-local IPv6 addresses of the network interface.

        Returns:
            list: List of link-local IPv6 addresses (starting with 'fe80').
        """
        ips = self.get_interface_ips()
        list_ll = []
        for ipv6 in ips:
            if ipv6.startswith("fe80"):
                list_ll.append(ipv6)
        return list_ll

    def get_interface_global_unicast_list(self) -> list:
        """
        Retrieve global IPv6 addresses of the network interface.

        Returns:
            list: List of global IPv6 addresses (not starting with 'fe80').
        """
        ips = self.get_interface_ips()
        list_global = []
        for ipv6 in ips:
            try:
                addr = ipaddress.IPv6Address(ipv6)
                if addr.is_global and not addr.is_multicast:
                    list_global.append(ipv6)
            except ipaddress.AddressValueError:
                # Ignore non-IPv6 entries from mixed interface address lists.
                pass
        return list_global

    def check_interface(self) -> bool:
        """Check if the configured network interface exists.

        Returns:
            bool: True if interface exists, False otherwise.
        """
        if not self.interface or self.interface is None:
            return False
        interface_list = netifaces.interfaces()
        return self.interface in interface_list

    def check_available_ipv6(self) -> bool:
        """
        Check if the network interface has any IPv6 addresses.

        Returns:
            bool: True if IPv6 addresses are available, False otherwise.
        """
        try:
            ip_output = subprocess.check_output(
                ["ip", "-6", "addr", "show", self.interface],
                universal_newlines=True
            )
        except (subprocess.CalledProcessError, FileNotFoundError) as error:
            ptprinthelper.ptprint(
                f"Failed to read IPv6 addresses of {self.interface}: {error}", "ERROR"
            )
            sys.exit(1)

        ipv6_addresses = []
        for line in ip_output.split("\n"):
            fields = line.split()
            if len(fields) >= 2 and fields[0] == "inet6":
                ipv6_addresses.append(fields[1])
        return bool(ipv6_addresses)

    def set_ipv6_address(self, ipv6_address: str) -> None:
        """
        Set an IPv6 address on the network interface.

        Args:
            ipv6_address (str): IPv6 address to assign.
        """
        try:
            subprocess.run(
                ["ip", "addr", "add", f"{ipv6_address}/64", "dev", self.interface],
                check=True
            )
        except subprocess.CalledProcessError:
            # Best-effort configuration; caller may continue with existing addressing.
            pass

    def check_status(self) -> str:
        """
        Check if the network interface exists and its status.

        Returns:
            str: Interface status or stdout output.
        """
        try:
            result = subprocess.run(
                ['ip', 'link', 'show', self.interface],
                capture_output=True,
                text=True,
                check=True
            )
            if "state DOWN" in result.stdout:
                return 'Interface down'
            return result.stdout
        except subprocess.CalledProcessError as e:
            ptprinthelper.ptprint(f"Failed to check interface {self.interface}: {e}", "ERROR")
            sys.exit(1)

    # The blocking rules passive mode installs, as (binary, chain, rule) triples.
    _BLOCK_RULES = (
        ("iptables", "OUTPUT", ["-o", "{iface}", "-j", "DROP"]),
        ("iptables", "FORWARD", ["-o", "{iface}", "-j", "DROP"]),
        ("iptables", "FORWARD", ["-i", "{iface}", "-j", "DROP"]),
        ("iptables", "INPUT", ["-i", "{iface}", "-j", "DROP"]),
        ("ip6tables", "OUTPUT", ["-o", "{iface}", "-j", "DROP"]),
        ("ip6tables", "FORWARD", ["-o", "{iface}", "-j", "DROP"]),
        ("ip6tables", "FORWARD", ["-i", "{iface}", "-j", "DROP"]),
        ("ip6tables", "INPUT", ["-i", "{iface}", "-j", "DROP"]),
    )

    def _block_rules(self):
        for binary, chain, rule in Interface._BLOCK_RULES:
            yield binary, chain, [part.format(iface=self.interface) for part in rule]

    def shutdown_traffic(self) -> str | None:
        """
        Blocks all traffic on the interface using iptables and ip6tables.

        Rules are tagged and added only when absent, so an interrupted run that
        never reached restore_traffic does not stack a second copy that a single
        removal pass would leave behind.

        Returns:
            str | None: Success message or None if interface is down.
        """
        status = self.check_status()
        if status == "Interface down":
            return None

        for binary, chain, rule in self._block_rules():
            _add_rule(binary, chain, rule)

        return 'Traffic on interface blocked'

    def restore_traffic(self) -> str | None:
        """
        Removes traffic blocking rules from the interface.
        Silently continues if rules don't exist.

        Returns:
            str | None: Success message or None if interface is down.
        """
        status = self.check_status()
        if status == "Interface down":
            return None

        for binary, chain, rule in self._block_rules():
            _delete_rule(binary, chain, rule)

        return 'Traffic on interface restored'


class IptablesConfig:
    """
    Class for managing iptables configuration.
    """

    @staticmethod
    def save() -> None:
        """
        Saves current iptables and ip6tables rules to files.
        """
        tmp_dir = get_tmp_path()
        iptables_file = tmp_dir / 'iptables.rules'
        ip6tables_file = tmp_dir / 'ip6tables.rules'

        try:
            with open(iptables_file, 'w') as f:
                subprocess.run(['iptables-save'], stdout=f, check=True)
            with open(ip6tables_file, 'w') as f:
                subprocess.run(['ip6tables-save'], stdout=f, check=True)
        except subprocess.CalledProcessError as e:
            ptprinthelper.ptprint(f"Failed to save iptables configuration: {e}", "ERROR")
            sys.exit(1)

    @staticmethod
    def load() -> None:
        """
        Loads iptables and ip6tables rules from files.
        """
        tmp_dir = get_tmp_path()
        iptables_file = tmp_dir / 'iptables.rules'
        ip6tables_file = tmp_dir / 'ip6tables.rules'

        try:
            with open(iptables_file, 'r') as f:
                subprocess.run(['iptables-restore'], stdin=f, check=True)
            with open(ip6tables_file, 'r') as f:
                subprocess.run(['ip6tables-restore'], stdin=f, check=True)
        except subprocess.CalledProcessError as e:
            ptprinthelper.ptprint(f"Failed to load iptables configuration: {e}", "ERROR")
            sys.exit(1)
        except FileNotFoundError as e:
            ptprinthelper.ptprint(f"Iptables configuration file not found: {e}", "ERROR")
            sys.exit(1)


class IptablesRule:
    """
    Class for managing iptables and ip6tables rules.
    """

    # The ICMP types each mode suppresses, per address family.
    _MODE_RULES = {
        "a": {
            "ip6tables": ["-p", "icmpv6", "--icmpv6-type", "port-unreachable", "-j", "DROP"],
            "iptables": ["-p", "icmp", "--icmp-type", "port-unreachable", "-j", "DROP"],
        },
        "a+": {
            "ip6tables": ["-p", "icmpv6", "--icmpv6-type", "redirect", "-j", "DROP"],
            "iptables": ["-p", "icmp", "--icmp-type", "redirect", "-j", "DROP"],
        },
    }

    @staticmethod
    def add(mode: str, ipv4: bool = True, ipv6: bool = True, nofwd: bool = False) -> None:
        """
        Add iptables and ip6tables rules based on mode and IP version.

        Args:
            mode (str): Mode ('a' or 'a+').
            ipv4 (bool): Whether to add IPv4 (iptables) rules. Default is True.
            ipv6 (bool): Whether to add IPv6 (ip6tables) rules. Default is True.
            nofwd (bool): Whether to disable forwarding.
        """
        rules = IptablesRule._MODE_RULES.get(mode)
        if rules is None:
            return

        if ipv6:
            _add_rule("ip6tables", "OUTPUT", rules["ip6tables"])
        if ipv4:
            _add_rule("iptables", "OUTPUT", rules["iptables"])

        if mode != "a+":
            return

        # Aggressive mode changes host-wide forwarding, so record what it was.
        save_forwarding_state()
        forward_target = "DROP" if nofwd else "ACCEPT"
        forward_value = "0" if nofwd else "1"

        if ipv6:
            _add_rule("ip6tables", "FORWARD", ["-j", forward_target])
            _write_sysctl("net.ipv6.conf.all.forwarding", forward_value)
        if ipv4:
            _add_rule("iptables", "FORWARD", ["-j", forward_target])
            _write_sysctl("net.ipv4.ip_forward", forward_value)

    @staticmethod
    def remove(ipv6_rule: bool | None, mode: str, ipv4: bool = True, ipv6: bool = True) -> None:
        """
        Remove iptables and ip6tables rules based on mode and IP version.

        Args:
            ipv6_rule (bool | None): IPv6 rule status.
            mode (str): Mode ('a' or 'a+').
            ipv4 (bool): Whether to remove IPv4 (iptables) rules. Default is True.
            ipv6 (bool): Whether to remove IPv6 (ip6tables) rules. Default is True.
        """
        if not (ipv6_rule is True or ipv6_rule is None):
            return

        rules = IptablesRule._MODE_RULES.get(mode)
        if rules is None:
            return

        if ipv6:
            _delete_rule("ip6tables", "OUTPUT", rules["ip6tables"])
        if ipv4:
            _delete_rule("iptables", "OUTPUT", rules["iptables"])

        if mode != "a+":
            return

        for binary, enabled in (("ip6tables", ipv6), ("iptables", ipv4)):
            if not enabled:
                continue
            _delete_rule(binary, "FORWARD", ["-j", "ACCEPT"])
            _delete_rule(binary, "FORWARD", ["-j", "DROP"])

        # Put forwarding back where the host had it rather than forcing it off.
        restore_forwarding_state()

    @staticmethod
    def check(mode: str, ipv4: bool = True, ipv6: bool = True, nofwd: bool = False) -> bool | None:
        """
        Check if iptables and ip6tables rules exist for the given mode and IP version.

        Detection asks iptables directly (`-C`) for the tagged rule rather than
        string-matching `-S` output, whose canonical spelling differs between
        iptables versions and between the legacy and nft backends.

        Args:
            mode (str): Mode ('a' or 'a+').
            ipv4 (bool): Whether to check IPv4 (iptables) rules. Default is True.
            ipv6 (bool): Whether to check IPv6 (ip6tables) rules. Default is True.
            nofwd (bool): Whether to check for disabled forwarding.

        Returns:
            bool | None: True if rule exists, False if not, None on error.
        """
        if not (ipv4 or ipv6):
            return None

        rules = IptablesRule._MODE_RULES.get(mode)
        if rules is None:
            return None

        expected_forwarding = "0" if nofwd else "1"
        rules_exist = False

        if ipv6:
            rules_exist = _rule_exists("ip6tables", "OUTPUT", rules["ip6tables"] + _COMMENT)
            if mode == "a+":
                rules_exist = rules_exist and _read_sysctl("net.ipv6.conf.all.forwarding") == expected_forwarding

        if ipv4:
            ipv4_rule_exists = _rule_exists("iptables", "OUTPUT", rules["iptables"] + _COMMENT)
            if mode == "a+":
                ipv4_rule_exists = ipv4_rule_exists and _read_sysctl("net.ipv4.ip_forward") == expected_forwarding
            rules_exist = rules_exist or ipv4_rule_exists

        return rules_exist
