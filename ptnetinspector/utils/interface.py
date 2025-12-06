#!/usr/bin/env python3
import os
import subprocess
import sys
import netifaces
from ptlibs import ptprinthelper
from ptnetinspector.utils.path import get_tmp_path

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

    def check_interface(self) -> bool:
        """
        Check if the network interface exists.

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
        except subprocess.CalledProcessError as e:
            print(f"Error: {e}")
            exit(1)

        addresses = ip_output.split("\n")
        ipv6_addresses = [line.split()[1] for line in addresses if "inet6" in line]
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

    def shutdown_traffic(self) -> str | None:
        """
        Blocks all traffic on the interface using iptables and ip6tables.
        
        Returns:
            str | None: Success message or None if interface is down.
        """
        status = self.check_status()
        if status == "Interface down":
            return None
        
        try:
            # IPv4 Rules
            subprocess.run(
                ["iptables", "-A", "OUTPUT", "-o", self.interface, "-j", "DROP"],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            subprocess.run(
                ["iptables", "-A", "FORWARD", "-o", self.interface, "-j", "DROP"],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            subprocess.run(
                ["iptables", "-A", "FORWARD", "-i", self.interface, "-j", "DROP"],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            subprocess.run(
                ["iptables", "-A", "INPUT", "-i", self.interface, "-j", "DROP"],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            
            # IPv6 Rules
            subprocess.run(
                ["ip6tables", "-A", "OUTPUT", "-o", self.interface, "-j", "DROP"],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            subprocess.run(
                ["ip6tables", "-A", "FORWARD", "-o", self.interface, "-j", "DROP"],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            subprocess.run(
                ["ip6tables", "-A", "FORWARD", "-i", self.interface, "-j", "DROP"],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            subprocess.run(
                ["ip6tables", "-A", "INPUT", "-i", self.interface, "-j", "DROP"],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            return 'Traffic on interface blocked'
        except subprocess.CalledProcessError as e:
            ptprinthelper.ptprint(f"Failed to block traffic on {self.interface}: {e}", "ERROR")
            return None

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
        
        rules = [
            (["iptables", "-D", "OUTPUT", "-o", self.interface, "-j", "DROP"], "iptables OUTPUT"),
            (["iptables", "-D", "FORWARD", "-o", self.interface, "-j", "DROP"], "iptables FORWARD out"),
            (["iptables", "-D", "FORWARD", "-i", self.interface, "-j", "DROP"], "iptables FORWARD in"),
            (["iptables", "-D", "INPUT", "-i", self.interface, "-j", "DROP"], "iptables INPUT"),
            (["ip6tables", "-D", "OUTPUT", "-o", self.interface, "-j", "DROP"], "ip6tables OUTPUT"),
            (["ip6tables", "-D", "FORWARD", "-o", self.interface, "-j", "DROP"], "ip6tables FORWARD out"),
            (["ip6tables", "-D", "FORWARD", "-i", self.interface, "-j", "DROP"], "ip6tables FORWARD in"),
            (["ip6tables", "-D", "INPUT", "-i", self.interface, "-j", "DROP"], "ip6tables INPUT"),
        ]
        
        for cmd, rule_name in rules:
            try:
                subprocess.run(
                    cmd,
                    check=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
            except subprocess.CalledProcessError:
                pass
        
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
        if mode == "a":
            if ipv6:
                subprocess.run(["ip6tables", "-A", "OUTPUT", "-p", "icmpv6", "--icmpv6-type", "port-unreachable", "-j", "DROP"], check=True)
            if ipv4:
                subprocess.run(["iptables", "-A", "OUTPUT", "-p", "icmp", "--icmp-type", "port-unreachable", "-j", "DROP"], check=True)
        
        if mode == "a+":
            if ipv6:
                subprocess.run(["ip6tables", "-A", "OUTPUT", "-p", "icmpv6", "--icmpv6-type", "redirect", "-j", "DROP"], check=True)
                if not nofwd:
                    command = 'sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null'
                    subprocess.run(["ip6tables", "-A", "FORWARD", "-j", "ACCEPT"], check=True)
                else:
                    command = 'sysctl -w net.ipv6.conf.all.forwarding=0 >/dev/null'
                    subprocess.run(["ip6tables", "-A", "FORWARD", "-j", "DROP"], check=True)
                os.system(command)
            
            if ipv4:
                subprocess.run(["iptables", "-A", "OUTPUT", "-p", "icmp", "--icmp-type", "redirect", "-j", "DROP"], check=True)

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
        if ipv6_rule is True or ipv6_rule is None:
            if mode == "a":
                if ipv6:
                    subprocess.run(["ip6tables", "-D", "OUTPUT", "-p", "icmpv6", "--icmpv6-type", "port-unreachable", "-j", "DROP"], check=False)
                if ipv4:
                    subprocess.run(["iptables", "-D", "OUTPUT", "-p", "icmp", "--icmp-type", "port-unreachable", "-j", "DROP"], check=False)
            
            if mode == "a+":
                if ipv6:
                    subprocess.run(["ip6tables", "-D", "OUTPUT", "-p", "icmpv6", "--icmpv6-type", "redirect", "-j", "DROP"], check=True)
                    command = 'sysctl -w net.ipv6.conf.all.forwarding=0 >/dev/null'
                    subprocess.run(["ip6tables", "-D", "FORWARD", "-j", "ACCEPT"], stderr=subprocess.DEVNULL, check=False)
                    subprocess.run(["ip6tables", "-D", "FORWARD", "-j", "DROP"], stderr=subprocess.DEVNULL, check=False)
                    os.system(command)
                
                if ipv4:
                    subprocess.run(["iptables", "-D", "OUTPUT", "-p", "icmp", "--icmp-type", "redirect", "-j", "DROP"], check=False)
                    subprocess.run(["iptables", "-D", "FORWARD", "-j", "ACCEPT"], stderr=subprocess.DEVNULL, check=False)
                    subprocess.run(["iptables", "-D", "FORWARD", "-j", "DROP"], stderr=subprocess.DEVNULL, check=False)

    @staticmethod
    def check(mode: str, ipv4: bool = True, ipv6: bool = True, nofwd: bool = False) -> bool | None:
        """
        Check if iptables and ip6tables rules exist for the given mode and IP version.
        
        Args:
            mode (str): Mode ('a' or 'a+').
            ipv4 (bool): Whether to check IPv4 (iptables) rules. Default is True.
            ipv6 (bool): Whether to check IPv6 (ip6tables) rules. Default is True.
            nofwd (bool): Whether to check for disabled forwarding.
        
        Returns:
            bool | None: True if rule exists, False if not, None on error.
        """
        try:
            rules_exist = False
            
            if ipv6:
                output = subprocess.check_output(["ip6tables", "-S", "OUTPUT"], stderr=subprocess.STDOUT, universal_newlines=True)
                if mode == "a":
                    rules_exist = any("-p ipv6-icmp -m icmp6 --icmpv6-type 1/4 -j DROP" in line for line in output.split("\n"))
                if mode == "a+":
                    rules_exist = any("-p ipv6-icmp -m icmp6 --icmpv6-type 137 -j DROP" in line for line in output.split("\n"))
                    output_2 = subprocess.check_output(["sysctl", "net.ipv6.conf.all.forwarding"], stderr=subprocess.STDOUT, universal_newlines=True)
                    if not nofwd:
                        rules_exist = rules_exist and "net.ipv6.conf.all.forwarding = 1" in output_2
                    else:
                        rules_exist = rules_exist and "net.ipv6.conf.all.forwarding = 0" in output_2
            
            if ipv4:
                output = subprocess.check_output(["iptables", "-S", "OUTPUT"], stderr=subprocess.STDOUT, universal_newlines=True)
                if mode == "a":
                    ipv4_rule_exists = any("-p icmp -m icmp --icmp-type port-unreachable -j DROP" in line for line in output.split("\n"))
                    rules_exist = rules_exist or ipv4_rule_exists
                if mode == "a+":
                    ipv4_rule_exists = any("-p icmp -m icmp --icmp-type redirect -j DROP" in line for line in output.split("\n"))
                    rules_exist = rules_exist or ipv4_rule_exists
            
            return rules_exist if (ipv4 or ipv6) else None
        
        except subprocess.CalledProcessError:
            return None
