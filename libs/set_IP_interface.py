#!/usr/bin/env python3
import ipaddress
import subprocess
import sys
from ptlibs import ptprinthelper

def save_iptables_configuration():
    """
    Saves current iptables and ip6tables rules to files.
    """
    try:
        with open('/tmp/iptables.rules', 'w') as f:
            subprocess.run(['iptables-save'], stdout=f, check=True)
        with open('/tmp/ip6tables.rules', 'w') as f:
            subprocess.run(['ip6tables-save'], stdout=f, check=True)
    except subprocess.CalledProcessError as e:
        exit(1)

def load_iptables_configuration():
    """
    Loads iptables and ip6tables rules from files.
    """
    try:
        with open('/tmp/iptables.rules', 'r') as f:
            subprocess.run(['iptables-restore'], stdin=f, check=True)
        with open('/tmp/ip6tables.rules', 'r') as f:
            subprocess.run(['ip6tables-restore'], stdin=f, check=True)
    except subprocess.CalledProcessError as e:
        exit(1)

def check_interface(interface):
    """
    Checks if the network interface exists and its status.
    """
    try:
        result = subprocess.run(['ip', 'link', 'show', interface], capture_output=True, text=True, check=True)
        if "state DOWN" in result.stdout:
            return 'Interface down'
        return result.stdout
    except subprocess.CalledProcessError:
        exit(1)

def shutdown_interface_traffic(interface):
    """
    Blocks all traffic on the specified interface using iptables and ip6tables.
    """
    status = check_interface(interface)
    if status == "Interface down":
        return None
    try:
        # IPv4 Rules
        subprocess.run(["iptables", "-A", "OUTPUT", "-o", interface, "-j", "DROP"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["iptables", "-A", "FORWARD", "-o", interface, "-j", "DROP"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["iptables", "-A", "FORWARD", "-i", interface, "-j", "DROP"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["iptables", "-A", "INPUT", "-i", interface, "-j", "DROP"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # IPv6 Rules
        subprocess.run(["ip6tables", "-A", "OUTPUT", "-o", interface, "-j", "DROP"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["ip6tables", "-A", "FORWARD", "-o", interface, "-j", "DROP"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["ip6tables", "-A", "FORWARD", "-i", interface, "-j", "DROP"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["ip6tables", "-A", "INPUT", "-i", interface, "-j", "DROP"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return 'Traffic on interface blocked'
    except subprocess.CalledProcessError as e:
        return None

def restore_interface_traffic(interface):
    """
    Removes traffic blocking rules from the specified interface.
    """
    status = check_interface(interface)
    if status == "Interface down":
        return None
    try:
        # Reset IPv4 Rules
        subprocess.run(["iptables", "-D", "OUTPUT", "-o", interface, "-j", "DROP"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["iptables", "-D", "FORWARD", "-o", interface, "-j", "DROP"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["iptables", "-D", "FORWARD", "-i", interface, "-j", "DROP"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["iptables", "-D", "INPUT", "-i", interface, "-j", "DROP"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # Reset IPv6 Rules
        subprocess.run(["ip6tables", "-D", "OUTPUT", "-o", interface, "-j", "DROP"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["ip6tables", "-D", "FORWARD", "-o", interface, "-j", "DROP"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["ip6tables", "-D", "FORWARD", "-i", interface, "-j", "DROP"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["ip6tables", "-D", "INPUT", "-i", interface, "-j", "DROP"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return 'Traffic on interface restored'
    except subprocess.CalledProcessError as e:
        return None
