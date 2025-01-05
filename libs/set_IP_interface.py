#!/usr/bin/env python3
import ipaddress
import subprocess
import sys
from libs.ptlibs import ptprinthelper

def save_iptables_configuration():
    try:
        # Save current iptables rules to a file
        with open('/tmp/iptables.rules', 'w') as f:
            subprocess.run(['iptables-save'], stdout=f, check=True)
        
        # Save current ip6tables rules to a file
        with open('/tmp/ip6tables.rules', 'w') as f:
            subprocess.run(['ip6tables-save'], stdout=f, check=True)
    except subprocess.CalledProcessError as e:
        # print(f"Failed to save iptables configuration: {e}")
        exit(1)

def load_iptables_configuration():
    try:
        # Restore saved iptables rules
        with open('/tmp/iptables.rules', 'r') as f:
            subprocess.run(['iptables-restore'], stdin=f, check=True)
        
        # Restore saved ip6tables rules
        with open('/tmp/ip6tables.rules', 'r') as f:
            subprocess.run(['ip6tables-restore'], stdin=f, check=True)
    except subprocess.CalledProcessError as e:
        # print(f"Failed to restore iptables configuration: {e}")
        exit(1)

def check_interface(interface):
    try:
        result = subprocess.run(['ip', 'link', 'show', interface], capture_output=True, text=True, check=True)
        if "state DOWN" in result.stdout:
            return "Interface down"
        return result.stdout
    except subprocess.CalledProcessError:
        # print("Wrong")
        exit(1)

def shutdown_interface_traffic(interface):
    # Check if the interface exists and is up
    if_status = check_interface(interface)

    if if_status == "Interface down":
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

        return "Traffic on interface blocked"
    except subprocess.CalledProcessError as e:
        # print(f"An error occurred: {e}")
        return None

def restore_interface_traffic(interface):
    # Check if the interface exists and is up
    if_status = check_interface(interface)

    if if_status == "Interface down":
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

        return "Traffic on interface restored"
    except subprocess.CalledProcessError as e:
        # print(f"An error occurred: {e}")
        return None