#!/usr/bin/env python3
import ipaddress
import subprocess
import sys
from ptlibs import ptprinthelper

def save_iptables_configuration():
    """
    Saves current iptables and ip6tables rules to files.
    Output: dict with 'output' (bool) and 'description' (str)
    """
    try:
        with open('/tmp/iptables.rules', 'w') as f:
            subprocess.run(['iptables-save'], stdout=f, check=True)
        with open('/tmp/ip6tables.rules', 'w') as f:
            subprocess.run(['ip6tables-save'], stdout=f, check=True)
        return {'output': True, 'description': 'iptables and ip6tables configuration saved successfully.'}
    except subprocess.CalledProcessError as e:
        return {'output': False, 'description': f'Failed to save iptables configuration: {e}'}

def load_iptables_configuration():
    """
    Loads iptables and ip6tables rules from files.
    Output: dict with 'output' (bool) and 'description' (str)
    """
    try:
        with open('/tmp/iptables.rules', 'r') as f:
            subprocess.run(['iptables-restore'], stdin=f, check=True)
        with open('/tmp/ip6tables.rules', 'r') as f:
            subprocess.run(['ip6tables-restore'], stdin=f, check=True)
        return {'output': True, 'description': 'iptables and ip6tables configuration restored successfully.'}
    except subprocess.CalledProcessError as e:
        return {'output': False, 'description': f'Failed to restore iptables configuration: {e}'}

def check_interface(interface):
    """
    Checks if the network interface exists and its status.
    Output: dict with 'output' (bool) and 'description' (str)
    """
    try:
        result = subprocess.run(['ip', 'link', 'show', interface], capture_output=True, text=True, check=True)
        if "state DOWN" in result.stdout:
            return {'output': False, 'description': 'Interface down'}
        return {'output': True, 'description': result.stdout}
    except subprocess.CalledProcessError:
        return {'output': False, 'description': 'Interface not found or error occurred.'}

def shutdown_interface_traffic(interface):
    """
    Blocks all traffic on the specified interface using iptables and ip6tables.
    Output: dict with 'output' (bool) and 'description' (str)
    """
    status = check_interface(interface)
    if not status['output']:
        return {'output': False, 'description': status['description']}
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
        return {'output': True, 'description': 'Traffic on interface blocked.'}
    except subprocess.CalledProcessError as e:
        return {'output': False, 'description': f'Failed to block traffic: {e}'}

def restore_interface_traffic(interface):
    """
    Removes traffic blocking rules from the specified interface.
    Output: dict with 'output' (bool) and 'description' (str)
    """
    status = check_interface(interface)
    if not status['output']:
        return {'output': False, 'description': status['description']}
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
        return {'output': True, 'description': 'Traffic on interface restored.'}
    except subprocess.CalledProcessError as e:
        return {'output': False, 'description': f'Failed to restore traffic: {e}'}