import argparse
import os
import subprocess
import sys

import pandas as pd
from src.parameters import __version__, SCRIPTNAME, get_help
from ptlibs import ptprinthelper
from src.parameters import ptjsonlib_object

# Utility Functions

def del_tmp():
    """
    Delete all files in the ./src/tmp directory.
    Output: None
    """
    file_list = os.listdir("./src/tmp")
    for file_name in file_list:
        file_path = os.path.join("./src/tmp", file_name)
        os.remove(file_path)

def delete_contents_except_headers(csv_path):
    """
    Remove all rows except the header from a CSV file.
    Output: None
    Description: Keeps only the header row in the CSV file.
    """
    if not csv_path.endswith('.csv'):
        print(f"{csv_path} is not a CSV file.")
        return

    df = pd.read_csv(csv_path)
    if len(df.index) > 1:
        header_row = df.iloc[0]
        df = pd.DataFrame(columns=df.columns)
        df = df.append(header_row, ignore_index=True)
        df.to_csv(csv_path, index=False)

# Argument Parsing

class CustomArgumentParser(argparse.ArgumentParser):
    """
    Custom ArgumentParser to handle specific error messages.
    Output: Error message printed and exits on error.
    """
    def error(self, message):
        error_msgs = [
            "argument -t: expected at least one argument",
            "argument -i: expected one argument",
            "argument -d: expected one argument",
            "argument -da+: expected one argument",
            "argument -prefix: expected one argument",
            "argument -smac: expected one argument",
            "argument -sip: expected one argument",
            "argument -rpref: expected one argument",
            "argument -period: expected one argument",
            "argument -chl: expected one argument",
            "argument -dns: expected at least one argument",
            "argument -mtu: expected one argument"
        ]
        for err in error_msgs:
            if err in message:
                msg = "Expected argument after the prefix or the argument is invalid. Try ptnetinspector -h for help"
                if '-j' in sys.argv:
                    print(ptjsonlib_object.end_error(msg, ptjsonlib_object))
                else:
                    ptprinthelper.ptprint(msg, "ERROR")
                sys.exit(2)
        pass

def parse_args():
    """
    Parse command-line arguments for ptnetinspector.
    Output: argparse.Namespace object with parsed arguments.
    """
    parser = CustomArgumentParser(description='start ptnetinspector')
    parser.add_argument("-t", nargs='+', choices=["802.1x", "p", "a", "a+"], help="first mandatory argument")
    parser.add_argument("-i", dest="interface", help="second mandatory argument")
    parser.add_argument("-j", action="store_true")
    parser.add_argument("-n", action="store_false")
    parser.add_argument("-more", action="store_true", default=False)
    parser.add_argument("-less", action="store_true", default=False)
    parser.add_argument("-nc", action="store_false", default=True)
    parser.add_argument("-4", dest="ipv4", action="store_true", default=False)
    parser.add_argument("-6", dest="ipv6", action="store_true", default=False)
    parser.add_argument("-d", action="store")
    parser.add_argument("-da+", dest="duration_router", action="store")
    parser.add_argument("-prefix", action="store")
    parser.add_argument("-smac", action="store", help="the MAC address of sender (resolved from the interface if skipping).")
    parser.add_argument("-sip", action="store", help="the MAC address of sender (resolved from the interface if skipping).")
    parser.add_argument("-rpref", action="store", help="the preference flag of RA in aggressive mode (High if skipping).")
    parser.add_argument("-period", action="store", help="the sending rate of RA in aggressive mode.")
    parser.add_argument("-chl", action="store", help="the current of RA in aggressive mode.")
    parser.add_argument("-dns", dest="dns", action="store", nargs="+", help="the IPv6 address of DNS server (separated by space if more than 1 address is inserted).")
    parser.add_argument("-mtu", action="store", help="the MTU of RA in aggressive mode.")
    parser.add_argument("-nofwd", action="store_true", default=False)

    # Print help message if no arguments provided or "-h" is used
    if len(sys.argv) == 1 or "-h" in sys.argv:
        ptprinthelper.help_print(get_help(), SCRIPTNAME, __version__)
        sys.exit(0)

    args, unknown_args = parser.parse_known_args()

    if unknown_args:
        msg = "Unexpected arguments found. Try ptnetinspector -h for help"
        if "-j" in unknown_args or args.j:
            print(ptjsonlib_object.end_error(msg, ptjsonlib_object))
            sys.exit(0)
        else:
            ptprinthelper.ptprint(msg, "ERROR")
            sys.exit(0)

    return args

# ip6tables Management

def add_rule(mode, nofwd=False):
    """
    Add ip6tables rules based on mode.
    Output: None
    Description: Adds rules for 'a' and 'a+' modes, manages forwarding.
    """
    if mode == "a":
        subprocess.run(["ip6tables", "-A", "OUTPUT", "-p", "icmpv6", "--icmpv6-type", "port-unreachable", "-j", "DROP"], check=True)
        subprocess.run(["iptables", "-A", "OUTPUT", "-p", "icmp", "--icmp-type", "port-unreachable", "-j", "DROP"], check=True)
    if mode == "a+":
        subprocess.run(["ip6tables", "-A", "OUTPUT", "-p", "icmpv6", "--icmpv6-type", "redirect", "-j", "DROP"], check=True)
        if not nofwd:
            command = 'sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null'
            subprocess.run(["ip6tables", "-A", "FORWARD", "-j", "ACCEPT"], check=True)
        else:
            command = 'sysctl -w net.ipv6.conf.all.forwarding=0 >/dev/null'
            subprocess.run(["ip6tables", "-A", "FORWARD", "-j", "DROP"], check=True)
        os.system(command)

def remove_rule(ipv6_rule, mode):
    """
    Remove ip6tables rules based on mode.
    Output: None
    Description: Removes rules for 'a' and 'a+' modes, resets forwarding.
    """
    if ipv6_rule is True or ipv6_rule is None:
        if mode == "a":
            subprocess.run(["ip6tables", "-D", "OUTPUT", "-p", "icmpv6", "--icmpv6-type", "port-unreachable", "-j", "DROP"], check=False)
        if mode == "a+":
            subprocess.run(["ip6tables", "-D", "OUTPUT", "-p", "icmpv6", "--icmpv6-type", "redirect", "-j", "DROP"], check=True)
            command = 'sysctl -w net.ipv6.conf.all.forwarding=0 >/dev/null'
            subprocess.run(["ip6tables", "-D", "FORWARD", "-j", "ACCEPT"], stderr=subprocess.DEVNULL, check=False)
            subprocess.run(["ip6tables", "-D", "FORWARD", "-j", "DROP"], stderr=subprocess.DEVNULL, check=False)
            os.system(command)

def check_rule(mode, nofwd=False):
    """
    Check if ip6tables rules exist for the given mode.
    Output: True if rule exists, False if not, None on error.
    Description: Checks for rules and forwarding status.
    """
    try:
        output = subprocess.check_output(["ip6tables", "-S", "OUTPUT"], stderr=subprocess.STDOUT, universal_newlines=True)
        if mode == "a":
            rule_exists = any("-p ipv6-icmp -m icmp6 --icmpv6-type 1/4 -j DROP" in line for line in output.split("\n"))
            return rule_exists
        if mode == "a+":
            rule_exists = any("-p ipv6-icmp -m icmp6 --icmpv6-type 137 -j DROP" in line for line in output.split("\n"))
            output_2 = subprocess.check_output(["sysctl", "net.ipv6.conf.all.forwarding"], stderr=subprocess.STDOUT, universal_newlines=True)
            if not nofwd:
                rule_exists_2 = "net.ipv6.conf.all.forwarding = 1" in output_2
            else:
                rule_exists_2 = "net.ipv6.conf.all.forwarding = 0" in output_2
            return rule_exists or rule_exists_2
    except subprocess.CalledProcessError:
        return None
