import argparse
import os
import subprocess
import sys

import pandas as pd
from src.parameters import __version__, SCRIPTNAME, get_help
from ptlibs import ptprinthelper
# Creating an instance of the PtJsonLib class
from src.parameters import ptjsonlib_object


# Function to delete temporary files
def del_tmp():
    file_list = os.listdir("./src/tmp")
    for file_name in file_list:
        file_path = os.path.join("./src/tmp", file_name)
        os.remove(file_path)


def delete_contents_except_headers(csv_path):
    # Check if the file is a CSV file
    if not csv_path.endswith('.csv'):
        print(f"{csv_path} is not a CSV file.")
        return

    # Load the CSV file into a DataFrame
    df = pd.read_csv(csv_path)

    # Check if the DataFrame has more than one row (including header)
    if len(df.index) > 1:
        # Keep only the header row and remove all other rows
        header_row = df.iloc[0]
        df = pd.DataFrame(columns=df.columns)
        df = df.append(header_row, ignore_index=True)

        # Save the modified DataFrame back to the CSV file
        df.to_csv(csv_path, index=False)

        # print(f"{csv_path} has been processed successfully.")
    else:
        # print(f"{csv_path} has only the header row. No rows to delete.")
        pass

class CustomArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        # Suppress specific error messages if they match the criteria
        if "argument -t: expected at least one argument" in message:
            if '-j' in sys.argv:
                print(ptjsonlib_object.end_error("Expected argument after the prefix or the argument is invalid. Try ptnetinspector -h for help", ptjsonlib_object))
            else:
                ptprinthelper.ptprint("Expected argument after the prefix or the argument is invalid. Try ptnetinspector -h for help", "ERROR")
            sys.exit(2)
        elif "argument -i: expected one argument" in message:
            if '-j' in sys.argv:
                print(ptjsonlib_object.end_error("Expected argument after the prefix or the argument is invalid. Try ptnetinspector -h for help", ptjsonlib_object))
            else:
                ptprinthelper.ptprint("Expected argument after the prefix or the argument is invalid. Try ptnetinspector -h for help", "ERROR")
            sys.exit(2)
        elif "argument -d: expected one argument" in message:
            if '-j' in sys.argv:
                print(ptjsonlib_object.end_error("Expected argument after the prefix or the argument is invalid. Try ptnetinspector -h for help", ptjsonlib_object))
            else:
                ptprinthelper.ptprint("Expected argument after the prefix or the argument is invalid. Try ptnetinspector -h for help", "ERROR")
            sys.exit(2)
        elif "argument -da+: expected one argument" in message:
            if '-j' in sys.argv:
                print(ptjsonlib_object.end_error("Expected argument after the prefix or the argument is invalid. Try ptnetinspector -h for help", ptjsonlib_object))
            else:
                ptprinthelper.ptprint("Expected argument after the prefix or the argument is invalid. Try ptnetinspector -h for help", "ERROR")
            sys.exit(2)
        elif "argument -prefix: expected one argument" in message:
            if '-j' in sys.argv:
                print(ptjsonlib_object.end_error("Expected argument after the prefix or the argument is invalid. Try ptnetinspector -h for help", ptjsonlib_object))
            else:
                ptprinthelper.ptprint("Expected argument after the prefix or the argument is invalid. Try ptnetinspector -h for help", "ERROR")
            sys.exit(2)
        elif "argument -smac: expected one argument" in message:
            if '-j' in sys.argv:
                print(ptjsonlib_object.end_error("Expected argument after the prefix or the argument is invalid. Try ptnetinspector -h for help", ptjsonlib_object))
            else:
                ptprinthelper.ptprint("Expected argument after the prefix or the argument is invalid. Try ptnetinspector -h for help", "ERROR")
            sys.exit(2)
        elif "argument -sip: expected one argument" in message:
            if '-j' in sys.argv:
                print(ptjsonlib_object.end_error("Expected argument after the prefix or the argument is invalid. Try ptnetinspector -h for help", ptjsonlib_object))
            else:
                ptprinthelper.ptprint("Expected argument after the prefix or the argument is invalid. Try ptnetinspector -h for help", "ERROR")
            sys.exit(2)
        elif "argument -rpref: expected one argument" in message:
            if '-j' in sys.argv:
                print(ptjsonlib_object.end_error("Expected argument after the prefix or the argument is invalid. Try ptnetinspector -h for help", ptjsonlib_object))
            else:
                ptprinthelper.ptprint("Expected argument after the prefix or the argument is invalid. Try ptnetinspector -h for help", "ERROR")
            sys.exit(2)
        elif "argument -period: expected one argument" in message:
            if '-j' in sys.argv:
                print(ptjsonlib_object.end_error("Expected argument after the prefix or the argument is invalid. Try ptnetinspector -h for help", ptjsonlib_object))
            else:
                ptprinthelper.ptprint("Expected argument after the prefix or the argument is invalid. Try ptnetinspector -h for help", "ERROR")
            sys.exit(2)
        elif "argument -chl: expected one argument" in message:
            if '-j' in sys.argv:
                print(ptjsonlib_object.end_error("Expected argument after the prefix or the argument is invalid. Try ptnetinspector -h for help", ptjsonlib_object))
            else:
                ptprinthelper.ptprint("Expected argument after the prefix or the argument is invalid. Try ptnetinspector -h for help", "ERROR")
            sys.exit(2)
        elif "argument -dns: expected at least one argument" in message:
            if '-j' in sys.argv:
                print(ptjsonlib_object.end_error("Expected argument after the prefix or the argument is invalid. Try ptnetinspector -h for help", ptjsonlib_object))
            else:
                ptprinthelper.ptprint("Expected argument after the prefix or the argument is invalid. Try ptnetinspector -h for help", "ERROR")
            sys.exit(2)
        elif "argument -mtu: expected one argument" in message:
            if '-j' in sys.argv:
                print(ptjsonlib_object.end_error("Expected argument after the prefix or the argument is invalid. Try ptnetinspector -h for help", ptjsonlib_object))
            else:
                ptprinthelper.ptprint("Expected argument after the prefix or the argument is invalid. Try ptnetinspector -h for help", "ERROR")
            sys.exit(2)
        else:
            pass

# Function to parse command-line arguments
def parse_args():
    parser = CustomArgumentParser(description='start ptnetinspector')
    parser.add_argument("-t", nargs='+', choices=["802.1x", "p", "a", "a+"], help="first mandatory argument")
    parser.add_argument("-i", dest="interface", help="second mandatory argument")
    parser.add_argument("-j", action="store_true")
    parser.add_argument("-n", action="store_false")
    parser.add_argument("-more", action="store_true", default=False)
    parser.add_argument("-less", action="store_true", default=False)
    parser.add_argument("-d", action="store")
    parser.add_argument("-da+", dest="duration_router", action="store")
    parser.add_argument("-prefix", action="store")
    parser.add_argument("-smac", action="store", help="the MAC address of sender (resolved from the interface if "
                                                    "skipping).")
    parser.add_argument("-sip", action="store", help="the MAC address of sender (resolved from the interface if "
                                                    "skipping).")
    parser.add_argument("-rpref", action="store", help="the preference flag of RA in aggressive mode (High if skipping).")
    parser.add_argument("-period", action="store", help="the sending rate of RA in aggressive mode.")
    parser.add_argument("-chl", action="store", help="the current of RA in aggressive mode.")
    parser.add_argument("-dns", dest="dns", action="store", nargs="+",
                        help="the IPv6 address of DNS server (separated by space if more than 1 address is inserted).")
    parser.add_argument("-mtu", action="store", help="the MTU of RA in aggressive mode.")
    parser.add_argument("-nofwd", action="store_true", default=False)

    # Print help message if no arguments provided or "-h" is used
    if len(sys.argv) == 1 or "-h" in sys.argv:
        ptprinthelper.help_print(get_help(), SCRIPTNAME, __version__)
        sys.exit(0)

    args, unknown_args = parser.parse_known_args()

    if unknown_args:
        if "-j" in unknown_args or args.j:
            print(ptjsonlib_object.end_error("Unexpected arguments found. Try ptnetinspector -h for help", ptjsonlib_object))
            sys.exit(0)
        else:
            ptprinthelper.ptprint("Unexpected arguments found. Try ptnetinspector -h for help", "ERROR")
            sys.exit(0)

    return args

# Function to add ip6tables rule
def add_rule(mode, nofwd=False):
    # Add the ip6tables rule
    if mode == "a":
        subprocess.run(["ip6tables", "-A", "OUTPUT", "-p", "icmpv6", "--icmpv6-type", "port-unreachable", "-j", "DROP"], 
                    check=True)
    if mode == "a+":
        # Dropping Redirect from the attacker
        subprocess.run(["ip6tables", "-A", "OUTPUT", "-p", "icmpv6", "--icmpv6-type", "redirect", "-j", "DROP"],
                    check=True)
        # Allowing forwarding
        if not nofwd:
            command = 'sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null'
            subprocess.run(["ip6tables", "-A", "FORWARD", "-j", "ACCEPT"], check=True)
        if nofwd:
            command = 'sysctl -w net.ipv6.conf.all.forwarding=0 >/dev/null'
            subprocess.run(["ip6tables", "-A", "FORWARD", "-j", "DROP"], check=True)
        os.system(command)

# Function to remove ip6tables rule
def remove_rule(ipv6_rule, mode):
    # Remove the ip6tables rule
    if ipv6_rule == True or ipv6_rule == None:
        if mode == "a":
            subprocess.run(["ip6tables", "-D", "OUTPUT", "-p", "icmpv6", "--icmpv6-type", "port-unreachable", "-j", "DROP"],
                       check=False)
        if mode == "a+":
            # Reset Redirect from the attacker
            subprocess.run(["ip6tables", "-D", "OUTPUT", "-p", "icmpv6", "--icmpv6-type", "redirect", "-j", "DROP"],
                        check=True)
            # Not allow forwarding
            command = 'sysctl -w net.ipv6.conf.all.forwarding=0 >/dev/null'
            subprocess.run(["ip6tables", "-D", "FORWARD", "-j", "ACCEPT"], stderr=subprocess.DEVNULL, check=False)
            subprocess.run(["ip6tables", "-D", "FORWARD", "-j", "DROP"], stderr=subprocess.DEVNULL, check=False)
            os.system(command)

# Function to check if the ip6tables rule exists
def check_rule(mode, nofwd=False):
    try:
        output = subprocess.check_output(["ip6tables", "-S", "OUTPUT"], stderr=subprocess.STDOUT,
                                         universal_newlines=True)
        if mode == "a":
            rule_exists = any("-p ipv6-icmp -m icmp6 --icmpv6-type 1/4 -j DROP" in line for line in output.split("\n"))
            if rule_exists:
                return True
            else:
                return False

        if mode == "a+":
            rule_exists = any("-p ipv6-icmp -m icmp6 --icmpv6-type 137 -j DROP" in line for line in output.split("\n"))

            output_2 = subprocess.check_output(["sysctl", "net.ipv6.conf.all.forwarding"], stderr=subprocess.STDOUT,
                                         universal_newlines=True)
            if not nofwd:
                rule_exists_2 = any("net.ipv6.conf.all.forwarding = 1" in line for line in output.split("\n"))
            if nofwd:
                rule_exists_2 = any("net.ipv6.conf.all.forwarding = 0" in line for line in output.split("\n"))

            if rule_exists or rule_exists_2:
                return True
            else:
                return False

    except subprocess.CalledProcessError as e:
        return None

