import csv
import subprocess
from ptnetinspector.utils.path import get_csv_path
from ptnetinspector.utils.ip_utils import has_additional_data


class Node:
    
    all_nodes = []
    
    def __init__(self, mac: str, ip: str):
        # Assign to self object
        self.mac = mac
        self.ip = ip
        Node.all_nodes.append(self)
    
    @classmethod
    def get_from_csv(cls):
        # Importing the information about nodes from tmp files
        csv_file = get_csv_path("addresses.csv")
        
        with open(csv_file, "r") as csv_file:
            reader = csv.DictReader(csv_file)
            nodes = list(reader)

            for node in nodes:
                Node(
                    mac=node.get('MAC'),
                    ip=node.get('IP')
                )

    def save_addresses(self):
        # Exporting addresses to csv files and avoid duplication
        csv_file = get_csv_path("packets.csv")
        
        with open(csv_file, 'a+', newline='') as csvfile:
            csvfile.seek(0)  # move the file pointer to the beginning of the file
            for row in csv.DictReader(csvfile):
                if row and row['src MAC'] == self.mac and row['source IP'] == self.ip:
                    return  # Record already exists in the file 
                   
            fieldnames = ['time', 'src MAC', 'des MAC', 'source IP', 'destination IP', 'protocol', 'length']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writerow({
                'source IP': self.ip,
                'src MAC': self.mac
            })
    
    @staticmethod
    def save_local_name(mac, local_name):
        # Function to save local names from mdns and llmnr to a CSV file
        csv_file = get_csv_path("localname.csv")
        
        with open(csv_file, 'a+', newline='') as csvfile:
            csvfile.seek(0)  # move the file pointer to the beginning of the file
            for row in csv.DictReader(csvfile):
                if row and row['MAC'] == mac and row['name'] == local_name:
                    return  # Record already exists in the file
                
            fieldnames = ['MAC', 'name']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writerow({
                'MAC': mac,
                'name': local_name
            })
    
    @staticmethod
    def save_ipv6_routing_table(Destination, Nexthop, Flag, Metric, Refcnt, Use, If):
        csv_file = get_csv_path("ipv6_route_table.csv")
        
        with open(csv_file, 'a+', newline='') as csvfile:
            csvfile.seek(0)  # move the file pointer to the beginning of the file
            for row in csv.reader(csvfile):
                if row and row == [Destination, Nexthop, Flag, Metric, Refcnt, Use, If]:
                    return  # Record already exists in the file
                    
            fieldnames = ['Destination', 'Nexthop', 'Flag', 'Metric', 'Refcnt', 'Use', 'If']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writerow({
                'Destination': Destination,
                'Nexthop': Nexthop,
                'Flag': Flag,
                'Metric': Metric,
                'Refcnt': Refcnt,
                'Use': Use,
                'If': If
            })

    @staticmethod
    def save_ipv4_routing_table(Destination, Gateway, Genmask, Flags, Metric, Ref, Use, Iface):
        csv_file = get_csv_path("ipv4_route_table.csv")
        
        with open(csv_file, 'a+', newline='') as csvfile:
            csvfile.seek(0)
            for row in csv.reader(csvfile):
                if row and row == [Destination, Gateway, Genmask, Flags, Metric, Ref, Use, Iface]:
                    return
                    
            fieldnames = ['Destination', 'Gateway', 'Genmask', 'Flags', 'Metric', 'Ref', 'Use', 'Iface']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writerow({
                'Destination': Destination,
                'Gateway': Gateway,
                'Genmask': Genmask,
                'Flags': Flags,
                'Metric': Metric,
                'Ref': Ref,
                'Use': Use,
                'Iface': Iface
            })

    @staticmethod
    def get_ipv6_route_metrics_and_addresses():
        try:
            # Run the "route -A inet6" command to get the IPv6 route table
            route_output = subprocess.check_output(["route", "-A", "inet6"]).decode("utf-8")

            # Split the route output into lines
            route_lines = route_output.splitlines()[2:]

            for line in route_lines:
                # Split each line into fields using whitespace as the delimiter
                fields = line.split()

                # Extract the fields of interest (Destination, Nexthop, Flag, Metric, Refcnt, Use, If)
                if len(fields) >= 7:
                    Destination, Nexthop, Flag, Metric, Refcnt, Use, If = fields[:7]
                    Node.save_ipv6_routing_table(Destination, Nexthop, Flag, Metric, Refcnt, Use, If)

        except subprocess.CalledProcessError as e:
            print("Error running 'ip' command:", e)
            return []

        except Exception as e:
            print("An error occurred:", e)
            return []

    @staticmethod
    def get_ipv4_route_metrics_and_addresses():
        try:
            route_output = subprocess.check_output(["route", "-n"]).decode("utf-8")
            route_lines = route_output.splitlines()[2:]

            for line in route_lines:
                fields = line.split()

                if len(fields) >= 8:
                    Destination, Gateway, Genmask, Flags, Metric, Ref, Use, Iface = fields[:8]
                    Node.save_ipv4_routing_table(Destination, Gateway, Genmask, Flags, Metric, Ref, Use, Iface)

        except subprocess.CalledProcessError as e:
            print("Error running 'route' command:", e)
            return []

        except Exception as e:
            print("An error occurred:", e)
            return []
    
    @staticmethod
    def get_status_ip(ip):
        # Check the status of IP (SLAAC, DHCP, Manual)
        csv_file = get_csv_path("addresses.csv")
        if has_additional_data(csv_file):
            pass
           
    def __repr__(self):
        return f"{self.__class__.__name__}({self.mac}, {self.ip})"