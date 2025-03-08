import csv
import subprocess
from libs.check import has_additional_data

class Node:
    
    all_nodes = []
    def __init__(self, mac:str, ip:str):
        # Assign to self object
        self.mac = mac
        self.ip = ip
        Node.all_nodes.append(self)
    
    @classmethod
    def get_from_csv(cls):
        # Importing the information about nodes from tmp files
        with open ("src/tmp/addresses.csv", "r") as csv_file:
            reader = csv.DictReader(csv_file)
            nodes = list(reader)

            for node in nodes:
                Node(
                    mac = node.get('MAC'),
                    ip = node.get('IP')
                )

    def save_addresses(self):
        # Exporting addresses to csv files and avoid duplication
        with open('src/tmp/packets.csv', 'a+', newline='') as csvfile:
            file_writer = csv.writer(csvfile)
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
        with open('src/tmp/localname.csv', 'a+', newline='') as csvfile:
            file_writer = csv.writer(csvfile)
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
    
    def save_ipv6_routing_table(Destination, Nexthop, Flag, Metric, Refcnt, Use, If):
        with open('src/tmp/ipv6_route_table.csv', 'a+', newline='') as csvfile:
            file_writer = csv.writer(csvfile)
            csvfile.seek(0)  # move the file pointer to the beginning of the file
            for row in csv.reader(csvfile):
                if row and row == file_writer:
                    return  # Record already exists in the file
                else:
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

    def save_ipv4_routing_table(Destination, Gateway, Genmask, Flags, Metric, Ref, Use, Iface):
        with open('src/tmp/ipv4_route_table.csv', 'a+', newline='') as csvfile:
            file_writer = csv.writer(csvfile)
            csvfile.seek(0)
            for row in csv.reader(csvfile):
                if row and row == file_writer:
                    return
                else:
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
    # Check the status of IP (SLAAC, DHCP, Manual)
    def get_status_ip(ip):
        if has_additional_data("src/tmp/addresses.csv"):
            pass
           
    def __repr__(self):
        return f"{self.__class__.__name__}({self.mac}, {self.ip})"



    
    