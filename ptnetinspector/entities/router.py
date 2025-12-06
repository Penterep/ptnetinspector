import csv
from ptnetinspector.utils.path import get_csv_path
from ptnetinspector.entities.node import Node


class Router(Node):
    all_nodes = []
    
    def __init__(self, mac: str, ip: str, M: str, O: str, H: str, A: str, L: str, Preference: str, Router_lft: str, Reachable_time: str, Retrans_time: str, DNS: str, MTU: str, Prefix: str, Valid_lft: str, Preferred_lft: str):      
        # Assign to self object
        self.mac = mac
        self.ip = ip

        self.M = M
        self.O = O
        self.H = H
        self.A = A
        self.L = L

        self.Preference = Preference
        self.Router_lft = Router_lft
        self.Reachable_time = Reachable_time
        self.Retrans_time = Retrans_time

        self.DNS = DNS
        self.MTU = MTU
        self.Prefix = Prefix
        self.Valid_lft = Valid_lft
        self.Preferred_lft = Preferred_lft

        Router.all_nodes.append(self)

    @classmethod
    def get_RA_from_csv(cls):
        # Importing the information about nodes from tmp files
        csv_file = get_csv_path("RA.csv")
        
        with open(csv_file, "r") as csv_file:
            reader = csv.DictReader(csv_file)
            nodes = list(reader)

            for node in nodes:
                Router(
                    mac=node.get('MAC'),
                    ip=node.get('IP'),
                    M=node.get('M'),
                    O=node.get('O'),
                    H=node.get('H'),
                    A=node.get('A'),
                    L=node.get('L'),
                    Preference=node.get('Preference'),
                    Router_lft=node.get('Router_lft'),
                    Reachable_time=node.get('Reachable_time'),
                    Retrans_time=node.get('Retrans_time'),
                    DNS=node.get('DNS'),
                    MTU=node.get('MTU'),
                    Prefix=node.get('Prefix'),
                    Valid_lft=node.get('Valid_lft'),
                    Preferred_lft=node.get('Preferred_lft')
                )

    @staticmethod
    def save_router_address(mac):
        # Function to save router MAC address to a CSV file
        csv_file = get_csv_path("routers.csv")
        
        with open(csv_file, 'a+', newline='') as csvfile:
            csvfile.seek(0)
            # Check if the IP and MAC addresses already exist in the file
            for row in csv.DictReader(csvfile):
                if row['MAC'] == mac:
                    return  # MAC already exist, no need to save

            # IP and MAC not found, save them to the file
            csv.writer(csvfile).writerow([mac])
    
    def save_RA(self):
        csv_file = get_csv_path("RA.csv")
        
        with open(csv_file, 'a+', newline='') as csvfile:
            csvfile.seek(0)  # move the file pointer to the beginning of the file
            for row in csv.DictReader(csvfile):
                if row and row['MAC'] == self.mac and row['IP'] == self.ip and row['M'] == self.M and row['O'] == self.O and row['A'] == self.A and row['Preference'] == self.Preference and row['Prefix'] == self.Prefix:
                    return  # Record already exists in the file
                
            fieldnames = ['MAC', 'IP', 'M', 'O', 'H', 'A', 'L', 'Preference', 'Router_lft', 'Reachable_time',
                        'Retrans_time', 'DNS', 'MTU', 'Prefix', 'Valid_lft', 'Preferred_lft']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writerow({
                'MAC': self.mac,
                'IP': self.ip,
                'M': self.M,
                'O': self.O,
                'H': self.H,
                'A': self.A,
                'L': self.L,
                'Preference': self.Preference,
                'Router_lft': self.Router_lft,
                'Reachable_time': self.Reachable_time,
                'Retrans_time': self.Retrans_time,
                'DNS': self.DNS,
                'MTU': self.MTU,
                'Prefix': self.Prefix,
                'Valid_lft': self.Valid_lft,
                'Preferred_lft': self.Preferred_lft
            })

    def __repr__(self):
        return f"{self.__class__.__name__}({self.mac}, {self.ip}, {self.M}, {self.O}, {self.H}, {self.A}, {self.L}, {self.Preference}, {self.Router_lft}, {self.Reachable_time}, {self.Retrans_time}, {self.DNS}, {self.MTU}, {self.Prefix}, {self.Valid_lft}, {self.Preferred_lft})"