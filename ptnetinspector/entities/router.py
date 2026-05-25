"""Entity for IPv6 Router Advertisement details discovered.

Persists RA fields per router into CSV for later analysis/output.
"""
import csv
from ptnetinspector.utils.path import get_csv_path
from ptnetinspector.entities.node import Node
from ptnetinspector.entities._registry import registry


class Router(Node):
    all_nodes = []

    def __init__(self, mac: str, ip: str, M: str, O: str, H: str, A: str, L: str, Preference: str, Router_lft: str, Reachable_time: str, Retrans_time: str, DNS: str, MTU: str, Prefix: str, Valid_lft: str, Preferred_lft: str) -> None:
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
    def get_RA_from_csv(cls) -> None:
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
    def save_router_address(mac: str) -> None:
        # Function to save router MAC address to a CSV file
        key = (mac,)
        if registry.seen("router_mac", key):
            return

        csv_file = get_csv_path("routers.csv")

        with open(csv_file, 'a', newline='') as csvfile:
            csv.writer(csvfile).writerow([mac])

    def save_RA(self) -> None:
        key = (self.mac, self.ip, self.M, self.O, self.A, self.Preference, self.Prefix)
        if registry.seen("router_ra", key):
            return

        csv_file = get_csv_path("RA.csv")

        with open(csv_file, 'a', newline='') as csvfile:
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

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.mac}, {self.ip}, {self.M}, {self.O}, {self.H}, {self.A}, {self.L}, {self.Preference}, {self.Router_lft}, {self.Reachable_time}, {self.Retrans_time}, {self.DNS}, {self.MTU}, {self.Prefix}, {self.Valid_lft}, {self.Preferred_lft})"