"""Entity for DHCP/DHCPv6 roles and addresses discovered.

Supports loading DHCP-related MAC/IP/role tuples from CSV artifacts.
"""
import csv
from ptnetinspector.utils.path import get_csv_path
from ptnetinspector.entities._registry import registry


class DHCP:

    all_nodes = []

    def __init__(self, mac: str, ip: str, role: str) -> None:
        # Assign to self object
        self.mac = mac
        self.ip = ip
        self.role = role
        DHCP.all_nodes.append(self)

    @classmethod
    def get_from_csv(cls) -> None:
        # Importing the information about nodes from tmp files
        csv_file = get_csv_path("dhcp.csv")

        with open(csv_file, "r") as csv_file:
            reader = csv.DictReader(csv_file)
            nodes = list(reader)

            for node in nodes:
                DHCP(
                    mac=node.get('MAC'),
                    ip=node.get('IP'),
                    role=node.get('Role')
                )

    def save_addresses(self) -> None:
        # Exporting addresses to csv files and avoid duplication
        key = (self.mac, self.ip, self.role)
        if registry.seen("dhcp", key):
            return

        csv_file = get_csv_path("dhcp.csv")

        with open(csv_file, 'a', newline='') as csvfile:
            fieldnames = ['MAC', 'IP', 'Role']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writerow({
                'IP': self.ip,
                'MAC': self.mac,
                'Role': self.role
            })

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.mac}, {self.ip})"