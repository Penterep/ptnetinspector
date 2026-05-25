"""Entity for mDNS responders observed on the network.

Persists observed MAC/IP pairs responding to mDNS into CSV.
"""
import csv
from ptnetinspector.utils.path import get_csv_path
from ptnetinspector.entities.node import Node
from ptnetinspector.entities._registry import registry


class MDNS(Node):
    def __init__(self, mac: str, ip: str) -> None:
        # Assign to self object
        super().__init__(mac, ip)

    def save_MDNS(self) -> None:
        # Function to save MDNS IP address to a CSV file
        key = (self.mac, self.ip)
        if registry.seen("mdns", key):
            return

        csv_file = get_csv_path("MDNS.csv")

        with open(csv_file, 'a', newline='') as csvfile:
            fieldnames = ['MAC', 'IP']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writerow({
                'MAC': self.mac,
                'IP': self.ip
            })

    @classmethod
    def get_MDNS_from_csv(cls) -> None:
        # Importing the information about nodes from tmp files
        csv_file = get_csv_path("MDNS.csv")

        with open(csv_file, "r") as csv_file:
            reader = csv.DictReader(csv_file)
            nodes = list(reader)

            for node in nodes:
                MDNS(
                    mac=node.get('MAC'),
                    ip=node.get('IP')
                )

    @staticmethod
    def full_name_MDNS(name: str) -> str:
        # Function to complete MDNS name to use for asking about IP
        # Strip trailing dot from FQDN before processing
        name = name.rstrip('.')
        if ".local" in name:
            return name
        else:
            return name + ".local"

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.mac}, {self.ip})"