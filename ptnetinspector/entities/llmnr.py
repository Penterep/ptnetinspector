"""Entity for LLMNR responders observed on the network.

Persists observed MAC/IP pairs responding to LLMNR into CSV.
"""
import csv
from ptnetinspector.utils.path import get_csv_path
from ptnetinspector.entities.node import Node
from ptnetinspector.entities._registry import registry


class LLMNR(Node):
    def __init__(self, mac: str, ip: str) -> None:
        # Assign to self object
        super().__init__(mac, ip)

    def save_LLMNR(self) -> None:
        # Function to save LLMNR IP address to a CSV file
        key = (self.mac, self.ip)
        if registry.seen("llmnr", key):
            return

        csv_file = get_csv_path("LLMNR.csv")

        with open(csv_file, 'a', newline='') as csvfile:
            fieldnames = ['MAC', 'IP']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writerow({
                'MAC': self.mac,
                'IP': self.ip
            })

    @classmethod
    def get_llmnr_from_csv(cls) -> None:
        # Importing the information about nodes from tmp files
        csv_file = get_csv_path("LLMNR.csv")

        with open(csv_file, "r") as csv_file:
            reader = csv.DictReader(csv_file)
            nodes = list(reader)

            for node in nodes:
                LLMNR(
                    mac=node.get('MAC'),
                    ip=node.get('IP')
                )

    @staticmethod
    def full_name_llmnr(name: str) -> str:
        # Completing LLMNR name to ask for IP
        if name.endswith('.local.'):
            return name[:-6]
        else:
            return name

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.mac}, {self.ip})"