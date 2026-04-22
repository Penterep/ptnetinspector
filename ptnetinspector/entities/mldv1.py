"""Entity for MLDv1 multicast membership observations.

Extends Node with protocol/multicast details and persists to CSV.
"""
import csv
from ptnetinspector.utils.path import get_csv_path
from ptnetinspector.entities.node import Node
from ptnetinspector.entities._registry import registry


class MLDv1(Node):
    def __init__(self, mac: str, ip: str, protocol: str, mulip: str) -> None:
        # Assign to self object
        super().__init__(mac, ip)
        self.protocol = protocol
        self.mulip = mulip

    def save_MLDv1(self) -> None:
        # Function to save MLDv1 information to a CSV file
        key = (self.mac, self.ip, self.protocol, self.mulip)
        if registry.seen("mldv1", key):
            return

        csv_file = get_csv_path("MLDv1.csv")

        with open(csv_file, 'a', newline='') as csvfile:
            fieldnames = ['MAC', 'IP', 'protocol', 'mulip']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writerow({
                'MAC': self.mac,
                'IP': self.ip,
                'protocol': self.protocol,
                'mulip': self.mulip
            })

    @classmethod
    def get_mldv1_from_csv(cls) -> None:
        # Importing the information about nodes from tmp files
        csv_file = get_csv_path("MLDv1.csv")

        with open(csv_file, "r") as csv_file:
            reader = csv.DictReader(csv_file)
            nodes = list(reader)

            for node in nodes:
                MLDv1(
                    mac=node.get('MAC'),
                    ip=node.get('IP'),
                    protocol=node.get('protocol'),
                    mulip=node.get('mulip')
                )

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.mac}, {self.ip}, {self.protocol}, {self.mulip})"