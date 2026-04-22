"""Entity for MLDv2 multicast membership observations.

Extends Node with report type, multicast and source list, persisted to CSV.
"""
import csv
from ptnetinspector.utils.path import get_csv_path
from ptnetinspector.entities.node import Node
from ptnetinspector.entities._registry import registry


class MLDv2(Node):
    def __init__(self, mac: str, ip: str, protocol: str, rtype: str, mulip: str, sources: str) -> None:
        # Assign to self object
        super().__init__(mac, ip)
        self.protocol = protocol
        self.rtype = rtype
        self.mulip = mulip
        self.sources = sources

    def save_MLDv2(self) -> None:
        # Function to save MLDv2 information to a CSV file
        key = (self.mac, self.ip, self.protocol, self.rtype, self.mulip, self.sources)
        if registry.seen("mldv2", key):
            return

        csv_file = get_csv_path("MLDv2.csv")

        with open(csv_file, 'a', newline='') as csvfile:
            fieldnames = ['MAC', 'IP', 'protocol', 'rtype', 'mulip', 'sources']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writerow({
                'MAC': self.mac,
                'IP': self.ip,
                'protocol': self.protocol,
                'rtype': self.rtype,
                'mulip': self.mulip,
                'sources': self.sources
            })

    @classmethod
    def get_mldv2_from_csv(cls) -> None:
        # Importing the information about nodes from tmp files
        csv_file = get_csv_path("MLDv2.csv")

        with open(csv_file, "r") as csv_file:
            reader = csv.DictReader(csv_file)
            nodes = list(reader)

            for node in nodes:
                MLDv2(
                    mac=node.get('MAC'),
                    ip=node.get('IP'),
                    protocol=node.get('protocol'),
                    rtype=node.get('rtype'),
                    mulip=node.get('mulip'),
                    sources=node.get('sources')
                )

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.mac}, {self.ip}, {self.protocol}, {self.rtype}, {self.mulip}, {self.sources})"