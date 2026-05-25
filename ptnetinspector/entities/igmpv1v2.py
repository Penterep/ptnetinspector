"""Entity for IGMPv1/v2 multicast membership observations.

Extends Node with protocol/multicast specifics and persists to CSV.
"""
import csv
from ptnetinspector.utils.path import get_csv_path
from ptnetinspector.entities.node import Node
from ptnetinspector.entities._registry import registry

class IGMPv1v2(Node):
    def __init__(self, mac: str, ip: str, protocol: str, mulip: str) -> None:
        super().__init__(mac, ip)
        self.protocol = protocol
        self.mulip = mulip

    def save(self) -> None:
        key = (self.mac, self.ip, self.protocol, self.mulip)
        if registry.seen("igmpv1v2", key):
            return

        csv_file = get_csv_path("IGMPv1v2.csv")

        with open(csv_file, 'a', newline='') as csvfile:
            fieldnames = ['MAC', 'IP', 'protocol', 'mulip']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writerow({
                'MAC': self.mac,
                'IP': self.ip,
                'protocol': self.protocol,
                'mulip': self.mulip
            })

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.mac}, {self.ip}, {self.protocol}, {self.mulip})"