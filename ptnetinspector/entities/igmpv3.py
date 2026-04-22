"""Entity for IGMPv3 multicast membership observations.

Extends Node with report type, multicast and source list, persisted to CSV.
"""
import csv
from ptnetinspector.utils.path import get_csv_path
from ptnetinspector.entities.node import Node
from ptnetinspector.entities._registry import registry


class IGMPv3(Node):
    def __init__(self, mac: str, ip: str, protocol: str, rtype: str, mulip: str, sources: str) -> None:
        super().__init__(mac, ip)
        self.protocol = protocol
        self.rtype = rtype
        self.mulip = mulip
        self.sources = sources

    def save(self) -> None:
        key = (self.mac, self.ip, self.protocol, self.rtype, self.mulip, self.sources)
        if registry.seen("igmpv3", key):
            return

        csv_file = get_csv_path("IGMPv3.csv")

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

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.mac}, {self.ip}, {self.protocol}, {self.rtype}, {self.mulip}, {self.sources})"