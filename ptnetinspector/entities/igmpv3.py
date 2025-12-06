import csv
from ptnetinspector.utils.path import get_csv_path
from ptnetinspector.entities.node import Node


class IGMPv3(Node):
    def __init__(self, mac: str, ip: str, protocol: str, rtype: str, mulip: str, sources: str):
        super().__init__(mac, ip)
        self.protocol = protocol
        self.rtype = rtype
        self.mulip = mulip
        self.sources = sources

    def save(self):
        csv_file = get_csv_path("IGMPv3.csv")
        
        with open(csv_file, 'a+', newline='') as csvfile:
            csvfile.seek(0)
            for row in csv.DictReader(csvfile):
                if row and row['MAC'] == self.mac and row['IP'] == self.ip and row['protocol'] == self.protocol and row['rtype'] == self.rtype and row['mulip'] == self.mulip and row['sources'] == self.sources:
                    return

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

    def __repr__(self):
        return f"{self.__class__.__name__}({self.mac}, {self.ip}, {self.protocol}, {self.rtype}, {self.mulip}, {self.sources})"