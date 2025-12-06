import csv
from ptnetinspector.utils.path import get_csv_path
from ptnetinspector.entities.node import Node

class IGMPv1v2(Node):
    def __init__(self, mac: str, ip: str, protocol: str, mulip: str):
        super().__init__(mac, ip)
        self.protocol = protocol
        self.mulip = mulip

    def save(self):
        csv_file = get_csv_path("IGMPv1v2.csv")
        
        with open(csv_file, 'a+', newline='') as csvfile:
            csvfile.seek(0)
            for row in csv.DictReader(csvfile):
                if row and row['MAC'] == self.mac and row['IP'] == self.ip and row['protocol'] == self.protocol and row['mulip'] == self.mulip:
                    return

            fieldnames = ['MAC', 'IP', 'protocol', 'mulip']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writerow({
                'MAC': self.mac,
                'IP': self.ip,
                'protocol': self.protocol,
                'mulip': self.mulip
            })

    def __repr__(self):
        return f"{self.__class__.__name__}({self.mac}, {self.ip}, {self.protocol}, {self.mulip})"