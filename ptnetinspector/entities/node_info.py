"""Entity for ICMPv6 Node Information replies (RFC 4620).

A responder returns its own hostname and its full address list, which is the
point of the query: those addresses are not advertised anywhere else and address
enumeration would not guess them. Support is uneven - many BSD and macOS stacks
answer, Linux generally does not - so an absent reply means "no support", not
"no host".
"""
import csv
from ptnetinspector.utils.path import get_csv_path
from ptnetinspector.entities._registry import registry


class NodeInfo:
    """One fact a node reported about itself."""

    FIELDS = ['MAC', 'IP', 'Type', 'Value']

    def __init__(self, mac: str, ip: str, info_type: str, value: str) -> None:
        self.mac = mac
        self.ip = ip
        self.info_type = info_type
        self.value = value

    def save(self) -> None:
        key = (self.mac, self.info_type, self.value)
        if registry.seen("node_info", key):
            return

        csv_file = get_csv_path("node_info.csv")

        with open(csv_file, 'a', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=NodeInfo.FIELDS)
            writer.writerow({
                'MAC': self.mac,
                'IP': self.ip,
                'Type': self.info_type,
                'Value': self.value,
            })

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.mac}, {self.info_type}={self.value})"
