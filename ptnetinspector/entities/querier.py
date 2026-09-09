"""Entity for the multicast querier observed on the link.

The device that emits MLDv2 / IGMP General Queries is the elected querier, which
is normally the router or the snooping switch. Recording it is free: the queries
are already captured, and knowing which box holds that role is infrastructure
detail a host-focused scan otherwise misses.
"""
import csv
from ptnetinspector.utils.path import get_csv_path
from ptnetinspector.entities._registry import registry


class Querier:
    """One observed General Query, attributed to its sender."""

    FIELDS = ['MAC', 'IP', 'Protocol', 'Group', 'QRV', 'QQIC', 'Max_response']

    def __init__(self, mac: str, ip: str, protocol: str, group: str = "",
                 qrv: str = "", qqic: str = "", max_response: str = "") -> None:
        self.mac = mac
        self.ip = ip
        self.protocol = protocol
        self.group = group
        self.qrv = qrv
        self.qqic = qqic
        self.max_response = max_response

    def save(self) -> None:
        key = (self.mac, self.ip, self.protocol, self.group)
        if registry.seen("querier", key):
            return

        csv_file = get_csv_path("querier.csv")

        with open(csv_file, 'a', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=Querier.FIELDS)
            writer.writerow({
                'MAC': self.mac,
                'IP': self.ip,
                'Protocol': self.protocol,
                'Group': self.group,
                'QRV': self.qrv,
                'QQIC': self.qqic,
                'Max_response': self.max_response,
            })

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.mac}, {self.ip}, {self.protocol})"
