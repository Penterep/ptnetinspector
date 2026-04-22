"""Entity representing default gateways discovered on the network.

Provides persistence helpers to record default gateway MAC/IP pairs into CSV.
"""
import csv
from ptnetinspector.utils.path import get_csv_path
from ptnetinspector.entities._registry import registry


class DefaultGateway:
    all_nodes = []

    def __init__(self, mac: str, ip: str) -> None:
        self.mac = mac
        self.ip = ip
        DefaultGateway.all_nodes.append(self)

    def save_addresses(self) -> None:
        key = (self.mac, self.ip)
        if registry.seen("default_gw", key):
            return

        csv_file = get_csv_path("default_gw.csv")

        with open(csv_file, 'a', newline='') as csvfile:
            fieldnames = ['MAC', 'IP']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writerow({
                'IP': self.ip,
                'MAC': self.mac
            })

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.mac}, {self.ip})"