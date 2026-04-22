"""Entity for EAP/EAPOL events captured during 802.1x checks.

Handles persistence of EAP observations in CSV form.
"""
import csv
from ptnetinspector.utils.path import get_csv_path
from ptnetinspector.entities._registry import registry


class EAP:

    all_nodes = []

    def __init__(self, mac: str, packet: str) -> None:
        # Assign to self object
        self.mac = mac
        self.packet = packet

    def save_eap(self) -> None:
        # Function to save EAP to a CSV file
        key = (self.mac, self.packet)
        if registry.seen("eap", key):
            return

        csv_file = get_csv_path("eap.csv")

        with open(csv_file, 'a', newline='') as csvfile:
            fieldnames = ['MAC', 'packet']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writerow({
                'MAC': self.mac,
                'packet': self.packet
            })

    @classmethod
    def get_eap_from_csv(cls) -> None:
        # Importing the information about nodes from tmp files
        csv_file = get_csv_path("eap.csv")

        with open(csv_file, "r") as csv_file:
            reader = csv.DictReader(csv_file)
            nodes = list(reader)

            for node in nodes:
                EAP(
                    mac=node.get('MAC'),
                    packet=node.get('packet')
                )

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.mac}, {self.packet})"