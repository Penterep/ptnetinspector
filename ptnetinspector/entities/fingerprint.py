"""Entity for passive host fingerprints derived from fields already captured.

Nothing here puts a packet on the wire: the hop limit, the interface-identifier
style and the RA timer values are read out of frames the scan already received,
so every observation is a by-product of traffic that was going to be parsed
anyway. These are raw observations only; the tool no longer guesses an operating
system from the hop limit, because without active port probing that guess was
unreliable enough to mislead rather than inform.
"""
import csv
from ptnetinspector.utils.path import get_csv_path
from ptnetinspector.entities._registry import registry


class Fingerprint:
    """One passive observation about a device, keyed by MAC."""

    FIELDS = ['MAC', 'Hop_limit', 'IID_type', 'Reachable_time', 'Retrans_time', 'Router_lft']

    def __init__(self, mac: str, hop_limit: str = "", iid_type: str = "",
                 reachable_time: str = "", retrans_time: str = "", router_lft: str = "") -> None:
        self.mac = mac
        self.hop_limit = hop_limit
        self.iid_type = iid_type
        self.reachable_time = reachable_time
        self.retrans_time = retrans_time
        self.router_lft = router_lft

    def save(self) -> None:
        key = (self.mac, self.hop_limit, self.iid_type, self.reachable_time,
               self.retrans_time, self.router_lft)
        if registry.seen("fingerprint", key):
            return

        csv_file = get_csv_path("fingerprint.csv")

        with open(csv_file, 'a', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=Fingerprint.FIELDS)
            writer.writerow({
                'MAC': self.mac,
                'Hop_limit': self.hop_limit,
                'IID_type': self.iid_type,
                'Reachable_time': self.reachable_time,
                'Retrans_time': self.retrans_time,
                'Router_lft': self.router_lft,
            })

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.mac}, {self.iid_type})"
