"""Entity for passive host fingerprints derived from fields already captured.

Nothing here puts a packet on the wire: the hop limit, the interface-identifier
style and the RA timer values are read out of frames the scan already received,
so every observation is a by-product of traffic that was going to be parsed
anyway. Results are heuristics and are reported as "likely", never as fact.
"""
import csv
from ptnetinspector.utils.path import get_csv_path
from ptnetinspector.entities._registry import registry


# Initial hop limit / TTL defaults, which stacks rarely change.
_HOP_LIMIT_OS = {
    255: "network device (Cisco/router-class default)",
    128: "Windows",
    64: "Linux / macOS / BSD",
    32: "legacy Windows",
}


def guess_os_from_hop_limit(hop_limit) -> str:
    """Map an observed hop limit back to the sender's initial value.

    The value on the wire has already been decremented once per router, so the
    nearest default at or above the observation is the useful guess. Only the
    on-link case is trusted enough to name.
    """
    try:
        observed = int(hop_limit)
    except (TypeError, ValueError):
        return ""

    for initial in sorted(_HOP_LIMIT_OS):
        if observed == initial:
            return _HOP_LIMIT_OS[initial]
        if observed < initial and initial - observed <= 8:
            return f"{_HOP_LIMIT_OS[initial]} ({initial - observed} hop(s) away)"
    return ""


class Fingerprint:
    """One passive observation about a device, keyed by MAC."""

    FIELDS = ['MAC', 'Hop_limit', 'OS_guess', 'IID_type', 'Reachable_time', 'Retrans_time', 'Router_lft']

    def __init__(self, mac: str, hop_limit: str = "", os_guess: str = "", iid_type: str = "",
                 reachable_time: str = "", retrans_time: str = "", router_lft: str = "") -> None:
        self.mac = mac
        self.hop_limit = hop_limit
        self.os_guess = os_guess
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
                'OS_guess': self.os_guess,
                'IID_type': self.iid_type,
                'Reachable_time': self.reachable_time,
                'Retrans_time': self.retrans_time,
                'Router_lft': self.router_lft,
            })

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.mac}, {self.os_guess}, {self.iid_type})"
