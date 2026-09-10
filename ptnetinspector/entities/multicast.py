"""Multicast groups whose traffic reached the scanning port.

Recorded so the report can name the groups this host received without ever
joining them. A switch that snoops MLD/IGMP forwards a group only to the ports
that asked for it, so traffic for a group nobody here joined is evidence the
segment floods instead of filtering - the observation the snooping probe wanted
to make but cannot make on its own, because telling whether *our* group reached
*other* ports needs a second vantage point.
"""
import csv
import logging

from ptnetinspector.entities._registry import registry
from ptnetinspector.utils.path import get_csv_path


logger = logging.getLogger(__name__)


class MulticastGroup:
    FIELDS = ['Group', 'Version', 'Source_MAC']

    def __init__(self, group: str, version: str, source_mac: str) -> None:
        self.group = group
        self.version = version
        self.source_mac = source_mac

    def save(self) -> None:
        key = (self.group, self.source_mac)
        if registry.seen("multicast_group", key):
            return

        try:
            with open(get_csv_path("multicast_groups.csv"), "a", newline="") as handle:
                csv.DictWriter(handle, fieldnames=MulticastGroup.FIELDS).writerow({
                    'Group': self.group,
                    'Version': self.version,
                    'Source_MAC': self.source_mac,
                })
        except OSError as error:
            logger.debug("Could not record multicast group %s: %s", self.group, error)
