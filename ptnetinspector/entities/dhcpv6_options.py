"""Entity for the configuration options a DHCPv6 server hands out.

Beyond the address itself, a Reply or Advertise carries the resolvers, the
domain search list, NTP/SIP servers, a boot-file URL and vendor data. Together
with the server DUID those characterise both the environment and the server.
"""
import csv
from ptnetinspector.utils.path import get_csv_path
from ptnetinspector.entities._registry import registry


class DHCPv6Options:
    """One option value returned by a DHCPv6 server."""

    FIELDS = ['MAC', 'IP', 'Option', 'Value']

    def __init__(self, mac: str, ip: str, option: str, value: str) -> None:
        self.mac = mac
        self.ip = ip
        self.option = option
        self.value = value

    def save(self) -> None:
        key = (self.mac, self.option, self.value)
        if registry.seen("dhcpv6_options", key):
            return

        csv_file = get_csv_path("dhcpv6_options.csv")

        with open(csv_file, 'a', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=DHCPv6Options.FIELDS)
            writer.writerow({
                'MAC': self.mac,
                'IP': self.ip,
                'Option': self.option,
                'Value': self.value,
            })

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.mac}, {self.option}={self.value})"
