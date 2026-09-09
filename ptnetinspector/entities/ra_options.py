"""Entity for the Router Advertisement options the scanner used to discard.

RAs are captured already; only RDNSS, MTU and the *first* Prefix Information
option were ever read out of them. Each option below is free recon data that was
being thrown away:

* DNSSL (RFC 8106)          - internal DNS search domains.
* Route Information (4191)  - more-specific routes, i.e. internal topology.
* PREF64 (RFC 8781)         - a NAT64/DNS64 prefix is in use.
* Captive Portal (RFC 8910) - the portal URL.
* Every Prefix Information and RDNSS option, not just the first.
"""
import csv
from ptnetinspector.utils.path import get_csv_path
from ptnetinspector.entities._registry import registry


class RAOption:
    """One option carried by an observed Router Advertisement."""

    FIELDS = ['MAC', 'IP', 'Option', 'Value', 'Lifetime', 'Flags']

    def __init__(self, mac: str, ip: str, option: str, value: str,
                 lifetime: str = "", flags: str = "") -> None:
        self.mac = mac
        self.ip = ip
        self.option = option
        self.value = value
        self.lifetime = lifetime
        self.flags = flags

    def save(self) -> None:
        key = (self.mac, self.ip, self.option, self.value)
        if registry.seen("ra_option", key):
            return

        csv_file = get_csv_path("ra_options.csv")

        with open(csv_file, 'a', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=RAOption.FIELDS)
            writer.writerow({
                'MAC': self.mac,
                'IP': self.ip,
                'Option': self.option,
                'Value': self.value,
                'Lifetime': self.lifetime,
                'Flags': self.flags,
            })

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.mac}, {self.option}={self.value})"
