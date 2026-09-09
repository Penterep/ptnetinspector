"""Entity for DNS-SD service instances discovered over mDNS.

Persists the service tree walked from `_services._dns-sd._udp.local`: which
service types exist, which instances advertise them, and the SRV host/port plus
TXT metadata each instance publishes.
"""
import csv
from ptnetinspector.utils.path import get_csv_path
from ptnetinspector.entities._registry import registry


class DNSSD:
    """One discovered DNS-SD record, keyed by the device that answered."""

    FIELDS = ['MAC', 'IP', 'Service', 'Instance', 'Target', 'Port', 'TXT']

    def __init__(self, mac: str, ip: str = "", service: str = "", instance: str = "",
                 target: str = "", port: str = "", txt: str = "") -> None:
        self.mac = mac
        self.ip = ip
        self.service = service
        self.instance = instance
        self.target = target
        self.port = port
        self.txt = txt

    def save(self) -> None:
        key = (self.mac, self.service, self.instance, self.target, self.port, self.txt)
        if registry.seen("dnssd", key):
            return

        csv_file = get_csv_path("dnssd.csv")

        with open(csv_file, 'a', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=DNSSD.FIELDS)
            writer.writerow({
                'MAC': self.mac,
                'IP': self.ip,
                'Service': self.service,
                'Instance': self.instance,
                'Target': self.target,
                'Port': self.port,
                'TXT': self.txt,
            })

    @staticmethod
    def collect_targets(max_services: int = 64, max_instances: int = 128) -> tuple[list[str], list[str]]:
        """Read back the service types and instances mDNS has already revealed.

        These are the follow-up targets for the active walk: a PTR per service
        type, then SRV and TXT per instance. Bounded, because a busy segment can
        advertise a great many.
        """
        from ptnetinspector.utils.ip_utils import has_additional_data

        service_types: list[str] = []
        instances: list[str] = []

        dnssd_file = get_csv_path("dnssd.csv")
        if not has_additional_data(dnssd_file):
            return service_types, instances

        try:
            with open(dnssd_file, newline="") as handle:
                for row in csv.DictReader(handle):
                    service = str(row.get("Service", "")).strip()
                    instance = str(row.get("Instance", "")).strip()
                    if service and service not in service_types:
                        service_types.append(service)
                    if instance and instance not in instances:
                        instances.append(instance)
        except OSError:
            # A missing or unreadable file simply means nothing to follow up on.
            return service_types, instances

        return service_types[:max_services], instances[:max_instances]

    def __repr__(self) -> str:
        return (f"{self.__class__.__name__}({self.mac}, {self.service}, "
                f"{self.instance}, {self.target}:{self.port})")
