from enum import IntEnum

from scapy.all import Raw, Packet
from scapy.layers.dns import DNS, DNSQR

class DNS_QType(IntEnum):
    A = 1
    AAAA = 28
    PTR = 12
    TXT = 16
    SRV = 33
    ANY = 255

class PrototypeL7:
    @staticmethod
    def get_dns_bundle_a_aaaa_any(qname: str, unicastresponse: int = 0) -> list[Packet]:
        return [
            DNS(rd=1, qd=DNSQR(qname=qname, qtype=DNS_QType.ANY, qclass=1, unicastresponse=unicastresponse)),
            DNS(rd=1, qd=DNSQR(qname=qname, qtype=DNS_QType.A, qclass=1, unicastresponse=unicastresponse)),
            DNS(rd=1, qd=DNSQR(qname=qname, qtype=DNS_QType.AAAA, qclass=1, unicastresponse=unicastresponse)),
        ]

    @staticmethod
    def get_dns_ptr(qname: str, unicastresponse: int = 0) -> Packet:
        return DNS(rd=1, qd=DNSQR(qname=qname, qtype=DNS_QType.PTR, unicastresponse=unicastresponse))
 
    @staticmethod
    def get_dns_srv_txt(qname: str, unicastresponse: int = 0) -> list[Packet]:
        """SRV and TXT for one DNS-SD instance: the host, port and metadata.

        The PTR walk only names instances; SRV says where an instance actually
        listens and TXT carries the model/version strings that identify it.
        """
        return [
            DNS(rd=1, qd=DNSQR(qname=qname, qtype=DNS_QType.SRV, qclass=1, unicastresponse=unicastresponse)),
            DNS(rd=1, qd=DNSQR(qname=qname, qtype=DNS_QType.TXT, qclass=1, unicastresponse=unicastresponse)),
        ]

    @staticmethod
    def get_dns_sd(unicastresponse: int = 0) -> Packet:
        return (
            DNS(id=33, rd=1, qd=DNSQR(qname="_services._dns-sd._udp.local.", qtype=DNS_QType.PTR, unicastresponse=unicastresponse)))