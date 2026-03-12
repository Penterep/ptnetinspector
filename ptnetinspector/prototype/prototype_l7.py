from enum import IntEnum

from scapy.all import Raw, Packet
from scapy.layers.dns import DNS, DNSQR

from ptnetinspector.prototype.prototype_l4 import *

class DNS_QType(IntEnum):
    A = 1
    AAAA = 28
    PTR = 12
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