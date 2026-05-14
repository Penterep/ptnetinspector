import random
import uuid

from scapy.layers.inet import UDP
from scapy.all import Raw, Packet
from scapy.layers.dns import DNS, DNSQR, DNSRR

from ptnetinspector.prototype.prototype_l7 import PrototypeL7

class PrototypeL4:
    MDNS_PORT = 5353 # Note: Keep same as the default value used in get_l3payload_mdns_sd sport parameter for consistency.
    LLMNR_PORT = 5355
    WS_DISCOVERY_PORT = 3702

    @staticmethod
    def get_l4port_random() -> int:
        """
        Returns a random ephemeral port number between 49152 and 65535.
        Args:
            None
        Output:
            int: A random ephemeral port number.
        """
        return random.randint(49152, 65535)

    @staticmethod
    def get_l3payload_wsdiscovery(message_id: str|None = None) -> Packet:
        """
        Returns WS-Discovery Probe packet.
        Does not include L2 and L3 headers, only the WS-Discovery payload.
        Args:
            None
        Output:
            Packet: Scapy packet representing WS-Discovery Probe.
        """
        id = str(uuid.uuid4()) if message_id is None else message_id
        soap_payload = f"""<?xml version="1.0" ?>
<s:Envelope xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:s="http://www.w3.org/2003/05/soap-envelope">
\t<s:Header>
\t\t<a:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</a:Action>
\t\t<a:MessageID>urn:uuid:{id}</a:MessageID>
\t\t<a:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</a:To>
\t</s:Header>
\t<s:Body>
\t\t<d:Probe/>
\t</s:Body>
</s:Envelope>
"""
        udp = UDP(sport=PrototypeL4.get_l4port_random(), dport=PrototypeL4.WS_DISCOVERY_PORT)
        payload = Raw(load=soap_payload)
        return udp / payload
    
    # Note: Check the PrototypeL4.MDNS_PORT constant for consistency with the default value used in get_l3payload_mdns_sd sport parameter.
    @staticmethod
    def get_l3payload_mdns_sd(unicastresponse: int = 0, sport: int|None = 5353) -> Packet:
        return (
            UDP(sport=PrototypeL4.get_l4port_random() if sport is None else sport, dport=PrototypeL4.MDNS_PORT) /
            PrototypeL7.get_dns_sd(unicastresponse=unicastresponse))