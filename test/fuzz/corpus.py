"""Seed frames covering every protocol ptnetinspector parses."""
from scapy.all import *
from scapy.layers.l2 import ARP, Dot1Q, Dot3, LLC, SNAP, STP
from scapy.layers.dot11 import Dot11
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dhcp6 import (
    DHCP6_Advertise, DHCP6_InfoRequest, DHCP6_Reply, DHCP6_Request,
    DHCP6OptClientId, DHCP6OptDNSDomains, DHCP6OptDNSServers, DHCP6OptIAAddress,
    DHCP6OptIA_NA, DHCP6OptServerId, DUID_LLT,
)
from scapy.layers.eap import EAP, EAPOL
from scapy.layers.inet6 import *
from scapy.contrib.igmp import IGMP
from scapy.contrib.igmpv3 import IGMPv3, IGMPv3gr, IGMPv3mq, IGMPv3mr
from scapy.layers.llmnr import LLMNRQuery, LLMNRResponse

conf.verb = 0

MAC = "aa:bb:cc:00:00:01"
LL = "fe80::1"
GUA = "2001:db8::1"


def seeds():
    e = lambda **kw: Ether(src=MAC, dst=kw.pop("dst", "33:33:00:00:00:01"), **kw)
    v6 = lambda dst="ff02::1", **kw: IPv6(src=LL, dst=dst, **kw)
    v4 = lambda dst="224.0.0.1", **kw: IP(src="192.168.1.1", dst=dst, **kw)
    out = {}

    # --- Neighbour Discovery, with every option the parser reads -----------
    out["ra_full"] = (e() / v6(hlim=255) / ICMPv6ND_RA()
        / ICMPv6NDOptSrcLLAddr(lladdr=MAC) / ICMPv6NDOptMTU(mtu=1500)
        / ICMPv6NDOptPrefixInfo(prefix="2001:db8::", prefixlen=64)
        / ICMPv6NDOptPrefixInfo(prefix="2001:db8:1::", prefixlen=64)
        / ICMPv6NDOptRDNSS(dns=["2001:db8::53", "2001:db8::54"])
        / ICMPv6NDOptDNSSL(searchlist=["lan.example.com.", "corp.example."])
        / ICMPv6NDOptRouteInfo(prefix="2001:db8:a::", plen=48)
        / ICMPv6NDOptPREF64(prefix="64:ff9b::")
        / ICMPv6NDOptCaptivePortal(URI=b"http://portal.example/login"))
    out["rs"] = e() / v6(hlim=255) / ICMPv6ND_RS() / ICMPv6NDOptSrcLLAddr(lladdr=MAC)
    out["ns"] = e() / v6(dst="ff02::1:ff00:1", hlim=255) / ICMPv6ND_NS(tgt=LL) / ICMPv6NDOptSrcLLAddr(lladdr=MAC)
    out["ns_dad"] = e() / IPv6(src="::", dst="ff02::1:ff00:1", hlim=255) / ICMPv6ND_NS(tgt=LL)
    out["na"] = e() / v6(hlim=255) / ICMPv6ND_NA(tgt=LL, R=1) / ICMPv6NDOptDstLLAddr(lladdr=MAC)
    out["redirect"] = e() / v6(hlim=255) / ICMPv6ND_Redirect(tgt=LL, dst=GUA)

    # --- MLD ---------------------------------------------------------------
    out["mldv2_report"] = (e() / v6(dst="ff02::16", hlim=1)
        / ICMPv6MLReport2(records=[ICMPv6MLDMultAddrRec(dst="ff02::fb", rtype=4),
                                   ICMPv6MLDMultAddrRec(dst="ff02::1:3", rtype=3,
                                                        sources=["2001:db8::9"])]))
    out["mldv2_query"] = e() / v6(hlim=1) / ICMPv6MLQuery2(mladdr="::")
    out["mldv1_report"] = e() / v6(dst="ff02::fb", hlim=1) / ICMPv6MLReport(mladdr="ff02::fb")
    out["mldv1_done"] = e() / v6(dst="ff02::2", hlim=1) / ICMPv6MLDone(mladdr="ff02::fb")
    out["mldv1_query"] = e() / v6(hlim=1) / ICMPv6MLQuery(mladdr="::")

    # --- IGMP --------------------------------------------------------------
    out["igmpv3_report"] = (e(dst="01:00:5e:00:00:16") / v4(dst="224.0.0.22", ttl=1)
        / IGMPv3(type=0x22) / IGMPv3mr(records=[IGMPv3gr(rtype=4, maddr="224.0.0.251"),
                                               IGMPv3gr(rtype=3, maddr="239.1.1.1",
                                                        srcaddrs=["192.168.1.9"])]))
    out["igmpv3_query"] = (e(dst="01:00:5e:00:00:01") / v4(ttl=1)
        / IGMPv3(type=0x11, mrcode=100) / IGMPv3mq(gaddr="0.0.0.0", qrv=2, qqic=125))
    out["igmpv2_report"] = e(dst="01:00:5e:00:00:fb") / v4(dst="224.0.0.251", ttl=1) / IGMP(type=0x16, gaddr="224.0.0.251")
    out["igmpv1_report"] = e(dst="01:00:5e:00:00:fb") / v4(dst="224.0.0.251", ttl=1) / IGMP(type=0x12, gaddr="224.0.0.251")
    out["igmpv2_query"] = e(dst="01:00:5e:00:00:01") / v4(ttl=1) / IGMP(type=0x11, gaddr="0.0.0.0")

    # --- mDNS / DNS-SD / LLMNR --------------------------------------------
    inst = "printer._ipp._tcp.local"
    out["mdns_dnssd"] = (e(dst="33:33:00:00:00:fb") / v6(dst="ff02::fb", hlim=255)
        / UDP(sport=5353, dport=5353)
        / DNS(qr=1, aa=1, an=[
            DNSRR(rrname="_services._dns-sd._udp.local", type="PTR", rdata="_ipp._tcp.local"),
            DNSRR(rrname="_ipp._tcp.local", type="PTR", rdata=inst),
            DNSRRSRV(rrname=inst, port=631, target="printer.local"),
            DNSRR(rrname=inst, type="TXT", rdata=[b"ty=Printer", b"rp=ipp/print"]),
            DNSRR(rrname="printer.local", type="AAAA", rdata=GUA),
            DNSRR(rrname="printer.local", type="A", rdata="192.168.1.9")]))
    out["mdns_query"] = (e(dst="33:33:00:00:00:fb") / v6(dst="ff02::fb", hlim=255)
        / UDP(sport=5353, dport=5353) / DNS(qr=0, qd=DNSQR(qname="printer.local", qtype="ALL")))
    out["llmnr_response"] = (e(dst="01:00:5e:00:00:fc") / v4(dst="224.0.0.252", ttl=1)
        / UDP(sport=5355, dport=5355)
        / LLMNRResponse(qd=DNSQR(qname="host.local"),
                        an=DNSRR(rrname="host.local", type="A", rdata="192.168.1.9")))
    out["llmnr_query"] = (e(dst="01:00:5e:00:00:fc") / v4(dst="224.0.0.252", ttl=1)
        / UDP(sport=5355, dport=5355) / LLMNRQuery(qd=DNSQR(qname="host.local")))

    # --- Node Information Queries -----------------------------------------
    out["ni_reply_name"] = e(dst=MAC) / IPv6(src=LL, dst="fe80::2", hlim=255) / ICMPv6NIReplyName(qtype=2, nonce=b"12345678", data=[120, "host.local"])
    out["ni_reply_v6"] = e(dst=MAC) / IPv6(src=LL, dst="fe80::2", hlim=255) / ICMPv6NIReplyIPv6(qtype=3, nonce=b"12345678", data=[(120, GUA)])
    out["ni_reply_v4"] = e(dst=MAC) / IPv6(src=LL, dst="fe80::2", hlim=255) / ICMPv6NIReplyIPv4(qtype=4, nonce=b"12345678", data=[(120, "192.168.1.9")])
    out["ni_query"] = e(dst=MAC) / IPv6(src=LL, dst="fe80::2", hlim=255) / ICMPv6NIQueryName(qtype=2, nonce=b"12345678", data="host.local")

    # --- DHCPv4 / DHCPv6 ---------------------------------------------------
    out["dhcp_offer"] = (e(dst="ff:ff:ff:ff:ff:ff") / IP(src="192.168.1.1", dst="255.255.255.255")
        / UDP(sport=67, dport=68)
        / BOOTP(op=2, yiaddr="192.168.1.50", siaddr="192.168.1.1")
        / DHCP(options=[("message-type", 2), ("server_id", "192.168.1.1"),
                        ("subnet_mask", "255.255.255.0"), ("router", "192.168.1.1"),
                        ("name_server", "192.168.1.1"), ("domain", "lan.example.com"),
                        ("lease_time", 86400), "end"]))
    out["dhcp_discover"] = (e(dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=68, dport=67) / BOOTP(op=1) / DHCP(options=[("message-type", 1), "end"]))
    out["dhcp6_advertise"] = (e() / v6(dst="fe80::2") / UDP(sport=547, dport=546)
        / DHCP6_Advertise(trid=0x112233)
        / DHCP6OptClientId(duid=DUID_LLT(lladdr=MAC))
        / DHCP6OptServerId(duid=DUID_LLT(lladdr="aa:bb:cc:00:00:02"))
        / DHCP6OptDNSServers(dnsservers=["2001:db8::53"])
        / DHCP6OptDNSDomains(dnsdomains=["lan.example.com."]))
    out["dhcp6_request"] = (e() / v6(dst="ff02::1:2") / UDP(sport=546, dport=547)
        / DHCP6_Request(trid=0x445566)
        / DHCP6OptIA_NA(iaid=1, ianaopts=[DHCP6OptIAAddress(addr=GUA, preflft=100, validlft=200)]))
    out["dhcp6_inforeq"] = e() / v6(dst="ff02::1:2") / UDP(sport=546, dport=547) / DHCP6_InfoRequest(trid=0x778899)
    out["dhcp6_reply"] = (e() / v6(dst="fe80::2") / UDP(sport=547, dport=546)
        / DHCP6_Reply(trid=0x112233) / DHCP6OptDNSServers(dnsservers=["2001:db8::53"]))

    # --- EAP / 802.1x ------------------------------------------------------
    out["eapol_start"] = Ether(src=MAC, dst="01:80:c2:00:00:03") / EAPOL(version=1, type=1)
    out["eap_request"] = Ether(src=MAC, dst="01:80:c2:00:00:03") / EAPOL(version=1, type=0) / EAP(code=1, id=1, type=1)

    # --- WS-Discovery / SSDP ----------------------------------------------
    out["wsd"] = (e(dst="33:33:00:00:00:0c") / v6(dst="ff02::c", hlim=1) / UDP(sport=3702, dport=3702)
        / Raw(load=b'<?xml version="1.0"?><soap:Envelope/>'))
    out["ssdp"] = (e(dst="01:00:5e:7f:ff:fa") / v4(dst="239.255.255.250", ttl=1) / UDP(sport=1900, dport=1900)
        / Raw(load=b"NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n\r\n"))

    # --- odd framings ------------------------------------------------------
    out["vlan_ipv6"] = e() / Dot1Q(vlan=10) / v6(hlim=255) / ICMPv6ND_RA()
    out["qinq_ipv6"] = e() / Dot1Q(vlan=10) / Dot1Q(vlan=20) / v6(hlim=255) / ICMPv6EchoRequest()
    out["dot3_snap_ipv6"] = Dot3(src=MAC, dst="33:33:00:00:00:01") / LLC() / SNAP(code=0x86DD) / v6(hlim=255) / ICMPv6EchoRequest()
    out["stp"] = Dot3(src=MAC, dst="01:80:c2:00:00:00") / LLC() / STP()
    out["dot11_ipv4"] = Dot11(type=2, addr1="11:11:11:11:11:11", addr2=MAC, addr3="33:33:33:33:33:33") / LLC() / SNAP(code=0x0800) / v4(dst="192.168.1.9") / ICMP()

    # --- plain traffic ------------------------------------------------------
    out["echo_reply"] = e(dst=MAC) / IPv6(src=LL, dst="fe80::2", hlim=64) / ICMPv6EchoReply()
    out["arp_reply"] = e(dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, psrc="192.168.1.9", hwsrc=MAC, pdst="192.168.1.1", hwdst="ff:ff:ff:ff:ff:ff")
    out["tcp"] = e(dst=MAC) / IPv6(src=LL, dst="fe80::2", hlim=64) / TCP(flags="SA")
    out["icmpv6_err"] = e(dst=MAC) / IPv6(src=LL, dst="fe80::2", hlim=64) / ICMPv6DestUnreach() / IPv6(src="fe80::2", dst=LL) / UDP()

    return {k: (bytes(v), v.__class__) for k, v in out.items()}
