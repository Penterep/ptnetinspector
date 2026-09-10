"""Structure-aware adversarial frames.

Byte-level mutation rarely lands on a self-describing count or length field
with a valid checksum around it. These are built to lie in exactly the places
the H1 defect lived: a record count larger than the records present, an option
length of zero, a name length that runs past the buffer.
"""
import signal
import sys
import tempfile
import traceback
from pathlib import Path
import os

REPO = Path(os.environ.get("PTNET_REPO", Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(REPO))
sys.path.insert(1, str(Path(__file__).parent))

import ptnetinspector.utils.path as pathmod
TMP = Path(tempfile.mkdtemp(prefix="fuzz-struct-"))
pathmod.get_output_dir = lambda base_path=None: TMP

from scapy.all import *
from scapy.layers.l2 import ARP, Dot1Q, Dot3, LLC, SNAP
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dhcp6 import *
from scapy.layers.inet6 import *
from scapy.contrib.igmp import IGMP
from scapy.contrib.igmpv3 import IGMPv3, IGMPv3gr, IGMPv3mq, IGMPv3mr
from scapy.layers.llmnr import LLMNRResponse

from ptnetinspector.utils.csv_helpers import create_csv
from ptnetinspector.utils.path import set_current_interface
from ptnetinspector import scan as scanmod
from ptnetinspector.scan import Save
from ptnetinspector.send.send import IPMode

conf.verb = 0
SCANNER_MAC = "ff:ff:ff:ff:ff:ff"
scanmod.get_if_hwaddr = lambda _i: SCANNER_MAC
set_current_interface("fuzz")
create_csv("fuzz")

MAC = "aa:bb:cc:00:00:01"
LL = "fe80::1"
E = lambda dst="33:33:00:00:00:01": Ether(src=MAC, dst=dst)
V6 = lambda dst="ff02::1", **kw: IPv6(src=LL, dst=dst, **kw)
V4 = lambda dst="224.0.0.1", **kw: IP(src="192.168.1.1", dst=dst, **kw)


def cases():
    c = {}

    # --- lying record / group counts (the original H1) --------------------
    for n in (0, 1, 200, 255, 65535):
        c[f"mldv2_records_number={n}"] = (E() / V6(dst="ff02::16", hlim=1)
            / ICMPv6MLReport2(records_number=n,
                              records=[ICMPv6MLDMultAddrRec(dst="ff02::fb", rtype=4)]))
        c[f"igmpv3_numgrp={n}"] = (E("01:00:5e:00:00:16") / V4(dst="224.0.0.22", ttl=1)
            / IGMPv3(type=0x22) / IGMPv3mr(numgrp=n, records=[IGMPv3gr(rtype=4, maddr="224.0.0.251")]))
    c["mldv2_no_records_high_count"] = (E() / V6(dst="ff02::16", hlim=1)
        / ICMPv6MLReport2(records_number=255, records=[]))
    c["igmpv3_no_records_high_count"] = (E("01:00:5e:00:00:16") / V4(dst="224.0.0.22", ttl=1)
        / IGMPv3(type=0x22) / IGMPv3mr(numgrp=255, records=[]))
    c["mldv2_rec_sources_number_lies"] = (E() / V6(dst="ff02::16", hlim=1)
        / ICMPv6MLReport2(records=[ICMPv6MLDMultAddrRec(dst="ff02::fb", rtype=4,
                                                       sources_number=255, sources=["2001:db8::9"])]))
    c["igmpv3_rec_numsrc_lies"] = (E("01:00:5e:00:00:16") / V4(dst="224.0.0.22", ttl=1)
        / IGMPv3(type=0x22) / IGMPv3mr(records=[IGMPv3gr(rtype=4, maddr="239.1.1.1",
                                                         numsrc=255, srcaddrs=["192.168.1.9"])]))

    # --- lying DNS counts -------------------------------------------------
    rr = DNSRR(rrname="host.local", type="A", rdata="192.168.1.9")
    for n in (0, 1, 255, 65535):
        c[f"mdns_ancount={n}"] = (E("33:33:00:00:00:fb") / V6(dst="ff02::fb", hlim=255)
            / UDP(sport=5353, dport=5353) / DNS(qr=1, aa=1, ancount=n, an=[rr]))
        c[f"llmnr_ancount={n}"] = (E("01:00:5e:00:00:fc") / V4(dst="224.0.0.252", ttl=1)
            / UDP(sport=5355, dport=5355) / LLMNRResponse(ancount=n, an=[rr]))
    c["mdns_arcount_lies"] = (E("33:33:00:00:00:fb") / V6(dst="ff02::fb", hlim=255)
        / UDP(sport=5353, dport=5353) / DNS(qr=1, aa=1, arcount=255, ar=[rr]))
    c["mdns_no_answers_high_count"] = (E("33:33:00:00:00:fb") / V6(dst="ff02::fb", hlim=255)
        / UDP(sport=5353, dport=5353) / DNS(qr=1, aa=1, ancount=255))

    # --- ND options: zero length is the classic infinite loop -------------
    for optlen in (0, 1, 255):
        c[f"ra_opt_len={optlen}"] = (E() / V6(hlim=255) / ICMPv6ND_RA()
            / ICMPv6NDOptSrcLLAddr(len=optlen, lladdr=MAC))
        c[f"ra_prefixinfo_len={optlen}"] = (E() / V6(hlim=255) / ICMPv6ND_RA()
            / ICMPv6NDOptPrefixInfo(len=optlen, prefix="2001:db8::", prefixlen=64))
    c["ra_unknown_option_type"] = (E() / V6(hlim=255) / ICMPv6ND_RA()
        / Raw(load=bytes([253, 1, 0, 0, 0, 0, 0, 0])))
    c["ra_option_truncated"] = (E() / V6(hlim=255) / ICMPv6ND_RA() / Raw(load=bytes([3, 4, 64])))
    c["ra_prefixlen_129"] = (E() / V6(hlim=255) / ICMPv6ND_RA()
        / ICMPv6NDOptPrefixInfo(prefix="2001:db8::", prefixlen=129))
    c["ra_prefixlen_255"] = (E() / V6(hlim=255) / ICMPv6ND_RA()
        / ICMPv6NDOptPrefixInfo(prefix="2001:db8::", prefixlen=255))
    c["ra_rdnss_empty"] = E() / V6(hlim=255) / ICMPv6ND_RA() / ICMPv6NDOptRDNSS(dns=[])
    c["ra_dnssl_empty"] = E() / V6(hlim=255) / ICMPv6ND_RA() / ICMPv6NDOptDNSSL(searchlist=[])
    c["ra_dnssl_huge"] = (E() / V6(hlim=255) / ICMPv6ND_RA()
        / ICMPv6NDOptDNSSL(searchlist=["a" * 63 + "." + "b" * 63 + "."] * 4))
    c["ra_routeinfo_plen_255"] = (E() / V6(hlim=255) / ICMPv6ND_RA()
        / ICMPv6NDOptRouteInfo(prefix="2001:db8::", plen=255))
    c["ra_captive_portal_empty"] = E() / V6(hlim=255) / ICMPv6ND_RA() / ICMPv6NDOptCaptivePortal(URI=b"")
    c["ra_captive_portal_binary"] = (E() / V6(hlim=255) / ICMPv6ND_RA()
        / ICMPv6NDOptCaptivePortal(URI=bytes(range(256))))
    c["ra_50_prefixes"] = (E() / V6(hlim=255) / ICMPv6ND_RA()
        / functools_reduce([ICMPv6NDOptPrefixInfo(prefix=f"2001:db8:{i:x}::", prefixlen=64) for i in range(50)]))

    # --- Node Information -------------------------------------------------
    c["ni_reply_empty_data"] = E(MAC) / IPv6(src=LL, dst="fe80::2", hlim=255) / ICMPv6NIReplyName(qtype=2, nonce=b"12345678", data=b"")
    c["ni_reply_binary_name"] = E(MAC) / IPv6(src=LL, dst="fe80::2", hlim=255) / ICMPv6NIReplyName(qtype=2, nonce=b"12345678", data=[0, bytes(range(64))])
    c["ni_reply_nul_name"] = E(MAC) / IPv6(src=LL, dst="fe80::2", hlim=255) / ICMPv6NIReplyName(qtype=2, nonce=b"12345678", data=[0, b"a\x00b\x00c"])
    c["ni_reply_long_name"] = E(MAC) / IPv6(src=LL, dst="fe80::2", hlim=255) / ICMPv6NIReplyName(qtype=2, nonce=b"12345678", data=[0, b".".join([b"x" * 60] * 8)])
    c["ni_reply_v6_empty"] = E(MAC) / IPv6(src=LL, dst="fe80::2", hlim=255) / ICMPv6NIReplyIPv6(qtype=3, nonce=b"12345678", data=[])
    c["ni_reply_v6_many"] = E(MAC) / IPv6(src=LL, dst="fe80::2", hlim=255) / ICMPv6NIReplyIPv6(qtype=3, nonce=b"12345678", data=[(0, f"2001:db8::{i:x}") for i in range(60)])
    c["ni_reply_code_nonzero"] = E(MAC) / IPv6(src=LL, dst="fe80::2", hlim=255) / ICMPv6NIReplyName(qtype=2, code=1, nonce=b"12345678", data=[0, b"host"])

    # --- DHCPv4 -----------------------------------------------------------
    c["dhcp_no_options"] = (E("ff:ff:ff:ff:ff:ff") / IP(src="192.168.1.1", dst="255.255.255.255")
        / UDP(sport=67, dport=68) / BOOTP(op=2) / DHCP(options=[]))
    c["dhcp_only_end"] = (E("ff:ff:ff:ff:ff:ff") / IP(src="192.168.1.1", dst="255.255.255.255")
        / UDP(sport=67, dport=68) / BOOTP(op=2) / DHCP(options=["end"]))
    c["dhcp_pad_first"] = (E("ff:ff:ff:ff:ff:ff") / IP(src="192.168.1.1", dst="255.255.255.255")
        / UDP(sport=67, dport=68) / BOOTP(op=2) / DHCP(options=["pad", "pad", ("message-type", 2), "end"]))
    c["dhcp_message_type_last"] = (E("ff:ff:ff:ff:ff:ff") / IP(src="192.168.1.1", dst="255.255.255.255")
        / UDP(sport=67, dport=68) / BOOTP(op=2)
        / DHCP(options=[("server_id", "192.168.1.1"), ("domain", "x"), ("message-type", 5), "end"]))
    for mt in (0, 6, 7, 8, 200, 255):
        c[f"dhcp_message_type={mt}"] = (E("ff:ff:ff:ff:ff:ff") / IP(src="192.168.1.1", dst="255.255.255.255")
            / UDP(sport=67, dport=68) / BOOTP(op=2) / DHCP(options=[("message-type", mt), "end"]))
    c["dhcp_raw_garbage_options"] = (E("ff:ff:ff:ff:ff:ff") / IP(src="192.168.1.1", dst="255.255.255.255")
        / UDP(sport=67, dport=68) / BOOTP(op=2) / Raw(load=b"\x63\x82\x53\x63" + bytes(range(64))))

    # --- DHCPv6 -----------------------------------------------------------
    c["dhcp6_advertise_no_opts"] = E() / V6(dst="fe80::2") / UDP(sport=547, dport=546) / DHCP6_Advertise(trid=1)
    c["dhcp6_request_no_ia"] = E() / V6(dst="ff02::1:2") / UDP(sport=546, dport=547) / DHCP6_Request(trid=1)
    c["dhcp6_ia_no_address"] = (E() / V6(dst="ff02::1:2") / UDP(sport=546, dport=547)
        / DHCP6_Request(trid=1) / DHCP6OptIA_NA(iaid=1, ianaopts=[]))
    c["dhcp6_reply_truncated_opts"] = (E() / V6(dst="fe80::2") / UDP(sport=547, dport=546)
        / DHCP6_Reply(trid=1) / Raw(load=bytes([0, 23, 0, 200]) + b"\x00" * 4))
    c["dhcp6_dns_empty"] = (E() / V6(dst="fe80::2") / UDP(sport=547, dport=546)
        / DHCP6_Reply(trid=1) / DHCP6OptDNSServers(dnsservers=[]))
    c["dhcp6_domains_binary"] = (E() / V6(dst="fe80::2") / UDP(sport=547, dport=546)
        / DHCP6_Reply(trid=1) / Raw(load=bytes([0, 24, 0, 8]) + b"\xff\xfe\x00\x01\x02\x03\x04\x05"))
    c["dhcp6_inforeq_from_server_port"] = E() / V6(dst="ff02::1:2") / UDP(sport=547, dport=547) / DHCP6_InfoRequest(trid=1)
    c["udp547_raw_type11"] = E() / V6(dst="fe80::2") / UDP(sport=546, dport=547) / Raw(load=b"\x0b\x01\x02\x03")
    c["udp547_raw_empty"] = E() / V6(dst="fe80::2") / UDP(sport=546, dport=547) / Raw(load=b"")

    # --- addresses / IIDs that break parsing ------------------------------
    c["src_unspecified"] = E() / IPv6(src="::", dst="ff02::1", hlim=255) / ICMPv6ND_NA(tgt="::")
    c["na_tgt_unspecified"] = E() / V6(hlim=255) / ICMPv6ND_NA(tgt="::")
    c["na_tgt_multicast"] = E() / V6(hlim=255) / ICMPv6ND_NA(tgt="ff02::1")
    c["ns_tgt_multicast"] = E() / V6(hlim=255) / ICMPv6ND_NS(tgt="ff02::1")
    c["mld_group_unicast"] = E() / V6(dst="ff02::16", hlim=1) / ICMPv6MLReport2(records=[ICMPv6MLDMultAddrRec(dst="2001:db8::9", rtype=4)])
    c["igmp_group_unicast"] = E("01:00:5e:00:00:16") / V4(dst="224.0.0.22", ttl=1) / IGMPv3(type=0x22) / IGMPv3mr(records=[IGMPv3gr(rtype=4, maddr="8.8.8.8")])
    c["arp_psrc_broadcast"] = E("ff:ff:ff:ff:ff:ff") / ARP(op=2, psrc="255.255.255.255", hwsrc=MAC)
    c["arp_psrc_zero"] = E("ff:ff:ff:ff:ff:ff") / ARP(op=2, psrc="0.0.0.0", hwsrc=MAC)

    # --- layer stacking abuse ---------------------------------------------
    c["nested_ipv6"] = E() / V6(hlim=255) / IPv6(src="fe80::2", dst="ff02::1") / ICMPv6ND_RA()
    c["ipv6_in_ipv4"] = E() / V4(dst="192.168.1.9") / IPv6(src=LL, dst="ff02::1") / ICMPv6ND_RA()
    c["two_ra_in_one"] = E() / V6(hlim=255) / ICMPv6ND_RA() / ICMPv6ND_RA()
    c["ra_then_na"] = E() / V6(hlim=255) / ICMPv6ND_RA() / ICMPv6ND_NA(tgt=LL)
    c["hopbyhop_chain"] = E() / V6(hlim=255) / IPv6ExtHdrHopByHop() / IPv6ExtHdrHopByHop() / ICMPv6ND_RA()
    c["fragmented_nd"] = E() / V6(hlim=255) / IPv6ExtHdrFragment(offset=0, m=1, id=1) / ICMPv6ND_RA()
    c["routing_hdr"] = E() / V6(hlim=255) / IPv6ExtHdrRouting() / ICMPv6ND_RA()
    c["ten_vlan_tags"] = E() / functools_reduce([Dot1Q(vlan=i) for i in range(10)]) / V6(hlim=255) / ICMPv6ND_RA()

    # --- empty / minimal --------------------------------------------------
    c["ether_only"] = E()
    c["ether_empty_src"] = Ether(src="00:00:00:00:00:00", dst="00:00:00:00:00:00")
    c["ipv6_no_payload"] = E() / V6(hlim=255)
    c["ipv4_no_payload"] = E() / V4(dst="192.168.1.9")
    c["udp_no_payload"] = E() / V6(hlim=255) / UDP(sport=5353, dport=5353)
    return c


def functools_reduce(layers):
    out = layers[0]
    for l in layers[1:]:
        out = out / l
    return out


class Timeout(Exception):
    pass


def _alarm(_sig, _frm):
    raise Timeout("parse did not finish in 5s")


def main():
    signal.signal(signal.SIGALRM, _alarm)
    built = failed_build = 0
    problems = []

    for name, packet in cases().items():
        try:
            raw = bytes(packet)
            parsed = packet.__class__(raw)
            repr(parsed)
        except Exception as exc:
            failed_build += 1
            print(f"  build/dissect failed (scapy, not the tool): {name}: {type(exc).__name__}")
            continue
        built += 1

        for label, call in (("save_async", lambda p=parsed: Save.save_async([p])),
                            ("save_packets", lambda p=parsed: Save.save_packets("fuzz", IPMode(True, True), [p]))):
            signal.alarm(5)
            try:
                call()
            except Timeout as exc:
                problems.append((name, label, "HANG", str(exc), ""))
            except Exception as exc:
                tb = traceback.extract_tb(exc.__traceback__)
                ours = [f for f in tb if "ptnetinspector" in f.filename]
                site = ours[-1] if ours else tb[-1]
                problems.append((name, label, type(exc).__name__, str(exc)[:160],
                                 f"{Path(site.filename).name}:{site.lineno} in {site.name}"))
            finally:
                signal.alarm(0)

    print(f"\n{built} adversarial frames fed ({failed_build} rejected by scapy itself)")
    if not problems:
        print("no crashes, no hangs")
        return 0
    print(f"{len(problems)} problem(s):\n")
    seen = set()
    for name, label, kind, msg, where in problems:
        key = (kind, where)
        marker = "" if key in seen else "  <-- new site"
        seen.add(key)
        print(f"  {kind:12s} {name}  (via {label}){marker}")
        print(f"       {where}")
        print(f"       {msg}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
