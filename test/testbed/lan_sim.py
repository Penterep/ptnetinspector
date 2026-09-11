#!/usr/bin/env python3
"""Simulated LAN for exercising ptnetinspector on a real link.

Runs on the far side of a veth pair and emulates four devices, each with its
own MAC, so a scan sees a plausible dual-stack segment instead of a single
kernel stack:

  * a router that advertises every RA option the scanner now parses,
  * a Windows-ish workstation (hop limit 128) that speaks mDNS and LLMNR,
  * a Raspberry Pi (hop limit 64) that advertises a DNS-SD printer service
    and answers Node Information Queries,
  * a switch/querier that emits MLD and IGMP general queries.

Everything is sent as raw frames, so the kernel in this namespace stays a
fifth, genuinely real host: it does its own DAD, answers NS, and joins
multicast groups in response to the router advertisements.
"""
import argparse
import random
import struct
import threading
import time

from scapy.all import (
    ARP, DHCP, BOOTP, DNS, DNSQR, DNSRR, Ether, IP, IPv6, UDP, Raw,
    conf, sendp, sniff,
)
from scapy.layers.dns import DNSRRSRV
from scapy.layers.inet6 import (
    ICMPv6EchoReply, ICMPv6EchoRequest, ICMPv6MLDMultAddrRec, ICMPv6MLQuery,
    ICMPv6MLQuery2, ICMPv6MLReport2, ICMPv6ND_NA, ICMPv6ND_NS, ICMPv6ND_RA,
    ICMPv6ND_RS, ICMPv6NDOptCaptivePortal, ICMPv6NDOptDNSSL, ICMPv6NDOptMTU,
    ICMPv6NDOptPREF64, ICMPv6NDOptPrefixInfo, ICMPv6NDOptRDNSS,
    ICMPv6NDOptRouteInfo, ICMPv6NDOptDstLLAddr, ICMPv6NDOptSrcLLAddr,
    ICMPv6NIQueryName, ICMPv6NIReplyIPv6, ICMPv6NIReplyName,
)
from scapy.contrib.igmp import IGMP
from scapy.contrib.igmpv3 import IGMPv3, IGMPv3mq, IGMPv3mr, IGMPv3gr

conf.verb = 0

# ---------------------------------------------------------------- inventory --
ROUTER_MAC = "00:50:56:c0:00:02"      # the address from the review document
ROUTER_LL = "fe80::250:56ff:fec0:2"
ROUTER_GUA = "fd00:73::1"
ROUTER_V4 = "192.168.73.1"

WIN_MAC = "08:00:27:aa:bb:01"
WIN_LL = "fe80::a00:27ff:feaa:bb01"
WIN_EUI = "fd00:73::a00:27ff:feaa:bb01"
WIN_PRIV = "fd00:73::7c9e:1f2b:aa31:9d4e"   # stable-privacy style, RFC 7217
WIN_V4 = "192.168.73.20"
WIN_NAME = "desktop-a17kq9"

PI_MAC = "b8:27:eb:11:22:33"
PI_LL = "fe80::ba27:ebff:fe11:2233"
PI_EUI = "fd00:73::ba27:ebff:fe11:2233"
PI_V4 = "192.168.73.31"
PI_NAME = "officeprinter"

SW_MAC = "00:1b:21:33:44:55"
SW_LL = "fe80::21b:21ff:fe33:4455"
SW_V4 = "192.168.73.2"

PREFIX = "fd00:73::"
DNS6 = "fd00:73::53"
DNS4 = "192.168.73.1"
DOMAIN = "lan.example.com"

V6_OWNERS = {
    ROUTER_LL: ROUTER_MAC, ROUTER_GUA: ROUTER_MAC,
    WIN_LL: WIN_MAC, WIN_EUI: WIN_MAC, WIN_PRIV: WIN_MAC,
    PI_LL: PI_MAC, PI_EUI: PI_MAC,
    SW_LL: SW_MAC,
}
V4_OWNERS = {ROUTER_V4: ROUTER_MAC, WIN_V4: WIN_MAC, PI_V4: PI_MAC, SW_V4: SW_MAC}
HOP = {ROUTER_MAC: 64, WIN_MAC: 128, PI_MAC: 64, SW_MAC: 255}

# Generic hosts, added with --extra-hosts, so a scan can be looked at with the
# device count a wifi segment has rather than the four above.
EXTRA = []          # (mac, ll, gua, v4, name)


def add_extra_hosts(count):
    for i in range(1, count + 1):
        mac = "02:00:00:ee:%02x:%02x" % (i // 256, i % 256)
        ll = "fe80::ee:%x" % i
        gua = "fd00:73::ee:%x" % i
        v4 = "192.168.73.%d" % (100 + i) if i <= 150 else "192.168.74.%d" % (i - 150)
        name = "host-%d" % i
        EXTRA.append((mac, ll, gua, v4, name))
        V6_OWNERS[ll] = mac
        V6_OWNERS[gua] = mac
        V4_OWNERS[v4] = mac
        HOP[mac] = 64 if i % 3 else 128

stats = {}
_lock = threading.Lock()


def bump(key):
    with _lock:
        stats[key] = stats.get(key, 0) + 1


def tx(frame, key):
    try:
        sendp(frame, iface=IFACE, verbose=0)
    except Exception as ex:
        bump(f"FAILED {key}: {type(ex).__name__} {ex}")
        return
    bump(key)


def sol_node(addr):
    """Solicited-node multicast address for an IPv6 address."""
    tail = int(__import__("ipaddress").IPv6Address(addr)) & 0xFFFFFF
    return "ff02::1:ff%02x:%04x" % (tail >> 16, tail & 0xFFFF)


def mcast_mac6(addr):
    tail = int(__import__("ipaddress").IPv6Address(addr)) & 0xFFFFFFFF
    return "33:33:%02x:%02x:%02x:%02x" % (
        (tail >> 24) & 0xFF, (tail >> 16) & 0xFF, (tail >> 8) & 0xFF, tail & 0xFF)


# ------------------------------------------------------------------- beacons --
def router_advertisement(dst_mac="33:33:00:00:00:01", dst="ff02::1"):
    """An RA carrying every option the scanner extracts (extension E1)."""
    return (
        Ether(src=ROUTER_MAC, dst=dst_mac)
        / IPv6(src=ROUTER_LL, dst=dst, hlim=255)
        / ICMPv6ND_RA(chlim=64, M=0, O=1, prf=1, routerlifetime=1800,
                      reachabletime=30000, retranstimer=1000)
        / ICMPv6NDOptSrcLLAddr(lladdr=ROUTER_MAC)
        / ICMPv6NDOptMTU(mtu=1500)
        / ICMPv6NDOptPrefixInfo(prefix=PREFIX, prefixlen=64, L=1, A=1,
                                validlifetime=2592000, preferredlifetime=604800)
        / ICMPv6NDOptPrefixInfo(prefix="2001:db8:beef::", prefixlen=64, L=1, A=1,
                                validlifetime=86400, preferredlifetime=3600)
        / ICMPv6NDOptRDNSS(dns=[DNS6, "fd00:73::54"], lifetime=600)
        / ICMPv6NDOptDNSSL(searchlist=[DOMAIN + ".", "corp.example."], lifetime=600)
        / ICMPv6NDOptRouteInfo(prefix="2001:db8:aaaa::", plen=48, prf=1, rtlifetime=1800)
        / ICMPv6NDOptPREF64(prefix="64:ff9b::", scaledlifetime=600, plc=0)
        / ICMPv6NDOptCaptivePortal(URI=b"http://portal.lan.example.com/login")
    )


def mld_report(mac, src_ll, groups):
    recs = [ICMPv6MLDMultAddrRec(dst=g, rtype=4) for g in groups]
    return (Ether(src=mac, dst="33:33:00:00:00:16")
            / IPv6(src=src_ll, dst="ff02::16", hlim=1)
            / ICMPv6MLReport2(records=recs))


def igmpv3_report(mac, src, groups):
    recs = [IGMPv3gr(rtype=4, maddr=g) for g in groups]
    return (Ether(src=mac, dst="01:00:5e:00:00:16")
            / IP(src=src, dst="224.0.0.22", ttl=1)
            / IGMPv3(type=0x22) / IGMPv3mr(records=recs))


def mld_general_query():
    """Querier behaviour the scanner records in querier.csv (extension E6)."""
    return (Ether(src=SW_MAC, dst="33:33:00:00:00:01")
            / IPv6(src=SW_LL, dst="ff02::1", hlim=1)
            / ICMPv6MLQuery2(mladdr="::", mrd=10000, QQIC=125, QRV=2))


def igmp_general_query():
    return (Ether(src=SW_MAC, dst="01:00:5e:00:00:01")
            / IP(src=SW_V4, dst="224.0.0.1", ttl=1)
            / IGMPv3(type=0x11, mrcode=100)
            / IGMPv3mq(gaddr="0.0.0.0", qqic=125, qrv=2))


def mdns_ptr_announce():
    """Unsolicited DNS-SD announcement (extension E2)."""
    svc = "_ipp._tcp.local"
    inst = f"{PI_NAME}._ipp._tcp.local"
    an = [DNSRR(rrname="_services._dns-sd._udp.local", type="PTR", ttl=4500, rdata=svc),
          DNSRR(rrname=svc, type="PTR", ttl=4500, rdata=inst),
          DNSRRSRV(rrname=inst, ttl=120, priority=0, weight=0, port=631,
                   target=f"{PI_NAME}.local"),
          DNSRR(rrname=inst, type="TXT", ttl=4500,
                rdata=[b"ty=HP LaserJet 400", b"rp=ipp/print", b"adminurl=http://officeprinter.local"]),
          DNSRR(rrname=f"{PI_NAME}.local", type="AAAA", ttl=120, rdata=PI_EUI),
          DNSRR(rrname=f"{PI_NAME}.local", type="A", ttl=120, rdata=PI_V4)]
    return (Ether(src=PI_MAC, dst="33:33:00:00:00:fb")
            / IPv6(src=PI_LL, dst="ff02::fb", hlim=255)
            / UDP(sport=5353, dport=5353)
            / DNS(qr=1, aa=1, an=an))


def beacon_loop(duration, stop, interval=2.0):
    """Periodic unsolicited traffic, staggered so nothing arrives in lockstep."""
    end = time.time() + duration
    tick = 0
    while not stop.is_set() and time.time() < end:
      try:
        if tick % 5 == 0:
            tx(router_advertisement(), "RA")
        if tick % 5 == 1:
            tx(mld_report(WIN_MAC, WIN_LL,
                          ["ff02::fb", "ff02::1:3", sol_node(WIN_EUI)]), "MLDv2 report")
            tx(mld_report(PI_MAC, PI_LL, ["ff02::fb", sol_node(PI_EUI)]), "MLDv2 report")
        if tick % 5 == 2:
            tx(mld_general_query(), "MLD query")
            tx(igmp_general_query(), "IGMP query")
        if tick % 5 == 3:
            tx(igmpv3_report(WIN_MAC, WIN_V4, ["224.0.0.251", "224.0.0.252"]), "IGMPv3 report")
            tx(mdns_ptr_announce(), "mDNS announce")
        if EXTRA:
            # A few extra hosts per tick, so discovery does not depend on the
            # scanner catching every one in a single burst.
            start = (tick * 6) % len(EXTRA)
            for mac, ll, gua, v4, name in EXTRA[start:start + 6]:
                tx(mld_report(mac, ll, [sol_node(gua), "ff02::fb"]), "MLDv2 report (extra)")
                tx(Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")
                   / ARP(op=2, psrc=v4, hwsrc=mac, pdst=v4, hwdst=mac), "ARP announce (extra)")
        if tick % 5 == 4:
            # Gratuitous ARP + a NA, so IPv4 and IPv6 device discovery both fire.
            tx(Ether(src=WIN_MAC, dst="ff:ff:ff:ff:ff:ff")
               / ARP(op=2, psrc=WIN_V4, hwsrc=WIN_MAC, pdst=WIN_V4, hwdst=WIN_MAC), "ARP announce")
            tx(Ether(src=PI_MAC, dst="33:33:00:00:00:01")
               / IPv6(src=PI_EUI, dst="ff02::1", hlim=255)
               / ICMPv6ND_NA(tgt=PI_EUI, R=0, S=0, O=1)
               / ICMPv6NDOptDstLLAddr(lladdr=PI_MAC), "unsolicited NA")
      except Exception as ex:
        bump(f"BEACON ERROR: {type(ex).__name__} {ex}")
      tick += 1
      stop.wait(interval)


# ----------------------------------------------------------------- responder --
def dns_name(raw):
    if isinstance(raw, bytes):
        return raw.decode(errors="replace").rstrip(".").lower()
    return str(raw).rstrip(".").lower()


def handle(pkt):
    if Ether not in pkt:
        return
    if pkt[Ether].src in HOP:          # our own emulated traffic
        return

    # --- IPv6 Neighbor Solicitation -> Neighbor Advertisement -----------------
    if ICMPv6ND_NS in pkt:
        tgt = pkt[ICMPv6ND_NS].tgt
        owner = V6_OWNERS.get(tgt)
        if owner and pkt[IPv6].src != "::":
            tx(Ether(src=owner, dst=pkt[Ether].src)
               / IPv6(src=tgt, dst=pkt[IPv6].src, hlim=255)
               / ICMPv6ND_NA(tgt=tgt, R=1 if owner == ROUTER_MAC else 0, S=1, O=1)
               / ICMPv6NDOptDstLLAddr(lladdr=owner), "NA (solicited)")
        return

    # --- Router Solicitation -> unicast RA ------------------------------------
    if ICMPv6ND_RS in pkt:
        dst = pkt[IPv6].src if pkt[IPv6].src != "::" else "ff02::1"
        dmac = pkt[Ether].src if pkt[IPv6].src != "::" else "33:33:00:00:00:01"
        tx(router_advertisement(dst_mac=dmac, dst=dst), "RA (solicited)")
        return

    # --- Node Information Query -> Reply (RFC 4620, extension E4) -------------
    if ICMPv6NIQueryName in pkt:
        q = pkt[ICMPv6NIQueryName]
        qtype = q.qtype
        target = None
        for addr, owner in V6_OWNERS.items():
            if addr == pkt[IPv6].dst:
                target = owner
                break
        if target is None:
            target = PI_MAC          # the Pi answers link-scoped NI queries
        src = PI_LL if target == PI_MAC else [a for a, o in V6_OWNERS.items() if o == target][0]
        name = {PI_MAC: PI_NAME, WIN_MAC: WIN_NAME, ROUTER_MAC: "gw"}.get(target, "node")
        if qtype == 2:               # NI Node Name
            reply = ICMPv6NIReplyName(qtype=2, code=0, nonce=q.nonce, flags=0,
                                      data=[120, f"{name}.local"])
        elif qtype == 3:             # NI Node Addresses
            reply = ICMPv6NIReplyIPv6(qtype=3, code=0, nonce=q.nonce, flags=0,
                                      data=[(120, PI_EUI)] if target == PI_MAC else [(120, WIN_EUI)])
        else:
            reply = ICMPv6NIReplyName(qtype=qtype, code=0, nonce=q.nonce, flags=0, data=b"")
        tx(Ether(src=target, dst=pkt[Ether].src)
           / IPv6(src=src, dst=pkt[IPv6].src, hlim=255) / reply, "NI reply")
        return

    # --- MLD query from the scanner -> reports (extensions E6/E7) -------------
    if ICMPv6MLQuery2 in pkt or ICMPv6MLQuery in pkt:
        tx(mld_report(WIN_MAC, WIN_LL, ["ff02::fb", "ff02::1:3"]), "MLDv2 report (solicited)")
        tx(mld_report(PI_MAC, PI_LL, ["ff02::fb"]), "MLDv2 report (solicited)")
        return

    if IGMPv3mq in pkt or (IGMP in pkt and pkt[IGMP].type == 0x11):
        tx(igmpv3_report(WIN_MAC, WIN_V4, ["224.0.0.251"]), "IGMPv3 report (solicited)")
        return

    # --- ICMPv6 echo (reachability probing) ----------------------------------
    if ICMPv6EchoRequest in pkt:
        owner = V6_OWNERS.get(pkt[IPv6].dst)
        if owner:
            tx(Ether(src=owner, dst=pkt[Ether].src)
               / IPv6(src=pkt[IPv6].dst, dst=pkt[IPv6].src, hlim=HOP[owner])
               / ICMPv6EchoReply(id=pkt[ICMPv6EchoRequest].id,
                                 seq=pkt[ICMPv6EchoRequest].seq), "echo reply")
        return

    # --- ARP who-has ----------------------------------------------------------
    if ARP in pkt and pkt[ARP].op == 1:
        owner = V4_OWNERS.get(pkt[ARP].pdst)
        if owner:
            tx(Ether(src=owner, dst=pkt[Ether].src)
               / ARP(op=2, psrc=pkt[ARP].pdst, hwsrc=owner,
                     pdst=pkt[ARP].psrc, hwdst=pkt[ARP].hwsrc), "ARP reply")
        return

    # --- DHCPv4 discover -> offer (extension E3) ------------------------------
    if DHCP in pkt:
        kinds = [o[1] for o in pkt[DHCP].options
                 if isinstance(o, tuple) and o[0] == "message-type"]
        if kinds and kinds[0] in (1, 3):
            tx(Ether(src=ROUTER_MAC, dst=pkt[Ether].src)
               / IP(src=ROUTER_V4, dst="255.255.255.255")
               / UDP(sport=67, dport=68)
               / BOOTP(op=2, yiaddr="192.168.73.101", siaddr=ROUTER_V4,
                       chaddr=pkt[BOOTP].chaddr, xid=pkt[BOOTP].xid)
               / DHCP(options=[("message-type", 2 if kinds[0] == 1 else 5),
                               ("server_id", ROUTER_V4), ("subnet_mask", "255.255.255.0"),
                               ("router", ROUTER_V4), ("name_server", DNS4),
                               ("domain", DOMAIN), ("lease_time", 86400), "end"]),
               "DHCP offer/ack")
        return

    # --- DHCPv6 Information-Request -> Reply (extension E3) -------------------
    if UDP in pkt and pkt[UDP].dport == 547:
        payload = bytes(pkt[UDP].payload)
        if payload and payload[0] == 11:          # INFORMATION-REQUEST
            xid = payload[1:4]
            opts = b""
            opts += struct.pack("!HH", 23, 16) + __import__("socket").inet_pton(
                __import__("socket").AF_INET6, DNS6)                       # DNS servers
            enc = b"".join(bytes([len(p)]) + p.encode() for p in DOMAIN.split(".")) + b"\x00"
            opts += struct.pack("!HH", 24, len(enc)) + enc                 # domain list
            opts += struct.pack("!HH", 31, 16) + __import__("socket").inet_pton(
                __import__("socket").AF_INET6, "fd00:73::123")             # SNTP
            body = bytes([7]) + xid + opts                                 # REPLY
            tx(Ether(src=ROUTER_MAC, dst=pkt[Ether].src)
               / IPv6(src=ROUTER_LL, dst=pkt[IPv6].src)
               / UDP(sport=547, dport=546) / Raw(load=body), "DHCPv6 reply")
        return

    # --- mDNS / LLMNR / DNS-SD ------------------------------------------------
    if DNS in pkt and UDP in pkt and pkt[UDP].dport in (5353, 5355):
        dnsl = pkt[DNS]
        if dnsl.qr != 0 or not dnsl.qdcount:
            return
        qname = dns_name(dnsl.qd[0].qname)
        is_mdns = pkt[UDP].dport == 5353
        v6 = IPv6 in pkt

        if is_mdns and qname in ("_services._dns-sd._udp.local", "_ipp._tcp.local"):
            tx(mdns_ptr_announce(), "DNS-SD PTR reply")
            return
        if is_mdns and qname.endswith("._tcp.local"):
            tx(mdns_ptr_announce(), "DNS-SD PTR reply")
            return

        for mac, name, v6a, v4a, ll in [
                (WIN_MAC, WIN_NAME, WIN_EUI, WIN_V4, WIN_LL),
                (PI_MAC, PI_NAME, PI_EUI, PI_V4, PI_LL)] + [
                (m, n, g, v, l) for (m, l, g, v, n) in EXTRA]:
            short = name.split(".")[0]
            if qname in (f"{short}.local", short):
                rr = [DNSRR(rrname=dnsl.qd[0].qname, type="AAAA", ttl=120, rdata=v6a),
                      DNSRR(rrname=dnsl.qd[0].qname, type="A", ttl=120, rdata=v4a)]
                l3 = (IPv6(src=ll, dst=pkt[IPv6].src if not is_mdns else "ff02::fb", hlim=255)
                      if v6 else
                      IP(src=v4a, dst=pkt[IP].src if not is_mdns else "224.0.0.251", ttl=255))
                dmac = pkt[Ether].src if not is_mdns else (
                    "33:33:00:00:00:fb" if v6 else "01:00:5e:00:00:fb")
                tx(Ether(src=mac, dst=dmac) / l3
                   / UDP(sport=pkt[UDP].dport, dport=pkt[UDP].dport)
                   / DNS(id=dnsl.id, qr=1, aa=1, an=rr),
                   "mDNS reply" if is_mdns else "LLMNR reply")
                return

        # Anything else: the Windows host answers LLMNR for its own name.
        if not is_mdns:
            rr = DNSRR(rrname=dnsl.qd[0].qname, type="A", ttl=30, rdata=WIN_V4)
            tx(Ether(src=WIN_MAC, dst=pkt[Ether].src)
               / (IPv6(src=WIN_LL, dst=pkt[IPv6].src) if v6 else IP(src=WIN_V4, dst=pkt[IP].src))
               / UDP(sport=5355, dport=pkt[UDP].sport)
               / DNS(id=dnsl.id, qr=1, aa=1, an=rr), "LLMNR reply")


def main():
    global IFACE
    ap = argparse.ArgumentParser()
    ap.add_argument("-i", "--iface", required=True)
    ap.add_argument("-d", "--duration", type=float, default=40.0)
    ap.add_argument("--extra-hosts", type=int, default=0,
                    help="emulate this many additional generic hosts")
    ap.add_argument("--beacon-interval", type=float, default=2.0,
                    help="seconds between beacon ticks; raise it to keep the "
                         "responder idle and quick to answer probes")
    args = ap.parse_args()
    IFACE = args.iface
    add_extra_hosts(args.extra_hosts)

    stop = threading.Event()
    beacon = threading.Thread(target=beacon_loop,
                              args=(args.duration, stop, args.beacon_interval), daemon=True)
    beacon.start()
    print(f"[lan_sim] emulating {4 + len(EXTRA)} devices on {IFACE} for {args.duration}s", flush=True)
    try:
        sniff(iface=IFACE, prn=handle, store=0, timeout=args.duration)
    finally:
        stop.set()
        print("[lan_sim] sent:", flush=True)
        for key in sorted(stats):
            print(f"    {stats[key]:4d}  {key}", flush=True)


if __name__ == "__main__":
    main()
