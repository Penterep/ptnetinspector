## Multicast management

### MLD

|Protocol|Message|Filter|
|---|---|---|
|MLDv2|Multicast Listener Query|`icmpv6.mld.flag == 0x02`|
|MLDv2|Multicast Listener Report|`icmpv6.type == 143`|
|MLDv2|Multicast Listener Report (join)|`icmpv6.mldr.mar.record_type == 2 \|\| icmpv6.mldr.mar.record_type == 4`|
|MLDv2|Multicast Listener Report (leave)|`icmpv6.mldr.mar.record_type == 1 \|\| icmpv6.mldr.mar.record_type == 3`|
|MLDv1|Multicast Listener Query|`icmpv6.type == 130 && !icmpv6.mld.flag`|
|MLDv1|Multicast Listener Report|`icmpv6.type == 131`|

### IGMP
|Protocol|Message|Filter|
|---|---|---|
|IGMPv3|All|`igmp.version == 3`|
|IGMPv3|Membership Query|`igmp.type == 0x11 and len(igmp) == 12`|
|IGMPv3|Membership Report|`igmp.type == 0x22`|
|IGMPv2|All|`igmp.version == 2`|
|IGMPv2|Membership Query|`igmp.type == 0x11 && len(igmp) == 8 && igmp.max_resp == 2`|
|IGMPv2|Membership Report|`igmp.type == 0x16`|
|IGMPv1|All|`igmp.version == 1`|
|IGMPv1|Membership Query|`igmp.type == 0x11 && !igmp.max_resp`|
|IGMPv1|Membership Report|`igmp.type == 0x12`|

## Multicast discovery

### IPv6 Multicast discovery

|Test|Message|Filter|
|---|---|---|
|6-MULTIECHO|Request|`icmpv6.type == 128 && !ipv6.dstopts && !ipv6.hopopts && ipv6.dst == ff02::1`|
|6-MULTIECHO|Response|`icmpv6.type == 129 && !icmpv6.resp_to`|
|6-INVEMPTYDO|Multicast request|`ipv6.opt.type == 0x80 && ipv6.dstopts && !icmpv6`|
|6-INVEMPTYDO|Multicast response|`ipv6.opt.type == 0x80 && ipv6.dstopts && icmpv6.type == 4 && !icmpv6.type == 128 && !icmpv6.type == 254`|
|6-INVEMPTYHBH|Multicast request|`ipv6.opt.type == 0x80 && ipv6.hopopts && !icmpv6`|
|6-INVEMPTYHBH|Multicast response|`ipv6.opt.type == 0x80 && ipv6.hopopts && icmpv6.type == 4 && !icmpv6.type == 128 && !icmpv6.type == 254`|
|6-INVPACKET|Multicast request|`icmpv6.type == 254 && ipv6.opt.type == 0x80 && !icmpv6.type == 4`|
|6-INVPACKET|Multicast response|`icmpv6.type == 254 && ipv6.opt.type == 0x80 && icmpv6.type == 4`|
|6-INVECHODO|Multicast request|`icmpv6.type == 128 && ipv6.opt.type == 0x80 && ipv6.dstopts && !icmpv6.type == 4`|
|6-INVECHODO|Multicast response|`icmpv6.type == 128 && ipv6.opt.type == 0x80 && ipv6.dstopts && icmpv6.type == 4`|
|6-INVECHOHBH|Multicast request|`icmpv6.type == 128 && ipv6.opt.type == 0x80 && ipv6.hopopts && !icmpv6.type == 4`|
|6-INVECHOHBH|Multicast response|`icmpv6.type == 128 && ipv6.opt.type == 0x80 && ipv6.hopopts && icmpv6.type == 4`|
|-|Router solicitation|`icmpv6.type == 133`|
|-|Router advertisement|`icmpv6.type == 134`|

### IPv4 Multicast discovery
|Test|Message|Filter|
|---|---|---|
|4-MULTIECHO|Request|`icmp.type == 8 && ip.dst == 224.0.0.1`|
|4-MULTIECHO|Response|`icmp.type == 0 && icmp.resp_to`|
|4-BRCASTECHO|Request|`icmp.type == 8 && !ip.dst == 224.0.0.1`|
|4-BRCASTECHO|Response|`icmp.type == 0 && !icmp.resp_to`|
|-|Router solicitation|`icmp.type == 10`|
|-|Router advertisement|`icmp.type == 9`|
|4-INVPACKET|Request|`icmp.type == 255`|

## Unicast tests

### IPv6 Unicast tests

|Test|Message|Filter|
|---|---|---|
|6-INVEMPTYDO|Multicast request|`ipv6.opt.type == 0xc0 && ipv6.dstopts && !icmpv6`|
|6-INVEMPTYDO|Multicast response|`ipv6.opt.type == 0xc0 && ipv6.dstopts && icmpv6.type == 4 && !icmpv6.type == 128 && !icmpv6.type == 254`|
|6-INVEMPTYHBH|Multicast request|`ipv6.opt.type == 0xc0 && ipv6.hopopts && !icmpv6`|
|6-INVEMPTYHBH|Multicast response|`ipv6.opt.type == 0xc0 && ipv6.hopopts && icmpv6.type == 4 && !icmpv6.type == 128 && !icmpv6.type == 254`|
|6-INVPACKET|Multicast request|`icmpv6.type == 254 && ipv6.opt.type == 0xc0 && !icmpv6.type == 4`|
|6-INVPACKET|Multicast response|`icmpv6.type == 254 && ipv6.opt.type == 0xc0 && icmpv6.type == 4`|
|6-INVECHODO|Multicast request|`icmpv6.type == 128 && ipv6.opt.type == 0xc0 && ipv6.dstopts && !icmpv6.type == 4`|
|6-INVECHODO|Multicast response|`icmpv6.type == 128 && ipv6.opt.type == 0xc0 && ipv6.dstopts && icmpv6.type == 4`|
|6-INVECHOHBH|Multicast request|icmpv6.type == 128 && ipv6.opt.type == 0xc0 && ipv6.hopopts && !icmpv6.type == 4|
|6-INVECHOHBH|Multicast response|`icmpv6.type == 128 && ipv6.opt.type == 0xc0 && ipv6.hopopts && icmpv6.type == 4`|
|-|Neighbor Solicitation|icmpv6.type == 135|
|-|Neighbor Advertisement|`icmpv6.type == 136`|

Note: Neighbor Solicitation is done for default gateway and first two addresses and last address in the available subnets (including link-local fe80::/64)

### IPv4 Unicast tests
|Message|Filter|
|---|---|
|Address Resolution Protocol (request)|`arp.opcode == 1`|
|Address Resolution Protocol (reply)|`arp.opcode == 2`|

Note: Address Resolution Protocol (request) is done for default gateway and first two addresses and last address in the available subnets

## Protocol specific tests

### DHCP & DHCPv6

|Protocol|Message|Filter|
|---|---|---|
|DHCPv6|Solicit|`dhcpv6.msgtype == 1`|
|DHCPv6|Advertise|`dhcpv6.msgtype == 2`|
|DHCP|Boot Request|`dhcp.type == 1`|
|DHCP|Boot Reply|`dhcp.type == 2`|

### WS-Discovery

|Message|Filter|
|---|---|
|Probe|`xml.tag ~ "Probe/?>"`|
|Probe match|`xml.tag ~ "ProbeMatches/?>"`|

### Name resolution protocols

|Protocol|Message|Filter|
|---|---|---|
|DNS-SD|Query|`dns.flags.response == False && dns.qry.name == "_services._dns-sd._udp.local"`|
|DNS-SD|Response|`dns.flags.response == True && dns.qry.name == "_services._dns-sd._udp.local"`|
|LLMNR|Query|`llmnr && dns.flags.response == False`|
|LLMNR|Response|`llmnr && dns.flags.response == True`|
|mDNS|Query|`mdns && dns.flags.response == False && dns.qry.name == "_services._dns-sd._udp.local"`|
|mDNS|Response|`mdns && dns.flags.response == True && dns.qry.name == "_services._dns-sd._udp.local"`|

Note: Protocols that support QU bit use both True and False values. Filter by `dns.qry.qu == False` or `dns.qry.qu == True`