from src.send_ipv6 import SendIPv6
from src.send_ipv6_dev import SendIPv6Dev

int = "eth0"

# ICMPv6 Echo Request
#SendIPv6.send_normal_multicast_ping(int)
# HBH 128 Error
#SendIPv6.send_invalid_multicast_icmpv6(int)
# HBH 128 Error
#SendIPv6.send_invalid_multicast_ping(int)
# X
#SendIPv6.send_invalid_ipv6_hbh(int)

SendIPv6Dev.send_empty_ipv6_hbhopt(int)
SendIPv6Dev.send_empty_ipv6_dstopt(int)

SendIPv6.send_normal_multicast_ping(int)

SendIPv6Dev.send_icmpv6_ping_hbhopt(int)
# |=> SendIPv6.send_invalid_ipv6_hbh

SendIPv6Dev.send_icmpv6_ping_dstopt(int)
# |=> SendIPv6.send_invalid_multicast_ping

SendIPv6Dev.send_invalid_ipv6_nh_hbhopt(int)
SendIPv6Dev.send_invalid_ipv6_nh_dstopt(int)
SendIPv6Dev.send_invalid_icmpv6_ipv6_hbhopt(int)
SendIPv6Dev.send_invalid_icmpv6_ipv6_dstopt(int)
# |=> SendIPv6.send_invalid_multicast_icmpv6

SendIPv6Dev.send_ssdp_msearch_ipv6(int)
SendIPv6Dev.send_coap_discovery_ipv6(int)