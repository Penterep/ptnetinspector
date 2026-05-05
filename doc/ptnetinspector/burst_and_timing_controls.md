# Burst and Timing controls
This file states variables and parameters that control specific timing controls and burst sizes.

## Burst limits

|File|Class|Variable|Default value|
|---|---|---|---|
|send/send_ipv4.py|SendIPv4|__ipv4_burst_limit|0|
|send/send_ipv6.py|SendIPv6|__ipv6_burst_limit|0|
|utils/address_control.py|AddressValidator|__max_concurrency|16|

## Timeouts

|File|Class|Function|Parameter|Default value|
|---|---|---|---|---|
|entities/node.py|Node|get_ipv4_route_metrics_and_addresses|timeout|10.0|
|entities/node.py|Node|get_ipv6_route_metrics_and_addresses|timeout|10.0|
|send/send_ipv4.py|SendIPv4|send_arp_request|rsp_timeout|0.1|
|send/send_ipv4.py|SendIPv4|send_reverse_ipv4_llmnr_batch|rsp_timeout|0.2|
|send/send_ipv4.py|SendIPv4|send_reverse_ipv4_MDNS_batch|rsp_timeout|0.2|
|send/send_ipv6.py|SendIPv6|send_ns|rsp_timeout|0.1|
|send/send_ipv6.py|SendIPv6|send_reverse_ipv6_llmnr_batch|rsp_timeout|0.2|
|send/send_ipv6.py|SendIPv6|send_reverse_ipv6_MDNS_batch|rsp_timeout|0.2|
|utils/address_control.py|AddressValidator|-|__timeout|0.2|

## Timings

|File|Class|Function|Parameter/Variable|Default value|
|---|---|---|---|---|
|send/send_ipv4.py|SendIPv4|react_to_igmp_queries|interval_s|10|
|send/send_ipv6.py|SendIPv6|react_to_mld_queries|interval_s|10|