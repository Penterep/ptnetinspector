# Notes of predictable IPv6 address detection

## Detection by utils/ip_utils.py is_ipv6_predictable (line 164)
- **EUI-64**
- At least **4 null hextets**
- At least **4 repeated hextets**
- **Last hextet** as at most **4 bit** value (0001, 0002, ... 000f)
- At least **3** simple **hextet patterns** (1111, 2222, ... ffff)