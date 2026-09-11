#!/usr/bin/env bash
# Run ptnetinspector against a simulated LAN on a real veth link.
#
# Needs no root: unprivileged user namespaces give CAP_NET_ADMIN and
# CAP_NET_RAW inside a private network namespace, and every firewall rule or
# sysctl the tool touches applies only in there.
#
#   ./testbed.sh <ptnetinspector args...>       e.g. ./testbed.sh -t a -i scan0 -vv
set -u
REPO="${REPO:-$(cd "$(dirname "$(readlink -f "$0")")/../.." && pwd)}"
SIM="$(dirname "$(readlink -f "$0")")/lan_sim.py"
SIM_DURATION="${SIM_DURATION:-45}"

exec unshare -Urn -- env PCAP="${PCAP:-}" bash -s "$REPO" "$SIM" "$SIM_DURATION" "$@" <<'INNER'
set -u
REPO="$1"; SIM="$2"; SIM_DURATION="$3"; shift 3

ip link set lo up
unshare -n -- sleep 3600 &
PEER=$!
cleanup() { kill "$PEER" 2>/dev/null; }
trap cleanup EXIT
sleep 0.4

ip link add scan0 type veth peer name lan0
ip link set lan0 netns "$PEER"

ip link set scan0 up
ip addr add 192.168.73.77/24 dev scan0
ip addr add fd00:73::77/64 dev scan0 nodad
ip route add default via 192.168.73.1 dev scan0 2>/dev/null
ip -6 route add default via fe80::250:56ff:fec0:2 dev scan0 2>/dev/null

nsenter -t "$PEER" -n ip link set lo up
nsenter -t "$PEER" -n ip link set lan0 up
nsenter -t "$PEER" -n ip addr add 192.168.73.78/24 dev lan0
nsenter -t "$PEER" -n sysctl -qw net.ipv6.conf.lan0.accept_ra=2

echo "== testbed: scan0 (scanner) <-> lan0 (simulated LAN) =="
ip -brief addr show scan0

if [ -n "${PCAP:-}" ]; then
  tcpdump -i scan0 -w "$PCAP" -U -s0 -Z root >/dev/null 2>&1 &
  TCPDUMP=$!
  echo "== capturing to $PCAP =="
fi

nsenter -t "$PEER" -n python3 "$SIM" -i lan0 -d "$SIM_DURATION" --beacon-interval "${BEACON_INTERVAL:-2}" --extra-hosts "${EXTRA_HOSTS:-0}" > /tmp/lan_sim.log 2>&1 &
SIMPID=$!
sleep 1.5

cd "$REPO"
python3 -m ptnetinspector "$@"
RC=$?

wait $SIMPID 2>/dev/null
[ -n "${TCPDUMP:-}" ] && { sleep 0.5; kill "$TCPDUMP" 2>/dev/null; wait "$TCPDUMP" 2>/dev/null; }
echo "== simulated LAN transmit counts =="
cat /tmp/lan_sim.log
exit $RC
INNER
