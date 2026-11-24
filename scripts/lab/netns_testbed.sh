#!/usr/bin/env bash
# Local testbed: a "scanner" namespace with two source IPs (A, B) and a Linux
# "target" namespace, joined by a veth pair. Nothing leaves the machine.
#
#   sudo scripts/lab/netns_testbed.sh up       # create
#   sudo ip netns exec ipid-scanner python3 scripts/probe_one.py 10.99.0.10 --iface s0
#   sudo scripts/lab/netns_testbed.sh down     # remove
set -euo pipefail

SCAN=ipid-scanner
TGT=ipid-target
A=10.99.0.2
B=10.99.0.3
T=10.99.0.10

up() {
  ip netns add $SCAN
  ip netns add $TGT
  ip link add s0 type veth peer name t0
  ip link set s0 netns $SCAN
  ip link set t0 netns $TGT
  ip -n $SCAN addr add $A/24 dev s0
  ip -n $SCAN addr add $B/24 dev s0
  ip -n $TGT  addr add $T/24 dev t0
  for ns in $SCAN $TGT; do
    ip -n $ns link set lo up
  done
  ip -n $SCAN link set s0 up
  ip -n $TGT  link set t0 up
  # an open TCP port on the target, so SYN probes get SYN/ACKs
  ip netns exec $TGT python3 -m http.server 80 --bind $T >/dev/null 2>&1 &
  echo $! > /tmp/ipid-target-http.pid
  sleep 1
  echo "Testbed up: scanner A=$A B=$B (iface s0), target $T (port 80 open)"
}

down() {
  if [[ -f /tmp/ipid-target-http.pid ]]; then
    kill "$(cat /tmp/ipid-target-http.pid)" 2>/dev/null || true
    rm -f /tmp/ipid-target-http.pid
  fi
  ip netns del $SCAN 2>/dev/null || true
  ip netns del $TGT 2>/dev/null || true
  echo "Testbed removed"
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  *) echo "usage: $0 up|down" >&2; exit 2 ;;
esac
