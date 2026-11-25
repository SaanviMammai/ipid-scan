#!/usr/bin/env bash
# Multi-target testbed for scan.py. Nothing leaves the machine.
#
#   sudo scripts/lab/scan_testbed.sh up [LIVE] [DEAD]   # default 20 live, 30 dead
#   sudo ip netns exec ipid-scanner .venv/bin/python3 scripts/scan.py random \
#        data/lab/lab_targets.csv --lab --iface s0 --src-a 10.99.0.2 --src-b 10.99.0.3 --yes
#   sudo scripts/lab/scan_testbed.sh down
#
# "ipid-scanner" has A=10.99.0.2 and B=10.99.0.3. "ipid-target" (a real Linux
# stack) answers on LIVE addresses in 10.99.1.0 - 10.99.9.255, with TCP 80 and 443 open.
# DEAD addresses 10.98.x.y are routed through the target namespace, which drops
# them silently (no forwarding), like most random IPs.
set -euo pipefail

SCAN=ipid-scanner
TGT=ipid-target
LIVE=${2:-20}
DEAD=${3:-30}
DIR="$(cd "$(dirname "$0")/../.." && pwd)/data/lab"

up() {
  ip netns add $SCAN
  ip netns add $TGT
  ip link add s0 type veth peer name t0
  ip link set s0 netns $SCAN
  ip link set t0 netns $TGT
  ip -n $SCAN addr add 10.99.0.2/16 dev s0
  ip -n $SCAN addr add 10.99.0.3/16 dev s0
  ip -n $TGT addr add 10.99.0.10/16 dev t0
  for i in $(seq 1 "$LIVE"); do ip -n $TGT addr add 10.99.$((1 + i / 250)).$((1 + i % 250))/16 dev t0; done
  for ns in $SCAN $TGT; do ip -n $ns link set lo up; done
  ip -n $SCAN link set s0 up
  ip -n $TGT link set t0 up
  ip netns exec $TGT sysctl -qw net.ipv4.ip_forward=0
  ip -n $SCAN route add 10.98.0.0/16 via 10.99.0.10
  for port in 80 443; do
    ip netns exec $TGT python3 -m http.server $port --bind 0.0.0.0 >/dev/null 2>&1 &
    echo $! >> /tmp/ipid-scan-testbed.pids
  done
  mkdir -p "$DIR"
  {
    echo "ip,round,slash16"
    # interleave live and dead addresses, like a real random list
    for i in $(seq 1 $(( LIVE > DEAD ? LIVE : DEAD ))); do
      if [[ $i -le $LIVE ]]; then echo "10.99.$((1 + i / 250)).$((1 + i % 250)),1,10.99"; fi
      if [[ $i -le $DEAD ]]; then echo "10.98.$((1 + i / 250)).$((1 + i % 250)),1,10.98"; fi
    done
  } > "$DIR/lab_targets.csv"
  [[ -n "${SUDO_UID:-}" ]] && chown -R "$SUDO_UID:$SUDO_GID" "$DIR" "$DIR/.."
  sleep 1
  echo "Testbed up: $LIVE live + $DEAD dead targets -> $DIR/lab_targets.csv"
}

down() {
  if [[ -f /tmp/ipid-scan-testbed.pids ]]; then
    xargs -r kill < /tmp/ipid-scan-testbed.pids 2>/dev/null || true
    rm -f /tmp/ipid-scan-testbed.pids
  fi
  ip netns del $SCAN 2>/dev/null || true
  ip netns del $TGT 2>/dev/null || true
  echo "Testbed removed"
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  *) echo "usage: $0 up [LIVE] [DEAD] | down" >&2; exit 2 ;;
esac
