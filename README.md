# ipid-scan

Measures how Internet hosts set the IPv4 IP-ID field (zero/constant, global,
per-destination or random) by probing each host from two source IPs.
CSE 4402 Network Security, Fall 2026, DoS/Scanning project #2.

## Layout

| Path | What it does |
|---|---|
| `config.toml` | Source IPs, rate limits, probe counts. Every rate limit lives here. |
| `ipid/probes.py` | Builds ICMP echo, TCP SYN and unsolicited SYN/ACK probes; matches replies to probes |
| `ipid/prober.py` | Rate-limited sender plus a separate sniffer; writes `sent.csv` and `replies.csv` |
| `scripts/probe_one.py` | Probes one target and prints its IP-ID sequences |
| `scripts/lab/netns_testbed.sh` | Local two-namespace testbed (scanner with IPs A and B, Linux target) |
| `tests/` | Unit tests for probe encoding and reply matching |
| `docs/SETUP.md` | Setting up the scanner machine and a test target |

Planned next: `targets.py` (random IPs and Tranco list), `classify.py`, `scan.py`
(many targets), `lifetime.py` (RQ2), `analysis/`.

## How replies are matched

Each run picks a random 16-bit run tag. Each probe carries the tag and a probe number:

| Probe | Where the tag goes | Reply | Where it comes back |
|---|---|---|---|
| ICMP echo | id = tag, seq = num | echo reply | id, seq copied |
| TCP SYN | seq = tag:num | SYN/ACK or RST/ACK | ack − 1 |
| TCP SYN/ACK | ack = tag:num | RST | seq |

## Quick start

```bash
sudo apt install python3-pip libpcap0.8 iproute2
pip install -r requirements.txt
python3 -m pytest -q tests

# local test, nothing leaves the machine
sudo scripts/lab/netns_testbed.sh up
sudo ip netns exec ipid-scanner python3 scripts/probe_one.py 10.99.0.10 --iface s0
sudo scripts/lab/netns_testbed.sh down

# a real target you own (set sources.A and sources.B in config.toml first)
sudo python3 scripts/probe_one.py <your-test-vm-ip>
```

## Output

`data/raw/<run_id>/sent.csv` has one row per probe: target, probe type, probe number,
position k, source label and IP, and send time. `replies.csv` has one row per matched
reply: target, probe type, probe number, receive time, IP-ID, TTL, DF bit and flags.
Join the two on (target, ptype, num). `data/` is git-ignored because it holds real addresses.

## Ethics

Only probe hosts you own until the full scan is approved. The scan caps total
sending at `rates.max_pps` (500), each host gets about 33 packets, nothing is spoofed,
and the scanner IPs' reverse DNS points to a project page with an opt-out.
See design doc §6.
