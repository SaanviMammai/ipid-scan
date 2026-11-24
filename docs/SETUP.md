# Setup: scanner machine and test target

Goal for 11/24: `probe_one.py` gets correct IP-IDs back from a machine you own,
using two source IPs (A and B).

## 0. Where to scan from

You need **one machine that owns two public IPv4 addresses**. Options:

- **UConn network (recommended for the full scan).** The instructor has already approved
  it. Ask him or UConn IT for two addresses (one host with two IPs, or two lab machines).
  Also ask whether the campus firewall drops outbound TCP SYN/ACKs that have no matching
  SYN, because stateful firewalls often do. If it does, the `synack` probes will get no
  replies.
- **AWS EC2.** Fine for testing against your own instances. For the Internet scan, the
  AUP bans anything that violates the security of another network or system, and AWS's
  scanning guidelines suggest 1 transaction per second per destination. Get written
  approval (AWS support, or the instructor) before scanning other people's hosts from
  AWS, and set `probe_gap_ms = 1000`.
- **DigitalOcean:** its staff say scanning hosts you don't own, without permission, counts
  as abuse. Don't use it for the scan.

## 1. AWS: one instance with two public IPs

1. Launch a small Ubuntu 24.04 instance (t3.micro is enough), the **scanner**.
2. EC2 → Network interfaces → select the scanner's interface → *Manage IP addresses* →
   *Assign new IP address*. Note the new **secondary private IP**.
3. EC2 → Elastic IPs → *Allocate*, then *Associate* it with the scanner's network
   interface **and the secondary private IP**. The primary private IP keeps its
   auto-assigned public IP. (Each public IPv4 costs about $0.005 per hour.)
4. On the scanner, Ubuntu does not always configure the secondary IP itself:

   ```bash
   ip -4 addr                    # is the secondary private IP listed?
   sudo ip addr add <SECONDARY_PRIVATE_IP>/<PREFIX> dev ens5   # if not (lost on reboot)
   ```

5. In `config.toml`, set `sources.A` and `sources.B` to the two **private** IPs. AWS
   translates them to the public IPs on the way out, so replies come back to the private
   addresses. Set `sources.iface = "ens5"` (check the name with `ip link`).

## 2. Install

```bash
sudo apt update && sudo apt install -y python3-pip python3-venv libpcap0.8 git
git clone <your repo> && cd ipid-scan
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python3 -m pytest -q tests
```

Run probes with `sudo .venv/bin/python3 scripts/probe_one.py ...`, since raw sockets need
root. Without libpcap you get "Cannot set filter: libpcap is not available."

## 3. Test target

1. Launch a second small instance, the **target**. In its security group, allow ICMP
   (echo request) and TCP 80 inbound **from the scanner's two public IPs only**.
2. On the target: `sudo python3 -m http.server 80` (an open port for SYN probes).
3. From the scanner: `sudo .venv/bin/python3 scripts/probe_one.py <TARGET_PUBLIC_IP>`.

## 4. What a working run looks like

From the local testbed (Linux 6.18 target), and a Linux target VM should look similar:

```
icmp: 10/10 replies          <- per-destination: A and B each step up by small
  k src  ipid  step(all) step(same src)   random amounts; A and B are far apart
  0  A  40317
  1  B  31623     56842
  2  A  40350      8727       33
  ...
syn: 10/10 replies           <- DF set, IP-ID always 0: zero/constant
synack: 10/10 replies        <- DF set, IP-ID always 0: zero/constant
```

**Done for today when:** all three probe types get 10/10 replies from your target, from
both A and B. If `synack` gets 0 replies while `syn` works, something between you and
the target drops unsolicited SYN/ACKs (see step 0).

## Local testbed (no cloud needed)

```bash
sudo scripts/lab/netns_testbed.sh up
sudo ip netns exec ipid-scanner python3 scripts/probe_one.py 10.99.0.10 --iface s0
sudo scripts/lab/netns_testbed.sh down
```

Needs Linux with `iproute2`. This also works on a single cloud VM, so you can test
the code before the second IP is set up.
