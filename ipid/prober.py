"""Send probes from a rate-limited queue and capture replies with a separate sniffer.

The sender never waits for replies (scapy's sr() is too slow for thousands of
targets). A background AsyncSniffer matches each reply to its probe with
probes.match() and appends it to replies.csv as it arrives. Sent probes go to
sent.csv. The two files are joined on (target, ptype, num) during analysis.
"""
import csv
import os
import random
import threading
import time
from pathlib import Path

from scapy.all import AsyncSniffer, conf
from scapy.layers.inet import ICMP, IP, TCP

from . import probes

SENT_FIELDS = ["run_id", "target", "ptype", "num", "k", "src_label", "src_ip",
               "dport", "t_send"]
REPLY_FIELDS = ["run_id", "target", "ptype", "num", "dst_ip", "t_recv", "ipid",
                "ttl", "df", "flags", "ip_len"]


class TokenBucket:
    """Global packets-per-second cap (design doc §6)."""

    def __init__(self, pps):
        self.interval = 1.0 / pps
        self.next_t = time.monotonic()

    def wait(self):
        now = time.monotonic()
        if now < self.next_t:
            time.sleep(self.next_t - now)
        self.next_t = max(self.next_t + self.interval, time.monotonic())


class Prober:
    def __init__(self, cfg, run_id=None, out_dir=None):
        self.cfg = cfg
        self.run_id = run_id or time.strftime("%Y%m%d-%H%M%S")
        self.run_tag = random.getrandbits(16)
        self.src = {"A": cfg["sources"]["A"], "B": cfg["sources"]["B"]}
        self.iface = cfg["sources"].get("iface") or None
        self.bucket = TokenBucket(cfg["rates"]["max_pps"])
        self.gap = cfg["rates"]["probe_gap_ms"] / 1000.0
        self.sport_base = cfg["probes"]["sport_base"]

        self.out_dir = Path(out_dir or cfg["output"]["dir"]) / self.run_id
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self._sent_f = open(self.out_dir / "sent.csv", "w", newline="")
        self._reply_f = open(self.out_dir / "replies.csv", "w", newline="")
        self.sent_w = csv.DictWriter(self._sent_f, SENT_FIELDS)
        self.reply_w = csv.DictWriter(self._reply_f, REPLY_FIELDS)
        self.sent_w.writeheader()
        self.reply_w.writeheader()

        self.lock = threading.Lock()
        self.replies = []      # kept in memory too, for the single-target summary
        self.n_sent = 0
        self.sock = conf.L3socket(iface=self.iface) if self.iface else conf.L3socket()
        self.sniffer = None

    # ---- receive side -------------------------------------------------------
    def _bpf(self):
        a, b = self.src["A"], self.src["B"]
        return (f"(dst host {a} or dst host {b}) and "
                f"(icmp[icmptype] == icmp-echoreply or tcp)")

    def _on_packet(self, pkt):
        m = probes.match(pkt, self.run_tag)
        if m is None:
            return
        target, ptype, num = m
        ip = pkt[IP]
        if TCP in pkt:
            flags = str(pkt[TCP].flags)
        else:
            flags = f"icmp{pkt[ICMP].type}"
        row = {"run_id": self.run_id, "target": target, "ptype": ptype, "num": num,
               "dst_ip": ip.dst, "t_recv": f"{float(pkt.time):.6f}", "ipid": ip.id,
               "ttl": ip.ttl, "df": int(bool(ip.flags.DF)), "flags": flags,
               "ip_len": ip.len}
        with self.lock:
            self.reply_w.writerow(row)
            self._reply_f.flush()
            self.replies.append(row)

    def start(self):
        kw = {"filter": self._bpf(), "prn": self._on_packet, "store": False}
        if self.iface:
            kw["iface"] = self.iface
        self.sniffer = AsyncSniffer(**kw)
        self.sniffer.start()
        time.sleep(0.5)  # let the capture socket open before the first probe
        if not self.sniffer.running:
            # surface capture errors (e.g. missing libpcap) before sending anything
            self.sniffer.stop()

    def stop(self):
        time.sleep(self.cfg["rates"]["reply_timeout_s"])
        if self.sniffer:
            self.sniffer.stop()
        self.sock.close()
        self._sent_f.close()
        self._reply_f.close()

    # ---- send side ----------------------------------------------------------
    def send(self, p: probes.Probe):
        pkt = probes.build(p, self.run_tag, self.sport_base)
        self.bucket.wait()
        t = time.time()
        self.sock.send(pkt)
        self.n_sent += 1
        with self.lock:
            self.sent_w.writerow({"run_id": self.run_id, "target": p.target,
                                  "ptype": p.ptype, "num": p.num, "k": p.k,
                                  "src_label": p.src_label, "src_ip": p.src_ip,
                                  "dport": p.dport, "t_send": f"{t:.6f}"})
            self._sent_f.flush()
        return t

    def send_spaced(self, plist):
        """Send probes to one target with probe_gap_ms between them."""
        for i, p in enumerate(plist):
            if i:
                time.sleep(self.gap)
            self.send(p)

    def replied_types(self, target, nums):
        with self.lock:
            return {r["ptype"] for r in self.replies
                    if r["target"] == target and r["num"] in nums}


def require_root():
    if os.geteuid() != 0:
        raise SystemExit("Raw sockets need root: run with sudo.")
