"""Build probe packets and match replies back to the probe that caused them.

Every probe carries a 16-bit run tag and a 16-bit probe number, so a reply can be
matched to (target, probe number) without keeping per-connection state:

  icmp   : ICMP echo request, id = run tag, seq = probe number.
           The echo reply copies id and seq.
  syn    : TCP SYN, seq = (run_tag << 16) | probe number.
           The SYN/ACK or RST/ACK reply has ack = our seq + 1.
  synack : unsolicited TCP SYN/ACK, ack = (run_tag << 16) | probe number.
           The RST reply has seq = our ack (RFC 9293, section 3.10.7.1).

The TCP source port is sport_base + probe number, which also makes each probe a
distinct flow, so middleboxes are less likely to merge them.
"""
from dataclasses import dataclass

from scapy.layers.inet import ICMP, IP, TCP

PROBE_TYPES = ("icmp", "syn", "synack")
MASK16 = 0xFFFF
MASK32 = 0xFFFFFFFF


@dataclass(frozen=True)
class Probe:
    target: str
    ptype: str      # "icmp", "syn" or "synack"
    src_label: str  # "A" or "B"
    src_ip: str
    num: int        # probe number, unique per (run, target)
    k: int          # position within this probe type's sequence (0..per_type-1)
    dport: int


def tag_word(run_tag, num):
    return ((run_tag & MASK16) << 16) | (num & MASK16)


def build(p: Probe, run_tag: int, sport_base: int):
    ip = IP(src=p.src_ip, dst=p.target)
    if p.ptype == "icmp":
        return ip / ICMP(type=8, id=run_tag & MASK16, seq=p.num & MASK16)
    sport = sport_base + (p.num % 20000)
    word = tag_word(run_tag, p.num)
    if p.ptype == "syn":
        return ip / TCP(sport=sport, dport=p.dport, flags="S", seq=word, window=1024)
    if p.ptype == "synack":
        return ip / TCP(sport=sport, dport=p.dport, flags="SA", seq=0x1000, ack=word,
                        window=1024)
    raise ValueError(f"unknown probe type {p.ptype}")


def match(pkt, run_tag: int):
    """Return (target, ptype, probe number) for a reply packet, or None.

    For TCP the probe type is inferred from which field echoes the tag:
    ack - 1 for SYN probes, seq for SYN/ACK probes.
    """
    if IP not in pkt:
        return None
    target = pkt[IP].src
    if ICMP in pkt:
        icmp = pkt[ICMP]
        if icmp.type == 0 and icmp.id == (run_tag & MASK16):
            return target, "icmp", icmp.seq
        return None
    if TCP in pkt:
        tcp = pkt[TCP]
        flags = str(tcp.flags)
        if "A" in flags:  # SYN/ACK or RST/ACK in reply to our SYN
            w = (tcp.ack - 1) & MASK32
            if (w >> 16) == (run_tag & MASK16):
                return target, "syn", w & MASK16
        if "R" in flags:  # bare RST in reply to our SYN/ACK
            w = tcp.seq & MASK32
            if (w >> 16) == (run_tag & MASK16):
                return target, "synack", w & MASK16
    return None


def schedule(target, src, per_type, types, dport, first_num=0):
    """Full probe set for one target: per_type probes of each type, alternating A/B.

    src is {"A": ip, "B": ip}. Returns a list of Probe in send order.
    """
    out, num = [], first_num
    for ptype in types:
        for k in range(per_type):
            label = "A" if k % 2 == 0 else "B"
            out.append(Probe(target, ptype, label, src[label], num, k, dport))
            num += 1
    return out


def discovery(target, src, types, dport, first_num=0):
    """One probe of each type from source A, to see whether the target replies."""
    return [Probe(target, t, "A", src["A"], first_num + i, 0, dport)
            for i, t in enumerate(types)]
