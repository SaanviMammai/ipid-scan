"""Round-trip tests: build a probe, fake the reply a real stack would send, match it."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scapy.layers.inet import ICMP, IP, TCP  # noqa: E402

from ipid import probes  # noqa: E402

TAG = 0xBEEF
SRC = {"A": "192.0.2.1", "B": "192.0.2.2"}
T = "198.51.100.7"


def _probe(ptype, num=1234):
    return probes.Probe(T, ptype, "A", SRC["A"], num, 0, 80)


def test_icmp_roundtrip():
    req = probes.build(_probe("icmp"), TAG, 40000)
    rep = IP(src=T, dst=SRC["A"]) / ICMP(type=0, id=req[ICMP].id, seq=req[ICMP].seq)
    assert probes.match(rep, TAG) == (T, "icmp", 1234)


def test_syn_synack_reply():
    req = probes.build(_probe("syn"), TAG, 40000)
    rep = IP(src=T, dst=SRC["A"]) / TCP(sport=80, dport=req[TCP].sport, flags="SA",
                                        seq=999, ack=req[TCP].seq + 1)
    assert probes.match(rep, TAG) == (T, "syn", 1234)


def test_syn_rst_reply_closed_port():
    req = probes.build(_probe("syn"), TAG, 40000)
    rep = IP(src=T, dst=SRC["A"]) / TCP(sport=80, dport=req[TCP].sport, flags="RA",
                                        seq=0, ack=req[TCP].seq + 1)
    assert probes.match(rep, TAG) == (T, "syn", 1234)


def test_synack_rst_reply():
    req = probes.build(_probe("synack"), TAG, 40000)
    rep = IP(src=T, dst=SRC["A"]) / TCP(sport=80, dport=req[TCP].sport, flags="R",
                                        seq=req[TCP].ack)
    assert probes.match(rep, TAG) == (T, "synack", 1234)


def test_wraparound_num_and_seq():
    # probe number 0xFFFF makes seq+1 carry into the tag bits; ack-1 must undo it
    req = probes.build(_probe("syn", num=0xFFFF), TAG, 40000)
    rep = IP(src=T, dst=SRC["A"]) / TCP(flags="SA", ack=(req[TCP].seq + 1) & 0xFFFFFFFF)
    assert probes.match(rep, TAG) == (T, "syn", 0xFFFF)


def test_other_run_ignored():
    req = probes.build(_probe("icmp"), TAG, 40000)
    rep = IP(src=T, dst=SRC["A"]) / ICMP(type=0, id=0x1111, seq=req[ICMP].seq)
    assert probes.match(rep, TAG) is None


def test_schedule_alternates_sources():
    s = probes.schedule(T, SRC, 10, ["icmp", "syn", "synack"], 80, first_num=100)
    assert len(s) == 30
    assert [p.src_label for p in s[:4]] == ["A", "B", "A", "B"]
    assert len({p.num for p in s}) == 30
