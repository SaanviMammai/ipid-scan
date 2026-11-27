"""Simulated scan and lifetime runs, in the exact file format scan.py and lifetime.py write.

Used by the analysis tests and by scripts/lab/fake_runs.py to preview the charts
before real data exists. Targets are in 198.18.0.0/15 (reserved for benchmarking),
so a fake run can never be mistaken for real addresses.

The mix of mechanisms is made up for illustration only; it is NOT a prediction.
"""
import csv
import json
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ipid.classify import FULL_SET_START, classify_run, write_rows  # noqa: E402
from ipid.lifetime import (STEP_FIELDS, SUMMARY_FIELDS, Track,  # noqa: E402
                           summarize_steps_file, write_csv)
from ipid.prober import REPLY_FIELDS, SENT_FIELDS  # noqa: E402

TYPES = ("icmp", "syn", "synack")
GAP = 0.15

# share of responding hosts per mechanism, per probe type (illustration only)
MIX = {
    "random": {"icmp": {"global": .35, "per_dest": .25, "random": .15, "constant": .15, "flaky": .10},
               "tcp": {"global": .30, "per_dest": .20, "random": .10, "constant": .30, "flaky": .10}},
    "tranco": {"icmp": {"global": .05, "per_dest": .55, "random": .25, "constant": .10, "flaky": .05},
               "tcp": {"global": .03, "per_dest": .17, "random": .20, "constant": .55, "flaky": .05}},
}
RESPONSE = {"random": 0.08, "tranco": 0.95}


class Mech:
    """IP-ID source for one host and probe type."""

    def __init__(self, kind, rng):
        self.kind, self.rng = kind, rng
        self.g = rng.randrange(65536)
        self.per = {"A": rng.randrange(65536), "B": rng.randrange(65536)}
        self.rate = rng.choice([0, 2, 20, 200])   # background packets/s for global

    def ipid(self, src, t_last_gap):
        k = self.kind
        if k == "constant":
            return 0
        if k == "random":
            return self.rng.randrange(65536)
        if k == "global" or k == "flaky":
            self.g = (self.g + 1 + int(self.rate * t_last_gap * self.rng.uniform(.5, 1.5))) % 65536
            return self.g
        self.per[src] = (self.per[src] + 1) % 65536
        return self.per[src]


def _pick(mix, rng):
    x, acc = rng.random(), 0.0
    for k, p in mix.items():
        acc += p
        if x < acc:
            return k
    return k


def make_scan_run(root, group, n_targets, seed=1, run_id=None):
    """Write data/raw-style folder for one fake scan and classify it. Returns the folder."""
    rng = random.Random(seed)
    run_id = run_id or f"fake-{group}"
    d = Path(root) / run_id
    d.mkdir(parents=True, exist_ok=True)
    src = {"A": "192.0.2.1", "B": "192.0.2.2"}
    dport = 80 if group == "random" else 443
    sent, replies, responders, by_type = [], [], 0, {t: 0 for t in TYPES}
    t = 1_800_000_000.0
    for i in range(n_targets):
        ip = f"198.{18 + i // 65536}.{(i // 256) % 256}.{i % 256}"
        live = rng.random() < RESPONSE[group]
        mechs = {}
        if live:
            responders += 1
            for p in TYPES:
                fam = "icmp" if p == "icmp" else "tcp"
                kind = _pick(MIX[group][fam], rng)
                if p == "synack" and "syn" in mechs and rng.random() < .8:
                    kind = mechs["syn"].kind   # TCP types usually agree
                mechs[p] = Mech(kind, rng)
                by_type[p] += 1
        for j, p in enumerate(TYPES):     # discovery: one per type from A
            sent.append([run_id, ip, p, j, 0, "A", src["A"], dport, f"{t:.6f}"])
            if live:
                replies.append([run_id, ip, p, j, src["A"], f"{t + .03:.6f}",
                                mechs[p].ipid("A", 1.0), 64, 1, "x", 40])
            t += 0.002
        if not live:
            continue
        num = FULL_SET_START
        for p in TYPES:
            for k in range(10):
                s = "A" if k % 2 == 0 else "B"
                sent.append([run_id, ip, p, num, k, s, src[s], dport, f"{t:.6f}"])
                m = mechs[p]
                drop = m.kind == "flaky" and rng.random() < .7
                v = m.ipid(s, GAP)
                if not drop:
                    replies.append([run_id, ip, p, num, src[s], f"{t + .03:.6f}", v, 64,
                                    int(m.kind == "constant"), "x", 40])
                num += 1
                t += GAP
    with open(d / "sent.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(SENT_FIELDS)
        w.writerows(sent)
    with open(d / "replies.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(REPLY_FIELDS)
        w.writerows(replies)
    meta = {"run_id": run_id, "group": group, "n_targets": n_targets, "dport": dport,
            "responders": responders, "responders_by_type": by_type, "lab": True,
            "fake": True}
    (d / "scan_meta.json").write_text(json.dumps(meta, indent=2))
    write_rows(classify_run(d), d / "classified.csv")
    return d


class _Host:
    """Per-destination counter for the lifetime run: real lifetime or Linux-style."""

    def __init__(self, rng):
        self.rng = rng
        self.kind = rng.choices(["linux", "life"], [.6, .4])[0]
        self.life_s = rng.choice([30, 90, 300, 600, 1500, 5000, 20000, 1e9])
        self.v, self.last = rng.randrange(65536), None

    def reply(self, t):
        if self.last is not None:
            idle = t - self.last
            if self.kind == "linux":
                self.v += self.rng.randrange(max(1, int(idle * 250)))
            elif idle > self.life_s:
                self.v = self.rng.randrange(65536)
        self.v = (self.v + 1) % 65536
        self.last = t
        return self.v


def make_lifetime_run(root, scan_dirs, per_group=60, seed=2, run_id="fake-lifetime",
                      gaps=(1, 2, 4, 8, 16, 32, 64), extend=(128, 256)):
    """Drive lifetime Tracks against simulated hosts on a fake clock."""
    rng = random.Random(seed)
    d = Path(root) / run_id
    d.mkdir(parents=True, exist_ok=True)
    tracks = []
    for sd in scan_dirs:
        meta = json.loads((Path(sd) / "scan_meta.json").read_text())
        with open(Path(sd) / "classified.csv", newline="") as f:
            rows = [r for r in csv.DictReader(f) if r["category"] == "per_dest"]
        for r in rows[:per_group]:
            tracks.append(Track(r["target"], r["ptype"], meta["group"], meta["dport"],
                                gaps, extend, 60.0))
    rows_out, reasons = [], {}
    for tr in tracks:
        h, t = _Host(rng), 1_800_000_000.0
        gone_at = rng.choice([None] * 9 + [rng.randint(2, 8)])
        while not tr.done:
            t = max(t, tr.due)
            ipid = None if (gone_at is not None and tr.step >= gone_at) else h.reply(t)
            row = tr.record(t, t, ipid, 1)
            rows_out.append({**row, "run_id": run_id, "unit": "min",
                             "gap_s": "" if row["gap_s"] is None else f"{row['gap_s']:.3f}"})
        reasons[(tr.target, tr.ptype)] = tr.end_reason
    write_csv(rows_out, d / "lifetime_steps.csv", STEP_FIELDS)
    write_csv(summarize_steps_file(d / "lifetime_steps.csv", reasons),
              d / "lifetime_summary.csv", SUMMARY_FIELDS)
    (d / "lifetime_meta.json").write_text(json.dumps({"run_id": run_id, "fake": True}))
    return d
