"""Tests for the counter lifetime logic (RQ2) with simulated hosts on a fake clock."""
import csv
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ipid.lifetime import (DEFAULT_EXTEND_MIN, DEFAULT_GAPS_MIN, STEP_FIELDS,  # noqa: E402
                           Track, judge, pick_sample, summarize, summarize_steps_file,
                           write_csv)

MIN = 60.0


class CounterHost:
    """Per-destination counter that +1s per packet and resets after `life_s` idle."""

    def __init__(self, life_s, start=1000, seed=1):
        self.life_s, self.value, self.last = life_s, start, None
        self.rng = random.Random(seed)

    def reply(self, t):
        if self.last is not None and t - self.last > self.life_s:
            self.value = self.rng.randrange(65536)   # forgot us: new random start
        else:
            self.value = (self.value + 1) % 65536
        self.last = t
        return self.value


class LinuxLikeHost:
    """Adds a random increment in [0, idle jiffies) before each +1 (HZ=1000)."""

    def __init__(self, hz=1000, seed=2):
        self.hz, self.value, self.last = hz, 5000, None
        self.rng = random.Random(seed)

    def reply(self, t):
        if self.last is not None:
            idle = int((t - self.last) * self.hz)
            if idle > 0:
                self.value += self.rng.randrange(idle)
        self.value = (self.value + 1) % 65536
        self.last = t
        return self.value


def run(host, gaps=DEFAULT_GAPS_MIN, extend=DEFAULT_EXTEND_MIN, lose=(), T=1000,
        retries=0, retry_s=3.0):
    """Drive one Track against a simulated host. `lose` = set of (step, try) to drop."""
    tr = Track("198.51.100.7", "icmp", "random", 80, tuple(gaps), tuple(extend),
               unit_s=MIN, T=T)
    t, sends = 0.0, []
    while not tr.done:
        t = max(t, tr.due)
        first, ipid, tries = t, None, 0
        for k in range(retries + 1):
            tries += 1
            sends.append((tr.step, t))
            v = host.reply(t)
            if (tr.step, k) not in lose:
                ipid = v
                break
            t += retry_s
        tr.record(first, t, ipid, tries)
    return tr, sends


def test_judge():
    assert judge(100, 101) == (1, "survived")
    assert judge(65535, 3) == (4, "survived")          # wraparound
    assert judge(100, 100) == (0, "no_change")
    assert judge(100, 5000) == (4900, "reset")
    assert judge(100, 1100, T=1000) == (1000, "survived")


def test_gaps_measured_from_previous_probe():
    tr, sends = run(CounterHost(life_s=1e9))
    times = [t for _, t in sends]
    gaps = [(b - a) / MIN for a, b in zip(times, times[1:])]
    assert gaps == [1, 2, 4, 8, 16, 32, 64, 128, 256]


def test_never_resets_gets_extended_and_reported_above_256():
    tr, _ = run(CounterHost(life_s=1e9))
    s = summarize(tr.history, tr.end_reason)
    assert s["label"] == ">256" and s["upper"] is None
    assert s["n_survived"] == 9 and s["consistent"] == 1
    assert tr.end_reason == "finished"


def test_reset_after_5_minutes_gives_4_to_8():
    tr, _ = run(CounterHost(life_s=5 * MIN))
    s = summarize(tr.history)
    assert s["label"] == "4-8" and (s["lower"], s["upper"]) == (4, 8)
    # it reset at 8, so no extension past 64
    assert max(r["planned_gap"] for r in tr.history) == 64


def test_reset_before_first_gap():
    tr, _ = run(CounterHost(life_s=30))
    assert summarize(tr.history)["label"] == "<1"


def test_survives_64_but_not_128():
    tr, _ = run(CounterHost(life_s=100 * MIN))
    s = summarize(tr.history)
    assert s["label"] == "64-128"
    assert [r["planned_gap"] for r in tr.history][-1] == 128   # no 256 after a reset


def test_linux_like_increments_grow_with_idle_time():
    tr, _ = run(LinuxLikeHost(hz=1000), T=1000)
    rows = [r for r in tr.history if r["step"] > 0]
    # idle 60 s at HZ=1000 gives a random increment up to 60,000: almost always "reset"
    assert all(r["outcome"] == "reset" for r in rows if r["planned_gap"] >= 2)
    assert summarize(tr.history)["label"] in ("<1", "<2")


def test_lost_reply_retried_within_step():
    # first try of step 3 is lost, the retry 3 s later is answered
    tr, sends = run(CounterHost(life_s=1e9), lose={(3, 0)}, retries=2)
    r3 = [r for r in tr.history if r["step"] == 3][0]
    assert r3["tries"] == 2 and r3["outcome"] == "survived" and r3["clean"] == 1
    assert r3["jump"] == 2          # the lost try still reached the host
    assert abs(r3["gap_s"] - 4 * MIN) < 1e-6   # idle gap ends at the FIRST try
    # the next gap starts after the retry
    t3 = [t for s, t in sends if s == 3][-1]
    t4 = [t for s, t in sends if s == 4][0]
    assert t4 - t3 == 8 * MIN


def test_unanswered_step_makes_next_step_unclean():
    tr, _ = run(CounterHost(life_s=1e9), lose={(2, 0)}, retries=0)
    by = {r["step"]: r for r in tr.history}
    assert by[2]["outcome"] == "no_reply"
    assert by[3]["outcome"] == "survived" and by[3]["clean"] == 0
    s = summarize(tr.history)
    assert s["n_clean"] == len(tr.history) - 3   # baseline, no_reply, unclean step
    assert s["label"] == ">256"


def test_two_misses_in_a_row_means_gone():
    tr, _ = run(CounterHost(life_s=1e9), lose={(4, 0), (5, 0)}, retries=0)
    assert tr.end_reason == "gone" and tr.history[-1]["step"] == 5


def test_no_baseline_reply_ends_track():
    tr, _ = run(CounterHost(life_s=1e9), lose={(0, 0)}, retries=0)
    assert tr.end_reason == "no_baseline" and len(tr.history) == 1
    assert summarize(tr.history)["label"] == "unknown"


def test_inconsistent_when_survives_longer_gap_than_a_reset():
    steps = [{"step": 0, "planned_gap": 0, "outcome": "baseline", "clean": 0}]
    for i, (g, o) in enumerate([(1, "survived"), (2, "reset"), (4, "survived")], 1):
        steps.append({"step": i, "planned_gap": g, "outcome": o, "clean": 1})
    s = summarize(steps)
    assert s["label"] == "1-2" and s["consistent"] == 0


def _rows(cat_by_ip_ptype):
    return [{"target": ip, "ptype": p, "category": c} for (ip, p), c in cat_by_ip_ptype.items()]


def test_pick_sample_per_group_seeded_and_deduplicated():
    rand_rows = _rows({(f"203.0.113.{i}", "icmp"): "per_dest" for i in range(50)}
                      | {("203.0.113.1", "syn"): "per_dest", ("203.0.113.2", "syn"): "global"})
    tranco_rows = _rows({(f"198.51.100.{i}", "synack"): "per_dest" for i in range(5)}
                        | {("203.0.113.3", "icmp"): "per_dest"})   # also in the random run
    runs = [{"group": "random", "dport": 80, "rows": rand_rows},
            {"group": "tranco", "dport": 443, "rows": tranco_rows}]
    a = pick_sample(runs, per_group=10, seed=7)
    assert a == pick_sample(runs, per_group=10, seed=7)
    groups = [g for _, g, _, _ in a]
    assert groups.count("random") == 10 and groups.count("tranco") == 5
    assert len({ip for ip, *_ in a}) == len(a)
    ptypes = {ip: p for ip, _, _, p in a}
    if "203.0.113.1" in ptypes:
        assert ptypes["203.0.113.1"] == ["icmp", "syn"]
    assert all(d == 443 for _, g, d, _ in a if g == "tranco")
    # exclusion list and probe-type filter
    b = pick_sample(runs, per_group=100, excl={"203.0.113.5"}, types={"icmp"})
    assert "203.0.113.5" not in {ip for ip, *_ in b}
    assert all(p == ["icmp"] for *_, p in b)


def test_summary_from_steps_file(tmp_path):
    tr, _ = run(CounterHost(life_s=5 * MIN))
    rows = [dict(r, run_id="x", unit="min") for r in tr.history]
    path = tmp_path / "lifetime_steps.csv"
    write_csv(rows, path, STEP_FIELDS)
    with open(path, newline="") as f:
        assert next(csv.reader(f)) == STEP_FIELDS
    out = summarize_steps_file(path, {("198.51.100.7", "icmp"): "finished"})
    assert len(out) == 1 and out[0]["label"] == "4-8" and out[0]["end_reason"] == "finished"
