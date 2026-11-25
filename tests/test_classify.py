"""Classifier tests on made-up sequences (design doc section 5), plus the
11/24 netns testbed values pushed through the CSV path."""
import csv
import random
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ipid.classify import (MOD, Obs, classify, classify_run, step,  # noqa: E402
                           swap16)

N = 10  # probes per type, alternating A, B, A, B ...


def src(k):
    return "A" if k % 2 == 0 else "B"


def seq(ipids, df=0, drop=()):
    """Turn a list of IP-IDs (one per probe slot) into observations."""
    return [Obs(k, src(k), v % MOD, df) for k, v in enumerate(ipids) if k not in drop]


def global_ids(start, rng, lo=1, hi=50):
    """One shared counter; background traffic adds lo..hi between our probes."""
    out, c = [], start
    for _ in range(N):
        c += rng.randint(lo, hi)
        out.append(c)
    return out


def per_dest_ids(start_a, start_b, rng, lo=1, hi=300):
    """Separate counters for A and B, Linux-style random increments."""
    c = {"A": start_a, "B": start_b}
    out = []
    for k in range(N):
        c[src(k)] += rng.randint(lo, hi)
        out.append(c[src(k)])
    return out


@pytest.fixture
def rng():
    return random.Random(4402)


# --- helpers ---------------------------------------------------------------

def test_step_wraps_around():
    assert step(65530, 4) == 10
    assert step(4, 65530) == 65526
    assert step(100, 100) == 0


def test_swap16():
    assert swap16(0x1234) == 0x3412
    assert swap16(swap16(0xBEEF)) == 0xBEEF


# --- the five categories ---------------------------------------------------

def test_global(rng):
    r = classify(seq(global_ids(1000, rng)))
    assert r.category == "global" and not r.byteswapped


def test_per_dest(rng):
    r = classify(seq(per_dest_ids(15000, 40000, rng)))
    assert r.category == "per_dest"
    assert r.max_step_all > 1000 >= r.max_step_same


def test_random(rng):
    r = classify(seq([rng.randrange(MOD) for _ in range(N)]))
    assert r.category == "random"


def test_constant_zero_with_df():
    r = classify(seq([0] * N, df=1))
    assert (r.category, r.const_value, r.df_frac) == ("constant", 0, 1.0)


def test_constant_nonzero():
    r = classify(seq([12345] * N))
    assert (r.category, r.const_value) == ("constant", 12345)


def test_unknown_when_b_silent(rng):
    r = classify(seq(global_ids(1000, rng), drop={1, 3, 5, 7, 9}))
    assert r.category == "unknown" and r.n_a == 5 and r.n_b == 0


def test_unknown_with_two_replies_from_one_source(rng):
    r = classify(seq(global_ids(1000, rng), drop={1, 3, 5}))
    assert r.category == "unknown" and r.n_b == 2


def test_unknown_with_no_replies():
    r = classify([])
    assert r.category == "unknown" and r.n_replies == 0


# --- wraparound ------------------------------------------------------------

def test_global_wraps_past_65535(rng):
    ids = global_ids(65400, rng, 20, 40)
    assert max(i % MOD for i in ids) > 65000 and min(i % MOD for i in ids) < 1000
    assert classify(seq(ids)).category == "global"


def test_per_dest_wraps_past_65535(rng):
    assert classify(seq(per_dest_ids(65300, 30000, rng))).category == "per_dest"


# --- missing replies -------------------------------------------------------

def test_global_survives_missing_replies(rng):
    # Steps of 600 per slot: two consecutive replies missing means a jump of
    # 1800 between received replies, which is allowed (T per slot).
    ids = [1000 + 600 * k for k in range(N)]
    r = classify(seq(ids, drop={3, 4}))
    assert r.category == "global" and r.n_replies == 8


def test_per_dest_survives_missing_replies(rng):
    ids = per_dest_ids(5000, 50000, rng, 300, 700)
    assert classify(seq(ids, drop={2, 7})).category == "per_dest"


# --- byte-swapped counters -------------------------------------------------

def test_byteswapped_slow_counter_flagged():
    # Counter +1 per probe stored little-endian: raw steps are exactly 256.
    ids = [swap16(500 + k) for k in range(N)]
    r = classify(seq(ids))
    assert r.category == "global" and r.byteswapped


def test_byteswapped_fast_counter_found_by_retry(rng):
    # Counter +5..20 per probe: raw steps 1280+, so only the swapped retry fits.
    ids = [swap16(v % MOD) for v in global_ids(3000, rng, 5, 20)]
    r = classify(seq(ids))
    assert r.category == "global" and r.byteswapped


def test_byteswapped_per_dest(rng):
    ids = [swap16(v % MOD) for v in per_dest_ids(2000, 20000, rng, 5, 20)]
    r = classify(seq(ids))
    assert r.category == "per_dest" and r.byteswapped


# --- known limits and edge cases (documented behaviour) ----------------------

def test_busy_global_counter_looks_random():
    # A host sending >T packets between our probes can't be told from random.
    # Design doc section 9 accepts this; the pilot tunes T to keep it rare.
    ids = [1000 + 2500 * k for k in range(N)]
    assert classify(seq(ids)).category == "random"


def test_raising_T_changes_the_answer(rng):
    ids = per_dest_ids(5000, 40000, rng, 1100, 1500)
    assert classify(seq(ids), T=1000).category == "random"
    assert classify(seq(ids), T=2000).category == "per_dest"


def test_constant_per_source_but_different():
    ids = [7 if src(k) == "A" else 9 for k in range(N)]
    r = classify(seq(ids))
    assert r.category == "random" and "constant per source" in r.reason


def test_order_of_input_does_not_matter(rng):
    obs = seq(global_ids(1000, rng))
    assert classify(list(reversed(obs))).category == "global"


def test_random_sequences_are_not_misclassified():
    rng = random.Random(1)
    wrong = sum(classify(seq([rng.randrange(MOD) for _ in range(N)])).category != "random"
                for _ in range(10000))
    assert wrong == 0


# --- 11/24 testbed run, through sent.csv / replies.csv ---------------------

TESTBED_ICMP = [15237, 25850, 15503, 25893, 15603, 25946, 15704, 26219, 15838, 26435]


def write_run(run_dir, target, types):
    """types: {ptype: (ipids, df)} for the full set; adds discovery and a duplicate."""
    run_dir.mkdir()
    with open(run_dir / "sent.csv", "w", newline="") as fs, \
         open(run_dir / "replies.csv", "w", newline="") as fr:
        _write_run(csv.writer(fs), csv.writer(fr), target, types)


def _write_run(sent, rep, target, types):
    sent.writerow(["run_id", "target", "ptype", "num", "k", "src_label", "src_ip",
                   "dport", "t_send"])
    rep.writerow(["run_id", "target", "ptype", "num", "dst_ip", "t_recv", "ipid",
                  "ttl", "df", "flags", "ip_len"])
    srcip = {"A": "10.99.0.1", "B": "10.99.0.2"}
    # Discovery probes (num < 100) with junk IP-IDs that must be ignored.
    for i, p in enumerate(types):
        sent.writerow(["run1", target, p, i, 0, "A", srcip["A"], 80, 0.0])
        rep.writerow(["run1", target, p, i, srcip["A"], 0.01, 999, 64, 0, "", 28])
    num = 100
    for p, (ids, df) in types.items():
        for k, v in enumerate(ids):
            t = 1 + num * 0.15
            sent.writerow(["run1", target, p, num, k, src(k), srcip[src(k)], 80, t])
            if v is not None:
                rep.writerow(["run1", target, p, num, srcip[src(k)], t + 0.001, v,
                              64, df, "", 40])
            num += 1
    # Duplicate of the first ICMP reply, arriving later with another IP-ID.
    rep.writerow(["run1", target, "icmp", 100, srcip["A"], 99.0, 1, 64, 0, "", 28])


def test_testbed_run_from_csv(tmp_path):
    run = tmp_path / "20261125-175614"
    write_run(run, "10.99.0.10", {
        "icmp": (TESTBED_ICMP, 0),
        "syn": ([0] * N, 1),
        "synack": ([0] * N, 1),
    })
    rows = {r["ptype"]: r for r in classify_run(run)}
    assert rows["icmp"]["category"] == "per_dest"
    assert rows["icmp"]["n_sent"] == rows["icmp"]["n_replies"] == 10
    assert rows["icmp"]["max_step_same"] == 273
    assert rows["syn"]["category"] == rows["synack"]["category"] == "constant"
    assert rows["syn"]["df_frac"] == 1.0


def test_missing_replies_from_csv(tmp_path):
    run = tmp_path / "r"
    ids = TESTBED_ICMP[:]
    ids[4] = ids[7] = None
    write_run(run, "10.99.0.10", {"icmp": (ids, 0)})
    (row,) = classify_run(run)
    assert (row["n_sent"], row["n_replies"], row["category"]) == (10, 8, "per_dest")
