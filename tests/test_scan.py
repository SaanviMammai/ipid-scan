"""Tests for the scan scheduler and Tranco one-IP-per-domain choice (no root needed)."""
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ipid.schedule import Interleaver, stagger_for  # noqa: E402
from ipid.targets import make_excluder, one_ip_per_domain  # noqa: E402


def simulate(n_targets, per_target, gap, max_pps, send_cost=0.0):
    """Run the scheduler against a fake clock. Returns {target: [send times]}."""
    plists = [[(t, i) for i in range(per_target)] for t in range(n_targets)]
    clock = 0.0
    sched = Interleaver(plists, gap, stagger_for(per_target, max_pps), clock)
    sent = defaultdict(list)
    min_interval = 1.0 / max_pps          # what the token bucket enforces
    last_start = -1e9
    while True:
        item = sched.pop(clock)
        if item is None:
            break
        due, plist, idx = item
        start = max(clock, due, last_start + min_interval)  # token bucket spacing
        last_start = start
        clock = start + send_cost
        t, i = plist[idx]
        sent[t].append((i, clock))
        sched.done(plist, idx, clock)
    return sent, clock


def test_every_probe_sent_once_in_order():
    sent, _ = simulate(200, 30, 0.15, 500)
    assert len(sent) == 200
    for seq in sent.values():
        assert [i for i, _ in seq] == list(range(30))


def test_per_target_spacing_at_least_gap():
    sent, _ = simulate(200, 30, 0.15, 500)
    for seq in sent.values():
        times = [t for _, t in seq]
        assert min(b - a for a, b in zip(times, times[1:])) >= 0.15 - 1e-9


def test_rate_close_to_cap_but_not_over():
    n, per, pps = 500, 30, 500
    sent, end = simulate(n, per, 0.15, pps)
    rate = n * per / end
    assert 0.8 * pps < rate <= pps * 1.001


def test_spacing_stays_near_gap_not_much_larger():
    # Interleaving must not stretch a target's probes far beyond the gap.
    sent, _ = simulate(300, 30, 0.15, 500)
    worst = max(max(b - a for (_, a), (_, b) in zip(seq, seq[1:])) for seq in sent.values())
    assert worst < 0.15 * 2


def test_slow_sender_does_not_explode():
    # If each send takes 4 ms (250 pps max), targets just start later: total time
    # is about all sends back to back plus the last target's own probe spacing.
    sent, end = simulate(100, 30, 0.15, 500, send_cost=0.004)
    assert len(sent) == 100 and end < 100 * 30 * 0.004 + 30 * 0.15 + 1


def test_empty():
    assert Interleaver([], 0.15, 0.1, 0).pop(0) is None


# --- one IP per domain ---------------------------------------------------------

def test_one_ip_per_domain_and_shared_reuse():
    excl = make_excluder()
    rows = [
        {"rank": 1, "domain": "big.com", "ips": ["1.1.1.1", "1.1.1.2", "1.1.1.3"]},
        {"rank": 2, "domain": "cdn-user.com", "ips": ["9.9.9.9", "1.1.1.2", "1.1.1.1"]},
        {"rank": 3, "domain": "private.com", "ips": ["10.0.0.1"]},
        {"rank": 4, "domain": "none.com", "ips": []},
        {"rank": 5, "domain": "small.org", "ips": ["8.8.4.4"]},
    ]
    t = one_ip_per_domain(rows, 4402, excl)
    assert len(t) == 2                       # big.com's pick reused by cdn-user.com
    assert t[0]["domains"] == "big.com;cdn-user.com" and t[0]["n_domains"] == 2
    assert t[0]["ip"].startswith("1.1.1.")
    assert t[1] == {"ip": "8.8.4.4", "best_rank": 5, "n_domains": 1, "domains": "small.org"}


def test_one_ip_per_domain_top_and_seed():
    excl = make_excluder()
    rows = [{"rank": r, "domain": f"d{r}.com", "ips": [f"5.{r}.0.1", f"5.{r}.0.2"]}
            for r in range(1, 21)]
    assert len(one_ip_per_domain(rows, 1, excl, top=10)) == 10
    assert one_ip_per_domain(rows, 1, excl) == one_ip_per_domain(rows, 1, excl)
