"""Classify IP-ID sequences into mechanisms (design doc, section 4 "Classification").

Each (target, probe type) is classified on its own, because one host can use
different mechanisms for ICMP and TCP (the 11/24 testbed showed exactly that).

A "small step" is an increase of 1..T, mod 65536. T starts at 1000 and is tuned
in the pilot. When replies are missing, the allowed step grows with the number
of probe slots skipped, so one lost packet doesn't turn a counter into "random".

Rules, checked in this order:
    unknown   fewer than `min_per_src` replies from A or from B
    constant  every IP-ID is the same value (usually 0, often with DF set)
    global    in send order (A, B, A, B, ...), every reply is a small step
              above the previous reply, whichever source got it
    per_dest  A's replies are small steps on their own, and so are B's,
              but they don't fit together as one sequence
    random    none of the above
If global/per_dest fails on the raw values, it is retried on byte-swapped
values (counters that step by 256), and `byteswapped` is set.

This module only uses the standard library, so tests run without scapy or root.
"""
import csv
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from statistics import median

MOD = 65536
DEFAULT_T = 1000
DEFAULT_MIN_PER_SRC = 3
FULL_SET_START = 100  # probe_one.py: nums 0..99 are discovery probes

CATEGORIES = ("constant", "global", "per_dest", "random", "unknown")


@dataclass(frozen=True)
class Obs:
    """One reply, placed by where its probe sat in the send order."""
    k: int          # probe position within this probe type (0..per_type-1)
    src: str        # "A" or "B"
    ipid: int
    df: int = 0


@dataclass
class Result:
    category: str
    n_replies: int = 0
    n_a: int = 0
    n_b: int = 0
    byteswapped: bool = False
    const_value: int | None = None
    df_frac: float | None = None
    max_step_all: int | None = None      # largest step between consecutive replies
    max_step_same: int | None = None     # largest step between replies to the same source
    median_step_same: float | None = None
    reason: str = ""
    extra: dict = field(default_factory=dict)


def step(a, b):
    """Increase from IP-ID a to IP-ID b, allowing for wraparound at 65536."""
    return (b - a) % MOD


def swap16(x):
    """Swap the two bytes of a 16-bit value (for little-endian counters)."""
    return ((x & 0xFF) << 8) | (x >> 8)


def _steps(seq):
    return [step(p.ipid, c.ipid) for p, c in zip(seq, seq[1:])]


def _is_chain(seq, T, slots):
    """True if every reply is a small step above the previous one.

    slots(prev, cur) is how many probe slots apart the two replies are; the
    limit is T per slot, so a missing reply in between doubles the allowance.
    """
    for p, c in zip(seq, seq[1:]):
        d = step(p.ipid, c.ipid)
        if not 0 < d <= T * slots(p, c):
            return False
    return True


def _slots_all(p, c):
    return max(1, c.k - p.k)


def _slots_same(p, c):
    # Same-source probes are every other slot (A, B, A, B ...).
    return max(1, (c.k - p.k) // 2)


def _mechanism(obs, a, b, T):
    if _is_chain(obs, T, _slots_all):
        return "global"
    if _is_chain(a, T, _slots_same) and _is_chain(b, T, _slots_same):
        return "per_dest"
    return None


def classify(observations, T=DEFAULT_T, min_per_src=DEFAULT_MIN_PER_SRC):
    """Classify one (target, probe type). `observations` is an iterable of Obs."""
    obs = sorted(observations, key=lambda o: o.k)
    a = [o for o in obs if o.src == "A"]
    b = [o for o in obs if o.src == "B"]
    r = Result("unknown", n_replies=len(obs), n_a=len(a), n_b=len(b))
    if obs:
        r.df_frac = sum(o.df for o in obs) / len(obs)
        all_steps = _steps(obs)
        same_steps = _steps(a) + _steps(b)
        r.max_step_all = max(all_steps) if all_steps else None
        r.max_step_same = max(same_steps) if same_steps else None
        r.median_step_same = median(same_steps) if same_steps else None

    if len(a) < min_per_src or len(b) < min_per_src:
        r.reason = f"only {len(a)} replies to A and {len(b)} to B (need {min_per_src} each)"
        return r

    values = {o.ipid for o in obs}
    if len(values) == 1:
        r.category, r.const_value = "constant", obs[0].ipid
        r.reason = f"all IP-IDs = {r.const_value}"
        return r

    found = _mechanism(obs, a, b, T)
    if found is not None:
        # A byte-swapped counter stepping by 1-3 shows raw steps of 256-768,
        # which already pass as "small"; catch it by the multiples of 256.
        chain_steps = _steps(obs) if found == "global" else _steps(a) + _steps(b)
        r.byteswapped = all(d % 256 == 0 for d in chain_steps)
    else:
        sw = lambda seq: [replace(o, ipid=swap16(o.ipid)) for o in seq]  # noqa: E731
        found = _mechanism(sw(obs), sw(a), sw(b), T)
        r.byteswapped = found is not None
    if found:
        r.category = found
        r.reason = ("one shared sequence" if found == "global"
                    else "separate sequences for A and B") + \
                   (" (byte-swapped)" if r.byteswapped else "")
        return r

    r.category = "random"
    if len({o.ipid for o in a}) == 1 and len({o.ipid for o in b}) == 1:
        r.reason = "constant per source but different values for A and B"
    else:
        r.reason = f"steps too large (largest same-source step {r.max_step_same} > T={T})"
    return r


# ---------------------------------------------------------------------------
# Reading probe runs (data/raw/<run_id>/sent.csv + replies.csv)
# ---------------------------------------------------------------------------

def _to_int(v):
    if v in (None, ""):
        return 0
    if str(v).lower() in ("true", "false"):
        return int(str(v).lower() == "true")
    return int(float(v))


def load_run(run_dir, full_set_start=FULL_SET_START):
    """Join sent.csv and replies.csv on (target, ptype, num).

    Returns {(target, ptype): {"n_sent": int, "obs": [Obs, ...], "run_id": str}}.
    Only probes with num >= full_set_start are used (discovery probes are skipped).
    If a probe got several replies, the earliest one counts.
    """
    run_dir = Path(run_dir)
    sent = {}
    groups = {}
    with open(run_dir / "sent.csv", newline="") as f:
        for row in csv.DictReader(f):
            num = int(row["num"])
            if num < full_set_start:
                continue
            key = (row["target"], row["ptype"], num)
            sent[key] = row
            g = groups.setdefault((row["target"], row["ptype"]),
                                  {"n_sent": 0, "obs": [], "run_id": row["run_id"]})
            g["n_sent"] += 1

    first = {}
    with open(run_dir / "replies.csv", newline="") as f:
        for row in csv.DictReader(f):
            key = (row["target"], row["ptype"], int(row["num"]))
            if key not in sent:
                continue
            t = float(row.get("t_recv") or 0)
            if key not in first or t < first[key][0]:
                first[key] = (t, row)

    for key, (_, rep) in first.items():
        s = sent[key]
        groups[key[:2]]["obs"].append(Obs(k=int(s["k"]), src=s["src_label"],
                                          ipid=_to_int(rep["ipid"]),
                                          df=_to_int(rep.get("df"))))
    return groups


OUT_FIELDS = ["run_id", "target", "ptype", "n_sent", "n_replies", "n_a", "n_b",
              "category", "byteswapped", "const_value", "df_frac", "max_step_all",
              "max_step_same", "median_step_same", "T", "reason"]


def classify_run(run_dir, T=DEFAULT_T, min_per_src=DEFAULT_MIN_PER_SRC,
                 full_set_start=FULL_SET_START):
    """Classify every (target, ptype) in one run. Returns a list of dict rows."""
    rows = []
    for (target, ptype), g in sorted(load_run(run_dir, full_set_start).items()):
        res = asdict(classify(g["obs"], T, min_per_src))
        res.pop("extra")
        rows.append({"run_id": g["run_id"], "target": target, "ptype": ptype,
                     "n_sent": g["n_sent"], "T": T, **res})
    return rows


def write_rows(rows, path):
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, OUT_FIELDS, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)
