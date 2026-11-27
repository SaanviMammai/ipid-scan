"""Counter lifetime test (RQ2, design doc section 4 "Counter lifetime").

For a sample of per-destination hosts, record the current IP-ID seen by source A,
then re-probe only from A after idle gaps of 1, 2, 4, 8, 16, 32 and 64 minutes.
Each gap is measured from the previous probe, because every probe refreshes the
host's counter. Hosts whose counter survived the 64-minute gap get two more
gaps, 128 and 256 minutes; anything still alive is reported as "> 256 min".

Each re-probe is compared with the previous reply:
    survived   0 < jump <= T      the counter kept counting through the idle time
    reset      jump > T            new counter, or a large time-based increment
    no_change  jump == 0           odd for a counter; kept but not used
    no_reply   nothing came back after all tries
Every jump is also recorded against the idle time, because some systems (Linux)
add a random increment that grows with idle time instead of resetting.

A (target, probe type) pair is one "track". A host that is per-destination for
two probe types gives two tracks, measured side by side.

This module only uses the standard library, so tests run without scapy or root.
"""
from __future__ import annotations  # allows "int | None" on Python 3.9

import csv
import random
from dataclasses import dataclass, field
from pathlib import Path

from .classify import DEFAULT_T, step

DEFAULT_GAPS_MIN = (1, 2, 4, 8, 16, 32, 64)
DEFAULT_EXTEND_MIN = (128, 256)
DEFAULT_PER_GROUP = 300   # ~500 needed; extra because some hosts drop out
DEFAULT_RETRIES = 2       # extra tries when a probe gets no reply
DEFAULT_RETRY_S = 3.0
DEFAULT_MAX_MISSES = 2    # consecutive unanswered steps before a host counts as gone

STEP_FIELDS = ["run_id", "group", "target", "ptype", "step", "planned_gap", "unit",
               "gap_s", "t_send", "tries", "ipid_prev", "ipid", "jump", "outcome",
               "clean"]
SUMMARY_FIELDS = ["group", "target", "ptype", "n_steps", "n_clean", "n_survived",
                  "n_reset", "n_no_reply", "lower", "upper", "unit", "label",
                  "consistent", "end_reason"]


def judge(prev_ipid, ipid, T=DEFAULT_T):
    """(jump, outcome) for a reply that follows prev_ipid after an idle gap."""
    jump = step(prev_ipid, ipid)
    if jump == 0:
        return 0, "no_change"
    return jump, ("survived" if jump <= T else "reset")


@dataclass
class Track:
    """State of one (target, probe type) through the lifetime schedule."""
    target: str
    ptype: str
    group: str
    dport: int
    gaps: tuple            # planned gaps in `unit`, main schedule
    extend: tuple          # extra gaps, only while the counter keeps surviving
    unit_s: float = 60.0   # seconds per gap unit (60 = minutes)
    T: int = DEFAULT_T
    max_misses: int = DEFAULT_MAX_MISSES
    step: int = 0          # next step to run; step 0 is the baseline
    last_ipid: int | None = None
    last_send: float | None = None   # last probe sent to this track (any try)
    misses: int = 0        # consecutive unanswered steps
    done: bool = False
    end_reason: str = ""
    due: float = 0.0       # when the next step should be sent
    history: list = field(default_factory=list)

    def planned_gap(self, i=None):
        """Planned gap (in gap units) before step i; 0 for the baseline."""
        i = self.step if i is None else i
        if i == 0:
            return 0
        allg = tuple(self.gaps) + tuple(self.extend)
        return allg[i - 1]

    def record(self, t_first, t_last, ipid, tries):
        """Finish the current step.

        t_first: send time of the step's first try (the idle gap ends here);
        t_last: send time of its last try (the next gap starts here);
        ipid: IP-ID of the reply, or None if no try was answered.
        Returns the step's row (dict) and schedules the next step or ends the track.
        """
        i = self.step
        gap_s = None if self.last_send is None else t_first - self.last_send
        row = {"target": self.target, "ptype": self.ptype, "group": self.group,
               "step": i, "planned_gap": self.planned_gap(i), "gap_s": gap_s,
               "t_send": t_first, "tries": tries, "ipid_prev": self.last_ipid,
               "ipid": ipid, "jump": None, "outcome": "", "clean": 0}
        if i == 0:
            if ipid is None:
                row["outcome"] = "no_reply"
                return self._finish(row, "no_baseline")
            row["outcome"] = "baseline"
            self.last_ipid = ipid
        elif ipid is None:
            row["outcome"] = "no_reply"
            self.misses += 1
        else:
            row["jump"], row["outcome"] = judge(self.last_ipid, ipid, self.T)
            # "clean": the previous step was answered, so the jump spans exactly
            # one idle gap. Unclean steps are kept for the jump chart only.
            row["clean"] = int(self.misses == 0)
            self.last_ipid = ipid
            self.misses = 0
        self.last_send = t_last
        self.history.append(row)

        if self.misses >= self.max_misses:
            return self._finish(row, "gone", record=False)
        nxt = i + 1
        if nxt <= len(self.gaps):
            pass
        elif nxt <= len(self.gaps) + len(self.extend) and row["outcome"] == "survived":
            pass
        else:
            return self._finish(row, "finished", record=False)
        self.step = nxt
        self.due = self.last_send + self.planned_gap(nxt) * self.unit_s
        return row

    def _finish(self, row, reason, record=True):
        if record:
            self.history.append(row)
        self.done, self.end_reason = True, reason
        return row


# ---------------------------------------------------------------------------
# Picking the sample
# ---------------------------------------------------------------------------

def pick_sample(runs, per_group=DEFAULT_PER_GROUP, seed=4402, types=None, excl=None):
    """Choose per-destination hosts from classified scan runs.

    runs: list of {"group": str, "dport": int, "rows": [classified.csv rows]}.
    Up to per_group hosts are drawn from each group (random / tranco) with a
    fixed seed. A host found in several runs is used once (first run wins).
    Returns a list of (target, group, dport, [ptypes]) in a seeded random order.
    """
    seen, by_group = {}, {}   # seen[ip] = (run index, group, dport, ptypes)
    for n, run in enumerate(runs):
        for r in run["rows"]:
            if r["category"] != "per_dest" or (types and r["ptype"] not in types):
                continue
            ip = r["target"]
            if excl is not None and ip in excl:
                continue
            if ip not in seen:
                seen[ip] = (n, run["group"], run["dport"], [])
                by_group.setdefault(run["group"], []).append(ip)
            elif seen[ip][0] != n:
                continue  # already taken from an earlier run
            if r["ptype"] not in seen[ip][3]:
                seen[ip][3].append(r["ptype"])
    rng = random.Random(seed)
    out = []
    for group in sorted(by_group):
        ips = sorted(by_group[group])
        chosen = rng.sample(ips, min(per_group, len(ips)))
        out += [(ip, group, seen[ip][2], sorted(seen[ip][3])) for ip in chosen]
    rng.shuffle(out)
    return out


# ---------------------------------------------------------------------------
# Per-track summary
# ---------------------------------------------------------------------------

def summarize(steps, end_reason=""):
    """Lifetime of one track from its step rows (dicts with step/planned_gap/outcome/clean).

    lower: largest idle gap the counter survived below the first reset;
    upper: smallest gap after which it had reset (None = never reset).
    So the lifetime is between lower and upper. consistent = False if the
    counter survived some gap longer than one where it reset (random increments).
    """
    clean = [s for s in steps if int(s.get("step", 0)) > 0 and int(s.get("clean") or 0)]
    surv = [float(s["planned_gap"]) for s in clean if s["outcome"] == "survived"]
    reset = [float(s["planned_gap"]) for s in clean if s["outcome"] == "reset"]
    upper = min(reset) if reset else None
    below = [g for g in surv if upper is None or g < upper]
    lower = max(below) if below else 0.0
    if not surv and not reset:
        label = "unknown"
    elif upper is None:
        label = f">{_fmt(lower)}"
    elif lower == 0:
        label = f"<{_fmt(upper)}"
    else:
        label = f"{_fmt(lower)}-{_fmt(upper)}"
    return {"n_steps": sum(1 for s in steps if int(s.get("step", 0)) > 0),
            "n_clean": len(clean), "n_survived": len(surv), "n_reset": len(reset),
            "n_no_reply": sum(1 for s in steps if s["outcome"] == "no_reply"),
            "lower": lower, "upper": upper, "label": label,
            "consistent": int(upper is None or not any(g > upper for g in surv)),
            "end_reason": end_reason}


def _fmt(g):
    return str(int(g)) if float(g).is_integer() else f"{g:g}"


def summarize_steps_file(path, end_reasons=None):
    """Read lifetime_steps.csv and return one summary row per track."""
    tracks = {}
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            key = (row["group"], row["target"], row["ptype"])
            tracks.setdefault(key, {"unit": row.get("unit", ""), "rows": []})["rows"].append(row)
    out = []
    for (group, target, ptype), t in sorted(tracks.items()):
        rows = sorted(t["rows"], key=lambda r: int(r["step"]))
        reason = (end_reasons or {}).get((target, ptype), "")
        out.append({"group": group, "target": target, "ptype": ptype, "unit": t["unit"],
                    **summarize(rows, reason)})
    return out


def write_csv(rows, path, fields):
    path = Path(path)
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)
