"""Result tables for the report (design doc section 7 "Expected Results").

Reads scan runs (scan_meta.json + classified.csv) and lifetime runs
(lifetime_summary.csv + lifetime_steps.csv) and builds:

  response   targets probed, how many answered discovery, per probe type
  categories hosts per IP-ID category, per group and probe type
             (out of hosts that answered that probe type in the full set)
  combos     how often a host uses different mechanisms for ICMP and TCP
  lifetime   counter lifetime ranges per group and probe type (RQ2)
  jumps      IP-ID jump size against idle time (RQ2, Linux-style increments)

Every table is totals and percentages only, never addresses (design doc section 6).
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pandas as pd

from .classify import CATEGORIES

PTYPES = ("icmp", "syn", "synack")
GROUPS = ("random", "tranco")


def _order(values, preferred):
    """preferred items first (in that order), then any others sorted."""
    values = list(dict.fromkeys(values))
    return [v for v in preferred if v in values] + sorted(v for v in values if v not in preferred)


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------

def load_scans(run_dirs, T=1000, min_per_src=3):
    """Return (metas, classified) for scan run folders.

    classified has one row per (group, target, ptype). If the same target and
    probe type appear in two runs of one group (a pilot and the full scan),
    the run listed last wins.
    """
    metas, frames = [], []
    for d in map(Path, run_dirs):
        meta = json.loads((d / "scan_meta.json").read_text())
        path = d / "classified.csv"
        if path.exists():
            df = pd.read_csv(path, dtype={"target": str})
        else:
            from .classify import classify_run
            df = pd.DataFrame(classify_run(d, T, min_per_src))
        df["group"] = meta["group"]
        metas.append(meta)
        frames.append(df)
    cl = pd.concat(frames, ignore_index=True) if frames else pd.DataFrame()
    if len(cl):
        cl = cl.drop_duplicates(["group", "target", "ptype"], keep="last")
        cl["byteswapped"] = cl["byteswapped"].astype(str).str.lower().isin(["true", "1"])
    return metas, cl


def load_lifetimes(run_dirs):
    """Return (summary, steps) DataFrames from lifetime run folders."""
    sums, steps = [], []
    for d in map(Path, run_dirs):
        sums.append(pd.read_csv(d / "lifetime_summary.csv", dtype={"target": str}))
        steps.append(pd.read_csv(d / "lifetime_steps.csv", dtype={"target": str}))
    if not sums:
        return pd.DataFrame(), pd.DataFrame()
    return pd.concat(sums, ignore_index=True), pd.concat(steps, ignore_index=True)


# ---------------------------------------------------------------------------
# RQ1 tables
# ---------------------------------------------------------------------------

def response_table(metas, classified):
    """One row per group: probed, answered discovery (any / per type), got a full set."""
    rows = {}
    for m in metas:
        g = m["group"]
        r = rows.setdefault(g, {"group": g, "probed": 0, "responded": 0,
                                **{f"responded_{p}": 0 for p in PTYPES}})
        r["probed"] += m["n_targets"]
        r["responded"] += m["responders"]
        for p, n in m.get("responders_by_type", {}).items():
            r[f"responded_{p}"] = r.get(f"responded_{p}", 0) + n
    out = pd.DataFrame([rows[g] for g in _order(rows, GROUPS)])
    if out.empty:
        return out
    out["responded_pct"] = 100 * out["responded"] / out["probed"].where(out["probed"] > 0)
    for p in PTYPES:
        out[f"responded_{p}_pct"] = 100 * out[f"responded_{p}"] / out["probed"].where(
            out["probed"] > 0)
    if len(classified):
        full = (classified[classified["n_replies"] > 0].groupby("group")["target"]
                .nunique().rename("full_set_replied"))
        out = out.merge(full, on="group", how="left").fillna({"full_set_replied": 0})
        out["full_set_replied"] = out["full_set_replied"].astype(int)
    return out


def category_table(classified):
    """Hosts per category for each (group, ptype), out of hosts that replied to that type.

    Long format: group, ptype, category, hosts, pct, plus per (group, ptype)
    totals: replied (the denominator), no_reply, byteswapped.
    """
    if classified.empty:
        return pd.DataFrame(columns=["group", "ptype", "category", "hosts", "pct"])
    c = classified
    replied = c[c["n_replies"] > 0]
    rows = []
    for g in _order(c["group"], GROUPS):
        for p in _order(c["ptype"], PTYPES):
            sel = replied[(replied["group"] == g) & (replied["ptype"] == p)]
            allp = c[(c["group"] == g) & (c["ptype"] == p)]
            if allp.empty:
                continue
            n = len(sel)
            for cat in CATEGORIES:
                k = int((sel["category"] == cat).sum())
                rows.append({"group": g, "ptype": p, "category": cat, "hosts": k,
                             "pct": 100 * k / n if n else float("nan"), "replied": n,
                             "no_reply": int(len(allp) - n),
                             "byteswapped": int(sel["byteswapped"].sum())})
    return pd.DataFrame(rows)


def category_wide(cat_long, value="pct"):
    """Pivot category_table to one row per (group, ptype), one column per category."""
    if cat_long.empty:
        return cat_long
    w = cat_long.pivot_table(index=["group", "ptype"], columns="category", values=value,
                             sort=False).reindex(columns=list(CATEGORIES))
    meta = cat_long.groupby(["group", "ptype"], sort=False)[["replied", "no_reply",
                                                            "byteswapped"]].first()
    return w.join(meta).reset_index()


def combo_table(classified, top=10):
    """Most common mechanism combinations across probe types, per group.

    Only hosts that got a clear (non-unknown) category for at least two probe types.
    'mixed' is True when those categories differ, e.g. ICMP per_dest but TCP constant.
    """
    if classified.empty:
        return pd.DataFrame(columns=["group", "combo", "hosts", "pct", "mixed"])
    c = classified[(classified["n_replies"] > 0) & (classified["category"] != "unknown")]
    rows = []
    for g in _order(c["group"], GROUPS):
        per_host = (c[c["group"] == g].pivot_table(index="target", columns="ptype",
                                                   values="category", aggfunc="first"))
        cols = _order(per_host.columns, PTYPES)
        per_host = per_host[cols]
        per_host = per_host[per_host.notna().sum(axis=1) >= 2]
        if per_host.empty:
            continue
        combos = per_host.apply(
            lambda r: ", ".join(f"{p}={r[p]}" for p in cols if pd.notna(r[p])), axis=1)
        mixed = per_host.apply(lambda r: r.dropna().nunique() > 1, axis=1)
        vc = combos.value_counts()
        n = len(per_host)
        for combo, k in vc.head(top).items():
            rows.append({"group": g, "combo": combo, "hosts": int(k), "pct": 100 * k / n,
                         "mixed": bool(mixed[combos == combo].iloc[0]), "of_hosts": n})
        rows.append({"group": g, "combo": "(any mixed combination)",
                     "hosts": int(mixed.sum()), "pct": 100 * mixed.sum() / n,
                     "mixed": True, "of_hosts": n})
    return pd.DataFrame(rows)


# ---------------------------------------------------------------------------
# RQ2 tables
# ---------------------------------------------------------------------------

CENSORED = "dropped out"


def _label_key(label):
    """Sort key for lifetime labels: '<1' < '1-2' < ... < '>256' < unknown."""
    if label == "unknown":
        return (3, 0)
    if label == CENSORED:
        return (4, 0)
    nums = [float(x) for x in re.findall(r"[\d.]+", label)]
    if label.startswith("<"):
        return (0, nums[0])
    if label.startswith(">"):
        return (2, nums[0])
    return (1, nums[0])


def lifetime_bin(row, max_gap):
    """Report label. A track reported as '>x' with x below the longest gap stopped
    early (host vanished, a reply was lost near the end, or the run was
    interrupted): it only gives a lower bound, so it is kept apart."""
    lab = str(row["label"])
    if lab.startswith(">"):
        try:
            if float(lab[1:]) < max_gap:
                return CENSORED
        except ValueError:
            pass
    return lab


def lifetime_table(summary, max_gap=None):
    """Tracks per lifetime range, per (group, ptype), with percentages."""
    if summary.empty:
        return pd.DataFrame(columns=["group", "ptype", "lifetime", "tracks", "pct"])
    s = summary.copy()
    if max_gap is None:
        ups = pd.to_numeric(s["upper"], errors="coerce")
        lows = pd.to_numeric(s["lower"], errors="coerce")
        max_gap = float(pd.concat([ups, lows]).max())
    s["lifetime"] = s.apply(lambda r: lifetime_bin(r, max_gap), axis=1)
    rows = []
    for g in _order(s["group"], GROUPS):
        for p in _order(s["ptype"], PTYPES):
            sel = s[(s["group"] == g) & (s["ptype"] == p)]
            if sel.empty:
                continue
            for lab in sorted(sel["lifetime"].unique(), key=_label_key):
                k = int((sel["lifetime"] == lab).sum())
                rows.append({"group": g, "ptype": p, "lifetime": lab, "tracks": k,
                             "pct": 100 * k / len(sel), "of_tracks": len(sel),
                             "unit": sel["unit"].iloc[0]})
    return pd.DataFrame(rows)


def jump_table(steps, T=1000):
    """Jump size per planned idle gap, per (group, ptype): clean re-probes only."""
    if steps.empty:
        return pd.DataFrame()
    st = steps[(steps["step"] > 0) & (steps["clean"] == 1) & steps["jump"].notna()].copy()
    st["jump"] = st["jump"].astype(int)
    rows = []
    for (g, p, gap), sel in st.groupby(["group", "ptype", "planned_gap"]):
        j = sel["jump"]
        rows.append({"group": g, "ptype": p, "idle_gap": gap, "unit": sel["unit"].iloc[0],
                     "n": len(j), "median_jump": float(j.median()),
                     "p90_jump": float(j.quantile(0.9)), "max_jump": int(j.max()),
                     "survived_pct": 100 * float((j <= T).mean())})
    out = pd.DataFrame(rows)
    out["_g"] = out["group"].map({g: i for i, g in enumerate(GROUPS)}).fillna(9)
    out["_p"] = out["ptype"].map({p: i for i, p in enumerate(PTYPES)}).fillna(9)
    return out.sort_values(["_g", "_p", "idle_gap"]).drop(columns=["_g", "_p"])


# ---------------------------------------------------------------------------
# Markdown for the report
# ---------------------------------------------------------------------------

def to_markdown(df, floatfmt=".1f"):
    """Plain markdown table (no extra dependency)."""
    if df is None or df.empty:
        return "_no data_\n"
    cols = list(df.columns)

    def fmt(v):
        if isinstance(v, float):
            return "–" if pd.isna(v) else format(v, floatfmt)
        return str(v)
    lines = ["| " + " | ".join(map(str, cols)) + " |",
             "|" + "|".join("---" for _ in cols) + "|"]
    lines += ["| " + " | ".join(fmt(v) for v in row) + " |"
              for row in df.itertuples(index=False)]
    return "\n".join(lines) + "\n"
