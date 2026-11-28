"""Static charts (PNG) for the report, drawn with matplotlib.

Colors are the validated categorical palette (colorblind-safe in adjacent order);
"unknown" is a neutral gray because it is not a mechanism. Every segment that is
wide enough carries its percentage, and every chart has a legend, so no value
depends on color alone. The exact numbers are also in the CSV tables.
"""
from __future__ import annotations

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

from .analysis import CENSORED, GROUPS, PTYPES, _label_key  # noqa: E402

TEXT, TEXT2, GRID, SURFACE = "#191919", "#666666", "#e6e6e6", "#ffffff"
CAT_COLORS = {"constant": "#257de0", "global": "#f47230", "per_dest": "#00b894",
              "random": "#f2a600", "unknown": "#a3a3a3"}
CAT_NAMES = {"constant": "Zero/constant", "global": "Global", "per_dest": "Per-destination",
             "random": "Random", "unknown": "Unknown"}
# label ink inside each fill: white on the dark blue, near-black on the light fills
CAT_INK = {"constant": "#ffffff", "global": TEXT, "per_dest": TEXT, "random": TEXT,
           "unknown": TEXT}
GROUP_COLORS = {"random": "#257de0", "tranco": "#f47230"}
GROUP_NAMES = {"random": "Random IPs", "tranco": "Tranco top sites"}
PTYPE_NAMES = {"icmp": "ICMP echo", "syn": "TCP SYN", "synack": "TCP SYN/ACK"}


def _style():
    plt.rcParams.update({
        "font.family": "DejaVu Sans", "font.size": 10, "text.color": TEXT,
        "axes.labelcolor": TEXT2, "axes.edgecolor": GRID, "xtick.color": TEXT2,
        "ytick.color": TEXT2, "axes.spines.top": False, "axes.spines.right": False,
        "figure.facecolor": SURFACE, "axes.facecolor": SURFACE, "savefig.dpi": 200,
        "legend.frameon": False,
    })


def _title(fig, title, subtitle, note=""):
    """Title, subtitle and an optional second line (e.g. 'simulated data')."""
    fig.text(0.01, 0.985, title, fontsize=13, fontweight="bold", color=TEXT, va="top")
    fig.text(0.01, 0.935, subtitle, fontsize=9.5, color=TEXT2, va="top")
    if note:
        fig.text(0.01, 0.935 - 0.33 / fig.get_size_inches()[1], note, fontsize=9.5,
                 color="#b3261e", fontweight="bold", va="top")


def _gname(g, names):
    return (names or {}).get(g, GROUP_NAMES.get(g, g))


def _top_shift(note, h):
    """Extra headroom (as a fraction of figure height) when a note line is drawn."""
    return 0.33 / h if note else 0.0


def lifetime_bins(gaps, present=()):
    """Every lifetime range the gap schedule can produce, in order, so empty ranges
    still get a slot on the x-axis: '<g1', 'g1-g2', ..., '>gN', then any extra
    labels seen in the data ('dropped out', 'unknown')."""
    from ipid.lifetime import _fmt
    gaps = sorted({float(g) for g in gaps if float(g) > 0})
    bins = []
    if gaps:
        bins.append(f"<{_fmt(gaps[0])}")
        bins += [f"{_fmt(a)}-{_fmt(b)}" for a, b in zip(gaps, gaps[1:])]
        bins.append(f">{_fmt(gaps[-1])}")
    extra = [b for b in present if b not in bins]
    return bins + sorted(extra, key=_label_key)


def category_chart(cat_long, path, names=None, note=""):
    """100% stacked horizontal bars: one per (group, probe type)."""
    _style()
    bars = []
    for g in [g for g in GROUPS if g in set(cat_long["group"])] + \
             sorted(set(cat_long["group"]) - set(GROUPS)):
        for p in [p for p in PTYPES if p in set(cat_long["ptype"])]:
            sel = cat_long[(cat_long["group"] == g) & (cat_long["ptype"] == p)]
            if len(sel) and sel["replied"].iloc[0] > 0:
                bars.append((g, p, sel.set_index("category")))
    if not bars:
        return None
    # leave a blank row between groups
    ys, labels, y, prev = [], [], 0, None
    for g, p, _ in bars:
        if prev is not None and g != prev:
            y += 0.6
        ys.append(y)
        labels.append(f"{_gname(g, names)}  ·  {PTYPE_NAMES.get(p, p)}")
        y += 1
        prev = g
    H = 0.55 * y + 1.9 + (0.33 if note else 0)
    fig, ax = plt.subplots(figsize=(9, H))
    fig.subplots_adjust(left=0.30, right=0.90, top=1 - (1.05 + (0.33 if note else 0)) / H,
                        bottom=0.35 / H)
    for yy, (g, p, sel) in zip(ys, bars):
        left = 0.0
        for cat in CAT_COLORS:
            v = float(sel.loc[cat, "pct"]) if cat in sel.index else 0.0
            if v <= 0:
                continue
            ax.barh(yy, v, left=left, height=0.62, color=CAT_COLORS[cat],
                    edgecolor=SURFACE, linewidth=2)
            if v >= 7:
                ax.text(left + v / 2, yy, f"{v:.0f}%", ha="center", va="center",
                        fontsize=8.5, color=CAT_INK[cat])
            left += v
        ax.text(101.5, yy, f"n={int(sel['replied'].iloc[0]):,}", va="center",
                fontsize=8.5, color=TEXT2)
    ax.set_yticks(ys, labels)
    ax.invert_yaxis()
    ax.set_xlim(0, 100)
    ax.set_xticks(range(0, 101, 25), [f"{x}%" for x in range(0, 101, 25)])
    ax.tick_params(axis="y", length=0, labelsize=9.5, labelcolor=TEXT)
    ax.spines["left"].set_visible(False)
    ax.grid(axis="x", color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)
    handles = [plt.Rectangle((0, 0), 1, 1, color=CAT_COLORS[c]) for c in CAT_COLORS]
    ax.legend(handles, [CAT_NAMES[c] for c in CAT_COLORS], ncol=5, loc="lower left",
              bbox_to_anchor=(-0.02, 1.0), fontsize=9, handlelength=1, columnspacing=1.2)
    _title(fig, "IP-ID mechanism by target group and probe type",
           "Share of hosts that replied to that probe type; n = hosts", note)
    fig.savefig(path)
    plt.close(fig)
    return path


def lifetime_chart(life, path, gaps=None, T=1000, names=None, note=""):
    """Share of tracks per lifetime range, random vs Tranco, one panel per probe type.

    gaps: the planned idle gaps (main + extended). With them, every possible range
    gets an x slot, so an empty range shows as an empty slot instead of vanishing.
    """
    _style()
    if life.empty:
        return None
    ptypes = [p for p in PTYPES if p in set(life["ptype"])]
    groups = [g for g in GROUPS if g in set(life["group"])]
    present = sorted(life["lifetime"].unique(), key=_label_key)
    bins = lifetime_bins(gaps, present) if gaps is not None and len(gaps) else present
    unit = life["unit"].iloc[0]
    H = 4.5 + (0.33 if note else 0)
    fig, axes = plt.subplots(1, len(ptypes), figsize=(max(3.6 * len(ptypes) + 1.2, 8.5), H),
                             sharey=True, squeeze=False)
    axes = axes[0]
    fig.subplots_adjust(left=0.07, right=0.99, top=0.73 - _top_shift(note, H), bottom=0.23,
                        wspace=0.08)
    x = np.arange(len(bins))
    w = 0.8 / max(1, len(groups))
    for ax, p in zip(axes, ptypes):
        for i, g in enumerate(groups):
            sel = life[(life["group"] == g) & (life["ptype"] == p)].set_index("lifetime")
            vals = [float(sel.loc[b, "pct"]) if b in sel.index else 0.0 for b in bins]
            ax.bar(x + (i - (len(groups) - 1) / 2) * w, vals, width=w * 0.92,
                   color=GROUP_COLORS.get(g, "#6a4ce2"), edgecolor=SURFACE, linewidth=0,
                   label=_gname(g, names))
            n = int(sel["of_tracks"].iloc[0]) if len(sel) else 0
            ax.text(0.99, 0.97 - 0.07 * i, f"{_gname(g, names)}: n={n}",
                    transform=ax.transAxes, ha="right", va="top", fontsize=8, color=TEXT2)
        ax.set_title(PTYPE_NAMES.get(p, p), fontsize=10.5, color=TEXT, loc="left")
        ax.set_xticks(x, [b if b in (CENSORED, "unknown") else b for b in bins],
                      rotation=45, ha="right", fontsize=8.5)
        ax.grid(axis="y", color=GRID, linewidth=0.8)
        ax.set_axisbelow(True)
        ax.tick_params(axis="x", length=0)
    axes[0].set_ylabel("Share of hosts (%)")
    axes[0].legend(loc="lower left", bbox_to_anchor=(-0.02, 1.08), ncol=2, fontsize=9,
                   handlelength=1)
    _title(fig, "Per-destination counter lifetime (RQ2)",
           f"Idle time ({unit}) the counter survived: a jump above T = {T:,} counts as a reset, "
           f"so time-based jumps (Linux) also end a track early.\n"
           f"'dropped out' = host stopped answering first. n = hosts tracked.", note)
    fig.savefig(path)
    plt.close(fig)
    return path


def jump_chart(steps, path, T=1000, names=None, note=""):
    """IP-ID jump against idle time (log-log), with the median per gap and the T line."""
    _style()
    if steps.empty:
        return None
    st = steps[(steps["step"] > 0) & (steps["clean"] == 1) & steps["jump"].notna()].copy()
    st = st[st["jump"] > 0]
    if st.empty:
        return None
    unit = st["unit"].iloc[0]
    scale = 60.0 if unit == "min" else 1.0
    st["idle"] = pd.to_numeric(st["gap_s"], errors="coerce") / scale
    ptypes = [p for p in PTYPES if p in set(st["ptype"])]
    groups = [g for g in GROUPS if g in set(st["group"])]
    H = 4.4 + (0.33 if note else 0)
    fig, axes = plt.subplots(1, len(ptypes), figsize=(max(3.8 * len(ptypes) + 1.2, 8.5), H),
                             sharey=True, squeeze=False)
    axes = axes[0]
    fig.subplots_adjust(left=0.08, right=0.99, top=0.76 - _top_shift(note, H), bottom=0.14,
                        wspace=0.08)
    rng = np.random.default_rng(0)
    gaps = sorted(st["planned_gap"].unique())
    for ax, p in zip(axes, ptypes):
        for i, g in enumerate(groups):
            sel = st[(st["group"] == g) & (st["ptype"] == p)]
            if sel.empty:
                continue
            col = GROUP_COLORS.get(g, "#6a4ce2")
            jitter = np.exp(rng.uniform(-0.12, 0.12, len(sel)))
            ax.scatter(sel["idle"] * jitter, sel["jump"], s=9, color=col, alpha=0.35,
                       linewidths=0)
            # Medians only where (almost) every host was probed: the extra gaps
            # (128, 256) only reach counters that survived 64, so their median
            # would show who was left, not a trend. Those stay as dots.
            cnt = sel.groupby("planned_gap")["jump"].size()
            keep = cnt[cnt >= 0.5 * cnt.iloc[0]].index
            med = sel[sel["planned_gap"].isin(keep)].groupby("planned_gap")["jump"].median()
            ax.plot(med.index, med.values, color=col, linewidth=2, marker="o",
                    markersize=6, markeredgecolor=SURFACE, markeredgewidth=1.5,
                    label=f"{_gname(g, names)} (median)")
        ax.axhline(T, color=TEXT2, linewidth=1, linestyle=(0, (4, 3)))
        ax.text(0.98, T * 0.78, f"T = {T:,}: below = survived", transform=ax.get_yaxis_transform(),
                ha="right", va="top", fontsize=8, color=TEXT2, bbox=dict(facecolor=SURFACE, edgecolor="none", alpha=0.85, pad=1.5))
        ax.axhline(32768, color=GRID, linewidth=1)
        ax.text(0.98, 32768 * 0.78, "typical full reset (random)", transform=ax.get_yaxis_transform(),
                ha="right", va="top", fontsize=8, color=TEXT2, bbox=dict(facecolor=SURFACE, edgecolor="none", alpha=0.85, pad=1.5))
        ax.set_xscale("log")
        ax.set_yscale("log")
        ax.set_ylim(0.7, 65536 * 1.6)
        ax.set_xticks(gaps, [f"{g:g}" for g in gaps], fontsize=8.5)
        ax.minorticks_off()
        ax.set_xlabel(f"Idle time before the probe ({unit})")
        ax.set_title(PTYPE_NAMES.get(p, p), fontsize=10.5, color=TEXT, loc="left")
        ax.grid(color=GRID, linewidth=0.8)
        ax.set_axisbelow(True)
    axes[0].set_ylabel("IP-ID jump since previous probe")
    axes[0].set_yticks([1, 10, 100, 1000, 10000, 65536], ["1", "10", "100", "1k", "10k", "65k"])
    axes[0].legend(loc="lower left", bbox_to_anchor=(-0.02, 1.08), ncol=2, fontsize=9)
    _title(fig, "IP-ID jump grows with idle time (RQ2)",
           "Dots: one re-probe from source A each. Lines: medians (longest gaps left out: only survivors reach them)",
           note)
    fig.savefig(path)
    plt.close(fig)
    return path
