#!/usr/bin/env python3
"""Build the report's tables and charts from scan and lifetime runs. No root needed.

    python3 scripts/analyze.py --scan data/raw/<random_run> data/raw/<tranco_run> \\
            --lifetime data/raw/<run_id>-lifetime --out results/full

Writes to --out (default results/latest):
    summary.md               every table in markdown, ready to paste into the report
    response.csv             targets probed and answering, per group
    categories.csv           hosts per category, per group and probe type (long format)
    categories_wide.csv      the same as one row per group and probe type (%)
    combos.csv               mechanism combinations across probe types
    lifetime.csv, jumps.csv  RQ2 (only with --lifetime)
    fig_categories.png, fig_lifetime.png, fig_jumps.png

Only totals and percentages are written, never addresses (design doc section 6),
so the results folder is safe to commit.
"""
import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ipid import analysis as A  # noqa: E402


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--scan", nargs="+", type=Path, required=True,
                    help="scan run folders (data/raw/<run_id>)")
    ap.add_argument("--lifetime", nargs="*", type=Path, default=[],
                    help="lifetime run folders (data/raw/<run_id>-lifetime)")
    ap.add_argument("--out", type=Path, default=ROOT / "results" / "latest")
    ap.add_argument("--T", type=int, default=1000)
    ap.add_argument("--min-per-src", type=int, default=3)
    ap.add_argument("--no-charts", action="store_true")
    args = ap.parse_args()
    out = args.out
    out.mkdir(parents=True, exist_ok=True)

    metas, cl = A.load_scans(args.scan, args.T, args.min_per_src)
    resp = A.response_table(metas, cl)
    cats = A.category_table(cl)
    wide = A.category_wide(cats)
    combos = A.combo_table(cl)
    resp.to_csv(out / "response.csv", index=False, float_format="%.2f")
    cats.to_csv(out / "categories.csv", index=False, float_format="%.2f")
    wide.to_csv(out / "categories_wide.csv", index=False, float_format="%.2f")
    combos.to_csv(out / "combos.csv", index=False, float_format="%.2f")

    life = jumps = None
    steps = None
    life_metas = []
    for d in args.lifetime:
        f = d / "lifetime_meta.json"
        life_metas.append(json.loads(f.read_text()) if f.exists() else {})
    if args.lifetime:
        summ, steps = A.load_lifetimes(args.lifetime)
        life = A.lifetime_table(summ)
        jumps = A.jump_table(steps, args.T)
        life.to_csv(out / "lifetime.csv", index=False, float_format="%.2f")
        jumps.to_csv(out / "jumps.csv", index=False, float_format="%.2f")

    # Label the charts honestly: simulated runs and testbed runs say so on the chart
    # itself, so a copied PNG can't be mistaken for an Internet result.
    all_metas = metas + life_metas
    fake = any(m.get("fake") for m in all_metas)
    lab = bool(metas) and all(m.get("lab") for m in metas)
    names, note = None, ""
    if fake:
        note = "SIMULATED DATA (made-up mix): layout check only, not a result"
    elif lab:
        names = {m["group"]: "Linux testbed" for m in metas}
        note = "LOCAL TESTBED: one Linux network namespace, not Internet hosts"

    figs = []
    if not args.no_charts:
        from ipid import charts
        figs.append(charts.category_chart(cats, out / "fig_categories.png", names, note))
        if life is not None:
            gaps = []
            for m in life_metas:
                gaps += list(m.get("gaps", [])) + list(m.get("extend", []))
            if not gaps and steps is not None and "planned_gap" in steps:
                gaps = steps["planned_gap"].dropna().unique().tolist()
            figs.append(charts.lifetime_chart(life, out / "fig_lifetime.png", gaps, args.T,
                                              names, note))
            figs.append(charts.jump_chart(steps, out / "fig_jumps.png", args.T, names, note))
    figs = [f for f in figs if f]

    resp_cols = ["group", "probed", "responded", "responded_pct", "responded_icmp_pct",
                 "responded_syn_pct", "responded_synack_pct", "full_set_replied"]
    md = ["# IP-ID scan results", "",
          f"Generated {datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC from "
          f"{len(args.scan)} scan run(s) and {len(args.lifetime)} lifetime run(s).",
          f"T = {args.T}, at least {args.min_per_src} replies per source.", ""]
    if lab and not fake:
        md += ["> **Local testbed** (Linux network namespace): not Internet hosts.", ""]
    if fake:
        md += ["> **Simulated data** (tests/fakedata.py): for checking the charts only, "
               "not a result.", ""]
    md += ["## Response rates", "",
           A.to_markdown(resp[[c for c in resp_cols if c in resp.columns]]),
           "## IP-ID mechanism (% of hosts that replied to that probe type)", "",
           A.to_markdown(wide), "## Mechanism combinations across probe types", "",
           A.to_markdown(combos)]
    if life is not None:
        md += ["## Counter lifetime (RQ2)", "", A.to_markdown(life),
               "## Jump size against idle time (RQ2)", "", A.to_markdown(jumps)]
    md += ["## Source runs", ""] + [f"- `{m['run_id']}` ({m['group']}, "
                                    f"{m['n_targets']:,} targets)" for m in metas]
    md += [f"- `{d.name}` (lifetime)" for d in args.lifetime]
    (out / "summary.md").write_text("\n".join(md) + "\n")
    (out / "inputs.json").write_text(json.dumps(
        {"scan": [str(p) for p in args.scan], "lifetime": [str(p) for p in args.lifetime],
         "T": args.T, "min_per_src": args.min_per_src}, indent=2) + "\n")

    print(f"Results in {out}/")
    print(A.to_markdown(wide))
    for f in figs:
        print(f"  chart: {f}")


if __name__ == "__main__":
    main()
