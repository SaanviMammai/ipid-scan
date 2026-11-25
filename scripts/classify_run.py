#!/usr/bin/env python3
"""Classify the IP-ID mechanism of every target in one or more probe runs.

    python3 scripts/classify_run.py data/raw/<run_id> [more run dirs ...]
            [--T 1000] [--min-per-src 3] [--config config.toml]

Reads sent.csv + replies.csv from each run directory, writes classified.csv next
to them, and prints one line per (target, probe type) plus totals. No root needed.

T and min_per_src come from the [classify] section of config.toml if present;
command-line flags override it.
"""
import argparse
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ipid.classify import (CATEGORIES, DEFAULT_MIN_PER_SRC, DEFAULT_T,  # noqa: E402
                           FULL_SET_START, classify_run, write_rows)


def load_classify_cfg(path):
    path = Path(path)
    if not path.exists():
        return {}
    try:
        import tomllib
    except ModuleNotFoundError:  # Python < 3.11
        return {}
    with open(path, "rb") as f:
        return tomllib.load(f).get("classify", {})


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("run_dirs", nargs="+", type=Path)
    ap.add_argument("--config", default=ROOT / "config.toml")
    ap.add_argument("--T", type=int)
    ap.add_argument("--min-per-src", type=int)
    ap.add_argument("--full-set-start", type=int, default=FULL_SET_START,
                    help="ignore probes numbered below this (discovery)")
    ap.add_argument("--quiet", action="store_true", help="totals only")
    args = ap.parse_args()

    cfg = load_classify_cfg(args.config)
    T = args.T or cfg.get("T", DEFAULT_T)
    mps = args.min_per_src or cfg.get("min_per_src", DEFAULT_MIN_PER_SRC)

    totals = {}
    for run in args.run_dirs:
        rows = classify_run(run, T, mps, args.full_set_start)
        out = run / "classified.csv"
        write_rows(rows, out)
        print(f"\n{run}  (T={T}, min {mps} replies per source)  ->  {out}")
        if not args.quiet:
            print(f"  {'target':<16}{'ptype':<8}{'replies':>8}  {'category':<10}"
                  f"{'max step (same src)':>20}  reason")
            for r in rows:
                cat = r["category"] + ("*" if r["byteswapped"] else "")
                ms = "" if r["max_step_same"] is None else r["max_step_same"]
                print(f"  {r['target']:<16}{r['ptype']:<8}"
                      f"{r['n_replies']:>4}/{r['n_sent']:<3}  {cat:<10}{ms:>20}  {r['reason']}")
        for r in rows:
            totals.setdefault(r["ptype"], Counter())[r["category"]] += 1

    print("\nTotals (targets per category; * = byte-swapped):")
    print(f"  {'ptype':<8}" + "".join(f"{c:>10}" for c in CATEGORIES))
    for ptype, c in sorted(totals.items()):
        print(f"  {ptype:<8}" + "".join(f"{c[k]:>10}" for k in CATEGORIES))


if __name__ == "__main__":
    main()
