#!/usr/bin/env python3
"""Make simulated scan + lifetime runs to preview the analysis (no root, no network).

    python3 scripts/lab/fake_runs.py            # writes data/fake/...
    python3 scripts/analyze.py --scan data/fake/fake-random data/fake/fake-tranco \
            --lifetime data/fake/fake-lifetime --out results/fake

The mix of mechanisms is made up; it only exercises the code and charts.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "tests"))

from fakedata import make_lifetime_run, make_scan_run  # noqa: E402

out = ROOT / "data" / "fake"
r = make_scan_run(out, "random", 3000, seed=1)
t = make_scan_run(out, "tranco", 500, seed=2)
lt = make_lifetime_run(out, [r, t], per_group=60)
print(f"Fake runs: {r}, {t}, {lt}")
