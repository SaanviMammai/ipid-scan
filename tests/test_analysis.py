"""Tests for the result tables and charts, on simulated runs (no root, no network)."""
import subprocess
import sys
from pathlib import Path

import pandas as pd
import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from fakedata import make_lifetime_run, make_scan_run  # noqa: E402
from ipid import analysis as A  # noqa: E402


@pytest.fixture(scope="module")
def runs(tmp_path_factory):
    d = tmp_path_factory.mktemp("runs")
    r = make_scan_run(d, "random", 1500, seed=1)
    t = make_scan_run(d, "tranco", 300, seed=2)
    lt = make_lifetime_run(d, [r, t], per_group=30)
    return r, t, lt


def test_response_rates(runs):
    r, t, _ = runs
    metas, cl = A.load_scans([r, t])
    resp = A.response_table(metas, cl).set_index("group")
    assert list(resp.index) == ["random", "tranco"]
    assert resp.loc["random", "probed"] == 1500 and resp.loc["tranco", "probed"] == 300
    assert resp.loc["random", "responded_pct"] < 20 < resp.loc["tranco", "responded_pct"]
    assert (resp["full_set_replied"] <= resp["responded"]).all()


def test_category_percentages_add_to_100(runs):
    metas, cl = A.load_scans(runs[:2])
    cats = A.category_table(cl)
    sums = cats.groupby(["group", "ptype"])["pct"].sum()
    assert len(sums) == 6
    assert all(abs(s - 100) < 1e-9 for s in sums)
    # denominator = hosts that replied to that probe type
    for (g, p), sel in cats.groupby(["group", "ptype"]):
        n = ((cl["group"] == g) & (cl["ptype"] == p) & (cl["n_replies"] > 0)).sum()
        assert sel["replied"].iloc[0] == n == sel["hosts"].sum()
    wide = A.category_wide(cats)
    assert list(wide.columns[:7]) == ["group", "ptype", "constant", "global", "per_dest",
                                      "random", "unknown"]


def test_no_addresses_in_any_table(runs):
    metas, cl = A.load_scans(runs[:2])
    summ, steps = A.load_lifetimes([runs[2]])
    tables = [A.response_table(metas, cl), A.category_table(cl), A.combo_table(cl),
              A.lifetime_table(summ), A.jump_table(steps)]
    for t in tables:
        assert "target" not in t.columns
        assert not t.astype(str).apply(lambda c: c.str.contains(r"198\.1[89]\.")).any().any()


def test_later_run_wins_for_duplicate_targets(runs, tmp_path):
    r = runs[0]
    pilot = make_scan_run(tmp_path, "random", 1500, seed=1, run_id="pilot")
    cl_pilot = pd.read_csv(pilot / "classified.csv")
    cl_pilot["category"] = "unknown"
    cl_pilot.to_csv(pilot / "classified.csv", index=False)
    _, cl = A.load_scans([pilot, r])            # full scan listed last
    assert (cl["category"] != "unknown").any()
    assert not cl.duplicated(["group", "target", "ptype"]).any()


def test_combos_flag_mixed_mechanisms():
    cl = pd.DataFrame([
        {"group": "random", "target": "h1", "ptype": "icmp", "category": "per_dest", "n_replies": 10},
        {"group": "random", "target": "h1", "ptype": "syn", "category": "constant", "n_replies": 10},
        {"group": "random", "target": "h2", "ptype": "icmp", "category": "global", "n_replies": 10},
        {"group": "random", "target": "h2", "ptype": "syn", "category": "global", "n_replies": 10},
        {"group": "random", "target": "h3", "ptype": "icmp", "category": "global", "n_replies": 10},
        {"group": "random", "target": "h3", "ptype": "syn", "category": "unknown", "n_replies": 2},
    ])
    c = A.combo_table(cl).set_index("combo")
    assert c.loc["icmp=per_dest, syn=constant", "mixed"]
    assert not c.loc["icmp=global, syn=global", "mixed"]
    assert c.loc["(any mixed combination)", "hosts"] == 1
    assert (c["of_hosts"] == 2).all()           # h3 has only one clear type


def test_lifetime_bins_ordered_and_dropouts_separate():
    summ = pd.DataFrame([
        {"group": "random", "ptype": "icmp", "label": lab, "end_reason": end, "unit": "min",
         "lower": 0, "upper": None}
        for lab, end in [(">256", "finished"), ("<1", "finished"), ("4-8", "finished"),
                         (">4", "gone"), (">32", "finished"), ("64-128", "finished")]])
    summ["upper"] = [None, 1, 8, None, None, 128]
    summ["lower"] = [256, 0, 4, 4, 32, 64]
    life = A.lifetime_table(summ)
    assert list(life["lifetime"]) == ["<1", "4-8", "64-128", ">256", A.CENSORED]
    assert life.set_index("lifetime").loc[A.CENSORED, "tracks"] == 2
    assert abs(life["pct"].sum() - 100) < 1e-9


def test_jump_table_clean_steps_only(runs):
    _, steps = A.load_lifetimes([runs[2]])
    j = A.jump_table(steps)
    clean = steps[(steps["step"] > 0) & (steps["clean"] == 1) & steps["jump"].notna()]
    assert j["n"].sum() == len(clean)
    first = j[j["idle_gap"] == 1]
    assert ((first["survived_pct"] >= 0) & (first["survived_pct"] <= 100)).all()


def test_markdown_table():
    md = A.to_markdown(pd.DataFrame({"a": [1, 2], "b": [0.25, float("nan")]}))
    assert md.splitlines()[0] == "| a | b |" and "| 2 | – |" in md


def test_analyze_script_end_to_end(runs, tmp_path):
    r, t, lt = runs
    out = tmp_path / "res"
    subprocess.run([sys.executable, str(ROOT / "scripts" / "analyze.py"), "--scan", str(r),
                    str(t), "--lifetime", str(lt), "--out", str(out)],
                   check=True, capture_output=True)
    for name in ("summary.md", "response.csv", "categories.csv", "categories_wide.csv",
                 "combos.csv", "lifetime.csv", "jumps.csv", "fig_categories.png",
                 "fig_lifetime.png", "fig_jumps.png"):
        assert (out / name).stat().st_size > 0, name
    md = (out / "summary.md").read_text()
    assert "Simulated data" in md and "198.18." not in md


def test_lifetime_bins_keep_empty_ranges():
    from ipid.charts import lifetime_bins
    bins = lifetime_bins([0, 1, 2, 4, 8, 16, 32, 64, 128, 256], ["<1", "4-8", "dropped out"])
    assert bins[:4] == ["<1", "1-2", "2-4", "4-8"]
    assert bins[-3:] == ["128-256", ">256", "dropped out"]
    assert lifetime_bins([1, 2, 4], ["unknown"]) == ["<1", "1-2", "2-4", ">4", "unknown"]


def test_simulated_runs_are_marked(tmp_path):
    import subprocess
    root = Path(__file__).resolve().parent.parent
    r = make_scan_run(tmp_path, "random", 300, seed=3)
    lt = make_lifetime_run(tmp_path, [r], per_group=10)
    out = tmp_path / "res"
    subprocess.run([sys.executable, str(root / "scripts" / "analyze.py"), "--scan", str(r),
                    "--lifetime", str(lt), "--out", str(out)], check=True,
                   capture_output=True)
    assert "Simulated data" in (out / "summary.md").read_text()
    assert (out / "fig_lifetime.png").exists()
