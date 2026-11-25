"""Tests for target-list building (no network needed)."""
import csv
import importlib.util
import io
import ipaddress
import json
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ipid.targets import (Excluder, dedupe_resolved, make_excluder,  # noqa: E402
                          parse_tranco, random_targets, read_cidr_file,
                          usable_slash16s)


@pytest.fixture(scope="module")
def excl():
    return make_excluder()


# --- exclusions --------------------------------------------------------------

@pytest.mark.parametrize("ip", ["10.1.2.3", "127.0.0.1", "192.168.1.1", "172.20.0.5",
                                "100.64.0.1", "169.254.169.254", "224.0.0.251",
                                "239.255.255.250", "255.255.255.255", "0.1.2.3",
                                "192.0.2.10", "198.51.100.7", "203.0.113.9"])
def test_special_ranges_excluded(excl, ip):
    assert ip in excl


@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "137.99.1.1", "172.15.255.255",
                                "172.32.0.0", "192.0.3.1", "223.255.255.254"])
def test_public_addresses_allowed(excl, ip):
    assert ip not in excl


def test_excluder_merges_overlaps():
    e = Excluder(["1.0.0.0/16", "1.0.128.0/17", "1.1.0.0/16"])
    assert e.covers_block(int(ipaddress.IPv4Address("1.0.0.0")),
                          int(ipaddress.IPv4Address("1.1.255.255")))
    assert "1.2.0.0" not in e


def test_usable_slash16_count(excl):
    # 65536 minus fully excluded /16s (0/8, 10/8, 127/8, 100.64/10, 172.16/12,
    # 169.254/16, 192.168/16, 198.18/15, 224/3). Partly excluded ones stay.
    assert len(usable_slash16s(excl)) == 56492


def test_read_cidr_file(tmp_path):
    p = tmp_path / "exclude.txt"
    p.write_text("# opt-outs\n8.8.8.0/24   # someone asked\n1.1.1.1\n\n")
    assert read_cidr_file(p) == ["8.8.8.0/24", "1.1.1.1"]
    assert read_cidr_file(tmp_path / "missing.txt") == []


# --- random targets, one per /16 per round -----------------------------------

def test_first_round_uses_distinct_slash16s(excl):
    rows = random_targets(1000, 1, excl)
    assert len(rows) == 1000
    assert len({b for _, _, b in rows}) == 1000
    assert {r for _, r, _ in rows} == {1}


def test_second_round_only_after_every_slash16(excl):
    n = len(usable_slash16s(excl)) + 50
    rows = random_targets(n, 2, excl)
    rounds = [r for _, r, _ in rows]
    assert rounds.count(1) == n - 50 and rounds.count(2) == 50
    assert rounds == sorted(rounds)  # no round-2 address before round 1 ends
    assert len({ip for ip, _, _ in rows}) == n


def test_no_excluded_or_edge_addresses(excl):
    for ip, _, _ in random_targets(5000, 3, excl):
        assert ip not in excl
        assert ip.split(".")[3] not in ("0", "255")


def test_same_seed_same_list(excl):
    assert random_targets(500, 7, excl) == random_targets(500, 7, excl)
    assert random_targets(500, 7, excl) != random_targets(500, 8, excl)


def test_opt_out_file_removes_networks():
    e = make_excluder(["44.0.0.0/8", "8.8.8.8"])
    rows = random_targets(len(usable_slash16s(e)), 5, e)
    assert not any(ip.startswith("44.") for ip, _, _ in rows)
    assert "8.8.8.8" not in {ip for ip, _, _ in rows}


# --- Tranco parsing and de-duplication ----------------------------------------

SAMPLE = "1,google.com\n2,Facebook.com.\n3,example.org\n4,cdn-a.net\n"


def test_parse_tranco_text_and_top():
    assert parse_tranco(SAMPLE, top=2) == [(1, "google.com"), (2, "facebook.com")]


def test_parse_tranco_zip_and_header():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("top-1m.csv", "rank,domain\n" + SAMPLE)
    assert len(parse_tranco(buf.getvalue())) == 4


def test_dedupe_shared_and_private(excl):
    resolved = [
        {"rank": 3, "domain": "c.com", "ips": ["93.184.216.34"]},
        {"rank": 1, "domain": "a.com", "ips": ["93.184.216.34", "1.2.3.4"]},
        {"rank": 2, "domain": "b.com", "ips": ["127.0.0.1"]},
        {"rank": 4, "domain": "d.com", "ips": []},
    ]
    targets, dropped = dedupe_resolved(resolved, excl)
    assert dropped == 1
    assert [t["ip"] for t in targets] == ["1.2.3.4", "93.184.216.34"]
    shared = targets[1]
    assert shared["best_rank"] == 1 and shared["n_domains"] == 2
    assert shared["domains"] == "a.com;c.com"


# --- the script, end to end, offline -----------------------------------------

def load_script():
    spec = importlib.util.spec_from_file_location("targets_script",
                                                  ROOT / "scripts" / "targets.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def run_script(mod, monkeypatch, argv):
    monkeypatch.setattr(sys, "argv", ["targets.py"] + argv)
    mod.main()


def test_script_random(tmp_path, monkeypatch):
    mod = load_script()
    run_script(mod, monkeypatch, ["--out-dir", str(tmp_path), "--exclude",
                                  str(tmp_path / "none.txt"), "random", "--n", "300"])
    out = tmp_path / "random_n300_seed4402.csv"
    rows = list(csv.DictReader(open(out)))
    assert len(rows) == 300 and rows[0].keys() == {"ip", "round", "slash16"}
    meta = json.loads(out.with_suffix(".meta.json").read_text())
    assert meta["seed"] == 4402 and meta["per_round"] == {"1": 300}


def test_script_tranco_with_file(tmp_path, monkeypatch):
    pytest.importorskip("dns.resolver")
    mod = load_script()
    fake = {"google.com": ["142.250.1.1"], "facebook.com": ["157.240.1.1"],
            "example.org": ["93.184.216.34"], "cdn-a.net": ["93.184.216.34"]}
    monkeypatch.setattr(mod, "resolve_one",
                        lambda r, d: (d, "ok", fake[d]) if fake.get(d) else (d, "nxdomain", []))
    (tmp_path / "tranco_TEST.csv").write_text(SAMPLE)
    run_script(mod, monkeypatch, ["--out-dir", str(tmp_path), "tranco", "--top", "4",
                                  "--file", str(tmp_path / "tranco_TEST.csv"),
                                  "--list-id", "TEST"])
    tg = tmp_path / "tranco_TEST_top4_targets.csv"
    rows = list(csv.DictReader(open(tg)))
    assert len(rows) == 3
    meta = json.loads(tg.with_suffix(".meta.json").read_text())
    assert meta["tranco_list_id"] == "TEST" and meta["ips_shared_by_several_domains"] == 1
