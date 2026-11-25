#!/usr/bin/env python3
"""Scan many targets: discovery, then the full A/B probe set for hosts that reply.

  Pilot (design doc "Test run"):
    sudo .venv/bin/python3 scripts/scan.py random data/targets/random_n100000_seed4402.csv --limit 1000
    sudo .venv/bin/python3 scripts/scan.py tranco data/targets/tranco_JZW4Y_top10000_domains.csv --top 500

  Full scan: same commands without --limit / with --top 10000.

For each chunk of targets (default 2000):
  1. discovery: one ICMP echo, SYN and SYN/ACK from source A to every target;
  2. wait reply_timeout_s;
  3. full set: per_type probes of each type, alternating A/B, probe_gap_ms apart,
     to every target that answered anything. Many targets are interleaved so the
     total rate stays near rates.max_pps.

Writes data/raw/<run_id>/: sent.csv, replies.csv (same format as probe_one.py),
targets.csv, scan_meta.json, classified.csv. At the end the run folder is handed
back to the user who ran sudo, so no chown is needed.

Tranco targets: one IPv4 address per domain (fixed seed), shared addresses probed once.
Opt-outs in data/exclude.txt are re-checked at scan time.
"""
import argparse
import csv
import json
import os
import signal
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ipid import config, probes  # noqa: E402
from ipid.classify import FULL_SET_START  # noqa: E402
from ipid.schedule import Interleaver, stagger_for  # noqa: E402
from ipid.targets import (Excluder, make_excluder, one_ip_per_domain,  # noqa: E402
                          read_cidr_file, read_domains_csv)


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def load_targets(args, excl):
    """Return list of dicts with at least 'ip'; order = probe order."""
    if args.group == "random":
        with open(args.targets, newline="") as f:
            rows = [r for r in csv.DictReader(f)]
        if args.limit:
            rows = rows[:args.limit]
        rows = [r for r in rows if r["ip"] not in excl]
        return rows
    rows = one_ip_per_domain(read_domains_csv(args.targets), args.seed, excl, top=args.top)
    if args.limit:
        rows = rows[:args.limit]
    # Probe in a seeded random order so no network gets a burst (design doc §4).
    import random
    random.Random(args.seed).shuffle(rows)
    return rows


def list_meta(path):
    """Copy the .meta.json written by targets.py, if present."""
    path = Path(path)
    candidates = [path.with_suffix(".meta.json")]
    if path.name.endswith("_domains.csv"):  # tranco: meta sits next to *_targets.csv
        candidates.append(path.with_name(path.name.replace("_domains.csv",
                                                           "_targets.meta.json")))
    for p in candidates:
        try:
            return json.loads(p.read_text())
        except (OSError, ValueError):
            continue
    return None


def _stop_on_signal(signum, frame):
    raise KeyboardInterrupt


def safe_print(*a, **kw):
    """print() that survives a closed terminal (e.g. after SSH dropped)."""
    try:
        print(*a, **kw)
    except OSError:
        pass


def chown_to_sudo_user(*paths):
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if os.geteuid() != 0 or not uid:
        return
    uid, gid = int(uid), int(gid)
    for top in paths:
        top = Path(top)
        if not top.exists():
            continue
        os.chown(top, uid, gid)
        for dirpath, dirnames, filenames in os.walk(top):
            for name in dirnames + filenames:
                os.chown(os.path.join(dirpath, name), uid, gid)


class Progress:
    def __init__(self, pr, every=10.0):
        self.pr, self.every = pr, every
        self.t0 = self.last = time.monotonic()

    def maybe(self, text, force=False):
        t = time.monotonic()
        if force or t - self.last >= self.every:
            self.last = t
            el = t - self.t0
            safe_print(f"  [{el/60:5.1f} min] {text}  sent={self.pr.n_sent} "
                       f"({self.pr.n_sent/max(el, 1e-9):.0f} pps avg)", flush=True)


def run_lists(pr, plists, gap, max_pps, progress, label):
    """Send interleaved probe lists; returns when all are sent."""
    if not plists:
        return
    sched = Interleaver(plists, gap, stagger_for(len(plists[0]), max_pps), time.monotonic())
    while True:
        item = sched.pop(time.monotonic())
        if item is None:
            break
        due, plist, idx = item
        wait = due - time.monotonic()
        if wait > 0:
            time.sleep(wait)
        pr.send(plist[idx])
        sched.done(plist, idx, time.monotonic())
        progress.maybe(f"{label}, {sched.active} targets in progress")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("group", choices=["random", "tranco"])
    ap.add_argument("targets", help="random_*.csv or tranco_*_domains.csv from targets.py")
    ap.add_argument("--limit", type=int, help="only the first N targets (pilot)")
    ap.add_argument("--top", type=int, help="tranco: only domains ranked <= TOP")
    ap.add_argument("--seed", type=int, default=4402, help="tranco IP choice and order")
    ap.add_argument("--chunk", type=int, default=2000, help="targets per discovery chunk")
    ap.add_argument("--config", help="path to config.toml")
    ap.add_argument("--exclude", type=Path, default=ROOT / "data" / "exclude.txt")
    ap.add_argument("--src-a"), ap.add_argument("--src-b"), ap.add_argument("--iface")
    ap.add_argument("--out", help="output directory (default: output.dir)")
    ap.add_argument("--lab", action="store_true",
                    help="testbed only: allow private target addresses")
    ap.add_argument("--yes", action="store_true", help="don't ask for confirmation")
    ap.add_argument("--no-classify", action="store_true")
    args = ap.parse_args()

    from ipid.prober import Prober, require_root
    require_root()
    cfg = config.load(args.config)
    for key, val in (("A", args.src_a), ("B", args.src_b), ("iface", args.iface)):
        if val:
            cfg["sources"][key] = val
    src = {"A": cfg["sources"]["A"], "B": cfg["sources"]["B"]}
    types = cfg["probes"]["types"]
    per_type = cfg["probes"]["per_type"]
    max_pps = cfg["rates"]["max_pps"]
    gap = cfg["rates"]["probe_gap_ms"] / 1000.0
    timeout = cfg["rates"]["reply_timeout_s"]
    dport = cfg["probes"]["port_random" if args.group == "random" else "port_tranco"]

    optouts = read_cidr_file(args.exclude)
    excl = Excluder(optouts) if args.lab else make_excluder(optouts)
    targets = load_targets(args, excl)
    n = len(targets)
    n_full = per_type * len(types)
    disc_min = n * len(types) / max_pps / 60
    print(f"{args.group}: {n} targets from {args.targets}")
    print(f"  sources A={src['A']} B={src['B']}  port {dport}  max {max_pps} pps  "
          f"gap {gap*1000:.0f} ms  {len(optouts)} opt-out entries")
    print(f"  estimated time: discovery ~{disc_min:.1f} min, plus ~{1000*n_full/max_pps/60:.1f} "
          f"min per 1000 hosts that reply")
    if not args.yes and input("Start the scan? Type yes: ").strip().lower() != "yes":
        raise SystemExit("Cancelled.")

    pr = Prober(cfg, out_dir=args.out)
    run_dir = pr.out_dir
    with open(run_dir / "targets.csv", "w", newline="") as f:
        w = csv.DictWriter(f, list(targets[0].keys()) if targets else ["ip"])
        w.writeheader()
        w.writerows(targets)
    meta = {"run_id": pr.run_id, "run_tag": pr.run_tag, "group": args.group,
            "targets_file": str(args.targets), "target_list_meta": list_meta(args.targets),
            "limit": args.limit, "top": args.top, "seed": args.seed, "n_targets": n,
            "tranco_ip_choice": "one per domain" if args.group == "tranco" else None,
            "sources": src, "dport": dport, "rates": cfg["rates"], "probes": cfg["probes"],
            "lab": args.lab, "opt_out_entries": len(optouts), "started": now_iso(),
            "finished": None, "interrupted": False, "responders": 0,
            "responders_by_type": {t: 0 for t in types}, "probes_sent": 0}

    progress = Progress(pr)
    # Ctrl+C, a dropped SSH session (SIGHUP) or kill (SIGTERM): stop cleanly and
    # still write scan_meta.json and hand the folder back.
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, _stop_on_signal)
    pr.start()
    try:
        for c0 in range(0, n, args.chunk):
            chunk = [t["ip"] for t in targets[c0:c0 + args.chunk]]
            label = f"chunk {c0 // args.chunk + 1}/{(n + args.chunk - 1) // args.chunk}"
            with pr.lock:          # earlier replies are already on disk
                pr.replies.clear()
            disc = [probes.discovery(ip, src, types, dport) for ip in chunk]
            run_lists(pr, disc, gap, max_pps, progress, f"{label} discovery")
            time.sleep(timeout)
            cset = set(chunk)
            with pr.lock:
                answered = {}
                for r in pr.replies:
                    if r["num"] < FULL_SET_START and r["target"] in cset:
                        answered.setdefault(r["target"], set()).add(r["ptype"])
                pr.replies.clear()
            meta["responders"] += len(answered)
            for ts in answered.values():
                for t in ts:
                    meta["responders_by_type"][t] += 1
            progress.maybe(f"{label}: {len(answered)}/{len(chunk)} replied to discovery",
                           force=True)
            full = [probes.schedule(ip, src, per_type, types, dport,
                                    first_num=FULL_SET_START)
                    for ip in chunk if ip in answered]
            run_lists(pr, full, gap, max_pps, progress, f"{label} full set")
    except KeyboardInterrupt:
        meta["interrupted"] = True
        safe_print("\nInterrupted: saving what was collected so far.")
    finally:
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            signal.signal(sig, signal.SIG_IGN)  # don't let a second signal break cleanup
        pr.stop()
        meta["finished"] = now_iso()
        meta["probes_sent"] = pr.n_sent
        (run_dir / "scan_meta.json").write_text(json.dumps(meta, indent=2) + "\n")
        chown_to_sudo_user(run_dir.parent, run_dir)
    if meta["interrupted"]:
        safe_print(f"  Partial data: {run_dir}/ (classify it with scripts/classify_run.py)")
        return

    print(f"\nDone: {meta['responders']}/{n} targets replied to discovery "
          f"{meta['responders_by_type']}; {pr.n_sent} probes sent.")
    print(f"  Raw data: {run_dir}/")
    if not args.no_classify:
        from ipid.classify import classify_run, write_rows
        cc = cfg.get("classify", {})
        rows = classify_run(run_dir, cc.get("T", 1000), cc.get("min_per_src", 3))
        write_rows(rows, run_dir / "classified.csv")
        chown_to_sudo_user(run_dir)
        counts = {}
        for r in rows:
            counts.setdefault(r["ptype"], {}).setdefault(r["category"], 0)
            counts[r["ptype"]][r["category"]] += 1
        print("  Categories per probe type (hosts that got the full set):")
        for p in types:
            print(f"    {p:<7} {counts.get(p, {})}")
        print(f"  Details: python3 scripts/classify_run.py {run_dir} --quiet")


if __name__ == "__main__":
    main()
