#!/usr/bin/env python3
"""Counter lifetime test (RQ2): re-probe per-destination hosts from source A after growing idle gaps.

  After the full scan (run inside tmux, it takes about 2 hours, up to ~8.5 for hosts
  whose counters never reset):
    sudo .venv/bin/python3 scripts/lifetime.py data/raw/<random_run> data/raw/<tranco_run>

  Testbed (gaps in seconds instead of minutes, about 1 minute in total):
    sudo ip netns exec ipid-scanner .venv/bin/python3 scripts/lifetime.py data/raw/<lab_run> \\
         --lab --iface s0 --src-a 10.99.0.2 --src-b 10.99.0.3 \\
         --gaps 1,2,4,8 --extend 16,32 --gap-unit s --yes

Picks up to --per-group per-destination hosts from each scan group (classified.csv),
takes a baseline IP-ID from source A, then probes again after gaps of 1, 2, 4, 8,
16, 32 and 64 minutes, each measured from the previous probe. Counters that
survived 64 minutes get gaps of 128 and 256 more. A probe with no reply is retried
a few seconds later. Each probe type a host is per-destination for is measured
separately.

Writes data/raw/<run_id>-lifetime/: sent.csv and replies.csv (same format as the scan),
lifetime_targets.csv, lifetime_steps.csv (one row per re-probe, written as it
happens), lifetime_summary.csv (one row per host and probe type) and
lifetime_meta.json. Ctrl+C or a dropped SSH session stops cleanly and still writes
the summary.
"""
import argparse
import csv
import heapq
import json
import signal
import sys
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ipid import config, probes  # noqa: E402
from ipid.lifetime import (DEFAULT_EXTEND_MIN, DEFAULT_GAPS_MIN, DEFAULT_MAX_MISSES,  # noqa: E402
                           DEFAULT_PER_GROUP, DEFAULT_RETRIES, DEFAULT_RETRY_S,
                           STEP_FIELDS, SUMMARY_FIELDS, Track, pick_sample,
                           summarize_steps_file, write_csv)
from ipid.runutil import (chown_to_sudo_user, now_iso, safe_print,  # noqa: E402
                          stop_on_signal)
from ipid.targets import Excluder, make_excluder, read_cidr_file  # noqa: E402

UNITS = {"min": 60.0, "s": 1.0}


def floats(text):
    return tuple(float(x) if "." in x else int(x) for x in text.split(",") if x.strip())


def load_scan_run(run_dir, T, min_per_src):
    """classified.csv + group/dport from scan_meta.json (classifies if needed)."""
    run_dir = Path(run_dir)
    meta = json.loads((run_dir / "scan_meta.json").read_text())
    path = run_dir / "classified.csv"
    if path.exists():
        with open(path, newline="") as f:
            rows = list(csv.DictReader(f))
    else:
        from ipid.classify import classify_run
        rows = classify_run(run_dir, T, min_per_src)
    return {"group": meta["group"], "dport": int(meta["dport"]), "rows": rows,
            "run_id": meta["run_id"], "dir": str(run_dir)}


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("scan_runs", nargs="+", type=Path,
                    help="data/raw/<run_id> folders from scan.py")
    ap.add_argument("--per-group", type=int, help=f"hosts per group (default {DEFAULT_PER_GROUP})")
    ap.add_argument("--types", help="probe types to measure, e.g. icmp,syn (default: all)")
    ap.add_argument("--gaps", help="main gaps, default 1,2,4,8,16,32,64")
    ap.add_argument("--extend", help="extra gaps while counters survive, default 128,256")
    ap.add_argument("--gap-unit", choices=UNITS, default="min")
    ap.add_argument("--T", type=int, help="largest step that counts as 'survived'")
    ap.add_argument("--seed", type=int, default=4402)
    ap.add_argument("--config", help="path to config.toml")
    ap.add_argument("--exclude", type=Path, default=ROOT / "data" / "exclude.txt")
    ap.add_argument("--src-a"), ap.add_argument("--src-b"), ap.add_argument("--iface")
    ap.add_argument("--out", help="output directory (default: output.dir)")
    ap.add_argument("--lab", action="store_true",
                    help="testbed only: allow private target addresses")
    ap.add_argument("--yes", action="store_true", help="don't ask for confirmation")
    args = ap.parse_args()

    cfg = config.load(args.config)
    lt, cc = cfg.get("lifetime", {}), cfg.get("classify", {})
    for key, val in (("A", args.src_a), ("B", args.src_b), ("iface", args.iface)):
        if val:
            cfg["sources"][key] = val
    T = args.T or lt.get("T") or cc.get("T", 1000)
    per_group = args.per_group or lt.get("per_group", DEFAULT_PER_GROUP)
    gaps = floats(args.gaps) if args.gaps else tuple(lt.get("gaps_min", DEFAULT_GAPS_MIN))
    extend = (floats(args.extend) if args.extend is not None
              else tuple(lt.get("extend_min", DEFAULT_EXTEND_MIN)))
    unit_s = UNITS[args.gap_unit]
    retries = lt.get("retries", DEFAULT_RETRIES)
    retry_s = lt.get("retry_s", DEFAULT_RETRY_S)
    max_misses = lt.get("max_misses", DEFAULT_MAX_MISSES)
    types = set(args.types.split(",")) if args.types else None
    src_a = cfg["sources"]["A"]

    optouts = read_cidr_file(args.exclude)
    excl = Excluder(optouts) if args.lab else make_excluder(optouts)
    runs = [load_scan_run(d, T, cc.get("min_per_src", 3)) for d in args.scan_runs]
    sample = pick_sample(runs, per_group, args.seed, types, excl)
    tracks = [Track(ip, p, group, dport, gaps, extend, unit_s, T, max_misses)
              for ip, group, dport, ptypes in sample for p in ptypes]

    avail = Counter(r["group"] for r in runs for x in r["rows"] if x["category"] == "per_dest")
    print(f"Lifetime test: {len(sample)} hosts, {len(tracks)} (host, probe type) tracks")
    for g, n in sorted(Counter(g for _, g, _, _ in sample).items()):
        print(f"  {g}: {n} hosts (of {avail[g]} per-destination rows in the scan)")
    print(f"  by probe type: {dict(sorted(Counter(t.ptype for t in tracks).items()))}")
    print(f"  source A={src_a} only, gaps {list(gaps)} then {list(extend)} {args.gap_unit}, "
          f"T={T}, {retries} retries {retry_s:g} s apart")
    print(f"  time: ~{sum(gaps) * unit_s / 60:.0f} min for every host, up to "
          f"~{(sum(gaps) + sum(extend)) * unit_s / 60:.0f} min if some counters never reset")
    if not tracks:
        raise SystemExit("No per-destination hosts to measure.")
    if not args.yes and input("Start? Type yes: ").strip().lower() != "yes":
        raise SystemExit("Cancelled.")

    from ipid.prober import Prober, require_root
    require_root()
    pr = Prober(cfg, run_id=time.strftime("%Y%m%d-%H%M%S") + "-lifetime", out_dir=args.out)
    run_dir = pr.out_dir
    write_csv([{"ip": ip, "group": g, "dport": d, "ptypes": ";".join(p)}
               for ip, g, d, p in sample], run_dir / "lifetime_targets.csv",
              ["ip", "group", "dport", "ptypes"])
    meta = {"run_id": pr.run_id, "run_tag": pr.run_tag,
            "scan_runs": [{"run_id": r["run_id"], "dir": r["dir"], "group": r["group"]}
                          for r in runs],
            "n_hosts": len(sample), "n_tracks": len(tracks), "per_group": per_group,
            "seed": args.seed, "source_a": src_a, "gaps": list(gaps),
            "extend": list(extend), "unit": args.gap_unit, "T": T, "retries": retries,
            "retry_s": retry_s, "max_misses": max_misses, "rates": cfg["rates"],
            "lab": args.lab, "opt_out_entries": len(optouts), "started": now_iso(),
            "finished": None, "interrupted": False, "probes_sent": 0, "end_reasons": {}}

    steps_f = open(run_dir / "lifetime_steps.csv", "w", newline="")
    steps_w = csv.DictWriter(steps_f, STEP_FIELDS, extrasaction="ignore")
    steps_w.writeheader()

    timeout = cfg["rates"]["reply_timeout_s"]
    next_num = Counter()               # probe numbers, unique per target
    pending = {}                       # track id -> state of the step in flight
    by_num = {}                        # (target, ptype, num) -> track id
    heap, seq = [], 0
    t0 = time.time()
    for tr in tracks:
        tr.due = t0
        heapq.heappush(heap, (tr.due, seq, tr))
        seq += 1
    end_reasons = {}
    n_steps = 0

    def send_try(tr):
        num = next_num[tr.target]
        next_num[tr.target] += 1
        p = probes.Probe(tr.target, tr.ptype, "A", src_a, num, tr.step, tr.dport)
        t = pr.send(p)
        st = pending.setdefault(id(tr), {"tr": tr, "t_first": t, "tries": 0})
        st["t_last"], st["tries"] = t, st["tries"] + 1
        st["deadline"] = t + (retry_s if st["tries"] <= retries else timeout)
        by_num[(tr.target, tr.ptype, num)] = id(tr)

    def finish_step(st, ipid):
        nonlocal seq, n_steps
        tr = st["tr"]
        del pending[id(tr)]
        row = tr.record(st["t_first"], st["t_last"], ipid, st["tries"])
        steps_w.writerow({**row, "run_id": pr.run_id, "unit": args.gap_unit,
                          "gap_s": "" if row["gap_s"] is None else f"{row['gap_s']:.3f}",
                          "t_send": f"{row['t_send']:.6f}"})
        steps_f.flush()
        n_steps += 1
        if tr.done:
            end_reasons[(tr.target, tr.ptype)] = tr.end_reason
        else:
            heapq.heappush(heap, (tr.due, seq, tr))
            seq += 1

    every = 60.0 if unit_s >= 60 else 5.0
    last_print = time.monotonic()
    cursor = 0
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, stop_on_signal)
    pr.start()
    try:
        while heap or pending:
            now = time.time()
            while heap and heap[0][0] <= now:
                send_try(heapq.heappop(heap)[2])
                now = time.time()
            with pr.lock:
                new = pr.replies[cursor:]
                cursor = len(pr.replies)
            for r in new:
                tid = by_num.pop((r["target"], r["ptype"], int(r["num"])), None)
                if tid in pending:
                    finish_step(pending[tid], int(r["ipid"]))
            now = time.time()
            for st in list(pending.values()):
                if now >= st["deadline"]:
                    if st["tries"] <= retries:
                        send_try(st["tr"])
                    else:
                        finish_step(st, None)
            if time.monotonic() - last_print >= every:
                last_print = time.monotonic()
                nxt = (heap[0][0] - time.time()) / 60 if heap else 0
                safe_print(f"  [{(time.time() - t0) / 60:6.1f} min] {n_steps} steps done, "
                           f"{len(heap) + len(pending)} tracks active, "
                           f"{len(end_reasons)} finished, next probe in {max(nxt, 0):.1f} min, "
                           f"sent={pr.n_sent}", flush=True)
            wait = (heap[0][0] - time.time()) if heap else 0.05
            time.sleep(min(max(wait, 0.0), 0.05))
    except KeyboardInterrupt:
        meta["interrupted"] = True
        safe_print("\nInterrupted: saving what was collected so far.")
    finally:
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            signal.signal(sig, signal.SIG_IGN)
        pr.stop()
        steps_f.close()
        for st in pending.values():
            end_reasons.setdefault((st["tr"].target, st["tr"].ptype), "interrupted")
        for _, _, tr in heap:
            end_reasons.setdefault((tr.target, tr.ptype), "interrupted")
        summary = summarize_steps_file(run_dir / "lifetime_steps.csv", end_reasons)
        write_csv(summary, run_dir / "lifetime_summary.csv", SUMMARY_FIELDS)
        meta["finished"] = now_iso()
        meta["probes_sent"] = pr.n_sent
        meta["end_reasons"] = dict(Counter(end_reasons.values()))
        (run_dir / "lifetime_meta.json").write_text(json.dumps(meta, indent=2) + "\n")
        chown_to_sudo_user(run_dir.parent, run_dir)

    print(f"\n{'Partial' if meta['interrupted'] else 'Done'}: {len(summary)} tracks, "
          f"{pr.n_sent} probes sent, endings {meta['end_reasons']}")
    print(f"  Data: {run_dir}/")
    print(f"  Lifetime ({args.gap_unit}) per group and probe type:")
    table = {}
    for s in summary:
        table.setdefault((s["group"], s["ptype"]), Counter())[s["label"]] += 1
    for (g, p), c in sorted(table.items()):
        print(f"    {g:<7} {p:<7} {dict(sorted(c.items()))}")


if __name__ == "__main__":
    main()
