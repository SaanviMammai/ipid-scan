#!/usr/bin/env python3
"""Probe a single target and print the IP-ID sequence for each probe type.

    sudo python3 scripts/probe_one.py TARGET_IP [--port 80] [--config config.toml]

Step 1 (discovery): one ICMP echo, one SYN and one SYN/ACK from source A.
Step 2 (full set):  if anything replied, per_type probes of each type, alternating
                    A, B, A, B, ... with probe_gap_ms between probes.

Writes data/raw/<run_id>/sent.csv and replies.csv. Only probe hosts you own or
have permission to probe.
"""
import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ipid import config, probes  # noqa: E402
from ipid.prober import Prober, require_root  # noqa: E402

FULL_SET_START = 100  # probe numbers 0..99 are reserved for discovery


def summarize(prober, target, plist):
    by_num = {}
    for r in prober.replies:
        if r["target"] == target:
            by_num.setdefault(r["num"], r)
    print(f"\nTarget {target}   run {prober.run_id}   run tag {prober.run_tag:#06x}")
    for ptype in prober.cfg["probes"]["types"]:
        sub = [p for p in plist if p.ptype == ptype]
        got = [by_num.get(p.num) for p in sub]
        n = sum(g is not None for g in got)
        print(f"\n  {ptype}: {n}/{len(sub)} replies")
        if not n:
            continue
        print("    k  src   ipid   step(all)  step(same src)  df  flags")
        prev_all, prev_src = None, {}
        for p, r in zip(sub, got):
            if r is None:
                print(f"   {p.k:2d}   {p.src_label}      -")
                continue
            ipid = r["ipid"]
            d_all = "" if prev_all is None else (ipid - prev_all) % 65536
            d_src = ("" if p.src_label not in prev_src
                     else (ipid - prev_src[p.src_label]) % 65536)
            print(f"   {p.k:2d}   {p.src_label}  {ipid:5d}  {str(d_all):>9}  "
                  f"{str(d_src):>14}   {r['df']}  {r['flags']}")
            prev_all, prev_src[p.src_label] = ipid, ipid
    print(f"\n  Raw data: {prober.out_dir}/")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target")
    ap.add_argument("--port", type=int, help="TCP port (default: probes.port_random)")
    ap.add_argument("--config", help="path to config.toml")
    ap.add_argument("--src-a", help="override sources.A")
    ap.add_argument("--src-b", help="override sources.B")
    ap.add_argument("--iface", help="override sources.iface")
    ap.add_argument("--out", help="output directory (default: output.dir)")
    ap.add_argument("--skip-discovery", action="store_true",
                    help="send the full set even if discovery gets no reply")
    args = ap.parse_args()

    require_root()
    cfg = config.load(args.config)
    if args.src_a:
        cfg["sources"]["A"] = args.src_a
    if args.src_b:
        cfg["sources"]["B"] = args.src_b
    if args.iface:
        cfg["sources"]["iface"] = args.iface
    dport = args.port or cfg["probes"]["port_random"]
    types = cfg["probes"]["types"]

    pr = Prober(cfg, out_dir=args.out)
    src = {"A": cfg["sources"]["A"], "B": cfg["sources"]["B"]}
    pr.start()
    try:
        if not args.skip_discovery:
            disc = probes.discovery(args.target, src, types, dport)
            pr.send_spaced(disc)
            time.sleep(cfg["rates"]["reply_timeout_s"])
            answered = pr.replied_types(args.target, {p.num for p in disc})
            print(f"Discovery: replies to {sorted(answered) or 'nothing'}")
            if not answered:
                print("No reply to any discovery probe; stopping.")
                return
        full = probes.schedule(args.target, src, cfg["probes"]["per_type"], types,
                               dport, first_num=FULL_SET_START)
        pr.send_spaced(full)
    finally:
        pr.stop()
    summarize(pr, args.target, full)


if __name__ == "__main__":
    main()
