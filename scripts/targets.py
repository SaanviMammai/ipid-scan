#!/usr/bin/env python3
"""Build target lists. No root needed.

  Random IPs, one per /16 per round (fixed seed):
    python3 scripts/targets.py random --n 100000 [--seed 4402] [--exclude data/exclude.txt]

  Tranco top domains -> resolve to IPv4 -> de-duplicate:
    python3 scripts/targets.py tranco --top 10000 [--list-id XXXXX] [--file tranco.csv]

  Pilot sizes (design doc "Test run"):
    python3 scripts/targets.py random --n 1000
    python3 scripts/targets.py tranco --top 500

Writes to data/targets/ (change with --out-dir), plus a .meta.json next to each
list recording the seed / Tranco list ID, date and counts, so the scan can be
repeated exactly.
"""
import argparse
import csv
import json
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ipid.targets import (SPECIAL_RANGES, dedupe_resolved, make_excluder,  # noqa: E402
                          parse_tranco, random_targets, read_cidr_file,
                          slash16_str, usable_slash16s)

TRANCO_API = "https://tranco-list.eu/api/lists"
UA = {"User-Agent": "ipid-scan (UConn CSE 4402 research project)"}


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def write_meta(path, meta):
    path.with_suffix(".meta.json").write_text(json.dumps(meta, indent=2) + "\n")


def http_get(url, timeout=120):
    with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=timeout) as r:
        return r.read()


# --- random ------------------------------------------------------------------

def cmd_random(args):
    extra = read_cidr_file(args.exclude)
    excl = make_excluder(extra)
    rows = random_targets(args.n, args.seed, excl)
    out = args.out_dir / f"random_n{args.n}_seed{args.seed}.csv"
    with open(out, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["ip", "round", "slash16"])
        for ip, rnd, b in rows:
            w.writerow([ip, rnd, slash16_str(b)])
    rounds = {}
    for _, rnd, _ in rows:
        rounds[rnd] = rounds.get(rnd, 0) + 1
    write_meta(out, {"kind": "random", "created": now(), "n": len(rows), "seed": args.seed,
                     "usable_slash16s": len(usable_slash16s(excl)),
                     "per_round": rounds, "skip_edge_hosts": True,
                     "excluded_special": SPECIAL_RANGES,
                     "exclude_file": str(args.exclude), "excluded_extra": len(extra)})
    print(f"{len(rows)} random targets in {len(rounds)} round(s) {rounds} -> {out}")


# --- tranco ------------------------------------------------------------------

def get_tranco(args):
    """Return (list_id, created_on, raw_bytes); caches the full list in out_dir."""
    if args.file:
        return args.list_id or Path(args.file).stem, None, Path(args.file).read_bytes()
    url = f"{TRANCO_API}/id/{args.list_id}" if args.list_id else f"{TRANCO_API}/date/latest"
    meta = json.loads(http_get(url, 30))
    if not meta.get("available"):
        raise SystemExit(f"Tranco list {meta.get('list_id')} is not available yet: {meta}")
    lid = meta["list_id"]
    cache = args.out_dir / f"tranco_{lid}.csv"
    if cache.exists():
        print(f"Using cached Tranco list {lid}: {cache}")
        return lid, meta.get("created_on"), cache.read_bytes()
    time.sleep(1.1)  # API limit: 1 query per second
    print(f"Downloading Tranco list {lid} ...")
    raw = http_get(meta["download"])
    rows = parse_tranco(raw)
    with open(cache, "w", newline="") as f:
        csv.writer(f).writerows(rows)
    return lid, meta.get("created_on"), cache.read_bytes()


def make_resolver(timeout):
    import dns.resolver
    r = dns.resolver.Resolver()
    r.timeout, r.lifetime = timeout, timeout * 2
    return r


def resolve_one(resolver, domain):
    """A records for domain, falling back to www.domain. Returns (qname, status, ips)."""
    import dns.exception
    import dns.resolver
    status = "error"
    for qname in (domain, "www." + domain):
        try:
            ans = resolver.resolve(qname, "A")
            return qname, "ok", sorted({a.address for a in ans})
        except dns.resolver.NXDOMAIN:
            status = "nxdomain"
        except dns.resolver.NoAnswer:
            status = "noanswer"
        except dns.exception.Timeout:
            status = "timeout"
        except Exception as e:  # NoNameservers, etc.
            status = type(e).__name__.lower()
    return domain, status, []


def cmd_tranco(args):
    try:
        import dns.resolver  # noqa: F401
    except ModuleNotFoundError:
        raise SystemExit("dnspython is missing: pip install dnspython")
    lid, created, raw = get_tranco(args)
    domains = parse_tranco(raw, args.top)
    print(f"Resolving {len(domains)} domains with {args.workers} threads ...")
    resolver = make_resolver(args.timeout)
    t0 = time.time()
    with ThreadPoolExecutor(args.workers) as pool:
        results = list(pool.map(lambda rd: resolve_one(resolver, rd[1]), domains))
    resolved = [{"rank": rank, "domain": dom, "qname": q, "status": st, "ips": ips}
                for (rank, dom), (q, st, ips) in zip(domains, results)]

    base = args.out_dir / f"tranco_{lid}_top{args.top}"
    dom_out = base.with_name(base.name + "_domains.csv")
    with open(dom_out, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["rank", "domain", "qname", "status", "ips"])
        for r in resolved:
            w.writerow([r["rank"], r["domain"], r["qname"], r["status"], ";".join(r["ips"])])

    excl = make_excluder(read_cidr_file(args.exclude))
    targets, dropped = dedupe_resolved(resolved, excl)
    tgt_out = base.with_name(base.name + "_targets.csv")
    with open(tgt_out, "w", newline="") as f:
        w = csv.DictWriter(f, ["ip", "best_rank", "n_domains", "domains"])
        w.writeheader()
        w.writerows(targets)

    status = {}
    for r in resolved:
        status[r["status"]] = status.get(r["status"], 0) + 1
    shared = sum(t["n_domains"] > 1 for t in targets)
    write_meta(tgt_out, {"kind": "tranco", "created": now(), "tranco_list_id": lid,
                         "tranco_created_on": created, "top": args.top,
                         "lookup_status": status, "unique_ips": len(targets),
                         "ips_shared_by_several_domains": shared,
                         "ips_dropped_excluded": dropped,
                         "dns_timeout_s": args.timeout, "seconds": round(time.time() - t0)})
    print(f"Tranco list {lid}: lookups {status}")
    ok = status.get("ok", 0) / max(1, len(resolved))
    if ok < 0.8:
        print(f"\nWARNING: only {ok:.0%} of lookups succeeded (normally about 90%+). "
              "Check DNS on this machine (try: dig google.com) before using this list.\n")
    print(f"{len(targets)} unique IPv4 targets ({shared} shared by several domains, "
          f"{dropped} dropped as private/reserved)")
    print(f"  {dom_out}\n  {tgt_out}")


def main():
    ap = argparse.ArgumentParser(description="Build IP-ID scan target lists.")
    ap.add_argument("--out-dir", type=Path, default=ROOT / "data" / "targets")
    ap.add_argument("--exclude", type=Path, default=ROOT / "data" / "exclude.txt",
                    help="opt-out IPs/CIDRs, one per line (optional)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("random", help="random IPv4, one per /16 per round")
    r.add_argument("--n", type=int, default=100000)
    r.add_argument("--seed", type=int, default=4402)

    t = sub.add_parser("tranco", help="Tranco top domains -> unique IPv4")
    t.add_argument("--top", type=int, default=10000)
    t.add_argument("--list-id", help="fixed Tranco list ID (default: latest)")
    t.add_argument("--file", help="use a Tranco CSV/zip you already downloaded")
    t.add_argument("--workers", type=int, default=32)
    t.add_argument("--timeout", type=float, default=3.0, help="DNS timeout per try (s)")

    args = ap.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    {"random": cmd_random, "tranco": cmd_tranco}[args.cmd](args)


if __name__ == "__main__":
    main()
