"""Target lists (design doc section 4, "Targets").

Random group: IPv4 addresses drawn with a fixed seed, one per /16 network per
round (instructor guidance): round 1 picks one address in every usable /16 in
random order, round 2 a second one, and so on, until n addresses are chosen.
Private, reserved, multicast and documentation ranges are excluded, plus any
CIDRs in an opt-out file.

Popular group: the top N domains of a fixed Tranco list, resolved to IPv4 and
de-duplicated (many domains share CDN addresses).

Only the standard library is used here; network access (Tranco download, DNS)
lives in scripts/targets.py so this module can be unit-tested offline.
"""
import bisect
import csv
import io
import ipaddress
import random
import zipfile
from pathlib import Path

# IANA IPv4 special-purpose registry + multicast + reserved (RFC 6890 and others).
SPECIAL_RANGES = [
    "0.0.0.0/8",          # "this network"
    "10.0.0.0/8",         # private
    "100.64.0.0/10",      # carrier-grade NAT
    "127.0.0.0/8",        # loopback
    "169.254.0.0/16",     # link-local
    "172.16.0.0/12",      # private
    "192.0.0.0/24",       # IETF protocol assignments
    "192.0.2.0/24",       # TEST-NET-1
    "192.31.196.0/24",    # AS112-v4
    "192.52.193.0/24",    # AMT
    "192.88.99.0/24",     # 6to4 relay anycast (deprecated)
    "192.168.0.0/16",     # private
    "192.175.48.0/24",    # direct delegation AS112
    "198.18.0.0/15",      # benchmarking
    "198.51.100.0/24",    # TEST-NET-2
    "203.0.113.0/24",     # TEST-NET-3
    "224.0.0.0/4",        # multicast
    "240.0.0.0/4",        # reserved, includes 255.255.255.255
]


class Excluder:
    """Fast membership test for a set of IPv4 CIDRs (merged sorted intervals)."""

    def __init__(self, cidrs):
        spans = sorted((int(n.network_address), int(n.broadcast_address))
                       for n in (ipaddress.IPv4Network(c, strict=False) for c in cidrs))
        merged = []
        for lo, hi in spans:
            if merged and lo <= merged[-1][1] + 1:
                merged[-1][1] = max(merged[-1][1], hi)
            else:
                merged.append([lo, hi])
        self.starts = [m[0] for m in merged]
        self.ends = [m[1] for m in merged]

    def _span(self, ip_int):
        i = bisect.bisect_right(self.starts, ip_int) - 1
        return i if i >= 0 and ip_int <= self.ends[i] else None

    def __contains__(self, ip):
        ip_int = ip if isinstance(ip, int) else int(ipaddress.IPv4Address(ip))
        return self._span(ip_int) is not None

    def covers_block(self, lo, hi):
        """True if every address lo..hi is excluded."""
        i = self._span(lo)
        return i is not None and self.ends[i] >= hi


def read_cidr_file(path):
    """One IP or CIDR per line; '#' starts a comment. Missing file -> []."""
    path = Path(path) if path else None
    if not path or not path.exists():
        return []
    out = []
    for line in path.read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            ipaddress.IPv4Network(line, strict=False)  # validate early
            out.append(line)
    return out


def make_excluder(extra_cidrs=()):
    return Excluder(SPECIAL_RANGES + list(extra_cidrs))


def usable_slash16s(excl):
    """All /16 blocks (as 0..65535) that are not completely excluded."""
    return [b for b in range(65536) if not excl.covers_block(b << 16, (b << 16) | 0xFFFF)]


def slash16_str(block):
    return f"{block >> 8}.{block & 0xFF}"


def random_targets(n, seed, excl, skip_edge=True, tries=200):
    """Draw n addresses, one per usable /16 per round, in random order.

    Returns a list of (ip_str, round, block) in the order drawn, which is also
    a sensible probe order: consecutive targets are in unrelated networks.
    skip_edge drops x.x.x.0 and x.x.x.255 (often broadcast-like in /24s).
    """
    rng = random.Random(seed)
    blocks = usable_slash16s(excl)
    chosen, out, rnd = set(), [], 0
    while len(out) < n:
        rnd += 1
        before = len(out)
        order = blocks[:]
        rng.shuffle(order)
        for b in order:
            if len(out) >= n:
                break
            for _ in range(tries):
                host = rng.randrange(65536)
                if skip_edge and (host & 0xFF) in (0, 255):
                    continue
                ip = (b << 16) | host
                if ip in chosen or ip in excl:
                    continue
                chosen.add(ip)
                out.append((str(ipaddress.IPv4Address(ip)), rnd, b))
                break
        if len(out) == before:  # nothing left to draw
            break
    return out


# ---------------------------------------------------------------------------
# Tranco
# ---------------------------------------------------------------------------

def parse_tranco(data, top=None):
    """Parse a Tranco list (CSV text/bytes, or the zipped CSV) into [(rank, domain)]."""
    if isinstance(data, bytes):
        if data[:2] == b"PK":
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                data = z.read(z.namelist()[0])
        data = data.decode("utf-8", "replace")
    rows = []
    for rec in csv.reader(io.StringIO(data)):
        if len(rec) < 2 or not rec[0].strip().isdigit():
            continue  # header or junk line
        rows.append((int(rec[0]), rec[1].strip().lower().rstrip(".")))
        if top and len(rows) >= top:
            break
    return rows


def read_domains_csv(path):
    """Read a *_domains.csv written by scripts/targets.py tranco."""
    with open(path, newline="") as f:
        return [{"rank": int(r["rank"]), "domain": r["domain"], "status": r["status"],
                 "ips": [ip for ip in r["ips"].split(";") if ip]}
                for r in csv.DictReader(f)]


def one_ip_per_domain(rows, seed, excl, top=None, max_names=5):
    """Pick one IPv4 address per domain, then de-duplicate.

    Domains are taken in rank order (only rank <= top if given). If one of a
    domain's addresses was already picked for a higher-ranked domain (a shared
    CDN address), that one is reused, so shared servers are probed once;
    otherwise one address is chosen at random with a fixed seed.
    Returns a list of dicts {ip, best_rank, n_domains, domains} in rank order.
    """
    rng = random.Random(seed)
    picked = {}
    for r in sorted(rows, key=lambda r: r["rank"]):
        if top and r["rank"] > top:
            break
        ips = sorted(ip for ip in r["ips"] if ip not in excl)
        if not ips:
            continue
        shared = [ip for ip in ips if ip in picked]
        ip = shared[0] if shared else rng.choice(ips)
        t = picked.setdefault(ip, {"ip": ip, "best_rank": r["rank"], "names": []})
        t["names"].append(r["domain"])
    return [{"ip": t["ip"], "best_rank": t["best_rank"], "n_domains": len(t["names"]),
             "domains": ";".join(t["names"][:max_names])} for t in picked.values()]


def dedupe_resolved(resolved, excl, max_names=5):
    """Turn per-domain lookups into per-IP targets.

    resolved: iterable of dicts with keys rank, domain, ips (list of str).
    Returns (targets, n_dropped) where targets is a list of dicts
    {ip, best_rank, n_domains, domains} sorted by best_rank, and n_dropped
    counts IPs removed because they fall in excluded ranges (e.g. a domain
    that resolves to 127.0.0.1 or a private address).
    """
    by_ip, dropped = {}, set()
    for r in sorted(resolved, key=lambda r: r["rank"]):
        for ip in r["ips"]:
            if ip in excl:
                dropped.add(ip)
                continue
            t = by_ip.setdefault(ip, {"ip": ip, "best_rank": r["rank"], "names": []})
            if r["domain"] not in t["names"]:
                t["names"].append(r["domain"])
    targets = []
    for t in sorted(by_ip.values(), key=lambda t: (t["best_rank"], t["ip"])):
        targets.append({"ip": t["ip"], "best_rank": t["best_rank"],
                        "n_domains": len(t["names"]),
                        "domains": ";".join(t["names"][:max_names])})
    return targets, len(dropped)
