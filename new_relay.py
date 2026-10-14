#!/usr/bin/env python3
"""New-relay detector: extract the external mail-relay hop from a ScamIntel
case's headers.txt and diff it against watchlist.json.

Usage:
    python3 new_relay.py <scamintel-case-analysis-dir> [--watch]

Finds Received lines of the form:
    from <helo> (<rdns> [<ip>]) by smtp.gmail.com ...
(the first external hop into Google's servers), extracts ip/helo/rdns,
and reports whether each relay is already in watchlist.json.

With --watch, unknown relays are appended to watchlist.json
(first_seen=today, source_case=directory name). Without the flag, report only.

Google's own mail IPs (209.85.0.0/16, 142.250.0.0/16, 172.253.0.0/16,
74.125.0.0/16) are never flagged as relays.

Stdlib only. Reads local case files; makes no network calls.
Defensive use only.
"""
import ipaddress
import json
import re
import sys
from datetime import date
from pathlib import Path

BASE = "/home/hatch/workspace/scam-intel/relay-watch"
WATCHLIST = f"{BASE}/watchlist.json"

# from <helo> (<rdns> [<ip>]) by <host>   -- rdns part is optional
RECV = re.compile(
    r"from\s+(\S+)\s+\((?:([^()]*?)\s+)?\[([0-9A-Fa-f:.]+)\]\)\s+by\s+(\S+)",
    re.IGNORECASE,
)

GOOGLE_NETS = [
    ipaddress.ip_network(n)
    for n in ("209.85.0.0/16", "142.250.0.0/16", "172.253.0.0/16", "74.125.0.0/16")
]


def is_google_ip(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in n for n in GOOGLE_NETS)


def extract_relays(headers_path):
    text = Path(headers_path).read_text(errors="replace")
    found = []
    seen = set()
    for m in RECV.finditer(text):
        helo, rdns, ip, by = m.group(1), (m.group(2) or "").rstrip("."), m.group(3), m.group(4)
        if "google" not in by.lower() and "gmail" not in by.lower():
            continue  # only hops delivered INTO Google's servers
        if is_google_ip(ip):
            continue  # Google's own infrastructure, never a suspect relay
        if ip in seen:
            continue
        seen.add(ip)
        found.append({"ip": ip, "helo": helo, "rdns": rdns or None})
    return found


def main(argv):
    args = [a for a in argv[1:] if a != "--watch"]
    do_watch = "--watch" in argv[1:]
    if len(args) != 1:
        print("usage: python3 new_relay.py <analysis-dir> [--watch]", file=sys.stderr)
        return 2
    analysis = Path(args[0])
    headers = analysis / "headers.txt"
    if not headers.is_file():
        print(f"no headers.txt in {analysis}", file=sys.stderr)
        return 1

    with open(WATCHLIST) as f:
        watch = json.load(f)
    watched = {r["ip"] for r in watch["relays"]}

    relays = extract_relays(str(headers))
    out_relays = []
    for r in relays:
        known = r["ip"] in watched
        out_relays.append({**r, "already_watched": known})
        if do_watch and not known:
            watch["relays"].append({
                "ip": r["ip"],
                "helo": r["helo"],
                "rdns": r["rdns"],
                "first_seen": date.today().isoformat(),
                "source_case": analysis.parent.name,
                "notes": "auto-added by new_relay.py",
            })
            watched.add(r["ip"])
    if do_watch:
        with open(WATCHLIST, "w") as f:
            json.dump(watch, f, indent=2)

    print(json.dumps({"case": analysis.parent.name,
                      "relays_found": out_relays}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
