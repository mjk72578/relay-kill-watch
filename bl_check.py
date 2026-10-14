#!/usr/bin/env python3
"""Blocklist-status checker: query the Spamhaus Zen DNSBL via DNS-over-HTTPS.

Usage:
    python3 bl_check.py 94.237.68.249
    python3 bl_check.py --all        # check every relay IP in watchlist.json

Stdlib only. Uses https://dns.google/resolve (public DoH).

IMPORTANT: Spamhaus rate-limits and often blocks queries that arrive via
large public resolvers. A 127.255.255.254 answer means the query was
REFUSED (excessive queries / resolver blocked) -- it is NOT a listing.
Only 127.0.0.x codes are real listings.

Defensive use only: this tool only reads public DNSBL data about IPs
already under investigation. It never touches phishing URLs.
"""
import json
import sys
import urllib.request
from datetime import datetime, timezone

BASE = "/home/hatch/workspace/scam-intel/relay-watch"
DOH = "https://dns.google/resolve"

# Spamhaus Zen return codes -> list names
CODES = {
    "127.0.0.2": "SBL",        # Spamhaus SBL (spam source / snowshoe)
    "127.0.0.3": "SBL-CSS",    # Spamhaus CSS (snowshoe spam)
    "127.0.0.4": "XBL-CBL",    # CBL (botnet / compromised host)
    "127.0.0.5": "XBL-CBL",
    "127.0.0.6": "XBL-CBL",
    "127.0.0.7": "XBL-CBL",
    "127.0.0.10": "PBL",       # Policy Block List (should not send mail directly)
    "127.0.0.11": "PBL",
}


def doh(name, rtype):
    req = urllib.request.Request(
        f"{DOH}?name={name}&type={rtype}",
        headers={"User-Agent": "bl-check/1.0"},
    )
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.load(r)


def check_ip(ip):
    rev = ".".join(reversed(ip.split(".")))
    qname = f"{rev}.zen.spamhaus.org"
    out = {
        "ip": ip,
        "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "listings": [],
        "query_blocked": False,
    }
    try:
        a = doh(qname, "A")
    except Exception as e:
        out["error"] = f"A query failed: {type(e).__name__}"
        return out
    if a.get("Status") != 0:
        # NXDOMAIN (Status 3) -> not listed. Anything else -> inconclusive.
        if a.get("Status") != 3:
            out["note"] = f"inconclusive DNS status {a.get('Status')}"
        return out
    for ans in a.get("Answer", []):
        code = ans["data"]
        if code == "127.255.255.252":
            out["note"] = "127.255.255.252: typing error in query"
            continue
        if code == "127.255.255.254":
            # Resolver blocked / excessive queries -- NOT a listing.
            out["query_blocked"] = True
            continue
        detail = ""
        try:
            t = doh(qname, "TXT")
            if t.get("Status") == 0:
                detail = " ".join(
                    x["data"].strip('"') for x in t.get("Answer", [])
                )
        except Exception:
            pass
        out["listings"].append(
            {"code": code, "list": CODES.get(code, "UNKNOWN"), "detail": detail}
        )
    return out


def main(argv):
    if "--all" in argv:
        with open(f"{BASE}/watchlist.json") as f:
            ips = [r["ip"] for r in json.load(f)["relays"]]
        results = [check_ip(ip) for ip in ips]
        print(json.dumps({
            "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "results": results,
        }, indent=2))
        return 0
    if len(argv) != 2 or argv[1].startswith("-"):
        print(__doc__.strip().splitlines()[0], file=sys.stderr)
        print("usage: python3 bl_check.py <ipv4> | --all", file=sys.stderr)
        return 2
    print(json.dumps(check_ip(argv[1]), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
