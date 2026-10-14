#!/usr/bin/env python3
"""Relay kill-watch: liveness check for watched phishing mail-relay IPs.

For each IP in watchlist.json, records:
  - PTR record (via Google DNS-over-HTTPS, bypasses local resolver quirks)
  - TCP reachability of ports 25 (SMTP) and 587 (submission)

Compares against state.json; prints a JSON summary with a "changes" list
flagging any relay whose signals changed since the last check (the kill
signal is PTR going NXDOMAIN *and* both mail ports refusing/closed).

Stdlib only. Never touches the phishing URLs themselves.
"""
import json
import socket
import sys
import urllib.request
from datetime import datetime, timezone

BASE = "/home/hatch/workspace/scam-intel/relay-watch"
DOH = "https://dns.google/resolve"


def doh_ptr(ip):
    rev = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
    try:
        req = urllib.request.Request(
            f"{DOH}?name={rev}&type=PTR",
            headers={"User-Agent": "relay-watch/1.0"},
        )
        with urllib.request.urlopen(req, timeout=15) as r:
            d = json.load(r)
        if d.get("Status") == 0:
            ans = [a["data"].rstrip(".") for a in d.get("Answer", [])]
            return ans[0] if ans else None
        return None  # NXDOMAIN or other failure -> no PTR
    except Exception as e:
        return f"ERROR:{type(e).__name__}"


def tcp_open(ip, port, timeout=8):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        return False


def main():
    with open(f"{BASE}/watchlist.json") as f:
        watch = json.load(f)["relays"]
    try:
        with open(f"{BASE}/state.json") as f:
            prev = json.load(f).get("relays", {})
    except FileNotFoundError:
        prev = {}

    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    cur, changes = {}, []
    for r in watch:
        ip = r["ip"]
        sig = {
            "ptr": doh_ptr(ip),
            "port25": tcp_open(ip, 25),
            "port587": tcp_open(ip, 587),
        }
        cur[ip] = {"checked_at": now, "signals": sig, "helo": r.get("helo")}
        old = prev.get(ip, {}).get("signals")
        if old is None:
            changes.append({"ip": ip, "event": "first_check", "signals": sig})
        elif old != sig:
            dead = sig["ptr"] is None and not sig["port25"] and not sig["port587"]
            was = "dead" if (old["ptr"] is None and not old["port25"] and not old["port587"]) else "alive"
            changes.append({
                "ip": ip,
                "event": "state_change",
                "was": was,
                "now": "dead" if dead else "alive",
                "old": old,
                "new": sig,
            })

    with open(f"{BASE}/state.json", "w") as f:
        json.dump({"checked_at": now, "relays": cur}, f, indent=2)

    print(json.dumps({"checked_at": now, "relays_checked": len(cur), "changes": changes}, indent=2))


if __name__ == "__main__":
    sys.exit(main())
