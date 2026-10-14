#!/usr/bin/env python3
"""Abuse-case tracker: one JSON store tying IOCs to abuse reports and follow-ups.

Subcommands:
    python3 cases.py add --id ID --title TITLE [--opened YYYY-MM-DD]
        [--status open] [--ioc-ip IP] [--ioc-domain D] [--ioc-bucket B]
        [--ioc-sender S]            (ioc flags are repeatable)
    python3 cases.py report --case ID --channel email|webform|...
        --target TARGET [--reference REF] [--status sent] [--date YYYY-MM-DD]
    python3 cases.py followup --case ID --due YYYY-MM-DD --note NOTE
    python3 cases.py done --case ID --followup-index N
    python3 cases.py list           # open cases + overdue follow-ups
    python3 cases.py show --case ID
    python3 cases.py seed           # seed the three known cases (idempotent)

Store: cases.json next to this script.
"""
import argparse
import json
import sys
from datetime import date

BASE = "/home/hatch/workspace/scam-intel/relay-watch"
STORE = f"{BASE}/cases.json"
TODAY = date.today().isoformat()


def load():
    try:
        with open(STORE) as f:
            return json.load(f)
    except FileNotFoundError:
        return {"cases": []}


def save(db):
    with open(STORE, "w") as f:
        json.dump(db, f, indent=2)


def find(db, cid):
    for c in db["cases"]:
        if c["id"] == cid:
            return c
    return None


def cmd_add(a):
    db = load()
    if find(db, a.id):
        print(f"case {a.id!r} already exists; not duplicated")
        return 0
    db["cases"].append({
        "id": a.id,
        "title": a.title,
        "opened": a.opened or TODAY,
        "status": a.status,
        "iocs": {
            "ips": a.ioc_ip or [],
            "domains": a.ioc_domain or [],
            "buckets": a.ioc_bucket or [],
            "senders": a.ioc_sender or [],
        },
        "reports": [],
        "follow_ups": [],
    })
    save(db)
    print(f"added case {a.id!r}")
    return 0


def cmd_report(a):
    db = load()
    c = find(db, a.case)
    if not c:
        print(f"unknown case {a.case!r}", file=sys.stderr)
        return 1
    c["reports"].append({
        "date": a.date or TODAY,
        "channel": a.channel,
        "target": a.target,
        "reference": a.reference or "",
        "status": a.status,
    })
    save(db)
    print(f"report added to {a.case!r}")
    return 0


def cmd_followup(a):
    db = load()
    c = find(db, a.case)
    if not c:
        print(f"unknown case {a.case!r}", file=sys.stderr)
        return 1
    c["follow_ups"].append({"due": a.due, "note": a.note, "done": False})
    save(db)
    print(f"follow-up added to {a.case!r}")
    return 0


def cmd_done(a):
    db = load()
    c = find(db, a.case)
    if not c:
        print(f"unknown case {a.case!r}", file=sys.stderr)
        return 1
    try:
        fu = c["follow_ups"][a.followup_index]
    except IndexError:
        print(f"no follow-up #{a.followup_index} on {a.case!r}", file=sys.stderr)
        return 1
    fu["done"] = True
    save(db)
    print(f"follow-up #{a.followup_index} on {a.case!r} marked done")
    return 0


def cmd_list(_a):
    db = load()
    open_cases = [c for c in db["cases"] if c["status"] == "open"]
    print(f"open cases: {len(open_cases)}")
    for c in open_cases:
        n_rep = len(c["reports"])
        n_fu = sum(1 for f in c["follow_ups"] if not f["done"])
        print(f"  [{c['id']}] {c['title']} (opened {c['opened']}) "
              f"{n_rep} reports, {n_fu} pending follow-ups")
    print("overdue follow-ups:")
    any_overdue = False
    for c in open_cases:
        for i, f in enumerate(c["follow_ups"]):
            if not f["done"] and f["due"] < TODAY:
                any_overdue = True
                print(f"  [{c['id']}] #{i} due {f['due']}: {f['note']}")
    if not any_overdue:
        print("  none")
    return 0


def cmd_show(a):
    db = load()
    c = find(db, a.case)
    if not c:
        print(f"unknown case {a.case!r}", file=sys.stderr)
        return 1
    print(json.dumps(c, indent=2))
    return 0


def cmd_seed(_a):
    """Seed the three real cases from existing ScamIntel evidence.
    Idempotent: existing ids are left untouched."""
    db = load()
    seeds = [
        {
            "id": "santiago-2026-10-14",
            "title": "'Santiago: Cloud Login Alert' phish wave (Oct 14, 2026)",
            "opened": "2026-10-14",
            "status": "open",
            "iocs": {
                "ips": ["94.237.68.249"],
                "domains": [],
                "buckets": ["odfoiv654df.lon1.digitaloceanspaces.com"],
                "senders": ["havajabwkwgsyshwb4@gmail.com"],
                "other": ["whatsapp:+917777073492"],
            },
            "reports": [
                {"date": "2026-10-14", "channel": "email",
                 "target": "abuse@digitalocean.com",
                 "reference": "new bucket odfoiv654df; cited prior ticket #12902340",
                 "status": "sent"},
                {"date": "2026-10-14", "channel": "webform",
                 "target": "Google Safe Browsing",
                 "reference": "2/2 URLs accepted", "status": "submitted"},
                {"date": "2026-10-14", "channel": "email",
                 "target": "abuse@upcloud.com",
                 "reference": "relay 94.237.68.249 (mail.blanceresemt.com, forged HELO)",
                 "status": "sent"},
                {"date": "2026-10-14", "channel": "webform",
                 "target": "FBI IC3",
                 "reference": "supplemental filed; confirmation delivered in chat, not stored",
                 "status": "submitted"},
            ],
            "follow_ups": [
                {"due": "2026-10-17",
                 "note": "Check for UpCloud abuse reply; re-report with fresh evidence if no action",
                 "done": False},
                {"due": "2026-10-21",
                 "note": "Verify bucket odfoiv654df status via takedown watch",
                 "done": False},
            ],
        },
        {
            "id": "katrina-2026-10-13",
            "title": "'Cloud Payment Failed' phish wave (Oct 13, 2026)",
            "opened": "2026-10-13",
            "status": "open",
            "iocs": {
                "ips": ["45.10.59.20"],
                "domains": ["www.winchesterstudents.co.uk"],
                "buckets": ["yuoupuptrgggfg.lon1.digitaloceanspaces.com"],
                "senders": ["doanung.tham60811@gmail.com"],
            },
            "reports": [
                {"date": "2026-10-13", "channel": "webform",
                 "target": "DigitalOcean Trust & Safety",
                 "reference": "submitted; no ticket number shown",
                 "status": "submitted"},
                {"date": "2026-10-13", "channel": "email",
                 "target": "abuse@digitalocean.com",
                 "reference": "auto-rejected by recipient", "status": "failed"},
                {"date": "2026-10-13", "channel": "webform",
                 "target": "Google Safe Browsing",
                 "reference": "accepted", "status": "submitted"},
            ],
            "follow_ups": [
                {"due": "2026-10-20",
                 "note": "Verify bucket yuoupuptrgggfg status via takedown watch",
                 "done": False},
            ],
        },
        {
            "id": "sellerpaymentverify-campaign",
            "title": "ebay.sellerpaymentverifi.com phishing kit campaign",
            "opened": "2026-10-07",
            "status": "open",
            "iocs": {
                "ips": [],
                "domains": ["ebay.sellerpaymentverifi.com",
                            "sellerpaymentverif.com", "bitlaunchy.com"],
                "buckets": [],
                "senders": [],
            },
            "reports": [
                {"date": "2026-10-08", "channel": "email",
                 "target": "NiceNIC abuse",
                 "reference": "case #792495; sellerpaymentverify.com suspended (clientHold/NXDOMAIN)",
                 "status": "sent"},
                {"date": "2026-10-13", "channel": "email",
                 "target": "tipline@scammerpayback.org",
                 "reference": "phishing-operation tip sent", "status": "sent"},
                {"date": "2026-10-13", "channel": "webform",
                 "target": "DigitalOcean Trust & Safety",
                 "reference": "ticket #12902340 (prior bucket wave)", "status": "submitted"},
            ],
            "follow_ups": [
                {"due": "2026-10-16",
                 "note": "bitlaunchy.com still live as of Oct 14 09:45 check; escalate if unchanged",
                 "done": False},
                {"due": "2026-10-18",
                 "note": "Recheck sellerpaymentverif.com sibling for live lure",
                 "done": False},
            ],
        },
    ]
    added = 0
    for s in seeds:
        if find(db, s["id"]):
            print(f"case {s['id']!r} already exists; skipped")
            continue
        db["cases"].append(s)
        added += 1
        print(f"seeded case {s['id']!r}")
    save(db)
    print(f"{added} new case(s) seeded")
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="cases.py",
                                description="Abuse-case tracker for phishing takedown work")
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("add", help="create a new case")
    a.add_argument("--id", required=True)
    a.add_argument("--title", required=True)
    a.add_argument("--opened", default=None)
    a.add_argument("--status", default="open")
    a.add_argument("--ioc-ip", action="append", default=None)
    a.add_argument("--ioc-domain", action="append", default=None)
    a.add_argument("--ioc-bucket", action="append", default=None)
    a.add_argument("--ioc-sender", action="append", default=None)
    a.set_defaults(fn=cmd_add)

    r = sub.add_parser("report", help="log an abuse report on a case")
    r.add_argument("--case", required=True)
    r.add_argument("--channel", required=True)
    r.add_argument("--target", required=True)
    r.add_argument("--reference", default="")
    r.add_argument("--status", default="submitted")
    r.add_argument("--date", default=None)
    r.set_defaults(fn=cmd_report)

    f = sub.add_parser("followup", help="add a follow-up to a case")
    f.add_argument("--case", required=True)
    f.add_argument("--due", required=True, help="YYYY-MM-DD")
    f.add_argument("--note", required=True)
    f.set_defaults(fn=cmd_followup)

    d = sub.add_parser("done", help="mark a follow-up done")
    d.add_argument("--case", required=True)
    d.add_argument("--followup-index", type=int, required=True)
    d.set_defaults(fn=cmd_done)

    l = sub.add_parser("list", help="open cases + overdue follow-ups")
    l.set_defaults(fn=cmd_list)

    s = sub.add_parser("show", help="show a case as JSON")
    s.add_argument("--case", required=True)
    s.set_defaults(fn=cmd_show)

    sd = sub.add_parser("seed", help="seed the three known cases (idempotent)")
    sd.set_defaults(fn=cmd_seed)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
