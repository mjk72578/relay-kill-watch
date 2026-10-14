# Relay Watch Toolkit

Defensive anti-phishing tooling: monitors the mail-relay infrastructure
behind phishing waves, tracks abuse reports, and confirms kills. Extends
the [ScamIntel](../email-phish-takedown-2.4.0.py) forensic pipeline.

**Defensive-only rule.** These tools monitor, record, and report. They never
visit phishing URLs, never probe beyond public DNS and plain TCP handshakes
on mail ports, and never take offensive action against anyone. Abuse reports
go through providers' official channels only.

## The tools

| Tool | Job |
|---|---|
| `check_relays.py` | Twice-daily liveness check of watched relay IPs (PTR + TCP 25/587); flags state changes (the kill signal). Run by cron. |
| `bl_check.py` | Spamhaus Zen DNSBL status for a relay IP (via DNS-over-HTTPS). Confirms whether a listing landed. |
| `cases.py` | Abuse-case tracker: one JSON store tying IOCs → reports filed → follow-ups. |
| `new_relay.py` | Extracts the external relay hop from a new ScamIntel case's `headers.txt`; diffs against the watchlist. |

Shared files: `watchlist.json` (watched relays), `state.json` (last liveness
signals, written by `check_relays.py`), `cases.json` (written by `cases.py`).

## Workflow

```
ScamIntel case (analysis/headers.txt)
        │
        ▼
python3 new_relay.py <analysis-dir> [--watch]   # new relay? -> watchlist.json
        │
        ▼
watchlist.json ──► check_relays.py (cron, 2x daily) ──► kill confirmed?
        │                                                      │
        ▼                                                      ▼
bl_check.py <ip>   (is it on Spamhaus Zen?)            cases.py followup --done
        │
        ▼
cases.py report ...   (log every abuse report filed)
```

## Examples

```bash
# 1. New phish wave lands -> extract its relay
python3 new_relay.py ../santiago-cloud-login-alert-2026-10-14-8beb80e881a0605f/analysis
# {"case": "...", "relays_found": [{"ip": "94.237.68.249", ..., "already_watched": true}]}

# Unknown relay? add it to the watchlist
python3 new_relay.py ../some-new-case/analysis --watch

# 2. Check blocklist status (single IP, or --all for the whole watchlist)
python3 bl_check.py 94.237.68.249
python3 bl_check.py --all
# listings: [] means clean; 127.0.0.2=SBL, 127.0.0.10/11=PBL, etc.
# "query_blocked": true means Spamhaus refused the query (public-resolver
# rate limiting) -- NOT a listing. Retry later or query from your own resolver.

# 3. Track the case
python3 cases.py seed        # seed the three known cases (idempotent)
python3 cases.py list        # open cases + overdue follow-ups
python3 cases.py show --case santiago-2026-10-14
python3 cases.py report --case santiago-2026-10-14 --channel email \
    --target abuse@upcloud.com --reference "relay 94.237.68.249" --status sent
python3 cases.py followup --case santiago-2026-10-14 --due 2026-10-21 \
    --note "Verify bucket status"
python3 cases.py done --case santiago-2026-10-14 --followup-index 0

# 4. Liveness is checked automatically twice daily by the relay-kill-watch cron.
#    Manual run:
python3 check_relays.py
```

## Interpreting `check_relays.py` output

- `ptr: null` + `port25/port587: false` = relay dead (kill confirmed).
- PTR removed but ports open = provider or operator touched DNS; keep watching.
- `first_check` events appear once per relay on the first run ever.

## Interpreting `bl_check.py` output

Spamhaus Zen return codes: `127.0.0.2` SBL, `127.0.0.3` SBL-CSS,
`127.0.0.4`–`127.0.0.7` XBL/CBL, `127.0.0.10`/`127.0.0.11` PBL.
`127.255.255.254` = query refused (resolver blocked), not a listing.
`127.255.255.252` = malformed query. NXDOMAIN = not listed.

## Requirements

Python 3, standard library only. Network use is limited to
`https://dns.google/resolve` (DNS-over-HTTPS) and plain TCP connects to
ports 25/587 of watched IPs. No JavaScript, no URL fetching, no auth.
