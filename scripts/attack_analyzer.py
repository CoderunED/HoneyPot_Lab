
#!/usr/bin/env python3
"""
attack_analyzer.py — Deep Attack Pattern Analysis
HoneyPot_Lab by @CoderunED
"""

import json
import sys
from collections import Counter, defaultdict
from datetime import datetime

LOG_PATH = "var/log/cowrie/cowrie.json"

def load_logs(path):
    events = []
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return events

def group_by_session(events):
    """Group events by session ID for per-attacker analysis."""
    sessions = defaultdict(list)
    for e in events:
        sid = e.get("session")
        if sid:
            sessions[sid].append(e)
    return sessions

def get_session_summary(sessions):
    """Build a summary dict per session."""
    summaries = []
    for sid, evts in sessions.items():
        src_ip = next((e.get("src_ip") for e in evts if e.get("src_ip")), "unknown")
        client = next((e.get("version") for e in evts if e.get("eventid") == "cowrie.client.version"), "unknown")
        hassh  = next((e.get("hassh") for e in evts if e.get("eventid") == "cowrie.client.kex"), "unknown")
        failed = [e for e in evts if e.get("eventid") == "cowrie.login.failed"]
        success= [e for e in evts if e.get("eventid") == "cowrie.login.success"]
        cmds   = [e for e in evts if e.get("eventid") == "cowrie.command.input"]
        connect= next((e for e in evts if e.get("eventid") == "cowrie.session.connect"), None)
        ts     = connect.get("timestamp", "") if connect else ""

        summaries.append({
            "session": sid,
            "src_ip": src_ip,
            "client": client,
            "hassh": hassh,
            "failed_logins": len(failed),
            "successful_logins": len(success),
            "commands": [e.get("input") for e in cmds],
            "creds_tried": [(e.get("username"), e.get("password")) for e in failed + success],
            "timestamp": ts,
        })
    return summaries

def analyze_botnets(summaries):
    """Group sessions by HASSH fingerprint to identify botnets."""
    botnets = defaultdict(list)
    for s in summaries:
        botnets[s["hassh"]].append(s)
    return botnets

def analyze_timeline(events):
    """Count attacks per hour."""
    hourly = Counter()
    for e in events:
        if e.get("eventid") == "cowrie.session.connect":
            ts = e.get("timestamp", "")
            if ts:
                try:
                    hour = datetime.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S").hour
                    hourly[hour] += 1
                except ValueError:
                    continue
    return hourly

def print_bar(label, value, max_val, width=30):
    filled = int((value / max_val) * width) if max_val > 0 else 0
    bar = "█" * filled + "░" * (width - filled)
    print(f"   {label:<22} [{bar}] {value}")

def run_analysis(events):
    sessions  = group_by_session(events)
    summaries = get_session_summary(sessions)
    botnets   = analyze_botnets(summaries)
    hourly    = analyze_timeline(events)

    print("=" * 65)
    print("  COWRIE HONEYPOT — DEEP ATTACK ANALYSIS")
    print(f"  Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print("=" * 65)

    # ── Botnet / HASSH Fingerprint Analysis ──────────────────────────
    print("\n BOTNET FINGERPRINT ANALYSIS (by HASSH)")
    print("   Groups sessions from the same scanner/botnet infrastructure\n")
    sorted_botnets = sorted(botnets.items(), key=lambda x: len(x[1]), reverse=True)
    for hassh, sessions_list in sorted_botnets[:5]:
        ips = list({s["src_ip"] for s in sessions_list})
        client = sessions_list[0]["client"]
        print(f"   HASSH : {hassh}")
        print(f"   Client: {client}")
        print(f"   IPs   : {', '.join(ips[:5])}")
        print(f"   Sessions: {len(sessions_list)}")
        print()

    # ── Credential Stuffing Patterns ─────────────────────────────────
    print("\n CREDENTIAL STUFFING PATTERNS")
    all_creds = []
    for s in summaries:
        all_creds.extend(s["creds_tried"])
    combo_counter = Counter(all_creds)
    print(f"   {'Username':<20} {'Password':<20} {'Count'}")
    print(f"   {'-'*20} {'-'*20} {'-'*5}")
    for (user, pwd), count in combo_counter.most_common(15):
        print(f"   {str(user):<20} {str(pwd):<20} {count}x")

    # ── Most Aggressive IPs ───────────────────────────────────────────
    print("\n MOST AGGRESSIVE ATTACKER IPs")
    ip_sessions = Counter(s["src_ip"] for s in summaries)
    max_val = ip_sessions.most_common(1)[0][1] if ip_sessions else 1
    for ip, count in ip_sessions.most_common(10):
        print_bar(ip, count, max_val)

    # ── Attackers Who Got In ──────────────────────────────────────────
    successful = [s for s in summaries if s["successful_logins"] > 0]
    if successful:
        print(f"\n  ATTACKERS WITH SUCCESSFUL LOGINS ({len(successful)} sessions)")
        for s in successful:
            print(f"   {s['src_ip']:<20} {s['successful_logins']} successful login(s) | client: {s['client']}")
            if s["commands"]:
                print(f"   Commands run: {', '.join(s['commands'][:5])}")

    # ── Attack Timeline ───────────────────────────────────────────────
    print("\n  ATTACK TIMELINE (connections per hour UTC)")
    if hourly:
        max_h = max(hourly.values())
        for hour in sorted(hourly.keys()):
            print_bar(f"{hour:02d}:00", hourly[hour], max_h)

    # ── Threat Summary ────────────────────────────────────────────────
    print("\nTHREAT SUMMARY")
    print(f"   Total sessions analyzed   : {len(summaries)}")
    print(f"   Unique botnets (HASSH)    : {len(botnets)}")
    print(f"   Sessions with success     : {len(successful)}")
    print(f"   Unique credential combos  : {len(combo_counter)}")
    peak_hour = hourly.most_common(1)[0] if hourly else (0, 0)
    print(f"   Peak attack hour (UTC)    : {peak_hour[0]:02d}:00 ({peak_hour[1]} connections)")
    print("\n" + "=" * 65)

if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else LOG_PATH
    try:
        events = load_logs(path)
        if not events:
            print("No events found.")
        else:
            run_analysis(events)
    except FileNotFoundError:
        print(f"Log file not found: {path}")
        print("Make sure you're in the /home/cowrie/cowrie directory.")
