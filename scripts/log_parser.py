#!/usr/bin/env python3
"""
log_parser.py — Cowrie Honeypot Log Analyzer
HoneyPot_Lab by @CoderunED
"""

import json
import sys
from collections import Counter
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

def analyze(events):
    connections     = [e for e in events if e["eventid"] == "cowrie.session.connect"]
    login_attempts  = [e for e in events if e["eventid"] == "cowrie.login.failed"]
    login_success   = [e for e in events if e["eventid"] == "cowrie.login.success"]
    commands        = [e for e in events if e["eventid"] == "cowrie.command.input"]
    clients         = [e for e in events if e["eventid"] == "cowrie.client.version"]

    unique_ips      = Counter(e["src_ip"] for e in connections)
    usernames       = Counter(e.get("username", "") for e in login_attempts)
    passwords       = Counter(e.get("password", "") for e in login_attempts)
    client_versions = Counter(e.get("version", "") for e in clients)
    cmd_list        = Counter(e.get("input", "") for e in commands)

    print("=" * 60)
    print("  COWRIE HONEYPOT — ATTACK SUMMARY")
    print(f"  Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print("=" * 60)

    print(f"\n  CONNECTIONS")
    print(f"   Total connection attempts : {len(connections)}")
    print(f"   Unique attacker IPs       : {len(unique_ips)}")
    print(f"   Successful logins         : {len(login_success)}")
    print(f"   Failed login attempts     : {len(login_attempts)}")
    print(f"   Commands executed         : {len(commands)}")

    print(f"\n TOP ATTACKER IPs")
    for ip, count in unique_ips.most_common(10):
        print(f"   {ip:<20} {count} connections")

    print(f"\n TOP USERNAMES TRIED")
    for user, count in usernames.most_common(10):
        print(f"   {user:<20} {count}x")

    print(f"\n  TOP PASSWORDS TRIED")
    for pwd, count in passwords.most_common(10):
        print(f"   {pwd:<20} {count}x")

    print(f"\n  ATTACKER SSH CLIENTS")
    for client, count in client_versions.most_common(5):
        print(f"   {client:<40} {count}x")

    if commands:
        print(f"\n  COMMANDS RUN BY ATTACKERS")
        for cmd, count in cmd_list.most_common(10):
            print(f"   {cmd:<40} {count}x")

    if login_success:
        print(f"\n  SUCCESSFUL LOGINS (attacker got in!)")
        for e in login_success:
            print(f"   {e['src_ip']} — user: {e.get('username')} pass: {e.get('password')}")

    print("\n" + "=" * 60)
    print(f"  Log file: {LOG_PATH}")
    print(f"  Total events parsed: {len(events)}")
    print("=" * 60)

if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else LOG_PATH
    try:
        events = load_logs(path)
        if not events:
            print("No events found. Is Cowrie running and receiving connections?")
        else:
            analyze(events)
    except FileNotFoundError:
        print(f"Log file not found: {path}")
        print("Make sure Cowrie is running and you're in the /home/cowrie/cowrie directory.")

