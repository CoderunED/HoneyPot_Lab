#!/usr/bin/env python3
"""
report_generator.py — Automated Threat Intelligence Report Generator
HoneyPot_Lab by @CoderunED

Generates a complete Markdown threat intel report from Cowrie JSON logs.
Output can be published directly to Medium/HackTrace or stored in reports/
"""

import json
import sys
import time
import urllib.request
from collections import Counter, defaultdict
from datetime import datetime, timezone

LOG_PATH    = "var/log/cowrie/cowrie.json"
REPORT_PATH = "reports/attack_summary.md"
API_URL     = "http://ip-api.com/json/{}?fields=status,country,countryCode,regionName,city,org,as,query"

# ── Helpers ───────────────────────────────────────────────────────────────────

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

def flag(code):
    if not code or len(code) != 2:
        return 
    return chr(ord(code[0]) + 127397) + chr(ord(code[1]) + 127397)

def lookup_ip(ip):
    try:
        req = urllib.request.Request(
            API_URL.format(ip),
            headers={"User-Agent": "HoneyPot-Lab-Reporter/1.0"}
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
            if data.get("status") == "success":
                return data
    except Exception:
        pass
    return {}

def group_sessions(events):
    sessions = defaultdict(list)
    for e in events:
        sid = e.get("session")
        if sid:
            sessions[sid].append(e)
    return sessions

# ── Analysis ──────────────────────────────────────────────────────────────────

def analyze(events):
    connections   = [e for e in events if e["eventid"] == "cowrie.session.connect"]
    failed        = [e for e in events if e["eventid"] == "cowrie.login.failed"]
    success       = [e for e in events if e["eventid"] == "cowrie.login.success"]
    commands      = [e for e in events if e["eventid"] == "cowrie.command.input"]
    clients       = [e for e in events if e["eventid"] == "cowrie.client.version"]
    kex_events    = [e for e in events if e["eventid"] == "cowrie.client.kex"]

    unique_ips    = Counter(e["src_ip"] for e in connections if e.get("src_ip"))
    usernames     = Counter(e.get("username","") for e in failed + success)
    passwords     = Counter(e.get("password","") for e in failed + success)
    client_vers   = Counter(e.get("version","") for e in clients)
    hassh_counter = Counter(e.get("hassh","") for e in kex_events)
    cmd_counter   = Counter(e.get("input","") for e in commands)
    success_ips   = set(e.get("src_ip") for e in success if e.get("src_ip"))

    hourly = Counter()
    for e in connections:
        ts = e.get("timestamp","")
        if ts:
            try:
                hour = datetime.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S").hour
                hourly[hour] += 1
            except ValueError:
                continue

    return {
        "total_events"   : len(events),
        "connections"    : len(connections),
        "unique_ips"     : unique_ips,
        "failed_logins"  : len(failed),
        "success_logins" : len(success),
        "success_ips"    : success_ips,
        "commands"       : len(commands),
        "usernames"      : usernames,
        "passwords"      : passwords,
        "clients"        : client_vers,
        "hassh"          : hassh_counter,
        "cmd_list"       : cmd_counter,
        "hourly"         : hourly,
    }

def geoip_lookup(unique_ips):
    print(f"[*] Looking up {len(unique_ips)} IPs for GeoIP data...")
    geo = {}
    for i, ip in enumerate(sorted(unique_ips.keys()), 1):
        print(f"    [{i}/{len(unique_ips)}] {ip}", end=" ... ", flush=True)
        data = lookup_ip(ip)
        geo[ip] = data
        print(data.get("country", "unknown"))
        time.sleep(1.4)
    return geo

# ── Report Builder ────────────────────────────────────────────────────────────

def build_report(stats, geo):
    now      = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    unique   = stats["unique_ips"]
    geo_data = geo

    country_counts = Counter()
    for ip, g in geo_data.items():
        country = g.get("country", "Unknown")
        country_counts[country] += unique.get(ip, 1)

    org_counts = Counter()
    for ip, g in geo_data.items():
        org = g.get("org", "Unknown")
        org_counts[org] += unique.get(ip, 1)

    peak_hour = stats["hourly"].most_common(1)[0] if stats["hourly"] else (0, 0)

    lines = []
    lines.append(f"#  HoneyPot Lab — Threat Intelligence Report")
    lines.append(f"\n> **Generated:** {now}  ")
    lines.append(f"> **Sensor:** AWS EC2 (us-east-2) — Cowrie SSH Honeypot  ")
    lines.append(f"> **Author:** Ervin D'Souza | MS Cybersecurity @ CCNY\n")
    lines.append("---\n")

    # Executive Summary
    lines.append("##  Executive Summary\n")
    lines.append(
        f"Over the monitored period, the honeypot recorded **{stats['connections']} connection attempts** "
        f"from **{len(unique)} unique IP addresses** across **{len(country_counts)} countries**. "
        f"Of these, **{stats['success_logins']} sessions resulted in successful authentication** "
        f"using weak or default credentials. All attacker activity was captured in an isolated "
        f"environment with no production systems at risk.\n"
    )

    # Key Metrics
    lines.append("##  Key Metrics\n")
    lines.append("| Metric | Value |")
    lines.append("|---|---|")
    lines.append(f"| Total events parsed | {stats['total_events']} |")
    lines.append(f"| Total connection attempts | {stats['connections']} |")
    lines.append(f"| Unique attacker IPs | {len(unique)} |")
    lines.append(f"| Countries represented | {len(country_counts)} |")
    lines.append(f"| Failed login attempts | {stats['failed_logins']} |")
    lines.append(f"| Successful logins | {stats['success_logins']} |")
    lines.append(f"| Commands executed | {stats['commands']} |")
    lines.append(f"| Unique botnets (HASSH) | {len(stats['hassh'])} |")
    lines.append(f"| Peak attack hour (UTC) | {peak_hour[0]:02d}:00 ({peak_hour[1]} connections) |\n")

    # Top Attacker IPs
    lines.append("##  Top Attacker IPs\n")
    lines.append("| IP Address | Country | Organization | Connections | Successful Login |")
    lines.append("|---|---|---|---|---|")
    for ip, count in unique.most_common(15):
        g = geo_data.get(ip, {})
        country = g.get("country", "Unknown")
        org     = g.get("org", "Unknown")[:35]
        f       = flag(g.get("countryCode", ""))
        pwned   = " YES" if ip in stats["success_ips"] else "No"
        lines.append(f"| `{ip}` | {f} {country} | {org} | {count} | {pwned} |")
    lines.append("")

    # Attacks by Country
    lines.append("## ️ Attacks by Country\n")
    lines.append("| Country | Connections | % of Total |")
    lines.append("|---|---|---|")
    total_conns = stats["connections"] or 1
    for country, count in country_counts.most_common(10):
        code = next((g.get("countryCode","") for g in geo_data.values() if g.get("country") == country), "")
        f    = flag(code)
        pct  = round((count / total_conns) * 100, 1)
        lines.append(f"| {f} {country} | {count} | {pct}% |")
    lines.append("")

    # Top Organizations
    lines.append("##  Top Attacker Organizations\n")
    lines.append("| Organization | Connections |")
    lines.append("|---|---|")
    for org, count in org_counts.most_common(8):
        lines.append(f"| {org} | {count} |")
    lines.append("")

    # Credential Analysis
    lines.append("## Credential Stuffing Analysis\n")
    lines.append("### Top Usernames Tried\n")
    lines.append("| Username | Attempts |")
    lines.append("|---|---|")
    for user, count in stats["usernames"].most_common(10):
        lines.append(f"| `{user}` | {count} |")
    lines.append("")

    lines.append("### Top Passwords Tried\n")
    lines.append("| Password | Attempts |")
    lines.append("|---|---|")
    for pwd, count in stats["passwords"].most_common(10):
        lines.append(f"| `{pwd}` | {count} |")
    lines.append("")

    # Botnet Analysis
    lines.append("## 🤖 Botnet Fingerprint Analysis\n")
    lines.append("| HASSH Fingerprint | SSH Client | Sessions |")
    lines.append("|---|---|---|")
    for hassh, count in stats["hassh"].most_common(8):
        client = next((e.get("version","unknown") for e in [] if e.get("hassh") == hassh), "unknown")
        lines.append(f"| `{hassh[:32]}...` | {client} | {count} |")
    lines.append("")

    # SSH Clients
    lines.append("## ️ Attacker SSH Clients\n")
    lines.append("| Client | Sessions |")
    lines.append("|---|---|")
    for client, count in stats["clients"].most_common(8):
        lines.append(f"| `{client}` | {count} |")
    lines.append("")

    # Attack Timeline
    lines.append("## Attack Timeline (UTC)\n")
    lines.append("| Hour | Connections |")
    lines.append("|---|---|")
    for hour in sorted(stats["hourly"].keys()):
        bar = "█" * min(stats["hourly"][hour], 20)
        lines.append(f"| {hour:02d}:00 | {bar} {stats['hourly'][hour]} |")
    lines.append("")

    # Commands
    if stats["cmd_list"]:
        lines.append("##  Commands Executed by Attackers\n")
        lines.append("| Command | Count |")
        lines.append("|---|---|")
        for cmd, count in stats["cmd_list"].most_common(10):
            lines.append(f"| `{cmd[:60]}` | {count} |")
        lines.append("")

    # Successful Logins
    if stats["success_ips"]:
        lines.append("##  Successful Logins\n")
        lines.append("| IP Address | Country | Credentials Used |")
        lines.append("|---|---|---|")
        seen = set()
        for e in [ev for ev in [] if ev.get("eventid") == "cowrie.login.success"]:
            ip  = e.get("src_ip","")
            usr = e.get("username","")
            pwd = e.get("password","")
            key = f"{ip}-{usr}-{pwd}"
            if key not in seen:
                seen.add(key)
                g   = geo_data.get(ip, {})
                f   = flag(g.get("countryCode",""))
                lines.append(f"| `{ip}` | {f} {g.get('country','Unknown')} | `{usr}:{pwd}` |")
        lines.append("")

    # Key Findings
    lines.append("## 🔍 Key Findings\n")
    top_country = country_counts.most_common(1)[0] if country_counts else ("Unknown", 0)
    top_org     = org_counts.most_common(1)[0] if org_counts else ("Unknown", 0)
    top_client  = stats["clients"].most_common(1)[0] if stats["clients"] else ("Unknown", 0)
    top_pwd     = stats["passwords"].most_common(1)[0] if stats["passwords"] else ("Unknown", 0)

    lines.append(f"1. **Geographic concentration** — {top_country[0]} was the top source of attacks with {top_country[1]} connections ({round(top_country[1]/total_conns*100,1)}% of total traffic).")
    lines.append(f"2. **Cloud infrastructure abuse** — {top_org[0]} was the most common attack origin, indicating attackers leverage cloud VPS for anonymity and scale.")
    lines.append(f"3. **Automated scanning** — {top_client[1]} sessions used `{top_client[0]}`, confirming fully automated botnet activity.")
    lines.append(f"4. **Weak credentials** — `{top_pwd[0]}` was the most attempted password, highlighting the risk of default credentials.")
    lines.append(f"5. **Coordinated campaign** — Multiple IPs sharing identical HASSH fingerprints across different countries indicate a single botnet operator controlling distributed infrastructure.\n")

    # Disclaimer
    lines.append("---\n")
    lines.append("##  Disclaimer\n")
    lines.append(
        "This honeypot is deployed on infrastructure owned and controlled by the author. "
        "All captured data is used solely for educational research and threat intelligence analysis. "
        "Attacker IPs in this report are real but published for research purposes only. "
        "No production systems were involved.\n"
    )
    lines.append("---\n")
    lines.append("*Report generated by [HoneyPot Lab](https://github.com/CoderunED/HoneyPot_Lab) — @CoderunED*")

    return "\n".join(lines)

# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    log_path    = sys.argv[1] if len(sys.argv) > 1 else LOG_PATH
    report_path = sys.argv[2] if len(sys.argv) > 2 else REPORT_PATH

    print(f"[*] Loading logs from {log_path}...")
    try:
        events = load_logs(log_path)
    except FileNotFoundError:
        print(f"[!] Log file not found: {log_path}")
        sys.exit(1)

    if not events:
        print("[!] No events found.")
        sys.exit(1)

    print(f"[*] Parsed {len(events)} events.")
    stats = analyze(events)

    geo = geoip_lookup(stats["unique_ips"])

    print(f"\n[*] Building report...")
    report = build_report(stats, geo)

    with open(report_path, "w") as f:
        f.write(report)

    print(f"[✓] Report saved to {report_path}")
    print(f"[✓] {len(report.splitlines())} lines written")
