#!/usr/bin/env python3
"""
geoip_lookup.py — GeoIP Lookup for Attacker IPs
HoneyPot_Lab by @CoderunED
"""

import json
import sys
import time
import urllib.request
import urllib.error
from collections import Counter
from datetime import datetime

LOG_PATH = "var/log/cowrie/cowrie.json"
API_URL  = "http://ip-api.com/json/{}?fields=status,country,countryCode,regionName,city,org,as,query"

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

def get_unique_ips(events):
    ips = set()
    for e in events:
        if e.get("eventid") == "cowrie.session.connect":
            ip = e.get("src_ip")
            if ip:
                ips.add(ip)
    return ips

def lookup_ip(ip):
    """Lookup a single IP via ip-api.com (free, no key needed)."""
    try:
        url = API_URL.format(ip)
        req = urllib.request.Request(url, headers={"User-Agent": "HoneyPot-Lab-Analyzer/1.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
            if data.get("status") == "success":
                return data
    except Exception:
        pass
    return None

def lookup_all(ips):
    """Lookup all IPs with rate limiting (ip-api allows 45 req/min free)."""
    results = {}
    total = len(ips)
    print(f"   Looking up {total} IPs (this may take a moment)...\n")
    for i, ip in enumerate(sorted(ips), 1):
        print(f"   [{i}/{total}] {ip}", end=" ... ", flush=True)
        data = lookup_ip(ip)
        if data:
            results[ip] = data
            print(f"{data.get('country', 'Unknown')} ({data.get('city', '')})")
        else:
            results[ip] = {"country": "Unknown", "countryCode": "??", "org": "Unknown", "city": ""}
            print("lookup failed")
        time.sleep(1.4)  # Stay under 45 req/min
    return results

def get_connection_counts(events):
    counts = Counter()
    for e in events:
        if e.get("eventid") == "cowrie.session.connect":
            ip = e.get("src_ip")
            if ip:
                counts[ip] += 1
    return counts

def get_successful_ips(events):
    ips = set()
    for e in events:
        if e.get("eventid") == "cowrie.login.success":
            ip = e.get("src_ip")
            if ip:
                ips.add(ip)
    return ips

def flag(code):
    """Convert country code to flag emoji."""
    if not code or len(code) != 2:
        return
    return chr(ord(code[0]) + 127397) + chr(ord(code[1]) + 127397)

def print_bar(label, value, max_val, width=25):
    filled = int((value / max_val) * width) if max_val > 0 else 0
    bar = "█" * filled + "░" * (width - filled)
    print(f"   {label:<25} [{bar}] {value}")

def run_geoip(events):
    unique_ips    = get_unique_ips(events)
    conn_counts   = get_connection_counts(events)
    success_ips   = get_successful_ips(events)

    print("=" * 65)
    print("  COWRIE HONEYPOT — GEOIP ATTACKER ANALYSIS")
    print(f"  Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print("=" * 65)
    print()

    geo_data = lookup_all(unique_ips)

    # ── Per-IP breakdown ─────────────────────────────────────────────
    print("\n  ATTACKER IP BREAKDOWN")
    print(f"   {'IP':<20} {'Country':<20} {'City':<15} {'Org':<30} {'Conns':<6} {'Pwned'}")
    print(f"   {'-'*20} {'-'*20} {'-'*15} {'-'*30} {'-'*6} {'-'*5}")
    for ip in sorted(unique_ips, key=lambda x: conn_counts[x], reverse=True):
        g = geo_data.get(ip, {})
        country  = g.get("country", "Unknown")
        city     = g.get("city", "")[:14]
        org      = g.get("org", "Unknown")[:29]
        conns    = conn_counts[ip]
        pwned    = "YES" if ip in success_ips else "no"
        f        = flag(g.get("countryCode", ""))
        print(f"   {ip:<20} {f} {country:<18} {city:<15} {org:<30} {conns:<6} {pwned}")

    # ── Country summary ───────────────────────────────────────────────
    country_counts = Counter()
    for ip, g in geo_data.items():
        country = g.get("country", "Unknown")
        country_counts[country] += conn_counts.get(ip, 1)

    print("\n ATTACKS BY COUNTRY")
    max_val = country_counts.most_common(1)[0][1] if country_counts else 1
    for country, count in country_counts.most_common(10):
        code = next((g.get("countryCode","") for g in geo_data.values() if g.get("country") == country), "")
        f = flag(code)
        print_bar(f"{f} {country}", count, max_val)

    # ── ASN / Org summary ─────────────────────────────────────────────
    org_counts = Counter()
    for ip, g in geo_data.items():
        org = g.get("org", "Unknown")
        org_counts[org] += conn_counts.get(ip, 1)

    print("\n  TOP ATTACKER ORGANIZATIONS / ASNs")
    max_org = org_counts.most_common(1)[0][1] if org_counts else 1
    for org, count in org_counts.most_common(8):
        print_bar(org[:25], count, max_org)

    # ── Summary ───────────────────────────────────────────────────────
    print(f"\n GEOIP SUMMARY")
    print(f"   Unique attacker IPs      : {len(unique_ips)}")
    print(f"   Countries represented    : {len(country_counts)}")
    top_country = country_counts.most_common(1)[0] if country_counts else ("Unknown", 0)
    print(f"   Most attacks from        : {top_country[0]} ({top_country[1]} connections)")
    print(f"   IPs with successful login: {len(success_ips)}")
    print("\n" + "=" * 65)

if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else LOG_PATH
    try:
        events = load_logs(path)
        if not events:
            print("No events found.")
        else:
            run_geoip(events)
    except FileNotFoundError:
        print(f"Log file not found: {path}")
        print("Make sure you're in the /home/cowrie/cowrie directory.")
