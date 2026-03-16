# 🔍 Honeypot Lab — Real Findings & Threat Intelligence

> **Observation period:** March 13–16, 2026  
> **Sensor:** AWS EC2 t2.micro (us-east-2) — Cowrie SSH Honeypot  
> **Author:** Ervin D'Souza | MS Cybersecurity @ CCNY

---

## 1. Overview

Within **6 minutes** of the honeypot going live, the first automated scanner had already probed the instance. Over the 3-day observation period, the honeypot recorded **102 connection attempts** from **24 unique IPs** across **9 countries**, with **26 successful logins** using weak or default credentials.

This confirms a well-known reality in cloud security: any publicly exposed SSH port will be discovered and attacked within minutes — not hours or days.

---

## 2. Key Findings

### Finding 1 — Internet Exposure = Immediate Attack
**Observation:** The first connection attempt arrived at `18:55:27 UTC` on March 13, just 6 minutes after Cowrie started listening on port 2222.

**Attacker:** `44.220.185.232` (AWS EC2, us-east-1) using `SSH-2.0-paramiko_2.9.2`

**Implication:** Cloud instances with open SSH ports are discovered almost instantly by automated scanners. Security groups must restrict SSH access by default — no exceptions.

---

### Finding 2 — Coordinated Botnet Campaign (DigitalOcean Infrastructure)
**Observation:** Four IP addresses from different geographic locations shared an identical HASSH fingerprint (`2ec37a7cc8daf20b10e1ad6221061ca5`) and SSH client (`SSH-2.0-Go`):

| IP | Location | Connections | Successful Logins |
|---|---|---|---|
| `162.243.100.170` | 🇺🇸 Secaucus, US | 11 | 6 |
| `167.71.203.14` | 🇸🇬 Singapore | 9 | 8 |
| `64.227.190.117` | 🇮🇳 Bengaluru, India | 8 | 5 |
| `134.199.175.210` | 🇦🇺 Sydney, Australia | 8 | 5 |

**Analysis:** All four IPs are DigitalOcean VPS instances. The identical HASSH fingerprint indicates the same scanning tool compiled from the same source code, controlled by a single threat actor operating distributed infrastructure across multiple continents to avoid IP-based blocking.

**Implication:** IP-based blocking alone is insufficient against distributed botnets. Behavioral detection (HASSH fingerprinting, rate limiting, geo-blocking) is more effective.

---

### Finding 3 — Credential Stuffing from rockyou.txt
**Observation:** The top passwords attempted were all from well-known wordlists:

| Rank | Password | Attempts |
|---|---|---|
| 1 | `root` | 4 |
| 2 | `123456` | 3 |
| 3 | `password` | 3 |
| 4 | `123456789` | 3 |
| 5 | `12345` | 3 |
| 6 | `admin` | 3 |
| 7 | `qwerty` | 2 |
| 8 | `1234` | 2 |
| 9 | `1q2w3e4r` | 1 |
| 10 | `P@ssword1` | 1 |

**Analysis:** 100% of login attempts targeted the `root` user. The password list matches the top entries from rockyou.txt — the most widely used credential stuffing wordlist. The presence of `P@ssword1` indicates attackers are also using "complex password" variations that meet basic password policies.

**Implication:** Default and common passwords remain the primary attack vector. Password policies alone are insufficient — MFA and key-based authentication are essential.

---

### Finding 4 — Indonesia as Top Attack Source
**Observation:** Indonesia accounted for **40 connections (39.2%)** of all traffic, with both IPs belonging to Telekomunikasi Indonesia (the state ISP):

| IP | City | Connections |
|---|---|---|
| `36.94.107.121` | Jakarta | 22 |
| `36.95.240.73` | South Tangerang | 18 |

**Analysis:** These IPs are likely compromised consumer routers or IoT devices on the Telekomunikasi Indonesia network being used as botnet nodes. The high volume with no successful logins suggests a pure scanning/enumeration role rather than active exploitation.

**Implication:** State ISP ranges from developing nations are commonly used as botnet relay infrastructure due to lower security monitoring. Geo-based rate limiting for high-volume source regions is an effective mitigation.

---

### Finding 5 — AWS Scanning AWS
**Observation:** `16.58.56.214` (AWS EC2, us-east-2 — same region as the honeypot) made 6 connection attempts using `SSH-2.0-libssh2_1.11.1`.

**Analysis:** Attackers actively use cloud provider infrastructure to scan other cloud instances. This creates a blind spot for cloud-provider-level network monitoring since the traffic appears to be legitimate intra-cloud communication.

**Implication:** Cloud security cannot rely solely on network perimeter controls. Host-based detection (like Cowrie) is essential for catching intra-cloud attacks.

---

### Finding 6 — HTTP Scanners Hitting SSH Port
**Observation:** 6 sessions used `GET / HTTP/1.1` as their SSH client string — HTTP scanners that hit every open port regardless of protocol.

**Analysis:** These are mass internet scanners (likely Shodan, Censys, or similar) that scan all ports on all IPs and attempt HTTP requests regardless of the service running. They confirm the honeypot's public IP was indexed by internet scanning services within hours of going live.

**Implication:** Any publicly exposed port will be discovered and probed. Security through obscurity (non-standard ports) provides minimal protection against modern internet scanners.

---

### Finding 7 — Peak Attack Hours
**Observation:** Attacks occurred at every hour of the day with a peak at **18:00 UTC (17 connections)**:

| Time (UTC) | Activity |
|---|---|
| 00:00–06:00 | Low (2–9 connections/hour) |
| 07:00–11:00 | Medium (10–11 connections/hour) |
| 14:00–15:00 | Medium (9–11 connections/hour) |
| 18:00–19:00 | **Peak (17–8 connections/hour)** |

**Analysis:** The continuous 24/7 attack pattern with no clear "off hours" confirms fully automated botnet activity with no human involvement. The 18:00 UTC peak may correspond to scheduled botnet jobs or higher internet activity in Asian time zones (02:00 JST = high activity period).

**Implication:** Security monitoring must be continuous — attack activity does not follow business hours.

---

## 3. MITRE ATT&CK Mapping

| Technique | ID | Observed |
|---|---|---|
| Valid Accounts: Default Accounts | T1078.001 | root/password, root/admin attempts |
| Brute Force: Password Spraying | T1110.003 | Same passwords tried across multiple sessions |
| Network Service Discovery | T1046 | Port scanners probing SSH |
| Exploit Public-Facing Application | T1190 | Direct SSH brute force |
| Resource Hijacking (likely intent) | T1496 | Attackers logging in suggest cryptomining intent |

---

## 4. Recommendations

Based on observed attack patterns, the following controls would have prevented all 26 successful honeypot logins:

1. **Disable password authentication** — Use SSH key-based authentication only (`PasswordAuthentication no` in sshd_config)
2. **Restrict SSH access** — Limit port 22 to specific trusted IP ranges via security groups
3. **Use AWS Session Manager** — Eliminate SSH entirely for administrative access (as this lab does)
4. **Enable MFA** — Add a second factor for any remote access
5. **Deploy fail2ban** — Auto-block IPs after N failed attempts
6. **HASSH-based detection** — Block known botnet SSH fingerprints at the network level
7. **CloudWatch alerts** — Set alarms for >10 failed SSH attempts in 5 minutes

---

## 5. Tools Used

| Tool | Purpose |
|---|---|
| Cowrie v2.9.14 | SSH honeypot — captured all sessions |
| log_parser.py | Parsed cowrie.json → attack summary |
| attack_analyzer.py | HASSH fingerprinting + botnet detection |
| geoip_lookup.py | IP → country/org mapping via ip-api.com |
| Filebeat 8.17 | Shipped logs to Elastic SIEM |
| Kibana Maps | Live geo visualization of attacker origins |
| AWS CloudWatch | Cloud-native log storage and querying |

---

*Part of the [HoneyPot Lab](https://github.com/CoderunED/HoneyPot_Lab) project by @CoderunED*
