<div align="center">

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=28&pause=1000&color=FF6B6B&center=true&vCenter=true&width=700&lines=HoneyPot+Lab;Cloud-Deployed+SSH+Honeypot;Real+Attackers.+Real+Data.+Real+Insights." alt="Typing SVG" />

<br/>

![AWS](https://img.shields.io/badge/AWS-EC2-FF9900?style=for-the-badge&logo=amazonaws&logoColor=white)
![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Cowrie](https://img.shields.io/badge/Cowrie-Honeypot-FF6B6B?style=for-the-badge)
![Linux](https://img.shields.io/badge/Linux-Ubuntu-E95420?style=for-the-badge&logo=ubuntu&logoColor=white)
![Status](https://img.shields.io/badge/Status-Active-00C176?style=for-the-badge)

</div>

---

## 🍯 What Is This?

A **cloud-deployed SSH/Telnet honeypot** running on AWS EC2 that captures real-world attack traffic from the internet. Using Cowrie — an industry-standard medium-interaction honeypot — this lab logs every login attempt, command executed, and file downloaded by attackers, then analyzes the data to extract threat intelligence patterns.

> *"The best way to understand how attackers think is to let them think they've won."*

---

## 🎯 Objectives

- Deploy a production-grade honeypot on AWS EC2
- Capture and analyze real SSH brute-force attempts
- Identify attacker patterns — credential stuffing, command sequences, origins
- Generate automated threat intelligence reports from raw logs
- Document findings as a real-world security research case study

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────┐
│                    Internet                         │
│         (Real attackers scanning the web)           │
└──────────────────────┬──────────────────────────────┘
                       │ SSH/Telnet attempts
                       ▼
┌─────────────────────────────────────────────────────┐
│              AWS EC2 (t2.micro)                     │
│                                                     │
│  ┌─────────────────────────────────────────────┐   │
│  │           Cowrie Honeypot                   │   │
│  │  - Listens on port 22/23                    │   │
│  │  - Emulates vulnerable SSH server           │   │
│  │  - Logs all sessions to JSON                │   │
│  └──────────────────┬──────────────────────────┘   │
│                     │                               │
│  ┌──────────────────▼──────────────────────────┐   │
│  │         Python Analysis Pipeline            │   │
│  │  - log_parser.py                            │   │
│  │  - geoip_lookup.py                          │   │
│  │  - report_generator.py                      │   │
│  └──────────────────┬──────────────────────────┘   │
│                     │                               │
│  ┌──────────────────▼──────────────────────────┐   │
│  │         Reports & Visualizations            │   │
│  │  - Attack summary (Markdown/PDF)            │   │
│  │  - Charts (matplotlib)                      │   │
│  │  - GeoIP map of attacker origins            │   │
│  └─────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────┘
```

---

## 📁 Project Structure

```
HoneyPot_Lab/
├── README.md                  # This file
├── setup/
│   ├── cowrie_setup.sh        # Automated Cowrie install script
│   └── security_groups.md    # AWS Security Group configuration
├── scripts/
│   ├── log_parser.py          # Parse Cowrie JSON logs
│   ├── geoip_lookup.py        # Map attacker IPs to countries
│   └── report_generator.py   # Auto-generate attack summary
├── analysis/
│   ├── findings.md            # Real findings from honeypot
│   └── sample_logs/           # Anonymized log samples
├── diagrams/
│   └── architecture.png       # AWS architecture diagram
└── reports/
    └── attack_summary.md      # Generated threat intel report
```

---

## 🛠️ Tech Stack

| Component | Technology |
|---|---|
| Cloud Platform | AWS EC2 (t2.micro, Free Tier) |
| OS | Ubuntu 22.04 LTS |
| Honeypot | Cowrie v2.x |
| Log Analysis | Python 3, pandas |
| GeoIP Lookup | ip-api.com / GeoIP2 |
| Visualization | matplotlib, seaborn |
| Reporting | Markdown, Python |

---

## 📊 What Gets Captured

Every attack session logged includes:

- **Attacker IP** and geolocation
- **Credentials attempted** (username + password combos)
- **Commands executed** inside the fake shell
- **Files downloaded** (malware samples)
- **Session duration** and timestamps
- **Attack signatures** and patterns

---

## 🚧 Build Progress

- [x] Day 1 — Repo structure + README + architecture diagram
- [x] Day 2 — AWS EC2 setup + Security Groups configured
- [x] Day 3 — Cowrie installed and running
- [x] Day 4 — Verified capturing live traffic
- [x] Day 5 — `log_parser.py` complete
- [ ] Day 6 — Attacker pattern analysis script
- [ ] Day 7 — GeoIP lookup script
- [ ] Day 8 — Auto report generator
- [ ] Day 9 — Visualizations (charts + maps)
- [ ] Day 10 — Real findings documented
- [ ] Day 11 — Architecture diagram finalized
- [ ] Day 12 — Full README polish
- [ ] Day 13 — HackTrace article drafted
- [ ] Day 14 — v1.0 release

---

## ⚠️ Disclaimer

This honeypot is deployed on infrastructure I own and control. All captured data is used solely for educational research and threat intelligence analysis. Attacker IPs in published logs are anonymized. This project is intended to demonstrate defensive security research techniques.

---

## 👨‍💻 Author

**Ervin D'Souza** — MS Cybersecurity @ CCNY | Aspiring Cloud Security Engineer

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-0A66C2?style=flat-square&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/ervindsouzaa)
[![Medium](https://img.shields.io/badge/Medium-HackTrace-000000?style=flat-square&logo=medium&logoColor=white)](https://medium.com/@ervindsouza08)
[![GitHub](https://img.shields.io/badge/GitHub-CoderunED-181717?style=flat-square&logo=github&logoColor=white)](https://github.com/CoderunED)

---

<div align="center">

*Part of an ongoing cloud security research series — follow along on HackTrace*

![Visitor Count](https://komarev.com/ghpvc/?username=CoderunED&color=FF6B6B&style=flat-square&label=Repo+Views)

</div>
