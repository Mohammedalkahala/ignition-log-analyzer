# Ignition Gateway Security Operations Pipeline

A Python security automation pipeline for OT/ICS environments — built for 24/7 watch operations teams protecting critical infrastructure.

---

## What It Does

**End-to-end automated security analysis in 5 steps:**

```
Parse Logs → Classify Severity → Extract IPs → Enrich via VT/Shodan → Export Reports
```

1. **Parse** raw Linux / Ignition Gateway logs from plant environments
2. **Classify** every event as CRITICAL / HIGH / MEDIUM / LOW using keyword matching
3. **Extract** external IP addresses from log data automatically
4. **Enrich** IPs via VirusTotal (reputation) and Shodan (open ports, CVEs, geolocation)
5. **Export** structured CSV reports per severity + JSON summaries for operational decisions

---

## Why It Exists

OT/ICS environments like Ignition Gateway generate thousands of log lines per shift. Watch operations analysts need to immediately identify:
- Which events are genuinely critical vs routine noise
- Which external IPs in the logs are known malicious actors
- What vulnerabilities those IPs are exposing

This pipeline automates that entire workflow — enabling overnight SOC teams to focus on response, not data wrangling.

---

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run with built-in sample OT/ICS logs (no API keys needed)
python3 main.py

# Run against a real log file
python3 main.py /var/log/ignition/wrapper.log

# Run with live VirusTotal + Shodan API calls
export VT_API_KEY="your_key_here"
export SHODAN_API_KEY="your_key_here"
python3 main.py /var/log/ignition/wrapper.log --live
```

---

## Sample Output

```
============================================================
  IGNITION GATEWAY SECURITY OPERATIONS PIPELINE
  NERC E-ISAC Watch Operations — Automated Analysis
============================================================

[STEP 1] Parsing and classifying log data...
[+] Parsed 25 log entries

[STEP 2] Severity Classification
  🔴 CRITICAL :   9  (36.0%)
  🟠 HIGH     :   7
  🟡 MEDIUM   :   2
  🟢 LOW      :   7

  TOP CRITICAL EVENTS:
  Keyword: authentication failure | Failed login from 203.0.113.5
  Keyword: privilege escalation   | Escalation attempt process 1337
  Keyword: ssl handshake failed   | SSL error from 198.51.100.7

[STEP 3] Extracted 3 unique external IPs

[STEP 4] IP Enrichment Results
  [CRITICAL] 203.0.113.5  — VT: MALICIOUS | ChinaNet | Ports: 22,80,443,3389 | CVEs: 2
  [CRITICAL] 198.51.100.99 — VT: MALICIOUS | DigitalOcean | Ports: 80,443,4444 | CVEs: 1
  [LOW]      198.51.100.7  — VT: SUSPICIOUS | Rostelecom | Ports: 22,443

[STEP 5] Reports exported to /output/
```

---

## Output Files

| File | Contents |
|------|----------|
| `all_events_TIMESTAMP.csv` | Full classified log dataset |
| `critical_events_TIMESTAMP.csv` | CRITICAL events only |
| `high_events_TIMESTAMP.csv` | HIGH events only |
| `enrichment_report_TIMESTAMP.csv` | IP enrichment results with risk scores |
| `enrichment_report_TIMESTAMP.json` | Structured enrichment data |
| `summary_TIMESTAMP.json` | Event counts, top keywords, metadata |

---

## Project Structure

```
ignition-log-analyzer/
├── main.py          # Pipeline orchestrator — runs all 5 steps
├── log_analyzer.py  # Log parsing, severity classification, CSV/JSON export
├── enrichment.py    # VirusTotal + Shodan IP enrichment, risk scoring
├── requirements.txt
└── README.md
```

---

## Severity Classification Keywords

| Level | Examples |
|-------|---------|
| CRITICAL | authentication failure, unauthorized, privilege escalation, data loss, ssl handshake failed, exploit, malware, fatal |
| HIGH | error, failed, timeout, suspicious, anomaly, brute force, scan detected, high cpu |
| MEDIUM | warning, retry, degraded, configuration change, disconnected |
| LOW | info, started, heartbeat, backup, success, connected |

---

## Supported Log Formats

- Standard Linux syslog
- Ignition Gateway format
- ISO timestamp format
- Raw unstructured log lines (fallback)

---

## Tech Stack

- **Python 3** — core language
- **pandas** — data wrangling, filtering, grouping, structured exports
- **requests** — VirusTotal and Shodan REST API integration
- **re** — log parsing with regex
- **json** — structured report generation

---

## Real-World Context

Built from direct experience securing 24/7 OT/ICS industrial environments at Tamaki Control — where manufacturing and utility clients cannot tolerate security blind spots. This pipeline automates the initial triage and enrichment workflow that watch operations analysts would otherwise perform manually.

**Directly applicable to:**
- NERC E-ISAC Watch Operations
- Electric utility security operations centers
- Manufacturing plant security monitoring
- Any 24/7 OT/ICS security operations environment

---

## Author

Mohammed Alkahala — Security Operations Engineer  
[LinkedIn](https://linkedin.com/in/mohammed-alkahala-6362b4192) | [GitHub](https://github.com/Mohammedalkahala)
