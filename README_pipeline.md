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

## Quick Start

### Windows (PowerShell)

```powershell
# Install dependencies
py -m pip install pandas requests

# Run with built-in sample OT/ICS logs (no API keys needed)
py main.py

# Run against a real Ignition Gateway wrapper log
py main.py C:\path\to\wrapper.log

# Run with live VirusTotal + Shodan API calls
$env:VT_API_KEY="your_vt_key_here"
$env:SHODAN_API_KEY="your_shodan_key_here"
py main.py C:\path\to\wrapper.log --live
```

### Linux / Mac

```bash
# Install dependencies
pip3 install pandas requests

# Run with built-in sample OT/ICS logs (no API keys needed)
python3 main.py

# Run against a real Ignition Gateway wrapper log
python3 main.py /var/log/ignition/wrapper.log

# Run with live VirusTotal + Shodan API calls
export VT_API_KEY="your_vt_key_here"
export SHODAN_API_KEY="your_shodan_key_here"
python3 main.py /var/log/ignition/wrapper.log --live
```

---

## API Keys — Do You Need Them?

**No — demo mode works without any API keys.**

Running without API keys uses built-in demo enrichment that produces realistic output for testing and presentation. This is the recommended starting point.

When you're ready to use real enrichment:

**VirusTotal (Free tier available)**
- Sign up at virustotal.com
- Go to your profile → API Key
- Free tier: 4 requests per minute, 500 requests per day
- Set key: `$env:VT_API_KEY="your_key"` (Windows) or `export VT_API_KEY="your_key"` (Linux/Mac)

**Shodan (Free tier very limited)**
- Sign up at account.shodan.io
- Free tier has limited query access
- Personal membership: $49 one-time fee for full access
- Enterprise accounts used in production SOC environments
- Set key: `$env:SHODAN_API_KEY="your_key"` (Windows) or `export SHODAN_API_KEY="your_key"` (Linux/Mac)

---

## Real-World Test Results

Tested against a live Ignition Gateway server running on Linux (Ubuntu, Proxmox VM):

```
============================================================
  IGNITION GATEWAY SECURITY OPERATIONS PIPELINE
  NERC E-ISAC Watch Operations — Automated Analysis
============================================================

[STEP 1] Parsing and classifying log data...
[+] Parsed 29,693 log entries from wrapper.log

[STEP 2] Severity Classification
  🔴 CRITICAL :      6  (connection refused — SQL exceptions)
  🟠 HIGH     :    323
  🟡 MEDIUM   :     57
  🟢 LOW      :  29,307

[STEP 3] Extracted 2 unique external IPs

[STEP 4] IP Enrichment (demo mode)
  All IPs resolved to LOW risk

[STEP 5] Reports exported to /output/
[✓] Pipeline complete.
```

**Key insight from real data:** Ignition Gateway sometimes logs serious errors like SQL
connection failures at INFO level. This pipeline catches them anyway via keyword matching —
something you would miss if filtering only by the log's own severity label.

---

## Sample Output (Built-in Demo Logs)

```
============================================================
  IGNITION GATEWAY LOG ANALYZER — SECURITY DASHBOARD
============================================================
  Total     : 25 events
------------------------------------------------------------
  🔴 CRITICAL :   9  (36.0%)
  🟠 HIGH     :   7
  🟡 MEDIUM   :   2
  🟢 LOW      :   7

  TOP CRITICAL EVENTS:
  Keyword: authentication failure | Failed login from 203.0.113.5
  Keyword: privilege escalation   | Escalation attempt process 1337
  Keyword: ssl handshake failed   | SSL error from 198.51.100.7

  IP ENRICHMENT DASHBOARD
  [CRITICAL] 203.0.113.5   — VT: MALICIOUS | ChinaNet  | CVEs: 2
  [CRITICAL] 198.51.100.99 — VT: MALICIOUS | DigitalOcean | CVEs: 1
```

---

## Output Files

| File | Contents |
|------|----------|
| `all_events_TIMESTAMP.csv` | Full classified log dataset |
| `critical_events_TIMESTAMP.csv` | CRITICAL events only |
| `high_events_TIMESTAMP.csv` | HIGH events only |
| `medium_events_TIMESTAMP.csv` | MEDIUM events only |
| `low_events_TIMESTAMP.csv` | LOW events only |
| `enrichment_report_TIMESTAMP.csv` | IP enrichment with risk scores |
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
| CRITICAL | authentication failure, unauthorized, privilege escalation, data loss, ssl handshake failed, exploit, malware, fatal, connection refused |
| HIGH | error, failed, timeout, suspicious, anomaly, brute force, scan detected, high cpu |
| MEDIUM | warning, retry, degraded, configuration change, disconnected |
| LOW | info, started, heartbeat, backup, success, connected |

---

## Supported Log Formats

- Standard Linux syslog
- Ignition Gateway wrapper.log format
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

Built from direct experience securing 24/7 OT/ICS industrial environments at Tamaki Control.
Tested against live Ignition Gateway wrapper logs from a production Linux server.

This pipeline automates the initial triage and enrichment workflow that watch operations
analysts would otherwise perform manually — directly applicable to NERC E-ISAC Watch
Operations and any critical infrastructure SOC environment.

---

## Author

Mohammed Alkahala — Security Operations Engineer
[LinkedIn](https://linkedin.com/in/mohammed-alkahala-6362b4192) | [GitHub](https://github.com/Mohammedalkahala)
