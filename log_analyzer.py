#!/usr/bin/env python3
"""
Ignition Gateway Log Analyzer
------------------------------
Parses Linux server logs from Ignition Gateway environments,
classifies events by severity using keyword matching,
and outputs structured reports for security operations review.

Author: Mohammed Alkahala
Use Case: OT/ICS Security Operations — Critical Infrastructure Monitoring
"""

import pandas as pd
import re
import json
import os
import sys
from datetime import datetime
from collections import defaultdict


# ─────────────────────────────────────────────
# SEVERITY KEYWORD MAPPING
# ─────────────────────────────────────────────

SEVERITY_KEYWORDS = {
    "CRITICAL": [
        "critical", "emergency", "fatal", "panic",
        "authentication failure", "unauthorized", "exploit",
        "intrusion", "attack", "breach", "ransomware",
        "malware", "rootkit", "backdoor", "privilege escalation",
        "remote code execution", "sql injection", "buffer overflow",
        "connection refused", "access denied", "certificate error",
        "ssl handshake failed", "corrupted", "data loss",
        "system failure", "kernel panic", "segfault"
    ],
    "HIGH": [
        "error", "failed", "failure", "denied",
        "timeout", "exception", "crash", "abort",
        "invalid", "rejected", "forbidden", "blocked",
        "suspicious", "anomaly", "unusual", "unexpected",
        "high cpu", "high memory", "disk full", "out of memory",
        "connection lost", "service down", "unresponsive",
        "repeated attempts", "brute force", "scan detected"
    ],
    "MEDIUM": [
        "warning", "warn", "deprecated", "retry",
        "slow", "delayed", "degraded", "partial",
        "mismatch", "conflict", "duplicate", "missing",
        "not found", "unavailable", "disconnected",
        "reconnecting", "fallback", "skipped", "ignored",
        "configuration", "change detected", "modified"
    ],
    "LOW": [
        "info", "notice", "started", "stopped",
        "connected", "disconnected", "initialized", "loaded",
        "scheduled", "completed", "success", "ok",
        "ready", "running", "normal", "healthy",
        "backup", "checkpoint", "heartbeat", "ping"
    ]
}


# ─────────────────────────────────────────────
# LOG PARSER
# ─────────────────────────────────────────────

def parse_log_line(line: str) -> dict:
    """
    Parse a single log line into structured fields.
    Handles common Linux syslog and Ignition Gateway log formats.
    """
    entry = {
        "raw": line.strip(),
        "timestamp": None,
        "hostname": None,
        "service": None,
        "pid": None,
        "message": line.strip(),
        "severity": "LOW",
        "matched_keyword": None
    }

    # Pattern 1: Standard syslog format
    # May 27 03:14:07 hostname service[pid]: message
    syslog_pattern = r'^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s+(.+)$'
    m = re.match(syslog_pattern, line)
    if m:
        entry["timestamp"] = m.group(1)
        entry["hostname"] = m.group(2)
        entry["service"] = m.group(3)
        entry["pid"] = m.group(4)
        entry["message"] = m.group(5)
        return entry

    # Pattern 2: Ignition Gateway format
    # 2025-05-27 03:14:07,123 [INFO   ] [gateway.module] - Message text
    ignition_pattern = r'^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}[,\d]*)\s+\[(\w+\s*)\]\s+\[([^\]]+)\]\s+-\s+(.+)$'
    m = re.match(ignition_pattern, line)
    if m:
        entry["timestamp"] = m.group(1).strip()
        entry["service"] = m.group(3).strip()
        entry["message"] = m.group(4).strip()
        return entry

    # Pattern 3: ISO timestamp format
    # 2025-05-27T03:14:07 hostname service: message
    iso_pattern = r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+):\s+(.+)$'
    m = re.match(iso_pattern, line)
    if m:
        entry["timestamp"] = m.group(1)
        entry["hostname"] = m.group(2)
        entry["service"] = m.group(3)
        entry["message"] = m.group(4)
        return entry

    return entry


def classify_severity(message: str) -> tuple:
    """
    Classify log message severity based on keyword matching.
    Returns (severity_level, matched_keyword).
    Priority order: CRITICAL > HIGH > MEDIUM > LOW
    """
    message_lower = message.lower()

    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        for keyword in SEVERITY_KEYWORDS[severity]:
            if keyword in message_lower:
                return severity, keyword

    return "LOW", None


# ─────────────────────────────────────────────
# MAIN ANALYZER
# ─────────────────────────────────────────────

def analyze_logs(log_input, source_name="log_source"):
    """
    Analyze log lines from a file path or list of strings.
    Returns a pandas DataFrame with classified events.
    """
    lines = []

    if isinstance(log_input, str) and os.path.isfile(log_input):
        with open(log_input, 'r', errors='replace') as f:
            lines = f.readlines()
        source_name = os.path.basename(log_input)
    elif isinstance(log_input, list):
        lines = log_input
    else:
        print(f"[ERROR] Invalid input: {log_input}")
        return pd.DataFrame()

    records = []
    for i, line in enumerate(lines, 1):
        line = line.strip()
        if not line:
            continue

        entry = parse_log_line(line)
        severity, keyword = classify_severity(entry["message"])
        entry["severity"] = severity
        entry["matched_keyword"] = keyword
        entry["line_number"] = i
        entry["source"] = source_name
        records.append(entry)

    df = pd.DataFrame(records)

    # Enforce severity ordering
    severity_order = pd.CategoricalDtype(
        categories=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        ordered=True
    )
    if not df.empty:
        df["severity"] = df["severity"].astype(severity_order)
        df = df.sort_values(["severity", "line_number"])

    return df


# ─────────────────────────────────────────────
# REPORT GENERATORS
# ─────────────────────────────────────────────

def generate_summary(df: pd.DataFrame) -> dict:
    """Generate a summary statistics dictionary."""
    if df.empty:
        return {}

    total = len(df)
    counts = df["severity"].value_counts().to_dict()

    summary = {
        "total_events": total,
        "critical_count": counts.get("CRITICAL", 0),
        "high_count": counts.get("HIGH", 0),
        "medium_count": counts.get("MEDIUM", 0),
        "low_count": counts.get("LOW", 0),
        "critical_pct": round(counts.get("CRITICAL", 0) / total * 100, 1),
        "high_pct": round(counts.get("HIGH", 0) / total * 100, 1),
        "sources": df["source"].unique().tolist() if "source" in df.columns else [],
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

    # Top services generating critical/high events
    if "service" in df.columns:
        hot = df[df["severity"].isin(["CRITICAL", "HIGH"])]
        if not hot.empty:
            top_services = (
                hot["service"]
                .dropna()
                .value_counts()
                .head(5)
                .to_dict()
            )
            summary["top_services_by_severity"] = top_services

    # Most common critical keywords
    crit = df[df["severity"] == "CRITICAL"]
    if not crit.empty:
        keyword_counts = (
            crit["matched_keyword"]
            .dropna()
            .value_counts()
            .head(10)
            .to_dict()
        )
        summary["top_critical_keywords"] = keyword_counts

    return summary


def export_csv(df: pd.DataFrame, output_dir: str = "output"):
    """Export full classified log data and per-severity CSVs."""
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Full dataset
    full_path = os.path.join(output_dir, f"all_events_{timestamp}.csv")
    df.to_csv(full_path, index=False)
    print(f"[+] Full report saved: {full_path}")

    # Per-severity CSVs
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        subset = df[df["severity"] == severity]
        if not subset.empty:
            path = os.path.join(output_dir, f"{severity.lower()}_events_{timestamp}.csv")
            subset.to_csv(path, index=False)
            print(f"[+] {severity} events saved: {path} ({len(subset)} records)")

    return full_path


def export_json_summary(summary: dict, output_dir: str = "output"):
    """Export summary statistics as JSON."""
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(output_dir, f"summary_{timestamp}.json")
    with open(path, 'w') as f:
        json.dump(summary, f, indent=2)
    print(f"[+] Summary JSON saved: {path}")
    return path


def print_dashboard(df: pd.DataFrame, summary: dict):
    """Print a terminal dashboard of results."""
    print("\n" + "="*60)
    print("  IGNITION GATEWAY LOG ANALYZER — SECURITY DASHBOARD")
    print("="*60)
    print(f"  Generated : {summary.get('generated_at', 'N/A')}")
    print(f"  Sources   : {', '.join(summary.get('sources', []))}")
    print(f"  Total     : {summary.get('total_events', 0)} events")
    print("-"*60)
    print(f"  🔴 CRITICAL : {summary.get('critical_count', 0):>6}  ({summary.get('critical_pct', 0)}%)")
    print(f"  🟠 HIGH     : {summary.get('high_count', 0):>6}")
    print(f"  🟡 MEDIUM   : {summary.get('medium_count', 0):>6}")
    print(f"  🟢 LOW      : {summary.get('low_count', 0):>6}")
    print("="*60)

    # Show top critical events
    critical_df = df[df["severity"] == "CRITICAL"]
    if not critical_df.empty:
        print("\n  TOP CRITICAL EVENTS:")
        print("-"*60)
        for _, row in critical_df.head(10).iterrows():
            src = row.get("source", "")
            ts = row.get("timestamp") or "N/A"
            msg = row.get("message", "")[:80]
            kw = row.get("matched_keyword", "")
            print(f"  [{ts}] ({src})")
            print(f"  Keyword: {kw} | {msg}")
            print()

    # Top keywords
    if "top_critical_keywords" in summary:
        print("  TOP CRITICAL KEYWORDS:")
        print("-"*60)
        for kw, count in summary["top_critical_keywords"].items():
            print(f"  {kw:<30} {count:>5} occurrences")
        print()


# ─────────────────────────────────────────────
# SAMPLE LOG GENERATOR (for demo/testing)
# ─────────────────────────────────────────────

SAMPLE_LOGS = [
    "May 27 01:00:01 plant-server ignition[1234]: System initialized successfully",
    "May 27 01:00:05 plant-server ignition[1234]: Connected to PLC at 192.168.1.100",
    "May 27 01:05:12 plant-server ignition[1234]: Authentication failure for user admin from 10.0.0.44",
    "May 27 01:05:13 plant-server ignition[1234]: Authentication failure for user admin from 10.0.0.44",
    "May 27 01:05:14 plant-server ignition[1234]: Authentication failure for user admin from 10.0.0.44",
    "May 27 01:06:00 plant-server sshd[5678]: Invalid user root from 203.0.113.5 port 45231",
    "May 27 01:10:22 plant-server ignition[1234]: Warning: OPC-UA connection timeout to device REACTOR_01",
    "May 27 01:11:00 plant-server ignition[1234]: Retry attempt 1 of 3 for REACTOR_01",
    "May 27 01:15:00 plant-server kernel: Out of memory: Kill process 9812 score 450",
    "May 27 01:20:05 plant-server ignition[1234]: Critical: Tag provider SCADA_TAGS failed to load",
    "May 27 01:20:06 plant-server ignition[1234]: Fatal error in gateway module com.inductiveautomation.opc-ua",
    "May 27 01:25:00 plant-server ignition[1234]: Unauthorized access attempt to /system/admin endpoint",
    "May 27 01:30:00 plant-server ignition[1234]: SSL handshake failed for connection from 198.51.100.7",
    "May 27 01:35:00 plant-server ignition[1234]: Scheduled backup completed successfully",
    "May 27 01:40:00 plant-server ignition[1234]: Heartbeat OK — all monitored services running",
    "May 27 01:45:00 plant-server ignition[1234]: Configuration change detected in tag database",
    "May 27 01:50:00 plant-server ignition[1234]: Suspicious packet detected from external IP 198.51.100.99",
    "May 27 01:55:00 plant-server ignition[1234]: Service gateway-network-interface stopped unexpectedly",
    "May 27 02:00:00 plant-server ignition[1234]: High CPU usage detected on historian module: 94%",
    "May 27 02:05:00 plant-server ignition[1234]: Disk full warning: /var/log partition at 98% capacity",
    "May 27 02:10:00 plant-server ignition[1234]: Connection restored to PLC at 192.168.1.100",
    "May 27 02:15:00 plant-server ignition[1234]: Data loss detected in historian buffer — 42 records dropped",
    "May 27 02:20:00 plant-server ignition[1234]: Normal operation resumed",
    "May 27 02:25:00 plant-server sshd[5679]: Accepted publickey for operator from 10.0.1.5",
    "May 27 02:30:00 plant-server ignition[1234]: Privilege escalation attempt detected for process 1337",
]


# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────

def main():
    print("\n[*] Ignition Gateway Log Analyzer — Starting")

    # Use file argument if provided, otherwise use sample logs
    if len(sys.argv) > 1:
        log_source = sys.argv[1]
        print(f"[*] Analyzing log file: {log_source}")
    else:
        print("[*] No log file provided — running with sample OT/ICS logs")
        log_source = SAMPLE_LOGS

    # Analyze
    df = analyze_logs(log_source, source_name="ignition_gateway")

    if df.empty:
        print("[!] No log entries found. Exiting.")
        return

    # Generate summary
    summary = generate_summary(df)

    # Print terminal dashboard
    print_dashboard(df, summary)

    # Export reports
    export_csv(df, output_dir="output")
    export_json_summary(summary, output_dir="output")

    print("\n[✓] Analysis complete.")


if __name__ == "__main__":
    main()
