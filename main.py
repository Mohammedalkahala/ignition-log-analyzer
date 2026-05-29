#!/usr/bin/env python3
"""
Ignition Gateway Security Operations Pipeline
----------------------------------------------
End-to-end security automation pipeline for OT/ICS environments:

1. Parse raw Ignition Gateway / Linux server logs
2. Classify events by severity (CRITICAL / HIGH / MEDIUM / LOW)
3. Extract external IP addresses from log data
4. Enrich IPs via VirusTotal and Shodan APIs
5. Calculate risk scores and generate prioritized reports
6. Export structured CSV and JSON outputs for watch operations

Author: Mohammed Alkahala
Use Case: NERC E-ISAC Watch Operations — Security Data Automation
"""

import pandas as pd
import json
import os
import sys
from datetime import datetime

from log_analyzer import analyze_logs, generate_summary, export_csv, export_json_summary, print_dashboard, SAMPLE_LOGS
from enrichment import extract_ips_from_logs, enrich_ips, demo_enrichment


def export_enrichment_report(enrichment_results: list, output_dir: str = "output"):
    """Export enrichment results to CSV and JSON."""
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    if not enrichment_results:
        print("[!] No enrichment results to export.")
        return

    df = pd.DataFrame(enrichment_results)

    # Sort by risk score descending
    if "risk_score" in df.columns:
        df = df.sort_values("risk_score", ascending=False)

    # CSV export
    csv_path = os.path.join(output_dir, f"enrichment_report_{timestamp}.csv")
    df.to_csv(csv_path, index=False)
    print(f"[+] Enrichment CSV saved: {csv_path}")

    # JSON export
    json_path = os.path.join(output_dir, f"enrichment_report_{timestamp}.json")
    with open(json_path, "w") as f:
        json.dump(enrichment_results, f, indent=2, default=str)
    print(f"[+] Enrichment JSON saved: {json_path}")

    return csv_path


def print_enrichment_dashboard(enrichment_results: list):
    """Print enrichment summary to terminal."""
    if not enrichment_results:
        return

    print("\n" + "="*60)
    print("  IP ENRICHMENT DASHBOARD")
    print("="*60)

    critical = [r for r in enrichment_results if r.get("risk_level") == "CRITICAL"]
    high = [r for r in enrichment_results if r.get("risk_level") == "HIGH"]
    medium = [r for r in enrichment_results if r.get("risk_level") == "MEDIUM"]
    low = [r for r in enrichment_results if r.get("risk_level") == "LOW"]

    print(f"  Total IPs enriched : {len(enrichment_results)}")
    print(f"  🔴 CRITICAL risk   : {len(critical)}")
    print(f"  🟠 HIGH risk       : {len(high)}")
    print(f"  🟡 MEDIUM risk     : {len(medium)}")
    print(f"  🟢 LOW risk        : {len(low)}")
    print("="*60)

    if critical or high:
        print("\n  HIGH PRIORITY IPs — REQUIRES IMMEDIATE REVIEW:")
        print("-"*60)
        for r in sorted(critical + high, key=lambda x: x.get("risk_score", 0), reverse=True):
            ip = r.get("ip", "N/A")
            score = r.get("risk_score", 0)
            level = r.get("risk_level", "N/A")
            verdict = r.get("vt_verdict", "N/A")
            country = r.get("vt_country") or r.get("shodan_country", "N/A")
            org = r.get("vt_as_owner") or r.get("shodan_org", "N/A")
            ports = r.get("shodan_ports", [])
            vulns = r.get("shodan_vulns", [])

            print(f"\n  [{level}] {ip} — Risk Score: {score}/100")
            print(f"  VT Verdict : {verdict}")
            print(f"  Country    : {country} | Org: {org}")
            if ports:
                print(f"  Open Ports : {', '.join(map(str, ports[:8]))}")
            if vulns:
                print(f"  CVEs       : {', '.join(vulns[:3])}")
    print()


def run_pipeline(log_source=None, demo_mode=True):
    """
    Run the full security operations pipeline:
    Parse → Classify → Extract IPs → Enrich → Report
    """
    print("\n" + "="*60)
    print("  IGNITION GATEWAY SECURITY OPERATIONS PIPELINE")
    print("  NERC E-ISAC Watch Operations — Automated Analysis")
    print("="*60)

    # ── Step 1: Parse and classify logs ──────────────────────
    print("\n[STEP 1] Parsing and classifying log data...")
    if log_source is None:
        log_source = SAMPLE_LOGS
        source_name = "sample_ot_ics_logs"
    else:
        source_name = os.path.basename(log_source)

    df = analyze_logs(log_source, source_name=source_name)
    if df.empty:
        print("[!] No log data found. Exiting.")
        return

    print(f"[+] Parsed {len(df)} log entries from {source_name}")

    # ── Step 2: Generate and print log summary ────────────────
    print("\n[STEP 2] Generating severity classification report...")
    summary = generate_summary(df)
    print_dashboard(df, summary)

    # ── Step 3: Extract external IPs ─────────────────────────
    print("\n[STEP 3] Extracting external IP addresses from logs...")
    ip_list = extract_ips_from_logs(df)
    print(f"[+] Found {len(ip_list)} unique external IPs: {', '.join(ip_list)}")

    # ── Step 4: Enrich IPs ────────────────────────────────────
    print("\n[STEP 4] Enriching IPs via VirusTotal and Shodan...")
    if demo_mode:
        enrichment_results = demo_enrichment(ip_list)
    else:
        enrichment_results = enrich_ips(ip_list, use_vt=True, use_shodan=True)

    # ── Step 5: Print enrichment dashboard ───────────────────
    print_enrichment_dashboard(enrichment_results)

    # ── Step 6: Export all reports ────────────────────────────
    print("\n[STEP 5] Exporting reports...")
    export_csv(df, output_dir="output")
    export_json_summary(summary, output_dir="output")
    export_enrichment_report(enrichment_results, output_dir="output")

    print("\n[✓] Pipeline complete. Reports saved to /output/")
    print("="*60)


if __name__ == "__main__":
    log_file = sys.argv[1] if len(sys.argv) > 1 else None
    demo = "--live" not in sys.argv  # Use --live flag for real API calls
    run_pipeline(log_source=log_file, demo_mode=demo)
