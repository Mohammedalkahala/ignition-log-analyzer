#!/usr/bin/env python3
"""
Ignition Gateway Security Operations Pipeline
----------------------------------------------
End-to-end security automation pipeline for OT/ICS environments:

1. Parse raw Ignition Gateway / Linux server logs (single or multiple files)
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
import glob
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

    if "risk_score" in df.columns:
        df = df.sort_values("risk_score", ascending=False)

    csv_path = os.path.join(output_dir, f"enrichment_report_{timestamp}.csv")
    df.to_csv(csv_path, index=False)
    print(f"[+] Enrichment CSV saved: {csv_path}")

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


def run_pipeline(log_sources=None, demo_mode=True):
    """
    Run the full security operations pipeline across one or multiple log files:
    Parse → Classify → Extract IPs → Enrich → Report
    """
    print("\n" + "="*60)
    print("  IGNITION GATEWAY SECURITY OPERATIONS PIPELINE")
    print("  NERC E-ISAC Watch Operations — Automated Analysis")
    print("="*60)

    # ── Step 1: Parse and classify all log files ──────────────
    print("\n[STEP 1] Parsing and classifying log data...")

    if log_sources is None:
        # No files provided — use built-in sample logs
        df = analyze_logs(SAMPLE_LOGS, source_name="sample_ot_ics_logs")
        print(f"[+] Parsed {len(df)} log entries from built-in sample logs")
    else:
        # Process all log files and combine into one DataFrame
        all_frames = []
        for log_file in log_sources:
            if os.path.isfile(log_file):
                source_name = os.path.basename(log_file)
                print(f"[*] Processing: {source_name}")
                df_single = analyze_logs(log_file, source_name=source_name)
                print(f"    → {len(df_single)} entries parsed")
                all_frames.append(df_single)
            else:
                print(f"[!] File not found, skipping: {log_file}")

        if not all_frames:
            print("[!] No valid log files found. Exiting.")
            return

        # Combine all DataFrames into one
        df = pd.concat(all_frames, ignore_index=True)

        # Re-sort combined DataFrame by severity
        from pandas.api.types import CategoricalDtype
        severity_order = CategoricalDtype(
            categories=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
            ordered=True
        )
        df["severity"] = df["severity"].astype(severity_order)
        df = df.sort_values("severity")

        print(f"\n[+] Combined total: {len(df)} log entries across {len(all_frames)} files")

    if df.empty:
        print("[!] No log entries found. Exiting.")
        return

    # ── Step 2: Generate and print summary ────────────────────
    print("\n[STEP 2] Generating severity classification report...")
    summary = generate_summary(df)
    print_dashboard(df, summary)

    # ── Step 3: Extract external IPs ─────────────────────────
    print("\n[STEP 3] Extracting external IP addresses from logs...")
    ip_list = extract_ips_from_logs(df)
    if ip_list:
        print(f"[+] Found {len(ip_list)} unique external IPs: {', '.join(ip_list)}")
    else:
        print("[+] No external IPs found in log data")

    # ── Step 4: Enrich IPs ────────────────────────────────────
    print("\n[STEP 4] Enriching IPs via VirusTotal and Shodan...")
    if ip_list:
        if demo_mode:
            enrichment_results = demo_enrichment(ip_list)
        else:
            enrichment_results = enrich_ips(ip_list, use_vt=True, use_shodan=True)
        print_enrichment_dashboard(enrichment_results)
    else:
        enrichment_results = []
        print("[+] No external IPs to enrich")

    # ── Step 5: Export all reports ────────────────────────────
    print("\n[STEP 5] Exporting reports...")
    export_csv(df, output_dir="output")
    export_json_summary(summary, output_dir="output")
    if enrichment_results:
        export_enrichment_report(enrichment_results, output_dir="output")

    print("\n[✓] Pipeline complete. Reports saved to /output/")
    print("="*60)


if __name__ == "__main__":
    args = sys.argv[1:]

    # Check for --live flag
    demo = "--live" not in args
    args = [a for a in args if a != "--live"]

    if not args:
        # No arguments — run on sample logs
        run_pipeline(log_sources=None, demo_mode=demo)
    else:
        # Expand any wildcards and collect all file paths
        log_files = []
        for arg in args:
            expanded = glob.glob(arg)
            if expanded:
                log_files.extend(expanded)
            else:
                log_files.append(arg)

        run_pipeline(log_sources=log_files, demo_mode=demo)
