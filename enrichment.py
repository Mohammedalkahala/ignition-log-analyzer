#!/usr/bin/env python3
"""
Security Enrichment Module
---------------------------
Enriches extracted IPs and domains from log data using:
- VirusTotal API (reputation, malicious votes, threat categories)
- Shodan API (open ports, services, geolocation, org)
- WHOIS (domain registration, registrar, creation date)

Author: Mohammed Alkahala
Use Case: NERC E-ISAC Watch Operations — Automated IOC Enrichment
"""

import requests
import json
import time
import socket
import re
from datetime import datetime
from typing import Optional


# ─────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────

# Set your API keys here or pass via environment variables
import os

VT_API_KEY = os.environ.get("VT_API_KEY", "YOUR_VT_API_KEY_HERE")
SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY", "YOUR_SHODAN_API_KEY_HERE")

VT_BASE_URL = "https://www.virustotal.com/api/v3"
SHODAN_BASE_URL = "https://api.shodan.io"

# Rate limiting — be respectful of free tier limits
VT_DELAY_SECONDS = 15      # VT free tier: 4 requests/minute
SHODAN_DELAY_SECONDS = 1   # Shodan free tier: 1 request/second


# ─────────────────────────────────────────────
# IP EXTRACTION
# ─────────────────────────────────────────────

def extract_ips_from_logs(df) -> list:
    """
    Extract unique IP addresses from a log DataFrame.
    Skips private/reserved IP ranges.
    """
    ip_pattern = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
    
    private_ranges = [
        '10.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.',
        '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.',
        '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.',
        '127.', '0.', '255.'
    ]
    
    ips = set()
    for col in ['message', 'raw']:
        if col in df.columns:
            for text in df[col].dropna():
                matches = ip_pattern.findall(str(text))
                for ip in matches:
                    if not any(ip.startswith(p) for p in private_ranges):
                        ips.add(ip)
    
    return list(ips)


# ─────────────────────────────────────────────
# VIRUSTOTAL ENRICHMENT
# ─────────────────────────────────────────────

def vt_check_ip(ip: str) -> dict:
    """
    Query VirusTotal for IP reputation.
    Returns malicious votes, categories, country, ASN.
    """
    result = {
        "ip": ip,
        "vt_malicious": 0,
        "vt_suspicious": 0,
        "vt_harmless": 0,
        "vt_undetected": 0,
        "vt_country": None,
        "vt_asn": None,
        "vt_as_owner": None,
        "vt_categories": [],
        "vt_tags": [],
        "vt_verdict": "UNKNOWN",
        "vt_checked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    if VT_API_KEY == "YOUR_VT_API_KEY_HERE":
        result["vt_verdict"] = "NO_API_KEY"
        return result
    
    try:
        headers = {"x-apikey": VT_API_KEY}
        url = f"{VT_BASE_URL}/ip_addresses/{ip}"
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json().get("data", {}).get("attributes", {})
            
            stats = data.get("last_analysis_stats", {})
            result["vt_malicious"] = stats.get("malicious", 0)
            result["vt_suspicious"] = stats.get("suspicious", 0)
            result["vt_harmless"] = stats.get("harmless", 0)
            result["vt_undetected"] = stats.get("undetected", 0)
            result["vt_country"] = data.get("country")
            result["vt_asn"] = data.get("asn")
            result["vt_as_owner"] = data.get("as_owner")
            result["vt_tags"] = data.get("tags", [])
            
            # Extract categories
            cats = data.get("categories", {})
            result["vt_categories"] = list(set(cats.values()))
            
            # Determine verdict
            if result["vt_malicious"] >= 3:
                result["vt_verdict"] = "MALICIOUS"
            elif result["vt_malicious"] >= 1 or result["vt_suspicious"] >= 3:
                result["vt_verdict"] = "SUSPICIOUS"
            elif result["vt_harmless"] > 0:
                result["vt_verdict"] = "CLEAN"
            else:
                result["vt_verdict"] = "UNDETECTED"
                
        elif response.status_code == 404:
            result["vt_verdict"] = "NOT_FOUND"
        elif response.status_code == 429:
            result["vt_verdict"] = "RATE_LIMITED"
            
    except requests.exceptions.RequestException as e:
        result["vt_verdict"] = f"ERROR: {str(e)[:50]}"
    
    time.sleep(VT_DELAY_SECONDS)
    return result


# ─────────────────────────────────────────────
# SHODAN ENRICHMENT
# ─────────────────────────────────────────────

def shodan_check_ip(ip: str) -> dict:
    """
    Query Shodan for open ports, services, and geolocation.
    """
    result = {
        "ip": ip,
        "shodan_ports": [],
        "shodan_services": [],
        "shodan_org": None,
        "shodan_isp": None,
        "shodan_country": None,
        "shodan_city": None,
        "shodan_hostnames": [],
        "shodan_vulns": [],
        "shodan_tags": [],
        "shodan_checked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    if SHODAN_API_KEY == "YOUR_SHODAN_API_KEY_HERE":
        result["shodan_org"] = "NO_API_KEY"
        return result
    
    try:
        url = f"{SHODAN_BASE_URL}/shodan/host/{ip}"
        params = {"key": SHODAN_API_KEY}
        response = requests.get(url, params=params, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            
            result["shodan_ports"] = data.get("ports", [])
            result["shodan_org"] = data.get("org")
            result["shodan_isp"] = data.get("isp")
            result["shodan_country"] = data.get("country_name")
            result["shodan_city"] = data.get("city")
            result["shodan_hostnames"] = data.get("hostnames", [])
            result["shodan_tags"] = data.get("tags", [])
            result["shodan_vulns"] = list(data.get("vulns", {}).keys())
            
            # Extract service banners
            services = []
            for item in data.get("data", []):
                svc = item.get("_shodan", {}).get("module", "unknown")
                port = item.get("port", "")
                if svc and svc not in services:
                    services.append(f"{port}/{svc}")
            result["shodan_services"] = services[:10]  # Cap at 10
            
        elif response.status_code == 404:
            result["shodan_org"] = "NOT_FOUND"
            
    except requests.exceptions.RequestException as e:
        result["shodan_org"] = f"ERROR: {str(e)[:50]}"
    
    time.sleep(SHODAN_DELAY_SECONDS)
    return result


# ─────────────────────────────────────────────
# COMBINED ENRICHMENT PIPELINE
# ─────────────────────────────────────────────

def enrich_ips(ip_list: list, use_vt: bool = True, use_shodan: bool = True) -> list:
    """
    Run full enrichment pipeline against a list of IPs.
    Returns list of enrichment result dicts.
    """
    results = []
    total = len(ip_list)
    
    print(f"\n[*] Starting enrichment for {total} unique external IPs...")
    
    for i, ip in enumerate(ip_list, 1):
        print(f"[{i}/{total}] Enriching {ip}...")
        
        enrichment = {"ip": ip}
        
        if use_vt:
            vt_data = vt_check_ip(ip)
            enrichment.update(vt_data)
        
        if use_shodan:
            shodan_data = shodan_check_ip(ip)
            enrichment.update(shodan_data)
        
        # Risk scoring
        enrichment["risk_score"] = calculate_risk_score(enrichment)
        enrichment["risk_level"] = score_to_level(enrichment["risk_score"])
        
        results.append(enrichment)
        
        # Print summary for this IP
        verdict = enrichment.get("vt_verdict", "N/A")
        ports = enrichment.get("shodan_ports", [])
        vulns = enrichment.get("shodan_vulns", [])
        risk = enrichment.get("risk_level", "UNKNOWN")
        print(f"    VT: {verdict} | Ports: {len(ports)} open | Vulns: {len(vulns)} | Risk: {risk}")
    
    return results


def calculate_risk_score(enrichment: dict) -> int:
    """
    Calculate a 0-100 risk score based on enrichment data.
    """
    score = 0
    
    # VirusTotal malicious votes (up to 50 points)
    malicious = enrichment.get("vt_malicious", 0)
    score += min(malicious * 10, 50)
    
    # VirusTotal suspicious votes (up to 20 points)
    suspicious = enrichment.get("vt_suspicious", 0)
    score += min(suspicious * 5, 20)
    
    # Known vulnerabilities from Shodan (up to 20 points)
    vulns = enrichment.get("shodan_vulns", [])
    score += min(len(vulns) * 5, 20)
    
    # High-risk open ports (up to 10 points)
    risky_ports = {22, 23, 3389, 445, 139, 1433, 3306, 5432, 6379, 27017}
    open_ports = set(enrichment.get("shodan_ports", []))
    risky_open = len(open_ports.intersection(risky_ports))
    score += min(risky_open * 2, 10)
    
    return min(score, 100)


def score_to_level(score: int) -> str:
    if score >= 70:
        return "CRITICAL"
    elif score >= 40:
        return "HIGH"
    elif score >= 20:
        return "MEDIUM"
    else:
        return "LOW"


# ─────────────────────────────────────────────
# DEMO MODE (no API keys needed)
# ─────────────────────────────────────────────

def demo_enrichment(ip_list: list) -> list:
    """
    Simulated enrichment for demo/testing without real API keys.
    Produces realistic-looking output for presentation purposes.
    """
    import random
    
    demo_results = []
    
    demo_data = {
        "203.0.113.5": {
            "vt_malicious": 8, "vt_suspicious": 2, "vt_verdict": "MALICIOUS",
            "vt_country": "CN", "vt_as_owner": "ChinaNet",
            "vt_categories": ["malware", "botnet"],
            "shodan_ports": [22, 80, 443, 8080, 3389],
            "shodan_org": "ChinaNet", "shodan_country": "China",
            "shodan_vulns": ["CVE-2021-44228", "CVE-2022-0847"]
        },
        "198.51.100.7": {
            "vt_malicious": 0, "vt_suspicious": 1, "vt_verdict": "SUSPICIOUS",
            "vt_country": "RU", "vt_as_owner": "Rostelecom",
            "vt_categories": ["suspicious"],
            "shodan_ports": [22, 443, 8443],
            "shodan_org": "Rostelecom", "shodan_country": "Russia",
            "shodan_vulns": []
        },
        "198.51.100.99": {
            "vt_malicious": 12, "vt_suspicious": 4, "vt_verdict": "MALICIOUS",
            "vt_country": "US", "vt_as_owner": "DigitalOcean",
            "vt_categories": ["malware", "phishing", "command-and-control"],
            "shodan_ports": [80, 443, 4444, 8080],
            "shodan_org": "DigitalOcean", "shodan_country": "United States",
            "shodan_vulns": ["CVE-2023-44487"]
        }
    }
    
    print(f"\n[*] Running DEMO enrichment for {len(ip_list)} IPs (no API keys required)")
    
    for ip in ip_list:
        data = demo_data.get(ip, {
            "vt_malicious": 0, "vt_suspicious": 0, "vt_verdict": "UNDETECTED",
            "vt_country": "US", "vt_as_owner": "Unknown",
            "vt_categories": [],
            "shodan_ports": [random.choice([80, 443, 22])],
            "shodan_org": "Unknown ISP", "shodan_country": "Unknown",
            "shodan_vulns": []
        })
        
        result = {"ip": ip}
        result.update(data)
        result["risk_score"] = calculate_risk_score(result)
        result["risk_level"] = score_to_level(result["risk_score"])
        result["vt_checked_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        result["shodan_checked_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        demo_results.append(result)
        
        print(f"    {ip}: VT={result['vt_verdict']} | "
              f"Ports={len(result['shodan_ports'])} | "
              f"Vulns={len(result['shodan_vulns'])} | "
              f"Risk={result['risk_level']}")
        time.sleep(0.3)
    
    return demo_results


if __name__ == "__main__":
    # Demo test
    test_ips = ["203.0.113.5", "198.51.100.7", "198.51.100.99"]
    results = demo_enrichment(test_ips)
    print("\nEnrichment complete.")
    for r in results:
        print(f"  {r['ip']} — Risk: {r['risk_level']} ({r['risk_score']}/100)")
