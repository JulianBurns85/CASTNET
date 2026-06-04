#!/usr/bin/env python3
# ============================================================
#  ARIA - WiFi Pineapple Pager Log Analyser
#  Parses PineAP logs, beacon data, and recon payloads
# ============================================================

import json
import sys
import os
import re
import argparse
import subprocess
from datetime import datetime
from collections import Counter

class C:
    RED    = '\033[91m'
    GREEN  = '\033[92m'
    YELLOW = '\033[93m'
    CYAN   = '\033[96m'
    BOLD   = '\033[1m'
    RESET  = '\033[0m'

# Known rogue AP indicators for Cranbourne East investigation
KNOWN_ROGUE_SSIDS = [
    "U7 pro",
    "GAME BOY",
]

KNOWN_ROGUE_MACS_PREFIX = [
    # Add known Ubiquiti U7 Pro MAC prefixes here
    "24:5a:4c",  # Ubiquiti prefix example
]

SUSPICIOUS_CAPABILITIES = [
    "karma",
    "evil twin",
    "pineap",
    "deauth",
]

def banner():
    print(f"{C.CYAN}{C.BOLD}")
    print("  ╔══════════════════════════════════════╗")
    print("  ║   ARIA - Pineapple Log Analyser      ║")
    print("  ║   Hostname: GAME BOY                 ║")
    print("  ╚══════════════════════════════════════╝")
    print(f"{C.RESET}")

def detect_file_type(filepath):
    """Detect whether file is JSON, NDJSON, CSV, or plain text log"""
    with open(filepath, 'r', errors='replace') as f:
        first_line = f.readline().strip()

    if first_line.startswith('[') or first_line.startswith('{'):
        try:
            json.loads(first_line)
            return 'ndjson'
        except:
            pass
        try:
            with open(filepath) as f:
                json.load(f)
            return 'json'
        except:
            pass

    if ',' in first_line and len(first_line.split(',')) > 3:
        return 'csv'

    return 'text'

def parse_log(filepath):
    file_type = detect_file_type(filepath)
    print(f"{C.GREEN}[+] File type detected: {file_type}{C.RESET}")

    records = []
    with open(filepath, 'r', errors='replace') as f:
        if file_type == 'ndjson':
            for line in f:
                line = line.strip()
                if line:
                    try:
                        records.append(json.loads(line))
                    except:
                        pass
        elif file_type == 'json':
            data = json.load(f)
            records = data if isinstance(data, list) else [data]
        elif file_type == 'csv':
            import csv
            reader = csv.DictReader(f)
            records = list(reader)
        else:
            # Plain text — parse as log lines
            for line in f:
                records.append({"raw": line.strip()})

    print(f"{C.GREEN}[+] Loaded {len(records)} records{C.RESET}")
    return records, file_type

def extract_networks(records):
    networks = {}
    for r in records:
        r_str = json.dumps(r).lower() if isinstance(r, dict) else r.get('raw', '').lower()

        # Extract SSIDs
        ssid_match = re.findall(r'"ssid"\s*:\s*"([^"]*)"', r_str, re.IGNORECASE)
        bssid_match = re.findall(r'"bssid"\s*:\s*"([0-9a-f:]{17})"', r_str, re.IGNORECASE)
        mac_match = re.findall(r'([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})', r_str)
        rssi_match = re.findall(r'"(?:rssi|signal)"\s*:\s*(-?\d+)', r_str)
        channel_match = re.findall(r'"channel"\s*:\s*(\d+)', r_str)

        for ssid in ssid_match:
            if ssid not in networks:
                networks[ssid] = {
                    "bssids": set(),
                    "rssi_values": [],
                    "channels": set(),
                    "seen_count": 0,
                    "flags": []
                }
            networks[ssid]["seen_count"] += 1

            for bssid in bssid_match:
                networks[ssid]["bssids"].add(bssid)
            for rssi in rssi_match:
                networks[ssid]["rssi_values"].append(int(rssi))
            for ch in channel_match:
                networks[ssid]["channels"].add(ch)

            # Flag known rogues
            if ssid in KNOWN_ROGUE_SSIDS:
                networks[ssid]["flags"].append("KNOWN_ROGUE_SSID")

            # Flag suspicious MAC prefixes
            for mac in mac_match:
                prefix = mac[:8].lower()
                if prefix in KNOWN_ROGUE_MACS_PREFIX:
                    networks[ssid]["flags"].append(f"ROGUE_MAC_PREFIX:{prefix}")

    return networks

def detect_karma_attacks(records):
    """Detect PineAP/Karma style probe response anomalies"""
    probes = []
    responses = []
    karma_indicators = []

    for r in records:
        r_str = json.dumps(r) if isinstance(r, dict) else r.get('raw', '')

        if 'probe' in r_str.lower():
            probes.append(r)
        if 'response' in r_str.lower():
            responses.append(r)

        # Karma: same BSSID responding to multiple different SSIDs
        bssids = re.findall(r'([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})', r_str.lower())
        ssids = re.findall(r'"ssid"\s*:\s*"([^"]*)"', r_str, re.IGNORECASE)

        if len(bssids) == 1 and len(ssids) > 1:
            karma_indicators.append({
                "type": "MULTI_SSID_SINGLE_BSSID",
                "bssid": bssids[0],
                "ssids": ssids,
                "record": r
            })

    return probes, responses, karma_indicators

def print_network_report(networks, karma_indicators):
    print(f"\n{C.BOLD}=== NETWORKS DETECTED: {len(networks)} ==={C.RESET}")

    for ssid, data in sorted(networks.items(), key=lambda x: -x[1]['seen_count']):
        flag_str = ""
        if data['flags']:
            flag_str = f" {C.RED}[{'|'.join(set(data['flags']))}]{C.RESET}"

        avg_rssi = sum(data['rssi_values']) / len(data['rssi_values']) if data['rssi_values'] else 0

        print(f"\n  {C.CYAN}SSID: {ssid}{C.RESET}{flag_str}")
        print(f"    Seen        : {data['seen_count']} times")
        print(f"    BSSIDs      : {', '.join(data['bssids']) or 'unknown'}")
        print(f"    Channels    : {', '.join(data['channels']) or 'unknown'}")
        if avg_rssi:
            print(f"    Avg RSSI    : {avg_rssi:.0f} dBm")

    print(f"\n{C.BOLD}=== KARMA/PINEAP INDICATORS: {len(karma_indicators)} ==={C.RESET}")
    if not karma_indicators:
        print(f"  {C.GREEN}No Karma attack patterns detected.{C.RESET}")
    else:
        for k in karma_indicators[:10]:
            print(f"\n  {C.RED}[!] {k['type']}{C.RESET}")
            print(f"      BSSID : {k['bssid']}")
            print(f"      SSIDs : {', '.join(k['ssids'])}")

def extract_clients(records):
    """Extract client devices seen probing"""
    client_macs = Counter()
    client_probes = {}

    for r in records:
        r_str = json.dumps(r) if isinstance(r, dict) else r.get('raw', '')
        macs = re.findall(r'([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})', r_str.lower())
        ssids = re.findall(r'"ssid"\s*:\s*"([^"]*)"', r_str, re.IGNORECASE)

        for mac in macs:
            client_macs[mac] += 1
            if mac not in client_probes:
                client_probes[mac] = set()
            for ssid in ssids:
                client_probes[mac].add(ssid)

    return client_macs, client_probes

def send_to_aria(networks, karma_indicators, clients, filepath):
    print(f"\n{C.CYAN}[*] Sending Pineapple findings to ARIA...{C.RESET}\n")

    network_summary = [
        {"ssid": ssid, "seen": data['seen_count'], "bssids": list(data['bssids']),
         "flags": list(set(data['flags']))}
        for ssid, data in list(networks.items())[:20]
    ]

    prompt = f"""You are analysing WiFi Pineapple Pager (hostname: GAME BOY) recon logs from a home network intrusion investigation in Cranbourne East, Melbourne, Australia.

File: {os.path.basename(filepath)}

Networks detected ({len(networks)} total, showing top entries):
{json.dumps(network_summary, indent=2)}

Karma/PineAP attack indicators: {len(karma_indicators)}
{json.dumps([{{'type': k['type'], 'bssid': k['bssid'], 'ssids': k['ssids']}} for k in karma_indicators[:5]], indent=2)}

Known rogue SSIDs in investigation: {KNOWN_ROGUE_SSIDS}

Please:
1. Identify the most suspicious networks and explain why
2. Assess whether Karma/evil twin attacks are occurring
3. Cross-reference with known rogue Ubiquiti U7 Pro APs
4. Suggest next investigative steps
5. Note anything relevant to the IMSI catcher investigation
"""

    result = subprocess.run(["ollama", "run", "aria", prompt], capture_output=True, text=True)
    print(result.stdout)

def main():
    banner()
    parser = argparse.ArgumentParser(description='ARIA Pineapple Log Analyser')
    parser.add_argument('file', help='Path to Pineapple log file')
    parser.add_argument('--no-aria', action='store_true', help='Skip ARIA analysis')
    parser.add_argument('--clients', action='store_true', help='Show client device list')
    args = parser.parse_args()

    if not os.path.exists(args.file):
        print(f"{C.RED}[-] File not found: {args.file}{C.RESET}")
        sys.exit(1)

    records, file_type = parse_log(args.file)
    networks = extract_networks(records)
    probes, responses, karma_indicators = detect_karma_attacks(records)
    client_macs, client_probes = extract_clients(records)

    print_network_report(networks, karma_indicators)

    if args.clients and client_macs:
        print(f"\n{C.BOLD}=== CLIENT DEVICES (top 20) ==={C.RESET}")
        for mac, count in client_macs.most_common(20):
            probed = ', '.join(list(client_probes.get(mac, set()))[:3])
            print(f"  {mac} — seen {count}x — probing: {probed or 'unknown'}")

    if not args.no_aria:
        send_to_aria(networks, karma_indicators, client_macs, args.file)

if __name__ == "__main__":
    main()
