#!/usr/bin/env python3
# ============================================================
#  ARIA - Rayhunter File Analyser
#  Parses NDJSON logs and flags LTE anomalies for ARIA review
# ============================================================

import json
import sys
import os
import argparse
import subprocess
from datetime import datetime

# Colour output
class C:
    RED    = '\033[91m'
    GREEN  = '\033[92m'
    YELLOW = '\033[93m'
    CYAN   = '\033[96m'
    BOLD   = '\033[1m'
    RESET  = '\033[0m'

# Known anomaly indicators
ANOMALY_PATTERNS = {
    "null_cipher": ["EEA0", "A5/0", "null cipher", "eea0"],
    "2g_downgrade": ["GERAN", "GSM", "2G", "downgrade", "fallback"],
    "identity_request": ["IdentityRequest", "identity_request", "IMSI request"],
    "proximity_tracking": ["reportProximityConfig", "ProSe", "proximity"],
    "forced_handover": ["handoverCommand", "forced handover", "HandoverCommand"],
    "suspicious_earfcn": [],  # filled from known rogue EARFCNs
}

# Jay's known rogue EARFCNs — add more as discovered
KNOWN_ROGUE_EARFCNS = []

def banner():
    print(f"{C.CYAN}{C.BOLD}")
    print("  ╔══════════════════════════════════════╗")
    print("  ║   ARIA - Rayhunter Anomaly Analyser  ║")
    print("  ╚══════════════════════════════════════╝")
    print(f"{C.RESET}")

def parse_ndjson(filepath):
    records = []
    anomalies = []

    print(f"{C.GREEN}[+] Parsing: {filepath}{C.RESET}")

    with open(filepath, 'r', errors='replace') as f:
        for i, line in enumerate(f):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
                records.append(record)

                # Convert to string for pattern matching
                record_str = json.dumps(record).lower()

                # Check each anomaly pattern
                for anomaly_type, patterns in ANOMALY_PATTERNS.items():
                    for pattern in patterns:
                        if pattern.lower() in record_str:
                            anomalies.append({
                                "line": i + 1,
                                "type": anomaly_type,
                                "pattern": pattern,
                                "data": record
                            })
                            break

                # Check for known rogue EARFCNs
                earfcn = record.get("earfcn") or record.get("EARFCN")
                if earfcn and int(earfcn) in KNOWN_ROGUE_EARFCNS:
                    anomalies.append({
                        "line": i + 1,
                        "type": "known_rogue_earfcn",
                        "pattern": f"EARFCN {earfcn}",
                        "data": record
                    })

            except json.JSONDecodeError:
                print(f"{C.YELLOW}[!] Line {i+1}: Could not parse JSON{C.RESET}")

    return records, anomalies

def extract_summary(records):
    summary = {
        "total_records": len(records),
        "earfcns": set(),
        "mcc_mnc": set(),
        "timestamps": [],
        "message_types": {}
    }

    for r in records:
        # Extract EARFCNs
        for key in ["earfcn", "EARFCN", "dl_earfcn"]:
            if key in r:
                summary["earfcns"].add(str(r[key]))

        # Extract MCC/MNC
        for key in ["mcc", "mnc"]:
            if key in r:
                summary["mcc_mnc"].add(f"{r.get('mcc','?')}-{r.get('mnc','?')}")

        # Extract timestamps
        for key in ["timestamp", "time", "ts"]:
            if key in r:
                summary["timestamps"].append(r[key])

        # Count message types
        for key in ["msg_type", "type", "message_type"]:
            if key in r:
                msg = str(r[key])
                summary["message_types"][msg] = summary["message_types"].get(msg, 0) + 1

    return summary

def print_summary(summary, anomalies):
    print(f"\n{C.BOLD}=== ANALYSIS SUMMARY ==={C.RESET}")
    print(f"  Total records  : {summary['total_records']}")
    print(f"  Unique EARFCNs : {', '.join(summary['earfcns']) or 'None found'}")
    print(f"  MCC-MNC pairs  : {', '.join(summary['mcc_mnc']) or 'None found'}")

    if summary["timestamps"]:
        print(f"  Time range     : {summary['timestamps'][0]} → {summary['timestamps'][-1]}")

    if summary["message_types"]:
        print(f"\n{C.BOLD}  Top Message Types:{C.RESET}")
        for msg, count in sorted(summary["message_types"].items(), key=lambda x: -x[1])[:10]:
            print(f"    {msg}: {count}")

    print(f"\n{C.BOLD}=== ANOMALIES DETECTED: {len(anomalies)} ==={C.RESET}")

    if not anomalies:
        print(f"  {C.GREEN}No anomalies detected.{C.RESET}")
    else:
        for a in anomalies:
            print(f"\n  {C.RED}[!] Line {a['line']} — {a['type'].upper()}{C.RESET}")
            print(f"      Pattern : {a['pattern']}")
            # Print relevant fields only
            relevant = {k: v for k, v in a['data'].items()
                       if k in ['timestamp','earfcn','mcc','mnc','msg_type','type','cause']}
            if relevant:
                print(f"      Data    : {json.dumps(relevant)}")

def send_to_aria(summary, anomalies, filepath):
    print(f"\n{C.CYAN}[*] Sending findings to ARIA for analysis...{C.RESET}\n")

    prompt = f"""You are analysing Rayhunter cellular monitoring data from a home network intrusion investigation in Cranbourne East, Melbourne, Australia.

File analysed: {os.path.basename(filepath)}
Total records: {summary['total_records']}
EARFCNs observed: {', '.join(summary['earfcns']) or 'none'}
MCC-MNC pairs: {', '.join(summary['mcc_mnc']) or 'none'}

Anomalies detected ({len(anomalies)} total):
{json.dumps([{'type': a['type'], 'pattern': a['pattern'], 'line': a['line']} for a in anomalies[:20]], indent=2)}

Top message types:
{json.dumps(dict(list(summary['message_types'].items())[:10]), indent=2)}

Please:
1. Assess the severity of these findings
2. Identify which anomalies are most forensically significant
3. Suggest follow-up analysis steps
4. Note any patterns consistent with IMSI catcher or rogue base station activity
"""

    result = subprocess.run(
        ["ollama", "run", "aria", prompt],
        capture_output=True, text=True
    )
    print(result.stdout)

def save_report(summary, anomalies, filepath):
    report_path = filepath.replace('.ndjson', '_aria_report.txt')
    report_path = report_path.replace('.json', '_aria_report.txt')

    with open(report_path, 'w') as f:
        f.write(f"ARIA Rayhunter Analysis Report\n")
        f.write(f"Generated: {datetime.now().isoformat()}\n")
        f.write(f"File: {filepath}\n\n")
        f.write(f"Total Records: {summary['total_records']}\n")
        f.write(f"EARFCNs: {', '.join(summary['earfcns'])}\n")
        f.write(f"MCC-MNC: {', '.join(summary['mcc_mnc'])}\n\n")
        f.write(f"ANOMALIES ({len(anomalies)}):\n")
        for a in anomalies:
            f.write(f"  Line {a['line']}: {a['type']} — {a['pattern']}\n")
            f.write(f"    {json.dumps(a['data'])}\n")

    print(f"\n{C.GREEN}[+] Report saved: {report_path}{C.RESET}")

def main():
    banner()

    parser = argparse.ArgumentParser(description='ARIA Rayhunter Analyser')
    parser.add_argument('file', help='Path to .ndjson file')
    parser.add_argument('--no-aria', action='store_true', help='Skip ARIA analysis')
    parser.add_argument('--save', action='store_true', help='Save report to file')
    args = parser.parse_args()

    if not os.path.exists(args.file):
        print(f"{C.RED}[-] File not found: {args.file}{C.RESET}")
        sys.exit(1)

    records, anomalies = parse_ndjson(args.file)
    summary = extract_summary(records)
    print_summary(summary, anomalies)

    if args.save:
        save_report(summary, anomalies, args.file)

    if not args.no_aria:
        send_to_aria(summary, anomalies, args.file)

if __name__ == "__main__":
    main()
