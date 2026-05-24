#!/usr/bin/env python3
"""
castnet_node.py — CASTNET Field Node v0.1
Civilian IMSI Catcher Detection Network
Tier 1 — no root required. Runs on Android (Termux) or Linux.
"""
import json, os, subprocess, time
from datetime import datetime, timezone

KNOWN_ROGUE_CIDS = {
    137713195, 137713175, 137713165, 137713155, 135836191,
    8409357, 8409367, 8409387, 8409397,
    8666381, 8666391, 8666411,
}

POLL_INTERVAL = 30
LOG_FILE      = "/data/data/com.termux/files/home/castnet_log.json"
NODE_ID       = "ulefone_tab4_node1"
CASTNET_API   = "http://100.68.146.48:5000/api/v1/report"

def get_cells():
    try:
        result = subprocess.run(["termux-telephony-cellinfo"],
            capture_output=True, text=True, timeout=10)
        data = json.loads(result.stdout)
        return data if isinstance(data, list) else []
    except Exception as e:
        print(f"[ERROR] Cell query failed: {e}")
        return []

def get_location():
    try:
        result = subprocess.run(["termux-location","-p","network","-r","once"],
            capture_output=True, text=True, timeout=15)
        loc = json.loads(result.stdout)
        return loc.get("latitude"), loc.get("longitude")
    except Exception:
        return None, None

def log_event(event):
    try:
        existing = []
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE,"r") as f: existing = json.load(f)
        existing.append(event)
        with open(LOG_FILE,"w") as f: json.dump(existing, f, indent=2)
    except Exception as e:
        print(f"[ERROR] Log failed: {e}")

def report_to_api(event):
    try:
        import requests
        requests.post(CASTNET_API, json=event, timeout=5)
        print(f"  [API] ✅ Reported to Castnet central")
    except Exception:
        print(f"  [API] Offline — local only")

def main():
    print(f"""
  CASTNET — Civilian IMSI Catcher Detection Network
  Node: {NODE_ID} | Tier 1 | No root required
  Because Stingrays are fish too. 🎣

  Monitoring {len(KNOWN_ROGUE_CIDS)} known rogue CIDs
  Poll interval: {POLL_INTERVAL}s
  API: {CASTNET_API}
  Started: {datetime.now(timezone.utc).isoformat()}
""")
    scan_count = 0; rogue_hits = 0
    while True:
        scan_count += 1
        ts    = datetime.now(timezone.utc).isoformat()
        cells = get_cells()
        print(f"[{ts}] Scan #{scan_count} — {len(cells)} cells visible", end="")
        rogues_this_scan = []
        for cell in cells:
            if not isinstance(cell, dict): continue
            ci = cell.get("ci")
            if ci and int(ci) in KNOWN_ROGUE_CIDS:
                rogues_this_scan.append(cell)
        if rogues_this_scan:
            rogue_hits += 1
            print(f" — 🚨 {len(rogues_this_scan)} ROGUE CID(s) DETECTED!")
            lat, lon = get_location()
            for cell in rogues_this_scan:
                event = {"timestamp":ts,"node_id":NODE_ID,"tier":1,
                    "alert":"ROGUE_CID_DETECTED","ci":cell.get("ci"),
                    "tac":cell.get("tac"),"mcc":cell.get("mcc"),"mnc":cell.get("mnc"),
                    "rsrp":cell.get("rsrp"),"rssi":cell.get("rssi"),
                    "timing_advance":cell.get("timing_advance"),"bands":cell.get("bands"),
                    "latitude":lat,"longitude":lon}
                print(f"  *** CID={cell.get('ci')} | TAC={cell.get('tac')} | RSRP={cell.get('rsrp')}dBm")
                if lat: print(f"  *** GPS: {lat}, {lon}")
                log_event(event)
                report_to_api(event)
        else:
            print(f" — ✅ Clean")
        print(f"  Total scans: {scan_count} | Rogue hits: {rogue_hits}")
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
