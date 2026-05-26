#!/usr/bin/env python3
"""
castnet_node.py — CASTNET Field Node v0.1.1
Civilian IMSI Catcher Detection Network

Tier 1 node — no root required.
Runs on Android via Termux, or any Linux system.

Requirements (Termux):
  pkg install python termux-api
  pip install requests

Requirements (Linux):
  pip install requests
  # Cell info via ModemManager or nmcli — see get_cells_linux()

Configuration:
  Set CASTNET_API_KEY environment variable to match the server.
  Set CASTNET_NODE_ID to identify this node uniquely.
  Set CASTNET_API to point at your central API (Tailscale IP default).

  export CASTNET_API_KEY=your-secret-key-here
  export CASTNET_NODE_ID=my_phone_node1
  export CASTNET_API=http://100.68.146.48:5000/api/v1/report

Version history:
  v0.1   (May 2026) — Initial build. Termux telephony, GPS, API reporting.
  v0.2   (May 2026) -- Offline buffer with auto-flush on reconnect.
  v0.1.1 (May 2026) — API key auth added. Portable log path (no Termux hardcode).
                      Config moved to environment variables + constants block.
                      Watchlist CIDs added. Linux cell fallback stub added.
                      Rogue CID set expanded to 18 confirmed CIDs.
"""

import json
import os
import platform
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

# ── Configuration — override via environment variables ────────────────────────
CASTNET_API   = os.environ.get("CASTNET_API",     "http://100.68.146.48:5000/api/v1/report")
NODE_ID       = os.environ.get("CASTNET_NODE_ID", "ulefone_tab4_node1")
API_KEY       = os.environ.get("CASTNET_API_KEY", "")
POLL_INTERVAL = int(os.environ.get("CASTNET_POLL", "30"))

# Portable log path — works on Termux, Linux, Windows
LOG_FILE   = Path.home() / "castnet_log.json"
QUEUE_FILE = Path.home() / "castnet_offline_queue.json"
QUEUE_MAX  = 500

IS_TERMUX = "com.termux" in str(Path.home())

# ── Known rogue CIDs ──────────────────────────────────────────────────────────
# Source: rayhunter-threat-analyzer confirmed findings, Cranbourne East VIC
# Keep this in sync with castnet_api.py
KNOWN_ROGUE_CIDS = {
    # Telstra AU — MCC=505 MNC=001 TAC=12385
    137713195,   # confirmed — highest observation count
    137713175,   # confirmed — geo-located Prendergast Ave 331m
    137713165,   # confirmed
    137713155,   # confirmed
    135836191,   # confirmed — geo-located Collison Rd 912m
    135836171,   # confirmed — geo-located Casey Fields 2424m
    135836161,   # added May 2026 — 31 observations, TAC=12385 cluster

    # Vodafone AU — MCC=505 MNC=003 TAC=30336
    8409357,     # confirmed
    8409367,     # confirmed
    8409387,     # confirmed
    8409397,     # confirmed — anomalous rapid sub-2s departures
    8435470,     # added May 2026 — 20 observations April reports
    8435480,     # confirmed

    # Post-ACMA inspection CIDs — appeared 8 May 2026
    8666381,
    8666391,
    8666411,
}

# Watchlist — observed but not yet confirmed rogue
WATCHLIST_CIDS = {8395020, 8395030}


# ── Cell info ─────────────────────────────────────────────────────────────────
def get_cells():
    """Get visible cell list. Returns list of dicts with ci, tac, mcc, mnc, rsrp etc."""
    if IS_TERMUX:
        return get_cells_termux()
    else:
        return get_cells_linux()


def get_cells_termux():
    try:
        result = subprocess.run(
            ["termux-telephony-cellinfo"],
            capture_output=True, text=True, timeout=10
        )
        data = json.loads(result.stdout)
        return data if isinstance(data, list) else []
    except Exception as e:
        print(f"  [ERROR] Termux cell query failed: {e}")
        return []


def get_cells_linux():
    """
    Linux cell info stub — implement via ModemManager or nmcli.
    Returns empty list until implemented.

    Example with ModemManager:
        mmcli -m 0 --output-json
    Example with nmcli (limited):
        nmcli -t -f IN-USE,BSSID,SIGNAL,CHAN device wifi list
    """
    # TODO: implement ModemManager integration for Linux nodes
    print("  [INFO] Linux cell query not yet implemented — returning empty")
    return []


# ── GPS ───────────────────────────────────────────────────────────────────────
def get_location():
    """Get GPS coordinates. Returns (lat, lon) or (None, None)."""
    if IS_TERMUX:
        return get_location_termux()
    return None, None


def get_location_termux():
    try:
        result = subprocess.run(
            ["termux-location", "-p", "network", "-r", "once"],
            capture_output=True, text=True, timeout=15
        )
        loc = json.loads(result.stdout)
        return loc.get("latitude"), loc.get("longitude")
    except Exception:
        return None, None


# ── Logging ───────────────────────────────────────────────────────────────────
def log_event(event):
    try:
        existing = []
        if LOG_FILE.exists():
            with open(LOG_FILE, "r", encoding="utf-8") as f:
                existing = json.load(f)
        existing.append(event)
        with open(LOG_FILE, "w", encoding="utf-8") as f:
            json.dump(existing, f, indent=2)
    except Exception as e:
        print(f"  [ERROR] Log write failed: {e}")


# -- Offline queue ----------------------------------------------------------------
def queue_event(event):
    try:
        import json as _json
        existing = []
        if QUEUE_FILE.exists():
            existing = _json.loads(QUEUE_FILE.read_text(encoding="utf-8"))
        existing.append(event)
        if len(existing) > QUEUE_MAX:
            existing = existing[-QUEUE_MAX:]
        QUEUE_FILE.write_text(_json.dumps(existing, indent=2), encoding="utf-8")
        print(f"  [QUEUE] Buffered offline -- {len(existing)} event(s) queued")
    except Exception as e:
        print(f"  [ERROR] Queue write failed: {e}")


def flush_offline_queue(headers):
    import json as _json
    if not QUEUE_FILE.exists():
        return
    try:
        queued = _json.loads(QUEUE_FILE.read_text(encoding="utf-8"))
    except Exception:
        return
    if not queued:
        return
    import requests
    print(f"  [QUEUE] Flushing {len(queued)} buffered event(s)...")
    flushed, failed = 0, []
    for ev in queued:
        try:
            r = requests.post(CASTNET_API, json=ev, headers=headers, timeout=5)
            if r.status_code == 200:
                flushed += 1
            else:
                failed.append(ev)
        except Exception:
            failed.append(ev)
            break
    if flushed:
        print(f"  [QUEUE] Flushed {flushed} event(s)")
    QUEUE_FILE.write_text(_json.dumps(failed, indent=2), encoding="utf-8")
    if not failed:
        QUEUE_FILE.unlink(missing_ok=True)


# ── API reporting ─────────────────────────────────────────────────────────────



# -- Offline queue ----------------------------------------------------------------
def queue_event(event):
    import json as _j
    try:
        existing = _j.loads(QUEUE_FILE.read_text(encoding='utf-8')) if QUEUE_FILE.exists() else []
        existing.append(event)
        if len(existing) > QUEUE_MAX:
            existing = existing[-QUEUE_MAX:]
        QUEUE_FILE.write_text(_j.dumps(existing, indent=2), encoding='utf-8')
        print(f"  [QUEUE] Buffered -- {len(existing)} event(s) queued")
    except Exception as e:
        print(f"  [ERROR] Queue write failed: {e}")


def flush_offline_queue(headers):
    import json as _j
    if not QUEUE_FILE.exists():
        return
    try:
        queued = _j.loads(QUEUE_FILE.read_text(encoding='utf-8'))
    except Exception:
        return
    if not queued:
        return
    import requests as _r
    print(f"  [QUEUE] Flushing {len(queued)} buffered event(s)...")
    flushed, failed = 0, []
    for ev in queued:
        try:
            r = _r.post(CASTNET_API, json=ev, headers=headers, timeout=5)
            if r.status_code == 200:
                flushed += 1
            else:
                failed.append(ev)
        except Exception:
            failed.append(ev)
            break
    if flushed:
        print(f"  [QUEUE] Flushed {flushed} event(s)")
    QUEUE_FILE.write_text(_j.dumps(failed, indent=2), encoding='utf-8')
    if not failed:
        QUEUE_FILE.unlink(missing_ok=True)


def report_to_api(event):
    import requests
    headers = {}
    if API_KEY:
        headers["X-Castnet-Key"] = API_KEY
    else:
        print("  [WARN] CASTNET_API_KEY not set -- unauthenticated")
    flush_offline_queue(headers)
    try:
        resp = requests.post(CASTNET_API, json=event, headers=headers, timeout=5)
        if resp.status_code == 200:
            print(f"  [API] Reported to Castnet central -- {resp.json().get('status')}")
        elif resp.status_code == 401:
            print("  [API] Auth failed -- check CASTNET_API_KEY")
        else:
            print(f"  [API] Unexpected response {resp.status_code}")
    except Exception as e:
        print(f"  [API] Offline -- queued for retry ({e})")
        queue_event(event)


def main():
    print(f"""
  CASTNET — Civilian IMSI Catcher Detection Network
  Node     : {NODE_ID}
  Tier     : 1 (no root required)
  Platform : {"Termux/Android" if IS_TERMUX else platform.system()}
  API      : {CASTNET_API}
  Auth     : {"configured" if API_KEY else "NOT SET — unauthenticated"}
  Log      : {LOG_FILE}
  CIDs     : {len(KNOWN_ROGUE_CIDS)} confirmed rogue | {len(WATCHLIST_CIDS)} watchlist
  Interval : {POLL_INTERVAL}s
  Started  : {datetime.now(timezone.utc).isoformat()}

  Because Stingrays are fish too. 🎣
""")

    if not API_KEY:
        print("  [WARN] *** CASTNET_API_KEY not set ***")
        print("  [WARN] Set it: export CASTNET_API_KEY=your-secret-key\n")

    scan_count = 0
    rogue_hits = 0

    while True:
        scan_count += 1
        ts    = datetime.now(timezone.utc).isoformat()
        cells = get_cells()

        print(f"[{ts}] Scan #{scan_count} — {len(cells)} cells visible", end="")

        rogues_this_scan    = []
        watchlist_this_scan = []

        for cell in cells:
            if not isinstance(cell, dict):
                continue
            ci = cell.get("ci")
            if ci is None:
                continue
            ci_int = int(ci)
            if ci_int in KNOWN_ROGUE_CIDS:
                rogues_this_scan.append(cell)
            elif ci_int in WATCHLIST_CIDS:
                watchlist_this_scan.append(cell)

        if rogues_this_scan:
            rogue_hits += 1
            print(f" — 🚨 {len(rogues_this_scan)} ROGUE CID(s) DETECTED!")
            lat, lon = get_location()

            for cell in rogues_this_scan:
                ci_int = int(cell.get("ci"))
                event = {
                    "timestamp":      ts,
                    "node_id":        NODE_ID,
                    "tier":           1,
                    "alert":          "ROGUE_CID_DETECTED",
                    "ci":             ci_int,
                    "tac":            cell.get("tac"),
                    "mcc":            cell.get("mcc"),
                    "mnc":            cell.get("mnc"),
                    "rsrp":           cell.get("rsrp"),
                    "rssi":           cell.get("rssi"),
                    "timing_advance": cell.get("timing_advance"),
                    "bands":          cell.get("bands"),
                    "latitude":       lat,
                    "longitude":      lon,
                }
                print(f"  *** CID={ci_int} | TAC={cell.get('tac')} | RSRP={cell.get('rsrp')} dBm")
                if lat:
                    print(f"  *** GPS: {lat:.6f}, {lon:.6f}")
                log_event(event)
                report_to_api(event)

        elif watchlist_this_scan:
            print(f" — 👀 {len(watchlist_this_scan)} watchlist CID(s) seen (not reported)")
            for cell in watchlist_this_scan:
                print(f"  --- CID={cell.get('ci')} | TAC={cell.get('tac')} | RSRP={cell.get('rsrp')} dBm")

        else:
            print(f" — ✅ Clean")

        print(f"  Total scans: {scan_count} | Rogue hits: {rogue_hits}")
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
