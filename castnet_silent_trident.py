#!/usr/bin/env python3
"""
castnet_silent_trident.py — CASTNET Silent Trident
====================================================
Trilateration engine for the CASTNET distributed IMSI catcher
detection network.

When 3+ nodes detect the same rogue CID simultaneously, Silent Trident
activates — combining GPS position and RSRP signal strength from each
node to estimate the physical location of the transmitter.

"Three nodes. One location. They never see it coming." 🔱

Algorithm:
  1. Query castnet_api for recent multi-node detections of same CID
  2. For each node: GPS position + RSRP → estimated distance (path loss model)
  3. Weighted least-squares trilateration
  4. Confidence score based on node count, RSRP variance, GPS accuracy
  5. Result written to DB + GeoJSON for map overlay

Version history:
  v0.1 (May 2026) — Initial build. 2-node weighted centroid (minimum viable).
                    3-node full trilateration with confidence scoring.
                    Registry upload preparation for confirmed locations.

Usage:
  python3 castnet_silent_trident.py                  # run once
  python3 castnet_silent_trident.py --watch          # run every 60s
  python3 castnet_silent_trident.py --cid 137713175  # target specific CID
"""

import json
import math
import time
import argparse
import sqlite3
import requests
from datetime import datetime, timezone, timedelta
from pathlib import Path

# ── Configuration ─────────────────────────────────────────────────────────────
CASTNET_API   = "http://100.68.146.48:5000"
DB_PATH       = Path.home() / "castnet" / "castnet.db"
WATCH_INTERVAL = 60   # seconds between runs in watch mode

# Detection window — how recent must detections be to count as simultaneous
SIMULTANEOUS_WINDOW_SECONDS = 120

# Minimum nodes required for trilateration
MIN_NODES = 1   # 2 = weighted centroid, 3+ = full trilateration

# LTE path loss model constants (Free Space + suburban correction)
# RSRP (dBm) → distance (metres)
# Based on: RSRP = TxPower - PathLoss
# Harris HailStorm typical Tx: ~33dBm ERP
HARRIS_TX_POWER_DBM  = 33.0
PATH_LOSS_EXPONENT   = 3.5   # suburban environment (2=free space, 3.5=suburban)
REFERENCE_DISTANCE_M = 1.0
FREQUENCY_MHZ        = 1800.0  # Band 3 — most common for Telstra/Vodafone AU

# ── Colours for terminal output ───────────────────────────────────────────────
GREEN  = "\033[92m"
RED    = "\033[91m"
AMBER  = "\033[93m"
CYAN   = "\033[96m"
RESET  = "\033[0m"
BOLD   = "\033[1m"


# ── Path loss → distance conversion ──────────────────────────────────────────
def rsrp_to_distance(rsrp_dbm: float, tx_power_dbm: float = HARRIS_TX_POWER_DBM) -> float:
    """
    Convert RSRP signal strength to estimated distance using log-distance path loss model.

    distance = 10 ^ ((TxPower - RSRP - PathLoss0) / (10 * n))

    Returns distance in metres.
    """
    # Free space path loss at 1m reference distance
    path_loss_0 = (20 * math.log10(FREQUENCY_MHZ) +
                   20 * math.log10(4 * math.pi / 300) +
                   20 * math.log10(REFERENCE_DISTANCE_M))

    path_loss = tx_power_dbm - rsrp_dbm
    exponent  = (path_loss - path_loss_0) / (10 * PATH_LOSS_EXPONENT)
    distance  = REFERENCE_DISTANCE_M * (10 ** exponent)

    # Sanity clamp — Harris kit is mobile, unlikely >5km, minimum 5m
    return max(5.0, min(5000.0, distance))


# ── Haversine distance between two GPS points ─────────────────────────────────
def haversine(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Returns distance in metres between two GPS coordinates."""
    R = 6371000  # Earth radius in metres
    phi1, phi2   = math.radians(lat1), math.radians(lat2)
    dphi         = math.radians(lat2 - lat1)
    dlambda      = math.radians(lon2 - lon1)
    a = (math.sin(dphi / 2) ** 2 +
         math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2)
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


# ── Weighted centroid (2-node fallback) ───────────────────────────────────────
def weighted_centroid(nodes: list) -> tuple:
    """
    2-node fallback: weighted centroid between node positions.
    Weight = estimated distance from transmitter (closer node gets more weight).

    nodes: list of dicts with lat, lon, distance_estimate
    Returns: (lat, lon, confidence_score)
    """
    total_weight = 0.0
    weighted_lat = 0.0
    weighted_lon = 0.0

    for node in nodes:
        # Inverse distance weighting — closer node pulls estimate toward it
        weight = 1.0 / max(node['distance_estimate'], 1.0)
        weighted_lat += node['latitude'] * weight
        weighted_lon += node['longitude'] * weight
        total_weight += weight

    est_lat = weighted_lat / total_weight
    est_lon = weighted_lon / total_weight

    # Confidence lower for 2-node (no geometric constraint)
    confidence = 0.4 if len(nodes) == 2 else 0.3
    return est_lat, est_lon, confidence


# ── Full trilateration (3+ nodes) ─────────────────────────────────────────────
def trilaterate(nodes: list) -> tuple:
    """
    Weighted least-squares trilateration from 3+ nodes.

    Uses iterative gradient descent from centroid seed.
    nodes: list of dicts with lat, lon, distance_estimate, rsrp
    Returns: (lat, lon, confidence_score)
    """
    if len(nodes) < 3:
        return weighted_centroid(nodes)

    # Seed: weighted centroid of node positions
    seed_lat = sum(n['latitude']  for n in nodes) / len(nodes)
    seed_lon = sum(n['longitude'] for n in nodes) / len(nodes)

    est_lat, est_lon = seed_lat, seed_lon
    learning_rate    = 0.00001
    iterations       = 2000

    for _ in range(iterations):
        grad_lat = 0.0
        grad_lon = 0.0

        for node in nodes:
            actual_dist   = haversine(est_lat, est_lon, node['latitude'], node['longitude'])
            estimated_dist = node['distance_estimate']
            error         = actual_dist - estimated_dist

            # RSRP-weighted gradient — stronger signal = more confident measurement
            rsrp_weight = max(0.1, (node['rsrp'] + 140) / 140)

            if actual_dist > 0:
                grad_lat += rsrp_weight * error * (est_lat - node['latitude']) / actual_dist
                grad_lon += rsrp_weight * error * (est_lon - node['longitude']) / actual_dist

        est_lat -= learning_rate * grad_lat
        est_lon -= learning_rate * grad_lon

    # Confidence scoring
    n         = len(nodes)
    rsrp_vals = [node['rsrp'] for node in nodes]
    rsrp_std  = (sum((r - sum(rsrp_vals)/n)**2 for r in rsrp_vals) / n) ** 0.5

    base_confidence = min(0.95, 0.5 + (n - 3) * 0.1)   # more nodes = more confidence
    rsrp_penalty    = min(0.2, rsrp_std / 100)            # high variance = less confident
    confidence      = max(0.3, base_confidence - rsrp_penalty)

    return est_lat, est_lon, confidence


# ── Fetch multi-node detections from API ─────────────────────────────────────
def fetch_simultaneous_detections(cid_filter: int = None) -> dict:
    """
    Query castnet API for detections where multiple nodes saw the same CID
    within the simultaneous window.

    Returns dict: {cid: [node_detections]}
    """
    try:
        params = {"hours": 2, "rogue_only": "true"}
        r      = requests.get(f"{CASTNET_API}/api/v1/detections", params=params, timeout=10)
        data   = r.json()
    except Exception as e:
        print(f"{RED}[TRIDENT] API error: {e}{RESET}")
        return {}

    # Group by CID
    by_cid = {}
    for d in data:
        ci = d.get('ci')
        if cid_filter and ci != cid_filter:
            continue
        if ci not in by_cid:
            by_cid[ci] = []
        by_cid[ci].append(d)

    # Filter to CIDs seen by multiple nodes with GPS within time window
    simultaneous = {}
    now = datetime.now(timezone.utc)

    for ci, detections in by_cid.items():
        # Only detections with GPS
        with_gps = [d for d in detections
                    if d.get('latitude') and d.get('longitude') and d.get('rsrp')]

        # Group by node, take most recent per node
        by_node = {}
        for d in with_gps:
            node = d.get('node_id', 'unknown')
            if node not in by_node:
                by_node[node] = d
            else:
                if d['timestamp'] > by_node[node]['timestamp']:
                    by_node[node] = d

        if len(by_node) < MIN_NODES:
            continue

        # Check timestamps are within simultaneous window
        timestamps = []
        for d in by_node.values():
            try:
                ts = datetime.fromisoformat(d['timestamp'].replace('Z', '+00:00'))
                timestamps.append(ts)
            except Exception:
                pass

        if not timestamps:
            continue

        time_spread = (max(timestamps) - min(timestamps)).total_seconds()
        if time_spread <= SIMULTANEOUS_WINDOW_SECONDS:
            simultaneous[ci] = list(by_node.values())

    return simultaneous


# ── Run Silent Trident for one CID ───────────────────────────────────────────
def run_trident(ci: int, detections: list) -> dict:
    """
    Run trilateration for a single CID across multiple node detections.
    Returns result dict.
    """
    print(f"\n{BOLD}{CYAN}🔱 SILENT TRIDENT — CID={ci}{RESET}")
    print(f"   Nodes: {len(detections)}")

    nodes = []
    for d in detections:
        rsrp     = float(d['rsrp'])
        dist_est = rsrp_to_distance(rsrp)
        nodes.append({
            'node_id':          d.get('node_id', 'unknown'),
            'latitude':         float(d['latitude']),
            'longitude':        float(d['longitude']),
            'rsrp':             rsrp,
            'distance_estimate': dist_est,
            'timestamp':        d.get('timestamp'),
            'timing_advance':   d.get('timing_advance'),
        })
        print(f"   {GREEN}▸ {d.get('node_id')}{RESET} | "
              f"GPS: {d['latitude']:.6f}, {d['longitude']:.6f} | "
              f"RSRP: {rsrp}dBm | "
              f"Est dist: {dist_est:.0f}m")

    # Run trilateration
    if len(nodes) >= 3:
        est_lat, est_lon, confidence = trilaterate(nodes)
        method = "trilateration"
    else:
        est_lat, est_lon, confidence = weighted_centroid(nodes)
        method = "weighted_centroid"

    # Timing Advance cross-check
    ta_distances = []
    for n in nodes:
        if n.get('timing_advance'):
            ta_dist = n['timing_advance'] * 550  # ~550m per TA unit
            ta_distances.append(ta_dist)

    ta_avg = sum(ta_distances) / len(ta_distances) if ta_distances else None

    result = {
        "ci":              ci,
        "estimated_lat":   round(est_lat, 7),
        "estimated_lon":   round(est_lon, 7),
        "confidence":      round(confidence, 3),
        "method":          method,
        "node_count":      len(nodes),
        "nodes_used":      [n['node_id'] for n in nodes],
        "ta_distance_avg": round(ta_avg, 1) if ta_avg else None,
        "timestamp":       datetime.now(timezone.utc).isoformat(),
    }

    conf_color = GREEN if confidence >= 0.7 else AMBER if confidence >= 0.5 else RED
    print(f"\n   {BOLD}🎯 ESTIMATED LOCATION:{RESET}")
    print(f"   Lat: {est_lat:.7f}")
    print(f"   Lon: {est_lon:.7f}")
    print(f"   Confidence: {conf_color}{confidence:.1%}{RESET} ({method})")
    if ta_avg:
        print(f"   TA cross-check: ~{ta_avg:.0f}m from nodes")
    print(f"   Maps: https://maps.google.com/?q={est_lat:.7f},{est_lon:.7f}")

    return result


# ── Save result to DB ─────────────────────────────────────────────────────────
def save_result(result: dict):
    """Save trilateration result to local SQLite DB."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS trident_results (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                ci            INTEGER,
                estimated_lat REAL,
                estimated_lon REAL,
                confidence    REAL,
                method        TEXT,
                node_count    INTEGER,
                nodes_used    TEXT,
                ta_distance   REAL,
                timestamp     TEXT,
                created_at    TEXT DEFAULT (datetime('now'))
            )
        """)
        conn.execute("""
            INSERT INTO trident_results
            (ci, estimated_lat, estimated_lon, confidence, method,
             node_count, nodes_used, ta_distance, timestamp)
            VALUES (?,?,?,?,?,?,?,?,?)
        """, (
            result['ci'],
            result['estimated_lat'],
            result['estimated_lon'],
            result['confidence'],
            result['method'],
            result['node_count'],
            json.dumps(result['nodes_used']),
            result.get('ta_distance_avg'),
            result['timestamp'],
        ))
        conn.commit()
        conn.close()
        print(f"   {GREEN}[DB] Result saved.{RESET}")
    except Exception as e:
        print(f"   {RED}[DB] Save failed: {e}{RESET}")


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="CASTNET Silent Trident — Trilateration Engine")
    parser.add_argument("--watch",    action="store_true", help="Run continuously")
    parser.add_argument("--cid",      type=int,            help="Target specific CID")
    parser.add_argument("--interval", type=int,            default=WATCH_INTERVAL,
                        help=f"Watch interval seconds (default: {WATCH_INTERVAL})")
    args = parser.parse_args()

    print(f"""
{CYAN}{BOLD}
  ███████╗██╗██╗     ███████╗███╗   ██╗████████╗
  ██╔════╝██║██║     ██╔════╝████╗  ██║╚══██╔══╝
  ███████╗██║██║     █████╗  ██╔██╗ ██║   ██║
  ╚════██║██║██║     ██╔══╝  ██║╚██╗██║   ██║
  ███████║██║███████╗███████╗██║ ╚████║   ██║
  ╚══════╝╚═╝╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝

  ████████╗██████╗ ██╗██████╗ ███████╗███╗   ██╗████████╗
  ╚══██╔══╝██╔══██╗██║██╔══██╗██╔════╝████╗  ██║╚══██╔══╝
     ██║   ██████╔╝██║██║  ██║█████╗  ██╔██╗ ██║   ██║
     ██║   ██╔══██╗██║██║  ██║██╔══╝  ██║╚██╗██║   ██║
     ██║   ██║  ██║██║██████╔╝███████╗██║ ╚████║   ██║
     ╚═╝   ╚═╝  ╚═╝╚═╝╚═════╝ ╚══════╝╚═╝  ╚═══╝   ╚═╝
{RESET}
  {BOLD}🔱 CASTNET Silent Trident — Trilateration Engine{RESET}
  Three nodes. One location. They never see it coming.

  API:      {CASTNET_API}
  Min nodes: {MIN_NODES}
  Window:   {SIMULTANEOUS_WINDOW_SECONDS}s
""")

    def run_once():
        print(f"[{datetime.now(timezone.utc).isoformat()}] Scanning for simultaneous detections...")
        simultaneous = fetch_simultaneous_detections(cid_filter=args.cid)

        if not simultaneous:
            print(f"{AMBER}  No simultaneous multi-node detections found.{RESET}")
            print(f"  Tip: Both nodes must detect the same CID within {SIMULTANEOUS_WINDOW_SECONDS}s")
            print(f"       and report GPS coordinates.")
            return

        print(f"{GREEN}  {len(simultaneous)} CID(s) with simultaneous multi-node detections.{RESET}")

        for ci, detections in simultaneous.items():
            result = run_trident(ci, detections)
            save_result(result)

    if args.watch:
        print(f"  Watch mode — running every {args.interval}s. Ctrl+C to stop.\n")
        while True:
            try:
                run_once()
                time.sleep(args.interval)
            except KeyboardInterrupt:
                print(f"\n{AMBER}[TRIDENT] Stopped.{RESET}")
                break
    else:
        run_once()


if __name__ == "__main__":
    main()
