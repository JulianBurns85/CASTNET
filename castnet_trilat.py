"""
castnet_trilat.py — CASTNET Trilateration Engine
=================================================
Estimates transmitter location from multi-node RSRP detections.

Usage (standalone test):
    python castnet_trilat.py

Usage (from castnet_api.py):
    from castnet_trilat import run_trilateration
    result = run_trilateration(detections)

Requirements:
    pip install numpy scipy --break-system-packages
"""

import math
import json
from datetime import datetime, timezone, timedelta
from typing import Optional

try:
    import numpy as np
    from scipy.optimize import minimize
    SCIPY_AVAILABLE = True
except ImportError:
    SCIPY_AVAILABLE = False
    print("[TRILAT] WARNING: numpy/scipy not installed. Run:")
    print("  pip install numpy scipy --break-system-packages")


# ── Constants ─────────────────────────────────────────────────────────────────

# Free-space path loss model for LTE Band 28 (700 MHz)
# RSRP (dBm) = TX_POWER - PATH_LOSS
# Path loss (dB) = 20*log10(d) + 20*log10(f) + 20*log10(4π/c)
# Simplified: distance_metres = 10 ** ((TX_POWER_DBM - RSRP_DBM - OFFSET) / 20)

# Typical IMSI catcher TX power: 30-43 dBm (legal limit AU: 43 dBm EIRP)
# We use a conservative 33 dBm (2W) as default — can be tuned
TX_POWER_DBM = 13.0
FREQ_MHZ = 700.0  # Band 28

# Path loss offset for 700 MHz
# PL_offset = 20*log10(4*pi*f/c) where f in Hz
# = 20*log10(4 * pi * 700e6 / 3e8) = ~69.4 dB
PL_OFFSET_DB = 20 * math.log10(4 * math.pi * FREQ_MHZ * 1e6 / 3e8)  # correct

# Minimum nodes required for trilateration
MIN_NODES = 3

# Maximum age of a detection to be included (seconds)
MAX_DETECTION_AGE_S = 120

# Earth radius for Haversine
EARTH_RADIUS_M = 6_371_000


# ── Path Loss → Distance ──────────────────────────────────────────────────────

def rsrp_to_distance(rsrp_dbm: float, tx_power_dbm: float = TX_POWER_DBM) -> float:
    """
    Convert RSRP reading to estimated distance in metres.
    Uses free-space path loss model for LTE Band 28 (700 MHz).

    Returns distance in metres. Clamped to 50m–5000m.
    """
    path_loss = tx_power_dbm - rsrp_dbm
    exponent = (path_loss - PL_OFFSET_DB) / 20.0
    distance = 10 ** exponent
    return max(50.0, min(distance, 5000.0))


# ── Coordinate Utilities ──────────────────────────────────────────────────────

def haversine(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Distance in metres between two lat/lon points."""
    r = EARTH_RADIUS_M
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlam = math.radians(lon2 - lon1)
    a = math.sin(dphi/2)**2 + math.cos(phi1)*math.cos(phi2)*math.sin(dlam/2)**2
    return 2 * r * math.asin(math.sqrt(a))


def offset_coords(lat: float, lon: float, dx_m: float, dy_m: float):
    """Offset a lat/lon by dx metres (east) and dy metres (north)."""
    new_lat = lat + (dy_m / EARTH_RADIUS_M) * (180 / math.pi)
    new_lon = lon + (dx_m / (EARTH_RADIUS_M * math.cos(math.radians(lat)))) * (180 / math.pi)
    return new_lat, new_lon


def to_local_xy(ref_lat: float, ref_lon: float, lat: float, lon: float):
    """Convert lat/lon to local x/y metres relative to a reference point."""
    x = haversine(ref_lat, ref_lon, ref_lat, lon) * (1 if lon >= ref_lon else -1)
    y = haversine(ref_lat, ref_lon, lat, ref_lon) * (1 if lat >= ref_lat else -1)
    return x, y


# ── Core Trilateration ────────────────────────────────────────────────────────

def trilaterate(nodes: list[dict]) -> Optional[dict]:
    """
    Estimate transmitter location from 3+ node detections.

    Each node dict must have:
        lat, lon, rsrp_dbm, node_id

    Returns dict with estimated lat/lon and confidence metrics,
    or None if trilateration fails.
    """
    if not SCIPY_AVAILABLE:
        return {"error": "numpy/scipy not installed"}

    if len(nodes) < MIN_NODES:
        return None

    # Reference point — centroid of all nodes
    ref_lat = sum(n["lat"] for n in nodes) / len(nodes)
    ref_lon = sum(n["lon"] for n in nodes) / len(nodes)

    # Convert node positions to local x/y and compute radii
    positions = []
    radii = []
    for n in nodes:
        x, y = to_local_xy(ref_lat, ref_lon, n["lat"], n["lon"])
        r = rsrp_to_distance(n["rsrp_dbm"])
        positions.append((x, y))
        radii.append(r)

    positions = np.array(positions)
    radii = np.array(radii)

    # Objective: minimise sum of squared residuals
    # residual_i = (distance from estimate to node_i) - radius_i
    def objective(point):
        px, py = point
        residuals = []
        for i, (nx, ny) in enumerate(positions):
            dist = math.sqrt((px - nx)**2 + (py - ny)**2)
            residuals.append((dist - radii[i])**2)
        return sum(residuals)

    # Initial guess: centroid of node positions
    x0 = np.mean(positions[:, 0])
    y0 = np.mean(positions[:, 1])

    result = minimize(objective, [x0, y0], method="Nelder-Mead",
                      options={"xatol": 1.0, "fatol": 1.0, "maxiter": 10000})

    if not result.success and result.fun > 1e6:
        return {"error": f"Optimisation failed: {result.message}"}

    est_x, est_y = result.x
    est_lat, est_lon = offset_coords(ref_lat, ref_lon, est_x, est_y)

    # Confidence: based on residual error relative to mean radius
    mean_radius = float(np.mean(radii))
    residual_rms = math.sqrt(result.fun / len(nodes))
    confidence_pct = max(0.0, min(100.0, 100 * (1 - residual_rms / mean_radius)))

    # Distance from each node to estimate
    node_distances = []
    for i, n in enumerate(nodes):
        d = haversine(est_lat, est_lon, n["lat"], n["lon"])
        node_distances.append({
            "node_id": n["node_id"],
            "distance_m": round(d, 1),
            "rsrp_dbm": n["rsrp_dbm"],
            "estimated_radius_m": round(radii[i], 1)
        })

    return {
        "estimated_lat": round(est_lat, 7),
        "estimated_lon": round(est_lon, 7),
        "confidence_pct": round(confidence_pct, 1),
        "residual_rms_m": round(residual_rms, 1),
        "mean_estimated_radius_m": round(mean_radius, 1),
        "node_count": len(nodes),
        "nodes": node_distances,
        "method": "FSPL_NelderMead",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


# ── API Integration Helper ────────────────────────────────────────────────────

def run_trilateration(detections: list[dict], cid: int = None) -> Optional[dict]:
    """
    Run trilateration on a list of detection records from castnet_log.json.

    If cid is specified, filters to that CID only.
    Filters to detections within MAX_DETECTION_AGE_S seconds.
    Requires at least MIN_NODES unique nodes with GPS coordinates.

    Returns trilateration result dict or None.
    """
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(seconds=MAX_DETECTION_AGE_S)

    # Filter by CID if specified
    if cid is not None:
        detections = [d for d in detections if d.get("ci") == cid]

    # Filter by age
    recent = []
    for d in detections:
        try:
            ts = datetime.fromisoformat(d["timestamp"])
            if ts >= cutoff:
                recent.append(d)
        except Exception:
            continue

    # Filter to records with GPS
    gps_detections = [d for d in recent if d.get("latitude") and d.get("longitude")]

    # One record per node — use strongest RSRP per node
    by_node = {}
    for d in gps_detections:
        nid = d["node_id"]
        if nid not in by_node or d["rsrp"] > by_node[nid]["rsrp"]:
            by_node[nid] = d

    if len(by_node) < MIN_NODES:
        return None

    nodes = [
        {
            "node_id": nid,
            "lat": d["latitude"],
            "lon": d["longitude"],
            "rsrp_dbm": d["rsrp"]
        }
        for nid, d in by_node.items()
    ]

    return trilaterate(nodes)


# ── Standalone Test ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("CASTNET Trilateration Engine — Test Mode")
    print("=" * 60)

    # Simulate 3 nodes detecting CID=137713165
    # Using real Cranbourne East coordinates with slight offsets
    # to simulate nodes at different locations
    test_nodes = [
        {
            "node_id": "ulefone_tab4_node1",
            "lat": -38.1184,
            "lon": 145.3056,
            "rsrp_dbm": -66.4
        },
        {
            "node_id": "grapher",
            "lat": -38.1210,
            "lon": 145.3120,
            "rsrp_dbm": -73.5
        },
        {
            "node_id": "node3_car",
            "lat": -38.1145,
            "lon": 145.3010,
            "rsrp_dbm": -71.2
        }
    ]

    print(f"\nInput nodes ({len(test_nodes)}):")
    for n in test_nodes:
        dist = rsrp_to_distance(n["rsrp_dbm"])
        print(f"  {n['node_id']}: RSRP={n['rsrp_dbm']} dBm → est. radius={dist:.0f}m")

    print("\nRunning trilateration...")
    result = trilaterate(test_nodes)

    if result and "error" not in result:
        print(f"\n✅ ESTIMATED TRANSMITTER LOCATION:")
        print(f"   Lat: {result['estimated_lat']}")
        print(f"   Lon: {result['estimated_lon']}")
        print(f"   Confidence: {result['confidence_pct']}%")
        print(f"   RMS residual: {result['residual_rms_m']}m")
        print(f"\n   Google Maps: https://maps.google.com/?q={result['estimated_lat']},{result['estimated_lon']}")
        print(f"\n   Per-node breakdown:")
        for n in result["nodes"]:
            print(f"     {n['node_id']}: {n['distance_m']}m from estimate (radius={n['estimated_radius_m']}m)")
    else:
        print(f"\n❌ Trilateration failed: {result}")

    print("\n" + "=" * 60)
    print("To use with real data:")
    print("  from castnet_trilat import run_trilateration")
    print("  result = run_trilateration(detections, cid=137713165)")
    print("=" * 60)
