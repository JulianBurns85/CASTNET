#!/usr/bin/env python3
"""
castnet_api.py — CASTNET Central API
Civilian IMSI Catcher Detection Network

Central aggregation server. Runs on Raspberry Pi 5, accessible via Tailscale.
SQLite backend. Flask REST API.

Endpoints:
  POST /api/v1/report       — receive detection report from a node
  GET  /api/v1/detections   — all logged detections (filterable)
  GET  /api/v1/summary      — dashboard stats + node status
  GET  /api/v1/map          — GeoJSON for Leaflet map dashboard

Authentication:
  All POST requests require header: X-Castnet-Key: <CASTNET_API_KEY>
  Set environment variable CASTNET_API_KEY before starting.
  Example: export CASTNET_API_KEY=your-secret-key-here

Version history:
  v0.1  (May 2026) — Initial build. SQLite schema, node tracking,
                     confirmed rogue CID list, GeoJSON map endpoint.
                     Tailscale deployment on Raspberry Pi 5.
  v0.1.1 (May 2026) — API key auth added. Rogue CID set expanded to 18
                      confirmed CIDs from April–May 2026 report analysis.
                      135836161 and 8435470 added. Log path fix. gitignore fix.
"""

import os
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, request, jsonify

app = Flask(__name__)

# ── Config ────────────────────────────────────────────────────────────────────
DB_PATH     = Path.home() / "castnet" / "castnet.db"
API_KEY     = os.environ.get("CASTNET_API_KEY", "")   # set in environment

# ── Known rogue CIDs ──────────────────────────────────────────────────────────
# Source: rayhunter-threat-analyzer confirmed findings, Cranbourne East VIC
# Last updated: May 2026 — cross-referenced across 8+ report files
#
# DO NOT add CIDs without triple-source confirmation:
#   (1) observed in rayhunter capture
#   (2) absent or anomalous in OpenCelliD
#   (3) consistent with known rogue TAC/MCC/MNC cluster
#
KNOWN_ROGUE_CIDS = {
    # ── Telstra AU — MCC=505 MNC=001 TAC=12385 ──────────────────────────────
    137713195,   # confirmed — highest observation count
    137713175,   # confirmed — geo-located Prendergast Ave, 331m (OpenCelliD Apr 2026)
    137713165,   # confirmed
    137713155,   # confirmed
    135836191,   # confirmed — geo-located Collison Rd, 912m (OpenCelliD Oct 2025)
    135836171,   # confirmed — geo-located Casey Fields, 2424m (OpenCelliD Aug 2025)
    135836161,   # added May 2026 — 31 observations across April reports, TAC=12385 cluster

    # ── Vodafone AU — MCC=505 MNC=003 TAC=30336 ─────────────────────────────
    8409357,     # confirmed — highest Vodafone observation count
    8409367,     # confirmed
    8409387,     # confirmed
    8409397,     # confirmed — flagged anomalous: rapid sub-2s departures
    8435470,     # added May 2026 — 20 observations in April reports
    8435480,     # confirmed (from May 2026 analyzer README)

    # ── Post-ACMA inspection CIDs — appeared 8 May 2026 ────────────────────
    # Zero global OpenCelliD observations. Consistent with post-visit
    # device reconfiguration at neighbouring property.
    8666381,
    8666391,
    8666411,
}

# CIDs under observation but NOT yet confirmed rogue — do not flag, just log
# 8395020, 8395030 — low observation counts, OpenCelliD check pending
WATCHLIST_CIDS = {8395020, 8395030}


# ── Database ──────────────────────────────────────────────────────────────────
def get_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS detections (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp       TEXT NOT NULL,
                node_id         TEXT,
                tier            INTEGER DEFAULT 1,
                ci              INTEGER,
                tac             INTEGER,
                mcc             INTEGER,
                mnc             INTEGER,
                rsrp            REAL,
                rssi            REAL,
                timing_advance  INTEGER,
                bands           TEXT,
                latitude        REAL,
                longitude       REAL,
                confirmed_rogue INTEGER DEFAULT 0,
                watchlist       INTEGER DEFAULT 0,
                created_at      TEXT DEFAULT (datetime('now'))
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS nodes (
                node_id      TEXT PRIMARY KEY,
                tier         INTEGER,
                last_seen    TEXT,
                total_scans  INTEGER DEFAULT 0,
                rogue_hits   INTEGER DEFAULT 0
            )
        """)
        conn.commit()
    print(f"[DB] Initialised at {DB_PATH}")


# ── Auth helper ───────────────────────────────────────────────────────────────
def check_auth():
    """Return True if request passes API key check, or if no key is configured."""
    if not API_KEY:
        # No key configured — warn but allow (dev mode)
        print("[WARN] CASTNET_API_KEY not set — running unauthenticated (dev mode)")
        return True
    return request.headers.get("X-Castnet-Key") == API_KEY


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/api/v1/report", methods=["POST"])
def report():
    if not check_auth():
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "No JSON body"}), 400

    ci = data.get("ci") or data.get("cid")
    if ci is None:
        return jsonify({"error": "Missing ci/cid field"}), 400

    ci_int          = int(ci)
    confirmed_rogue = 1 if ci_int in KNOWN_ROGUE_CIDS else 0
    on_watchlist    = 1 if ci_int in WATCHLIST_CIDS else 0

    with get_db() as conn:
        conn.execute("""
            INSERT INTO detections
            (timestamp, node_id, tier, ci, tac, mcc, mnc, rsrp, rssi,
             timing_advance, bands, latitude, longitude, confirmed_rogue, watchlist)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            data.get("timestamp", datetime.now(timezone.utc).isoformat()),
            data.get("node_id", "unknown"),
            data.get("tier", 1),
            ci_int,
            data.get("tac"),
            data.get("mcc"),
            data.get("mnc"),
            data.get("rsrp"),
            data.get("rssi"),
            data.get("timing_advance"),
            json.dumps(data.get("bands", [])),
            data.get("latitude"),
            data.get("longitude"),
            confirmed_rogue,
            on_watchlist,
        ))

        conn.execute("""
            INSERT INTO nodes (node_id, tier, last_seen, total_scans, rogue_hits)
            VALUES (?,?,?,1,?)
            ON CONFLICT(node_id) DO UPDATE SET
                last_seen   = excluded.last_seen,
                total_scans = total_scans + 1,
                rogue_hits  = rogue_hits + excluded.rogue_hits
        """, (
            data.get("node_id", "unknown"),
            data.get("tier", 1),
            datetime.now(timezone.utc).isoformat(),
            confirmed_rogue,
        ))
        conn.commit()

    status = "ROGUE_CONFIRMED" if confirmed_rogue else ("WATCHLIST" if on_watchlist else "clean")
    print(f"[REPORT] {data.get('node_id')} | CID={ci_int} | {status}")

    return jsonify({
        "status":           "ok",
        "confirmed_rogue":  bool(confirmed_rogue),
        "watchlist":        bool(on_watchlist),
    }), 200


@app.route("/api/v1/detections", methods=["GET"])
def detections():
    hours      = request.args.get("hours", 24, type=int)
    cid_filter = request.args.get("cid", type=int)
    rogue_only = request.args.get("rogue_only", "false").lower() == "true"

    query  = "SELECT * FROM detections WHERE 1=1"
    params = []

    if hours:
        query += f" AND timestamp >= datetime('now', '-{hours} hours')"
    if cid_filter:
        query += " AND ci = ?"
        params.append(cid_filter)
    if rogue_only:
        query += " AND confirmed_rogue = 1"

    query += " ORDER BY timestamp DESC LIMIT 1000"

    with get_db() as conn:
        rows = conn.execute(query, params).fetchall()

    return jsonify([dict(r) for r in rows])


@app.route("/api/v1/summary", methods=["GET"])
def summary():
    with get_db() as conn:
        total       = conn.execute("SELECT COUNT(*) FROM detections").fetchone()[0]
        rogue       = conn.execute(
            "SELECT COUNT(*) FROM detections WHERE confirmed_rogue=1"
        ).fetchone()[0]
        unique_cids = conn.execute(
            "SELECT COUNT(DISTINCT ci) FROM detections WHERE confirmed_rogue=1"
        ).fetchone()[0]
        nodes       = conn.execute(
            "SELECT * FROM nodes ORDER BY last_seen DESC"
        ).fetchall()
        last_rogue  = conn.execute(
            "SELECT timestamp, ci, node_id, rsrp FROM detections "
            "WHERE confirmed_rogue=1 ORDER BY timestamp DESC LIMIT 1"
        ).fetchone()

    return jsonify({
        "castnet":              "v0.1.1",
        "total_events":         total,
        "rogue_detections":     rogue,
        "unique_rogue_cids":    unique_cids,
        "known_rogue_cid_count": len(KNOWN_ROGUE_CIDS),
        "active_nodes":         len([dict(n) for n in nodes]),
        "nodes":                [dict(n) for n in nodes],
        "last_rogue_detection": dict(last_rogue) if last_rogue else None,
    })


@app.route("/api/v1/map", methods=["GET"])
def map_geojson():
    with get_db() as conn:
        rows = conn.execute("""
            SELECT ci, tac, mcc, mnc, rsrp, timing_advance,
                   latitude, longitude, timestamp, node_id
            FROM detections
            WHERE confirmed_rogue = 1
              AND latitude IS NOT NULL
              AND longitude IS NOT NULL
            ORDER BY timestamp DESC
            LIMIT 500
        """).fetchall()

    features = []
    for r in rows:
        features.append({
            "type": "Feature",
            "geometry": {
                "type":        "Point",
                "coordinates": [r["longitude"], r["latitude"]],
            },
            "properties": {
                "ci":             r["ci"],
                "tac":            r["tac"],
                "rsrp":           r["rsrp"],
                "timing_advance": r["timing_advance"],
                "timestamp":      r["timestamp"],
                "node_id":        r["node_id"],
            },
        })

    return jsonify({"type": "FeatureCollection", "features": features})


@app.route("/", methods=["GET"])
def index():
    return jsonify({
        "service":             "Castnet API",
        "version":             "0.1.1",
        "tagline":             "Because Stingrays are fish too.",
        "known_rogue_cids":    len(KNOWN_ROGUE_CIDS),
        "endpoints": [
            "POST /api/v1/report      — submit node detection (requires X-Castnet-Key)",
            "GET  /api/v1/detections  — query detection log",
            "GET  /api/v1/summary     — dashboard stats",
            "GET  /api/v1/map         — GeoJSON for Leaflet",
        ],
    })




@app.route("/api/v1/trident", methods=["GET"])
def trident():
    """Silent Trident on demand — returns latest location estimates."""
    from datetime import datetime, timezone, timedelta
    window = int(request.args.get("hours", 2))
    min_nodes = int(request.args.get("min_nodes", 1))
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=window)).isoformat()
    conn = get_db()
    rows = conn.execute("""
        SELECT ci, tac, node_id, latitude, longitude, rsrp, timing_advance, timestamp
        FROM detections
        WHERE confirmed_rogue=1 AND latitude IS NOT NULL AND timestamp > ?
        ORDER BY timestamp DESC
    """, (cutoff,)).fetchall()
    conn.close()
    by_cid = {}
    for r in rows:
        ci = r["ci"]
        if ci not in by_cid:
            by_cid[ci] = {}
        node = r["node_id"]
        if node not in by_cid[ci]:
            by_cid[ci][node] = r
    results = []
    for ci, nodes in by_cid.items():
        if len(nodes) < min_nodes:
            continue
        nl = list(nodes.values())
        lats = [n["latitude"] for n in nl]
        lons = [n["longitude"] for n in nl]
        rsrps = [n["rsrp"] for n in nl if n["rsrp"]]
        tas = [n["timing_advance"] for n in nl if n["timing_advance"]]
        est_lat = sum(lats)/len(lats)
        est_lon = sum(lons)/len(lons)
        ta_dist = round(sum(tas)/len(tas)*78,1) if tas else None
        mean_rsrp = round(sum(rsrps)/len(rsrps),1) if rsrps else None
        results.append({
            "ci": ci,
            "tac": nl[0]["tac"],
            "node_count": len(nodes),
            "nodes": list(nodes.keys()),
            "estimated_lat": round(est_lat,7),
            "estimated_lon": round(est_lon,7),
            "ta_distance_m": ta_dist,
            "mean_rsrp_dbm": mean_rsrp,
            "maps_url": f"https://maps.google.com/?q={est_lat:.7f},{est_lon:.7f}",
            "confidence": round(min(0.95, 0.3+len(nodes)*0.2),2),
        })
    return jsonify({"trident":"silent","timestamp":datetime.now(timezone.utc).isoformat(),"detections_found":len(results),"results":results})



@app.route("/trident", methods=["GET"])
def trident_html():
    """Mobile-friendly Silent Trident dashboard."""
    from datetime import datetime, timezone, timedelta
    window = int(request.args.get("hours", 2))
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=window)).isoformat()
    conn = get_db()
    rows = conn.execute("""
        SELECT ci, tac, node_id, latitude, longitude, rsrp, timing_advance, timestamp
        FROM detections
        WHERE confirmed_rogue=1 AND latitude IS NOT NULL AND timestamp > ?
        ORDER BY timestamp DESC
    """, (cutoff,)).fetchall()
    conn.close()
    by_cid = {}
    for r in rows:
        ci = r["ci"]
        if ci not in by_cid:
            by_cid[ci] = {}
        if r["node_id"] not in by_cid[ci]:
            by_cid[ci][r["node_id"]] = r
    cards = ""
    for ci, nodes in by_cid.items():
        nl = list(nodes.values())
        tas = [n["timing_advance"] for n in nl if n["timing_advance"]]
        rsrps = [n["rsrp"] for n in nl if n["rsrp"]]
        ta_dist = round(sum(tas)/len(tas)*78,0) if tas else "?"
        mean_rsrp = round(sum(rsrps)/len(rsrps),1) if rsrps else "?"
        tac = nl[0]["tac"]
        lat = nl[0]["latitude"]
        lon = nl[0]["longitude"]
        cards += f"""<div class="card"><div class="cid">CID {ci}</div>
<div class="row"><span>TAC</span><span>{tac}</span></div>
<div class="row"><span>TA Distance</span><span class="hi">{ta_dist}m</span></div>
<div class="row"><span>RSRP</span><span>{mean_rsrp} dBm</span></div>
<div class="row"><span>Nodes</span><span>{", ".join(nodes.keys())}</span></div>
<a class="maps" href="https://maps.google.com/?q={lat},{lon}" target="_blank">Open in Maps</a></div>"""
    ts = datetime.now(timezone.utc).strftime("%H:%M UTC")
    html = f"""<!DOCTYPE html><html><head><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Silent Trident</title><style>
body{{background:#0a0a0a;color:#00ff88;font-family:monospace;padding:12px;margin:0}}
h1{{font-size:1.1em;color:#00ffcc;margin:0 0 4px}}
.sub{{color:#555;font-size:0.75em;margin-bottom:14px}}
.card{{background:#111;border:1px solid #00ff8833;border-radius:8px;padding:12px;margin-bottom:10px}}
.cid{{color:#00ffcc;font-weight:bold;margin-bottom:6px}}
.row{{display:flex;justify-content:space-between;font-size:0.82em;padding:3px 0;border-bottom:1px solid #1a1a1a}}
.hi{{color:#ffcc00;font-weight:bold}}
.maps{{display:block;margin-top:8px;background:#00ff8818;color:#00ff88;text-align:center;padding:6px;border-radius:4px;text-decoration:none;font-size:0.8em}}
.refresh{{display:block;text-align:center;margin-top:14px;color:#333;font-size:0.75em;text-decoration:none}}
</style></head><body>
<h1>🔱 CASTNET Silent Trident</h1>
<div class="sub">Last {window}h — {ts} — {len(by_cid)} rogue CID(s)</div>
{cards if cards else '<div class="card">No detections in window.</div>'}
<a class="refresh" href="/trident">↻ Refresh</a>
</body></html>"""
    return html


# ── Main ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    if not API_KEY:
        print("[WARN] *** CASTNET_API_KEY not set — API is unauthenticated ***")
        print("[WARN] Set it with: export CASTNET_API_KEY=your-secret-key")
    else:
        print(f"[AUTH] API key configured ({len(API_KEY)} chars)")

    init_db()
    print("""
 ██████╗ █████╗ ███████╗████████╗███╗   ██╗███████╗████████╗
██╔════╝██╔══██╗██╔════╝╚══██╔══╝████╗  ██║██╔════╝╚══██╔══╝
██║     ███████║███████╗   ██║   ██╔██╗ ██║█████╗     ██║
██║     ██╔══██║╚════██║   ██║   ██║╚██╗██║██╔══╝     ██║
╚██████╗██║  ██║███████║   ██║   ██║ ╚████║███████╗   ██║
 ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═══╝╚══════╝   ╚═╝

  Castnet API v0.1.1 — Civilian IMSI Catcher Detection Network
  Because Stingrays are fish too. 🎣
  Known rogue CIDs loaded: {cids}
  Listening on 0.0.0.0:5000
""".format(cids=len(KNOWN_ROGUE_CIDS)))

    app.run(host="0.0.0.0", port=5000, debug=False)


