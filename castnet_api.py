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
