#!/usr/bin/env python3
"""
castnet_communal_api.py - CASTNET Communal Aggregation Server v0.1
Multi-operator community IMSI catcher detection network.
Because Stingrays are fish too. 🎣
"""

import hashlib, json, os, secrets, sqlite3
from datetime import datetime, timezone, timedelta
from pathlib import Path
from functools import wraps
from flask import Flask, request, jsonify, g

app = Flask(__name__)

DB_PATH        = Path(os.environ.get("CASTNET_DB", str(Path.home() / "castnet_communal.db")))
ADMIN_KEY      = os.environ.get("CASTNET_ADMIN_KEY", "")
PORT           = int(os.environ.get("CASTNET_PORT", "5001"))
CONSENSUS_THRESHOLD = 3

SEED_ROGUE_CIDS = [
    {"ci": 137713195, "tac": 12385, "mcc": 505, "mnc": 1, "confidence": "CONFIRMED", "notes": "Highest observation count. Cranbourne East 2026."},
    {"ci": 137713175, "tac": 12385, "mcc": 505, "mnc": 1, "confidence": "CONFIRMED", "notes": "Geo-located Prendergast Ave ~331m."},
    {"ci": 137713165, "tac": 12385, "mcc": 505, "mnc": 1, "confidence": "CONFIRMED", "notes": "Confirmed. Followed mobile node ~2km westward."},
    {"ci": 137713155, "tac": 12385, "mcc": 505, "mnc": 1, "confidence": "CONFIRMED", "notes": "Rotating identity pattern confirmed."},
    {"ci": 135836191, "tac": 12385, "mcc": 505, "mnc": 1, "confidence": "CONFIRMED", "notes": "Geo-located Collison Rd ~912m."},
    {"ci": 135836171, "tac": 12385, "mcc": 505, "mnc": 1, "confidence": "CONFIRMED", "notes": "Geo-located Casey Fields ~2424m."},
    {"ci": 135836161, "tac": 12385, "mcc": 505, "mnc": 1, "confidence": "CONFIRMED", "notes": "31 observations May 2026."},
    {"ci": 8409357,   "tac": 30336, "mcc": 505, "mnc": 3, "confidence": "CONFIRMED", "notes": ""},
    {"ci": 8409367,   "tac": 30336, "mcc": 505, "mnc": 3, "confidence": "CONFIRMED", "notes": ""},
    {"ci": 8409387,   "tac": 30336, "mcc": 505, "mnc": 3, "confidence": "CONFIRMED", "notes": ""},
    {"ci": 8409397,   "tac": 30336, "mcc": 505, "mnc": 3, "confidence": "CONFIRMED", "notes": "Anomalous rapid sub-2s departures."},
    {"ci": 8435470,   "tac": 30336, "mcc": 505, "mnc": 3, "confidence": "CONFIRMED", "notes": ""},
    {"ci": 8435480,   "tac": 30336, "mcc": 505, "mnc": 3, "confidence": "CONFIRMED", "notes": ""},
    {"ci": 8666381,   "tac": 30336, "mcc": 505, "mnc": 3, "confidence": "HIGH", "notes": "Appeared post-ACMA visit 8 May 2026. Zero OpenCelliD observations globally."},
    {"ci": 8666391,   "tac": 30336, "mcc": 505, "mnc": 3, "confidence": "HIGH", "notes": "Appeared post-ACMA visit 8 May 2026. Zero OpenCelliD observations globally."},
    {"ci": 8666411,   "tac": 30336, "mcc": 505, "mnc": 3, "confidence": "HIGH", "notes": "Appeared post-ACMA visit 8 May 2026. Zero OpenCelliD observations globally."},
]

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop("db", None)
    if db: db.close()

def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS operators (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            handle TEXT UNIQUE NOT NULL,
            region TEXT,
            key_hash TEXT UNIQUE NOT NULL,
            share_data INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now')),
            last_seen TEXT
        );
        CREATE TABLE IF NOT EXISTS detections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            operator_id INTEGER REFERENCES operators(id),
            node_id TEXT, timestamp TEXT,
            ci INTEGER, tac INTEGER, mcc INTEGER, mnc INTEGER,
            rsrp REAL, rssi REAL, timing_advance INTEGER,
            latitude REAL, longitude REAL, region TEXT,
            shared INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS community_cids (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ci INTEGER UNIQUE, tac INTEGER, mcc INTEGER, mnc INTEGER,
            confidence TEXT DEFAULT 'UNCONFIRMED',
            operator_count INTEGER DEFAULT 0,
            total_reports INTEGER DEFAULT 0,
            first_seen TEXT, last_seen TEXT, notes TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE INDEX IF NOT EXISTS idx_det_ci  ON detections(ci);
        CREATE INDEX IF NOT EXISTS idx_det_op  ON detections(operator_id);
        CREATE INDEX IF NOT EXISTS idx_det_ts  ON detections(timestamp);
        CREATE INDEX IF NOT EXISTS idx_cid_ci  ON community_cids(ci);
    """)
    for cid in SEED_ROGUE_CIDS:
        conn.execute("""
            INSERT OR IGNORE INTO community_cids
            (ci,tac,mcc,mnc,confidence,operator_count,total_reports,first_seen,last_seen,notes)
            VALUES (?,?,?,?,?,1,1,datetime('now'),datetime('now'),?)
        """, (cid["ci"],cid["tac"],cid["mcc"],cid["mnc"],cid["confidence"],cid.get("notes","")))
    conn.commit()
    conn.close()
    print(f"[DB] Initialised at {DB_PATH} — {len(SEED_ROGUE_CIDS)} CIDs seeded")

def hash_key(key): return hashlib.sha256(key.encode()).hexdigest()

def require_operator(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get("X-Castnet-Key","")
        if not key: return jsonify({"error":"Missing X-Castnet-Key"}),401
        db = get_db()
        op = db.execute("SELECT * FROM operators WHERE key_hash=?",(hash_key(key),)).fetchone()
        if not op: return jsonify({"error":"Invalid API key"}),401
        db.execute("UPDATE operators SET last_seen=? WHERE id=?",(datetime.now(timezone.utc).isoformat(),op["id"]))
        db.commit()
        g.operator = op
        return f(*args,**kwargs)
    return decorated

def require_admin(f):
    @wraps(f)
    def decorated(*args,**kwargs):
        key = request.headers.get("X-Castnet-Admin","")
        if not ADMIN_KEY or key!=ADMIN_KEY: return jsonify({"error":"Admin key required"}),403
        return f(*args,**kwargs)
    return decorated

@app.route("/admin/operators/register",methods=["POST"])
@require_admin
def register_operator():
    data   = request.json or {}
    handle = data.get("handle","").strip()
    region = data.get("region","").strip()
    if not handle: return jsonify({"error":"handle required"}),400
    api_key  = f"CASTNET-{secrets.token_hex(16)}"
    key_hash = hash_key(api_key)
    try:
        get_db().execute("INSERT INTO operators (handle,region,key_hash) VALUES (?,?,?)",(handle,region,key_hash))
        get_db().commit()
    except sqlite3.IntegrityError:
        return jsonify({"error":f"Handle '{handle}' already exists"}),409
    return jsonify({"status":"registered","handle":handle,"region":region,"api_key":api_key,"warning":"Store this key securely"})

@app.route("/admin/operators",methods=["GET"])
@require_admin
def list_operators():
    ops = get_db().execute("SELECT id,handle,region,share_data,created_at,last_seen FROM operators").fetchall()
    return jsonify([dict(o) for o in ops])

@app.route("/api/v1/report",methods=["POST"])
@require_operator
def report_detection():
    data = request.json
    if not data: return jsonify({"error":"JSON body required"}),400
    ci = data.get("ci")
    if not ci: return jsonify({"error":"ci required"}),400
    op     = g.operator
    shared = 1 if op["share_data"] else 0
    ts     = data.get("timestamp",datetime.now(timezone.utc).isoformat())
    db     = get_db()
    db.execute("""
        INSERT INTO detections
        (operator_id,node_id,timestamp,ci,tac,mcc,mnc,rsrp,rssi,timing_advance,latitude,longitude,region,shared)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """,(op["id"],data.get("node_id"),ts,int(ci),data.get("tac"),data.get("mcc"),data.get("mnc"),
          data.get("rsrp"),data.get("rssi"),data.get("timing_advance"),data.get("latitude"),data.get("longitude"),op["region"] or "",shared))
    _update_community_cid(db,data,op["id"])
    db.commit()
    return jsonify({"status":"ok","shared":bool(shared)})

def _update_community_cid(db,data,operator_id):
    ci  = int(data.get("ci",0))
    now = datetime.now(timezone.utc).isoformat()
    existing = db.execute("SELECT * FROM community_cids WHERE ci=?",(ci,)).fetchone()
    if existing:
        op_count = db.execute("SELECT COUNT(DISTINCT operator_id) FROM detections WHERE ci=?",(ci,)).fetchone()[0]
        confidence = existing["confidence"]
        if op_count >= CONSENSUS_THRESHOLD and confidence=="UNCONFIRMED": confidence="COMMUNITY_CONFIRMED"
        elif op_count >= 2 and confidence=="UNCONFIRMED": confidence="WATCHLIST"
        db.execute("UPDATE community_cids SET total_reports=total_reports+1,operator_count=?,confidence=?,last_seen=? WHERE ci=?",(op_count,confidence,now,ci))
    else:
        db.execute("INSERT INTO community_cids (ci,tac,mcc,mnc,confidence,operator_count,total_reports,first_seen,last_seen) VALUES (?,?,?,?,'UNCONFIRMED',1,1,?,?)",
                   (ci,data.get("tac"),data.get("mcc"),data.get("mnc"),now,now))

@app.route("/community/cids",methods=["GET"])
def community_cids():
    order = {"UNCONFIRMED":0,"WATCHLIST":1,"HIGH":2,"CONFIRMED":3,"COMMUNITY_CONFIRMED":4}
    min_c = order.get(request.args.get("confidence","WATCHLIST"),1)
    cids  = get_db().execute("SELECT ci,tac,mcc,mnc,confidence,operator_count,total_reports,first_seen,last_seen,notes FROM community_cids ORDER BY total_reports DESC").fetchall()
    filtered = [dict(c) for c in cids if order.get(c["confidence"],0)>=min_c]
    return jsonify({"cids":filtered,"count":len(filtered)})

@app.route("/community/map",methods=["GET"])
def community_map():
    hours = int(request.args.get("hours",168))
    since = (datetime.now(timezone.utc)-timedelta(hours=hours)).isoformat()
    rows  = get_db().execute("""
        SELECT d.ci,d.tac,d.rsrp,d.latitude,d.longitude,d.region,d.timestamp,c.confidence,c.operator_count
        FROM detections d LEFT JOIN community_cids c ON d.ci=c.ci
        WHERE d.shared=1 AND d.latitude IS NOT NULL AND d.longitude IS NOT NULL AND d.timestamp>=?
        ORDER BY d.timestamp DESC LIMIT 2000
    """, (since,)).fetchall()
    features = [{"type":"Feature","geometry":{"type":"Point","coordinates":[r["longitude"],r["latitude"]]},"properties":dict(r)} for r in rows]
    return jsonify({"type":"FeatureCollection","features":features,"count":len(features)})

@app.route("/community/stats",methods=["GET"])
def community_stats():
    db  = get_db()
    now = datetime.now(timezone.utc)
    return jsonify({
        "operators":      db.execute("SELECT COUNT(*) FROM operators").fetchone()[0],
        "sharing":        db.execute("SELECT COUNT(*) FROM operators WHERE share_data=1").fetchone()[0],
        "total_shared":   db.execute("SELECT COUNT(*) FROM detections WHERE shared=1").fetchone()[0],
        "shared_24h":     db.execute("SELECT COUNT(*) FROM detections WHERE shared=1 AND timestamp>=?",(  (now-timedelta(hours=24)).isoformat(),)).fetchone()[0],
        "confirmed_cids": db.execute("SELECT COUNT(*) FROM community_cids WHERE confidence IN ('CONFIRMED','COMMUNITY_CONFIRMED','HIGH')").fetchone()[0],
        "generated_at":   now.isoformat(),
    })

@app.route("/my/detections",methods=["GET"])
@require_operator
def my_detections():
    hours = int(request.args.get("hours",24))
    since = (datetime.now(timezone.utc)-timedelta(hours=hours)).isoformat()
    rows  = get_db().execute("SELECT d.*,c.confidence FROM detections d LEFT JOIN community_cids c ON d.ci=c.ci WHERE d.operator_id=? AND d.timestamp>=? ORDER BY d.timestamp DESC LIMIT 1000",(g.operator["id"],since)).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/my/settings",methods=["POST"])
@require_operator
def update_settings():
    share = 1 if (request.json or {}).get("share_data") else 0
    get_db().execute("UPDATE operators SET share_data=? WHERE id=?",(share,g.operator["id"]))
    get_db().commit()
    return jsonify({"status":"updated","share_data":bool(share)})

@app.route("/health",methods=["GET"])
def health():
    return jsonify({"status":"ok","version":"0.1","name":"CASTNET Communal API","time":datetime.now(timezone.utc).isoformat()})

if __name__=="__main__":
    if not ADMIN_KEY:
        print("[WARN] CASTNET_ADMIN_KEY not set")
    init_db()
    print("  CASTNET Communal API v0.1 — Because Stingrays are fish too. 🎣")
    print(f"  Running on port {PORT}")
    app.run(host="0.0.0.0",port=PORT,debug=False)
