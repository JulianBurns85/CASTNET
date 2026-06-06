#!/usr/bin/env python3
"""
CASTNET Aggregation Server v1.0
Runs on Pi (raspberrypi, 192.168.1.239, Tailscale 100.68.146.48)
Receives passive RF observations from Android nodes, runs FleetSignatureDetector,
stores results, serves real-time map via WebSocket.

Install:
    pip3 install flask flask-socketio flask-cors pyyaml

Run:
    python3 castnet_server.py

Endpoints:
    POST /obs          — Android node posts observations JSON
    GET  /map          — Leaflet map HTML page
    GET  /api/contacts — Current classified contacts (JSON)
    GET  /api/history  — Detection history (JSON)
    WS   /socket.io    — Real-time push to map browser
"""

import json
import logging
import os
import sys
import threading
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify, render_template_string, request, send_from_directory
from flask_cors import CORS
from flask_socketio import SocketIO, emit

# Add parent dir to path for fleet detector imports
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from detectors.fleet_signature_detector import FleetSignatureDetector, ObservedSignal
    from detectors.bladerf_bridge import BladeRFBridge
    _HAS_DETECTOR = True
except ImportError:
    _HAS_DETECTOR = False
    print("[WARN] Fleet detector not found — running in passthrough mode")

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("castnet")

# ─── CONFIG ──────────────────────────────────────────────────────────
LIBRARY_DIR     = str(Path(__file__).parent.parent / "intelligence")
HOST            = "0.0.0.0"
PORT            = 5001
MAX_HISTORY     = 500   # max detections to keep in memory
CONTACT_TTL_S   = 300   # contacts expire after 5 min if not refreshed
HOME_LAT        = -38.1100
HOME_LON        = 145.2780
HOME_LABEL      = "74 Prendergast Ave"

app = Flask(__name__)
CORS(app)
app.config["SECRET_KEY"] = "castnet_overkill_au"
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# ─── STATE ───────────────────────────────────────────────────────────
detection_history = deque(maxlen=MAX_HISTORY)
active_contacts   = {}   # contact_id → contact dict
history_lock      = threading.Lock()

if _HAS_DETECTOR:
    detector = FleetSignatureDetector(LIBRARY_DIR)
    bridge   = BladeRFBridge()
    logger.info(f"Fleet detector ready: {len(detector.signatures)} base signatures")
else:
    detector = None
    bridge   = None


# ─── OBSERVATION PROCESSING ──────────────────────────────────────────

def process_observations(obs_list: list, node_id: str) -> list:
    """Run fleet detection on incoming observations, return classified contacts."""
    if not _HAS_DETECTOR or not obs_list:
        return []

    try:
        signals = bridge.from_manual(obs_list)
        if not signals:
            return []

        # Extract location from first obs that has it
        location = None
        for obs in obs_list:
            if obs.get("lat") and obs.get("lon"):
                location = (obs["lat"], obs["lon"])
                break

        results = detector.analyze(signals, location=location, min_confidence=0.45)

        contacts = []
        now = datetime.now(timezone.utc).isoformat()

        for r in results:
            contact = {
                "id":           f"{r.signature_id}_{node_id}",
                "signature_id": r.signature_id,
                "label":        r.label,
                "category":     r.category,
                "subcategory":  r.subcategory,
                "confidence":   r.confidence,
                "confidence_pct": f"{r.confidence:.0%}",
                "alert_level":  r.alert_level,
                "display_color": r.display_color,
                "map_icon":     r.map_icon,
                "lat":          r.location_lat or HOME_LAT,
                "lon":          r.location_lon or HOME_LON,
                "timestamp":    now,
                "node_id":      node_id,
                "matched":      [
                    m["spec"] if isinstance(m, dict) else str(m)
                    for m in r.matched_signals
                ],
                "missing":      r.missing_signals,
                "forensic_note": r.forensic_note or "",
                "requires_corroboration": r.requires_corroboration,
                "remote_id":    None,
                "expires_at":   time.time() + CONTACT_TTL_S,
            }
            if r.remote_id:
                contact["remote_id"] = {
                    "serial":   r.remote_id.serial_number,
                    "operator": r.remote_id.operator_registration,
                    "lat":      r.remote_id.gps_latitude,
                    "lon":      r.remote_id.gps_longitude,
                    "alt_m":    r.remote_id.altitude_m_agl,
                }
            contacts.append(contact)

        return contacts

    except Exception as e:
        logger.error(f"Detection error: {e}")
        return []


def expire_contacts():
    """Background thread — removes stale contacts and pushes updates."""
    while True:
        time.sleep(15)
        now = time.time()
        expired = []
        with history_lock:
            for cid, contact in list(active_contacts.items()):
                if contact.get("expires_at", 0) < now:
                    expired.append(cid)
            for cid in expired:
                del active_contacts[cid]
        if expired:
            logger.info(f"Expired {len(expired)} stale contact(s)")
            socketio.emit("contacts_update", get_contacts_payload())


threading.Thread(target=expire_contacts, daemon=True).start()


def get_contacts_payload():
    with history_lock:
        return {
            "contacts":      list(active_contacts.values()),
            "count":         len(active_contacts),
            "elevated":      sum(
                1 for c in active_contacts.values()
                if c["alert_level"] in ("warning", "high", "flag")
            ),
            "timestamp":     datetime.now(timezone.utc).isoformat(),
        }


# ─── API ENDPOINTS ────────────────────────────────────────────────────

@app.route("/obs", methods=["POST"])
def receive_observations():
    """Android node POSTs observations here."""
    try:
        data = request.get_json(force=True)
        if not data:
            return jsonify({"error": "no data"}), 400

        node_id  = data.get("node_id", "unknown")
        obs_list = data.get("observations", data if isinstance(data, list) else [])

        logger.info(f"[{node_id}] {len(obs_list)} observation(s) received")

        contacts = process_observations(obs_list, node_id)

        with history_lock:
            for contact in contacts:
                active_contacts[contact["id"]] = contact
                detection_history.append(contact)

        if contacts:
            elevated = [c for c in contacts if c["alert_level"] in ("warning", "high", "flag")]
            if elevated:
                logger.warning(f"[{node_id}] ELEVATED: {[c['label'] for c in elevated]}")
            socketio.emit("contacts_update", get_contacts_payload())
            socketio.emit("new_detections", {"contacts": contacts, "node": node_id})

        return jsonify({
            "status":   "ok",
            "received": len(obs_list),
            "detected": len(contacts),
        })

    except Exception as e:
        logger.error(f"POST /obs error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/contacts")
def api_contacts():
    return jsonify(get_contacts_payload())


@app.route("/api/history")
def api_history():
    with history_lock:
        return jsonify({
            "history": list(detection_history),
            "count":   len(detection_history),
        })


@app.route("/api/status")
def api_status():
    return jsonify({
        "server":      "CASTNET v1.0",
        "node":        "raspberrypi / overkill",
        "detector":    _HAS_DETECTOR,
        "signatures":  len(detector.signatures) if detector else 0,
        "composites":  len(detector.composite_signatures) if detector else 0,
        "contacts":    len(active_contacts),
        "history":     len(detection_history),
        "uptime":      time.time(),
        "home":        {"lat": HOME_LAT, "lon": HOME_LON, "label": HOME_LABEL},
    })


@app.route("/map")
@app.route("/")
def serve_map():
    return render_template_string(MAP_HTML,
                                  home_lat=HOME_LAT,
                                  home_lon=HOME_LON,
                                  home_label=HOME_LABEL)


@socketio.on("connect")
def on_connect():
    logger.info(f"Map client connected: {request.sid}")
    emit("contacts_update", get_contacts_payload())
    emit("status", api_status().get_json())


# ─── MAP HTML ─────────────────────────────────────────────────────────
MAP_HTML = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1">
<title>CASTNET — Live RF Contact Map</title>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<script src="https://cdn.socket.io/4.7.2/socket.io.min.js"></script>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
       background: #0d0d0d; color: #e0e0e0; height: 100vh; display: flex; flex-direction: column; }

#header { background: #111; border-bottom: 1px solid #222; padding: 10px 14px;
          display: flex; align-items: center; gap: 12px; flex-shrink: 0; }
#header h1 { font-size: 14px; font-weight: 600; letter-spacing: 0.05em; color: #4ade80; }
#status-dot { width: 8px; height: 8px; border-radius: 50%; background: #4ade80;
              box-shadow: 0 0 6px #4ade80; flex-shrink: 0; }
#status-dot.offline { background: #ef4444; box-shadow: 0 0 6px #ef4444; }
#counts { margin-left: auto; display: flex; gap: 16px; font-size: 12px; color: #888; }
#counts span { display: flex; align-items: center; gap: 5px; }
#counts .val { color: #e0e0e0; font-weight: 600; }
#counts .alert-val { color: #f59e0b; }

#map { flex: 1; }

#panel { position: fixed; bottom: 0; left: 0; right: 0; max-height: 45vh;
         background: #111; border-top: 1px solid #222; overflow-y: auto;
         transform: translateY(calc(100% - 44px)); transition: transform 0.3s ease;
         z-index: 1000; }
#panel.open { transform: translateY(0); }
#panel-tab { padding: 12px 16px; font-size: 13px; font-weight: 600; cursor: pointer;
             display: flex; align-items: center; justify-content: space-between;
             border-bottom: 1px solid #1e1e1e; }
#panel-tab span { color: #888; font-size: 11px; }
#contact-list { padding: 8px; }

.contact-card { background: #1a1a1a; border: 1px solid #2a2a2a; border-radius: 8px;
                padding: 10px 12px; margin-bottom: 8px; cursor: pointer; }
.contact-card:hover { border-color: #3a3a3a; }
.contact-card.elevated { border-left: 3px solid #f59e0b; }
.contact-card.warning  { border-left: 3px solid #ef4444; }
.contact-header { display: flex; align-items: center; justify-content: space-between; }
.contact-label { font-size: 13px; font-weight: 600; }
.contact-conf  { font-size: 11px; color: #888; }
.contact-meta  { font-size: 11px; color: #666; margin-top: 4px; }
.badge { display: inline-block; font-size: 10px; padding: 2px 6px; border-radius: 10px;
         font-weight: 600; margin-right: 4px; }
.badge-info    { background: #1e3a5f; color: #60a5fa; }
.badge-flag    { background: #3d2800; color: #f59e0b; }
.badge-warning { background: #3d0000; color: #f87171; }
.badge-high    { background: #3d0000; color: #ef4444; }

.forensic-note { font-size: 10px; color: #f59e0b; margin-top: 6px;
                  background: #1a1400; padding: 4px 6px; border-radius: 4px; }

#toast { position: fixed; top: 60px; right: 12px; z-index: 2000;
         background: #1a2a1a; border: 1px solid #4ade80; border-radius: 8px;
         padding: 10px 14px; font-size: 12px; max-width: 240px;
         transform: translateX(260px); transition: transform 0.3s; }
#toast.show { transform: translateX(0); }
#toast.alert-toast { background: #2a1a00; border-color: #f59e0b; }

.leaflet-popup-content-wrapper { background: #111; border: 1px solid #333;
                                   color: #e0e0e0; border-radius: 8px; }
.leaflet-popup-tip { background: #111; }
</style>
</head>
<body>

<div id="header">
  <div id="status-dot" class="offline"></div>
  <h1>CASTNET — Live RF Contacts</h1>
  <div id="counts">
    <span>Contacts <b class="val" id="cnt-contacts">0</b></span>
    <span>Elevated <b class="alert-val" id="cnt-elevated">0</b></span>
  </div>
</div>

<div id="map"></div>

<div id="panel">
  <div id="panel-tab" onclick="togglePanel()">
    <span>RF CONTACT LIST</span>
    <span id="panel-count">0 contacts</span>
  </div>
  <div id="contact-list"></div>
</div>

<div id="toast"></div>

<script>
const HOME_LAT = {{ home_lat }};
const HOME_LON = {{ home_lon }};
const HOME_LABEL = "{{ home_label }}";

const map = L.map("map", { zoomControl: true }).setView([HOME_LAT, HOME_LON], 16);

L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
  attribution: "© OSM",
  className: "map-tiles"
}).addTo(map);

// Dark tile overlay
const style = document.createElement("style");
style.textContent = ".map-tiles { filter: invert(1) hue-rotate(180deg) brightness(0.85) saturate(0.7); }";
document.head.appendChild(style);

// Home marker
L.marker([HOME_LAT, HOME_LON], {
  icon: L.divIcon({
    className: "",
    html: '<div style="width:14px;height:14px;background:#4ade80;border-radius:50%;border:2px solid #fff;box-shadow:0 0 8px #4ade80"></div>',
    iconSize: [14, 14], iconAnchor: [7, 7]
  })
}).addTo(map).bindPopup(`<b>${HOME_LABEL}</b><br>Subject address`);

const markers = {};
const COLORS = {
  info:    "#60a5fa",
  flag:    "#f59e0b",
  warning: "#f87171",
  high:    "#ef4444",
};

function getMarkerHtml(contact) {
  const color = COLORS[contact.alert_level] || "#888";
  const size = contact.alert_level === "warning" || contact.alert_level === "high" ? 16 : 12;
  return `<div style="width:${size}px;height:${size}px;background:${color};border-radius:50%;
    border:2px solid rgba(255,255,255,0.4);
    box-shadow:0 0 ${size/2}px ${color}80;
    animation:${contact.alert_level === 'warning' || contact.alert_level === 'high' ? 'pulse 1.5s infinite' : 'none'}
  "></div>`;
}

function popupHtml(c) {
  const badge = `<span class="badge badge-${c.alert_level}">${c.alert_level.toUpperCase()}</span>`;
  const rid = c.remote_id ? `<br><small>Remote ID: ${c.remote_id.serial} / Op: ${c.remote_id.operator}</small>` : "";
  const fn = c.forensic_note ? `<div class="forensic-note">FORENSIC: ${c.forensic_note.substring(0,80)}...</div>` : "";
  return `<b>${c.label}</b><br>${badge} ${c.confidence_pct}<br>
    <small>${c.category} / ${c.subcategory}</small><br>
    <small>Matched: ${c.matched.join(", ")}</small>
    ${c.missing.length ? `<br><small style="color:#888">Missing: ${c.missing.join(", ")}</small>` : ""}
    ${rid}${fn}
    <br><small style="color:#555">${c.node_id} · ${c.timestamp.substring(11,19)}Z</small>`;
}

function updateMarkers(contacts) {
  const seen = new Set();
  contacts.forEach(c => {
    seen.add(c.id);
    if (markers[c.id]) {
      markers[c.id].setLatLng([c.lat, c.lon]);
      markers[c.id].setPopupContent(popupHtml(c));
    } else {
      const m = L.marker([c.lat, c.lon], {
        icon: L.divIcon({
          className: "",
          html: getMarkerHtml(c),
          iconSize: [16, 16], iconAnchor: [8, 8]
        })
      }).addTo(map).bindPopup(popupHtml(c));
      markers[c.id] = m;
    }
  });
  Object.keys(markers).forEach(id => {
    if (!seen.has(id)) { markers[id].remove(); delete markers[id]; }
  });
}

function updatePanel(contacts) {
  const list = document.getElementById("contact-list");
  document.getElementById("panel-count").textContent = `${contacts.length} contacts`;
  if (contacts.length === 0) {
    list.innerHTML = '<div style="padding:16px;color:#555;text-align:center;font-size:13px">No contacts detected</div>';
    return;
  }
  list.innerHTML = contacts
    .sort((a,b) => b.confidence - a.confidence)
    .map(c => `
      <div class="contact-card ${c.alert_level === 'warning' || c.alert_level === 'high' ? 'warning' : c.alert_level === 'flag' ? 'elevated' : ''}"
           onclick="map.setView([${c.lat},${c.lon}],17);markers['${c.id}']&&markers['${c.id}'].openPopup()">
        <div class="contact-header">
          <span class="contact-label">${c.label}</span>
          <span class="contact-conf">${c.confidence_pct}</span>
        </div>
        <div class="contact-meta">
          <span class="badge badge-${c.alert_level}">${c.alert_level.toUpperCase()}</span>
          ${c.category} · ${c.node_id}
          ${c.matched.length ? '· ' + c.matched.slice(0,3).join(', ') : ''}
        </div>
        ${c.forensic_note ? `<div class="forensic-note">${c.forensic_note.substring(0,90)}</div>` : ''}
      </div>`
    ).join("");
}

let panelOpen = false;
function togglePanel() {
  panelOpen = !panelOpen;
  document.getElementById("panel").classList.toggle("open", panelOpen);
}

let toastTimer;
function showToast(msg, isAlert) {
  const t = document.getElementById("toast");
  t.textContent = msg;
  t.className = "show" + (isAlert ? " alert-toast" : "");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.className = ""; }, 4000);
}

const socket = io();

socket.on("connect", () => {
  document.getElementById("status-dot").className = "";
  showToast("Connected to CASTNET server");
});

socket.on("disconnect", () => {
  document.getElementById("status-dot").className = "offline";
  showToast("Disconnected from server", true);
});

socket.on("contacts_update", data => {
  document.getElementById("cnt-contacts").textContent = data.count;
  document.getElementById("cnt-elevated").textContent = data.elevated;
  updateMarkers(data.contacts);
  updatePanel(data.contacts);
});

socket.on("new_detections", data => {
  const elevated = data.contacts.filter(c =>
    c.alert_level === "warning" || c.alert_level === "high"
  );
  if (elevated.length > 0) {
    showToast(`ALERT: ${elevated[0].label} (${elevated[0].confidence_pct})`, true);
    if (panelOpen === false) togglePanel();
  } else if (data.contacts.length > 0) {
    showToast(`${data.node}: ${data.contacts[0].label} detected`);
  }
});

// Add pulse animation
const pulse = document.createElement("style");
pulse.textContent = `@keyframes pulse {
  0%,100%{opacity:1;transform:scale(1)}
  50%{opacity:0.7;transform:scale(1.3)}
}`;
document.head.appendChild(pulse);
</script>
</body>
</html>"""


if __name__ == "__main__":
    logger.info("=" * 50)
    logger.info("CASTNET Aggregation Server v1.0")
    logger.info(f"Listening: http://{HOST}:{PORT}")
    logger.info(f"Map:       http://192.168.1.239:{PORT}/map")
    logger.info(f"Tailscale: http://100.68.146.48:{PORT}/map")
    logger.info("=" * 50)
    socketio.run(app, host=HOST, port=PORT, debug=False, allow_unsafe_werkzeug=True)
