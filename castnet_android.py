#!/usr/bin/env python3
"""
CASTNET Android Node — Termux BLE/WiFi Scanner v1.0
Runs on your Android phone via Termux.
Passively scans for BLE advertisements and WiFi beacons,
converts to ObservedSignal format, posts to Pi aggregation server.

INSTALL ON ANDROID (Termux):
    pkg update && pkg upgrade
    pkg install python termux-api
    pip install requests

PERMISSIONS NEEDED (allow in Android settings):
    Termux:API → Location (precise)
    Termux:API → Bluetooth scan
    Termux:API → Nearby WiFi networks

RUN:
    python castnet_android.py

    # Or with custom server:
    python castnet_android.py --server http://100.68.146.48:5001
    python castnet_android.py --server http://192.168.1.239:5001

The script uses termux-api commands:
    termux-bluetooth-scanmode    — enables BLE scanning
    termux-bluetooth-devices     — lists nearby BLE devices
    termux-wifi-scaninfo          — lists nearby WiFi APs
    termux-location              — gets GPS coordinates
"""

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone

try:
    import requests
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False
    print("[ERROR] requests not installed. Run: pip install requests")
    sys.exit(1)

# ─── CONFIG ──────────────────────────────────────────────────────────
DEFAULT_SERVER  = "http://192.168.1.239:5001"   # Pi local IP
TAILSCALE_SERVER = "http://100.68.146.48:5001"  # Pi Tailscale IP
NODE_ID         = "android_julian"               # change per device
SCAN_INTERVAL_S = 10    # seconds between scans
POST_TIMEOUT_S  = 5
LOCATION_INTERVAL = 6   # update GPS every N scans

# ─── KNOWN BLE MANUFACTURER IDS ──────────────────────────────────────
# Used to enrich observations before sending
MANUFACTURER_MAP = {
    "004c": "0x004C",   # Apple (AirTag, iBeacon)
    "00d7": "0x00D7",   # Tile
    "0075": "0x0075",   # Samsung SmartTag
    "2c05": "0x2C05",   # DJI
    "e000": "0xE000",   # Estimote
}

REMOTE_ID_UUIDS = {
    "0000fffa-0000-1000-8000-00805f9b34fb",  # ASTM F3411 Remote ID
    "0000fff9-0000-1000-8000-00805f9b34fb",  # Alternative Remote ID
}


def run_termux(cmd: list, timeout: int = 8) -> dict | list | None:
    """Run a termux-api command and return parsed JSON output."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        if result.stdout.strip():
            return json.loads(result.stdout)
        return None
    except subprocess.TimeoutExpired:
        print(f"[TIMEOUT] {cmd[0]}")
        return None
    except json.JSONDecodeError:
        return None
    except Exception as e:
        print(f"[ERR] {cmd[0]}: {e}")
        return None


def get_location() -> dict | None:
    """Get GPS coordinates via termux-location."""
    result = run_termux(["termux-location", "-p", "gps", "-r", "once"], timeout=15)
    if result and "latitude" in result:
        return {
            "lat": result["latitude"],
            "lon": result["longitude"],
            "accuracy_m": result.get("accuracy", 0),
        }
    # Fallback to network location
    result = run_termux(["termux-location", "-p", "network", "-r", "once"], timeout=10)
    if result and "latitude" in result:
        return {
            "lat": result["latitude"],
            "lon": result["longitude"],
            "accuracy_m": result.get("accuracy", 99),
        }
    return None


def scan_ble() -> list:
    """Scan for BLE devices using termux-bluetooth-devices."""
    devices = run_termux(["termux-bluetooth-devices"], timeout=8)
    if not devices:
        return []

    observations = []
    now = datetime.now(timezone.utc).isoformat()

    for dev in (devices if isinstance(devices, list) else []):
        name = dev.get("name", "") or ""
        mac  = dev.get("address", "") or ""
        rssi = dev.get("rssi", -100)

        obs = {
            "type":                    "ble",
            "mac":                     mac,
            "rsrp_dbm":                rssi,
            "ts":                      now,
        }

        # Enrich from name heuristics
        name_lower = name.lower()

        if "airtag" in name_lower or (mac and mac.startswith("1C:")):
            obs["manufacturer_id"] = "0x004C"
            obs["payload_type"]    = "apple_nearby_action"

        # Check UUIDs if available
        uuids = dev.get("uuids", []) or []
        for uuid in uuids:
            if uuid.lower() in REMOTE_ID_UUIDS:
                obs["payload_type"] = "astm_f3411_22a"
                break

        # Manufacturer data prefix → ID
        mfr_data = dev.get("manufacturerSpecificData", {}) or {}
        for mfr_id_str in mfr_data:
            key = mfr_id_str.lower().replace("0x", "").zfill(4)
            if key in MANUFACTURER_MAP:
                obs["manufacturer_id"] = MANUFACTURER_MAP[key]

        # Advertisement interval heuristic from scan record
        adv_ms = dev.get("advertisingInterval", None)
        if adv_ms:
            obs["advertisement_interval_ms"] = adv_ms

        observations.append(obs)

    return observations


def scan_wifi() -> list:
    """Scan for WiFi APs using termux-wifi-scaninfo."""
    networks = run_termux(["termux-wifi-scaninfo"], timeout=8)
    if not networks:
        return []

    observations = []
    now = datetime.now(timezone.utc).isoformat()

    for net in (networks if isinstance(networks, list) else []):
        ssid     = net.get("ssid", "") or ""
        bssid    = net.get("bssid", "") or ""
        freq_mhz = (net.get("frequency", 0) or 0) / 1e6 if net.get("frequency", 0) > 1000 else net.get("frequency", 2400)
        rssi     = net.get("level", -100)

        # Determine signal type from frequency
        if 2400 <= freq_mhz <= 2484:
            sig_type = "wifi"
        elif 5150 <= freq_mhz <= 5875:
            # Check for OcuSync-style patterns
            sig_type = "ocusync3" if any(
                x in ssid.lower() for x in ["dji", "mavic", "phantom", "mini", "fpv"]
            ) else "wifi"
        else:
            sig_type = "wifi"

        obs = {
            "type":      sig_type,
            "freq_mhz":  freq_mhz,
            "ssid":      ssid if ssid else None,
            "mac":       bssid,
            "rsrp_dbm":  rssi,
            "ts":        now,
        }

        # Detect Remote ID WiFi NaN broadcasts (specific OUI patterns)
        if bssid.upper().startswith(("FA:8F:", "FA:8E:", "16:AB:")):
            obs["payload_type"] = "astm_f3411_22a"
            obs["type"]         = "wifi"

        observations.append(obs)

    return observations


def scan_cellular() -> list:
    """Get cellular network info from termux-telephony-cellinfo."""
    cells = run_termux(["termux-telephony-cellinfo"], timeout=8)
    if not cells:
        return []

    observations = []
    now = datetime.now(timezone.utc).isoformat()

    for cell in (cells if isinstance(cells, list) else []):
        cell_type = cell.get("type", "").lower()

        if "lte" in cell_type:
            band = cell.get("earfcn", 0)
            carrier = "telstra"  # default — refine from MNC if available
            mnc = str(cell.get("mnc", ""))
            if mnc == "1":   carrier = "telstra"
            elif mnc == "3": carrier = "vodafone"
            elif mnc == "2": carrier = "optus"

            # Detect LTE-M heuristic: very low signal + serving cell
            rsrp = cell.get("rsrp", -85)
            sig_type = "lte_m" if rsrp < -105 else "lte"

            observations.append({
                "type":     sig_type,
                "carrier":  carrier,
                "band":     "B28" if 9210 <= band <= 9659 else f"EARFCN_{band}",
                "rsrp_dbm": rsrp,
                "ts":       now,
            })

        elif "nr" in cell_type or "5g" in cell_type:
            observations.append({
                "type":    "lte",
                "carrier": "telstra",
                "band":    "5G_NR",
                "ts":      now,
            })

    return observations


def post_observations(server: str, observations: list, location: dict | None):
    """POST observations to CASTNET aggregation server."""
    if not observations:
        return

    # Attach location to all observations
    if location:
        for obs in observations:
            obs["lat"] = location["lat"]
            obs["lon"] = location["lon"]

    payload = {
        "node_id":      NODE_ID,
        "observations": observations,
    }

    try:
        resp = requests.post(
            f"{server}/obs",
            json=payload,
            timeout=POST_TIMEOUT_S,
            headers={"Content-Type": "application/json"}
        )
        data = resp.json()
        detected = data.get("detected", 0)
        if detected > 0:
            print(f"  [SERVER] {detected} contact(s) detected!")
        return detected
    except requests.ConnectionError:
        print(f"  [ERR] Cannot reach server: {server}")
        return 0
    except Exception as e:
        print(f"  [ERR] POST failed: {e}")
        return 0


def check_server(server: str) -> bool:
    """Check if CASTNET server is reachable."""
    try:
        resp = requests.get(f"{server}/api/status", timeout=3)
        data = resp.json()
        print(f"[OK] Server: {data.get('server')} | "
              f"Signatures: {data.get('signatures')} | "
              f"Contacts: {data.get('contacts')}")
        return True
    except Exception:
        return False


def main():
    ap = argparse.ArgumentParser(description="CASTNET Android Node")
    ap.add_argument("--server", default=DEFAULT_SERVER,
                    help=f"CASTNET server URL (default: {DEFAULT_SERVER})")
    ap.add_argument("--interval", type=int, default=SCAN_INTERVAL_S,
                    help=f"Scan interval seconds (default: {SCAN_INTERVAL_S})")
    ap.add_argument("--node-id", default=NODE_ID,
                    help=f"Node identifier (default: {NODE_ID})")
    ap.add_argument("--tailscale", action="store_true",
                    help="Use Tailscale server address")
    ap.add_argument("--no-cellular", action="store_true",
                    help="Skip cellular scanning")
    args = ap.parse_args()

    server = TAILSCALE_SERVER if args.tailscale else args.server
    global NODE_ID
    NODE_ID = args.node_id

    print("=" * 50)
    print("CASTNET Android Node v1.0")
    print(f"Node:     {NODE_ID}")
    print(f"Server:   {server}")
    print(f"Interval: {args.interval}s")
    print("=" * 50)

    # Check server reachability
    print("\nConnecting to server...")
    for attempt in range(3):
        if check_server(server):
            break
        print(f"  Retry {attempt+1}/3...")
        time.sleep(2)
    else:
        print(f"[WARN] Server unreachable. Will keep trying during scan loop.")

    location = None
    scan_count = 0

    print("\nStarting passive scan loop. Press Ctrl+C to stop.\n")

    while True:
        try:
            scan_count += 1
            ts = datetime.now().strftime("%H:%M:%S")
            print(f"[{ts}] Scan #{scan_count}")

            # Update location periodically
            if scan_count % LOCATION_INTERVAL == 1:
                print("  Getting GPS location...")
                location = get_location()
                if location:
                    print(f"  Location: {location['lat']:.4f}, {location['lon']:.4f} "
                          f"(±{location['accuracy_m']:.0f}m)")

            # BLE scan
            print("  BLE scan...")
            ble_obs = scan_ble()
            print(f"    {len(ble_obs)} BLE device(s)")

            # WiFi scan
            print("  WiFi scan...")
            wifi_obs = scan_wifi()
            print(f"    {len(wifi_obs)} WiFi AP(s)")

            # Cellular
            cell_obs = []
            if not args.no_cellular:
                cell_obs = scan_cellular()
                if cell_obs:
                    print(f"  Cellular: {len(cell_obs)} cell(s)")

            all_obs = ble_obs + wifi_obs + cell_obs

            if all_obs:
                print(f"  Posting {len(all_obs)} observations...")
                detected = post_observations(server, all_obs, location)
            else:
                print("  No signals detected this scan")

            print()
            time.sleep(args.interval)

        except KeyboardInterrupt:
            print("\n[STOP] Scan loop stopped.")
            break
        except Exception as e:
            print(f"[ERR] Scan loop error: {e}")
            time.sleep(args.interval)


if __name__ == "__main__":
    main()
