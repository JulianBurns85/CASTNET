# CASTNET 🎣
## Predator Hunter — v2.0

**Distributed Civilian IMSI Catcher Detection and Geolocation Network**

> Where Rayhunter Threat Analyzer is the forensic lab, CASTNET is the net.

Built as the live operational layer for an ongoing IMSI catcher investigation — Cranbourne East, Victoria, Australia, 2026.

![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue) ![License: MIT](https://img.shields.io/badge/license-MIT-green) ![Status: Live](https://img.shields.io/badge/status-live-brightgreen)

---

## What It Does

Every CASTNET node (a phone, tablet, or vehicle dongle) passively monitors cellular signals and reports confirmed rogue Cell ID detections — tagged with GPS coordinates, RSRP signal strength, and Timing Advance — to a central aggregation API running on a Raspberry Pi.

When three or more nodes detect the same rogue CID simultaneously, trilateration runs automatically and the attacker's physical location is estimated.

A live Leaflet.js map dashboard shows all detections, node status, and signal data in real time — served directly from the Pi via Flask at `/dashboard`.

---

## Live Dashboard

![map](map)

Access via: `http://<pi-lan-ip>:5000/dashboard`

---

## Architecture

```
castnet_node.py / castnet_android.py   (phone / tablet / OBD-II dongle)
       |
       | POST /api/v1/report  (via Tailscale WireGuard — encrypted)
       v
castnet_api.py           (Raspberry Pi — Flask + SQLite)
       |
       |── GET /api/v1/summary      → live stats
       |── GET /api/v1/detections   → detection feed
       |── GET /api/v1/map          → GeoJSON for Leaflet
       |── GET /dashboard           → serves live map HTML
       v
castnet_map.html         (Leaflet.js live map dashboard — browser)
```

---

## Components

| Component | Location | Description |
|---|---|---|
| Field node (Linux) | `castnet_node.py` | Runs on Linux or Android (Termux). No root required. |
| Field node (Android) | `castnet_android.py` | Native Android node via Termux. GPS + cellular scanning. |
| Central API | `castnet_api.py` | Flask REST API + SQLite. Runs on Raspberry Pi 24/7 via systemd. Serves dashboard at `/dashboard`. |
| Map dashboard | `dashboard/castnet_map.html` | Green-on-black Leaflet.js live map. Auto-refreshes every 30s. |
| Communal API | `castnet_communal_api.py` | Multi-operator aggregation server for community-wide detection. |
| Server | `castnet_server.py` | Extended server with additional reporting and aggregation logic. |
| Silent Trident | `castnet_silent_trident.py` | Passive trilateration engine — no active probing. |
| systemd service | `docs/castnet-api.service` | Auto-start and auto-restart on Pi boot. |

---

## Quick Start

### Central API (Raspberry Pi)

```bash
mkdir ~/castnet
cd ~/castnet
pip install flask --break-system-packages
python castnet_api.py
```

Auto-start on boot:

```bash
sudo cp docs/castnet-api.service /etc/systemd/system/
sudo systemctl enable castnet-api
sudo systemctl start castnet-api
```

### Field Node (Android Termux)

```bash
pkg install termux-api
pip install requests
python castnet_android.py
```

> **Termux requirements:** Install the Termux:API companion app from F-Droid (not Play Store). Grant Phone and Location permissions to Termux:API in Android Settings.

### Field Node (Linux)

```bash
pip install requests
python castnet_node.py
```

### Map Dashboard

Open in any browser on your local network:

```
http://<pi-lan-ip>:5000/dashboard
```

---

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/v1/report` | Receive detection from node |
| GET | `/api/v1/detections` | All detections (filterable by hours, rogue_only) |
| GET | `/api/v1/summary` | Live stats — nodes, detection counts, last hit |
| GET | `/api/v1/map` | GeoJSON for Leaflet map |
| GET | `/dashboard` | Serve live map dashboard (HTML) |

---

## Live Network — Cranbourne East Investigation

| Node | Device | Status |
|---|---|---|
| grapher | Pixel 9 Pro (GrapheneOS) | ✅ Live |
| ulefone_tab4_node1 | Ulefone Android tablet | ✅ Live |

**Confirmed rogue CIDs monitored (16 confirmed + 2 watchlist):**

```python
# Telstra AU (MCC=505 MNC=001 TAC=12385)
137713195,   # highest observation count
137713175,   # geo-located Prendergast Ave 331m
137713165,   # confirmed
137713155,   # confirmed
135836191,   # geo-located Collison Rd 912m
135836171,   # geo-located Casey Fields 2424m
135836161,   # added May 2026 — 31 observations

# Vodafone AU (MCC=505 MNC=003 TAC=30336)
8409357, 8409367, 8409387,
8409397,     # anomalous — rapid sub-2s departures

# Post-ACMA visit CIDs (appeared 8 May 2026 — zero OpenCelliD observations)
8666381, 8666391, 8666411
```

Full forensic analysis: [rayhunter-threat-analyzer](https://github.com/JulianBurns85/rayhunter-threat-analyzer)

---

## Roadmap

- [x] v0.1 — Field node + central API + Tailscale reporting
- [x] v0.1 — systemd auto-start on Pi boot
- [x] v0.1 — Leaflet.js live map dashboard
- [x] v0.1 — Two-node live network operational
- [x] v0.2 — Node heartbeat + offline buffering
- [x] v0.3 — Dual reporting to local + communal server simultaneously
- [x] v0.3 — GPS tagging on mobile nodes (live — Termux GPS)
- [x] v0.4 — Trilateration engine (3+ nodes + RSRP)
- [x] v0.5 — RSRP signal strength heat map overlay
- [x] v2.0 — Flask serves dashboard directly at `/dashboard` (LAN + Tailscale)
- [x] v2.0 — Android-native node (`castnet_android.py`)
- [x] v2.0 — Live detection feed with per-node stats and known rogue CID list
- [ ] v2.1 — CRIKEY! alert mode 🦅
- [ ] v3.0 — OBD-II vehicle node (Pi Zero 2W)
- [ ] v3.0 — Public communal rogue CID registry

---

## Hardware

**Central:** Raspberry Pi 5 (API + Pi-hole + Tailscale + ARIA)

**Nodes:** Android tablet + Pixel 9 Pro (GrapheneOS) via Termux

**Planned:** bladeRF 2.0 micro xA4 · MikroTik Chateau 5G R17 ax · Poynting XPOL-2-5G · Pi Zero 2W OBD-II node

---

## Related Projects

- [rayhunter-threat-analyzer](https://github.com/JulianBurns85/rayhunter-threat-analyzer) — the forensic lab
- [EFF Rayhunter](https://github.com/EFForg/rayhunter) — the IMSI catcher detector nodes complement
- [SeaGlass](https://seaglass.cs.washington.edu/) — UW distributed detection (inspiration)

---

## Want to Run a Node?

If you're in Australia and suspect IMSI catcher activity in your area, you can run `castnet_android.py` on any Android device with Termux — no root required, no special hardware beyond the phone you already have.

Your node will:
- Scan for rogue CIDs from the known database every 30 seconds
- Tag detections with GPS coordinates and signal strength
- Report to your own local API (self-hosted — your data stays yours)

See Contributing below, or open an issue if you want help getting set up.

---

## Legal

Passive monitoring only. No transmission. No network impersonation.

**Australia:** Radiocommunications Act 1992 (Cth) — passive reception of signals requires no licence.

**Regulatory actions on file:**
- ACMA ENQ-1851DVJH04
- TIO 2026-03-04898
- VicPol CIRS-20260331-141
- AFP LEX 4864

---

## Contributing

Pull requests welcome. If you're running your own CASTNET instance or have confirmed rogue CIDs to add to the registry, open an issue.

If you're a researcher, journalist, or regulator interested in the underlying investigation data, contact via GitHub or the regulatory references above.

---

## License

MIT — see [LICENSE](LICENSE)

---

*Built with a Raspberry Pi 5, two Android devices, a bladeRF SDR, too much coffee, and justifiable paranoia.*

*— Julian Burns, Cranbourne East VIC, 2026*

> *"Because Stingrays are fish too."* 🎣
