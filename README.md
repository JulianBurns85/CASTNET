# CASTNET 🎣

**Distributed Civilian IMSI Catcher Detection and Geolocation Network**

> Where [Rayhunter Threat Analyzer](https://github.com/JulianBurns85/rayhunter-threat-analyzer) is the forensic lab, Castnet is the net.

Built as the live operational layer for an ongoing IMSI catcher investigation — Cranbourne East, Victoria, Australia, 2026.

![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue) ![License: MIT](https://img.shields.io/badge/license-MIT-green) ![Status: Live](https://img.shields.io/badge/status-live-brightgreen)

---

## What It Does

Every Castnet **node** (a phone, tablet, or vehicle dongle) passively monitors cellular signals and reports confirmed rogue Cell ID detections — tagged with GPS coordinates, RSRP signal strength, and Timing Advance — to a central **aggregation API** running on a Raspberry Pi.

When three or more nodes detect the same rogue CID simultaneously, **trilateration runs automatically** and the attacker's physical location is estimated.

A live **Leaflet.js map dashboard** shows all detections, node status, and signal data in real time.

---

## Architecture

```
castnet_node.py          (phone / tablet / OBD-II dongle)
       |
       | POST /api/v1/report  (via Tailscale WireGuard — encrypted)
       v
castnet_api.py           (Raspberry Pi — Flask + SQLite)
       |
       | GET /map
       v
castnet_map.html         (Leaflet.js live map dashboard — browser)
```

---

## Components

| Component | Location | Description |
|---|---|---|
| Field node | `node/castnet_node.py` | Runs on Android (Termux) or Linux. No root required. |
| Central API | `api/castnet_api.py` | Flask REST API + SQLite. Runs on Raspberry Pi 24/7 via systemd. |
| Map dashboard | `dashboard/castnet_map.html` | Green-on-black Leaflet.js live map. Auto-refreshes every 30s. |
| systemd service | `docs/castnet-api.service` | Auto-start and auto-restart on Pi boot. |

---

## Quick Start

### Central API (Raspberry Pi)

```bash
mkdir ~/castnet
cd ~/castnet
pip install flask --break-system-packages
python castnet_api.py
# Listening on 0.0.0.0:5000
```

Auto-start on boot:

```bash
sudo cp docs/castnet-api.service /etc/systemd/system/
sudo systemctl enable castnet-api
sudo systemctl start castnet-api
```

### Field Node (Android Termux / Linux)

```bash
# Termux prerequisites
pkg install termux-api
pip install requests

# Edit castnet_node.py — set NODE_ID and CASTNET_API
python castnet_node.py
```

### Map Dashboard

Open in any browser on the same Tailscale network:

```
http://<pi-tailscale-ip>:5000/map
```

---

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/v1/report` | Receive detection from node |
| `GET` | `/api/v1/detections` | All detections (filterable by hours, CID, rogue_only) |
| `GET` | `/api/v1/summary` | Live stats — nodes, detection counts, last hit |
| `GET` | `/api/v1/map` | GeoJSON for Leaflet map |
| `GET` | `/map` | Serve live map dashboard |

---

## Live Network — Cranbourne East Investigation

Currently operational with two nodes monitoring confirmed rogue Cell IDs associated with an active IMSI catcher investigation.

| Node | Device | Status |
|---|---|---|
| `ulefone_tab4_node1` | Ulefone Android tablet | ✅ Live |
| `grapher` | Pixel 9 Pro (GrapheneOS) | ✅ Live |

**Confirmed rogue CIDs monitored (15 total):**

```python
# Telstra AU (MCC=505 MNC=001 TAC=12385)
137713195, 137713175, 137713165, 137713155, 135836191

# Vodafone AU (MCC=505 MNC=003 TAC=30336)
8409357, 8409367, 8409387, 8409397

# Post-ACMA visit CIDs (appeared 8 May 2026)
8666381, 8666391, 8666411
```

Full forensic analysis of these CIDs: [rayhunter-threat-analyzer](https://github.com/JulianBurns85/rayhunter-threat-analyzer)

---

## Roadmap

- [x] v0.1 — Field node (Termux) + central API (Flask/SQLite) + Tailscale reporting
- [x] v0.1 — systemd auto-start on Pi boot
- [x] v0.1 — Leaflet.js live map dashboard
- [x] v0.1 — Two-node live network operational
- [ ] v0.2 — Node heartbeat + offline detection buffering
- [ ] v0.3 — GPS tagging on mobile nodes
- [ ] v0.4 — Trilateration engine (3+ nodes + RSRP)
- [ ] v0.5 — RSRP signal strength heat map overlay
- [ ] v1.0 — OBD-II vehicle node (Pi Zero 2W — mobile sweep capability)

---

## Hardware

**Central (Pi):**
- Raspberry Pi 5 (API + Pi-hole + Tailscale + ARIA)

**Nodes:**
- Android tablet — Termux + termux-telephony-cellinfo
- Pixel 9 Pro (GrapheneOS) — Termux + termux-telephony-cellinfo

**Planned:**
- bladeRF 2.0 micro xA4 (SDR layer — Phase 2)
- MikroTik Chateau 5G (cellular monitoring uplink)
- Pi Zero 2W in OBD-II enclosure (vehicle node)

---

## Related Projects

- [rayhunter-threat-analyzer](https://github.com/JulianBurns85/rayhunter-threat-analyzer) — forensic batch analysis tool; the lab to Castnet's net
- [EFF Rayhunter](https://github.com/EFForg/rayhunter) — the open-source IMSI catcher detector Castnet nodes complement
- [SeaGlass](https://seaglass.cs.washington.edu/) — University of Washington distributed IMSI catcher detection (inspiration)

---

## Legal

**Passive monitoring only. No transmission. No network impersonation.**

Australia: Radiocommunications Act 1992 (Cth) — passive reception of signals does not constitute radiocommunication and requires no licence.

Regulatory actions on file from the parent investigation:
- ACMA ENQ-1851DVJH04
- TIO 2026-03-04898
- VicPol CIRS-20260331-141

---

## License

MIT — see LICENSE

---

*Built with a Raspberry Pi 5, two Android devices, too much coffee, and justifiable paranoia.*

*— Julian Burns, Cranbourne East VIC, 2026*

*"Because Stingrays are fish too. G#y Fish" - KanyRay West🎣*
