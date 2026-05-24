# CASTNET ??

**Distributed Civilian IMSI Catcher Detection and Geolocation Network**

> Where Rayhunter Threat Analyzer is the forensic lab, Castnet is the net.

Built as the operational layer for the [Rayhunter Threat Analyzer](https://github.com/JulianBurns85/rayhunter-threat-analyzer) investigation — Cranbourne East, Victoria, Australia, 2026.

---

## What It Does

Every Castnet **node** (a phone, tablet, or vehicle dongle) passively monitors cellular signals and reports confirmed rogue CID detections — tagged with GPS coordinates and signal strength — to a central **aggregation API** running on a Raspberry Pi.

When three or more nodes detect the same rogue CID simultaneously, **trilateration runs automatically** and the attacker's physical location is estimated.

---

## Architecture

\\\
castnet_node.py          (phone / tablet / OBD dongle)
       |
       | POST /api/v1/report  (via Tailscale WireGuard)
       v
castnet_api.py           (Raspberry Pi — Flask + SQLite)
       |
       | GET /api/v1/map
       v
castnet_map.html         (Leaflet.js browser dashboard)
\\\

---

## Components

| Component | Location | Description |
|---|---|---|
| Node script | \
ode/castnet_node.py\ | Field detection unit — runs on any Android (Termux) or Linux device |
| Central API | \pi/castnet_api.py\ | Flask API + SQLite — runs on Raspberry Pi 24/7 |
| Map dashboard | \dashboard/castnet_map.html\ | Leaflet.js live map — browser accessible via Tailscale |

---

## Quick Start

### Central API (Raspberry Pi)
\\\ash
cd ~/castnet
pip install flask --break-system-packages
python castnet_api.py
# Listening on 0.0.0.0:5000
\\\

### Node (Android Termux / Linux)
\\\ash
pip install requests
python castnet_node.py --api http://<pi-tailscale-ip>:5000 --node-id my-phone
\\\

---

## Roadmap

- [x] v0.1 — Single node detection + central API + SQLite
- [x] v0.1 — Tailscale encrypted reporting
- [ ] v0.2 — Node heartbeat + offline buffering
- [ ] v0.3 — GPS tagging on mobile nodes
- [ ] v0.4 — Trilateration engine (3+ nodes)
- [ ] v0.5 — Leaflet.js live map dashboard
- [ ] v1.0 — OBD-II vehicle dongle node (Pi Zero 2W)

---

## Hardware Used

- Raspberry Pi 5 (central API + Pi-hole + Tailscale)
- Pixel 9 Pro / Android tablet (Termux nodes)
- bladeRF 2.0 micro xA4 (SDR layer — Phase 2)
- MikroTik Chateau 5G (cellular monitoring uplink)

---

## Related

- [rayhunter-threat-analyzer](https://github.com/JulianBurns85/rayhunter-threat-analyzer) — forensic batch analysis tool this project extends
- [EFF Rayhunter](https://github.com/EFForg/rayhunter) — the IMSI catcher detector Castnet nodes are built around

---

## Legal

Passive monitoring only. No transmission. No network impersonation.

Australia: Radiocommunications Act 1992 (Cth) — passive reception of signals does not constitute radiocommunication.

---

## License

MIT

*Built with a Raspberry Pi 5, too much coffee, and justifiable paranoia.*

*— Julian Burns, Cranbourne East VIC, 2026*
