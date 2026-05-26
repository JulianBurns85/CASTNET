# CASTNET Communal Server — Deployment Guide

## What This Is

The communal server is a community-scale aggregation layer that sits above individual CASTNET instances. Multiple independent operators report detections to a shared server, building a collective intelligence database of rogue CIDs.

**Private by default.** Operators control exactly what gets shared.

---

## Architecture

```
Operator A (Cranbourne East)  ──┐
Operator B (Frankston)         ─┤──→  castnet_communal_api.py  ──→  communal.db
Operator C (Dandenong)         ─┘              │
Operator D (anywhere AU)       ─┘              ├──→ /community/map   (opted-in only)
                                               ├──→ /community/cids  (consensus registry)
                                               └──→ /my/detections   (private — own data)
```

---

## Data Model

### Operators
- Each operator registers with a unique handle and region
- Gets a unique API key (`CASTNET-<random32>`)
- `share_data = 0` by default — detections are private
- Can opt in to sharing via `POST /my/settings`

### Community CID Registry
Starts seeded with all 16 confirmed Cranbourne East rogue CIDs.

Confidence levels:
| Level | Meaning |
|---|---|
| `UNCONFIRMED` | Reported by 1 operator |
| `WATCHLIST` | Reported by 2 operators |
| `COMMUNITY_CONFIRMED` | Reported by 3+ independent operators |
| `HIGH` | Manually elevated (post-ACMA CIDs etc.) |
| `CONFIRMED` | Forensically confirmed (investigation-grade) |

### Dead Man's Switch
All detections are stored regardless of sharing setting.
A private operator's data is preserved on the server even if they never share it.
Export your data any time via `/my/detections`.

---

## Deployment Options

### Option A — DigitalOcean / Linode VPS (~$5 AUD/month)
Best for community use. Public IP, SSL via Let's Encrypt.

```bash
# On fresh Ubuntu 24 VPS
apt update && apt install python3-pip nginx certbot python3-certbot-nginx -y
pip3 install flask --break-system-packages

# Clone repo
git clone https://github.com/JulianBurns85/CASTNET /opt/castnet
cd /opt/castnet

# Set environment
export CASTNET_ADMIN_KEY=$(openssl rand -hex 32)
export CASTNET_DB=/opt/castnet/communal.db
echo "Admin key: $CASTNET_ADMIN_KEY"   # SAVE THIS

# Run
python3 castnet_communal_api.py
```

### Option B — Raspberry Pi via Tailscale (private/vault mode)
Best for the "dead man's switch" use case. Not publicly accessible.

```bash
ssh overkill@100.68.146.48

cd ~/castnet
export CASTNET_ADMIN_KEY=$(openssl rand -hex 32)
export CASTNET_PORT=5001   # different port from local API on 5000
python3 castnet_communal_api.py
```

### Systemd Service (auto-start)
```ini
[Unit]
Description=CASTNET Communal API
After=network.target

[Service]
Type=simple
User=overkill
WorkingDirectory=/home/overkill/castnet
Environment=CASTNET_ADMIN_KEY=your-key-here
Environment=CASTNET_PORT=5001
ExecStart=/usr/bin/python3 /home/overkill/castnet/castnet_communal_api.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

---

## Operator Registration

Admin registers each new operator:

```bash
curl -X POST http://localhost:5001/admin/operators/register \
  -H "Content-Type: application/json" \
  -H "X-Castnet-Admin: YOUR_ADMIN_KEY" \
  -d '{"handle": "overkill_au", "region": "Cranbourne East VIC"}'
```

Response:
```json
{
  "status": "registered",
  "handle": "overkill_au",
  "region": "Cranbourne East VIC",
  "api_key": "CASTNET-a3f8b2c1d4e5f6...",
  "warning": "Store this key securely — it cannot be recovered"
}
```

---

## Node Configuration

Point existing CASTNET nodes at the communal server by setting env vars:

```bash
# On phone/tablet — add second reporting target
export CASTNET_COMMUNAL_API=http://YOUR_SERVER:5001/api/v1/report
export CASTNET_COMMUNAL_KEY=CASTNET-your-operator-key
```

Or run two instances of castnet_node.py with different API targets.
A future v0.3 of castnet_node.py will support dual reporting natively.

---

## Opting In to Community Sharing

```bash
curl -X POST http://localhost:5001/my/settings \
  -H "X-Castnet-Key: YOUR_OPERATOR_KEY" \
  -H "Content-Type: application/json" \
  -d '{"share_data": true}'
```

---

## Community Endpoints (public, no auth)

```bash
# Confirmed CID registry
curl http://localhost:5001/community/cids

# Community map GeoJSON (last 7 days of shared detections)
curl http://localhost:5001/community/map

# Stats
curl http://localhost:5001/community/stats
```

---

## Roadmap

- [ ] v0.1 — Multi-operator support, consensus scoring, private/shared model
- [ ] v0.2 — Encrypted backup export (dead man's switch archive)
- [ ] v0.3 — castnet_node.py dual-reporting (local + communal simultaneously)
- [ ] v0.4 — Community Silent Trident (cross-operator trilateration)
- [ ] v0.5 — Web registration portal for self-service operator signup
- [ ] v1.0 — National AU rogue CID registry

---

## Legal

Passive monitoring only. No transmission. No interception.
Australia: Radiocommunications Act 1992 (Cth) — passive reception requires no licence.

*"Because Stingrays are fish too."* 🎣
