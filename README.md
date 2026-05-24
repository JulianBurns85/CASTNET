# castnet-registry 🎣

**Global Rogue Cell ID Registry — Community IMSI Catcher Intelligence**

> The shared intelligence layer for the [CASTNET](https://github.com/JulianBurns85/CASTNET) distributed detection network.

---

## What This Is

A community-maintained, privacy-first database of confirmed rogue Cell IDs associated with IMSI catcher / rogue base station activity worldwide.

Every [CASTNET](https://github.com/JulianBurns85/CASTNET) node automatically syncs this registry. Every new confirmed CID immediately protects every node operator worldwide.

---

## Privacy Model

This registry contains **zero identifying information about contributors.**

| Included | Excluded |
|---|---|
| ✅ Cell ID, TAC, MCC, MNC | ❌ GPS coordinates |
| ✅ Carrier, country, region (city level) | ❌ Contributor identity |
| ✅ Detection methods | ❌ Node IDs |
| ✅ Hardware profile | ❌ Precise timestamps |
| ✅ Confidence level | ❌ Movement data |

The registry records **where the attacker is** — never **where the reporter is.**

---

## How to Use

### Automatic sync (CASTNET nodes)

```bash
# Add to crontab — daily sync at 2am
0 2 * * * python3 ~/castnet/castnet_sync.py
```

### Manual import

```python
import yaml, requests

url = "https://raw.githubusercontent.com/JulianBurns85/castnet-registry/main/castnet_global_registry.yaml"
registry = yaml.safe_load(requests.get(url).text)

KNOWN_ROGUE_CIDS = {
    entry['cid']
    for entry in registry['confirmed_rogue_cids']
    if entry['confidence'] in ('HIGH', 'MEDIUM')
}
```

### rayhunter-threat-analyzer integration

The registry is directly compatible with the rayhunter-threat-analyzer intelligence database. Drop `castnet_global_registry.yaml` into `intelligence/db/` and it will be loaded automatically.

---

## Current Registry

| Region | Carrier | CIDs | Hardware | Confidence |
|---|---|---|---|---|
| Cranbourne East, VIC, AU | Telstra AU | 6 | Harris HailStorm/StingRay II | HIGH |
| Cranbourne East, VIC, AU | Vodafone AU | 6 | Harris HailStorm/StingRay II | HIGH |
| Cranbourne East, VIC, AU | Vodafone AU | 3 | Harris (post-reconfiguration) | HIGH |

**13 HIGH confidence + 1 MEDIUM confidence entries**

Full forensic analysis of the Cranbourne East investigation: [rayhunter-threat-analyzer](https://github.com/JulianBurns85/rayhunter-threat-analyzer)

---

## How to Contribute

### Minimum evidence for submission

**HIGH confidence** requires at least two of:
- Confirmed absence from OpenCelliD or anomalous position
- Behavioural indicator (metronomic timer, IMEISV harvesting, cipher downgrade)
- Cross-session consistency (observed across multiple independent captures)
- Regulatory confirmation (ACMA, FCC, Ofcom, etc.)

**MEDIUM confidence** requires:
- Single detection method with consistent observations
- Plausible absence from legitimate carrier infrastructure

### Submission process

1. Fork this repo
2. Add your entry to `castnet_global_registry.yaml` following the schema
3. Submit a pull request with a brief description of evidence
4. Do **not** include GPS coordinates, node IDs, or any identifying information

### Entry schema

```yaml
- cid: 12345678
  tac: 12345
  mcc: 505
  mnc: "01"
  carrier: "Carrier Name"
  country: "AU"
  region: "City/Suburb, State"
  first_confirmed: "YYYY-MM"
  detection_methods:
    - "Method 1"
    - "Method 2"
  confidence: "HIGH"
  hardware_profile: "Harris HailStorm / unknown"
  observations: 100
  notes: "Any relevant context"
```

---

## Ecosystem

| Repo | Role |
|---|---|
| [rayhunter-threat-analyzer](https://github.com/JulianBurns85/rayhunter-threat-analyzer) | Forensic batch analysis — generate confirmed CIDs |
| [CASTNET](https://github.com/JulianBurns85/CASTNET) | Live detection network — consume this registry |
| **castnet-registry** | Shared intelligence — you are here |

---

## Legal

Contributing to this registry does not constitute interception, transmission, or interference with communications. Passive reception of cellular signals and documentation of anomalous Cell IDs is lawful in most jurisdictions.

Consult local telecommunications law before deploying detection hardware.

---

## License

CC0 1.0 Universal — public domain. No rights reserved.

Intelligence should be free.

*— Julian Burns, Cranbourne East VIC, 2026*

*"Because Stingrays are fish too. G#y Fish" — KanyRay West 🎣*
