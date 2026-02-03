# Quick Start — Tesla Gateway Research

**Goal:** Understand this research in 5 minutes

---

## What Is This Research?

This repository reverse-engineers the **Tesla Gateway ECU** — the PowerPC-based controller managing:
- **662 vehicle configurations** (VIN, features, regions, hardware mappings)
- **CAN bus routing** (6,647 message database)
- **Feature enablement** (Autopilot, supercharging, trials)
- **Firmware update authentication**

**Why it matters:** The Gateway controls what your Tesla can do and where it can charge.

---

## The One Thing You Must Know

**Gateway has a two-tier security model:**

| Tier | Access Method | Examples | Risk |
|------|---------------|----------|------|
| **Insecure** | UDP port 3500 (no auth) | Map region, trial timers, ECU map | Anyone on 192.168.90.0/24 can modify |
| **Secure** | Hermes WSS:443 (auth required) | VIN, country, supercharger access | Requires Tesla backend |
| **Hardware-locked** | Fuses (cannot change) | Debug security level | Permanent after fusing |

**CRC algorithm:** CRC-8, polynomial 0x2F (validated on all 662 configs)

**Evidence:** ✅ Verified — Odin database with `accessLevel: "UDP"` flags, configs extracted and validated

---

## Quick Navigation

| I want to... | Read this | Time |
|--------------|-----------|------|
| **Understand the Gateway** | [GATEWAY-OVERVIEW.md](GATEWAY-OVERVIEW.md) | 15 min |
| **Query configs** | [GATEWAY-CONFIGS.md](GATEWAY-CONFIGS.md) + use `gateway_database_query.py` | 10 min |
| **Learn about exploits** | [ATTACK-SUMMARY.md](ATTACK-SUMMARY.md) | 10 min |
| **Recover orphan car** | [AUTH-ORPHAN-CARS.md](AUTH-ORPHAN-CARS.md) | 15 min |
| **Understand Odin tool** | [ODIN-OVERVIEW.md](ODIN-OVERVIEW.md) | 15 min |
| **Check evidence quality** | [EVIDENCE-QUALITY.md](EVIDENCE-QUALITY.md) | 5 min |

---

## Top 5 Critical Findings

### 1. Insecure Configs (UDP Port 3500) ✅ Verified

**What:** Some configs accessible via UDP without authentication  
**Which configs:** Map region (`mapRegion`), autopilot trial timer, ECU map version  
**Odin flag:** `accessLevel: "UDP"`  
**Impact:** Network-level modification possible  
**Details:** [GATEWAY-SECURITY.md](GATEWAY-SECURITY.md#insecure-configs)

---

### 2. CAN Flood Opens Updater Shell ⚠️ Inferred

**What:** Flooding CAN opens TCP port 25956 (firmware update interface)  
**Method:** CAN 0x3C2 @ 10k msg/sec + 0x622 @ 33 msg/sec for 10-30s  
**Hardware:** PCAN USB (~$50)  
**Success rate:** Reported 98%  
**Details:** [ATTACK-CAN-FLOOD.md](ATTACK-CAN-FLOOD.md)

---

### 3. Odin Database Unhashed ✅ Verified

**What:** Tesla's service tool config database obtained before encryption  
**Contents:** 2,988 scripts, accessId mapping, enum values  
**API:** `get_vehicle_configuration(access_id=INTEGER)` — **NO AUTH** for normal levels  
**Details:** [ODIN-CONFIG-DATABASE.md](ODIN-CONFIG-DATABASE.md)

---

### 4. Service Mode = Backend Validation ⚠️ Inferred

**What:** Service PIN not checked locally — requires Tesla backend  
**Method:** DoIP + Protobuf signed commands  
**Evidence:** D-Bus analysis, no local PIN found  
**Impact:** Cannot bypass offline  
**Details:** [AUTH-SERVICE-MODE.md](AUTH-SERVICE-MODE.md)

---

### 5. Complete Firmware Analysis ✅ Verified

**What:** 6MB PowerPC binary fully reverse-engineered  
**Contents:** 37,702 strings, 6,647 CAN messages, 21K metadata entries  
**Disassembly:** 1.5M lines PowerPC assembly  
**Details:** [GATEWAY-FIRMWARE.md](GATEWAY-FIRMWARE.md)

---

## Common Questions

### Q: Can I modify my VIN?

**Technical answer:** Yes (config 0x0000), requires:
- CAN flood exploit OR service tool access
- CRC recalculation (polynomial 0x2F)
- VIN stored in multiple ECUs (Gateway, MCU, APE)

**Practical answer:** Don't. Illegal, breaks supercharging, detectable.

**Use for research only.**

---

### Q: How do I recover an orphan car?

**Orphan car** = certificate expired while offline

**Recovery options:**
1. **Tesla service** (high success, recommended)
2. **Restore backup certs** (if you have `/var/lib/car_creds/` backup)
3. **DIY cert generation:** NO method exists (requires Tesla infrastructure)

**Details:** [AUTH-ORPHAN-CARS.md](AUTH-ORPHAN-CARS.md)

---

### Q: Can I enable Autopilot features?

**Technical:** Config flags exist (accessId levels in Odin)

**Practical issues:**
- Requires secure (authenticated) config write → Hermes backend
- Hardware must support (cameras, FSD computer)
- Backend may reject hardware mismatch
- Likely illegal in most jurisdictions

**This research documents what's possible, not what's legal.**

---

### Q: What's the CRC algorithm?

**CRC-8, polynomial 0x2F:**

```python
def crc8(data):
    crc = 0x00
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x80:
                crc = (crc << 1) ^ 0x2F
            else:
                crc = crc << 1
    return crc & 0xFF
```

**Validated:** 100% success on all 662 configs

**Tool:** `scripts/gateway_crc_validator.py`

---

### Q: Is this tested on real vehicles?

**Mixed:**

| Finding | Status | Evidence |
|---------|--------|----------|
| Firmware analysis | ✅ Tested | Binaries extracted, disassembled |
| Config extraction | ✅ Tested | 662 configs validated |
| CAN flood | ⚠️ Inferred | Working script, reported success |
| Voltage glitch | ❌ Theoretical | Based on TU Berlin research |

**See [EVIDENCE-QUALITY.md](EVIDENCE-QUALITY.md) for per-finding ratings.**

---

## Tools You Can Use Today

### Query Gateway Configs
```bash
python3 scripts/gateway_database_query.py --search "autopilot"
# Shows all autopilot-related configs
```

### Validate Config CRC
```bash
python3 scripts/gateway_crc_validator.py --config-id 0x0020 --data "01"
# Output: CRC: 0xXX (valid/invalid)
```

### Parse Flash Dump
```bash
python3 scripts/gateway_crc_validator.py parse ryzenfromtable.bin
# Extracts all 662 configs from binary
```

### Match Odin to Gateway
```bash
python3 scripts/match_odin_to_configs.py
# Maps Odin accessId to Gateway config IDs
```

---

## File Organization

```
tesla/
├── README.md                    # Full introduction
├── QUICK-START.md               # This file (you are here)
├── INDEX.md                     # Complete navigation
├── EVIDENCE-QUALITY.md          # Verification status
│
├── GATEWAY-*.md                 # Gateway ECU (9 docs)
├── ODIN-*.md                    # Tesla service tool (4 docs)
├── ATTACK-*.md                  # Attack vectors (6 docs)
├── AUTH-*.md                    # Authentication (5 docs)
├── UPDATE-*.md                  # OTA/USB updates (5 docs)
├── NETWORK-*.md                 # Network architecture (3 docs)
├── APE-*.md                     # Autopilot ECU (2 docs)
├── MCU-*.md                     # MCU/QtCar (2 docs)
│
├── VCSEC-KEY-PROGRAMMING.md     # Key pairing
├── CAN-PROTOCOL.md              # CAN analysis
├── BINARY-OFFSETS.md            # All offsets
│
├── data/                        # Extracted data
│   ├── configs/                 # Config databases
│   ├── strings/                 # String extractions
│   └── disassembly/             # Disassembly outputs
│
└── scripts/                     # Analysis tools
    ├── gateway_crc_validator.py
    ├── gateway_database_query.py
    └── openportlanpluscan.py
```

---

## Next Steps

1. **Understand system:** Read [GATEWAY-OVERVIEW.md](GATEWAY-OVERVIEW.md) (15 min)
2. **Check evidence:** See [EVIDENCE-QUALITY.md](EVIDENCE-QUALITY.md) (5 min)
3. **Pick a topic:** Choose from file organization above
4. **Try tools:** Run scripts in `scripts/` directory
5. **Deep dive:** Read firmware analysis for binary-level details

---

## ⚠️ Warning

**This research is for:**
- ✅ Educational security analysis
- ✅ Responsible vulnerability disclosure
- ✅ Understanding automotive security

**NOT for:**
- ❌ Vehicle theft
- ❌ Fraud (VIN manipulation, free supercharging)
- ❌ Safety system tampering

**Use responsibly:**
- Only on vehicles you own
- Only for research/education
- Report vulnerabilities to Tesla
- Respect laws and safety

---

**You're now oriented!**

**Recommended first read:** [GATEWAY-OVERVIEW.md](GATEWAY-OVERVIEW.md)  
*15 minutes, gives you foundation for everything else*

