# Tesla Gateway Security Research

**Complete reverse engineering documentation for Tesla Model 3/Y (ICE) and Model S/X (MCU2) infotainment and Gateway ECU systems.**

---

## Research Statistics

| Metric | Value | Status |
|--------|-------|--------|
| Gateway Configs Extracted | 662 entries | ✅ 100% CRC verified |
| Odin Scripts Analyzed | 2,988 Python files | ✅ Complete |
| Gateway Firmware Size | 6 MB (6,225,920 bytes) | ✅ Extracted |
| CAN Messages Documented | 6,647 entries | ✅ Cataloged |
| Config Hashing Algorithm | SHA256 | ✅ Fully decoded |
| ODJ File Encryption | Fernet (PBKDF2-HMAC-SHA256) | ✅ Cracked |

---

## Quick Start

**5 minutes to understand the research:**
1. [QUICKSTART.md](QUICKSTART.md) - Essential concepts
2. [docs/1-overview/key-findings.md](docs/1-overview/key-findings.md) - Major discoveries

**Deep dive by topic:**
- [Gateway Security](docs/2-gateway/) - Complete Gateway reverse engineering
- [Odin Diagnostic System](docs/3-odin/) - Tesla service tool analysis  
- [Attack Research](docs/5-attacks/) - Security vulnerabilities
- [Tools](docs/6-tools/) - Scripts and utilities

---

## Repository Structure

```
tesla/
├── README.md                   # This file
├── QUICKSTART.md               # 5-minute getting started
├── docs/
│   ├── 1-overview/             # Research overview and key findings
│   │   ├── README.md           # What this research covers
│   │   ├── key-findings.md     # Major discoveries
│   │   └── evidence-quality.md # Verification standards
│   │
│   ├── 2-gateway/              # Gateway ECU analysis
│   │   ├── README.md           # Gateway overview
│   │   ├── architecture.md     # Hardware and firmware
│   │   ├── config-system.md    # 662 configs, CRC-8, two-tier security
│   │   ├── udp-protocol.md     # Port 3500 API
│   │   ├── security-model.md   # Secure vs insecure configs
│   │   └── firmware-analysis.md # Disassembly findings
│   │
│   ├── 3-odin/                 # Odin diagnostic system
│   │   ├── README.md           # Odin overview
│   │   ├── architecture.md     # How Odin works
│   │   ├── config-decoder.md   # SHA256 hashing (COMPLETE)
│   │   ├── odj-encryption.md   # Fernet/PBKDF2 decryption
│   │   └── routines-database.md # 2,988 scripts analyzed
│   │
│   ├── 4-firmware/             # Platform-specific firmware
│   │   ├── ice/                # Model 3/Y (ICE platform)
│   │   │   ├── overview.md
│   │   │   └── usb-updates.md
│   │   └── mcu2/               # Model S/X (MCU2 platform)
│   │       └── overview.md
│   │
│   ├── 5-attacks/              # Security research
│   │   ├── README.md           # Attack surface overview
│   │   ├── can-flood.md        # Port 25956 opening exploit
│   │   ├── vin-write.md        # VIN modification (JTAG)
│   │   ├── service-mode.md     # Authentication analysis
│   │   └── certificate-recovery.md # Orphan vehicle certs
│   │
│   └── 6-tools/                # Tool documentation
│       ├── README.md           # Tools overview
│       ├── config-decoder.md   # decode_gateway_config.py
│       ├── odj-decryptor.md    # decrypt_odj.py
│       ├── gateway-tools.md    # gw-diag, UDP tools
│       └── scripts-reference.md # All scripts
│
├── data/                       # Decoded data files
│   ├── configs/                # Gateway configuration databases
│   ├── gateway/                # Gateway strings, CAN messages
│   └── odj/                    # Decrypted Odin job files
│
├── odin/                       # Odin decompiled source
│   └── decompiled/             # Python files from bytecode
│
└── scripts/                    # Research tools
    ├── decode_gateway_config.py
    ├── decrypt_odj.py
    ├── gateway_crc_validator.py
    ├── gateway_database_query.py
    └── signatures.json
```

---

## Platform Terminology

| Term | Meaning | Vehicles |
|------|---------|----------|
| **ICE** | Infotainment Computer for Entertainment | Model 3, Model Y |
| **MCU2** | Media Control Unit 2 | Model S/X (2018+, Raven, Plaid) |
| **Gateway** | Central CAN bus aggregator ECU | All Tesla vehicles |
| **APE** | Autopilot ECU (NVIDIA hardware) | All with Autopilot |
| **Zen/Ryzen** | AMD Ryzen-based newer MCU | 2022+ vehicles |
| **Hermes** | Tesla's mTLS authentication system | Backend connectivity |

---

## Key Findings Summary

### 1. Gateway Configuration System ✅ COMPLETE

- **662 configuration entries** extracted from 6MB flash dump
- **CRC-8 algorithm verified** (polynomial 0x2F, 100% validation rate)
- **Two-tier security model**:
  - **Insecure (UDP)**: Map region, units, preferences - modifiable via UDP:3500
  - **Secure (Hermes)**: VIN, country, supercharger - require Tesla authentication
- **Source**: [docs/2-gateway/config-system.md](docs/2-gateway/config-system.md)

### 2. Odin Diagnostic System ✅ COMPLETE

- **SHA256-based config hashing** fully reverse engineered
  - Algorithm: `SHA256(value + key + salt)` for values
  - All 62-64 public configs decoded
- **Fernet encryption** for ODJ files cracked
  - Password: `cmftubxi7wlvmh1wmbzz00vf1ziqezf6`
  - PBKDF2-HMAC-SHA256, 123456 iterations
- **2,988 diagnostic scripts** analyzed for access patterns
- **Source**: [docs/3-odin/architecture.md](docs/3-odin/architecture.md)

### 3. Service Mode Authentication ✅ VERIFIED

- **NOT a local PIN comparison** - backend validation required
- Uses D-Bus + Protobuf signed command infrastructure
- No hardcoded backdoors found in binary analysis
- Geofence restrictions exist (`isServiceModeAllowedOutsideGeofence`)
- **Source**: [docs/5-attacks/service-mode.md](docs/5-attacks/service-mode.md)

### 4. USB Offline Updates ✅ COMPLETE

- **Package format**: SquashFS (LZ4) + NaCl Ed25519 signature + dm-verity hash table
- **File extensions**: `.ice` (Model 3/Y), `.mcu2` (Model S/X)
- **Signature magic**: `0xba01ba01`
- **Cannot bypass on fused vehicles** - hardware enforced
- **Source**: [docs/4-firmware/ice/usb-updates.md](docs/4-firmware/ice/usb-updates.md)

### 5. CAN Flood Exploit ⚠️ PARTIALLY TESTED

- **Mechanism**: Flood CAN bus with 0x3C2 + 0x622 → opens port 25956
- **Impact**: Enables firmware handshake redirection
- **Reliability**: Varies by firmware version
- **Source**: [docs/5-attacks/can-flood.md](docs/5-attacks/can-flood.md)

---

## Tools Reference

| Tool | Purpose | Location |
|------|---------|----------|
| `decode_gateway_config.py` | Decode SHA256-hashed config names | [scripts/](scripts/) |
| `decrypt_odj.py` | Decrypt Odin ODJ job files | [scripts/](scripts/) |
| `gateway_crc_validator.py` | Validate Gateway config CRCs | [scripts/](scripts/) |
| `gateway_database_query.py` | Query Gateway via UDP:3500 | [scripts/](scripts/) |

---

## Evidence Standards

All claims follow strict evidence requirements:

| Marker | Meaning | Confidence |
|--------|---------|------------|
| **✅ VERIFIED** | Multiple sources confirm, binary offsets cited | 95-100% |
| **⚠️ INFERRED** | Logical deduction from evidence, limited testing | 60-80% |
| **❌ UNTESTED** | Theoretical only, no hardware validation | <60% |

---

## Network Architecture

```
[Vehicle Internal Network: 192.168.90.0/24]

┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  MCU (ICE/MCU2) │     │  Gateway ECU    │     │  APE (Autopilot)│
│  192.168.90.100 │────▶│  192.168.90.102 │────▶│  192.168.90.103 │
│                 │     │                 │     │                 │
│ • QtCarServer   │     │ • UDP:3500      │     │ • HTTP:8901     │
│ • sx-updater    │     │ • TFTP:69       │     │   (factory API) │
│ • hermes_client │     │ • CAN bus       │     │ • Calibration   │
└─────────────────┘     └─────────────────┘     └─────────────────┘
         │                      │
         │                      │
    ┌────┴────┐           ┌─────┴─────┐
    │ Modem   │           │  CAN Bus  │
    │ .90.60  │           │  (OBD-II) │
    └─────────┘           └───────────┘
```

---

## Security Notice

This research is for **educational and security research purposes only**.

- Do not modify vehicles without authorization
- Report security findings to Tesla via responsible disclosure
- Respect intellectual property rights

---

## Contributing

1. All claims must cite source (file path, binary offset, or decompiled code)
2. Use firmware-relative paths (e.g., `/usr/tesla/UI/`, `/opt/odin/`)
3. Never use host extraction paths (e.g., `/root/downloads/`)
4. Label platforms clearly: ICE = Model 3/Y, MCU2 = Model S/X (newer)
5. Test all markdown links before committing

---

## Firmware Paths Reference

| Purpose | Path |
|---------|------|
| MCU UI binaries | `/usr/tesla/UI/bin/` |
| Odin tool | `/opt/odin/` |
| Deploy packages | `/deploy/` |
| Hermes client | `/opt/hermes/` |
| Car credentials | `/var/lib/car_creds/` |
| System config | `/etc/` |

---

**Last Updated:** 2026-02-07  
**Research Status:** Gateway configuration COMPLETE, Odin decoding COMPLETE
