# Tesla Gateway Research - Quick Start Guide

**Time to read: 5 minutes**

---

## What Is This?

Complete reverse engineering of Tesla's Gateway ECU and Odin diagnostic system. This research documents:

1. **Gateway Configuration System** - 662 configs, CRC validation, security model
2. **Odin Diagnostic Tool** - SHA256 hashing, Fernet encryption, 2,988 scripts
3. **USB Update Format** - SquashFS + Ed25519 signatures + dm-verity
4. **Security Architecture** - Two-tier config security, service mode auth

---

## The 30-Second Summary

### Gateway (The Brain)

- **What**: Central ECU that bridges all CAN buses
- **Processor**: NXP MPC5748G (PowerPC e200z7 VLE)
- **Configs**: 662 entries stored in flash
- **Access**: UDP port 3500 (some configs), Hermes auth (secure configs)

### Key Security Finding

**Two types of configs:**
```
INSECURE (UDP:3500)     │  SECURE (Hermes auth)
────────────────────────┼────────────────────────
Map region              │  VIN
Display units           │  Country code
User preferences        │  Supercharger access
Debug flags             │  Hardware IDs
```

---

## Essential Concepts

### 1. CRC-8 Validation

Every Gateway config has a CRC-8 checksum:
```
Polynomial: 0x2F (47 decimal)
Applied to: [Config ID (2 bytes BE)] + [Data]
```

**Why it matters**: Invalid CRC = config rejected

### 2. Config Hashing (Odin)

Tesla obfuscates config names using SHA256:
```python
key_hash = SHA256(key + salt)
value_hash = SHA256(value + key + salt)  # Note: value FIRST
```

**We cracked it**: All 62-64 public configs decoded

### 3. ODJ Encryption

Odin job files use Fernet encryption:
```
Password: cmftubxi7wlvmh1wmbzz00vf1ziqezf6
KDF: PBKDF2-HMAC-SHA256
Iterations: 123456
Salt: First 16 bytes of file
```

### 4. USB Update Signatures

Package format:
```
[SquashFS] + [Padding] + [0xba01ba01 + Ed25519 sig] + [dm-verity hash table]
```

**Cannot forge**: Requires Tesla's Ed25519 private key

---

## Quick Reference Tables

### Critical Config IDs

| ID | Name | Type | Access |
|----|------|------|--------|
| 0x0000 | VIN | String(17) | Secure |
| 0x0006 | Country | String(2) | Secure |
| 0x0014 | mapRegion | Byte | UDP |
| 0x0020 | ecuMapVersion | Byte | UDP |
| 0x0025 | Hash 1 | SHA-256 | Secure |
| 0x0026 | Hash 2 | SHA-256 | Secure |

### Network Ports

| Port | Protocol | Service | Access |
|------|----------|---------|--------|
| 3500 | UDP | Gateway config API | Internal network |
| 25956 | TCP | Emergency updater | CAN flood trigger |
| 8901 | HTTP | APE factory API | Bearer token |
| 69 | TFTP | Gateway firmware | Service mode |

### Platform Labels

| Label | Meaning | Use For |
|-------|---------|---------|
| ICE | Infotainment Computer for Entertainment | Model 3/Y |
| MCU2 | Media Control Unit 2 | Model S/X (2018+) |
| Zen | AMD Ryzen MCU | 2022+ vehicles |
| APE | Autopilot ECU | All with AP |

---

## Common Tasks

### Read a Gateway Config

```bash
# Using UDP (insecure configs only)
python3 scripts/gateway_database_query.py read 0x0014
```

### Decode Config Hashes

```bash
python3 scripts/decode_gateway_config.py \
  /opt/odin/data/Model3/config-options.json
```

### Decrypt ODJ File

```bash
python3 scripts/decrypt_odj.py input.odj output.json
```

### Validate Config CRC

```python
from scripts.gateway_crc_validator import calculate_crc8

config_id = 0x0000
data = b"7SAYGDEEXPA052466"  # VIN
crc = calculate_crc8(config_id, data)  # Polynomial 0x2F
```

---

## Security Model Summary

```
┌─────────────────────────────────────────────────────────┐
│                    GATEWAY ECU                          │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  ┌─────────────────┐     ┌─────────────────────────┐   │
│  │  UDP Port 3500  │     │  Hermes Authenticated   │   │
│  │  (INSECURE)     │     │  (SECURE)               │   │
│  ├─────────────────┤     ├─────────────────────────┤   │
│  │ • Map region    │     │ • VIN                   │   │
│  │ • Units         │     │ • Country               │   │
│  │ • Preferences   │     │ • Supercharger          │   │
│  │ • Debug flags   │     │ • Hardware IDs          │   │
│  │                 │     │ • Firmware hashes       │   │
│  │ NO AUTH NEEDED  │     │ gw-diag + auth token    │   │
│  └─────────────────┘     └─────────────────────────┘   │
│                                                         │
│  ┌─────────────────────────────────────────────────┐   │
│  │  PHYSICAL ACCESS (JTAG)                         │   │
│  │  Bypasses ALL security - direct flash access    │   │
│  └─────────────────────────────────────────────────┘   │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

---

## What's Verified vs Theoretical

### ✅ Verified (High Confidence)

- CRC-8 polynomial 0x2F (100% validation on 662 configs)
- SHA256 config hashing algorithm (decompiled source)
- Fernet ODJ encryption (password extracted)
- Two-tier security model (confirmed by source)
- USB package format (real packages analyzed)

### ⚠️ Inferred (Medium Confidence)

- Service mode backend validation (binary analysis, not packet capture)
- Port 25956 bind address (behavior observed, not disassembled)
- APE bearer token requirement (string evidence)

### ❌ Untested (Low Confidence)

- CAN flood success rate across firmware versions
- Exact gwmon timeout value
- Geofence restriction regions

---

## Next Steps

1. **Deep dive**: [docs/2-gateway/README.md](docs/2-gateway/README.md)
2. **Attack research**: [docs/5-attacks/README.md](docs/5-attacks/README.md)
3. **Tool usage**: [docs/6-tools/README.md](docs/6-tools/README.md)
4. **Full knowledge base**: [docs/1-overview/README.md](docs/1-overview/README.md)

---

## Files You'll Use Most

| File | Purpose |
|------|---------|
| `scripts/gateway_database_query.py` | Read/write Gateway configs via UDP |
| `scripts/decode_gateway_config.py` | Decode Odin config hashes |
| `scripts/decrypt_odj.py` | Decrypt Odin job files |
| `data/gateway/gateway_configs_parsed.txt` | All 662 Gateway configs |
| `data/gateway/strings.csv` | 37,702 Gateway firmware strings |

---

**You're ready to dive in!** Start with [Gateway Architecture](docs/2-gateway/architecture.md) for the full picture.
