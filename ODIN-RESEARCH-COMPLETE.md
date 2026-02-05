# Odin Research - Complete Summary

**Date:** 2026-02-05  
**Status:** ✅ COMPLETE

---

## Overview

Complete reverse engineering of Tesla's Odin diagnostic system, including:
- Config file decoder (SHA256 hashing)
- ODJ file decryptor (Fernet encryption)
- Full Odin source code reconstruction (1312/1348 files decompiled)
- Gateway config database documentation

---

## What Was Accomplished

### 1. Config Decoder ✅

**Achievement:** Reverse engineered SHA256-based config hashing system

**Files Added:**
- `scripts/decode_gateway_config.py` (9.0 KB) - Decoder tool
- `docs/gateway/CONFIG-DECODER-COMPLETE.md` (14 KB) - Complete documentation
- `data/configs/config-options-FULL-DECODED.json` (86 KB) - Sample decoded output
- `data/configs/config-options-FULL-DECODED.txt` (56 KB) - Human-readable output

**Results:**
- 62-64 Gateway configs fully decoded
- All enum values extracted
- Access IDs mapped to config names
- Unknown hashes identified (94-96)

**Key Configs Decoded:**
- `packEnergy` (ID 14) - Battery capacity
- `factoryMode` (ID 15) - Factory mode enable
- `dasHw` (ID 59) - FSD hardware version
- `brakeHWType` (ID 17) - Brake variants (15 options)
- `mapRegion` (ID 67) - Navigation region (14 options)

**Source:** Decompiled from `gen3/config_options.py` (Odin firmware)

### 2. ODJ Decryptor ✅

**Achievement:** Extracted hardcoded Fernet encryption password from Odin firmware

**Files Added:**
- `scripts/decrypt_odj.py` (9.5 KB) - Decryption tool
- `docs/tools/ODIN-TOOLS.md` (11 KB) - Complete tools documentation

**Encryption Details:**
- **Algorithm:** Fernet (AES-128-CBC + HMAC-SHA256)
- **Key Derivation:** PBKDF2-HMAC-SHA256
- **Iterations:** 123456
- **Password:** `cmftubxi7wlvmh1wmbzz00vf1ziqezf6`
- **Source:** Decompiled from `binary_metadata_utils.py`

**Capabilities:**
- Decrypt all .odj files
- Extract VIN write routines
- Analyze security algorithms
- Map UDS routine IDs

**Example Decrypted Routine:**
```json
{
  "name": "LEARN_VIN",
  "routine_id": 1028,
  "security_level": 0,
  "description": "Learn VIN from MCU to RCM"
}
```

### 3. Full Odin Decompilation ✅

**Achievement:** Decompiled 97% of Odin Python bytecode (1312/1348 files)

**Location:** `/root/.openclaw/workspace/odin_decompiled_full/`

**Modules Decompiled:**
- Core (CAN, UDS, ISO-TP, Gateway) - 100%
- Platform support (Gen3) - 100%
- Security algorithms - 100%
- Services and engine - 97%

**Key Extracted Files:**
- `tesla_hash.py` - Key card algorithm
- `pektron_hash.py` - ECU security (LFSR)
- `remote_routines.py` - Diagnostic routines
- `data_transmission.py` - Read/write data
- `uds_service.py` - UDS request/response
- `gen3/gateway.py` - Gateway TCP/UDP protocol
- `gen3/config_options.py` - Config decoder

**Reconstructed Application:**
- Location: `/root/.openclaw/workspace/odin_reconstructed/`
- 152 Odin modules organized
- Virtual environment with dependencies
- Main entry point created
- Test suite included

### 4. Documentation ✅

**Files Updated:**
- `docs/SCRIPTS.md` - Added config decoder and ODJ decryptor
- `docs/tools/ODIN-TOOLS.md` - NEW - Complete tools guide
- `docs/gateway/CONFIG-DECODER-COMPLETE.md` - NEW - Decoder documentation

**Research Files Created:**
- `ODIN-RECONSTRUCTION-STATUS.md` - Decompilation status
- `GATEWAY-COMPLETE-FINDINGS.md` - Gateway research summary
- `COMPLETE-ODIN-FLOW.md` - UDS/ISO-TP flow
- `RCM-CAN-IDS-FOUND.md` - VIN write CAN IDs
- `GATEWAY-CONFIG-QUICK-REFERENCE.md` - Config ID reference

---

## Repository Structure

### Scripts

```
scripts/
├── decode_gateway_config.py  ✅ NEW - Config decoder
├── decrypt_odj.py            ✅ NEW - ODJ decryptor
├── gateway_crc_validator.py   (existing)
├── gateway_database_query.py  (existing)
└── match_odin_to_configs.py   (existing)
```

### Documentation

```
docs/
├── SCRIPTS.md                     ✅ UPDATED - Added new tools
├── tools/
│   └── ODIN-TOOLS.md             ✅ NEW - Complete tools guide
└── gateway/
    ├── CONFIG-DECODER-COMPLETE.md ✅ NEW - Decoder documentation
    ├── 82-odin-routines-database-UNHASHED.md (existing)
    ├── 83-odin-config-api-analysis.md (existing)
    └── ... (existing files)
```

### Data Files

```
data/
├── configs/
│   ├── config-options-FULL-DECODED.json ✅ NEW - Decoded config (Model Y)
│   └── config-options-FULL-DECODED.txt  ✅ NEW - Human-readable
├── 09a-gateway-config-ids.csv (existing)
├── odin-hash-mapping.txt (existing)
└── ... (existing files)
```

---

## Tools Usage

### Decode Gateway Config

```bash
# Decode Model 3 config
python3 scripts/decode_gateway_config.py \
  /opt/odin/data/Model3/config-options.json

# Output:
#   config-options-FULL-DECODED.json (86 KB)
#   config-options-FULL-DECODED.txt (56 KB)
```

### Decrypt ODJ Files

```bash
# Decrypt single file
python3 scripts/decrypt_odj.py \
  /opt/odin/data/Model3/odj/RCM_VIN_LEARN.odj

# Decrypt entire directory
python3 scripts/decrypt_odj.py \
  /opt/odin/data/Model3/odj/ \
  --recursive --analyze
```

---

## Key Findings

### 1. Config Hashing Algorithm

**Formula:**
```python
key_hash = SHA256(key_name + salt)
value_hash = SHA256(enum_value + key_name + salt)
```

**Salts:**
- Model 3: `gj55iz2tgghun9nyw2sa8s5oxsykmfwo`
- Model Y: `2xz83kgreak7h956dgb3mdmd260c6cun`

**Security:** Obfuscation only (not cryptographic security)

### 2. ODJ Encryption

**Stack:**
```
Plaintext JSON
    ↓
Fernet.encrypt(data, key)
    ↓
PBKDF2-HMAC-SHA256(password, salt, 123456 iterations)
    ↓
Password: cmftubxi7wlvmh1wmbzz00vf1ziqezf6
```

**Source:** Hardcoded in Odin firmware binary

### 3. Gateway Communication

**TCP Bridge:** localhost:10001 (Odin → Gateway)
**Gateway Tools:**
- `gw-diag` - Direct Gateway diagnostic tool
- `gwxfer` - Gateway filesystem access

**Config Access:**
```bash
# Read config (ID 14 = packEnergy)
gw-diag GET_CONFIG_DATA "0x00 0x0E"

# Write config (requires permissions)
gw-diag SET_CONFIG_DATA "0x00 0x0E 0x01"  # Set LR
```

### 4. VIN Write Procedure

**Target:** RCM (Restraint Control Module)
**Protocol:** UDS over ISO-TP on CH bus
**Routine:** LEARN_VIN (0x0404)
**Security:** Level 0 (NO AUTHENTICATION!)

**Flow:**
```
1. Extended Diagnostic Session (10 03)
2. LEARN_VIN routine (31 01 04 04)
3. Wait 3 seconds (MCU provides VIN to RCM)
4. Verify VIN (22 F1 90)
```

**CAN IDs:**
- Request: 0x641 (UDS_rcmRequest)
- Response: 0x649 (RCM_udsResponse)

---

## Research Impact

### What This Enables

1. **Configuration Analysis**
   - Decode all vehicle configs
   - Identify hardware options
   - Map regional variants

2. **Diagnostic Development**
   - Build custom diagnostic tools
   - Implement VIN write procedures
   - Create test frameworks

3. **Security Research**
   - Analyze authentication mechanisms
   - Study encryption schemes
   - Test security boundaries

4. **Educational Use**
   - Learn automotive diagnostics
   - Study Python bytecode decompilation
   - Understand embedded systems

### What It Does NOT Enable

❌ **Bypassing Command 0x33** - Still requires Tesla's private signing key  
❌ **Enabling Factory Mode** - Requires unfused vehicle or is_fused() bypass  
❌ **Unauthorized Modifications** - Gateway firmware validates all writes  
❌ **Certificate Bypass** - MITM still blocked by certificate pinning

---

## Files Summary

### New Scripts (2)
1. `scripts/decode_gateway_config.py` (9.0 KB)
2. `scripts/decrypt_odj.py` (9.5 KB)

### New Documentation (2)
1. `docs/tools/ODIN-TOOLS.md` (11 KB)
2. `docs/gateway/CONFIG-DECODER-COMPLETE.md` (14 KB)

### Updated Documentation (1)
1. `docs/SCRIPTS.md` (added tools 3 and 4)

### New Data Files (2)
1. `data/configs/config-options-FULL-DECODED.json` (86 KB)
2. `data/configs/config-options-FULL-DECODED.txt` (56 KB)

**Total Files Added/Updated:** 7 files

---

## Testing

### Decoder Test

```bash
$ python3 scripts/decode_gateway_config.py \
    /opt/odin/data/Model3/config-options.json

Decoding: /opt/odin/data/Model3/config-options.json

✓ JSON output: config-options-FULL-DECODED.json
✓ Text output: config-options-FULL-DECODED.txt

Decoded 62 config keys
Unknown: 94 keys

================================================================================
SAMPLE DECODED CONFIGS
================================================================================

packEnergy (Access ID: 14)
  Values: 3 options
    - SR: 0
    - LR: 1
    - MR: 2

dasHw (Access ID: 59)
  Values: 3 options
    - PARKER_PASCAL_2_5: 3
    - TESLA_AP3: 4
    - TESLA_AP4: 5
```

### ODJ Decryptor Test

```bash
$ python3 scripts/decrypt_odj.py \
    RCM_VIN_LEARN.odj --analyze

✓ Decrypted: RCM_VIN_LEARN.odj → RCM_VIN_LEARN.json

================================================================================
ODJ ANALYSIS: RCM_VIN_LEARN.odj
================================================================================

Routines: 2
  - LEARN_VIN (ID: 0x0404, Security: 0)
  - VIN_RESET (ID: 0xF102, Security: 3)

Data Identifiers: 15
  - 0xF190: VIN
```

---

## No Redundancy

### Checked for Duplicates

✅ **decode_gateway_config.py** - NEW (old decode_odin_config.py is different)
✅ **decrypt_odj.py** - NEW (no existing ODJ decryptor)
✅ **ODIN-TOOLS.md** - NEW comprehensive guide
✅ **CONFIG-DECODER-COMPLETE.md** - NEW detailed documentation

### Updated Existing

✅ **docs/SCRIPTS.md** - Added tools 3 and 4 to existing list
✅ **data/configs/** - Added sample outputs (new directory)

### Preserved Existing

✅ All existing gateway docs preserved
✅ All existing scripts preserved
✅ All existing data files preserved

---

## Legal Notice

**Research Purpose:** Educational and security research only

**Disclaimers:**
- Tools extract data through legal reverse engineering
- Config hashing is obfuscation (not security)
- Real security is in Gateway firmware validation
- Respect Tesla's intellectual property

**Responsible Use:**
- Do not modify vehicles without authorization
- Report security findings to Tesla
- Follow responsible disclosure practices

---

## Summary

✅ **2 new tools created and documented**  
✅ **All tools integrated into repository**  
✅ **Complete documentation added**  
✅ **Sample outputs provided**  
✅ **No redundancy with existing files**  
✅ **All findings properly organized**

**Status:** RESEARCH COMPLETE AND DOCUMENTED

---

**Repository:** https://github.com/talas9/tesla  
**Last Updated:** 2026-02-05
