# Tesla Odin - Reconstructed Diagnostic System

Complete reconstruction of Tesla's Odin diagnostic tool with all decoded data files.

## Structure

```
odin/
├── old-firmware/          # Python 3.6 (Feb 2021) - Source decompilation
│   └── src/              # Full decompiled Odin source (1312/1348 files)
└── latest/               # Latest firmware (2024+) - Decoded data
    └── data/
        ├── Model3/       # Model 3 diagnostic data
        │   └── odj/     # 34 decrypted ODJ files
        └── ModelY/       # Model Y diagnostic data
            └── odj/     # Decrypted ODJ files
```

## What's Included

### Decrypted ODJ Files (34 per model)
- **APS.odj.json** - Automatic Park Assist
- **DAS.odj.json** - Driver Assist System
- **RCM2_custom.odj.json** - Restraint Control Module (VIN routines)
- **HVBMS.odj.json** - High Voltage Battery Management
- **EPB3.odj.json** - Electronic Parking Brake
- And 29 more ECU diagnostic files

### ODJ Contents
Each ODJ file contains:
- **Routines** - Diagnostic procedures (VIN write, security access, etc.)
- **DIDs** - Data Identifiers for read/write operations
- **Security** - Authentication algorithms and parameters
- **UDS Services** - Complete UDS service definitions

## Usage

### Decode Additional Configs
```bash
# Decode Model 3 config
python3 ../scripts/decode_gateway_config.py \
  /path/to/config-options.json
```

### View ODJ Data
```bash
# Pretty-print RCM routines (VIN write)
jq '.routines[] | select(.name | contains("VIN"))' \
  latest/data/Model3/odj/RCM2_custom.odj.json
```

### Example: VIN Write Routine
```json
{
  "name": "LEARN_VIN",
  "routine_id": 1028,
  "security_level": 0,
  "description": "Learn VIN from MCU to RCM"
}
```

## Decompilation Status

### old-firmware (Python 3.6)
- **Total files:** 1348
- **Successfully decompiled:** 1312 (97%)
- **Failed:** 36 (3%)
- **Source:** `/root/downloads/old-firmware/opt/odin/`

### Decompiled Modules
- ✅ Core (CAN, UDS, ISO-TP, Gateway) - 100%
- ✅ Security algorithms (tesla_hash, pektron_hash) - 100%
- ✅ Platforms (Gen3, Gen2) - 100%
- ✅ Services & Engine - 97%

## Decryption Details

### ODJ Encryption
- **Algorithm:** Fernet (AES-128-CBC + HMAC-SHA256)
- **Key Derivation:** PBKDF2-HMAC-SHA256
- **Iterations:** 123456
- **Password:** `cmftubxi7wlvmh1wmbzz00vf1ziqezf6`
- **Source:** Extracted from decompiled `binary_metadata_utils.py`

### Config Hashing
- **Algorithm:** SHA256
- **Key Hash:** `SHA256(key + salt)`
- **Value Hash:** `SHA256(value + key + salt)`
- **Decoded:** 299/308 values (97%)

## Tools

All tools located in `../scripts/`:
- **decode_gateway_config.py** - Decode hashed configs
- **decrypt_odj.py** - Decrypt ODJ files
- **bruteforce_unknown_hashes.py** - Find unknown enum values

## Research Applications

1. **VIN Write Analysis**
   - Extract complete VIN write procedure
   - Map UDS routine IDs and security levels
   
2. **Security Research**
   - Study authentication mechanisms
   - Analyze encryption schemes
   
3. **Diagnostic Development**
   - Build custom diagnostic tools
   - Implement UDS services

4. **Protocol Documentation**
   - Map all ECU routines
   - Document CAN messages

## Source

- **Firmware extraction:** model3y-extracted, old-firmware
- **ODJ decryption:** github.com/talas9/tesla_odj
- **Decompilation:** uncompyle6 3.9.3
- **Research:** 2026-02-05

## Legal Notice

This software was obtained through reverse engineering for research and educational purposes.
Tesla, Inc. retains all rights to the original Odin software.

**Use responsibly:**
- Research and education only
- Do not modify vehicles without authorization
- Respect intellectual property rights
- Follow responsible disclosure practices

---

**Last Updated:** 2026-02-05  
**Status:** ODJ files complete, DEJ files pending, source reconstruction in progress
