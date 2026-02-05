# Odin Analysis Tools

Complete toolkit for decoding and analyzing Tesla's Odin diagnostic system.

---

## Overview

Odin is Tesla's diagnostic tool that runs on the MCU and communicates with the Gateway and other ECUs. These tools enable analysis of Odin's configuration files, encrypted diagnostic jobs, and protocols.

**Key Capabilities:**
- Decode hashed configuration files
- Decrypt encrypted diagnostic routines
- Extract VIN write procedures
- Analyze security algorithms
- Map Gateway config IDs

---

## 1. Gateway Config Decoder

### Purpose
Decode SHA256-hashed `config-options.json` files from Odin firmware to reveal vehicle configuration options.

### File
`scripts/decode_gateway_config.py` (9.1 KB)

### Background

Odin's config files use SHA256 hashing to obscure configuration keys and values:

**Key Hashing:**
```python
key_hash = SHA256(key_name + salt)
```

**Value Hashing:**
```python
value_hash = SHA256(enum_value + key_name + salt)
```

**Example:**
```
key = "brakeHWType"
salt = "gj55iz2tgghun9nyw2sa8s5oxsykmfwo"
key_hash = SHA256("brakeHWTypegj55iz2tgghun9nyw2sa8s5oxsykmfwo")
         = "b845fd7008982fd6ae79d93c29ee801f21287afa87afffd604d8e5f49b282902"
```

### Usage

```bash
# Decode Model 3 config
python3 scripts/decode_gateway_config.py \
  /opt/odin/data/Model3/config-options.json

# Decode Model Y with custom output
python3 scripts/decode_gateway_config.py \
  /opt/odin/data/ModelY/config-options.json \
  --output ./decoded_configs/
```

### Output Files

**1. JSON Format** (`config-options-FULL-DECODED.json`)
```json
{
  "metadata": {
    "source": "/opt/odin/data/Model3/config-options.json",
    "salt": "gj55iz2tgghun9nyw2sa8s5oxsykmfwo",
    "decoded_keys": 62,
    "unknown_keys": 94
  },
  "configs": {
    "packEnergy": {
      "accessId": 14,
      "description": "Battery pack energy capacity",
      "odinReadWriteAccess": "RepairAndMaintenance",
      "values": [
        {"codeKey": "SR", "value": 0, "description": "Standard Range"},
        {"codeKey": "LR", "value": 1, "description": "Long Range"},
        {"codeKey": "MR", "value": 2, "description": "Mid Range"}
      ],
      "allEnums": [...]
    }
  }
}
```

**2. Text Format** (`config-options-FULL-DECODED.txt`)
```
================================================================================
CONFIG: packEnergy
================================================================================
Access ID: 14 (0x0E)
Description: Battery pack energy capacity
Access Level: RepairAndMaintenance

Current Values (3):
  - SR: 0 // Standard Range
  - LR: 1 // Long Range
  - MR: 2 // Mid Range

All Possible Values (3):
  SR                             = 0      // Standard Range
  LR                             = 1      // Long Range
  MR                             = 2      // Mid Range
```

### Decoded Configs

**Total:** 62-64 configs (varies by model)

**Critical Configs:**
- `packEnergy` (ID 14) - Battery capacity
- `factoryMode` (ID 15) - Factory mode enable
- `restraintsHardwareType` (ID 16) - Airbag calibration
- `brakeHWType` (ID 17) - Brake hardware (15 variants)
- `dasHw` (ID 59) - FSD hardware (HW2.5/3/4)
- `mapRegion` (ID 67) - Navigation region (14 regions)
- `tireType` (ID 65) - Tire configuration (31 variants)

**Access Levels:**
- `RepairAndMaintenanceReadOnly` - Read-only by technicians
- `RepairAndMaintenance` - Read/write by Tesla Service
- `SecureOperation` - Secure write only (safety-critical)
- `ResearchAndDevelopment` - Tesla engineering only

### Use Cases

1. **Vehicle Configuration Analysis**
   - Identify installed hardware
   - Determine enabled features
   - Check regional variant

2. **Config Modification Planning**
   - See all possible values before modifying
   - Understand Access ID mapping
   - Verify config compatibility

3. **Research**
   - Study Tesla's vehicle variant management
   - Understand feature flags
   - Map hardware options

### Salt Values

| Model | Firmware | Salt |
|-------|----------|------|
| Model 3 | Latest | `gj55iz2tgghun9nyw2sa8s5oxsykmfwo` |
| Model Y | Latest | `2xz83kgreak7h956dgb3mdmd260c6cun` |
| Model S | Old | `different_salt_per_platform` |

---

## 2. ODJ File Decryptor

### Purpose
Decrypt Fernet-encrypted Odin Diagnostic Job (ODJ) files to extract diagnostic routines, VIN write procedures, and security algorithms.

### File
`scripts/decrypt_odj.py` (9.6 KB)

### Background

ODJ files contain diagnostic routines encrypted with Fernet (AES-128-CBC + HMAC-SHA256).

**Encryption Stack:**
```
Plaintext JSON
    ↓
JSON.stringify()
    ↓
Fernet.encrypt(data, key)
    ↓
Key = PBKDF2-HMAC-SHA256(password, salt, 123456 iterations)
    ↓
Password: "cmftubxi7wlvmh1wmbzz00vf1ziqezf6"
    ↓
Encrypted .odj file
```

**Key Extraction:**
- Source: Decompiled `binary_metadata_utils.py` from Odin firmware
- Method: Reverse engineered from Python 3.6 bytecode
- Password is base64-decoded from hardcoded constant

### Usage

```bash
# Decrypt single ODJ file
python3 scripts/decrypt_odj.py \
  /opt/odin/data/Model3/odj/RCM_VIN_LEARN.odj

# Decrypt all ODJ files in directory
python3 scripts/decrypt_odj.py \
  /opt/odin/data/Model3/odj/ \
  --recursive

# Decrypt with analysis
python3 scripts/decrypt_odj.py \
  RCM_VIN_LEARN.odj \
  --analyze

# Use custom output directory
python3 scripts/decrypt_odj.py \
  /opt/odin/data/ModelY/odj/ \
  --output ./decrypted_odj/ \
  --recursive
```

### Output

**Decrypted JSON Structure:**
```json
{
  "routines": [
    {
      "name": "LEARN_VIN",
      "routine_id": 1028,
      "security_level": 0,
      "parameters": [...],
      "description": "Learn VIN from MCU to RCM"
    },
    {
      "name": "VIN_RESET",
      "routine_id": 61698,
      "security_level": 3,
      "security_algorithm": "pektron_hash",
      "description": "Reset VIN in RCM memory"
    }
  ],
  "dids": {
    "61840": {
      "name": "VIN",
      "size": 17,
      "access": "read_write"
    }
  },
  "security": {
    "algorithm": "pektron_hash",
    "buffer_size": 3,
    "fixed_bytes": "6E6164616D"
  }
}
```

**Analysis Output:**
```
================================================================================
ODJ ANALYSIS: RCM_VIN_LEARN.odj
================================================================================

Routines: 2
  - LEARN_VIN (ID: 0x0404, Security: 0)
  - VIN_RESET (ID: 0xF102, Security: 3)

Data Identifiers: 15
  - 0xF190: VIN
  - 0xF187: ECU Serial Number
  - 0xF18C: Software Version

Security Config:
  Algorithm: pektron_hash
  Buffer Size: 3
```

### Decryption Details

**Algorithm:** Fernet (RFC 7539)
- **Cipher:** AES-128-CBC
- **MAC:** HMAC-SHA256
- **Padding:** PKCS#7

**Key Derivation:** PBKDF2-HMAC-SHA256
- **Password:** `cmftubxi7wlvmh1wmbzz00vf1ziqezf6`
- **Salt:** `b"salt_123"` (default Odin salt)
- **Iterations:** 123456
- **Key Length:** 32 bytes (256 bits)

**Dependencies:**
```bash
pip install cryptography
```

### Extracted Routines

**VIN Write (RCM):**
- `LEARN_VIN` (0x0404) - Security level 0 (no auth!)
- `VIN_RESET` (0xF102) - Security level 3 (pektron_hash)

**Security Access:**
- `tesla_hash` - Key card algorithm (XOR 0x35)
- `pektron_hash` - ECU security (LFSR-based)

**Data Transmission:**
- `ReadDataByIdentifier` - DID reading
- `WriteDataByIdentifier` - DID writing
- Routine IDs and parameters

### Use Cases

1. **VIN Write Research**
   - Extract VIN write procedure
   - Identify security requirements
   - Map UDS routine IDs

2. **Security Analysis**
   - Study authentication algorithms
   - Analyze security levels
   - Extract seed/key procedures

3. **Protocol Documentation**
   - Map all diagnostic routines
   - Document DIDs
   - Understand UDS services

---

## 3. Combined Workflow

### Complete Vehicle Config Analysis

```bash
#!/bin/bash
# Complete Odin analysis workflow

ODIN_DATA="/opt/odin/data/Model3"

# 1. Decode config options
echo "Decoding config-options.json..."
python3 scripts/decode_gateway_config.py \
  "$ODIN_DATA/config-options.json" \
  --output ./analysis/

# 2. Decrypt all ODJ files
echo "Decrypting ODJ files..."
python3 scripts/decrypt_odj.py \
  "$ODIN_DATA/odj/" \
  --output ./analysis/odj/ \
  --recursive

# 3. Extract VIN routine
echo "Analyzing VIN write routine..."
python3 scripts/decrypt_odj.py \
  "$ODIN_DATA/odj/RCM_VIN_LEARN.odj" \
  --analyze

# 4. Check Gateway configs
echo "Analyzing Gateway configs..."
grep -A 10 "packEnergy\|factoryMode\|dasHw" \
  ./analysis/config-options-FULL-DECODED.txt

echo "Analysis complete! Results in ./analysis/"
```

### Extract Critical Configs

```python
#!/usr/bin/env python3
"""Extract critical Gateway configs"""

import json

# Load decoded config
with open('config-options-FULL-DECODED.json', 'r') as f:
    data = json.load(f)

critical = ['packEnergy', 'factoryMode', 'dasHw', 'brakeHWType', 'mapRegion']

print("CRITICAL GATEWAY CONFIGS")
print("=" * 80)

for key in critical:
    if key in data['configs']:
        cfg = data['configs'][key]
        print(f"\n{key} (Access ID: {cfg['accessId']})")
        print(f"  Access: {cfg['odinReadWriteAccess']}")
        print(f"  Values:")
        for val in cfg['values']:
            if val.get('decoded', True):
                print(f"    {val['codeKey']:30s} = {val['value']}")
```

---

## Installation

### Requirements
```bash
# Core dependencies
pip3 install cryptography

# Optional (for analysis)
pip3 install pandas
```

### Setup
```bash
# Clone repository
git clone https://github.com/talas9/tesla.git
cd tesla

# Make scripts executable
chmod +x scripts/*.py

# Test installation
python3 scripts/decode_gateway_config.py --help
python3 scripts/decrypt_odj.py --help
```

---

## Data Files

### Location
```
/opt/odin/data/
├── Model3/
│   ├── config-options.json       # Hashed configs
│   ├── nodes.json                # ECU definitions
│   └── odj/
│       ├── RCM_VIN_LEARN.odj    # VIN routines (encrypted)
│       ├── BMS_*.odj            # Battery diagnostics
│       └── ...
├── ModelY/
├── ModelS/
└── ModelX/
```

### Sample Files

Decrypted samples available in repository:
- `data/configs/Model3-config-options-FULL-DECODED.json`
- `data/configs/Model3-config-options-FULL-DECODED.txt`

---

## Security Notice

**These tools are for research and educational purposes only.**

- ODJ decryption password was extracted via legal reverse engineering
- Config hashing is security through obscurity (not cryptographic security)
- Do NOT use these tools for unauthorized vehicle modifications
- Respect Tesla's intellectual property rights

**Responsible Disclosure:**
- Security findings should be reported to Tesla's security team
- Do not publish exploits without coordination
- Follow responsible disclosure practices

---

## References

**Documentation:**
- [Gateway Config Reference](../gateway/CONFIG-DATABASE.md)
- [Odin Architecture](../core/ODIN-ARCHITECTURE.md)
- [VIN Write Complete Guide](../attacks/VIN-WRITE-GUIDE.md)

**Scripts:**
- [decode_gateway_config.py](../../scripts/decode_gateway_config.py)
- [decrypt_odj.py](../../scripts/decrypt_odj.py)

**Data:**
- [Gateway Config IDs](../../data/09a-gateway-config-ids.csv)
- [Odin Hash Mapping](../../data/odin-hash-mapping.txt)

---

**Last Updated:** 2026-02-05  
**Version:** 1.0
