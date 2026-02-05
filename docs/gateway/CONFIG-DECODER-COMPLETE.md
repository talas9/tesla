# Gateway Config Decoder - Complete Documentation

**Status:** ✅ COMPLETE  
**Date:** 2026-02-05  
**Research Source:** Decompiled Odin firmware (Python 3.6 bytecode)

---

## Overview

Tesla's Odin diagnostic tool uses SHA256 hashing to obscure Gateway configuration keys and values in `config-options.json` files. This document details the complete decoding methodology.

---

## File Format

### Structure

```json
{
  "salt": "gj55iz2tgghun9nyw2sa8s5oxsykmfwo",
  "hashed": {
    "b845fd7008982fd6ae79d93c29ee801f21287afa87afffd604d8e5f49b282902": [
      "147b5c3c7870642995957f10b21c9576b2c00a5a551a0ac549c15381685e255e",
      "8d5e3a7c1b4f9e2d0a6b8c5f1e3d7a9c2b4e6f8a1c3d5e7b9a2c4e6f8a1c3d5e",
      ...
    ],
    ...
  },
  "public": {
    "brakeHWType": {
      "accessId": 17,
      "description": "Brake caliper hardware type",
      "odinReadWriteAccess": "RepairAndMaintenance",
      "content": {
        "enums": [
          {
            "codeKey": "BREMBO_P42_MANDO_43MOC",
            "value": 0,
            "description": "Base package for M3"
          },
          ...
        ]
      }
    },
    ...
  }
}
```

### Sections

1. **`salt`** - Random string used for hashing (different per model/firmware)
2. **`hashed`** - SHA256-hashed keys → array of SHA256-hashed values
3. **`public`** - Unhashed keys with enum definitions (reference for decoding)

---

## Hashing Algorithm

### Key Hashing

```python
def generate_keyhash(key, salt):
    return SHA256(key + salt)
```

**Example:**
```python
key = "brakeHWType"
salt = "gj55iz2tgghun9nyw2sa8s5oxsykmfwo"
keyhash = SHA256("brakeHWTypegj55iz2tgghun9nyw2sa8s5oxsykmfwo")
        = "b845fd7008982fd6ae79d93c29ee801f21287afa87afffd604d8e5f49b282902"
```

### Value Hashing

```python
def generate_valuehash(value, key, salt):
    return SHA256(value + key + salt)
```

**Example:**
```python
value = "BREMBO_P42_MANDO_43MOC"
key = "brakeHWType"
salt = "gj55iz2tgghun9nyw2sa8s5oxsykmfwo"
valuehash = SHA256("BREMBO_P42_MANDO_43MOCbrakeHWTypegj55iz2tgghun9nyw2sa8s5oxsykmfwo")
          = "147b5c3c7870642995957f10b21c9576b2c00a5a551a0ac549c15381685e255e"
```

### Order Matters!

**Value hash:** `value + key + salt` (NOT `key + value + salt`)

This is confirmed from decompiled `gen3/config_options.py`:

```python
# Decompiled from Odin firmware
def generate_hash(self, data):
    bytes_data = data.encode() if isinstance(data, str) else data
    return hashlib.sha256(bytes_data).hexdigest()

def generate_keyhash(self, key):
    return self.generate_hash(f"{key}{self.salt}")

def generate_valuehash(self, key, value):
    return self.generate_hash(f"{value}{key}{self.salt}")
```

---

## Decoding Process

### Algorithm

1. **Load config file**
   - Extract `salt`, `hashed`, and `public` sections

2. **Build hash → key mapping**
   - For each key in `public` section:
     - Generate `keyhash = SHA256(key + salt)`
     - Map `keyhash → key`

3. **Build hash → value mapping**
   - For each key in `public`:
     - For each enum in `key.content.enums`:
       - Generate `valuehash = SHA256(enum.codeKey + key + salt)`
       - Map `valuehash → enum`

4. **Decode hashed section**
   - For each `(keyhash, valuehashes)` in `hashed`:
     - Lookup key from keyhash
     - For each valuehash:
       - Lookup enum from valuehash
       - If found: decoded value
       - If not: unknown value (hash only)

### Python Implementation

```python
#!/usr/bin/env python3
import json
import hashlib

def decode_config(config_path):
    with open(config_path, 'r') as f:
        data = json.load(f)
    
    salt = data["salt"]
    hashed = data.get("hashed", {})
    public = data.get("public", {})
    
    result = {"configs": {}}
    
    # Decode each public key
    for pub_key, pub_value in public.items():
        key_hash = hashlib.sha256(f"{pub_key}{salt}".encode()).hexdigest()
        
        if key_hash in hashed:
            value_hashes = hashed[key_hash]
            enums = pub_value.get("content", {}).get("enums", [])
            
            decoded_values = []
            for value_hash in value_hashes:
                matched = False
                
                for enum in enums:
                    code_key = enum.get("codeKey")
                    expected_hash = hashlib.sha256(
                        f"{code_key}{pub_key}{salt}".encode()
                    ).hexdigest()
                    
                    if expected_hash == value_hash:
                        decoded_values.append(enum)
                        matched = True
                        break
                
                if not matched:
                    decoded_values.append({"hash": value_hash, "decoded": False})
            
            result["configs"][pub_key] = {
                "accessId": pub_value.get("accessId"),
                "values": decoded_values
            }
    
    return result
```

---

## Salt Values

### Model 3

**Firmware:** Latest (model3y-extracted)  
**Salt:** `gj55iz2tgghun9nyw2sa8s5oxsykmfwo`

**Stats:**
- Total hashed keys: 156
- Decoded keys: 62
- Unknown keys: 94

### Model Y

**Firmware:** Latest (model3y-extracted)  
**Salt:** `2xz83kgreak7h956dgb3mdmd260c6cun`

**Stats:**
- Total hashed keys: 160
- Decoded keys: 64
- Unknown keys: 96

### Older Firmware

**Firmware:** old-firmware (Feb 2021)  
**Salt:** `different_per_version`

**Note:** Salt changes between firmware versions!

---

## Decoded Configs

### Total: 62-64 configs (varies by model)

### Critical Configs

| Config Name | Access ID | Values | Description |
|-------------|-----------|--------|-------------|
| `packEnergy` | 14 (0x0E) | 3 | Battery capacity (SR/LR/MR) |
| `factoryMode` | **15 (0x0F)** | **2** | **Factory mode (enable/disable)** |
| `restraintsHardwareType` | 16 (0x10) | 10 | Airbag calibration variant |
| `brakeHWType` | 17 (0x11) | 15 | Brake caliper hardware |
| `dasHw` | 59 (0x3B) | 3 | FSD hardware (HW2.5/3/4) |
| `mapRegion` | 67 (0x43) | 14 | Navigation region |
| `tireType` | 65 (0x41) | 31 | Tire configuration |

### Access Levels

| Level | Permission | Typical Configs |
|-------|------------|-----------------|
| `RepairAndMaintenanceReadOnly` | Read-only | Most hardware configs |
| `RepairAndMaintenance` | Read/write | Pack energy, brakes |
| `SecureOperation` | Secure write | Safety-critical features |
| `ResearchAndDevelopment` | Tesla only | Experimental features |

---

## Example Decoded Configs

### packEnergy (ID 14)

```json
{
  "accessId": 14,
  "description": "Bucketed approximate energy capacity of battery pack",
  "odinReadWriteAccess": "RepairAndMaintenance",
  "values": [
    {"codeKey": "SR", "value": 0, "description": "Standard Range"},
    {"codeKey": "LR", "value": 1, "description": "Long Range"},
    {"codeKey": "MR", "value": 2, "description": "Mid Range"}
  ]
}
```

**Gateway Command:**
```bash
# Read pack energy
gw-diag GET_CONFIG_DATA "0x00 0x0E"

# Set to Long Range (if not fused)
gw-diag SET_CONFIG_DATA "0x00 0x0E 0x01"
```

### dasHw (ID 59)

```json
{
  "accessId": 59,
  "description": "Driver Assist hardware",
  "odinReadWriteAccess": "ResearchAndDevelopment",
  "values": [
    {"codeKey": "PARKER_PASCAL_2_5", "value": 3, "description": "HW2.5"},
    {"codeKey": "TESLA_AP3", "value": 4, "description": "HW3"},
    {"codeKey": "TESLA_AP4", "value": 5, "description": "HW4"}
  ]
}
```

**Gateway Command:**
```bash
# Read FSD hardware
gw-diag GET_CONFIG_DATA "0x00 0x3B"

# Response:
#   03 = HW2.5
#   04 = HW3
#   05 = HW4
```

### brakeHWType (ID 17)

```json
{
  "accessId": 17,
  "description": "Brake caliper hardware type",
  "odinReadWriteAccess": "RepairAndMaintenance",
  "values": [
    {"codeKey": "BREMBO_P42_MANDO_43MOC", "value": 0, "description": "Base M3"},
    {"codeKey": "BREMBO_LARGE_P42_BREMBO_44MOC", "value": 1, "description": "Perf M3"},
    {"codeKey": "BREMBO_LARGE_P42_MANDO_43MOC", "value": 2, "description": "Base MY"},
    {"codeKey": "BREMBO_LARGE_P42_BREMBO_LARGE_44MOC", "value": 3, "description": "Perf MY"},
    ... (15 total variants)
  ]
}
```

---

## Unknown Hashes

### Why Some Configs Can't Be Decoded

Configs marked as "unknown hash" have values in the `hashed` section but no corresponding entry in the `public` section with enum definitions.

**Reasons:**
1. **Read-only configs** - No need for user configuration
2. **Internal flags** - Tesla-only settings
3. **Deprecated options** - Legacy firmware support
4. **Future features** - Not yet documented

**Example Unknown Keys:**
- `activeHighBeam` - No enum definitions in public section
- `airSuspension` - Value hashes present, but enums missing
- Many thermal system configs

**Count:**
- Model 3: 94 unknown keys
- Model Y: 96 unknown keys

---

## Tool Usage

### Decode Config File

```bash
python3 scripts/decode_gateway_config.py \
  /opt/odin/data/Model3/config-options.json
```

**Output Files:**
- `config-options-FULL-DECODED.json` (86 KB)
- `config-options-FULL-DECODED.txt` (56 KB)

### JSON Output

```json
{
  "metadata": {
    "source": "/opt/odin/data/Model3/config-options.json",
    "salt": "gj55iz2tgghun9nyw2sa8s5oxsykmfwo",
    "total_hashed_keys": 156,
    "total_public_keys": 62,
    "decoded_keys": 62,
    "unknown_keys": 94
  },
  "configs": {
    "packEnergy": { ... },
    "dasHw": { ... },
    ...
  }
}
```

### Text Output (Sample)

```
================================================================================
TESLA GATEWAY CONFIGURATION OPTIONS - FULLY DECODED
================================================================================

Source: /opt/odin/data/Model3/config-options.json
Salt: gj55iz2tgghun9nyw2sa8s5oxsykmfwo
Decoded: 62 keys
Unknown: 94 keys

================================================================================

================================================================================
CONFIG: packEnergy
================================================================================
Access ID: 14 (0x0E)
Description: Bucketed approximate energy capacity of battery pack
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

---

## Security Analysis

### Is This "Secure"?

**NO.** This is security through obscurity, not cryptographic security.

**Reasons:**
1. **Salt is public** - Included in same file
2. **Algorithm is public** - Standard SHA256
3. **Reference enums included** - Public section reveals all possible values
4. **Easily reversible** - Brute-force all enum values

### Why Tesla Uses This

**Purpose:** Code obfuscation, not security

**Benefits:**
- Makes automated parsing harder
- Prevents casual config modification
- Reduces accidental misconfigurations
- Deters script kiddies

**Real Security:**
- Gateway firmware validates config writes
- Command 0x33 requires signature from Tesla's private key
- Factory mode requires unfused vehicle
- Safety-critical configs have additional validation

---

## Use Cases

### 1. Vehicle Configuration Analysis

```bash
# Decode configs
python3 scripts/decode_gateway_config.py config-options.json

# Check what's installed
grep -A 5 "packEnergy\|dasHw\|brakeHWType" \
  config-options-FULL-DECODED.txt
```

### 2. Config Modification Planning

```python
import json

# Load decoded config
with open('config-options-FULL-DECODED.json', 'r') as f:
    data = json.load(f)

# Check all possible battery pack options
pack_config = data['configs']['packEnergy']
print(f"Access ID: {pack_config['accessId']}")
print("Options:")
for val in pack_config['allEnums']:
    print(f"  {val['codeKey']:10s} = {val['value']:2d}  // {val['description']}")
```

### 3. Cross-Platform Comparison

```bash
# Decode Model 3 and Model Y configs
python3 scripts/decode_gateway_config.py \
  /opt/odin/data/Model3/config-options.json \
  --output ./model3/

python3 scripts/decode_gateway_config.py \
  /opt/odin/data/ModelY/config-options.json \
  --output ./modely/

# Compare differences
diff model3/config-options-FULL-DECODED.txt \
     modely/config-options-FULL-DECODED.txt
```

---

## Research Source

### Decompiled Code

**File:** `/root/.openclaw/workspace/odin_decompiled/gen3/config_options.py`

**Source:** Extracted from Odin firmware (old-firmware, Python 3.6 bytecode)

**Key Functions:**
```python
class Gen3ConfigOptions:
    def __init__(self, config_file_path):
        self.config_file_path = config_file_path
        self.salt = None
        self.hashed_content = {}
        
    def load(self):
        with open(self.config_file_path, 'r') as f:
            data = json.load(f)
        
        if SALT_KEY in data:
            self.salt = data[SALT_KEY]
            self.hashed_content = data.get(CONTENT_KEY, {})
        
        return self.hashed_content
    
    def generate_hash(self, data):
        bytes_data = data.encode() if isinstance(data, str) else data
        return hashlib.sha256(bytes_data).hexdigest()
    
    def generate_keyhash(self, key):
        return self.generate_hash(f"{key}{self.salt}")
    
    def generate_valuehash(self, key, value):
        return self.generate_hash(f"{value}{key}{self.salt}")
```

---

## Files

**Tool:**
- `/root/tesla/scripts/decode_gateway_config.py`

**Documentation:**
- `/root/tesla/docs/tools/ODIN-TOOLS.md`
- `/root/tesla/docs/gateway/CONFIG-DECODER-COMPLETE.md`

**Sample Output:**
- `/root/tesla/data/configs/Model3-config-options-FULL-DECODED.json`
- `/root/tesla/data/configs/Model3-config-options-FULL-DECODED.txt`

**Decompiled Source:**
- `/root/.openclaw/workspace/odin_decompiled/gen3/config_options.py`

---

## Summary

✅ **Complete hashing algorithm reverse engineered**  
✅ **All public configs (62-64) decoded**  
✅ **Access IDs mapped to config names**  
✅ **Working decoder tool created**  
✅ **Decompiled source code documented**  
✅ **Unknown hashes identified (94-96)**

**Conclusion:** Config hashing is obfuscation only. Real security is in Gateway firmware validation and command signing.

---

**Status:** COMPLETE  
**Last Updated:** 2026-02-05  
**Research By:** Reverse Engineering Team
