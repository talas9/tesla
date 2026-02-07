# Odin Config Decoder

**Complete reverse engineering of Tesla's SHA256 config hashing algorithm.**

---

## Overview

Tesla's Odin tool obfuscates configuration keys and values using SHA256 hashing. This document details the complete decoding methodology.

| Metric | Value |
|--------|-------|
| Algorithm | SHA256 |
| Key Format | `SHA256(key + salt)` |
| Value Format | `SHA256(value + key + salt)` |
| Decoded Configs | 62-64 (varies by model) |
| Unknown Hashes | 94-96 |

---

## File Format

### config-options.json Structure

```json
{
  "salt": "gj55iz2tgghun9nyw2sa8s5oxsykmfwo",
  "hashed": {
    "b845fd7008982fd6...": [
      "147b5c3c7870642...",
      "8d5e3a7c1b4f9e2..."
    ]
  },
  "public": {
    "brakeHWType": {
      "accessId": 17,
      "description": "Brake caliper hardware type",
      "content": {
        "enums": [
          {"codeKey": "BREMBO_P42_MANDO_43MOC", "value": 0}
        ]
      }
    }
  }
}
```

### Sections

| Section | Purpose |
|---------|---------|
| `salt` | Random string for hashing (per firmware) |
| `hashed` | SHA256 key hashes → array of value hashes |
| `public` | Unhashed configs with enum definitions |

---

## Hashing Algorithm

### Key Hashing

```python
def generate_keyhash(key: str, salt: str) -> str:
    """Generate SHA256 hash for config key."""
    return hashlib.sha256(f"{key}{salt}".encode()).hexdigest()
```

**Example:**
```python
key = "brakeHWType"
salt = "gj55iz2tgghun9nyw2sa8s5oxsykmfwo"
keyhash = SHA256("brakeHWTypegj55iz2tgghun9nyw2sa8s5oxsykmfwo")
        = "b845fd7008982fd6ae79d93c29ee801f21287afa87afffd604d8e5f49b282902"
```

### Value Hashing

**IMPORTANT:** Value comes FIRST in the hash input!

```python
def generate_valuehash(value: str, key: str, salt: str) -> str:
    """Generate SHA256 hash for config value."""
    # Note: value + key + salt (NOT key + value + salt)
    return hashlib.sha256(f"{value}{key}{salt}".encode()).hexdigest()
```

**Example:**
```python
value = "BREMBO_P42_MANDO_43MOC"
key = "brakeHWType"
salt = "gj55iz2tgghun9nyw2sa8s5oxsykmfwo"
valuehash = SHA256("BREMBO_P42_MANDO_43MOCbrakeHWTypegj55iz2tgghun9nyw2sa8s5oxsykmfwo")
```

---

## Decoding Process

### Algorithm

1. Load config-options.json
2. Extract `salt`, `hashed`, and `public` sections
3. For each public config:
   - Compute `keyhash = SHA256(key + salt)`
   - If keyhash exists in `hashed` section:
     - For each value in public config enums:
       - Compute `valuehash = SHA256(enum.codeKey + key + salt)`
       - Match against hashed values

### Python Implementation

```python
import json
import hashlib

def decode_config_file(path: str) -> dict:
    with open(path, 'r') as f:
        data = json.load(f)
    
    salt = data["salt"]
    hashed = data.get("hashed", {})
    public = data.get("public", {})
    
    result = {}
    
    for key, config in public.items():
        keyhash = hashlib.sha256(f"{key}{salt}".encode()).hexdigest()
        
        if keyhash in hashed:
            decoded_values = []
            enums = config.get("content", {}).get("enums", [])
            
            for value_hash in hashed[keyhash]:
                matched = False
                for enum in enums:
                    code_key = enum.get("codeKey", "")
                    expected = hashlib.sha256(
                        f"{code_key}{key}{salt}".encode()
                    ).hexdigest()
                    
                    if expected == value_hash:
                        decoded_values.append(enum)
                        matched = True
                        break
                
                if not matched:
                    decoded_values.append({"hash": value_hash, "unknown": True})
            
            result[key] = {
                "accessId": config.get("accessId"),
                "values": decoded_values
            }
    
    return result
```

---

## Salt Values

| Model | Firmware | Salt |
|-------|----------|------|
| Model 3 | 2024+ | `gj55iz2tgghun9nyw2sa8s5oxsykmfwo` |
| Model Y | 2024+ | `2xz83kgreak7h956dgb3mdmd260c6cun` |
| Older | 2021 | Different per version |

**Note:** Salt changes between firmware versions. Always extract from the actual config file.

---

## Decoded Configs

### Critical Configs

| Config | Access ID | Values | Description |
|--------|-----------|--------|-------------|
| packEnergy | 14 | SR/LR/MR | Battery capacity |
| factoryMode | 15 | on/off | Factory mode enable |
| dasHw | 59 | HW2.5/HW3/HW4 | FSD hardware |
| mapRegion | 67 | 14 regions | Navigation maps |
| brakeHWType | 17 | 15 variants | Brake calibration |

### Access Levels

| Level | Permission |
|-------|------------|
| `RepairAndMaintenanceReadOnly` | Read-only |
| `RepairAndMaintenance` | Read/write |
| `SecureOperation` | Secure write |
| `ResearchAndDevelopment` | Tesla only |

---

## Example Output

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

---

## Unknown Hashes

Some configs cannot be decoded:

| Count | Reason |
|-------|--------|
| 94-96 | No enum definitions in `public` section |

**Why:**
- Read-only configs (no user modification)
- Internal Tesla flags
- Deprecated options
- Future features not yet documented

---

## Tool Usage

### Decode Config File

```bash
python3 scripts/decode_gateway_config.py \
  /opt/odin/data/Model3/config-options.json
```

### Output Files

- `config-options-FULL-DECODED.json` (86 KB)
- `config-options-FULL-DECODED.txt` (56 KB)

---

## Security Analysis

### Is This Secure?

**NO.** This is obfuscation, not cryptographic security.

**Weaknesses:**
- Salt included in same file
- Algorithm is standard SHA256
- All enum values provided for brute-force
- Public section contains reference data

**Real Security:**
- Gateway firmware validates writes
- Secure configs require Hermes authentication
- Factory mode requires unfused vehicle

---

## Decompiled Source

**Location:** Odin firmware, Python 3.6 bytecode

```python
# From gen3/config_options.py
class Gen3ConfigOptions:
    def generate_hash(self, data):
        bytes_data = data.encode() if isinstance(data, str) else data
        return hashlib.sha256(bytes_data).hexdigest()
    
    def generate_keyhash(self, key):
        return self.generate_hash(f"{key}{self.salt}")
    
    def generate_valuehash(self, key, value):
        return self.generate_hash(f"{value}{key}{self.salt}")
```

---

## Cross-References

- [Odin Architecture](architecture.md) - How Odin uses these configs
- [Gateway Config System](../2-gateway/config-system.md) - Config IDs
- [scripts/decode_gateway_config.py](https://github.com/talas9/tesla/blob/master/scripts/decode_gateway_config.py) - Decoder tool

---

**Status:** COMPLETE ✅  
**Evidence:** Decompiled source, working decoder  
**Last Updated:** 2026-02-07
