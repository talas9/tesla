# Odin Routines Database

**Analysis of Tesla's 2,988 diagnostic scripts and access level mappings.**

---

## Overview

The Odin routines database is a JSON file containing config definitions with access levels that reveal Tesla's security model.

| Metric | Value |
|--------|-------|
| Total Scripts | 2,988 Python files |
| Gen3 Configs | Model 3, Y, Lychee, Tamarind |
| Gen2 Configs | Model S, X (pre-refresh) |
| Source | Internal unhashed database |

---

## Database Structure

### Format

```json
{
  "gen3": [
    {
      "accessId": 7,
      "codeKey": "exteriorColor",
      "accessLevel": null,
      "content": {
        "enums": [...]
      },
      "description": "exterior vehicle color",
      "products": ["Model3", "ModelY", "Tamarind", "Lychee"]
    }
  ],
  "gen2": [...]
}
```

### Key Fields

| Field | Purpose | Example |
|-------|---------|---------|
| `accessId` | Permission level | 7, 33, 54 |
| `codeKey` | Config name | `exteriorColor` |
| `accessLevel` | Security flag | `"UDP"`, `"GTW"`, null |
| `content.enums` | Valid values | `[{codeKey, value}]` |
| `products` | Applicable vehicles | `["Model3", "ModelY"]` |

---

## Access Levels

### Security Flags

| Flag | Meaning | Count | Example |
|------|---------|-------|---------|
| `"UDP"` | Insecure, no auth | 3 | ecuMapVersion |
| `"GTW"` | Hardware locked | 1 | devSecurityLevel |
| `null` | Standard auth | ~150 | Most configs |

### Insecure Configs (`accessLevel: "UDP"`)

| Config | accessId | Description |
|--------|----------|-------------|
| ecuMapVersion | 33 | ECU configuration version |
| autopilotTrialExpireTime | 54 | AP trial expiration |
| bmpWatchdogDisabled | 61 | Battery watchdog |

### Hardware-Locked Config (`accessLevel: "GTW"`)

```json
{
  "accessId": 15,
  "accessLevel": "GTW",
  "codeKey": "devSecurityLevel",
  "content": {
    "enums": [
      {"codeKey": "LC_FACTORY", "value": 3, "description": "Factory - CUST_DEL"},
      {"codeKey": "LC_GATED", "value": 2, "description": "Production - OEM_PROD"}
    ]
  }
}
```

This controls the MPC5748G hardware security fuses.

---

## Critical Configs

### superchargingAccess (accessId 30)

```json
{
  "accessId": 30,
  "codeKey": "superchargingAccess",
  "content": {
    "enums": [
      {"codeKey": "NOT_ALLOWED", "value": 0},
      {"codeKey": "ALLOWED", "value": 1},
      {"codeKey": "PAY_AS_YOU_GO", "value": 2}
    ]
  },
  "description": "Customer's access to Tesla supercharging network"
}
```

**Status:** Secure (no UDP flag, confirmed by source)

### autopilot (accessId 29)

```json
{
  "accessId": 29,
  "codeKey": "autopilot",
  "content": {
    "enums": [
      {"codeKey": "NONE", "value": 0},
      {"codeKey": "HIGHWAY", "value": 1},
      {"codeKey": "ENHANCED", "value": 2},
      {"codeKey": "SELF_DRIVING", "value": 3},
      {"codeKey": "BASIC", "value": 4}
    ]
  }
}
```

**Status:** Likely secure (paid feature, no UDP flag)

### mapRegion (accessId 66)

```json
{
  "accessId": 66,
  "codeKey": "mapRegion",
  "content": {
    "enums": [
      {"codeKey": "US", "value": 0},
      {"codeKey": "EU", "value": 1},
      {"codeKey": "NONE", "value": 2},
      {"codeKey": "CN", "value": 3},
      {"codeKey": "AU", "value": 4},
      {"codeKey": "JP", "value": 5},
      {"codeKey": "TW", "value": 6},
      {"codeKey": "KR", "value": 7},
      {"codeKey": "ME", "value": 8},
      {"codeKey": "HK", "value": 9},
      {"codeKey": "MO", "value": 10},
      {"codeKey": "SE", "value": 11}
    ]
  }
}
```

**Status:** Insecure (empirically confirmed modifiable)

---

## accessId to Config ID Mapping

### Discovered Mappings

| accessId | Config ID | Name |
|----------|-----------|------|
| 14 | 0x0E | packEnergy |
| 15 | 0x0F | devSecurityLevel |
| 17 | 0x11 | brakeHWType |
| 20 | 0x14 | mapRegion |
| 59 | 0x3B | dasHardwareConfig |
| 66 | 0x42 | mapRegion |
| 81 | 0x51 | deliveryStatus |

### Pattern

```
Config ID = accessId (for low IDs)
OR
Config ID = (accessId - offset) for some ranges
```

Full mapping requires cross-referencing flash dump with database.

---

## Gen2 vs Gen3 Differences

### Gen2 (Model S/X Pre-Refresh)

| Feature | Value |
|---------|-------|
| accessId format | String |
| Enum values | Strings |
| Special flags | None found |
| Product codes | `ModelS`, `ModelX` |

### Gen3 (Model 3/Y/Refresh)

| Feature | Value |
|---------|-------|
| accessId format | Integer |
| Enum values | Integers |
| Special flags | `UDP`, `GTW` |
| Product codes | `Model3`, `ModelY`, `Lychee`, `Tamarind` |

---

## Security Implications

### Identification of Insecure Configs

Configs with `accessLevel: "UDP"` can be modified via UDP:3500 without authentication:
- ecuMapVersion (ECU list translation)
- autopilotTrialExpireTime (trial duration)
- bmpWatchdogDisabled (battery watchdog)

### Identification of Secure Configs

Configs without `accessLevel` flag that control:
- Paid features (supercharger, FSD)
- Vehicle identity (VIN, country)
- Safety systems (restraints, brakes)

These require authenticated Hermes session.

### Attack Surface

```python
# Test UDP writeability
def is_insecure(config):
    return config.get("accessLevel") == "UDP"

insecure_configs = [c for c in gen3 if is_insecure(c)]
# Returns: ecuMapVersion, autopilotTrialExpireTime, bmpWatchdogDisabled
```

---

## Practical Applications

### Enum Value Lookup

```python
import json

with open('routines-database.json') as f:
    db = json.load(f)

def get_enum_values(config_name):
    for config in db['gen3']:
        if config['codeKey'] == config_name:
            return config['content']['enums']
    return None

# Get all autopilot levels
values = get_enum_values('autopilot')
# Returns: NONE=0, HIGHWAY=1, ENHANCED=2, SELF_DRIVING=3, BASIC=4
```

### Security Classification

```python
def classify_config(config):
    if config.get('accessLevel') == 'UDP':
        return 'INSECURE'
    elif config.get('accessLevel') == 'GTW':
        return 'HARDWARE_LOCKED'
    else:
        return 'STANDARD_AUTH'
```

---

## Cross-References

- [Gateway Security Model](../2-gateway/security-model.md) - Two-tier security
- [Config System](../2-gateway/config-system.md) - Config ID reference
- [Config Decoder](config-decoder.md) - Hash decoding

---

**Status:** VERIFIED ✅  
**Evidence:** Unhashed database from internal source  
**Last Updated:** 2026-02-07
