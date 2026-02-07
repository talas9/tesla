# Tesla Gateway Configuration Options - Fully Decoded

Complete decoded Gateway configuration files for all available Tesla models.

## Files

### Model 3 (Latest Firmware - 2024+)
- **config-options-FULL-DECODED.json** (86 KB) - Machine-readable
- **config-options-FULL-DECODED.txt** (56 KB) - Human-readable
- **Decoded:** 82 config keys, 299/308 values (97%)
- **Salt:** `gj55iz2tgghun9nyw2sa8s5oxsykmfwo`

### Model Y (Latest Firmware - 2024+)
- **config-options-FULL-DECODED.json** (88 KB) - Machine-readable
- **config-options-FULL-DECODED.txt** (58 KB) - Human-readable
- **Decoded:** 84 config keys, 291/314 values (92%)
- **Salt:** `2xz83kgreak7h956dgb3mdmd260c6cun`

### Model 3 (Old Firmware - Feb 2021)
- **config-options-decoded.json** (156 KB) - Already decoded (not hashed)
- **Format:** Plain JSON (older firmware didn't use SHA256 hashing)

### Model S / Model X (MCU2)
**Note:** Model S/X MCU2 firmware does not use the config-options.json format.
- No config-options.json file in extracted firmware
- Model S/X use different configuration system
- May use older MCU1 config format or different Odin version

## Decoded Configuration Keys

### Critical Configs (All Models)

| Config Name | Access ID | Description | Values |
|-------------|-----------|-------------|--------|
| packEnergy | 14 | Battery capacity | SR (0), LR (1), MR (2) |
| factoryMode | 15 | Factory mode enable | Disabled (2), Enabled (3) |
| restraintsHardwareType | 16 | Airbag calibration | 10+ regional variants |
| brakeHWType | 17 | Brake hardware | 15 variants (Brembo, Hitachi, etc.) |
| dasHw | 59 | FSD hardware | HW2.5 (3), HW3 (4), HW4 (5) |
| mapRegion | 67 | Navigation region | 14 regions (NA, EU, CN, etc.) |
| chassisType | N/A | Chassis variant | MODEL_3 (2), MODEL_Y (3) |

### New Decoded Values (Brute-forced)

**Exterior Colors:**
- MIDNIGHT_CHERRY_RED
- QUICKSILVER  
- ABYSS_BLUE (Deep Blue Metallic)

**Chassis:**
- MODEL_Y_CHASSIS (3) - Not in old reference

### Decoding Statistics

| Model | Total Keys | Decoded Keys | Total Values | Decoded Values | Success Rate |
|-------|------------|--------------|--------------|----------------|--------------|
| Model 3 (Latest) | 156 | 82 | 308 | 299 | 97% |
| Model Y (Latest) | 160 | 84 | 314 | 291 | 92% |
| Model 3 (Old) | N/A | All | N/A | All | 100% (not hashed) |

## Config File Format

### Latest Firmware (Hashed)

```json
{
  "salt": "gj55iz2tgghun9nyw2sa8s5oxsykmfwo",
  "hashed": {
    "SHA256(key+salt)": ["SHA256(value+key+salt)", ...]
  },
  "public": {
    "key": {
      "accessId": 14,
      "content": {"enums": [...]},
      "description": "...",
      "odinReadWriteAccess": "RepairAndMaintenance"
    }
  }
}
```

### Old Firmware (Plain JSON)

```json
{
  "gen3": [
    {
      "codeKey": "packEnergy",
      "accessId": 14,
      "content": {
        "enums": [
          {"codeKey": "SR", "value": 0, "description": "Standard Range"},
          {"codeKey": "LR", "value": 1, "description": "Long Range"}
        ]
      }
    }
  ]
}
```

## Hashing Algorithm

**Key Hash:**
```
SHA256(key_name + salt)
```

**Value Hash:**
```
SHA256(enum_value + key_name + salt)
```

**Example:**
```python
key = "brakeHWType"
salt = "gj55iz2tgghun9nyw2sa8s5oxsykmfwo"

key_hash = SHA256("brakeHWTypegj55iz2tgghun9nyw2sa8s5oxsykmfwo")
         = "b845fd7008982fd6ae79d93c29ee801f21287afa87afffd604d8e5f49b282902"

value = "BREMBO_P42_MANDO_43MOC"
value_hash = SHA256("BREMBO_P42_MANDO_43MOCbrakeHWTypegj55iz2tgghun9nyw2sa8s5oxsykmfwo")
           = "147b5c3c7870642995957f10b21c9576b2c00a5a551a0ac549c15381685e255e"
```

## Usage

### View Decoded Configs

**JSON (Machine-readable):**
```bash
jq '.configs.packEnergy' Model3/config-options-FULL-DECODED.json
```

**Text (Human-readable):**
```bash
grep -A 20 "CONFIG: packEnergy" Model3/config-options-FULL-DECODED.txt
```

### Decode Your Own Config

```bash
# Decode any config-options.json
python3 ../../scripts/decode_gateway_config.py /path/to/config-options.json
```

### Search for Specific Config

```bash
# Find all configs with "battery" in description
jq '.configs | to_entries[] | select(.value.description | contains("battery"))' \
  Model3/config-options-FULL-DECODED.json
```

## Access Levels

| Level | Description | Who Can Modify |
|-------|-------------|----------------|
| RepairAndMaintenanceReadOnly | Read-only | Tesla Service (read only) |
| RepairAndMaintenance | Read/write | Tesla Service Center |
| SecureOperation | Secure write | Tesla Service (signed) |
| ResearchAndDevelopment | R&D only | Tesla Engineering |

## Unknown Values

Some configs have unknown values (5-8% per model):
- **Reason:** New enum values not in reference database
- **Reference:** From Feb 2021 firmware (outdated)
- **Solution:** Brute-force common patterns or wait for updated reference

**Known Unknown Categories:**
- New exterior colors (Ultra Red, Stealth Grey, etc.)
- New hardware variants (RDU cable types, etc.)
- Performance package options
- EPAS types
- RGB lighting variants

## Tools

**Decoder:**
- `../../scripts/decode_gateway_config.py` - Decode hashed configs
- `../../scripts/bruteforce_unknown_hashes.py` - Find unknown values

**Documentation:**
- `../../docs/gateway/CONFIG-DECODER-COMPLETE.md` - Complete algorithm
- `../../docs/tools/ODIN-TOOLS.md` - Tools guide

## Sources

- **Latest Firmware:** model3y-extracted (2024+)
- **Old Firmware:** old-firmware (Feb 2021)
- **MCU2 Firmware:** mcu2-extracted (Model S/X)
- **Reference Database:** Unhashed Odin config from older firmware
- **Brute-force Additions:** 4 new values discovered through pattern matching

## Security Analysis

**Hashing Purpose:** Code obfuscation, not security
- Salt is public (included in same file)
- Algorithm is standard SHA256
- Reference enums reveal all values
- Easily reversible with enum database

**Real Security:** Gateway firmware validation
- Writes validated by Gateway
- Command 0x33 requires Tesla signature
- Factory mode requires unfused vehicle
- Safety-critical configs have additional checks

---

**Last Updated:** 2026-02-07  
**Total Files:** 6 (3 JSON + 3 TXT for latest models, 1 JSON for old firmware)  
**Models Covered:** Model 3, Model Y (Model S/X use different format)
