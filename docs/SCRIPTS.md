# Tools & Scripts Download

All analysis tools and scripts are available in the repository.

---

## Python Scripts

### 1. Gateway CRC Validator

**File:** `scripts/gateway_crc_validator.py` (10.5KB)  
**Purpose:** Calculate and validate CRC-8 checksums for Gateway configs

**Usage:**
```bash
python3 scripts/gateway_crc_validator.py --config-id 0x0020 --data "01"
```

**Features:**
- CRC-8 calculation (polynomial 0x2F, init 0xFF)
- Config format validator
- Batch validation mode
- 100% validation rate on 662 configs

**Download:** [gateway_crc_validator.py](https://github.com/talas9/tesla/raw/master/scripts/gateway_crc_validator.py)

---

### 2. Gateway Database Query Tool

**File:** `scripts/gateway_database_query.py`  
**Purpose:** Query Gateway config database

**Usage:**
```bash
# Search by name
python3 scripts/gateway_database_query.py --search "mapRegion"

# Search by ID
python3 scripts/gateway_database_query.py --id 0x0020

# List all configs
python3 scripts/gateway_database_query.py --list
```

**Features:**
- Search configs by name or ID
- Display config metadata
- Export to JSON/CSV
- Access level detection

**Download:** [gateway_database_query.py](https://github.com/talas9/tesla/raw/master/scripts/gateway_database_query.py)

---

### 3. Gateway Config Decoder

**File:** `scripts/decode_gateway_config.py` (9.1KB)  
**Purpose:** Decode SHA256-hashed Odin config-options.json files

**Usage:**
```bash
# Decode Model 3 config
python3 scripts/decode_gateway_config.py /opt/odin/data/Model3/config-options.json

# Specify output directory
python3 scripts/decode_gateway_config.py config.json --output ./decoded/
```

**Features:**
- Decodes SHA256-hashed keys and values
- Extracts all enum definitions (64+ configs)
- Generates human-readable text output
- Generates machine-readable JSON output
- Maps Access IDs to config names

**Output Files:**
- `config-options-FULL-DECODED.json` - Machine-readable
- `config-options-FULL-DECODED.txt` - Human-readable

**Decoded Configs Include:**
- `packEnergy` (ID 14) - Battery capacity (SR/LR/MR)
- `factoryMode` (ID 15) - Factory mode enable/disable
- `dasHw` (ID 59) - FSD hardware (HW2.5/3/4)
- `brakeHWType` (ID 17) - 15 brake variants
- `mapRegion` (ID 67) - 14 navigation regions
- And 60+ more hardware/feature configs

**Download:** [decode_gateway_config.py](https://github.com/talas9/tesla/raw/master/scripts/decode_gateway_config.py)

---

### 4. ODJ File Decryptor

**File:** `scripts/decrypt_odj.py` (9.6KB)  
**Purpose:** Decrypt Fernet-encrypted Odin Diagnostic Job (ODJ) files

**Usage:**
```bash
# Decrypt single ODJ file
python3 scripts/decrypt_odj.py /opt/odin/data/Model3/odj/RCM_VIN_LEARN.odj

# Decrypt all ODJ files in directory
python3 scripts/decrypt_odj.py /opt/odin/data/Model3/odj/ --recursive

# Analyze decrypted content
python3 scripts/decrypt_odj.py file.odj --analyze
```

**Features:**
- Decrypts Fernet (AES-128-CBC + HMAC) encrypted ODJ files
- Uses hardcoded Odin password from firmware
- PBKDF2-HMAC-SHA256 key derivation (123456 iterations)
- Extracts diagnostic routines (VIN write, security access, etc.)
- Analyzes routine IDs, DIDs, and security levels
- Batch processing with recursive directory support

**Encryption Details:**
- **Algorithm:** Fernet (symmetric encryption)
- **Password:** `cmftubxi7wlvmh1wmbzz00vf1ziqezf6`
- **Iterations:** 123456
- **Source:** Decompiled from `binary_metadata_utils.py`

**Example Output:**
```
ODJ ANALYSIS: RCM_VIN_LEARN.odj
Routines: 2
  - LEARN_VIN (ID: 0x0404, Security: 0)
  - VIN_RESET (ID: 0xF102, Security: 3)
Data Identifiers: 15
  - 0xF190: VIN
```

**Download:** [decrypt_odj.py](https://github.com/talas9/tesla/raw/master/scripts/decrypt_odj.py)

---

### 5. Odin Config Mapper

**File:** `scripts/match_odin_to_configs.py`  
**Purpose:** Map Odin `access_id` to Gateway config IDs

**Usage:**
```bash
python3 scripts/match_odin_to_configs.py
```

**Features:**
- Maps Odin database to Gateway configs
- Identifies security flags
- Exports mapping table

**Download:** [match_odin_to_configs.py](https://github.com/talas9/tesla/raw/master/scripts/match_odin_to_configs.py)

---

## Shell Scripts

### 1. Evidence Audit Script

**File:** `scripts/audit-script.sh`  
**Purpose:** Audit evidence quality across all documents

**Usage:**
```bash
bash scripts/audit-script.sh
```

**Download:** [audit-script.sh](https://github.com/talas9/tesla/raw/master/scripts/audit-script.sh)

---

## Data Files

### Configuration Database
- **gateway_configs_parsed.txt** (42KB) - 662 parsed Gateway configs
- **odin-config-decoded.json** (156KB) - Unhashed Odin database
- **can-message-database-VERIFIED.csv** - Verified CAN messages

### String Extractions
- **93-gateway-ALL-STRINGS.csv** (2.5MB) - 37,702 strings from firmware

### Disassembly (Large Files)
- **gateway_full_disassembly.txt** (100MB+) - Complete PowerPC disassembly
  - *Available on request due to size*

**Download all data:** [Clone repository](https://github.com/talas9/tesla)

---

## Installation

```bash
# Clone repository
git clone https://github.com/talas9/tesla.git
cd tesla

# Install Python dependencies (if needed)
pip install -r requirements.txt

# Run tools
python3 scripts/gateway_crc_validator.py --help
```

---

## Requirements

**Python 3.7+** with standard library (no external dependencies for core scripts)

Optional:
- `pandas` for CSV exports
- `requests` for network tools

---

## Contributing

Found a bug or want to add a feature? Open an issue or pull request!

**Repository:** https://github.com/talas9/tesla

---

## License

These tools are provided for security research purposes. Use responsibly.

**Disclaimer:** These tools are for educational and research purposes only. Do not use on vehicles you do not own or have permission to test.
