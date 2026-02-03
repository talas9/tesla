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

### 3. Odin Config Mapper

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

**Download all data:** [Clone repository](https://github.com/talas9/tesla-research)

---

## Installation

```bash
# Clone repository
git clone https://github.com/talas9/tesla-research.git
cd tesla-research

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

**Repository:** https://github.com/talas9/tesla-research

---

## License

These tools are provided for security research purposes. Use responsibly.

**Disclaimer:** These tools are for educational and research purposes only. Do not use on vehicles you do not own or have permission to test.
