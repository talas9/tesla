# Tools Reference

**Documentation for research tools and scripts.**

---

## Available Tools

| Tool | Purpose | Status |
|------|---------|--------|
| [decode_gateway_config.py](decode_gateway_config.py) | Decode SHA256 config hashes | ✅ Working |
| [decrypt_odj.py](decrypt_odj.py) | Decrypt Odin ODJ files | ✅ Working |
| [gateway_crc_validator.py](gateway_crc_validator.py) | Validate/calculate CRC-8 | ✅ Working |
| [gateway_database_query.py](gateway_database_query.py) | UDP config read/write | ✅ Working |
| [openportlanpluscan.py](openportlanpluscan.py) | CAN flood attack | ⚠️ Tested |

---

## Quick Reference

### Decode Odin Config Hashes

```bash
python3 scripts/decode_gateway_config.py \
  /opt/odin/data/Model3/config-options.json
```

### Decrypt ODJ File

```bash
python3 scripts/decrypt_odj.py input.odj output.json
```

### Read Gateway Config

```bash
python3 scripts/gateway_database_query.py read 0x0014
```

### Validate Config CRC

```bash
python3 scripts/gateway_crc_validator.py parse gateway_flash.bin
```

---

## Tool Documentation

| Document | Description |
|----------|-------------|
| [config-decoder.md](config-decoder.md) | SHA256 decoding tool |
| [odj-decryptor.md](odj-decryptor.md) | ODJ decryption tool |
| [gateway-tools.md](gateway-tools.md) | Gateway UDP tools |
| [scripts-reference.md](scripts-reference.md) | All scripts overview |

---

## Installation

### Dependencies

```bash
# Python packages
pip install cryptography pycryptodome python-can

# For CAN tools (Linux)
# Install PCAN driver from PEAK Systems
```

### Scripts Location

All tools are in the `scripts/` directory:

```
scripts/
├── decode_gateway_config.py    # Odin hash decoder
├── decrypt_odj.py              # ODJ decryptor
├── gateway_crc_validator.py    # CRC-8 tools
├── gateway_database_query.py   # UDP access
├── openportlanpluscan.py       # CAN flood
├── bruteforce_unknown_hashes.py # Hash brute-force
├── match_odin_to_configs.py    # Config mapping
└── signatures.json             # Firmware signatures
```

---

## Common Tasks

### Read All Gateway Configs

```python
from scripts.gateway_database_query import read_config

for config_id in range(0x0000, 0x00A2):
    try:
        data = read_config(config_id)
        print(f"0x{config_id:04x}: {data.hex()}")
    except:
        pass
```

### Decode Config File and Export

```bash
python3 scripts/decode_gateway_config.py config-options.json \
  --output decoded/
# Creates: decoded/config-options-FULL-DECODED.json
# Creates: decoded/config-options-FULL-DECODED.txt
```

### Calculate CRC-8 for New Config

```python
from scripts.gateway_crc_validator import calculate_crc8

config_id = 0x0014
data = bytes([0x01])  # Map region = EU
crc = calculate_crc8(config_id, data)
print(f"CRC: 0x{crc:02x}")
```

---

## Data Files

| File | Description |
|------|-------------|
| `data/gateway/gateway_configs_parsed.txt` | 662 parsed configs |
| `data/gateway/strings.csv` | 37,702 firmware strings |
| `data/gateway/can-message-database-VERIFIED.csv` | CAN entries |
| `scripts/signatures.json` | Firmware signature database |

---

**Last Updated:** 2026-02-07
