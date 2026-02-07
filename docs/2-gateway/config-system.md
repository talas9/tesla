# Gateway Configuration System

**Complete documentation of the 662 Gateway configuration entries, CRC validation, and storage format.**

---

## Overview

The Gateway ECU stores 662 configuration entries in flash memory. Each entry contains vehicle identity, feature flags, and hardware settings.

| Metric | Value |
|--------|-------|
| Total Configs | 662 entries |
| CRC Algorithm | CRC-8, polynomial 0x2F |
| Validation Rate | 100% verified |
| Source | Ryzen Gateway flash dump |

---

## Entry Format

### Structure

```
Offset  Size    Field           Description
+0x00   1       CRC             CRC-8 checksum (polynomial 0x2F)
+0x01   1       Length          Data length (including ID)
+0x02   2       Config ID       Big-endian config identifier
+0x04   N       Data            Variable-length data (up to 253 bytes)
```

### Example: VIN (Config ID 0x0000)

```
Hex:    A5 11 00 00 37 53 41 59 47 44 45 45 58 50 41 30 35 32 34 36 36
        │  │  └──┘  └────────────────────────────────────────────────┘
        │  │   ID   ASCII: "7SAYGDEEXPA052466" (VIN)
        │  Length: 17 bytes + 2 (ID) = 0x11
        CRC-8 checksum
```

---

## CRC-8 Algorithm

### Specification

| Parameter | Value |
|-----------|-------|
| Polynomial | 0x2F (47 decimal) |
| Initial Value | 0x00 |
| Input | [Config ID (2 bytes BE)] + [Data] |
| Output | 1 byte CRC |

### Python Implementation

```python
def calculate_crc8(config_id: int, data: bytes) -> int:
    """Calculate CRC-8 with polynomial 0x2F."""
    POLY = 0x2F
    crc = 0x00
    
    # Process config ID (big-endian)
    for byte in config_id.to_bytes(2, 'big'):
        crc ^= byte
        for _ in range(8):
            if crc & 0x80:
                crc = ((crc << 1) ^ POLY) & 0xFF
            else:
                crc = (crc << 1) & 0xFF
    
    # Process data
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x80:
                crc = ((crc << 1) ^ POLY) & 0xFF
            else:
                crc = (crc << 1) & 0xFF
    
    return crc
```

### Validation Results

```
Tested:    662 configs
Passed:    662 (100%)
Failed:    0
Algorithm: VERIFIED ✅
```

---

## Config ID Ranges

### Distribution

| Range | Count | Description |
|-------|-------|-------------|
| 0x0000 - 0x00A1 | 88 | Core vehicle configs (VIN, features) |
| 0x1400 - 0x147C | 384 | CAN mailbox configurations |
| 0x15xx | 9 | System configs |
| 0x4000+ | 2 | Large tables (routing) |
| 0xC000+ | 179 | Unknown (possibly code addresses) |

### Critical Config IDs

| ID | Name | Size | Access | Description |
|----|------|------|--------|-------------|
| 0x0000 | VIN | 17 | Secure | Vehicle Identification Number |
| 0x0001 | partNumber | ~12 | Secure | Gateway part number |
| 0x0003 | firmwareVersion | ~12 | Read-only | Firmware version string |
| 0x0006 | country | 2 | Secure | Country code (US, DE, CN) |
| 0x0010 | factoryMode | 1 | Secure | Factory mode status (bit 7) |
| 0x0011 | debugUart | 1 | UDP | Debug UART enable |
| 0x0014 | mapRegion | 1 | UDP | Navigation map region |
| 0x0020 | ecuMapVersion | 1 | UDP | ECU configuration version |
| 0x0025 | hash1 | 32 | Secure | Firmware hash 1 |
| 0x0026 | hash2 | 32 | Secure | Firmware hash 2 |
| 0x0029 | featureFlags | 1 | Mixed | Feature bitmap |

---

## Config Values Extracted

### Vehicle Identity

```
ID=0x0000: VIN = "7SAYGDEEXPA052466"
ID=0x0001: Part Number = "1684435-00-E"
ID=0x0003: Firmware P/N = "1960101-12-D"
ID=0x0006: Country = "US"
```

### Feature Flags

| ID | Value | Interpretation |
|----|-------|----------------|
| 0x0007 | 0x01 | Feature enabled |
| 0x0008 | 0x01 | Feature enabled |
| 0x0010 | 0x83 | Factory mode enabled (bit 7 set) |
| 0x0011 | 0x08 | Debug UART enabled |
| 0x0020 | 0x02 | Region: North America |
| 0x0023 | 0x03 | Hardware revision 3 |
| 0x0029 | 0x0F | All features enabled |

### Security Hashes

```
Hash 1 (0x0025): cbba81fb37a95522177d7bd571e60bef515ecede556410cd6733935da456afc6
Hash 2 (0x0026): 5f8cf2c792acce3f821c87ec9d303c18f7bcdcc920e4085ea2c84bc1d7286e99
```

---

## CAN Mailbox Configs (0x1400-0x147C)

### Format

```
Size: 13 bytes typically
Structure:
[CRC:1][0x0D][ID:2 BE][CAN_ID:2][Reserved:4][Filter_Mask:4][Status:1]
```

### Example Entry

```
0x1400: 00 00 00 00 FF FF FF FF 00 00 00 00 01
        │  │  └──┘  └────────┘  └────────┘  │
        │  │   ID   CAN ID     Mask         Status (enabled)
        │  Length
        CRC
```

### Status Values

| Value | Meaning |
|-------|---------|
| 0x00 | Disabled |
| 0x01 | Enabled |
| 0x02 | Unknown |

**Purpose:** Define which CAN message IDs are accepted/filtered by the Gateway.

---

## Large Configs (0x4000+)

| ID | Size | Description |
|----|------|-------------|
| 0x4000 | 192 bytes | Routing table or filter bank |
| 0x0415 | 57 bytes | System configuration |
| 0x15FE | 148 bytes | Array of IDs |
| 0x15FB | 41 bytes | Hex ASCII hash |

---

## Practical Usage

### Read Config via UDP

```python
import socket
import struct

GATEWAY_IP = "192.168.90.102"
GATEWAY_PORT = 3500
CMD_READ = 0x01

def read_config(config_id: int) -> bytes:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    packet = struct.pack('<HBH', 3, CMD_READ, config_id)
    sock.sendto(packet, (GATEWAY_IP, GATEWAY_PORT))
    response, _ = sock.recvfrom(1024)
    return response
```

### Write Config via UDP

```python
CMD_WRITE = 0x02

def write_config(config_id: int, data: bytes) -> bool:
    # Only works for INSECURE configs!
    crc = calculate_crc8(config_id, data)
    length = len(data) + 2  # ID + data
    
    packet = struct.pack('<HBBH', length + 3, CMD_WRITE, length, config_id)
    packet += bytes([crc]) + data
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(packet, (GATEWAY_IP, GATEWAY_PORT))
    # Check response for success/failure
```

### Validate Config CRC

```bash
python3 scripts/gateway_crc_validator.py parse gateway_flash.bin
```

---

## Security Classification

See [security-model.md](security-model.md) for full details on which configs are secure vs insecure.

### Quick Reference

| Type | Access | Examples |
|------|--------|----------|
| **Insecure** | UDP:3500 | mapRegion, units, debugUart |
| **Secure** | Hermes auth | VIN, country, supercharger |
| **Read-only** | N/A | firmwareVersion, hardware IDs |
| **Hardware** | Fuses | devSecurityLevel |

---

## Cross-References

- [UDP Protocol](udp-protocol.md) - Packet format for reading/writing
- [Security Model](security-model.md) - Secure vs insecure configs
- [Odin Routines Database](../3-odin/routines-database.md) - Config access levels
- [data/gateway/gateway_configs_parsed.txt](https://github.com/talas9/tesla/blob/master/data/gateway/gateway_configs_parsed.txt) - All 662 configs

---

**Status:** COMPLETE ✅  
**Evidence:** Flash dump analysis, 100% CRC validation  
**Last Updated:** 2026-02-07
