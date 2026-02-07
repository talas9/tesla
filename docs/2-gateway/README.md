# Gateway ECU Research

**Complete reverse engineering of Tesla's Gateway Electronic Control Unit.**

---

## Overview

The Gateway ECU is Tesla's central CAN bus aggregator, bridging all vehicle networks and storing critical configuration data. This research documents:

- **Hardware**: NXP MPC5748G (PowerPC e200z7 VLE core)
- **Firmware**: 6 MB binary, fully extracted
- **Configs**: 662 entries with CRC-8 validation
- **Security**: Two-tier model (UDP insecure, Hermes secure)

---

## Documentation

| Document | Description |
|----------|-------------|
| [architecture.md](architecture.md) | Hardware, memory map, firmware structure |
| [config-system.md](config-system.md) | 662 configs, CRC algorithm, storage format |
| [security-model.md](security-model.md) | Two-tier security, secure vs insecure configs |
| [udp-protocol.md](udp-protocol.md) | Port 3500 API format and commands |
| [firmware-analysis.md](firmware-analysis.md) | Disassembly findings, function table |

---

## Quick Facts

| Metric | Value |
|--------|-------|
| Processor | NXP MPC5748G |
| Architecture | PowerPC e200z7 VLE |
| Firmware Size | 6,225,920 bytes (6 MB) |
| Config Count | 662 entries |
| CRC Polynomial | 0x2F (CRC-8) |
| UDP Port | 3500 |
| Emergency Port | 25956 (CAN flood) |

---

## Key Findings

### 1. Configuration System ✅ COMPLETE

- **662 configuration entries** extracted from Ryzen Gateway flash dump
- **CRC-8 validation** with polynomial 0x2F (100% verification rate)
- **Two-tier security**: UDP-accessible vs Hermes-authenticated
- **Entry format**: `[CRC:1][Len:1][ID:2 BE][Data:variable]`

### 2. Security Model ✅ VERIFIED

**Insecure (UDP port 3500):**
- Map region, display units, preferences
- No authentication required
- Any device on 192.168.90.0/24 can modify

**Secure (Hermes + gw-diag):**
- VIN, country, supercharger access
- Requires authenticated Tesla session
- Cryptographic signature validation

### 3. CAN Message Database ✅ COMPLETE

- **6,647 CAN message entries** extracted from firmware
- Message IDs, data lengths, and handlers documented
- See [data/gateway/can-message-database-VERIFIED.csv](https://github.com/talas9/tesla/blob/master/data/gateway/can-message-database-VERIFIED.csv)

### 4. Firmware Strings ✅ EXTRACTED

- **37,702 strings** extracted from 6MB binary
- Config names, function references, error messages
- See [data/gateway/strings.csv](https://github.com/talas9/tesla/blob/master/data/gateway/strings.csv)

---

## Tools

| Tool | Purpose |
|------|---------|
| [gateway_database_query.py](https://github.com/talas9/tesla/blob/master/scripts/gateway_database_query.py) | UDP config read/write |
| [gateway_crc_validator.py](https://github.com/talas9/tesla/blob/master/scripts/gateway_crc_validator.py) | CRC-8 calculation |
| gw-diag (Tesla) | Authenticated config access |

---

## Network Access

```
Gateway IP: 192.168.90.102
UDP Port:   3500 (config API)
TFTP Port:  69 (firmware updates)
Emergency:  25956 (CAN flood trigger)
```

---

## Related Research

- [Odin Routines Database](../3-odin/routines-database.md) - Access levels from Odin
- [CAN Flood Attack](../5-attacks/can-flood.md) - Opening port 25956
- [VIN Write Attack](../5-attacks/vin-write.md) - JTAG flash modification

---

**Status:** COMPLETE  
**Last Updated:** 2026-02-07
