# Gateway Architecture

**Hardware and firmware architecture of Tesla's Gateway ECU.**

---

## Hardware Specifications

### Processor

| Specification | Value |
|---------------|-------|
| Chip | NXP MPC5748G |
| Core | PowerPC e200z7 |
| Instruction Set | VLE (Variable Length Encoding) |
| Flash Size | 6 MB |
| RAM | ~384 KB SRAM |

**Evidence:** JTAG ID pattern analysis, Ghidra disassembly confirms VLE encoding.

### Debug Interface

| Pin | Function |
|-----|----------|
| Mini-HDMI connector | Debug/JTAG interface |
| Pins 4+6 short | Recovery mode trigger |

**Evidence:** [Hardware pinout analysis](https://github.com/talas9/tesla/blob/master/data/gateway/)

---

## Memory Map

### Flash Layout

| Address Range | Size | Description |
|---------------|------|-------------|
| 0x00000000 - 0x00018FFF | ~100 KB | Bootloader region |
| 0x00019000 - 0x00030000 | ~100 KB | Configuration database |
| 0x00030000 - 0x00403000 | ~4 MB | Main firmware code |
| 0x00403000 - 0x00500000 | ~1 MB | Data tables (CAN messages, metadata) |
| 0x00500000 - 0x005F0000 | ~1 MB | Additional firmware/data |

**Evidence:** Flash dump analysis from [80-ryzen-gateway-flash-COMPLETE.md](https://github.com/talas9/tesla/blob/master/data/gateway/)

### Configuration Storage

```
Base Address: 0x19000
End Address:  0x30000 (approximate)
Entry Count:  662 configs
Format:       [CRC:1][Len:1][ID:2 BE][Data:variable]
```

**Entry Format Example:**
```
Offset   Data              Meaning
+0x00    A5                CRC-8 checksum
+0x01    11                Length (17 bytes)
+0x02    00 00             Config ID (0x0000 = VIN)
+0x04    37 53 41 59...    ASCII VIN "7SAY..."
```

---

## Firmware Structure

### Binary Analysis

| Metric | Value |
|--------|-------|
| Total Size | 6,225,920 bytes |
| String Count | 37,702 |
| Function Count | ~8,000 (estimated) |
| CAN Message Handlers | 6,647 entries |

### Key Regions

| Offset | Content | Evidence |
|--------|---------|----------|
| 0x00950 | Jump table start | Disassembly pattern |
| 0x00CAC | Jump table end | Disassembly pattern |
| 0x01044 | Factory gate check | Symbol pattern |
| 0x36730 | SHA-256 hash | 32-byte hash value |
| 0x403000 | CAN metadata table | 21,000+ entries |

---

## CAN Bus Architecture

### Bus Bridging

The Gateway bridges multiple CAN networks:

```
┌─────────────┐
│   CHASSIS   │◄──┐
│    CAN      │   │
└─────────────┘   │
                  │     ┌─────────────┐
┌─────────────┐   ├────▶│   GATEWAY   │
│  POWERTRAIN │◄──┤     │     ECU     │
│    CAN      │   │     └─────────────┘
└─────────────┘   │            ▲
                  │            │
┌─────────────┐   │     ┌──────┴──────┐
│   BODY      │◄──┤     │  Ethernet   │
│    CAN      │   │     │ 192.168.90.x│
└─────────────┘   │     └─────────────┘
                  │
┌─────────────┐   │
│  INFOTAIN   │◄──┘
│    CAN      │
└─────────────┘
```

### CAN Message Database

| Metric | Value |
|--------|-------|
| Total Entries | 6,647 |
| ID Range | 0x000 - 0x7FF (standard) |
| Data Format | CSV with ID, length, handler |

**Location:** [data/gateway/can-message-database-VERIFIED.csv](https://github.com/talas9/tesla/blob/master/data/gateway/can-message-database-VERIFIED.csv)

---

## Network Interface

### Ethernet

| Parameter | Value |
|-----------|-------|
| IP Address | 192.168.90.102 |
| Subnet | 192.168.90.0/24 |
| Gateway | 192.168.90.1 |

### Ports

| Port | Protocol | Service |
|------|----------|---------|
| 3500 | UDP | Configuration API |
| 69 | TFTP | Firmware transfer |
| 25956 | TCP | Emergency updater (CAN flood) |

---

## Bootloader

### Factory Gate

The bootloader contains a "factory gate" check:

| Offset | Function |
|--------|----------|
| 0x01044 | Factory mode check |
| Result | Determines fuse state (dev vs prod) |

**Fused (Production):**
- JTAG readout protection active
- Signature verification enforced
- Factory mode blocked

**Unfused (Development):**
- JTAG access allowed
- Dev keys accepted
- Factory mode available

---

## Security Features

### Hardware Security

| Feature | Status |
|---------|--------|
| JTAG Fuse | Blown on production |
| Signature Keys | Ed25519 (hardware locked) |
| Flash Protection | Write-protected regions |

### Firmware Verification

```
Hash 1 (0x0025): cbba81fb37a95522177d7bd571e60bef515ecede556410cd6733935da456afc6
Hash 2 (0x0026): 5f8cf2c792acce3f821c87ec9d303c18f7bcdcc920e4085ea2c84bc1d7286e99
```

These SHA-256 hashes verify firmware integrity and are checked at boot.

---

## Comparison: Intel MCU vs Ryzen MCU

| Feature | Intel MCU Gateway | Ryzen MCU Gateway |
|---------|-------------------|-------------------|
| Config Count | ~90 | 662 |
| Flash Layout | Smaller | Expanded regions |
| CAN Mailbox Configs | ~50 | 384 (0x1400-0x147C) |

**Note:** Ryzen-based vehicles have significantly larger configuration databases.

---

## Research Artifacts

| File | Description |
|------|-------------|
| `data/gateway/gateway_configs_parsed.txt` | All 662 parsed configs |
| `data/gateway/strings.csv` | 37,702 extracted strings |
| `data/gateway/can-message-database-VERIFIED.csv` | CAN message entries |

---

## Tools for Analysis

### Ghidra

```bash
# Load with PowerPC VLE processor
# Base address: 0x00000000
# Entry point: 0x00000000 or 0x00001000
```

### Binary Ninja

```bash
# Requires VLE plugin for proper disassembly
# See scripts/ghidra-vle-analysis.py
```

---

**Status:** VERIFIED  
**Evidence:** JTAG flash dump, Ghidra disassembly, CRC validation  
**Last Updated:** 2026-02-07
