# Gateway ECU — System Overview

**Purpose:** Complete introduction to Tesla Gateway ECU architecture  
**Related Docs:** [GATEWAY-FIRMWARE.md](GATEWAY-FIRMWARE.md), [GATEWAY-CONFIGS.md](GATEWAY-CONFIGS.md), [GATEWAY-SECURITY.md](GATEWAY-SECURITY.md)  
**Evidence Quality:** ✅ Verified (hardware specs, firmware extracted, disassembly confirmed)

---

## TL;DR

- **What:** PowerPC-based MPC5748G microcontroller managing vehicle configuration and CAN bus routing
- **Role:** Central configuration hub storing VIN, features, regions, hardware mappings (662 configs total)
- **Security:** Two-tier model (UDP-accessible vs Hermes-authenticated configs)
- **Firmware:** 6MB binary, completely reverse-engineered (1.5M line disassembly)
- **Key finding:** Some configs modifiable without authentication via UDP port 3500

---

## Table of Contents

- [What Is the Gateway?](#what-is-the-gateway)
- [Hardware Architecture](#hardware-architecture)
- [Firmware Overview](#firmware-overview)
- [Configuration System](#configuration-system)
- [Network Integration](#network-integration)
- [Security Model](#security-model)
- [Physical Location](#physical-location)
- [Cross-References](#cross-references)

---

## What Is the Gateway?

### Role in Tesla Architecture

The **Gateway ECU** is the central configuration and CAN bus routing controller in Tesla vehicles (Model S/X/3/Y). It serves as:

1. **Configuration Store** — Holds 662 vehicle configuration entries including:
   - Vehicle identity (VIN, part numbers, serial numbers)
   - Feature enablement (Autopilot, supercharging, trial periods)
   - Regional settings (map region, country code)
   - Hardware mappings (ECU configurations, CAN mailbox filters)

2. **CAN Bus Router** — Aggregates and routes messages between:
   - Body CAN (interior, HVAC, doors, seats)
   - Chassis CAN (suspension, steering, brakes)
   - Powertrain CAN (battery, motors, inverters)
   - Ethernet backbone (MCU, APE, modem)

3. **Update Gateway** — Manages firmware updates for other ECUs via TFTP/CAN

4. **Diagnostic Interface** — Provides service tool access via UDP and authenticated channels

### Why It Matters

**The Gateway controls what your Tesla can do:**
- Which features are enabled (Autopilot, FSD, Performance Mode)
- Where you can supercharge (regional restrictions)
- What hardware configurations are recognized
- Which CAN messages are routed vs. filtered

**Security implications:**
- Some configs modifiable without authentication (UDP port 3500)
- VIN and critical identifiers stored here
- Feature flags can be toggled (though backend may reject changes)

---

## Hardware Architecture

### Primary Microcontroller

**Chip:** NXP (Freescale) MPC5748G  
**Architecture:** PowerPC VLE (Variable Length Encoding)  
**Core:** e200z4 (dual-core, lockstep configuration)  
**Clock:** 160 MHz  
**Flash:** 6 MB (firmware + configuration storage)  
**RAM:** 768 KB SRAM  
**CAN:** 8x FlexCAN controllers

**Key features:**
- Automotive-grade (AEC-Q100 qualified)
- Hardware Security Module (HSM) with crypto acceleration
- Configurable memory protection (MPU)
- Lockstep cores for safety-critical applications

### Security Co-Processor (SPC)

**Chip:** Custom Tesla security processor (ARM-based)  
**Purpose:** Cryptographic operations, secure storage, authentication  
**Functions:**
- Hermes authentication (mTLS handshake)
- Signed command validation
- Secure config write operations
- Hardware fuse management

**Security features:**
- Hardware fuses (one-time programmable)
- Secure boot chain
- Isolated crypto operations
- Anti-tamper detection

**Physical attack:** SPC chip can be replaced via BGA rework (~$600-5,200 equipment), bypassing all fuse-based protections. See [ATTACK-SPC-REPLACEMENT.md](ATTACK-SPC-REPLACEMENT.md).

### Memory Map (MPC5748G)

| Address Range | Size | Function |
|---------------|------|----------|
| 0x00000000 - 0x005FFFFF | 6 MB | Flash (firmware + configs) |
| 0x40000000 - 0x400BFFFF | 768 KB | SRAM |
| 0xF0000000 - 0xFFFFFFFF | — | Memory-mapped peripherals |
| 0xFC000000 - 0xFC1FFFFF | 2 MB | FlexCAN modules |
| 0xFFE00000 - 0xFFE0FFFF | 64 KB | Boot ROM |

**Detailed memory map:** See [GATEWAY-FIRMWARE.md](GATEWAY-FIRMWARE.md#memory-map)

### Peripherals

**CAN Controllers:**
- 8x FlexCAN modules (up to 64 mailboxes each)
- Configurable message filtering
- Hardware-accelerated CAN-FD support

**Ethernet:**
- 10/100 Mbps Fast Ethernet MAC
- Connected to vehicle network (192.168.90.102)
- UDP configuration server (ports 1050, 3500)

**UART:**
- Debug console (disabled on production vehicles)
- Accessible via mini-HDMI debug port (some models)

**SPI:**
- External flash (if present)
- SPC communication

---

## Firmware Overview

### Binary Characteristics

**File size:** 6,029,152 bytes (exactly 6.0 MB)  
**Format:** Raw PowerPC binary (no ELF headers in production flash)  
**Endianness:** Big-endian (PowerPC standard)  
**Compression:** None (raw binary)

**Extraction method:** JTAG flash readout (requires unfused chip or voltage glitching)

### Firmware Regions

| Offset | Size | Content |
|--------|------|---------|
| 0x000000 - 0x000100 | 256 B | Boot vector table (magic: DEADBEEF at 0x2C) |
| 0x000100 - 0x3FFFFF | ~4 MB | Executable code (.text section) |
| 0x400000 - 0x5FFFFF | ~2 MB | Data sections (strings, tables, configs) |
| 0x401150 - 0x401800 | 1.7 KB | Config name string table |
| 0x402400 - 0x402590 | 400 B | Config ID index array (200 entries) |
| 0x403000 - 0x410000 | 56 KB | Config metadata table (21,000+ entries) |
| 0x36730 | 64 B | SHA-256 constants (firmware verification) |

**Complete disassembly:** See [GATEWAY-FIRMWARE.md](GATEWAY-FIRMWARE.md)

### RTOS

**Operating system:** FreeRTOS  
**Version:** 10.x (inferred from task names)  
**Scheduler:** Preemptive, priority-based  
**Tasks identified:** 15+ (udpApiTask, gwXmit100Task, teleCANETHis_task, etc.)

**Task list:** See [GATEWAY-FIRMWARE.md](GATEWAY-FIRMWARE.md#freertos-tasks)

---

## Configuration System

### Overview

The Gateway stores **662 unique configuration entries** in flash memory, each identified by a 16-bit config ID and protected by CRC-8 checksum.

**Config format:**
```
[CRC:1] [LENGTH:1] [ID:2_BE] [DATA:variable]
```

**CRC algorithm:** CRC-8, polynomial 0x2F, initial value 0x00

**Example (config 0x0000, VIN):**
```
7A 12 00 00 37 53 41 59 47 44 45 45 58 50 41 30 35 32 34 36 36
^^CRC  ^^len ^^^^ID  ^^^^^^^^^^^^^^^^^^^^^^^ VIN (17 bytes ASCII)
```

**Detailed config system:** See [GATEWAY-CONFIGS.md](GATEWAY-CONFIGS.md)

### Configuration Categories

**Identity configs (0x0000-0x0010):**
- 0x0000: VIN (17 bytes ASCII)
- 0x0001: Gateway part number
- 0x0003: Firmware part number
- 0x0006: Country code (2 bytes ASCII)

**Feature configs (0x0020-0x00A0):**
- Feature flags (Autopilot, FSD, Performance Mode)
- Trial period timers (expiration timestamps)
- Regional enablement (supercharger access)

**Hardware configs (0x1400-0x147C):**
- CAN mailbox filters (384 entries)
- ECU mapping (which ECUs are present)
- Sensor configurations

**Security configs (0x0015, 0x0025-0x0026):**
- 0x0015: devSecurityLevel (factory vs gated)
- 0x0025-0x0026: Firmware hashes (SHA-256)
- 0x0037-0x0038: Cryptographic keys (prodCodeKey, prodCmdKey)

**Complete config list:** See [GATEWAY-CONFIGS.md](GATEWAY-CONFIGS.md#complete-config-list)

### CRC Algorithm

**Polynomial:** 0x2F (47 decimal)  
**Initial value:** 0x00  
**Width:** 8 bits  
**Validation:** 100% success on all 662 configs

**Python implementation:**
```python
def crc8(data):
    crc = 0x00
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x80:
                crc = (crc << 1) ^ 0x2F
            else:
                crc = crc << 1
    return crc & 0xFF
```

**Validation tool:** `scripts/gateway_crc_validator.py`

**Evidence:** CRC algorithm confirmed by testing on 662 extracted configs (100% match)

---

## Network Integration

### IP Address

**Address:** 192.168.90.102  
**Hostname:** `gw`  
**Subnet:** 192.168.90.0/24 (vehicle internal network)

### Network Services

| Port | Protocol | Service | Authentication |
|------|----------|---------|----------------|
| 1050 | UDP | gwxfer (file transfer) | None |
| 3500 | UDP | Config read/write API | None (for insecure configs) |
| 25956 | TCP | Emergency updater shell | None (opened via CAN flood) |

**Detailed protocol analysis:** See [GATEWAY-PROTOCOLS.md](GATEWAY-PROTOCOLS.md)

### Network Topology

```
┌─────────────────────────────────────────────────────────────┐
│           Tesla Vehicle Network (192.168.90.0/24)            │
└─────────────────────────────────────────────────────────────┘

   192.168.90.100 (MCU)
        │
        ├──── Ethernet Switch ────┐
        │                         │
   192.168.90.102 (Gateway) ──────┤
        │                         │
        ├── CAN: Body             │
        ├── CAN: Chassis     192.168.90.103 (APE)
        └── CAN: Powertrain       │
                             192.168.90.60 (Modem)
```

**Complete network diagram:** See [NETWORK-TOPOLOGY.md](NETWORK-TOPOLOGY.md)

---

## Security Model

### Two-Tier Access Control

**Tier 1: Insecure (UDP-accessible)**
- **Access:** UDP port 3500, no authentication
- **Examples:** Map region, trial timers, ECU map version
- **Odin flag:** `accessLevel: "UDP"`
- **Risk:** Anyone on vehicle network can modify

**Tier 2: Secure (Hermes-authenticated)**
- **Access:** Requires Tesla backend authentication (Hermes WSS:443)
- **Examples:** VIN, country code, supercharger access
- **Odin flag:** accessId 7-43 (normal access levels)
- **Protection:** Backend validates request before Gateway accepts

**Tier 3: Hardware-locked (Gateway-only, fused)**
- **Access:** Cannot be changed after chip fusing
- **Example:** devSecurityLevel (LC_FACTORY vs LC_GATED)
- **Odin flag:** `accessLevel: "GTW"`
- **Protection:** Tied to MPC5748G hardware fuses

**Detailed security analysis:** See [GATEWAY-SECURITY.md](GATEWAY-SECURITY.md)

### Hardware Fuses

**Function:** One-time programmable (OTP) bits in MPC5748G  
**Purpose:** Transition from factory mode (unfused) to production mode (fused)

**Security levels:**
- **LC_FACTORY (3):** Full access, JTAG enabled, debug UART active
- **LC_GATED (2):** Production mode, JTAG disabled, debug locked

**Fuse transition:** Irreversible (cannot unfuse without chip replacement)

---

## Physical Location

### Model 3 / Model Y

**Location:** Under rear passenger seat, driver's side  
**Access:** Remove seat bottom cushion, unscrew Gateway module cover

**Connector:** 2x multi-pin connectors (power + CAN)

### Model S / Model X

**Location:** Behind MCU, center console area (varies by model year)  
**Access:** More difficult (requires dash/console disassembly)

### Debug Interfaces

**Mini-HDMI port (some models):**
- Located on Gateway board
- Shorting pins 4+6 enters recovery mode (disables signature verification)
- Provides UART console + JTAG access
- **Risk level:** CRITICAL (complete compromise)

**Detailed debug interface analysis:** See [GATEWAY-BOOTLOADER.md](GATEWAY-BOOTLOADER.md#debug-interfaces)

---

## Cross-References

**Related documentation:**
- [GATEWAY-FIRMWARE.md](GATEWAY-FIRMWARE.md) — Binary analysis, disassembly, memory map
- [GATEWAY-CONFIGS.md](GATEWAY-CONFIGS.md) — Complete config database (662 entries)
- [GATEWAY-SECURITY.md](GATEWAY-SECURITY.md) — Security model, access control
- [GATEWAY-PROTOCOLS.md](GATEWAY-PROTOCOLS.md) — UDP protocols (ports 1050, 3500)
- [GATEWAY-BOOTLOADER.md](GATEWAY-BOOTLOADER.md) — Boot sequence, factory gate
- [GATEWAY-TOOLS.md](GATEWAY-TOOLS.md) — gw-diag, gwxfer, usage examples
- [GATEWAY-CAN.md](GATEWAY-CAN.md) — CAN routing, 6,647 message database

**Attack vectors:**
- [ATTACK-CAN-FLOOD.md](ATTACK-CAN-FLOOD.md) — Opens port 25956 via CAN flooding
- [ATTACK-SPC-REPLACEMENT.md](ATTACK-SPC-REPLACEMENT.md) — Hardware chip swap attack

**Tools:**
- [ODIN-OVERVIEW.md](ODIN-OVERVIEW.md) — Tesla's service tool that interfaces with Gateway
- [ODIN-COMMANDS.md](ODIN-COMMANDS.md) — gw-diag command reference (27 commands)

---

## Sources

**Synthesized from:**
- docs/gateway/38-gateway-firmware-DETAILED.md
- docs/gateway/54-gateway-spc-architecture.md
- docs/gateway/80-ryzen-gateway-flash-COMPLETE.md
- docs/gateway/81-gateway-secure-configs-CRITICAL.md
- docs/gateway/97-gateway-MEMORY-MAP.md
- docs/gateway/38-gateway-firmware-SUMMARY.md
- docs/core/04-network-ports-firewall.md
- docs/gateway/50-gateway-udp-config-protocol.md
- MPC5748G datasheet (NXP public documentation)

**Last Updated:** 2026-02-03

