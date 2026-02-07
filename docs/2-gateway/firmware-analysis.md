# Gateway Firmware Analysis

**Disassembly findings from the 6MB Gateway firmware binary.**

---

## Overview

The Gateway firmware was extracted via JTAG and analyzed using Ghidra with PowerPC VLE support.

| Metric | Value |
|--------|-------|
| Binary Size | 6,225,920 bytes (6 MB) |
| Architecture | PowerPC e200z7 VLE |
| Strings Extracted | 37,702 |
| Functions (estimated) | ~8,000 |

---

## Key Regions

### Jump Table

| Offset | Description |
|--------|-------------|
| 0x00950 | Jump table start |
| 0x00CAC | Jump table end |
| Purpose | Function dispatch table |

### Factory Gate

| Offset | Description |
|--------|-------------|
| 0x01044 | Factory gate check |
| Purpose | Determines fuse state (dev/prod) |

### Firmware Hashes

| Offset | Size | Description |
|--------|------|-------------|
| 0x36730 | 32 bytes | SHA-256 firmware hash |

### Config Metadata

| Offset | Size | Description |
|--------|------|-------------|
| 0x403000 | ~100 KB | CAN message metadata table |
| 0x019000 | ~100 KB | Configuration database |

---

## String Analysis

### Statistics

| Category | Count |
|----------|-------|
| Total strings | 37,702 |
| Config-related | ~500 |
| CAN message IDs | ~6,600 |
| Debug messages | ~2,000 |
| Error strings | ~800 |

### Notable Patterns

```
get_config_%04X    - Config read functions
set_config_%04X    - Config write functions
CAN_MSG_0x%03X     - CAN message handlers
ERR_%s             - Error conditions
```

### Example Strings

```
"Gateway firmware version %s"
"Config ID 0x%04X not found"
"CRC validation failed"
"Authentication required"
"Factory mode: %s"
```

---

## Function Table

### Identified Functions

| Address | Function (Inferred) |
|---------|---------------------|
| 0x00950 | Entry dispatch |
| 0x01000 | Main initialization |
| 0x01044 | Factory gate check |
| 0x02000 | CAN handler dispatch |
| 0x10000 | Config read handler |
| 0x10500 | Config write handler |
| 0x20000 | UDP service loop |

**Note:** Binary is stripped, function names are inferred from behavior.

---

## CAN Message Handlers

### Handler Table Location

Found at offset **0x403000**, containing 6,647 entries.

### Entry Format

```
Offset   Size    Field
─────────────────────────────────────────
+0x00    2       CAN ID (big-endian)
+0x02    1       Data length
+0x03    1       Handler type
+0x04    4       Handler address
```

### Message Types

| Type | Description |
|------|-------------|
| 0x01 | Periodic status |
| 0x02 | Request/response |
| 0x03 | Event notification |
| 0x04 | Diagnostic (UDS) |

---

## UDP Handler

### Port 3500 Service

**Status:** Handler not fully located in disassembly.

**Evidence found:**
- String references to port 3500
- UDP socket creation calls
- Config read/write dispatch

**Challenge:** Binary is stripped, RTOS task structure makes tracing difficult.

---

## Security Functions

### Signature Verification

| Address | Function |
|---------|----------|
| 0x30000 | Ed25519 verify (estimated) |
| 0x30800 | SHA-256 hash |

### Config Validation

| Address | Function |
|---------|----------|
| 0x10500 | CRC-8 check |
| 0x10600 | Access level check |
| 0x10700 | Hermes auth verify |

---

## Disassembly Tools

### Ghidra Setup

```
Processor: PowerPC VLE
Base Address: 0x00000000
Entry Point: 0x00001000 (or 0x00000000)
Endianness: Big-endian
```

### PowerPC VLE Notes

- Variable Length Encoding (16-bit and 32-bit instructions)
- Non-standard opcode encoding
- Requires VLE-specific Ghidra processor
- Some instructions only 16 bits

---

## Data Files

| File | Description |
|------|-------------|
| `data/gateway/strings.csv` | All 37,702 strings |
| `data/gateway/gateway_configs_parsed.txt` | 662 parsed configs |
| `data/gateway/can-message-database-VERIFIED.csv` | CAN entries |

---

## Research Recommendations

### Completed

- ✅ String extraction
- ✅ Config region identification
- ✅ CAN handler table location
- ✅ CRC-8 algorithm reverse engineering

### Remaining

- ❌ Complete UDP handler disassembly
- ❌ Hermes authentication flow
- ❌ Full function naming
- ❌ Bootloader analysis

---

## Cross-References

- [Architecture](architecture.md) - Memory map, hardware
- [Config System](config-system.md) - 662 configs
- [UDP Protocol](udp-protocol.md) - Port 3500 API

---

**Status:** PARTIAL  
**Evidence:** Ghidra analysis, string extraction  
**Last Updated:** 2026-02-07
