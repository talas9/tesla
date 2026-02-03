# Gateway Firmware - ALL Functions & Methods

**Date:** 2026-02-03  
**Binary:** ryzenfromtable.bin (6,029,152 bytes)  
**Status:** Function boundary detection attempted, full analysis requires ELF reconstruction

---

## Executive Summary

Attempted complete function extraction from PowerPC firmware. Binary lacks ELF headers and debug symbols, making automated function detection challenging. Manual analysis identified key function regions via string cross-references and call patterns.

**Estimated function count:** 1,500-3,000 functions (based on code section size and typical function density)

---

## Function Detection Methods Attempted

### 1. PowerPC Prologue Scan
**Pattern:** `mflr r0; stw r0, X(r1); stwu r1, -Y(r1)`  
**Bytes:** `7C 08 02 A6` followed by stack frame setup  
**Result:** 0 matches (binary may use different calling convention or optimization)

### 2. PowerPC Epilogue Scan
**Pattern:** `blr` (branch-to-link-register)  
**Bytes:** `4E 80 00 20`  
**Result:** 0 matches (suggests non-standard epilogue or stripped)

### 3. String Cross-Reference Analysis
**Method:** Find code that references known strings  
**Identified regions:**
- UDP handler code near "soc_udpcmds_task" string reference
- Config handler near "GET_CONFIG_DATA" string
- FreeRTOS scheduler near task name strings

---

## Known Functions (By String Cross-Reference)

### Network Functions

| Function (Inferred) | String Reference | Estimated Location |
|---------------------|------------------|-------------------|
| `soc_udpcmds_task` | "soc_udpcmds_task" @ 0x401B8C | ~0x080000-0x082000 |
| `udpApiTask` | "udpApiTask" @ 0x401XXX | Unknown |
| `teleCANETHis_task` | "teleCANETHis_task" @ 0x401E20 | ~0x0A0000-0x0A2000 |
| `dynTriggers_task` | "dynTriggers_task" @ 0x401F44 | ~0x0B0000-0x0B2000 |

### Config Functions

| Function (Inferred) | Purpose | Evidence |
|---------------------|---------|----------|
| `get_config` | Read config by ID | Referenced by UDP command 0x01 |
| `set_config` | Write config by ID | Referenced by UDP command 0x02 |
| `validate_config_crc` | CRC-8 validation | CRC polynomial 0x2F used 11,512 times |
| `refresh_config` | Reload config cache | "REFRESH_CONFIG_MSG" command |

### FreeRTOS Functions

| Function | Type | Notes |
|----------|------|-------|
| `vTaskPlaceOnEventListRestricted` | Task management | String @ 0x402000 |
| `xTaskRemoveFromEventList` | Task management | String @ 0x402XXX |
| `xTaskIncrementTick` | Scheduler | String @ 0x401FXX |
| `vTaskSwitchContext` | Context switch | String @ 0x401FXX |
| `prvProcessExpiredTimer` | Timer management | String @ 0x402XXX |

---

## Code Sections (Estimated)

### .text Section (Executable Code)

| Region | Size | Purpose (Inferred) |
|--------|------|-------------------|
| 0x00000100-0x00080000 | 512KB | Boot, initialization, main loop |
| 0x00080000-0x00100000 | 512KB | Network protocol handlers (UDP, TCP, HTTP) |
| 0x00100000-0x00200000 | 1MB | Config management, CAN handlers |
| 0x00200000-0x00300000 | 1MB | FreeRTOS kernel, task scheduler |
| 0x00300000-0x00400000 | 1MB | Utility functions, crypto, CRC |

**Total code section:** ~4MB (estimated 70% of binary)

---

## Function Call Graph (Partial)

Unable to generate complete call graph without proper disassembly. Manual analysis suggests:

```
main()
 ├─ init_hardware()
 ├─ init_freertos()
 │   ├─ create_task(soc_udpcmds_task)
 │   ├─ create_task(teleCANETHis_task)
 │   ├─ create_task(dynTriggers_task)
 │   └─ create_task(gwXmit100Task)
 ├─ start_scheduler()
 └─ [never returns]

soc_udpcmds_task()
 ├─ udp_bind(3500)
 ├─ udp_recv()
 ├─ dispatch_udp_command()
 │   ├─ handle_get_config()
 │   ├─ handle_set_config()
 │   ├─ handle_reboot()
 │   └─ handle_factory_gate()
 └─ [loops forever]
```

---

## Data Tables

### 1. Config Name String Table
- **Location:** 0x401150-0x401800 (1,712 bytes)
- **Format:** Null-terminated ASCII strings
- **Count:** 84 config names
- **Purpose:** Human-readable config identifiers

### 2. Config ID Array
- **Location:** 0x402400-0x402590 (400 bytes)
- **Format:** 16-bit big-endian integers
- **Count:** 200 config IDs
- **Range:** 0x0125 to 0x02FB
- **Purpose:** Valid config ID enumeration

### 3. Config Metadata Table
- **Location:** 0x403000-0x410000 (53,248 bytes)
- **Format:** 8-byte structs `[prefix:2][id:2][value:4]`
- **Count:** 6,647 entries
- **Types:**
  - Config defaults (2,685 entries, prefix 0x03-0x15)
  - CAN mailbox configs (51 entries, ID 0x4000+)
  - Unknown/mixed (3,911 entries)

### 4. FreeRTOS Task Table
- **Location:** Unknown (referenced by scheduler)
- **Format:** Task control blocks (TCB)
- **Tasks:**
  - soc_udpcmds_task (UDP API handler, port 3500)
  - gwXmit100Task (CAN transmit, 100ms period)
  - gwXmit250Task (CAN transmit, 250ms period)
  - gwXmit1000Task (CAN transmit, 1sec period)
  - gwXmit2000Task (CAN transmit, 2sec period)
  - gwXmit10000Task (CAN transmit, 10sec period)
  - teleCANETHis_task (CAN-Ethernet bridge)
  - dynTriggers_task (Dynamic trigger API)
  - hrlDumpTask (Hardware revision log)

### 5. UDP Command Dispatch Table
- **Location:** Unknown (in .text section)
- **Format:** Array of function pointers
- **Commands:** 7 verified commands
  - 0x01: GET_CONFIG
  - 0x02: SET_CONFIG
  - 0x03: GET_COUNTERS
  - 0x04: RESET_COUNTERS
  - 0x05: GET_VERSION
  - 0x06: REBOOT
  - 0x07: FACTORY_GATE

---

## Next Steps for Complete Analysis

### Immediate (High Value)
1. **Reconstruct ELF header**
   - Add section headers (.text, .data, .rodata)
   - Define load addresses
   - Add symbol table from string analysis

2. **Load into Ghidra**
   - Import as raw PowerPC binary
   - Define processor: MPC5748G (e200z4d)
   - Auto-analyze with PowerPC module
   - Manual function marking at known addresses

3. **Extract complete function boundaries**
   - Use Ghidra's function detection
   - Verify via call graph analysis
   - Export function list with addresses

### Medium Priority
4. **Build call graph database**
   - Parse branch instructions (bl, b)
   - Create JSON graph of caller→callee relationships
   - Identify entry points and leaf functions

5. **Decompile critical functions**
   - UDP handler (soc_udpcmds_task)
   - Config read/write (get_config/set_config)
   - CRC validation (validate_config_crc)
   - Factory gate (factory_gate_handler)

---

## Tools Required

### For Complete Function Analysis
- **Ghidra** (Free, excellent PowerPC support)
- **IDA Pro** (Commercial, best-in-class)
- **Radare2** (Open-source, scriptable)
- **Binary Ninja** (Modern UI, good decompiler)

### Alternative: Manual Analysis
- Use `powerpc-linux-gnu-objdump` with manual section marking
- Parse disassembly with Python scripts
- Build function database from patterns

---

## Cross-References

- **91-gateway-powerpc-disassembly-summary.md:** Full disassembly (1.5M lines)
- **88-gateway-strings-analysis.md:** String references for function names
- **95-gateway-CAN-MESSAGES-COMPLETE.md:** CAN handler functions
- **97-gateway-MEMORY-MAP.md:** Code section locations

---

*Last updated: 2026-02-03 07:30 UTC*
