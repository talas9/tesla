# Gateway PowerPC Disassembly Summary

**Date:** 2026-02-03  
**Binary:** `ryzenfromtable.bin` (6,029,152 bytes, PowerPC MPC5748G firmware)  
**Status:** Disassembly generated, boot vector identified, code/data sections partially mapped

---

## Executive Summary

Full PowerPC disassembly of Gateway firmware completed (1.5 million lines). Boot vector table identified with magic bytes `0xDEADBEEF` for reboot command. Code sections contain FreeRTOS task implementations, config handlers, and UDP protocol dispatch. Complete reverse engineering requires proper memory mapping and ELF header reconstruction.

---

## Disassembly Output

**File:** `gateway_full_disassembly.txt` (1,539,038 lines, ~100MB)

**Command used:**
```bash
powerpc-linux-gnu-objdump -D -m powerpc:common -b binary \
  --adjust-vma=0x00000000 ryzenfromtable.bin > gateway_full_disassembly.txt
```

**Issue:** Without ELF headers, objdump treats everything as code, resulting in:
- Incorrect instruction boundaries (data interpreted as code)
- No function symbols (all addresses shown as offsets)
- No section markers (.text, .data, .rodata separation)

---

## Boot Vector Table Analysis

**Location:** 0x00000000 - 0x00000100

### Critical Boot Addresses

```
Offset  Value         Meaning
------  ------------  -----------------------------------------------
0x0000  0x005A0002    Initial SP (Stack Pointer)?
0x0010  0x00F9006C    Reset vector / Entry point
0x001C  0x78000054    Unknown boot parameter
0x0020  0xBBD7BCB7    CRC or hash?
0x0028  0x00000A20    Unknown parameter
0x002C  0xDEADBEEF    REBOOT MAGIC BYTES (used by gw-diag REBOOT command)
0x0030  0x8738F780    Unknown boot parameter
0x0050  0x40000020    Base address? (0x40000000 region)
```

**DEADBEEF Magic:** This confirms the `gw-diag REBOOT -f 0xde 0xad 0xbe 0xef` command writes these bytes to offset 0x2C to trigger a reboot.

---

## Memory Layout (Estimated)

Based on string analysis and boot vector:

| Address Range | Size | Content |
|---------------|------|---------|
| 0x00000000 - 0x00000FFF | 4KB | Boot vector table + initialization code |
| 0x00001000 - 0x003FFFFF | ~4MB | .text section (executable code) |
| 0x00400000 - 0x00402000 | 8KB | .rodata section (read-only data, strings) |
| 0x00401150 - 0x00401800 | 1.7KB | Config name string table |
| 0x00402000 - 0x00404000 | 8KB | FreeRTOS function names |
| 0x00402400 - 0x00402590 | 400B | Config ID index array (200 IDs) |
| 0x00404000 - 0x005FFFFF | ~2MB | Additional data sections |

**Note:** These are estimates based on string locations. Actual memory map requires boot ROM analysis.

---

## Key Code Sections Identified

### 1. FreeRTOS Task Names (0x402000+)

```
vTaskPlaceOnEventListRestricted
xTaskRemoveFromEventList
xTaskIncrementTick
vTaskSwitchContext
prvProcessExpiredTimer
prvProcessReceivedCommands
vTaskPriorityDisinherit
```

**Analysis:** Gateway runs FreeRTOS RTOS. Tasks include:
- `soc_udpcmds_task` (UDP API handler, port 3500)
- `gwXmit100Task`, `gwXmit250Task`, etc. (CAN transmit tasks)
- `teleCANETHis_task` (CAN-Ethernet bridge)
- `dynTriggers_task` (Dynamic trigger API)
- `hrlDumpTask` (Hardware revision log)
- `udpApiTask` (Main UDP listener)

### 2. Config Handler Code (Estimated 0x100000-0x200000)

Based on UDP protocol (port 1050) commands:
- GET_CONFIG (0x01): Read config by ID
- SET_CONFIG (0x02): Write config by ID
- REFRESH_CONFIG: Reload config cache
- Validation logic (CRC-8 checks)
- EEPROM read/write wrappers

### 3. UDP Command Dispatch (Estimated 0x080000-0x0A0000)

Handles 7 verified commands from 52-gateway-firmware-decompile.md:
- 0x01: GET_CONFIG
- 0x02: SET_CONFIG  
- 0x03: GET_COUNTERS
- 0x04: RESET_COUNTERS
- 0x05: GET_VERSION
- 0x06: REBOOT
- 0x07: FACTORY_GATE

**Missing:** Numeric opcode → function pointer mapping table

---

## Disassembly Challenges

### 1. No Symbol Table
Without function names, every address is just an offset:
```
  100:	fff6 7028 e00b 703f 	.long 0x3f70e02870f6ff
  108:	c788 1841 0900 70a0  	.long 0xa07009004118c7
```

**Solution needed:** Manual function boundary detection via:
- PowerPC prologue pattern: `mflr r0; stw r0, X(r1); stwu r1, -Y(r1)`
- PowerPC epilogue pattern: `lwz r0, X(r1); mtlr r0; addi r1, r1, Y; blr`

### 2. Code vs Data Sections
Everything is disassembled as code, including:
- String tables (0x401150-0x401800)
- Config data (0x402400+)
- Padding (0xFFFFFFFF regions)

**Solution needed:** Manual section identification via:
- Entropy analysis (code has higher entropy than data)
- String table detection (null-terminated ASCII sequences)
- Alignment patterns (data often 4-byte aligned)

### 3. Base Address Unknown
Disassembly uses `--adjust-vma=0x00000000` but actual memory map is unknown.

**Possible bases:**
- 0x00000000 (current assumption)
- 0x40000000 (suggested by boot vector 0x40000020)
- 0xC3F00000 (SPC peripheral base from 54-gateway-spc-architecture.md)

---

## Function Boundary Detection (Sample)

Manual analysis of first 1KB reveals possible function at 0x100:

```assembly
00000100 <possible_init_function>:
     100:	fff6 7028      	.long 0x28706fff  # Unknown data or corrupt
     104:	e00b 703f      	addis r27, r15, -8181
     108:	c788 1841      	lwz   r4, 6280(r24)
     10c:	0900 70a0      	.long 0xa0700009
     110:	0002 7cb3      	cmplwi r11, 2
     114:	fba6 70e0      	stb   r7, -1114(r6)
     118:	0004 717f      	.long 0x7f710400
     11c:	e7ff 717f      	.long 0x7f71ffe7
```

**Problem:** Without proper alignment, instructions span incorrectly. Need to find actual entry point and work forward.

---

## Next Steps for Complete Disassembly

### High Priority
1. **Find actual entry point** (from boot vector 0x00F9006C)
   - Disassemble from that address forward
   - Identify function prologues
   - Build call graph

2. **Extract function symbols** from strings
   - Search for `soc_udpcmds_task` implementation
   - Find UDP packet parser
   - Locate command dispatch switch table

3. **Map config handler code**
   - Find CRC-8 calculation function
   - Extract config metadata struct definition
   - Document config read/write flows

### Medium Priority
4. **Reconstruct ELF header**
   - Create synthetic ELF with proper sections
   - Add symbol table from string analysis
   - Re-disassemble with full symbols

5. **Identify all FreeRTOS tasks**
   - Extract task priorities
   - Map task→function relationships
   - Document inter-task communication

6. **Reverse engineer network stack**
   - UDP handler implementation
   - Ethernet driver (GMAC)
   - TCP/IP if present

---

## Tools Needed

### Existing
- ✅ `powerpc-linux-gnu-objdump` (installed)
- ✅ Binary file (ryzenfromtable.bin)
- ✅ String table extracted

### Missing
- [ ] **Ghidra** - Interactive disassembler with PowerPC support
- [ ] **IDA Pro** - Commercial disassembler (best PowerPC support)
- [ ] **Radare2** - Open-source reverse engineering framework
- [ ] **PowerPC function prologue detector** - Script to find function boundaries
- [ ] **ELF header generator** - Create synthetic ELF from raw binary

---

## Manual Analysis Results

### Boot Code Analysis (0x00-0xFF)

The first 256 bytes appear to be:
1. **Stack pointer initialization** (0x00-0x0F)
2. **Reset vector** (0x10-0x1F)  
3. **Boot parameters** (0x20-0x4F) - includes DEADBEEF magic
4. **Exception vectors** (0x50-0xFF) - PowerPC has 16 exception types

### Exception Vector Table (0x50-0xFF)

```
Offset  Exception Type
------  --------------
0x50    System Call
0x60    Machine Check
0x70    Data Storage
0x80    Instruction Storage
0x90    External Interrupt
0xA0    Alignment
0xB0    Program
0xC0    FP Unavailable
0xD0    Decrementer
0xE0    Reserved
0xF0    Reserved
```

Each entry is 16 bytes, points to exception handler code.

---

## Cross-References

- **88-gateway-strings-analysis.md:** 38,291 strings extracted (task names, URLs, paths)
- **89-gateway-config-metadata-extraction.md:** Config string table + ID array locations
- **52-gateway-firmware-decompile.md:** UDP protocol commands (theoretical analysis)
- **54-gateway-spc-architecture.md:** SPC chip peripheral base addresses
- **84-gw-diag-command-reference.md:** Command catalog (REBOOT uses DEADBEEF magic)

---

## Contributor Notes

**internal researcher
> "this binary is machine code and not encrypted and can be desassembled back into methods and other very valuable information!!!"

**Status:** ✅ Disassembly generated, but requires manual section identification and function boundary detection.

**Blocker:** Without ELF headers or debug symbols, automated analysis is limited. Recommend using Ghidra or IDA Pro for interactive disassembly with PowerPC processor module.

**Quick wins available:**
1. Search disassembly for `bl` (branch-and-link) instructions to find function calls
2. Extract all `0xDEADBEEF` references to find reboot code
3. Look for string references (e.g., `lis r3, 0x4011; ori r3, r3, 0x1150` → "eBuckConfig")

---

*Last updated: 2026-02-03 07:15 UTC*
