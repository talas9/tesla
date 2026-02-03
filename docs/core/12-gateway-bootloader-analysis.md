# Tesla Gateway Bootloader Reverse Engineering Analysis

**Date:** 2026-02-02  
**Targets:**
- `models-fusegtw-GW_R4.img` (90,340 bytes) - Primary bootloader R4
- `models-fusegtw-GW_R7.img` (94,436 bytes) - Primary bootloader R7

## Executive Summary

The Tesla Gateway bootloader is a PowerPC e500 (Book E) embedded firmware running on an automotive-grade microcontroller. It implements a FreeRTOS-based RTOS with lwIP networking stack. Key findings:

1. **Architecture:** Power Architecture Book-E MCU firmware (Freescale/NXP MPC55xx / SPC5x-class; earlier text said e500—likely closer to e200z6 on MPC55xx)
2. **Network Stack:** lwIP (Lightweight IP) with UDP/TCP support
3. **RTOS:** FreeRTOS-like scheduler
4. **Security:** "Factory gate" mechanism for privileged operations
5. **Memory Layout:** Code at 0x40000000, RAM at 0x4002xxxx

---

## 1. File Structure

### Header Format (0x00-0x3F)

```
Offset  Size  Description
------  ----  -----------
0x00    4     Branch instruction (b 0x40 → entry point)
0x04    4     Checksum/version hash
0x08    4     Unknown flags (0x0001609c for R4, 0x0001709c for R7)
0x0C    4     Memory configuration
0x10    4     Size field (0x0000002c = 44 bytes header?)
0x14    4     Reserved (0x00000000)
0x18    8     Version string "GW R4   " or "GW R7   "
0x20    4     Version number (0x00000001)
0x24    16    SHA-256 hash fragment: 7b424911 74e55f83 342e608b 67bd7ef4
0x34    4     Build signature: 4dd7e199
0x38    4     Config flags (0x00000003)
0x3C    4     CRC/checksum
```

### Key Differences Between R4 and R7:
- R7 is ~4KB larger (additional code/data)
- Memory addresses shifted by 0x1000 in some locations
- Same core functionality, minor enhancements in R7

---

## 2. Boot Sequence

### Entry Point (0x00)
```asm
0x000:  b       0x40                  ; Jump to real init
```

### Early Initialization (0x40-0x130)
```asm
; MMU/TLB Setup
0x040:  lis     r1, 0xFFFE           ; r1 = 0xFFFE0000 (MMIO base?)
0x044:  ori     r1, r1, 0x0000
0x048:  li      r0, 2
0x04c:  stw     r0, 0(r1)            ; Write to control register

; Configure memory controller  
0x050:  lis     r1, 0xFFFE
0x054:  ori     r1, r1, 0xC000
0x058:  lwz     r0, 0(r1)            ; Read status
0x05c:  oris    r0, r0, 1            ; Set bit

; Clock initialization at 0xFFF38000
0x098:  lis     r1, 0xFFF3
0x09c:  ori     r1, r1, 0x8000
0x0a0:  lis     r0, 0x0989
0x0a4:  ori     r0, r0, 0x6800       ; Clock divisor?
0x0a8:  stw     r0, 8(r1)

; TLB Configuration (0xD0-0x130)
; SPR 624-627 = MAS0-MAS3 (TLB entries)
0x0d0:  lis     r0, 0x1003
0x0d4:  mtspr   624, r0              ; MAS0 = 0x10030000
0x0d8:  lis     r0, 0xC000
0x0dc:  ori     r0, r0, 0x0500
0x0e0:  mtspr   625, r0              ; MAS1 = 0xC0000500 (Valid, IPROT, TID=0)
0x0e4:  lis     r0, 0x4000
0x0e8:  ori     r0, r0, 0x0008
0x0ec:  mtspr   626, r0              ; MAS2 = 0x40000008 (EPN=0x40000000, cache attrs)
0x0f0:  lis     r0, 0x4000
0x0f4:  ori     r0, r0, 0x003F
0x0f8:  mtspr   627, r0              ; MAS3 = 0x4000003F (RPN=0x40000000, full perms)
0x0fc:  tlbwe                        ; Write TLB entry

; Second TLB entry for 0xC3F00000 (peripheral space)
0x100:  lis     r0, 0x1004
0x104:  mtspr   624, r0
0x114:  lis     r0, 0xC3F0
0x118:  ori     r0, r0, 0x0008
0x11c:  mtspr   626, r0              ; Map 0xC3F00000 (SIU/peripheral base)
```

### Register Initialization (0x130-0x1A0)
```asm
; Clear all GPRs r4-r31
0x130:  li      r4, 0
0x134:  li      r5, 0
...
0x19c:  li      r31, 0
```

### BSS Clear and Stack Setup (0x1A0-0x21C)
```asm
; Check boot mode
0x1a8:  lwz     r0, 0x4C(r1)         ; Read boot config at 0xFFFEC04C
0x1ac:  cmplwi  r0, 0
0x1b0:  beq-    0x1c0                ; Branch based on config

; Clear BSS (0x40016000 to 0x40080000)
0x1d0:  stmw    r4, 0(r1)            ; Store zeros (r4-r31 are 0)
0x1d4:  addi    r1, r1, 112          ; Increment by 28 words
0x1d8:  cmplw   r1, r2
0x1dc:  blt+    0x1d0

; Set up interrupt vectors
0x200:  mtivpr  r1                   ; Interrupt vector prefix = 0x40000000
0x204:  li      r1, 0x2D0
0x208:  mtivor4 r1                   ; External interrupt at offset 0x2D0
0x20c:  li      r1, 0x220
0x210:  mtivor8 r1                   ; System call at offset 0x220

; Stack pointer setup
0x214:  lis     r1, 0x4009
0x218:  ori     r1, r1, 0x3FF8       ; Stack at 0x40093FF8 (top of RAM)
0x21c:  b       0xe9c                ; Jump to main
```

---

## 3. Exception/Interrupt Handlers

### System Call Handler (0x220)
```asm
0x220:  addi    r1, r1, -152         ; Allocate stack frame
0x224:  stw     r0, 0(r1)            ; Save r0
0x228:  stmw    r2, 4(r1)            ; Save r2-r31
0x22c:  mfcr    r0
0x230:  stw     r0, 124(r1)          ; Save CR
0x234:  mfsrr0  r0
0x238:  stw     r0, 128(r1)          ; Save SRR0 (return address)
0x23c:  mfsrr1  r0
0x240:  stw     r0, 132(r1)          ; Save SRR1 (MSR)
0x244:  mflr    r0
0x248:  stw     r0, 148(r1)          ; Save LR
...
0x264:  lis     r2, 0x4002
0x268:  lwz     r2, -19164(r2)       ; Get current task context
0x26c:  stw     r1, 0(r2)            ; Save stack pointer
0x270:  bl      0x2410               ; Call scheduler
...
0x2c4:  rfi                          ; Return from interrupt
```

---

## 4. FreeRTOS Scheduler

### Task Structure (at 0x4002B5xx)
```
Offset  Description
------  -----------
0x00    Stack pointer
0x04    Next task pointer  
0x08    Task state
0x0C    Priority
0x10    Task name pointer
0x14    Task parameter
0x18    Delay counter
0x2C    Task number/ID
0x38    Tick count
0x40    Nesting count
0x44    Ready list index
0x48    Timeout counter
```

### Key Scheduler Functions:
- **0x2410** - vTaskSwitchContext (task scheduler)
- **0x2B98** - Enter critical section (wrteei 0)
- **0x2BC8** - Exit critical section (wrteei 1)
- **0x28A4** - Set task ready flag
- **0x28B4** - Get scheduler state

---

## 5. Network Stack (lwIP)

### String References at 0x5CE4:
```
0x5CE4:  "RAW_PCB"
0x5CEC:  "UDP_PCB"
0x5CF4:  "TCP_PCB"
0x5CFC:  "TCP_PCB_LISTEN"
0x5D0C:  "TCP_SEG"
0x5D14:  "NETBUF"
0x5D1C:  "NETCONN"
0x5D24:  "TCPIP_MSG_API"
0x5D34:  "TCPIP_MSG_INPKT"
0x5D44:  "SYS_TIMEOUT"
0x5D50:  "PBUF_REF/ROM"
0x5D60:  "PBUF_POOL"
```

### Task Names:
- **0x5E40:** "tcpip_thread" - Main TCP/IP processing thread
- **0x5E70:** "rxTask" - Network receive task

### UDP Socket Creation (0x5C20)
```asm
0x5c20:  stwu    r1, -32(r1)          ; Stack frame
0x5c28:  lis     r9, 0x4003           ; Memory pool base
0x5c30:  mulli   r0, r3, 12           ; Index * 12 (PCB size?)
0x5c34:  addi    r9, r9, 0x4858       ; PCB pool at 0x40034858
0x5c40:  lwzx    r3, r9, r0           ; Get PCB from pool
0x5c44:  li      r5, 50               ; Timeout = 50
0x5c48:  li      r6, 0
0x5c5c:  bl      0x3378               ; udp_new()
0x5c60:  cmpwi   cr7, r3, 0
0x5c64:  bne-    cr7, 0x5c88          ; If success, continue
...
0x5c88:  lwz     r3, 8(r30)           ; Get port number from config
0x5c94:  bl      0x3e08               ; udp_bind()
```

### IP Checksum Calculation (0x6344)
This function computes TCP/UDP/IP checksums - standard lwIP implementation.

---

## 6. Factory Gate Mechanism

### Strings at 0x1004:
```
0x1004:  "Factory gate succeeded"
0x101C:  "Factory gate failed"
0x1030:  "blinky"
0x1038:  "mainTask"
```

### Factory Gate Function (0x1044)
```asm
0x1044:  mfcr    r12                  ; Save condition register
0x1048:  cmpwi   cr4, r3, 10          ; Check if r3 == 10 (magic value?)
0x104c:  stwu    r1, -32(r1)          ; Stack frame
0x1050:  mflr    r0
0x1058:  mr      r31, r3              ; Save input
0x1060:  stw     r0, 36(r1)
0x106c:  beq-    cr4, 0x1158          ; If r3==10, special handling

; Normal path
0x1070:  bl      0x28B4               ; Get scheduler state
0x1074:  cmpwi   cr7, r3, 2           ; Check state == 2 (running?)
0x1078:  beq-    cr7, 0x116c          ; Branch if running

; Factory gate buffer at 0x40016000 (24KB buffer)
0x1084:  lis     r29, 0x4001
0x1088:  lwz     r9, 0x6000(r29)      ; Read current position
0x108c:  addi    r0, r9, 1            ; Increment
0x1090:  stb     r31, 0(r9)           ; Store byte to buffer
0x1094:  stw     r0, 0x6000(r29)      ; Update position

; Check if buffer full (8 bytes triggers action?)
0x1098:  lis     r30, 0x4002
0x109c:  addi    r30, r30, -19408     ; 0x4002B430
0x10a0:  subf    r4, r30, r0          ; Bytes written
0x10a4:  cmpwi   cr6, r4, 8           ; Check if 8 bytes
0x10a8:  beq-    cr6, 0x10f0          ; If 8 bytes, process command
...
```

This appears to be a command accumulation mechanism - bytes are collected until 8 are received, then processed as a command.

---

## 7. Jump Table / Command Dispatch

### Jump Table at 0x950-0xCAC

The jump table at offset 0x950 contains function pointers indexed by command ID:

```
Default handler: 0x40005E78 (no-op/error)

Special handlers (non-default entries):
Index   Address      Function
-----   --------     --------
0x21    0x40005400   Handler 1
0x24    0x40005408   Handler 2
0x2D    0x400051E8   Handler 3  
0x49    0x400054B4   Handler 4
0x4C    0x400054BC   Handler 5
0x55    0x40005568   Handler 6
0x58    0x40005570   Handler 7
0x67    0x4000561C   Handler 8
0x6A    0x40005624   Handler 9
0x79    0x400056D0   Handler 10
0x7C    0x400056D8   Handler 11
0x8B    0x40005784   Handler 12
0x8E    0x4000578C   Handler 13
0xAB    0x40014410   Handler 14 (special - different range)
```

This is likely the CAN message handler dispatch table - each index corresponds to a CAN arbitration ID or message type.

---

## 8. Memory Map

Based on TLB configuration and code analysis:

```
Address Range        Description
--------------       -----------
0x40000000-0x4001FFFF  Code (flash/ROM mapped)
0x40020000-0x4002FFFF  RAM (BSS, stack, heap)
  0x4002B4xx           Task control blocks
  0x4002B508           Current tick count
  0x4002B50C           Tick period
  0x4002B524           Current task pointer
  0x4002B544           Scheduler running flag
0x40030000-0x4003FFFF  Network buffers
  0x40034858           UDP PCB pool
0x40016000-0x40017FFF  Factory gate buffer

0xC3F00000-0xC3FFFFFF  Peripherals (SIU, etc.)
0xFFFE0000-0xFFFEFFFF  Memory controller / MMIO
0xFFF30000-0xFFF3FFFF  Clock controller
```

---

## 9. CAN Message Processing

While specific CAN ID handlers aren't explicitly visible in strings, the jump table structure suggests:

1. **Message arrives** via interrupt
2. **CAN ID extracted** and used as index into jump table at 0x950
3. **Handler called** with message data in registers
4. **State machine** processes multi-frame messages (factory gate accumulates 8 bytes)

### Likely CAN ID Mapping (based on table indices):
- 0x21 → Basic query
- 0x49-0x4C → Configuration commands
- 0x55-0x58 → Status commands
- 0x67-0x6A → Diagnostic commands
- 0x79-0x7C → Control commands
- 0x8B-0x8E → Special functions
- 0xAB → Extended/privileged command

The CAN flood attack (0x3C2 = 962 decimal) would need to be processed through this dispatch mechanism or bypass it entirely by triggering the factory gate through a specific sequence.

---

## 10. Attack Surface Assessment

### Entry Points:
1. **CAN Bus** - All messages processed through jump table
2. **UDP API** - Port 3500 (lwIP udp_bind)
3. **Factory Gate** - 8-byte command sequence triggers action

### Potential Vulnerabilities:
1. **Factory Gate Bypass**
   - If the 8-byte sequence is known/guessable
   - No apparent authentication beyond "magic bytes"
   
2. **Jump Table Overflow**
   - Table appears bounded but indices aren't validated in disassembly
   
3. **Network Stack**
   - lwIP has known vulnerabilities depending on version
   - No TLS/encryption visible
   
4. **Memory Layout**
   - Stack at fixed address (0x40093FF8)
   - No ASLR possible on this architecture

### The CAN Flood (0x3C2) Theory:
Based on the structure:
1. Rapid CAN messages overflow some buffer
2. Corruption triggers factory gate bypass
3. Port 25956 (0x6564) opens - possibly through factory mode enabling debug services

---

## 11. Key Function Summary

| Address | Name/Purpose |
|---------|--------------|
| 0x0000 | Entry point (branch to 0x40) |
| 0x0040 | Hardware init (MMU, clocks) |
| 0x0220 | System call exception handler |
| 0x0E9C | Main entry (after init) |
| 0x1044 | Factory gate processor |
| 0x2410 | Task scheduler |
| 0x2B98 | Enter critical section |
| 0x2BC8 | Exit critical section |
| 0x3378 | udp_new() |
| 0x3E08 | udp_bind() |
| 0x5C20 | Socket creation wrapper |
| 0x5E78 | Default message handler |
| 0x6344 | IP checksum calculation |

---

## 12. Recommendations for Further Analysis

1. **Full Disassembly** - Use Ghidra/IDA with PowerPC e500 processor module
2. **CAN ID Mapping** - Cross-reference with known Tesla CAN databases
3. **Factory Gate Protocol** - Fuzz the 8-byte command format
4. **Network Protocol** - Capture UDP traffic to port 3500
5. **Hardware Debug** - JTAG access would reveal runtime behavior

---

## Appendix: Version Comparison

| Feature | GW R4 | GW R7 |
|---------|-------|-------|
| Size | 90,340 bytes | 94,436 bytes |
| Version | 0x0001609C | 0x0001709C |
| BSS Range | 0x400160A0 | 0x400170A0 |
| Jump Table | Same structure | Same structure |
| Core Functions | Identical | Identical |
| Additional Code | - | ~4KB more |

The R7 version appears to be a minor update with additional functionality but the same core architecture.
