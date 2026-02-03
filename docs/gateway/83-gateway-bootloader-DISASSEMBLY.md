# Gateway Bootloader Disassembly Analysis
## File: gateway-app-firmware.bin (256KB)
## Architecture: ARM Cortex-M7 (i.MX RT1062 / Teensy 4.x compatible)

---

## Executive Summary

This is **NOT** MPC5748G firmware as previously assumed. Analysis reveals:
- **Platform**: NXP i.MX RT1062 (ARM Cortex-M7)
- **Boot Method**: FlexSPI XIP (Execute-in-Place)
- **Base Address**: 0x60000000 (XIP Flash)
- **Code Size**: ~38KB active, 256KB total image
- **USB**: Teensyduino-compatible USB Serial/HID

---

## 1. Memory Layout

### Flash Configuration Block (FCB) @ 0x0000-0x0200
```
Offset   Value       Description
------   -----       -----------
0x0000   'FCFB'      Magic (FlexSPI Configuration Block)
0x0004   0x0156      Version
0x0044   0x0804      Read Sample Clock Source
0x0050   0x2000      Serial Flash Size (8MB)
0x0080   0x0a1804eb  LUT[0] - READ command
```

### Image Vector Table (IVT) @ 0x1000
```
Offset   Value        Description
------   -----        -----------
0x1000   0x432000D1   IVT Header (Tag=0xD1, Length=0x20, Version=0x43)
0x1004   0x60001649   Entry Point (Reset_Handler + 1 for Thumb)
0x1008   0x00000000   Reserved
0x100C   0x00000000   DCD Pointer (no Device Configuration Data)
0x1010   0x60001020   Boot Data Pointer
0x1014   0x60001000   Self Pointer
0x1018   0x60008C00   CSF Pointer (Code Signing/HAB)
0x101C   0x00000000   Reserved
```

### Boot Data @ 0x1020
```
Start Address:  0x60000000  (XIP Flash base)
Length:         0x00009800  (38,912 bytes active code)
Plugin Flag:    0x00000000  (normal boot, not plugin)
```

---

## 2. Function Analysis

### 2.1 Memory Copy Routines (0x1400-0x1424)

**memcpy32() @ 0x1400**
```asm
; void memcpy32(void* dst, void* src, void* end)
; Copies 32-bit words from src to dst until dst >= end
1400: cmp     r1, r0           ; Compare src to dst
1402: beq.n   0x1410           ; Skip if equal
1404: ldr.w   r3, [r1], #4     ; Load word, post-increment
1408: str.w   r3, [r0], #4     ; Store word, post-increment
140c: cmp     r2, r0           ; Compare end to dst
140e: bhi.n   0x1404           ; Loop if dst < end
1410: bx      lr               ; Return
```

**memset32() @ 0x1414**
```asm
; void memset32(void* start, void* end, uint32_t value)
; Fills memory with 32-bit value
1414: ldr     r2, [pc, #16]    ; Load end address
1416: ldr     r1, [pc, #20]    ; Load start address  
1418: mov.w   r3, #0           ; Value to fill
141c: str.w   r3, [r2], #4     ; Store and increment
1420: cmp     r1, r2           ; Check if done
1422: bhi.n   0x141c           ; Loop
1424: bx      lr               ; Return
```

### 2.2 Reset Handler / main() @ 0x1430

**Entry Point Analysis:**
```asm
1430: stmdb   sp!, {r3, r7, fp, lr}  ; Save registers
1434: dsb     sy                      ; Data Synchronization Barrier
1438: nop                             ; (alignment padding)
...
1440: bl      0x1670                  ; Call early_init()
```

**System Initialization Sequence:**
1. **0x1440**: Call early_init() - disables watchdog
2. **0x1444-0x1448**: Configure WDOG (0x400D8000 + 0x154)
3. **0x146C-0x147C**: Copy .data section from flash to RAM
4. **0x1482**: Clear .bss section (zero-fill)
5. **0x1486-0x14AE**: Configure NVIC (interrupt priorities)
6. **0x14B2-0x14D6**: Initialize FlexCAN clocks
7. **0x1514**: Call clock_init() @ 0x1680
8. **0x154C**: Call pll_init() @ 0x1790
9. **0x1562**: Call peripheral_init() @ 0x1AE8
10. **0x15AC-0x15B8**: Initialize CAN, USB, timers
11. **0x15DE**: WFI loop (Wait For Interrupt - main idle)

### 2.3 Clock Configuration @ 0x1680

```asm
; Configure MPU regions and system clocks
1680: push    {r4}
1682: mov.w   r3, #0xE000E000      ; NVIC/System Control base
1686: movs    r1, #0
1688: movs    r4, #16
168A: ldr     r0, [pc, #196]        ; MPU region config
168C: str.w   r1, [r3, #0xD94]      ; MPU_CTRL - disable MPU
1690: str.w   r4, [r3, #0xD9C]      ; MPU_RNR - region number
...
1724: movs    r2, #1
1726: str.w   r2, [r3, #0xD94]      ; MPU_CTRL - enable MPU
172A: dsb     sy
172E: isb     sy
```

### 2.4 PLL Configuration @ 0x1790

```asm
; FlexCAN bit timing and PLL setup
1790: push    {r4, r5, r6, r7}
1792: ldr     r2, [pc, #84]         ; FlexCAN1 base
1794: movs    r7, #64
1796: mov.w   r1, #65536            ; 0x10000
...
; Monitors CAN status register for sync
17AA: ldr     r3, [r2, #16]         ; Read CAN MCR
17AC: tst.w   r3, #2                ; Check SOFT_RST
17B0: bne.n   0x17D0
...
```

### 2.5 Floating Point Timer Calibration @ 0x17EC

```asm
; Uses FPU for precise timer calculations
; Visible VMOV, VCVT, VMUL, VDIV instructions
17EC: ldr     r2, [pc, #252]        ; PIT base
17EE: movs    r0, #3
17F0: ldr     r1, [pc, #252]
17F2: vmov.f32 s11, #57             ; 25.0
17F6: ldr.w   r3, [r2, #128]
...
; FPU operations for CAN bit timing calculation
182E: vcvt.f32.s32 s15, s15
...
```

### 2.6 CAN Initialization @ 0x191C

```asm
; Initialize FlexCAN1 and FlexCAN2
191C: ldr     r3, [pc, #196]        ; 0x400D8000 (FlexCAN1)
191E: movw    r2, #3937             ; 0xF61 - timing config
1922: push    {r4, lr}
1924: str.w   r2, [r3, #288]        ; MCR register
...
; Configure CAN bit timing, mailboxes, filters
```

### 2.7 USB Initialization (Inferred from strings)

USB descriptors found at 0x1AF0-0x1BF0:
- Device: "Teensyduino" 
- Interface: "USB Serial"
- Class: CDC-ACM (Communication Device Class)
- Endpoint configuration for bulk transfer

---

## 3. Critical Functions Identified

| Address | Name (Inferred) | Purpose |
|---------|-----------------|---------|
| 0x1400  | memcpy32        | Copy 32-bit aligned memory |
| 0x1414  | memset32        | Zero-fill memory region |
| 0x1430  | Reset_Handler   | Main entry/initialization |
| 0x1670  | early_init      | Disable watchdog |
| 0x1674  | stub_return     | Empty function (unused hook) |
| 0x1678  | stub_return2    | Empty function (unused hook) |
| 0x167C  | nop_return      | NOP then return |
| 0x1680  | mpu_clock_init  | Configure MPU and clocks |
| 0x1790  | flexcan_init    | Initialize FlexCAN peripheral |
| 0x17EC  | timer_calibrate | FPU-based timing calculation |
| 0x191C  | can_bus_init    | Full CAN bus initialization |
| 0x1A04  | fault_handler   | BKPT 0xFB on fault (debug) |
| 0x1A50  | system_reset    | Trigger system reset |
| 0x1AE8  | peripheral_init | Initialize all peripherals |

---

## 4. Security-Relevant Observations

### 4.1 HAB (High Assurance Boot)
- CSF pointer at 0x60008C00 indicates HAB signing is configured
- Boot ROM validates signature before executing
- **Bypass**: Would require compromised fuses or glitching

### 4.2 Debug Interface
- BKPT instruction at 0x1A0E indicates debug hooks
- No JTAG disable visible in analyzed code
- SWD likely enabled for development

### 4.3 Watchdog
- WDOG at 0x400D8000 is configured but timing unclear
- Early init disables/reconfigures watchdog

### 4.4 Memory Protection
- MPU is configured with multiple regions
- Flash marked execute-only
- RAM has separate data/code permissions

---

## 5. Peripheral Map

| Base Address | Peripheral | Usage |
|--------------|------------|-------|
| 0x400D8000   | FlexCAN1   | Primary CAN bus |
| 0x400D4000   | FlexCAN2   | Secondary CAN bus |
| 0x400AC000   | LPUART1    | Debug UART |
| 0x400FC000   | CCM        | Clock Control Module |
| 0x40084000   | GPT1       | General Purpose Timer |
| 0xE000E000   | NVIC       | Interrupt Controller |
| 0xE0001000   | DWT        | Debug Watchpoint/Trace |

---

## 6. Embedded Strings

| Offset | String | Purpose |
|--------|--------|---------|
| 0x1AFB | "USB Serial" | USB descriptor |
| 0x1B13 | "Teensyduino" | Device name |
| 0x7FDC | "FIFO Enabled -->" | CAN debug |
| 0x7FF0 | "Interrupt Enabled" | Debug output |
| 0x8050 | " code: RX_INACTIVE" | CAN status |
| 0x8108 | " code: TX_DATA (Transmitting)" | CAN status |
| 0x8278 | "5YJ3F7EB0LF610940" | Tesla VIN |
| 0x82CE | "WINUSB" | USB class |

---

## 7. Conclusions

### Platform Identification
This is **Teensy 4.x compatible** firmware running on an NXP i.MX RT1062:
- ARM Cortex-M7 @ 600MHz
- FlexSPI XIP boot
- Dual FlexCAN controllers
- USB Device support

### Relation to Tesla Gateway
This appears to be a **CAN bus interface/bridge** device, possibly:
1. A development/test tool for Gateway communication
2. An aftermarket diagnostic adapter
3. A captured firmware from a Tesla diagnostic dongle

### Missing Security Features
- No encryption visible in code
- No authentication handshake in CAN init
- Debug interfaces appear enabled
- VIN is stored in plaintext

### Recommendations for Further Analysis
1. Trace CAN message handlers (not fully analyzed)
2. Identify USB command parsing
3. Find config storage (if any)
4. Analyze interrupt handlers

---

*Analysis completed: Feb 3, 2026*
*Binary size: 262,144 bytes*
*Active code: ~38,912 bytes*
*Architecture: ARMv7-M (Thumb-2)*
