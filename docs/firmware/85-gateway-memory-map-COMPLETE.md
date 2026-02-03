# Gateway Memory Map - Complete Analysis
## File: gateway-app-firmware.bin  
## Platform: NXP i.MX RT1062 (ARM Cortex-M7)

---

## Executive Summary

This document maps the memory architecture of the Teensy-based CAN adapter.
**Note**: This is NOT the Tesla Gateway's memory map - that would be MPC5748G/PowerPC.

---

## 1. i.MX RT1062 Memory Map

### 1.1 System Memory Regions

| Start | End | Size | Region | Usage |
|-------|-----|------|--------|-------|
| 0x00000000 | 0x0007FFFF | 512KB | ITCM | Tightly Coupled Instruction Memory |
| 0x00200000 | 0x002FFFFF | 1MB | FlexSPI Alias | Read-only flash alias |
| 0x20000000 | 0x2007FFFF | 512KB | DTCM | Tightly Coupled Data Memory |
| 0x20200000 | 0x202FFFFF | 1MB | OCRAM | On-chip RAM |
| 0x40000000 | 0x43FFFFFF | 64MB | AIPS-1 | Peripheral bus 1 |
| 0x60000000 | 0x7FFFFFFF | 504MB | FlexSPI | XIP Flash (Execute-in-Place) |
| 0xE0000000 | 0xE00FFFFF | 1MB | PPB | Private Peripheral Bus (Cortex-M) |

### 1.2 Memory Usage in This Firmware

```
Flash Layout (256KB image @ 0x60000000):
┌─────────────────────────────────────────┐
│ 0x60000000: FlexSPI Config Block (FCB)  │ 512 bytes
├─────────────────────────────────────────┤
│ 0x60000200: Reserved/Padding            │ 3.5KB  
├─────────────────────────────────────────┤
│ 0x60001000: Image Vector Table (IVT)    │ 32 bytes
├─────────────────────────────────────────┤
│ 0x60001020: Boot Data                   │ 16 bytes
├─────────────────────────────────────────┤
│ 0x60001030: Reserved (0xFF padding)     │ ~976 bytes
├─────────────────────────────────────────┤
│ 0x60001400: Code Section (.text)        │ ~30KB
├─────────────────────────────────────────┤
│ 0x60007F00: Read-only Data (.rodata)    │ ~4KB
├─────────────────────────────────────────┤
│ 0x60008C00: CSF (Code Signing Data)     │ ~4KB
├─────────────────────────────────────────┤
│ 0x60009800: End of active image         │
├─────────────────────────────────────────┤
│ 0x6003FFFF: End of 256KB                │ (unused)
└─────────────────────────────────────────┘

RAM Layout:
┌─────────────────────────────────────────┐
│ 0x20000000: .data section start         │
├─────────────────────────────────────────┤
│ 0x20000EC0: .data section end           │ ~3.75KB
├─────────────────────────────────────────┤
│ 0x20000EC0: .bss section start          │
├─────────────────────────────────────────┤
│ 0x200063E0: .bss section end            │ ~21.5KB
├─────────────────────────────────────────┤
│ 0x20006380: Status variables            │
├─────────────────────────────────────────┤
│ 0x2007F000: Stack top (approx)          │
└─────────────────────────────────────────┘
```

---

## 2. Peripheral Memory Map

### 2.1 Peripherals Used (from code analysis)

| Base Address | Peripheral | Reference in Code |
|--------------|------------|-------------------|
| 0x400D8000 | FlexCAN1 | @ 0x15E4 |
| 0x400D4000 | FlexCAN2 | @ 0x1630 |
| 0x400AC000 | LPUART1 | @ 0x1610 |
| 0x400FC000 | CCM | @ 0x1644 |
| 0x400C4000 | PIT | @ 0x1AA0 (inferred) |
| 0x40084000 | GPT1 | @ 0x162C |
| 0x401F8000 | USB1 | (from USB descriptors) |
| 0x401F4000 | USB PHY | (inferred) |
| 0x400D0000 | USB OTG1 | (inferred) |

### 2.2 FlexCAN1 Register Map (0x400D8000)

| Offset | Register | Description |
|--------|----------|-------------|
| 0x000 | MCR | Module Configuration |
| 0x004 | CTRL1 | Control 1 (bit timing) |
| 0x008 | TIMER | Free Running Timer |
| 0x00C | Reserved | - |
| 0x010 | RXMGMASK | RX Mailbox Global Mask |
| 0x014 | RX14MASK | RX Buffer 14 Mask |
| 0x018 | RX15MASK | RX Buffer 15 Mask |
| 0x01C | ECR | Error Counter |
| 0x020 | ESR1 | Error and Status 1 |
| 0x024 | IMASK2 | Interrupt Mask 2 |
| 0x028 | IMASK1 | Interrupt Mask 1 |
| 0x02C | IFLAG2 | Interrupt Flag 2 |
| 0x030 | IFLAG1 | Interrupt Flag 1 |
| 0x034 | CTRL2 | Control 2 |
| 0x038 | ESR2 | Error and Status 2 |
| 0x044 | CRCR | CRC Register |
| 0x048 | RXFGMASK | RX FIFO Global Mask |
| 0x04C | RXFIR | RX FIFO Information |
| 0x080-0x47F | MB[0-63] | Message Buffers |

### 2.3 System Control Block (0xE000E000)

| Offset | Register | Description |
|--------|----------|-------------|
| 0x010 | SYST_CSR | SysTick Control |
| 0x014 | SYST_RVR | SysTick Reload |
| 0x018 | SYST_CVR | SysTick Current |
| 0x100 | NVIC_ISER[0-7] | Interrupt Set Enable |
| 0x180 | NVIC_ICER[0-7] | Interrupt Clear Enable |
| 0x200 | NVIC_ISPR[0-7] | Interrupt Set Pending |
| 0x280 | NVIC_ICPR[0-7] | Interrupt Clear Pending |
| 0x300 | NVIC_IABR[0-7] | Interrupt Active Bit |
| 0x400 | NVIC_IPR[0-59] | Interrupt Priority |
| 0xD00 | CPUID | CPU ID |
| 0xD04 | ICSR | Interrupt Control State |
| 0xD08 | VTOR | Vector Table Offset |
| 0xD0C | AIRCR | Application Interrupt/Reset |
| 0xD10 | SCR | System Control |
| 0xD14 | CCR | Configuration Control |
| 0xD18 | SHPR1 | System Handler Priority 1 |
| 0xD24 | SHCSR | System Handler Control/State |
| 0xD88 | CPACR | Coprocessor Access Control |
| 0xD94 | MPU_CTRL | MPU Control |
| 0xD98 | MPU_RNR | MPU Region Number |
| 0xD9C | MPU_RBAR | MPU Region Base Address |
| 0xDA0 | MPU_RASR | MPU Region Attribute/Size |
| 0xF50 | ICIALLU | I-Cache Invalidate All |

---

## 3. Vector Table Analysis

### 3.1 Cortex-M7 Vector Table

The vector table for this device would be at 0x60001000 (relocated from default 0x00000000).

**IVT Header at 0x60001000:**
```
0x432000D1 = Tag=0xD1, Len=0x20, Ver=0x43
```

This is i.MX RT boot format, not standard Cortex-M vector table.
The actual NVIC vectors are set up dynamically.

### 3.2 Interrupt Handlers (Inferred)

| IRQ | Handler | Description |
|-----|---------|-------------|
| -1 | Reset_Handler @ 0x1648 | System reset |
| -2 | NMI_Handler | Non-maskable interrupt |
| -3 | HardFault_Handler | Hard fault |
| -4 | MemManage_Handler | Memory management fault |
| -5 | BusFault_Handler | Bus fault |
| -6 | UsageFault_Handler | Usage fault |
| -7...-4 | Reserved | - |
| -3 | SVC_Handler | Supervisor call |
| -2 | DebugMon_Handler | Debug monitor |
| -1 | Reserved | - |
| 0 | PendSV_Handler | Pendable service |
| 1 | SysTick_Handler | System tick |
| 36 | CAN1_Handler | FlexCAN1 interrupt |
| 37 | CAN2_Handler | FlexCAN2 interrupt |
| 113 | USB_OTG1_Handler | USB interrupt |

---

## 4. Stack and Heap

### 4.1 Stack Configuration

From code at 0x1A28:
```asm
1A28: mov     sp, r3           ; Set stack pointer
```

Stack appears to be at high end of DTCM:
- **Stack Top**: ~0x2007F000
- **Stack Size**: ~64KB reserved
- **Stack Growth**: Downward

### 4.2 Heap (if any)

No obvious heap allocation found. Likely static allocation only.

---

## 5. Memory Protection Unit (MPU)

### 5.1 MPU Configuration @ 0x1680

The code configures multiple MPU regions:

```asm
; MPU configuration sequence
1680: push    {r4}
1682: mov.w   r3, #0xE000E000
168C: str.w   r1, [r3, #0xD94]      ; Disable MPU
1690: str.w   r4, [r3, #0xD9C]      ; Region 0
1696: str.w   r0, [r3, #0xDA0]      ; Region config
...
1726: str.w   r2, [r3, #0xD94]      ; Enable MPU
```

### 5.2 MPU Region Attributes (Typical)

| Region | Base | Size | Attributes |
|--------|------|------|------------|
| 0 | 0x00000000 | 4GB | Background (default deny) |
| 1 | 0x60000000 | 256KB | Flash: RO, Execute |
| 2 | 0x20000000 | 512KB | RAM: RW, No Execute |
| 3 | 0x40000000 | 1MB | Peripheral: Device |
| 4 | 0xE0000000 | 1MB | System: Device |

---

## 6. Data Sections

### 6.1 .data Section (Initialized)

- **Flash source**: 0x60001C00
- **RAM destination**: 0x20000000
- **End**: 0x20000EC0
- **Size**: ~3,776 bytes

Contents: Initialized global variables, literal pools

### 6.2 .bss Section (Zero-initialized)

- **Start**: 0x20000EC0
- **End**: 0x200063E0
- **Size**: ~21,792 bytes

Contents: Uninitialized globals (cleared to zero at startup)

### 6.3 .rodata Section (Read-only)

- **Location**: 0x60007F00 - 0x600082FF
- **Size**: ~1,024 bytes

Contents: 
- String literals ("FIFO Enabled", "Interrupt Enabled", etc.)
- CAN status messages
- VIN string
- USB descriptors

---

## 7. Key Memory Addresses

### 7.1 From Literal Pool Analysis

| Address | Value | Purpose |
|---------|-------|---------|
| 0x15E4 | 0x400D8000 | FlexCAN1 base |
| 0x15F4 | 0x20000EC0 | .bss start |
| 0x15F8 | 0x60007A14 | Flash constant |
| 0x15FC | 0x20000000 | .data start |
| 0x1600 | 0x20000C00 | Vector table (RAM) |
| 0x1608 | 0xE000E400 | NVIC_IPR |
| 0x1610 | 0x400AC000 | LPUART1 |
| 0x1618 | 0x2000637C | Status variable |
| 0x1620 | 0x20200000 | OCRAM start |
| 0x1624 | 0xE0001000 | DWT base |
| 0x1630 | 0x400D4000 | FlexCAN2 base |
| 0x1638 | 0x20006380 | Main loop counter |
| 0x1644 | 0x400FC000 | CCM base |

### 7.2 Status Variables

| Address | Type | Description |
|---------|------|-------------|
| 0x20006368 | uint32_t | CAN RX error count |
| 0x2000636C | uint32_t | CAN TX error count |
| 0x20006370 | uint32_t | Message counter |
| 0x20006374 | uint32_t | Timestamp |
| 0x2000637C | uint32_t | DWT cycle counter |
| 0x20006380 | uint32_t | Main loop counter |

---

## 8. Flash Regions

### 8.1 Code Signing (HAB)

- **CSF Location**: 0x60008C00
- **CSF Size**: ~4KB
- **Purpose**: High Assurance Boot signature data

HAB validates:
1. IVT signature
2. Boot data integrity
3. Code hash

### 8.2 Unused Flash

The image is 38,912 bytes but the flash is 256KB.
Unused regions (0x60009800 - 0x6003FFFF) are typically 0xFF.

---

## 9. Comparison: i.MX RT1062 vs MPC5748G (Tesla Gateway)

| Feature | i.MX RT1062 (This) | MPC5748G (Gateway) |
|---------|--------------------|--------------------|
| Architecture | ARM Cortex-M7 | PowerPC e200z4 |
| Word size | 32-bit | 32-bit |
| Endianness | Little | Big |
| Flash | FlexSPI (external) | Internal + SPI |
| RAM | DTCM + OCRAM | SRAM + FlexRAM |
| CAN | FlexCAN | M_CAN |
| USB | USB OTG | USB OTG (limited) |
| Security | HAB | HSM |

---

## 10. For Gateway Analysis

To analyze the ACTUAL Tesla Gateway memory map, you need:

1. **Flash dump** from MPC5748G via JTAG
2. **Memory regions** for MPC5748G:
   - 0x00000000: Flash (6MB)
   - 0x40000000: SRAM (768KB)
   - 0xC3F00000: Peripheral base
   - 0xFFF00000: Boot ROM

The Gateway uses HSM (Hardware Security Module) which is NOT present in this Teensy adapter.

---

*Memory map analysis completed: Feb 3, 2026*
*Platform: NXP i.MX RT1062 / Teensy 4.x*
*Note: This is a CAN adapter, not the Tesla Gateway ECU*
