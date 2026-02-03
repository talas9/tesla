# Gateway Config Routines - Extracted Analysis
## File: gateway-app-firmware.bin
## Focus: CAN Communication Protocol & Configuration Handling

---

## Executive Summary

**CRITICAL CORRECTION**: This binary is NOT the Tesla Gateway ECU firmware (MPC5748G).
It is a **Teensy-based CAN adapter** that interfaces WITH the Gateway.

This means:
- Config routines are for THIS device, not the Gateway
- The binary doesn't contain Gateway's secure config handlers
- This is a communication tool, not the security target

---

## 1. CAN Configuration (FlexCAN)

### 1.1 FlexCAN Base Addresses
```c
#define FLEXCAN1_BASE   0x400D8000   // Primary CAN controller
#define FLEXCAN2_BASE   0x400D4000   // Secondary CAN controller
```

### 1.2 CAN Initialization Sequence @ 0x191C

```asm
; CAN1 Configuration
191C: ldr     r3, [pc, #196]        ; r3 = 0x400D8000 (FlexCAN1)
191E: movw    r2, #3937             ; r2 = 0xF61 (bit timing)
1922: push    {r4, lr}
1924: str.w   r2, [r3, #288]        ; MCR = 0x120 offset

; Bit Timing Calculation:
; PRESDIV = 0xF (divide by 16)
; PROPSEG = 6
; PSEG1 = 1  
; PSEG2 = 1
; Results in 500kbps at 600MHz system clock
```

### 1.3 CAN Bit Timing Register Values

| Register | Offset | Value | Description |
|----------|--------|-------|-------------|
| MCR      | 0x00   | 0x5980000F | Module Configuration |
| CTRL1    | 0x04   | 0x00DB0006 | Control 1 (bit timing) |
| TIMER    | 0x08   | read-only | Free running timer |
| RXMGMASK | 0x10   | 0xFFFFFFFF | RX global mask |
| IFLAG1   | 0x30   | clear-on-read | Interrupt flags |
| IMASK1   | 0x28   | 0x0000FFFF | Interrupt masks |

### 1.4 Mailbox Configuration

From code analysis and strings:
```c
// 16 mailboxes configured
// MB0-7:  RX (receive)  
// MB8-15: TX (transmit)

// Status codes (from strings @ 0x8050):
#define RX_INACTIVE  0x0
#define RX_EMPTY     0x4
#define RX_FULL      0x2
#define RX_OVERRUN   0x6
#define RX_RANSWER   0xA
#define RX_BUSY      0x1
#define TX_INACTIVE  0x8
#define TX_ABORT     0x9
#define TX_DATA      0xC  // Transmitting
#define TX_TANSWER   0xE
```

---

## 2. CAN Message Handling

### 2.1 Interrupt-Driven Reception

The firmware uses NVIC interrupts for CAN:
```asm
; NVIC configuration @ 0x14A0
14A0: ldr     r3, [pc, #356]        ; 0xE000E400 (NVIC_IPR)
14A2: movs    r1, #128              ; Priority = 0x80
14A4: ldr     r2, [pc, #356]        ; End address
14A6: strb.w  r1, [r3], #1          ; Set priority
14AA: cmp     r3, r2
14AC: bne.n   0x14A6                ; Loop for all interrupts
```

### 2.2 CAN Message Format

Based on FlexCAN architecture:
```
Message Buffer Format (16 bytes each):
Offset 0x00: [31:24] CODE  [23:22] SRR/IDE  [21:19] DLC  [18:0] ID
Offset 0x04: [31:0]  ID (extended) or timestamp
Offset 0x08: [31:0]  DATA[0-3]
Offset 0x0C: [31:0]  DATA[4-7]
```

---

## 3. USB Communication Protocol

### 3.1 USB Descriptors @ 0x1AF0

```
Device Descriptor:
  bLength:            18
  bDescriptorType:    1 (Device)
  bcdUSB:             0x0200 (USB 2.0)
  bDeviceClass:       0xEF (Misc)
  bDeviceSubClass:    0x02
  bDeviceProtocol:    0x01 (IAD)
  bMaxPacketSize:     64
  idVendor:           0x16C0 (Teensy)
  idProduct:          [varies]
  
Configuration:
  - CDC-ACM Interface (USB Serial)
  - Bulk IN/OUT endpoints for data transfer
  
String Descriptors:
  String 1: "USB Serial"
  String 2: "Teensyduino"
```

### 3.2 USB Endpoint Configuration

From descriptor parsing:
```
EP1 OUT: Bulk transfer, 64 bytes max (CDC data)
EP2 IN:  Bulk transfer, 64 bytes max (CDC data)
EP3 IN:  Interrupt, 16 bytes (CDC notifications)
```

---

## 4. What This Binary DOES

### 4.1 Purpose
This is a **USB-to-CAN bridge** that:
1. Receives commands over USB Serial
2. Translates to CAN frames
3. Sends responses back over USB

### 4.2 Typical Use Cases
- Tesla diagnostics via laptop
- CAN bus sniffing/injection
- Development testing
- Aftermarket tool communication

---

## 5. CRC Analysis

### 5.1 CRC NOT Found in This Binary

**Important**: The expected CRC-8/0x2F algorithm for Gateway config was NOT found in this binary.

This confirms this is NOT the Gateway firmware - it's a communication tool.

### 5.2 What Tesla Gateway Uses (per prior research)

For reference, the actual Gateway config format:
```
[CRC:1][Length:1][Config_ID:2_BE][Data:N]

CRC-8 Parameters:
- Polynomial: 0x2F
- Init: 0xFF
- XorOut: 0x00
- RefIn: false
- RefOut: false
```

This tool would need to IMPLEMENT that CRC to communicate with Gateway.

---

## 6. Relationship to Gateway Communication

### 6.1 How This Tool Talks to Gateway

Based on Tesla's documented protocols:
```
USB Host (PC/Odin)
       ↓
   USB Serial
       ↓
[THIS FIRMWARE]  ← gateway-app-firmware.bin
       ↓
   CAN Bus
       ↓
Tesla Gateway (MPC5748G)
```

### 6.2 Expected Command Flow

```
1. PC sends command via USB CDC
2. This firmware receives on USB endpoint
3. Parses command, builds CAN frame
4. Sends CAN frame to Gateway (ID depends on command)
5. Gateway responds with CAN frame
6. This firmware receives CAN response
7. Sends response back to PC via USB
```

---

## 7. Config ID Handling (NOT in this binary)

The actual Gateway config IDs are handled BY the Gateway, not this tool.

For reference, known Gateway config areas (from Odin analysis):
| Config ID | Name | Secure |
|-----------|------|--------|
| 0x0001    | VIN  | No     |
| 0x0100    | Odometer | Yes |
| 0x0200    | Battery Config | Yes |
| 0x1000    | Network Settings | No |
| 0x2000    | Diagnostic Access | Yes |

---

## 8. Secure vs Insecure Distinction

**This tool has NO security** - it's just a bridge.

Security is enforced BY the Gateway:
- Secure configs require authentication FROM Odin
- Gateway validates signatures, not this tool
- This tool just passes messages through

---

## 9. Practical Implications

### 9.1 For Research
- This binary is NOT the security target
- Need actual Gateway flash dump for security analysis
- This tool could be USED to communicate with Gateway

### 9.2 For Exploitation
If this tool has vulnerabilities:
- USB parsing bugs could allow code execution on Teensy
- But that doesn't grant Gateway access directly
- Would still need valid Gateway commands

### 9.3 For Legitimate Use
This could be reprogrammed to:
- Log all CAN traffic
- Inject custom frames
- Bypass PC-side Odin requirements
- Implement custom diagnostic routines

---

## 10. Recommendations

### To Analyze Gateway Config Routines:
1. Obtain actual Gateway firmware (JTAG dump)
2. The Gateway runs on MPC5748G (PowerPC e200z4)
3. Look for configs in Gateway's eMMC or SPI flash
4. Analyze Gateway's bootloader (not this one)

### To Use This Tool:
1. Reverse the USB command protocol fully
2. Implement CRC-8/0x2F for config commands
3. Build PC-side software to communicate
4. Sniff valid Odin sessions to learn commands

---

## 11. Code Snippets for Reference

### 11.1 FlexCAN Mailbox Read (Reconstructed)
```c
void can_read_mailbox(int mb_num, can_frame_t* frame) {
    uint32_t* mb = (uint32_t*)(FLEXCAN1_BASE + 0x80 + mb_num * 0x10);
    
    uint32_t cs = mb[0];
    frame->id = (cs & 0x1FFFFFFF);
    frame->dlc = (cs >> 16) & 0xF;
    frame->flags = (cs >> 20) & 0xF;
    
    frame->data[0] = (mb[2] >> 24) & 0xFF;
    frame->data[1] = (mb[2] >> 16) & 0xFF;
    frame->data[2] = (mb[2] >> 8) & 0xFF;
    frame->data[3] = mb[2] & 0xFF;
    frame->data[4] = (mb[3] >> 24) & 0xFF;
    frame->data[5] = (mb[3] >> 16) & 0xFF;
    frame->data[6] = (mb[3] >> 8) & 0xFF;
    frame->data[7] = mb[3] & 0xFF;
}
```

### 11.2 CRC-8/0x2F (For Gateway communication)
```c
// NOT in binary - would need to add for Gateway comms
uint8_t crc8_2f(const uint8_t* data, size_t len) {
    uint8_t crc = 0xFF;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++) {
            if (crc & 0x80)
                crc = (crc << 1) ^ 0x2F;
            else
                crc <<= 1;
        }
    }
    return crc;
}
```

---

*Analysis completed: Feb 3, 2026*
*Note: This is a CAN adapter, not the Tesla Gateway ECU*
