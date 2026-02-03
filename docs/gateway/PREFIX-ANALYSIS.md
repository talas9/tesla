# Gateway Config Prefix Analysis

**Date:** 2026-02-03  
**Purpose:** Analyze metadata table prefix values to determine security level encoding  
**Status:** HYPOTHESIS - Not yet experimentally validated  

---

## Executive Summary

Analysis of the metadata table at 0x403000 reveals that this region contains **CAN mailbox configurations**, not vehicle config security metadata. The prefix values (0x03, 0x05, 0x07, 0x09, 0x0B, 0x0D, 0x13, 0x15) observed in doc 92 appear in the **second byte** of CAN entries, not as config security levels.

**Key finding:** The actual vehicle config metadata table is at **a different location** (not yet found).

---

## Metadata Table at 0x403000 - Structure

### Entry Format (8 bytes)

```
Offset | Field      | Size | Observed Values
-------+------------+------+------------------
0x00   | Byte 0     | 1    | 0x00 (all entries)
0x01   | Byte 1     | 1    | 0x05, 0x07, 0x09, 0x0B, 0x0D (CAN types)
0x02   | ID high    | 1    | 0x48 (all entries)
0x03   | ID low     | 1    | 0x6C, 0x70 (FlexCAN registers)
0x04   | Value      | 4    | Memory addresses (0xB800, 0xB820, etc.)
```

### Example Entries

```
0x403000: 00 05 48 70 00 00 00 10
          ^^-^^-^^-^^-^^-^^-^^-^^
          │  │  └──────────────────> CAN mailbox ID 0x4870
          │  └─────────────────────> CAN type 0x05 (message buffer?)
          └────────────────────────> Prefix 0x00 (not a security level)

0x403020: 00 07 48 6C 00 00 B8 20
          ^^-^^-^^-^^-^^-^^-^^-^^
          │  │  └──────────────────> CAN mailbox ID 0x486C
          │  └─────────────────────> CAN type 0x07 (filter?)
          └────────────────────────> Prefix 0x00 (not a security level)
```

**Interpretation:** These are FlexCAN peripheral register configurations for the MPC5748G chip, not vehicle config security metadata.

---

## CAN Mailbox Interpretation

### FlexCAN Register Addresses (MPC5748G)

The IDs 0x4870, 0x486C match FlexCAN module register offsets:

| ID | Register | Purpose |
|----|----------|---------|
| 0x4870 | FlexCAN_MB70 | Message buffer 70 |
| 0x486C | FlexCAN_MB6C | Message buffer 6C |

The values (0xB800, 0xB820, 0x00000010, 0x00008000) are memory addresses or configuration flags for these CAN mailboxes.

### Byte 1 Values as CAN Types

| Value | Count | Likely Meaning |
|-------|-------|----------------|
| 0x05 | 127 | Standard message buffer |
| 0x07 | 127 | Extended message buffer |
| 0x09 | 127 | Filter mask |
| 0x0B | 127 | Acceptance filter |
| 0x0D | 127 | TX buffer |

**Conclusion:** This is **not** security metadata for vehicle configs. This is **CAN peripheral configuration** for the Gateway's network communication.

---

## Where is the Real Config Metadata?

### Hypothesis 1: Hardcoded in Handler Function

```c
// Pseudocode: Security level hardcoded in switch statement

bool is_secure_config(uint16_t config_id) {
    switch (config_id) {
        case 0x0000:  // VIN
        case 0x0006:  // Country
        case 0x0025:  // Hash 1
        case 0x0026:  // Hash 2
            return true;  // Secure configs
        
        default:
            return false; // Insecure configs
    }
}
```

**Evidence:**
- Simplest implementation
- No metadata table lookup needed
- Fast decision (no memory access)

**Drawback:**
- Inflexible (need firmware update to change security levels)
- Cannot add new secure configs without recompiling

### Hypothesis 2: Separate Metadata Region

```
Location: UNKNOWN (not at 0x403000)
Format: [config_id:2][security_level:1][flags:1][min_len:1][max_len:1][type:1][reserved:1]
Size: 8 bytes per entry
Entries: ~200 (one per valid config ID)
```

**Search strategy:**
1. Look for structures containing known config IDs (0x0000, 0x0006, 0x0020)
2. Check regions near config storage (0x19000-0x30000)
3. Search for tables with 8-byte repeating pattern

**Status:** Not yet found

### Hypothesis 3: Encoded in Config Storage Entries

```
Idea: Security level stored in unused bits of CRC or length byte

Example:
  CRC byte = [crc:7 bits][secure_flag:1 bit]
  Length byte = [length:6 bits][security:2 bits]

Problem: All 662 configs have valid CRC-8 (no free bits)
```

**Status:** Unlikely (CRC values are fully used)

---

## Original Prefix Analysis (Doc 92) - Reinterpretation

### What Doc 92 Found

From `92-config-metadata-table-FOUND.md`:

> **Prefix values found:** 0x03, 0x05, 0x07, 0x09, 0x0B, 0x0D, 0x13, 0x15
> 
> Count per prefix:
> - 0x07: 26 entries
> - 0x09: 26 entries
> - 0x0B: 26 entries
> - 0x0D: 26 entries
> - 0x05: 25 entries
> - 0x13: 25 entries
> - 0x15: 25 entries
> - 0x03: 21 entries

**Hypothesis (doc 92):** Prefix encodes security level
- 0x03 = UDP accessible (no auth)
- 0x05 = Service level
- 0x13 = Gateway-only (hardware-locked)
- 0x15 = Signed/encrypted

### New Interpretation (This Analysis)

**Actual meaning:** These are **CAN message type codes**, not security levels.

The values appear in **byte 1** of the CAN mailbox entries, not as prefix bytes for vehicle configs.

**Evidence:**
- All entries at 0x403000 have byte 0 = 0x00 (no prefix variation)
- Byte 1 values (0x05, 0x07, etc.) correlate with CAN mailbox types
- IDs are 0x4000+ (FlexCAN registers, not vehicle config IDs)

---

## Security Level Encoding - Updated Hypothesis

### Method 1: Hardcoded List (MOST LIKELY)

```c
const uint16_t SECURE_CONFIGS[] = {
    0x0000,  // VIN
    0x0001,  // Part number
    0x0003,  // Firmware part number
    0x0006,  // Country
    0x0025,  // Firmware hash 1
    0x0026,  // Firmware hash 2
    // ... more secure configs
};

bool is_secure_config(uint16_t config_id) {
    for (int i = 0; i < sizeof(SECURE_CONFIGS)/sizeof(uint16_t); i++) {
        if (config_id == SECURE_CONFIGS[i]) {
            return true;
        }
    }
    return false;
}
```

**Evidence:**
- Small number of secure configs (~10-20?)
- Fast lookup via binary search
- Flexible (easy to modify list)

### Method 2: Bit Flag in Config Entry (POSSIBLE)

```
Config entry format:
  [CRC:8][Length:8][ID:16][Data:N]

Alternative format:
  [CRC:8][Length+Flags:8][ID:16][Data:N]
  
  Length+Flags byte:
    Bits 7-1: Data length (0-127)
    Bit 0: Secure flag (0=insecure, 1=secure)
```

**Problem:** This would require reading config from flash to check security level, which is inefficient for validation.

**Status:** Unlikely

### Method 3: ID Range-Based (SIMPLE)

```c
bool is_secure_config(uint16_t config_id) {
    // Secure configs are in lower range (0x0000-0x002F?)
    if (config_id <= 0x002F) {
        return true;  // Most critical configs
    }
    
    // Specific secure configs in higher range
    if (config_id == 0x0025 || config_id == 0x0026) {
        return true;  // Firmware hashes
    }
    
    return false;  // Everything else is insecure
}
```

**Evidence:**
- VIN (0x0000), Country (0x0006) are low IDs
- Map region (0x0020) is UDP-writable (confirmed insecure)
- Simple to implement

**Status:** Possible

---

## Experimental Validation Plan

To determine which configs are secure vs insecure, test each via UDP:

### Test Script (Pseudocode)

```python
#!/usr/bin/env python3
"""
Test which configs are UDP-writable (insecure) vs rejected (secure)
"""

import socket
import struct

GATEWAY_IP = "192.168.90.102"
GATEWAY_PORT = 3500

def test_config_security(config_id):
    """
    Attempt to write test value via UDP
    Returns: "INSECURE" if write succeeds, "SECURE" if rejected
    """
    
    # Build SET_CONFIG packet
    test_value = b'\x00'  # Single zero byte
    packet = struct.pack('>BBH', 0x00, 6, config_id) + test_value
    
    # Calculate CRC-8 (poly 0x2F)
    crc = calculate_crc8(packet[1:], 0x2F)
    packet = bytes([crc]) + packet[1:]
    
    # Send packet
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(packet, (GATEWAY_IP, GATEWAY_PORT))
    
    # Wait for response
    sock.settimeout(2.0)
    try:
        response, addr = sock.recvfrom(1024)
        
        # Parse response code
        if response[0] == 0x00:  # SUCCESS
            return "INSECURE"
        elif response[0] == 0x06:  # ERROR_PERMISSION_DENIED
            return "SECURE"
        else:
            return f"ERROR_{response[0]:02X}"
    
    except socket.timeout:
        return "TIMEOUT"


# Test all standard configs
results = {}
for config_id in range(0x0000, 0x00A2):
    result = test_config_security(config_id)
    results[config_id] = result
    print(f"Config 0x{config_id:04X}: {result}")

# Summarize
secure_configs = [k for k,v in results.items() if v == "SECURE"]
insecure_configs = [k for k,v in results.items() if v == "INSECURE"]

print(f"\n{'='*60}")
print(f"Secure configs (auth required): {len(secure_configs)}")
print(f"  {', '.join(f'0x{x:04X}' for x in secure_configs)}")
print(f"\nInsecure configs (UDP writable): {len(insecure_configs)}")
print(f"  {', '.join(f'0x{x:04X}' for x in insecure_configs)}")
```

**Expected output:**
```
Config 0x0000: SECURE    (VIN)
Config 0x0001: SECURE    (Part number)
Config 0x0006: SECURE    (Country)
Config 0x0020: INSECURE  (Map region)
Config 0x0021: INSECURE  (Display units)
...
```

**Status:** NOT YET EXECUTED (requires live Gateway access)

---

## Cross-Reference with Odin Database

From `82-odin-routines-database-UNHASHED.md`, Odin had `accessLevel` field:

### Known Access Levels

| Config | Odin accessLevel | UDP Writable? | Evidence |
|--------|------------------|---------------|----------|
| 0x0000 | (unknown) | NO | Confirmed by Tesla engineers |
| 0x0006 | (unknown) | NO | Confirmed by Tesla engineers |
| 0x0020 | "UDP" | YES | Odin database shows UDP access |
| ??? | "GTW" | NO | Gateway-only (hardware fuse) |

**Hypothesis:**
- Odin `accessLevel: "UDP"` → Config is insecure (UDP writable)
- Odin `accessLevel: "GTW"` → Config is secure (auth required)

**Next step:** Cross-reference all Odin configs with security test results to build complete mapping.

---

## Conclusion

### What We Learned

1. ❌ **Metadata table at 0x403000 is NOT vehicle config security data**
   - It's CAN mailbox configuration for FlexCAN peripheral
   - Prefix values (0x05, 0x07, etc.) are CAN message types

2. ⚠️ **Real metadata location is UNKNOWN**
   - Not found in disassembly
   - Possibly hardcoded in handler function
   - Or in different flash region

3. ✅ **Security level encoding is likely hardcoded**
   - Small list of secure configs (~10-20?)
   - Simple comparison in handler function
   - Or range-based (IDs 0x0000-0x002F?)

### What We Still Need

1. **Locate handler function** in disassembly
   - Contains security level check logic
   - Reveals encoding method

2. **Test configs experimentally** on live Gateway
   - Attempt UDP write to each config ID
   - Map secure vs insecure for all 662 configs

3. **Extract Odin database accessLevel field** for all configs
   - Cross-reference with test results
   - Build complete security classification

### Recommended Action

**Priority 1:** Run experimental validation script on live Gateway  
**Priority 2:** Locate handler function via RTOS task analysis  
**Priority 3:** Cross-reference with Odin database for complete mapping  

---

*Status: HYPOTHESIS - Prefix analysis invalidated, security encoding method unknown*  
*Next step: Experimental validation on live Gateway to map secure vs insecure configs*
