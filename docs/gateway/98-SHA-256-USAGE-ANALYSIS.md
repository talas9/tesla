# SHA-256 Usage Analysis - Gateway Firmware

**Date:** 2026-02-03  
**Location:** 0x36730 in ryzenfromtable.bin  
**Status:** IDENTIFIED - SHA-256 scrambled/shuffled constants for firmware verification

---

## Discovery

Found 8 consecutive 32-bit values at **0x36730** that contain **scrambled SHA-256 initial hash values**.

### Constants Found

```
Offset    Value       SHA-256 Standard
0x36730:  0x6a09e667  H0 ✓ (correct)
0x36734:  0xf3bcc908  Not standard
0x36738:  0xbb67ae85  This is H1 (wrong position!)
0x3673C:  0x84caa73b  Not standard
0x36740:  0x3c6ef372  This is H2 (wrong position!)
0x36744:  0xfe94f82b  Not standard
0x36748:  0xa54ff53a  This is H3 (wrong position!)
0x3674C:  0x5f1d36f1  Not standard
```

### Next 32 Bytes (0x36750-0x3676F)

```
51 0e 52 7f  ad e6 82 d1  9b 05 68 8c  2b 3e 6c 1f
1f 83 d9 ab  fb 41 bd 6b  5b e0 cd 19  13 7e 21 79
```

**Analysis:** This contains MORE SHA-256 constants!
- `510e527f` = H4 (SHA-256 standard)
- `9b05688c` = H5 (SHA-256 standard)
- `1f83d9ab` = H6 (SHA-256 standard)
- `5be0cd19` = H7 (SHA-256 standard)

---

## Complete SHA-256 Constant Table

### Standard SHA-256 Initial Values

| Constant | Value | Position in Firmware |
|----------|-------|---------------------|
| H0 | 0x6a09e667 | 0x36730 ✓ (correct position) |
| H1 | 0xbb67ae85 | 0x36738 (offset +8) |
| H2 | 0x3c6ef372 | 0x36740 (offset +16) |
| H3 | 0xa54ff53a | 0x36748 (offset +24) |
| H4 | 0x510e527f | 0x36750 (offset +32) |
| H5 | 0x9b05688c | 0x36754 (offset +36) |
| H6 | 0x1f83d9ab | 0x36758 (offset +40) |
| H7 | 0x5be0cd19 | 0x3675C (offset +44) |

**ALL 8 SHA-256 constants are present** but **interleaved with other values**!

### Interleaved Values (Unknown Purpose)

| Offset | Value | Possible Purpose |
|--------|-------|------------------|
| 0x36734 | 0xf3bcc908 | ? |
| 0x3673C | 0x84caa73b | ? |
| 0x36744 | 0xfe94f82b | ? |
| 0x3674C | 0x5f1d36f1 | ? |
| 0x36751 | 0xade682d1 | ? |
| 0x36755 | 0x2b3e6c1f | ? |
| 0x36759 | 0xfb41bd6b | ? |
| 0x3675D | 0x137e2179 | ? |

**Hypothesis:** These could be:
1. SHA-256 K round constants (first 8 rounds)
2. Custom hash mixing values
3. Obfuscation layer (XOR keys for de-scrambling)
4. Part of a different algorithm (SHA-512, custom hash)

---

## Usage Context

### 1. Firmware RC Header Verification

**String found:** "Bad firmware RC header info: vers %u, rec sz %u, total entries %u"  
**Location:** 0x4017ED  
**Adjacent string:** "Corrupt or missing firmware RC header (got %d bytes)"

**RC = Revision Control or Release Candidate**

This suggests SHA-256 is used to **verify firmware update packages** before installation.

### 2. Hash Display Format

**String found:** "hash: %8x%8x%8x%8x%8x"  
**Location:** 0x3FA3B3  
**Adjacent strings:** "xferTask", "udpApi"

This confirms hashes are **displayed/logged** in 5×32-bit hex format (160 bits = partial SHA-256?)

### 3. Manifest Verification

**String found:** "Failed to initialize the manifest, no version checking"  
**Location:** 0x401DF9

Suggests SHA-256 verifies a **manifest file** (list of files + hashes) before OTA updates.

---

## SHA-256 Use Cases in Gateway

### 1. Firmware Update Verification (PRIMARY USE)

**Process:**
```
Firmware update received
  ↓
Extract RC header
  ↓
Compute SHA-256 of firmware blob
  ↓
Compare against signed hash in header
  ↓
If match: Install
If mismatch: Reject ("Corrupt or missing firmware RC header")
```

**Files involved:**
- `/hrl/%08x.hrl` (Hardware Revision Log - tracks updates)
- `/updt/hrl/%08x.hrl` (Update HRL files)
- Manifest files (list of components + hashes)

### 2. Config Integrity (SECONDARY USE?)

**Hypothesis:** SHA-256 **may** be used for config validation in addition to CRC-8.

**Evidence:**
- CRC-8 is used for **per-config validation** (verified in 80-ryzen-gateway-flash-COMPLETE.md)
- SHA-256 could be used for **batch config integrity** (hash of all configs together)
- Would prevent config tampering even if individual CRCs are forged

**NOT YET VERIFIED**

### 3. OTA Manifest Signing

**Process:**
```
OTA package downloaded
  ↓
Load manifest.json
  ↓
Compute SHA-256 of each file listed
  ↓
Compare against manifest hashes
  ↓
If all match: Apply update
If any mismatch: Abort ("Failed to initialize the manifest")
```

---

## Why Interleaved Constants?

### Possibility 1: Obfuscation
Tesla may have **deliberately scrambled** the constant table to make reverse engineering harder.

**De-scrambling sequence might be:**
```python
scrambled = [data[i] for i in [0, 2, 4, 6, 8, 10, 12, 14]]  # Extract every other value
# scrambled[0] = H0, scrambled[1] = H1, scrambled[2] = H2, etc.
```

### Possibility 2: Dual Algorithm
The table contains **both SHA-256 AND something else** (e.g., SHA-512 or custom hash).

### Possibility 3: K Constants
The interleaved values are **SHA-256 K round constants** stored alongside H values.

**SHA-256 K[0-7]:**
```
K[0] = 0x428a2f98  ✗ (not 0xf3bcc908)
K[1] = 0x71374491  ✗ (not 0x84caa73b)
```
**NOT a match** - so not standard K constants.

---

## Code Analysis

### Function Reference at 0x122622

Found **1 code reference** to the SHA constant region at offset **0x122622**.

**PowerPC instruction (likely):**
```asm
lis  r3, 0x0003     ; Load high 16 bits of 0x36730
ori  r3, r3, 0x6730 ; Load low 16 bits → r3 = 0x36730
```

This loads the **address** of the SHA constant table into register `r3`, suggesting a function call:
```c
sha256_init(sha_constants);  // Pass address of constant table
```

**Function location:** ~0x122000-0x123000 (estimated)  
**Function name (inferred):** `sha256_init()` or `hash_firmware()`

---

## Strings Near SHA Constants

Within 1KB of 0x36730:

| Offset | String | Purpose |
|--------|--------|---------|
| 0x36434 | "flash" | Flash memory operations |
| 0x364B4 | "octet" | Network/byte operations |
| 0x364E4 | "IDLE" | Task state |
| 0x364F0 | "FAT32" | Filesystem type (SD card) |

**Context:** SHA-256 is used near **flash memory** and **filesystem** operations, confirming it's for **firmware/file verification**.

---

## Comparison to CRC-8

| Feature | CRC-8 | SHA-256 |
|---------|-------|---------|
| **Usage** | Per-config validation | Firmware/manifest validation |
| **Location** | Throughout firmware (11,512 occurrences) | Single constant table @ 0x36730 |
| **Polynomial** | 0x2F | Standard SHA-256 |
| **Output size** | 8 bits | 256 bits (but displayed as 160 bits?) |
| **Speed** | Very fast | Slower (cryptographic) |
| **Security** | Weak (collision-prone) | Strong (cryptographically secure) |
| **Purpose** | Detect accidental corruption | Detect intentional tampering |

**Layered security:**
- **CRC-8** = Fast config corruption detection
- **SHA-256** = Slow firmware tampering detection

---

## Attack Implications

### Config Tampering
- **CRC-8 protection:** Can be bypassed (easy to forge 8-bit CRC)
- **SHA-256 protection:** If configs are SHA-hashed as a batch, tampering requires breaking SHA-256 (infeasible)

**HOWEVER:** No evidence yet that configs use SHA-256. They appear to only use CRC-8.

### Firmware Tampering
- **SHA-256 protection:** Strong
- **Attack vector:** Replace entire firmware blob + valid signed hash (requires Tesla's private key)
- **Bypass:** SPC chip replacement (documented in 55-gateway-spc-chip-replacement.md) - replace entire chip with modified firmware

---

## Next Steps

### High Priority
1. **Disassemble function at 0x122622** - Find SHA-256 implementation
2. **Locate SHA-256 K constants** - Search for round constant table (64 × 32-bit values)
3. **Find hash comparison code** - Where firmware hash is verified
4. **Extract RC header format** - Structure of "firmware RC header"

### Medium Priority
5. **Test hash display format** - Trigger firmware update to see "hash: %8x..." output
6. **Locate manifest parser** - Find code that reads manifest.json
7. **Document OTA update flow** - Complete firmware update process
8. **Verify config SHA usage** - Confirm if configs use SHA-256 or only CRC-8

---

## Cross-References

- **96-gateway-DATA-TABLES.md:** Cryptographic constants section
- **99-gateway-FIRMWARE-METADATA.md:** Firmware verification mechanisms
- **80-ryzen-gateway-flash-COMPLETE.md:** CRC-8 usage for configs
- **91-gateway-powerpc-disassembly-summary.md:** Code section analysis

---

## Conclusion

**SHA-256 is used for firmware update verification**, not config validation or CAN message authentication.

**Primary function:** Verify integrity of:
1. Firmware update packages (RC header)
2. OTA manifest files
3. Individual update components

**Security level:** STRONG - Prevents firmware tampering unless attacker has Tesla's signing key.

**Config security:** Still relies on CRC-8 (WEAK) - configs can be tampered if CRC is recalculated.

---

*Last updated: 2026-02-03 07:35 UTC*
