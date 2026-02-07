# Evidence Quality Standards

**Verification framework for research claims.**

---

## Confidence Levels

### ✅ VERIFIED (95-100% confidence)

**Requirements:**
- Multiple independent sources confirm
- Binary offsets or code citations
- Tested and validated

**Examples:**
- CRC-8 polynomial 0x2F (100% validation on 662 configs)
- SHA256 config hashing (decompiled source code)
- Fernet ODJ encryption (working decryption)

### ⚠️ INFERRED (60-80% confidence)

**Requirements:**
- Logical deduction from evidence
- String analysis or pattern matching
- Limited testing

**Examples:**
- Service mode backend validation (symbol analysis, not packet capture)
- APE bearer token requirement (string evidence)
- Port 25956 behavior (observed, not disassembled)

### ❌ UNTESTED (<60% confidence)

**Requirements:**
- Theoretical only
- No hardware validation
- Based on documentation or patterns

**Examples:**
- CAN flood success rate across firmware versions
- Exact gwmon timeout value
- Geofence restriction regions

---

## Evidence Types

### Strong Evidence

| Type | Description | Example |
|------|-------------|---------|
| Binary offset | Exact location in firmware | `0x655ec0: setServicePIN()` |
| CRC validation | 100% match on known data | 662 configs all pass |
| Decompiled source | Original code recovered | Odin config_options.py |
| Working tool | Functional implementation | decrypt_odj.py |
| Multiple sources | Independent confirmation | VIN at config 0x0000 |

### Medium Evidence

| Type | Description | Example |
|------|-------------|---------|
| String extraction | Function names found | `GUI_serviceModeAuth` |
| Pattern matching | Consistent structure | Config entry format |
| D-Bus config | Permission analysis | doip-gateway privilege |
| Single source | One reliable source | Internal researcher confirmation |

### Weak Evidence

| Type | Description | Example |
|------|-------------|---------|
| Naming inference | Guessed from names | Function purpose |
| Documentation | Tesla docs (may change) | Port numbers |
| Speculation | Logical but unconfirmed | Timeout values |
| Single observation | One test result | CAN flood timing |

---

## Per-Topic Quality Assessment

### Gateway Research

| Topic | Status | Evidence Quality |
|-------|--------|-----------------|
| 662 configs extracted | ✅ VERIFIED | Flash dump + CRC validation |
| CRC-8 polynomial | ✅ VERIFIED | 100% match rate |
| Two-tier security | ✅ VERIFIED | Odin database + source confirm |
| UDP protocol format | ✅ VERIFIED | Working implementation |
| Config metadata table | ⚠️ INFERRED | Found table, flags unverified |

### Odin Research

| Topic | Status | Evidence Quality |
|-------|--------|-----------------|
| SHA256 hashing | ✅ VERIFIED | Decompiled source |
| Fernet encryption | ✅ VERIFIED | Working decryption |
| Access levels | ✅ VERIFIED | JSON database |
| Config ID mapping | ⚠️ PARTIAL | Some IDs unknown |

### Service Mode

| Topic | Status | Evidence Quality |
|-------|--------|-----------------|
| No hardcoded PIN | ✅ VERIFIED | Binary search negative |
| Backend validation | ⚠️ INFERRED | Symbol + D-Bus analysis |
| Geofence function | ⚠️ INFERRED | Function name exists |
| Exact validation flow | ❌ UNTESTED | Needs packet capture |

### USB Updates

| Topic | Status | Evidence Quality |
|-------|--------|-----------------|
| Package structure | ✅ VERIFIED | Real package analysis |
| Ed25519 signature | ✅ VERIFIED | Magic byte + size match |
| dm-verity format | ✅ VERIFIED | Table extracted |
| Signature bypass | ❌ NOT FOUND | No method exists |

### CAN Flood

| Topic | Status | Evidence Quality |
|-------|--------|-----------------|
| Port 25956 opening | ⚠️ INFERRED | Single vehicle test |
| Message IDs required | ⚠️ INFERRED | Script works sometimes |
| Reliability rate | ❌ UNTESTED | Single data point |
| Firmware mitigations | ⚠️ INFERRED | Behavior changes observed |

---

## Documentation Standards

### Required for All Claims

1. **Source citation** - File path, binary offset, or code reference
2. **Verification status** - One of: VERIFIED, INFERRED, UNTESTED
3. **Evidence type** - What proves this claim
4. **Date** - When verified (findings may become outdated)

### Example Citation

```markdown
### Finding: VIN stored at config ID 0x0000

**Status:** ✅ VERIFIED  
**Evidence:** 
- Flash dump extraction at offset 0x19004
- CRC-8 validation passed
- Confirmed by Odin database (accessId mapping)
**Source:** [gateway/80-ryzen-gateway-flash-COMPLETE.md]
**Date:** 2026-02-03
```

---

## Contradictions Resolved

| Topic | Old Claim | New Claim | Resolution |
|-------|-----------|-----------|------------|
| Config count | "~90 configs" | "662 configs" | Ryzen has more than Intel MCU |
| Config hashing | "Unknown" | "SHA256 complete" | Algorithm decompiled |
| Service PIN | "May be local hash" | "Backend only" | Binary analysis |
| Cert validity | "10 years" | "~2 years" | Certificate analysis |

All contradictions were resolved by preferring:
1. More recent analysis
2. Multiple sources over single
3. Binary evidence over speculation

---

## Updating Documentation

### When to Update

- New firmware analysis
- Hardware validation
- Contradiction found
- Tool created/tested

### Update Process

1. Verify new finding against existing
2. Update status marker if improved
3. Add new evidence citation
4. Note date of update
5. Resolve any contradictions

---

## Quality Metrics

### Current Repository Status

| Category | Count | Percentage |
|----------|-------|------------|
| VERIFIED | ~25 documents | 40% |
| INFERRED | ~20 documents | 35% |
| UNTESTED | ~15 documents | 25% |

### Target

| Category | Target |
|----------|--------|
| VERIFIED | >50% |
| INFERRED | <35% |
| UNTESTED | <15% |

---

**Last Updated:** 2026-02-07
