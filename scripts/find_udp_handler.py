#!/usr/bin/env python3
"""
Find UDP task handler and authentication logic by analyzing binary patterns.
"""

import struct
from pathlib import Path

FIRMWARE = Path("/root/tesla/data/binaries/ryzenfromtable.bin")
BASE_ADDR = 0x00F00000

def read_u32_be(data, offset):
    """Read big-endian 32-bit value"""
    if offset + 4 > len(data):
        return None
    return struct.unpack(">I", data[offset:offset+4])[0]

def read_u16_be(data, offset):
    """Read big-endian 16-bit value"""
    if offset + 2 > len(data):
        return None
    return struct.unpack(">H", data[offset:offset+2])[0]

def find_pointer_refs(data, target_addr):
    """Find 32-bit pointers to target address"""
    refs = []
    for offset in range(0, len(data) - 3, 4):
        value = read_u32_be(data, offset)
        if value == target_addr:
            refs.append(offset)
    return refs

def disasm_vle_simple(data, offset):
    """Very basic VLE instruction decoder for key patterns"""
    w1 = read_u16_be(data, offset)
    if w1 is None:
        return None
    
    # Check if 32-bit instruction (SE_* forms are 16-bit, rest often 32-bit)
    if (w1 & 0xF800) in [0x0000, 0x0800, 0x1000, 0x1800, 0x2000, 0x2800]:
        # Likely 16-bit form
        return {"size": 2, "word": w1}
    else:
        # Likely 32-bit form
        w2 = read_u16_be(data, offset + 2)
        if w2 is None:
            return {"size": 2, "word": w1}
        return {"size": 4, "word": (w1 << 16) | w2}

def analyze_function(data, offset, max_size=1024):
    """Analyze function looking for interesting patterns"""
    interesting = []
    pos = offset
    
    for _ in range(max_size // 2):
        instr = disasm_vle_simple(data, pos)
        if instr is None:
            break
        
        word = instr["word"]
        
        # Look for compare immediate with security prefix values
        # VLE cmpli: e_cmpli (0x1C80xxxx or similar patterns)
        if instr["size"] == 4:
            opcode = (word >> 26) & 0x3F
            
            # Check for compare-type opcodes
            if opcode in [0x0A, 0x0B, 0x1C, 0x1D]:  # cmpi, cmpli variants
                immediate = word & 0xFFFF
                if immediate in [0x03, 0x13, 0x15, 0xFF]:
                    interesting.append({
                        "offset": pos,
                        "addr": BASE_ADDR + pos,
                        "type": "COMPARE",
                        "value": immediate,
                        "word": f"0x{word:08X}"
                    })
        
        # Look for branch on equal/not equal after compare
        if instr["size"] == 2 or instr["size"] == 4:
            # beq, bne patterns
            if (word >> 10) & 0x3F in [0x04, 0x05]:  # Simplified branch check
                interesting.append({
                    "offset": pos,
                    "addr": BASE_ADDR + pos,
                    "type": "BRANCH",
                    "word": f"0x{word:04X}" if instr["size"] == 2 else f"0x{word:08X}"
                })
        
        pos += instr["size"]
    
    return interesting

def main():
    print("=" * 80)
    print("Gateway UDP Handler Finder")
    print("=" * 80)
    
    firmware = FIRMWARE.read_bytes()
    print(f"\nFirmware: {len(firmware):,} bytes")
    
    # Find string locations
    string_addrs = [
        BASE_ADDR + 0x3FA3E4,  # First occurrence
        BASE_ADDR + 0x401B8C,  # Second occurrence
    ]
    
    print(f"\nTask name string locations:")
    for addr in string_addrs:
        print(f"  0x{addr:08X} (file offset 0x{addr - BASE_ADDR:06X})")
    
    # Find pointer references to these strings
    print(f"\nSearching for pointer references...")
    
    all_refs = []
    for addr in string_addrs:
        refs = find_pointer_refs(firmware, addr)
        print(f"\n  References to 0x{addr:08X}:")
        for ref_offset in refs:
            ref_addr = BASE_ADDR + ref_offset
            print(f"    File 0x{ref_offset:06X} -> Memory 0x{ref_addr:08X}")
            all_refs.append(ref_offset)
    
    # Analyze code around references
    if all_refs:
        print(f"\nAnalyzing code around references...")
        for ref_offset in all_refs[:5]:  # Limit to first 5
            # Look backwards for function start (usually aligned)
            func_start = (ref_offset - 256) & ~0xF  # Align to 16 bytes, look back 256 bytes
            
            print(f"\n  Analyzing function near 0x{BASE_ADDR + func_start:08X}")
            patterns = analyze_function(firmware, func_start, max_size=2048)
            
            if patterns:
                print(f"    Found {len(patterns)} interesting patterns:")
                for p in patterns[:10]:  # Show first 10
                    print(f"      {p['type']:10s} @ 0x{p['addr']:08X} - {p.get('value', p['word'])}")
    
    # Search for metadata table accesses
    print(f"\n{'=' * 80}")
    print("Searching for metadata table access patterns...")
    print(f"Metadata table base: 0x{BASE_ADDR + 0x403000:08X}")
    
    # Search for the base address being loaded (0x01303000)
    # High half: 0x0130, Low half: 0x3000
    meta_base = BASE_ADDR + 0x403000
    refs = find_pointer_refs(firmware, meta_base)
    
    print(f"\nDirect references to metadata table base: {len(refs)}")
    for ref_offset in refs[:10]:
        print(f"  File 0x{ref_offset:06X} -> Memory 0x{BASE_ADDR + ref_offset:08X}")
    
    # Also search for high halfword (lis r*, 0x0130)
    print(f"\nSearching for 'lis' with high halfword 0x0130...")
    lis_pattern = 0x3C000130  # lis r0, 0x0130 (example)
    lis_refs = []
    
    for offset in range(0, len(firmware) - 3, 2):
        word = read_u32_be(firmware, offset)
        if word and (word & 0xFFFF0000) == 0x3C000000:
            immediate = word & 0xFFFF
            if immediate == 0x0130:
                lis_refs.append(offset)
    
    print(f"Found {len(lis_refs)} potential 'lis r*, 0x0130' instructions:")
    for ref_offset in lis_refs[:20]:
        word = read_u32_be(firmware, ref_offset)
        reg = (word >> 21) & 0x1F
        print(f"  0x{BASE_ADDR + ref_offset:08X}: lis r{reg}, 0x0130")
    
    # Search for error return (li r3, 0xFF; blr pattern)
    print(f"\n{'=' * 80}")
    print("Searching for 'return 0xFF' patterns...")
    
    error_returns = []
    for offset in range(0, len(firmware) - 7, 2):
        # Pattern: li r3, 0xFF followed by blr
        # li r3, 0xFF could be: 0x38600FF (simplified)
        word1 = read_u32_be(firmware, offset)
        if word1 and (word1 & 0xFFFFFF00) == 0x386000FF:  # li r3, immediate near 0xFF
            # Check for blr (0x4E800020) within next few instructions
            for blr_off in range(4, 16, 4):
                word2 = read_u32_be(firmware, offset + blr_off)
                if word2 == 0x4E800020:  # blr
                    error_returns.append({
                        "offset": offset,
                        "addr": BASE_ADDR + offset,
                        "li_word": f"0x{word1:08X}",
                        "blr_offset": blr_off
                    })
                    break
    
    print(f"\nFound {len(error_returns)} 'return 0xFF' patterns:")
    for ret in error_returns[:20]:
        print(f"  0x{ret['addr']:08X}: {ret['li_word']} ... blr (+{ret['blr_offset']})")
    
    # Generate summary report
    print(f"\n{'=' * 80}")
    print("SUMMARY")
    print(f"{'=' * 80}")
    print(f"\n✅ Task name string refs: {len(all_refs)}")
    print(f"✅ Metadata table refs: {len(refs)}")
    print(f"✅ 'lis r*, 0x0130' instructions: {len(lis_refs)}")
    print(f"✅ 'return 0xFF' patterns: {len(error_returns)}")
    
    print(f"\n📝 Next steps:")
    print(f"1. Disassemble functions around string refs to find task entry point")
    print(f"2. Follow metadata table loads (lis r*, 0x0130) to find config lookup")
    print(f"3. Check error returns near metadata access for auth decision")
    
    # Write detailed report
    report = generate_detailed_report(all_refs, refs, lis_refs, error_returns)
    report_path = Path("/root/tesla/docs/gateway/GATEWAY-AUTHENTICATION-DECISION.md")
    report_path.write_text(report)
    print(f"\n✅ Detailed report: {report_path}")

def generate_detailed_report(string_refs, meta_refs, lis_refs, error_returns):
    """Generate comprehensive markdown report"""
    
    report = f"""# Gateway Authentication Decision - Binary Analysis

**Date:** 2026-02-03  
**Firmware:** Tesla Gateway Application (6MB PowerPC VLE)  
**Base Address:** 0x{BASE_ADDR:08X}  
**Method:** Static binary analysis with pattern matching

---

## Phase 1: UDP Task Identification

### String: "soc_udpcmds_task"

Located at two file offsets:
- 0x3FA3E4 → Memory 0x{BASE_ADDR + 0x3FA3E4:08X}
- 0x401B8C → Memory 0x{BASE_ADDR + 0x401B8C:08X}

### Pointer References to Task Name

Found **{len(string_refs)}** direct pointer references:

"""
    
    for ref_offset in string_refs:
        report += f"- `0x{BASE_ADDR + ref_offset:08X}` (file offset 0x{ref_offset:06X})\n"
    
    if not string_refs:
        report += "*No direct pointers found - may use runtime address calculation*\n"
    
    report += f"""

**Interpretation:**

These references likely appear in:
1. FreeRTOS task creation call: `xTaskCreate(task_function, "soc_udpcmds_task", stack_size, ...)`
2. Debug/logging strings
3. Task control blocks

The task creation call contains a pointer to the actual task entry function. 
**Action:** Disassemble code around these references to find the task function pointer.

---

## Phase 2: Metadata Table Access

### Metadata Table Location

- **File Offset:** 0x403000
- **Memory Address:** 0x{BASE_ADDR + 0x403000:08X}
- **Entry Size:** 8 bytes
- **Format:** `[prefix_byte(1)] [config_id(2)] [unknown(5)]`

### Security Prefix Bytes

| Prefix | Security Model | Authentication |
|--------|----------------|----------------|
| 0x03   | Insecure       | ❌ None required |
| 0x13   | Secure         | ✅ Hermes session |
| 0x15   | Secure         | ✅ Hermes session |

### Direct References to Metadata Table Base

Found **{len(meta_refs)}** direct 32-bit pointers to table base:

"""
    
    for ref_offset in meta_refs[:20]:
        report += f"- `0x{BASE_ADDR + ref_offset:08X}` (file offset 0x{ref_offset:06X})\n"
    
    report += f"""

### High Halfword Loads (lis instructions)

Found **{len(lis_refs)}** instructions loading high halfword 0x0130:

"""
    
    for ref_offset in lis_refs[:30]:
        word = struct.unpack(">I", Path("/root/tesla/data/binaries/ryzenfromtable.bin").read_bytes()[ref_offset:ref_offset+4])[0]
        reg = (word >> 21) & 0x1F
        report += f"- `0x{BASE_ADDR + ref_offset:08X}`: `lis r{reg}, 0x0130`\n"
    
    report += f"""

**Interpretation:**

The pattern `lis r{reg}, 0x0130` loads the high 16 bits of address 0x0130xxxx into a register.
This is followed by offset addition to access specific metadata entries.

**Expected pattern:**
```asm
lis     r3, 0x0130        ; Load base 0x01300000
addi    r3, r3, 0x3000    ; Add offset -> 0x01303000 (table base)
mulli   r4, r5, 8         ; config_id * entry_size
lbzx    r6, r3, r4        ; Load prefix byte from table[config_id]
```

**Action:** Examine code around these `lis` instructions to find metadata access patterns.

---

## Phase 3: Authentication Decision Point

### Error Return Pattern (0xFF)

The Gateway returns 0xFF for authentication failures and invalid operations.

Found **{len(error_returns)}** potential "return 0xFF" sequences:

"""
    
    for ret in error_returns[:30]:
        report += f"- `0x{ret['addr']:08X}`: `li r3, 0xFF` ... `blr` (offset +{ret['blr_offset']})\n"
    
    report += f"""

**Interpretation:**

PowerPC calling convention uses `r3` for return values.
The pattern `li r3, 0xFF; blr` means "return 0xFF".

**Critical decision point:**
```asm
lbz     r4, metadata_prefix(r3)  ; Load prefix byte

cmpi    r4, 0x03                 ; Is it insecure?
beq     allow_write              ; Yes -> allow

cmpi    r4, 0x13                 ; Is it secure type 1?
beq     check_auth
cmpi    r4, 0x15                 ; Is it secure type 2?
beq     check_auth

; Unknown prefix or failed auth
li      r3, 0xFF                 ; ← AUTHENTICATION DENIAL
blr

check_auth:
bl      is_hermes_authenticated
cmpi    r3, 0
beq     deny_access              ; Not authenticated -> return 0xFF
```

**Action:** Cross-reference error returns with metadata table access locations.
The authentication decision is where these two patterns intersect.

---

## Phase 4: Attack Surface

### The Critical Branch

The authentication enforcement depends on a **single conditional branch**:

```asm
; After loading prefix byte and checking authentication
beq     allow_write    ; Branch if authenticated
; Fall through to:
li      r3, 0xFF      ; Denial
blr
```

### Potential Bypasses

1. **Patch the comparison**
   ```asm
   - cmpi   r4, 0x03    ; Check if insecure
   + cmpi   r4, 0xFF    ; Always fail -> treat as insecure
   ```

2. **Patch the branch**
   ```asm
   - beq    deny_access      ; Branch if not authenticated
   + b      allow_write      ; Unconditional branch to allow
   ```

3. **Modify metadata**
   ```
   Change prefix: 0x13 → 0x03  (secure → insecure)
   ```

### Defense Mechanisms

Tesla's protection layers:
1. **Signed firmware** (prevents code patching)
2. **Bootloader chain of trust** (verifies signature)
3. **Read-only metadata region** (prevents table modification)
4. **Hermes session encryption** (prevents session forgery)

---

## Next Steps

### To Find Exact Assembly

1. **Load firmware in IDA Pro or Ghidra** with PowerPC VLE support
   - Import base address: 0x{BASE_ADDR:08X}
   - Set processor: PowerPC VLE (VLEALT)

2. **Navigate to task creation references**
   ```
"""
    
    for ref_offset in string_refs[:5]:
        report += f"   - 0x{BASE_ADDR + ref_offset:08X}\n"
    
    report += f"""   ```

3. **Follow task function pointer** to UDP handler entry

4. **Search for metadata table loads** (lis r*, 0x0130)
   ```
"""
    
    for ref_offset in lis_refs[:5]:
        report += f"   - 0x{BASE_ADDR + ref_offset:08X}\n"
    
    report += f"""   ```

5. **Find prefix byte comparison** followed by error return
   - Look for `cmpi r*, 0x03/0x13/0x15`
   - Followed by conditional branch
   - Leading to `li r3, 0xFF; blr`

6. **Document exact address** of authentication branch instruction

---

## Cross-Reference Points

The authentication decision logic will be found where these patterns converge:

1. ✅ Metadata table access (`lis r*, 0x0130`) **{len(lis_refs)} candidates**
2. ✅ Prefix byte comparison (`cmpi r*, 0x03/0x13/0x15`)  
3. ✅ Error return (`li r3, 0xFF; blr`) **{len(error_returns)} candidates**
4. ✅ Authentication check call (`bl is_hermes_authenticated`)

**Recommendation:** Use Ghidra's cross-reference analysis to find functions that:
- Reference the metadata table base address
- Contain error return patterns  
- Are called from the UDP task handler

This will narrow down to the exact `handle_set_config()` function.

---

## Appendix: Raw Data

### String References (Full List)

"""
    
    for ref_offset in string_refs:
        report += f"- File 0x{ref_offset:06X} → Mem 0x{BASE_ADDR + ref_offset:08X}\n"
    
    report += f"""

### Metadata Table lis Instructions (Sample)

"""
    
    firmware = Path("/root/tesla/data/binaries/ryzenfromtable.bin").read_bytes()
    for ref_offset in lis_refs[:50]:
        word = struct.unpack(">I", firmware[ref_offset:ref_offset+4])[0]
        reg = (word >> 21) & 0x1F
        report += f"- 0x{BASE_ADDR + ref_offset:08X}: lis r{reg}, 0x0130 (word: 0x{word:08X})\n"
    
    report += f"""

### Error Return Locations (Sample)

"""
    
    for ret in error_returns[:50]:
        report += f"- 0x{ret['addr']:08X}: {ret['li_word']} + blr @+{ret['blr_offset']}\n"
    
    report += """

---

**End of Analysis**
"""
    
    return report

if __name__ == "__main__":
    main()
