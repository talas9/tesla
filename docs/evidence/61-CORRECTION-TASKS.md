# Document Correction Task List

**Generated:** 2026-02-03  
**Purpose:** Line-by-line fixes needed for evidence quality

This is the actionable task list from the evidence audit. Each task is specific, measurable, and can be completed independently.

---

## 🔴 CRITICAL FIXES (Do These First)

### 02-gateway-can-flood-exploit.md
**Issue:** Exploit code with no testing evidence  
**Tasks:**
- [ ] Add header: "⚠️ UNTESTED EXPLOIT - Theoretical only, not validated"
- [ ] Line 1: Add evidence disclaimer
- [ ] Throughout: Replace "will work" → "may work (untested)"
- [ ] Add section: "Validation Checklist" with test requirements
- [ ] Mark exploit code blocks with `# UNTESTED - DO NOT RUN IN PRODUCTION`

**Estimated time:** 30 minutes

---

### 03-certificate-recovery-orphan-cars.md
**Issue:** 22 uncertain phrases, theoretical procedures  
**Tasks:**
- [ ] Line 1: Add "⚠️ THEORETICAL - Recovery procedures not tested"
- [ ] Line 17: Change "Theoretical Recovery Procedures" → "Proposed Recovery Procedures (Untested)"
- [ ] Line 271-500: Add "**Status:** Untested hypothesis" to each procedure
- [ ] Line 316: Add comment to code: `# WARNING: This is theoretical code`
- [ ] Add references section: Document what files/paths need validation
- [ ] Create validation checklist at end

**Estimated time:** 1 hour

---

### 04-network-ports-firewall.md
**Issue:** No evidence, needs actual network scan  
**Tasks:**
- [ ] Line 1: Add "⚠️ NEEDS VALIDATION - Based on analysis, not live scan"
- [ ] Line 525: Change "could be exploited" → "potential exploit vector (needs testing)"
- [ ] Line 689: Remove "assumed", add "needs verification"
- [ ] Add section: "Validation Required" listing what to test
- [ ] Document methodology: How were ports discovered?
- [ ] Add disclaimer: "Port list compiled from documentation, not live scan"

**Estimated time:** 45 minutes

---

## 🟠 HIGH PRIORITY FIXES

### 26-bootloader-exploit-research.md
**Issue:** Claims 7 CVEs without full validation  
**Tasks:**
- [ ] Create CVE validation table with columns: CVE | Status | Evidence | Test Results
- [ ] Mark each CVE as: ✅ Tested | ⚠️ Partial Evidence | ❌ Theoretical
- [ ] Add "Validation Status" section at top
- [ ] For untested CVEs, add: "Requires hardware testing"
- [ ] Link to actual proof-of-concept code or mark as "PoC pending"

**Estimated time:** 2 hours

---

### 47-gateway-debug-interface.md
**Issue:** Claims hardware exploit without physical testing  
**Tasks:**
- [ ] Line 1: Add "⚠️ HARDWARE ACCESS UNTESTED"
- [ ] Add section: "Physical Testing Required"
- [ ] Mark pin diagrams with "Theory - needs multimeter validation"
- [ ] Add disclaimer: "Claims based on PCB analysis, not live testing"
- [ ] Create hardware test checklist
- [ ] Document safety warnings for physical testing

**Estimated time:** 1 hour

---

### 48-hardware-architecture.md
**Issue:** 17 uncertain phrases, needs concrete evidence  
**Tasks:**
- [ ] Replace all "likely" with specific evidence or "unconfirmed"
- [ ] Add board photos or mark sections as "visual inspection needed"
- [ ] Document chip part numbers from actual board (if available)
- [ ] Create "Verified vs Unverified" component table
- [ ] Add references to datasheets for claimed components

**Estimated time:** 1.5 hours

---

## 🟡 MEDIUM PRIORITY (Citation Additions)

### 38-gateway-firmware-analysis.md
**Issue:** Good analysis, missing source citations  
**Template to add:**
```markdown
**Binary Source:** `/path/to/firmware.bin`  
**Offset:** 0x12345  
**Extraction Command:** `strings -n 10 firmware.bin | grep "factory"`  
**Disassembly:** Ghidra project: `gateway_analysis.gzf`  
```

**Tasks:**
- [ ] Add binary source to every memory address claim
- [ ] Document extraction methodology in header
- [ ] Create "Files Analyzed" section listing all binaries
- [ ] Add Ghidra/IDA project references
- [ ] Link to binary dump locations

**Estimated time:** 2 hours

---

### 39-qtcarserver-security-audit.md
**Issue:** Security claims need source references  
**Tasks:**
- [ ] Add "Source Analysis" section
- [ ] Link each vulnerability to specific function/file
- [ ] Document which binary version was analyzed
- [ ] Add checksums for analyzed binaries
- [ ] Create vulnerability evidence table

**Estimated time:** 2 hours

---

### 40-ape-firmware-extraction.md
**Issue:** Extraction claims without file paths  
**Tasks:**
- [ ] Add "Extracted Files" table with full paths
- [ ] Document extraction commands used
- [ ] Add file checksums for verification
- [ ] Link to filesystem dump location
- [ ] Create directory tree diagram from actual dump

**Estimated time:** 1 hour

---

## 🟢 LOW PRIORITY (Quick Wins)

### Documents needing simple citations (15-30 min each):

**Group A: Add "Source: [file]" headers**
- [ ] 01-ui-decompilation-service-factory.md
- [ ] 05-gap-analysis-missing-pieces.md
- [ ] 12-gateway-bootloader-analysis.md
- [ ] 15-updater-component-inventory.md
- [ ] 20-service-mode-authentication.md

**Group B: Mark theoretical sections**
- [ ] 07-usb-map-installation.md - Add test requirements
- [ ] 08-key-programming-vcsec.md - Mark as reverse engineering needed
- [ ] 09-gateway-sdcard-log-analysis.md - Add sample log outputs
- [ ] 11-vcsec-keycard-routines.md - Add firmware extraction needed

**Group C: Add version numbers**
- [ ] 33-can-protocol-reverse-engineering.md - Document CAN capture source
- [ ] 34-chromium-webkit-attack-surface.md - Add Chromium version tested
- [ ] 36-gateway-sx-updater-reversing.md - Add binary version/checksum

---

## Standard Templates

### Evidence Quality Header Template
Add to top of every document:

```markdown
## Evidence Quality

**Status:** [✅ VERIFIED | ⚠️ INFERRED | ❌ UNTESTED | 🔍 NEEDS RE-ANALYSIS]  
**Confidence:** [High 90%+ | Medium 60-90% | Low <60%]  
**Last Validated:** YYYY-MM-DD  

**Evidence Sources:**
- Binary: `/path/to/file` (SHA256: ...)
- Firmware version: X.Y.Z
- Extraction tool: binwalk/strings/ghidra
- Test environment: [if applicable]

**Limitations:**
- [List what couldn't be verified]
- [List assumptions made]
- [List needed validation]
```

---

### Binary Reference Template
Use for every memory address or config claim:

```markdown
**Source:** `gateway_main.bin`  
**Offset:** 0x00123456  
**Function:** `factory_gate_handler`  
**Extraction:**
```bash
strings -t x gateway_main.bin | grep "factory_gate"
objdump -d gateway_main.bin | grep -A 20 "400053BC"
```
**Verification:** Confirmed in Ghidra decompilation (gateway_analysis.gzf)
```

---

### Theoretical Claim Template
Use for untested hypotheses:

```markdown
### [Claim Name] (❌ UNTESTED)

**Hypothesis:** [Clear statement of what might be possible]

**Reasoning:**
1. Evidence point A (cite source)
2. Evidence point B (cite source)
3. Logical inference

**Validation Required:**
- [ ] Test step 1
- [ ] Test step 2
- [ ] Expected outcome if true
- [ ] Expected outcome if false

**Risk Level:** [High/Medium/Low] - If wrong, impact is [describe]

**DO NOT USE IN PRODUCTION UNTIL VALIDATED**
```

---

## Bulk Replace Operations

### Uncertain Language → Specific Language

**Find and replace across all docs:**

| Find | Replace With |
|------|-------------|
| "likely" | "unconfirmed hypothesis:" |
| "probably" | "evidence suggests (untested):" |
| "assumed" | "assumption (needs verification):" |
| "appears to" | "behavioral observation:" |
| "seems to" | "preliminary analysis suggests:" |
| "might be" | "possible attack vector (untested):" |
| "could be" | "potential vulnerability (unconfirmed):" |
| "theoretical" | "untested theory:" |

**Regex patterns to find:**
```regex
\b(likely|probably|assumed|appears to|seems to|might be|could be)\b
```

---

## Quality Assurance Checklist

After making corrections, verify:

- [ ] Every memory address has a source file/offset
- [ ] Every exploit has a "UNTESTED" or "VERIFIED" marker
- [ ] Every config claim has a file path
- [ ] Uncertain language is replaced or justified
- [ ] Each document has evidence quality header
- [ ] README.md reflects actual confidence levels
- [ ] Theoretical sections clearly marked
- [ ] Test/validation checklists added where needed

---

## Automation Script

**Create:** `scripts/add_citations.py`

```python
#!/usr/bin/env python3
"""Automatically add citation templates to documents"""

import re
from pathlib import Path

EVIDENCE_HEADER = """
## Evidence Quality

**Status:** 🔍 NEEDS RE-ANALYSIS  
**Confidence:** Medium (60-90%)  
**Last Validated:** {date}  

**Evidence Sources:**
- [Add binary paths here]

**Limitations:**
- [Add limitations here]
"""

def add_header(filepath):
    content = filepath.read_text()
    if "## Evidence Quality" not in content:
        # Insert after title
        lines = content.split('\n')
        lines.insert(2, EVIDENCE_HEADER.format(date="YYYY-MM-DD"))
        filepath.write_text('\n'.join(lines))

# Run on all markdown files needing updates
```

---

## Progress Tracking

**Total tasks:** 47  
**Estimated total time:** 20-25 hours  

**Priority breakdown:**
- 🔴 Critical: 6 tasks (5 hours)
- 🟠 High: 6 tasks (9 hours)  
- 🟡 Medium: 3 tasks (5 hours)
- 🟢 Low: 32 tasks (8 hours)

**Recommended order:**
1. Week 1: Critical fixes (add disclaimers, mark untested)
2. Week 2: High priority (CVE validation, hardware claims)
3. Week 3: Medium priority (citation additions)
4. Week 4: Low priority (batch updates, polish)

---

**Next Action:** Start with 02-gateway-can-flood-exploit.md - highest risk claim with no evidence.
