# Re-Analysis Priority List

**Generated:** 2026-02-03  
**Purpose:** Guide firmware-backed validation of theoretical claims

Based on [59-EVIDENCE-AUDIT.md](59-EVIDENCE-AUDIT.md), this document prioritizes which analyses need firmware validation first.

---

## 🔴 CRITICAL - Validate Immediately (Safety/Security Impact)

### 1. Gateway CAN Flood Exploit (02-gateway-can-flood-exploit.md)
**Status:** ❌ UNTESTED  
**Current Evidence:** Theory only, no CAN captures  
**Needed:**
- [ ] Capture actual CAN traffic during gateway boot
- [ ] Verify 0x3C2 message ID exists
- [ ] Test flood timing (10k msg/sec for 10-30s)
- [ ] Confirm port 25956 opens post-flood
- [ ] Document failure modes and side effects

**Impact:** If real, this is a remote exploit. If fake, it's spreading FUD.

---

### 2. Gateway Mini-HDMI Debug Interface (47-gateway-debug-interface.md)
**Status:** ⚠️ INFERRED  
**Current Evidence:** Pin analysis, no physical testing  
**Needed:**
- [ ] Physical access to gateway board
- [ ] Test pin 4+6 short with multimeter
- [ ] Confirm UART output on console
- [ ] Verify JTAG accessibility
- [ ] Document actual recovery mode behavior

**Impact:** Claims 5-minute full compromise via hardware.

---

### 3. Certificate Recovery for Orphan Cars (03-certificate-recovery-orphan-cars.md)
**Status:** ❌ UNTESTED (22 uncertain phrases)  
**Current Evidence:** Theoretical procedures only  
**Needed:**
- [ ] Verify `/etc/tesla/car.crt` path exists
- [ ] Confirm certificate format (PEM/DER)
- [ ] Test OpenSSL certificate generation
- [ ] Validate CAN frame format for cert upload
- [ ] Document actual backend handshake

**Impact:** Claims to enable orphaned vehicle recovery.

---

## 🟠 HIGH - Validate for Exploit Chains

### 4. VCSEC Key Programming (08-key-programming-vcsec.md, 11-vcsec-keycard-routines.md)
**Status:** ❌ UNTESTED  
**Current Evidence:** No source citations  
**Needed:**
- [ ] Extract VCSEC firmware binary
- [ ] Reverse engineer key programming routines
- [ ] Document actual CAN protocol for pairing
- [ ] Verify keycard RFID protocol
- [ ] Test key cloning feasibility

**Impact:** Claims unauthorized key creation possible.

---

### 5. Gateway Heartbeat Failsafe Timing (21-gateway-heartbeat-failsafe.md)
**Status:** ⚠️ INFERRED  
**Current Evidence:** Behavioral observation  
**Needed:**
- [ ] Disassemble watchdog timer routine
- [ ] Confirm 5-second timeout with binary analysis
- [ ] Test actual reboot behavior on heartbeat loss
- [ ] Verify port closure timing

**Impact:** Used in exploit timing calculations.

---

### 6. Bootloader Exploit Research (26-bootloader-exploit-research.md)
**Status:** ⚠️ INFERRED (claims 7 CVEs)  
**Current Evidence:** Some disassembly, missing validation  
**Needed:**
- [ ] Reproduce claimed exploits in safe environment
- [ ] Validate each CVE with proof-of-concept
- [ ] Confirm bootloader version numbers
- [ ] Test signature verification bypass claims
- [ ] Document actual exploit success rates

**Impact:** Claims multiple bootloader vulnerabilities.

---

## 🟡 MEDIUM - Add Source Citations

These documents have good evidence but need explicit source citations:

### 7. Gateway Firmware Analysis (38-gateway-firmware-analysis.md)
**Status:** ⚠️ INFERRED  
**Action:** Add binary paths and offsets for every claim

### 8. QtCarServer Security Audit (39-qtcarserver-security-audit.md)
**Status:** ⚠️ INFERRED  
**Action:** Link each finding to specific binary/source file

### 9. APE Network Services (43-ape-network-services.md)
**Status:** 🔍 NEEDS RE-ANALYSIS (7 uncertain phrases)  
**Action:** 
- [ ] Re-analyze with actual APE firmware
- [ ] Verify port 8901 authentication claims
- [ ] Test factory mode access controls

### 10. Network Ports & Firewall (04-network-ports-firewall.md)
**Status:** ❌ UNTESTED  
**Action:**
- [ ] Live network scan of actual MCU
- [ ] Verify all 139 claimed ports
- [ ] Document actual firewall rules from iptables

---

## 🟢 LOW - Complete but Could Improve

### 11-20. Documents needing minor citation additions
See [59-EVIDENCE-AUDIT.md](59-EVIDENCE-AUDIT.md) "Documents Needing Source Citations" section.

**Standard template for adding citations:**
```markdown
**Source:** `/path/to/binary.so` offset 0x12345  
**Extraction:** `strings gateway.bin | grep "factory_gate"`  
**Disassembly:** Ghidra analysis of function at 0xABCD  
```

---

## Re-Analysis Workflow

### Phase 1: Locate Firmware (CURRENT)
- [ ] Find all available firmware dumps
- [ ] Organize by component (MCU, Gateway, APE, VCSEC)
- [ ] Index binary locations in master doc

### Phase 2: Critical Validation
- [ ] Work through CRITICAL list above
- [ ] Update documents with binary evidence
- [ ] Mark claims as ✅ VERIFIED or ❌ DEBUNKED

### Phase 3: Exploit Testing
- [ ] Set up safe test environment
- [ ] Reproduce claimed exploits
- [ ] Document success/failure rates
- [ ] Update CVSS scores based on actual impact

### Phase 4: Citation Pass
- [ ] Add sources to all INFERRED documents
- [ ] Convert uncertain language to specific claims
- [ ] Update quality scores in audit

### Phase 5: Final Report
- [ ] Regenerate evidence audit
- [ ] Update README with confidence levels
- [ ] Prepare responsible disclosure package

---

## Evidence Standards

### ✅ VERIFIED Requirements
- Binary path + offset OR config file path
- Disassembly or hexdump excerpt
- Reproducible extraction steps
- No uncertain language

### ⚠️ INFERRED Requirements
- Logical deduction from 2+ sources
- All sources explicitly cited
- Confidence level stated (e.g., "high confidence based on...")
- Clearly marked as inference

### ❌ UNTESTED Allowed Uses
- Hypotheses for future testing
- Brainstorming attack vectors
- **Must be clearly marked as theoretical**
- Should include validation checklist

---

## Quick Win Checklist

**Easy fixes (< 1 hour each):**
- [ ] Add "Source: ..." lines to 38-gateway-firmware-analysis.md
- [ ] Mark theoretical sections in 03-certificate-recovery.md
- [ ] Update 26-bootloader-exploit with "Untested - needs validation"
- [ ] Add firmware paths to 40-ape-extraction-summary.md
- [ ] Label exploit code in 35-practical-exploit-guide.md as untested

**Medium effort (2-4 hours each):**
- [ ] Re-analyze 04-network-ports with actual netstat output
- [ ] Validate 21-gateway-heartbeat timing with disassembly
- [ ] Cross-check 39-qtcarserver claims against source

**High effort (8+ hours each):**
- [ ] Reproduce CAN flood attack (02-gateway-can-flood)
- [ ] Physical test of mini-HDMI debug (47-gateway-debug)
- [ ] Full VCSEC firmware extraction (08, 11)

---

## Firmware Inventory Needed

To complete re-analysis, need these binaries:

### High Priority
- [ ] Gateway bootloader (u-boot)
- [ ] Gateway main firmware (`sx-updater`, SPC binaries)
- [ ] VCSEC firmware (key programming routines)
- [ ] MCU QtCarServer binary
- [ ] APE factory calibration service

### Medium Priority
- [ ] CAN gateway config files
- [ ] Certificate store (`/etc/tesla/`)
- [ ] Bootloader environment variables
- [ ] DoIP authentication binaries

### Low Priority
- [ ] Modem firmware (Iris/Tillit)
- [ ] Chromium build for MCU
- [ ] AppArmor profiles (already have some)

---

## Automation Opportunities

**Create scripts to:**
1. Scan all markdown files for uncertain language
2. Validate that claimed memory addresses exist in binaries
3. Cross-reference file paths with actual filesystem dumps
4. Generate citation templates from binary analysis
5. Auto-update quality scores after changes

---

**Next Action:** Start with Phase 1 - locate and index all available firmware dumps.
