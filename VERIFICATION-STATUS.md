# Research Verification Status

## Evidence Quality Levels

### ✅ VERIFIED (Direct Evidence)
- Binary strings extracted
- Disassembly with addresses cited
- Configuration files parsed
- Network traffic captured
- Hardware measurements

### ⚠️ INFERRED (Logical Deduction)
- Protocol format reconstructed from strings
- Timing estimated from multiple sources
- Security behavior predicted from code patterns

### ❌ HYPOTHETICAL (Educated Guess)
- Packet formats not traffic-captured
- Algorithms without implementation seen
- Attack chains not tested on hardware

## Document Quality Assessment

### HIGH CONFIDENCE (>90% Verified)
- 47-gateway-debug-interface.md - Pin measurements, strings, bootloader code
- 36-gateway-sx-updater-reversing.md - Complete disassembly with addresses
- 52-gateway-firmware-decompile.md - Extracted from actual firmware
- 44-mcu-networking-deep-dive.md - Config files + iptables parsing
- 43-ape-network-services.md - Service configs + firewall rules

### MEDIUM CONFIDENCE (60-90% Verified)
- 50-gateway-udp-config-protocol.md - Protocol *reconstructed* from strings
  - ✅ Port 1050 verified in gwxfer
  - ✅ Config IDs extracted from firmware
  - ⚠️ Packet format hypothesized (not captured)
  - ❌ Factory gate sequence not extracted
  
- 21-gateway-heartbeat-failsafe.md
  - ✅ Kernel watchdog: 4sec from /etc/sysctl.conf
  - ⚠️ gwmon timeout: estimated 15-30s (not exact)
  
### NEEDS VALIDATION
- CAN protocol timing (28-can-flood-refined-timing.md)
  - Claims 98% success but not hardware-tested
  
- Factory gate derivation (50-gateway-udp-config-protocol.md)
  - Algorithm is speculative

## Corrections Needed

### 50-gateway-udp-config-protocol.md
**Line 245:** "Hypothesized packet format"
- Mark as UNVERIFIED, needs traffic capture
- Remove code claiming to work without testing

**Line 387:** Factory gate derivation function
- Mark as THEORETICAL
- Cannot work without actual gate sequence

### 28-can-flood-refined-timing.md
**Claim:** "98% success rate"
- Mark as UNTESTED
- Based on analysis, not hardware validation

## Recommendations

1. **Add headers to each section:**
   - ✅ VERIFIED FROM: [source]
   - ⚠️ INFERRED FROM: [logic]
   - ❌ THEORETICAL (UNTESTED)

2. **Mark all code as:**
   - FUNCTIONAL (tested)
   - FRAMEWORK (structure only)
   - THEORETICAL (untested logic)

3. **Separate findings from speculation:**
   - Keep evidence-based in main document
   - Move untested theories to appendix

## High-Confidence Findings Only

The following are 100% verified from actual sources:

### Gateway
- ✅ Port 1050 UDP (from gwxfer binary)
- ✅ Mini-HDMI pins 4+6 trigger recovery (from bootloader strings)
- ✅ Config ID database (from firmware extraction)
- ✅ SPC chip with fuses (from hardware description + firmware)

### APE  
- ✅ Port 8901 no auth (from service_api analysis + firewall)
- ✅ Factory mode HTTP endpoints (from binary strings)
- ✅ 962MB filesystem (from extraction)

### MCU
- ✅ 139 ports (from iptables + service configs)
- ✅ Service-shell on 4035 (from firewall rules)
- ✅ Chromium version 136.0.7103.92 (from binary)

### Exploits
- ❌ CAN flood NOT hardware-tested
- ❌ UDP protocol packets NOT traffic-captured  
- ❌ Factory gate sequence NOT extracted
- ✅ Recovery mode pin-short verified in bootloader code
