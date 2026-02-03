# Tesla Gateway Security Research

**Complete reverse engineering of Tesla Gateway ECU configuration system**

---

## What Is This?

This repository documents comprehensive security research on the **Tesla Gateway ECU** — the PowerPC-based controller that manages vehicle configuration, CAN bus routing, and feature enablement across Model S/X/3/Y vehicles.

**Key discoveries:**
- **662 Gateway configurations** extracted and validated (CRC-8, polynomial 0x2F)
- **Two-tier security model** discovered: UDP-accessible configs vs. Hermes-authenticated
- **Tesla Odin service tool** database obtained (unhashed, 2,988 Python scripts)
- **Complete firmware analysis**: 6MB PowerPC binary, 37,702 strings, 6,647 CAN messages
- **Multiple attack vectors** documented with working proof-of-concepts

**Research scope:** Gateway ECU (primary), Autopilot ECU, MCU2, authentication systems, update mechanisms

---

## 🎯 Quick Start

**New to this research?** Start here:

1. **[QUICK-START.md](QUICK-START.md)** — 5-minute orientation
2. **[GATEWAY-OVERVIEW.md](GATEWAY-OVERVIEW.md)** — Understand the Gateway system (15 min read)
3. **[EVIDENCE-QUALITY.md](EVIDENCE-QUALITY.md)** — What's verified vs. inferred vs. theoretical

**Looking for something specific?**
- **Configs:** See [GATEWAY-CONFIGS.md](GATEWAY-CONFIGS.md) — All 662 configs documented
- **Security model:** See [GATEWAY-SECURITY.md](GATEWAY-SECURITY.md) — Two-tier system explained
- **Exploits:** See [ATTACK-SUMMARY.md](ATTACK-SUMMARY.md) — Attack vectors and risk assessment
- **Odin tool:** See [ODIN-OVERVIEW.md](ODIN-OVERVIEW.md) — Tesla's service tool analyzed
- **Orphan cars:** See [AUTH-ORPHAN-CARS.md](AUTH-ORPHAN-CARS.md) — Certificate recovery guide

---

## 🔴 Critical Findings

### 1. Gateway Two-Tier Security Model ✅ Verified

**Finding:** Gateway configs split into three access tiers:

1. **Insecure (UDP port 3500, no auth):**
   - Map region, autopilot trial timer, ECU map version
   - Marked `accessLevel: "UDP"` in Odin database
   - Anyone on vehicle network can modify

2. **Secure (Hermes-authenticated):**
   - VIN, country code, supercharger access
   - Requires Tesla backend authentication via WSS:443
   - accessId 7-43 in Odin database

3. **Hardware-locked (Gateway-only, fused):**
   - Debug security level (LC_FACTORY vs LC_GATED)
   - Tied to MPC5748G hardware fuses
   - Cannot change after chip fusing

**Evidence:** Odin database (`accessLevel` flags), 662 configs extracted, CRC algorithm validated  
**Impact:** Insecure configs modifiable by anyone with network access  
**Details:** [GATEWAY-SECURITY.md](GATEWAY-SECURITY.md)

---

### 2. Odin Service Tool Config Database (Unhashed) ✅ Verified

**Finding:** Tesla's Odin service tool configuration database obtained before encryption was added, revealing complete config system architecture.

**Contents:**
- 2,988 Python scripts extracted from Model 3/Y firmware
- Unhashed JSON database mapping accessId → config names → enum values
- Config read API: `get_vehicle_configuration(access_id=INTEGER)` — **NO authentication** for normal access levels
- Complete list of which configs require elevated permissions

**Evidence:** JSON file obtained, scripts extracted from firmware  
**Impact:** Complete map of vehicle configuration system  
**Details:** [ODIN-CONFIG-DATABASE.md](ODIN-CONFIG-DATABASE.md)

---

### 3. CAN Flood Opens Emergency Updater ⚠️ Inferred

**Finding:** Flooding CAN bus with specific message IDs opens TCP port 25956 on Gateway within 10-30 seconds, providing unauthenticated firmware update interface.

**Method:**
- CAN ID 0x3C2 @ 10,000 msg/sec (data: `49 65 00 00 00 00 00 00`)
- CAN ID 0x622 @ 33 msg/sec (UDS tester-present)
- Opens port 25956 with 4 commands: help, set_handshake, install, status

**Evidence:** Working Python script, timing analysis, reported 98% success rate  
**Hardware:** PCAN USB adapter (~$50), OBD-II access  
**Details:** [ATTACK-CAN-FLOOD.md](ATTACK-CAN-FLOOD.md)

---

### 4. Service Mode Requires Backend Validation ⚠️ Inferred

**Finding:** Service mode authentication is NOT a simple local PIN check — it uses DoIP (Diagnostic over IP) + Protobuf signed commands + backend validation.

**Evidence:**
- D-Bus method analysis: `setServicePIN()` at QtCar:0x655ec0
- No local PIN comparison found in binaries
- Signed command infrastructure: `optional_signed_cmd_service_mode`
- doip-gateway user has special D-Bus permissions

**Impact:** Cannot bypass service mode offline without signed commands  
**Offline behavior:** Unknown (requires live testing)  
**Details:** [AUTH-SERVICE-MODE.md](AUTH-SERVICE-MODE.md)

---

### 5. Complete Firmware Disassembly ✅ Verified

**Finding:** Complete Gateway firmware reverse-engineered:
- 6,029,152 byte PowerPC MPC5748G binary
- 1.5M line disassembly generated
- 37,702 strings extracted (ASCII + UTF-16)
- 6,647 CAN message entries documented
- 21,000+ config metadata entries located at 0x403000

**Evidence:** Binary dumps, disassembly, string databases, CRC validation  
**Details:** [GATEWAY-FIRMWARE.md](GATEWAY-FIRMWARE.md)

---

## 📚 Documentation Structure

### Core Documentation
- **[README.md](README.md)** (this file) — Overview and critical findings
- **[QUICK-START.md](QUICK-START.md)** — 5-minute orientation guide
- **[INDEX.md](INDEX.md)** — Complete navigation index
- **[EVIDENCE-QUALITY.md](EVIDENCE-QUALITY.md)** — What's verified vs. theoretical

### Gateway ECU (Primary Focus)
- **[GATEWAY-OVERVIEW.md](GATEWAY-OVERVIEW.md)** — Hardware, architecture, system description
- **[GATEWAY-FIRMWARE.md](GATEWAY-FIRMWARE.md)** — Binary analysis, disassembly, memory map
- **[GATEWAY-CONFIGS.md](GATEWAY-CONFIGS.md)** — 662 configs, CRC algorithm, extraction
- **[GATEWAY-SECURITY.md](GATEWAY-SECURITY.md)** — Two-tier model, access control
- **[GATEWAY-PROTOCOLS.md](GATEWAY-PROTOCOLS.md)** — UDP ports 1050/3500, packet formats
- **[GATEWAY-BOOTLOADER.md](GATEWAY-BOOTLOADER.md)** — Boot sequence, factory gate, vulnerabilities
- **[GATEWAY-TOOLS.md](GATEWAY-TOOLS.md)** — gw-diag, gwxfer, usage examples
- **[GATEWAY-CAN.md](GATEWAY-CAN.md)** — CAN mailbox configs, 6,647 message database
- **[GATEWAY-DATA-TABLES.md](GATEWAY-DATA-TABLES.md)** — Memory structures, metadata table

### Tesla Odin Service Tool
- **[ODIN-OVERVIEW.md](ODIN-OVERVIEW.md)** — Architecture, 2,988 scripts
- **[ODIN-CONFIG-DATABASE.md](ODIN-CONFIG-DATABASE.md)** — Unhashed database analysis
- **[ODIN-API.md](ODIN-API.md)** — Config read API, authentication
- **[ODIN-COMMANDS.md](ODIN-COMMANDS.md)** — gw-diag command reference (27 commands)

### Attack Vectors
- **[ATTACK-SUMMARY.md](ATTACK-SUMMARY.md)** — Attack tree, risk matrix, decision tree
- **[ATTACK-CAN-FLOOD.md](ATTACK-CAN-FLOOD.md)** — CAN flood exploit (port 25956)
- **[ATTACK-VOLTAGE-GLITCH.md](ATTACK-VOLTAGE-GLITCH.md)** — AMD Ryzen MCU glitching
- **[ATTACK-SPC-REPLACEMENT.md](ATTACK-SPC-REPLACEMENT.md)** — Hardware chip swap attack
- **[ATTACK-NETWORK.md](ATTACK-NETWORK.md)** — Network attack surface analysis
- **[ATTACK-APPARMOR-BYPASS.md](ATTACK-APPARMOR-BYPASS.md)** — AppArmor escalation (60+ unconfined scripts)

### Authentication & Certificates
- **[AUTH-SERVICE-MODE.md](AUTH-SERVICE-MODE.md)** — Service mode deep dive
- **[AUTH-HERMES.md](AUTH-HERMES.md)** — Hermes mTLS, backend communication
- **[AUTH-CERTIFICATES.md](AUTH-CERTIFICATES.md)** — Certificate lifecycle, renewal
- **[AUTH-ORPHAN-CARS.md](AUTH-ORPHAN-CARS.md)** — Orphan car recovery procedures
- **[AUTH-FACTORY-MODE.md](AUTH-FACTORY-MODE.md)** — Factory mode triggers and gating

### Update Mechanisms
- **[UPDATE-OTA.md](UPDATE-OTA.md)** — OTA architecture, handshake protocol
- **[UPDATE-USB.md](UPDATE-USB.md)** — USB offline updates, package format
- **[UPDATE-SIGNATURES.md](UPDATE-SIGNATURES.md)** — NaCl/Ed25519, dm-verity
- **[UPDATE-COMPONENTS.md](UPDATE-COMPONENTS.md)** — Component inventory (sx-updater, etc.)
- **[UPDATE-EMERGENCY.md](UPDATE-EMERGENCY.md)** — Port 25956 emergency updater

### Network Architecture
- **[NETWORK-TOPOLOGY.md](NETWORK-TOPOLOGY.md)** — 192.168.90.0/24, component IPs
- **[NETWORK-PORTS.md](NETWORK-PORTS.md)** — 139 ports documented, firewall rules
- **[NETWORK-ATTACK-SURFACE.md](NETWORK-ATTACK-SURFACE.md)** — Risk assessment

### Other ECUs
- **[APE-OVERVIEW.md](APE-OVERVIEW.md)** — Autopilot ECU hardware/architecture
- **[APE-FACTORY-CALIBRATION.md](APE-FACTORY-CALIBRATION.md)** — Port 8901 calibration API
- **[MCU-ARCHITECTURE.md](MCU-ARCHITECTURE.md)** — MCU2 hardware, services
- **[MCU-QTCARSERVER.md](MCU-QTCARSERVER.md)** — QtCarServer security analysis

### Specialized Topics
- **[VCSEC-KEY-PROGRAMMING.md](VCSEC-KEY-PROGRAMMING.md)** — BLE/NFC key pairing
- **[CAN-PROTOCOL.md](CAN-PROTOCOL.md)** — Complete CAN protocol analysis
- **[MEMORY-MAPS.md](MEMORY-MAPS.md)** — All component memory maps

### Evidence & Methodology
- **[BINARY-OFFSETS.md](BINARY-OFFSETS.md)** — All firmware offsets reference
- **[RESEARCH-METHODOLOGY.md](RESEARCH-METHODOLOGY.md)** — How research was conducted

---

## 🛠️ Tools & Scripts

### Included in Repository

**Analysis Tools:**
- `scripts/gateway_crc_validator.py` — CRC-8 calculator (polynomial 0x2F)
- `scripts/gateway_database_query.py` — Query config database by ID/name
- `scripts/match_odin_to_configs.py` — Map Odin accessId to Gateway config IDs

**Exploit Tools:**
- `scripts/openportlanpluscan.py` — CAN flood proof-of-concept

### Usage Examples

```bash
# Validate a config CRC
python3 scripts/gateway_crc_validator.py --config-id 0x0020 --data "01"

# Query config database
python3 scripts/gateway_database_query.py --search "autopilot"

# Parse Gateway flash dump
python3 scripts/gateway_crc_validator.py parse ryzenfromtable.bin
```

---

## 📊 Research Statistics

- **Documents:** ~50 comprehensive guides (down from 147 research notes)
- **Gateway Configs:** 662 extracted and CRC-validated
- **CRC Validation:** 100% success on all configs (polynomial 0x2F)
- **Firmware Size:** 6,029,152 bytes (PowerPC MPC5748G)
- **Strings Extracted:** 37,702 (ASCII + UTF-16)
- **CAN Messages:** 6,647 documented
- **Config Metadata:** 21,000+ entries at 0x403000
- **Odin Scripts:** 2,988 Python scripts analyzed
- **Network Ports:** 139 documented
- **Research Time:** ~200 hours
- **Code Lines:** ~50,000 original research notes

---

## ⚠️ Evidence Quality Disclaimer

**This research combines verified findings with inferred analysis:**

| Quality | % | Description |
|---------|---|-------------|
| ✅ Verified | 25% | Binary evidence, extracted configs, working tools |
| ⚠️ Inferred | 37% | Logical deduction, protocol reverse engineering |
| 🔍 Needs Validation | 17% | Requires deeper firmware analysis or live testing |
| ❌ Theoretical | 20% | Untested exploits, hypotheses, published research |

**See [EVIDENCE-QUALITY.md](EVIDENCE-QUALITY.md) for detailed per-finding assessment.**

---

## ⚖️ Legal & Ethical Notice

- **Research conducted on:** Legally purchased Tesla hardware and extracted firmware
- **No unauthorized access:** No attempts to access Tesla servers or production systems
- **Educational purpose:** For security research and vulnerability disclosure
- **Responsible use only:** Do not exploit on vehicles you don't own
- **Safety-critical:** Some findings affect vehicle safety systems

**This research is for educational purposes. Use responsibly. Respect laws. Protect safety.**

---

## 🙏 Acknowledgments

- TU Berlin automotive security team (voltage glitching research)
- Anonymous internal sources (firmware dumps, Odin database)
- Open-source community (Binary Ninja, Ghidra, reverse engineering tools)

**Special thanks to those who provided critical data while maintaining responsible disclosure practices.**

---

## 📞 Contact & Disclosure

**Disclosure Status:** Not yet disclosed to Tesla  
**Contact:** security@tesla.com (for coordinated disclosure)  
**Recommended:** 90-day disclosure period before public release

---

## 📄 License

- **Documentation:** Creative Commons Attribution 4.0 (CC BY 4.0)
- **Code/Scripts:** MIT License
- **Attribution required** for academic or commercial use

---

**Last Updated:** 2026-02-03  
**Version:** 2.0 (Complete reorganization)  
**Repository:** https://github.com/[your-org]/tesla-gateway-research

