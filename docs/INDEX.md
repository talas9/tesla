# Tesla MCU2 Security Research - Complete Index

**Last Updated:** 2026-02-03  
**Total Documents:** 111 markdown files  
**Status:** Research complete, organized structure

---

## 📖 Documentation Structure

```
tesla/
├── docs/               # All research documentation
│   ├── README.md       # Project overview
│   ├── INDEX.md        # This file - complete navigation
│   ├── core/           # Core research (20 docs)
│   ├── gateway/        # Gateway research (45 docs)
│   ├── mcu/            # MCU research (12 docs)
│   ├── ape/            # APE/Autopilot research (7 docs)
│   ├── network/        # Network analysis (2 docs)
│   ├── tools/          # Tools & scripts (3 docs)
│   ├── evidence/       # Evidence audit (17 docs)
│   └── firmware/       # Firmware analysis (2 docs)
├── data/               # Extracted data files
│   ├── configs/        # Config databases
│   ├── strings/        # String extractions
│   ├── disassembly/    # Disassembly outputs
│   └── binaries/       # Firmware binaries
└── scripts/            # Analysis scripts
    ├── gateway_crc_validator.py
    ├── gateway_database_query.py
    └── match_odin_to_configs.py
```

---

## 🎯 Quick Start

### Essential Reading (Start Here)
1. **[README.md](README.md)** - Project overview, key discoveries, evidence quality
2. **[00-master-cross-reference.md](core/00-master-cross-reference.md)** - Complete cross-reference matrix
3. **[VERIFICATION-STATUS.md](VERIFICATION-STATUS.md)** - Evidence quality ratings
4. **[59-EVIDENCE-AUDIT.md](evidence/59-EVIDENCE-AUDIT.md)** - Detailed evidence audit

### Gateway Security Model (Critical)
- **[81-gateway-secure-configs-CRITICAL.md](gateway/81-gateway-secure-configs-CRITICAL.md)** - Two-tier security explained
- **[80-ryzen-gateway-flash-COMPLETE.md](gateway/80-ryzen-gateway-flash-COMPLETE.md)** - 662 configs extracted
- **[82-odin-routines-database-UNHASHED.md](gateway/82-odin-routines-database-UNHASHED.md)** - Tesla service tool database

### Attack Research
- **[02-gateway-can-flood-exploit.md](core/02-gateway-can-flood-exploit.md)** - CAN flood attack
- **[55-gateway-spc-chip-replacement.md](gateway/55-gateway-spc-chip-replacement.md)** - Hardware bypass
- **[03-certificate-recovery-orphan-cars.md](core/03-certificate-recovery-orphan-cars.md)** - Certificate extraction

---

## 📚 Documentation by Category

### Core Research (docs/core/)

**System Architecture**
- [00-master-cross-reference.md](core/00-master-cross-reference.md) - Master index of all discoveries
- [04-network-ports-firewall.md](core/04-network-ports-firewall.md) - Complete network topology
- [05-gap-analysis-missing-pieces.md](core/05-gap-analysis-missing-pieces.md) - Research gaps

**Update Mechanisms**
- [06-usb-firmware-update.md](core/06-usb-firmware-update.md) - USB update format
- [07-usb-map-installation.md](core/07-usb-map-installation.md) - Map update process
- [10-usb-firmware-update-deep.md](core/10-usb-firmware-update-deep.md) - Deep dive
- [14-offline-update-practical-guide.md](core/14-offline-update-practical-guide.md) - Practical guide
- [13-ota-handshake-protocol.md](core/13-ota-handshake-protocol.md) - OTA handshake

**Update Components**
- [15-updater-component-inventory.md](core/15-updater-component-inventory.md) - Component inventory
- [16-offline-update-format-notes.md](core/16-offline-update-format-notes.md) - Format notes
- [17-zen-cid-ice-updaters-findings.md](core/17-zen-cid-ice-updaters-findings.md) - Updater analysis
- [18-cid-iris-update-pipeline.md](core/18-cid-iris-update-pipeline.md) - Update pipeline
- [19-ice-updater-components.md](core/19-ice-updater-components.md) - ICE components

**Security & Keys**
- [08-key-programming-vcsec.md](core/08-key-programming-vcsec.md) - VCSEC key programming
- [11-vcsec-keycard-routines.md](core/11-vcsec-keycard-routines.md) - Keycard routines
- [20-service-mode-authentication.md](core/20-service-mode-authentication.md) - Service mode auth

**Exploits**
- [02-gateway-can-flood-exploit.md](core/02-gateway-can-flood-exploit.md) - CAN flood attack
- [03-certificate-recovery-orphan-cars.md](core/03-certificate-recovery-orphan-cars.md) - Certificate extraction

**UI Analysis**
- [01-ui-decompilation-service-factory.md](core/01-ui-decompilation-service-factory.md) - UI decompilation

---

### Gateway Research (docs/gateway/)

**CRITICAL DISCOVERIES**
- [80-ryzen-gateway-flash-COMPLETE.md](gateway/80-ryzen-gateway-flash-COMPLETE.md) - **662 configs extracted, CRC-8 verified**
- [81-gateway-secure-configs-CRITICAL.md](gateway/81-gateway-secure-configs-CRITICAL.md) - **Two-tier security model**
- [82-odin-routines-database-UNHASHED.md](gateway/82-odin-routines-database-UNHASHED.md) - **Tesla Odin database**
- [92-config-metadata-table-FOUND.md](gateway/92-config-metadata-table-FOUND.md) - **21,000+ metadata entries**

**Firmware Analysis**
- [76-gateway-app-firmware-REAL.md](gateway/76-gateway-app-firmware-REAL.md) - Gateway firmware hex
- [77-gateway-config-database-REAL.md](gateway/77-gateway-config-database-REAL.md) - Config database
- [79-gateway-flash-dump-JTAG.md](gateway/79-gateway-flash-dump-JTAG.md) - JTAG flash dumps
- [91-gateway-powerpc-disassembly-summary.md](gateway/91-gateway-powerpc-disassembly-summary.md) - PowerPC disassembly

**Complete Firmware Extraction**
- [88-gateway-strings-analysis.md](gateway/88-gateway-strings-analysis.md) - 38,291 strings
- [89-gateway-config-metadata-extraction.md](gateway/89-gateway-config-metadata-extraction.md) - Metadata structures
- [93-gateway-ALL-STRINGS.csv](../data/93-gateway-ALL-STRINGS.csv) - Complete string database
- [94-gateway-ALL-FUNCTIONS.md](gateway/94-gateway-ALL-FUNCTIONS.md) - Function analysis
- [95-gateway-CAN-MESSAGES-COMPLETE.md](gateway/95-gateway-CAN-MESSAGES-COMPLETE.md) - 6,647 CAN entries
- [96-gateway-DATA-TABLES.md](gateway/96-gateway-DATA-TABLES.md) - All data tables
- [97-gateway-MEMORY-MAP.md](gateway/97-gateway-MEMORY-MAP.md) - Memory layout
- [98-SHA-256-USAGE-ANALYSIS.md](gateway/98-SHA-256-USAGE-ANALYSIS.md) - SHA-256 usage
- [99-gateway-FIRMWARE-METADATA.md](gateway/99-gateway-FIRMWARE-METADATA.md) - Firmware metadata

**Odin Service Tool**
- [83-odin-config-api-analysis.md](gateway/83-odin-config-api-analysis.md) - Config read API
- [84-gw-diag-command-reference.md](gateway/84-gw-diag-command-reference.md) - `gw-diag` commands
- [90-gw-diag-detailed-usage.md](gateway/90-gw-diag-detailed-usage.md) - Detailed usage patterns

**Bootloader & Protocol**
- [12-gateway-bootloader-analysis.md](gateway/../core/12-gateway-bootloader-analysis.md) - Bootloader analysis
- [21-gateway-protocol.md](gateway/21-gateway-protocol.md) - Gateway protocol
- [22-gateway-can-protocol.md](gateway/22-gateway-can-protocol.md) - CAN protocol
- [23-gateway-udp-protocol.md](gateway/23-gateway-udp-protocol.md) - UDP protocol

**Hardware & SPC**
- [36-gateway-spc-architecture.md](gateway/36-gateway-spc-architecture.md) - SPC chip architecture
- [37-gateway-spc-security-analysis.md](gateway/37-gateway-spc-security-analysis.md) - SPC security
- [38-gateway-spc-peripherals.md](gateway/38-gateway-spc-peripherals.md) - SPC peripherals
- [55-gateway-spc-chip-replacement.md](gateway/55-gateway-spc-chip-replacement.md) - **Hardware bypass attack**

**Configuration System**
- [47-gateway-config-security.md](gateway/47-gateway-config-security.md) - Config security
- [50-gateway-factory-gate.md](gateway/50-gateway-factory-gate.md) - Factory gate mechanism
- [51-gateway-config-database.md](gateway/51-gateway-config-database.md) - Config database
- [52-gateway-config-map-region.md](gateway/52-gateway-config-map-region.md) - Map region config
- [53-gateway-config-autopilot.md](gateway/53-gateway-config-autopilot.md) - Autopilot configs
- [54-gateway-config-charging.md](gateway/54-gateway-config-charging.md) - Charging configs

---

### MCU Research (docs/mcu/)

**Architecture**
- [24-mcu-architecture.md](mcu/24-mcu-architecture.md) - MCU architecture overview
- [25-mcu-boot-sequence.md](mcu/25-mcu-boot-sequence.md) - Boot sequence
- [26-mcu-partition-layout.md](mcu/26-mcu-partition-layout.md) - Partition layout

**Services**
- [27-mcu-services.md](mcu/27-mcu-services.md) - Service inventory
- [28-mcu-qtcarserver.md](mcu/28-mcu-qtcarserver.md) - QtCarServer analysis
- [29-mcu-connectivity.md](mcu/29-mcu-connectivity.md) - Connectivity services

**Security**
- [30-mcu-security-model.md](mcu/30-mcu-security-model.md) - Security model
- [31-mcu-chromium-security.md](mcu/31-mcu-chromium-security.md) - Chromium security
- [32-mcu-webkit-vulnerabilities.md](mcu/32-mcu-webkit-vulnerabilities.md) - WebKit vulns

**Software**
- [33-mcu-software-stack.md](mcu/33-mcu-software-stack.md) - Software stack
- [34-mcu-update-mechanism.md](mcu/34-mcu-update-mechanism.md) - Update mechanism
- [35-mcu-factory-reset.md](mcu/35-mcu-factory-reset.md) - Factory reset

---

### APE/Autopilot Research (docs/ape/)

**Firmware Extraction**
- [40-INDEX.md](ape/40-INDEX.md) - APE index
- [40-ape-extraction-summary.md](ape/40-ape-extraction-summary.md) - Extraction summary
- [40-ape-firmware-extraction.md](ape/40-ape-firmware-extraction.md) - Firmware extraction

**Configuration & Calibration**
- [41-ape-factory-calibration.md](ape/41-ape-factory-calibration.md) - Factory calibration

**Networking**
- [43-ape-network-services.md](ape/43-ape-network-services.md) - Network services
- [44-mcu-networking-deep-dive.md](ape/44-mcu-networking-deep-dive.md) - MCU networking deep dive
- [44-mcu-networking-enhanced.md](ape/44-mcu-networking-enhanced.md) - Enhanced networking
- [45-ape-networking-deep-dive.md](ape/45-ape-networking-deep-dive.md) - APE networking deep dive

---

### Network Research (docs/network/)

- [48-network-attack-surface.md](network/48-network-attack-surface.md) - Attack surface analysis
- [49-network-mitigation.md](network/49-network-mitigation.md) - Mitigation strategies

---

### Tools & Scripts (docs/tools/)

- [56-tools-gateway-database-query.md](tools/56-tools-gateway-database-query.md) - Database query tool
- [57-tools-can-flood-exploit.md](tools/57-tools-can-flood-exploit.md) - CAN flood tool
- [58-tools-config-validator.md](tools/58-tools-config-validator.md) - Config validator

**Scripts** (../scripts/)
- `gateway_crc_validator.py` - CRC-8 calculator & validator
- `gateway_database_query.py` - Config database query tool
- `match_odin_to_configs.py` - Match Odin accessId to config IDs

---

### Evidence & Audit (docs/evidence/)

**Quality Assurance**
- [59-EVIDENCE-AUDIT.md](evidence/59-EVIDENCE-AUDIT.md) - Complete evidence audit (75 docs, 1,700 lines)
- [60-RE-ANALYSIS-PRIORITIES.md](evidence/60-RE-ANALYSIS-PRIORITIES.md) - Re-analysis priorities
- [61-CORRECTION-TASKS.md](evidence/61-CORRECTION-TASKS.md) - Correction tasks
- [62-TOP-10-CORRECTIONS.md](evidence/62-TOP-10-CORRECTIONS.md) - Top 10 corrections

---

### Firmware Analysis (docs/firmware/)

- [85-gateway-memory-map-COMPLETE.md](firmware/85-gateway-memory-map-COMPLETE.md) - Complete memory map
- [86-gateway-security-analysis-DETAILED.md](firmware/86-gateway-security-analysis-DETAILED.md) - Detailed security

---

## 🔍 Research by Topic

### Security Model
- [81-gateway-secure-configs-CRITICAL.md](gateway/81-gateway-secure-configs-CRITICAL.md) - Two-tier config security
- [30-mcu-security-model.md](mcu/30-mcu-security-model.md) - MCU security model
- [37-gateway-spc-security-analysis.md](gateway/37-gateway-spc-security-analysis.md) - SPC security

### Attack Vectors
- [02-gateway-can-flood-exploit.md](core/02-gateway-can-flood-exploit.md) - CAN flood
- [55-gateway-spc-chip-replacement.md](gateway/55-gateway-spc-chip-replacement.md) - Hardware bypass
- [48-network-attack-surface.md](network/48-network-attack-surface.md) - Network attacks
- [31-mcu-chromium-security.md](mcu/31-mcu-chromium-security.md) - Browser exploits

### Configuration System
- [80-ryzen-gateway-flash-COMPLETE.md](gateway/80-ryzen-gateway-flash-COMPLETE.md) - Complete config dump
- [51-gateway-config-database.md](gateway/51-gateway-config-database.md) - Config database
- [47-gateway-config-security.md](gateway/47-gateway-config-security.md) - Config security

### Firmware Updates
- [06-usb-firmware-update.md](core/06-usb-firmware-update.md) - USB updates
- [13-ota-handshake-protocol.md](core/13-ota-handshake-protocol.md) - OTA updates
- [34-mcu-update-mechanism.md](mcu/34-mcu-update-mechanism.md) - MCU updates

### Reverse Engineering
- [91-gateway-powerpc-disassembly-summary.md](gateway/91-gateway-powerpc-disassembly-summary.md) - PowerPC disassembly
- [94-gateway-ALL-FUNCTIONS.md](gateway/94-gateway-ALL-FUNCTIONS.md) - Function analysis
- [01-ui-decompilation-service-factory.md](core/01-ui-decompilation-service-factory.md) - UI decompilation

---

## 📊 Data Files (data/)

### Configuration Data
- `gateway_configs_parsed.txt` - 662 parsed Gateway configs
- `can-message-database-VERIFIED.csv` - Verified CAN messages
- `odin-config-decoded.json` - Odin database (decoded)
- `odin_config_mapping.txt` - Odin accessId → config_id mapping

### String Extractions
- `93-gateway-ALL-STRINGS.csv` - 37,702 strings from Gateway firmware
- `gateway-strings.txt` - Gateway strings (legacy)
- `dbus-interfaces-raw.txt` - D-Bus interfaces

### Disassembly
- `gateway_full_disassembly.txt` - Complete PowerPC disassembly (1.5M lines)
- `gateway-app-disasm-sample.txt` - Sample disassembly

### Metadata
- `gateway_config_id_index.txt` - Config ID index (200 IDs)
- `gateway_config_names_hex.txt` - Config names (hex offsets)
- `gateway_config_metadata_table.txt` - Metadata table (21,000+ entries)

---

## 🛠️ Scripts (scripts/)

### Gateway Tools
- **gateway_crc_validator.py** - CRC-8 calculator & validator (working)
- **gateway_database_query.py** - Query Gateway config database
- **match_odin_to_configs.py** - Map Odin accessId to config IDs

### Usage Examples

```bash
# Validate config CRC
python3 scripts/gateway_crc_validator.py --config-id 0x0020 --data "01"

# Query config database
python3 scripts/gateway_database_query.py --search "mapRegion"

# Match Odin to Gateway configs
python3 scripts/match_odin_to_configs.py
```

---

## 🎯 Key Discoveries Summary

### Gateway Security Model
- **662 configs extracted** from Ryzen Gateway flash dump
- **CRC-8 algorithm verified** (polynomial 0x2F, 100% validation)
- **Two-tier security:**
  - Insecure: UDP-accessible (map region, trial timers)
  - Secure: Hermes auth required (VIN, country, features)
  - Hardware-locked: MPC5748G fuses (debug level)

### Odin Service Tool
- **2,988 Python scripts extracted** from Model 3/Y firmware
- **Config read API discovered:** `get_vehicle_configuration(access_id=INTEGER)` - NO AUTH
- **27 `gw-diag` commands cataloged** (GET_CONFIG, SET_CONFIG, REBOOT, etc.)
- **Unhashed database obtained** with security flags (`accessLevel: "UDP"` vs `"GTW"`)

### Firmware Analysis
- **6,029,152 byte PowerPC binary** fully extracted
- **37,702 strings extracted** (ASCII + UTF-16)
- **6,647 CAN/config entries** documented
- **21,000+ metadata entries** at 0x403000-0x410000
- **SHA-256 constants found** at 0x36730 (firmware verification)

### CVEs Identified
- **CVE-2025-4664** - Chromium 0-day (before public disclosure)
- 6 additional CVEs in Chromium, Qt, and kernel

---

## 🚀 For Deployment

### Static Site Generators (Recommended)

**MkDocs** (Best for technical docs)
```bash
pip install mkdocs mkdocs-material
mkdocs new tesla-research
# Copy docs/ to docs/
mkdocs serve  # Preview
mkdocs build  # Deploy to GitHub Pages
```

**Docsify** (No build step)
```bash
npm i docsify-cli -g
docsify init ./tesla-research
# Edit index.html
docsify serve
```

**VitePress** (Modern, Vue-based)
```bash
npm install -D vitepress
npx vitepress init
# Deploy to Netlify/Vercel
```

### Free Hosting
- **GitHub Pages** - Free, unlimited public repos
- **ReadTheDocs** - Free for open source
- **Netlify** - Free tier (100GB bandwidth)
- **Vercel** - Free for personal projects

---

## 📝 Git Structure

Current repo: `/root/tesla/`

**Recommended .gitignore:**
```
# Binaries
*.bin
data/binaries/

# Large files
data/disassembly/*.txt
data/strings/*.txt

# Temp files
*.pyc
__pycache__/
```

**Recommended structure:**
```
tesla/
├── .git/
├── .gitignore
├── README.md           # High-level overview
├── docs/
│   ├── INDEX.md        # This file
│   ├── core/
│   ├── gateway/
│   └── ...
├── data/               # Git LFS or exclude large files
└── scripts/
```

---

## 📞 Contributing

This research is complete but can be extended. Areas for future work:

1. **Hash algorithm for config-options.json** (salt: `gj55iz2tgghun9nyw2sa8s5oxsykmfwo`)
2. **Complete function call graph** (requires Ghidra analysis)
3. **Config metadata prefix decoding** (map 0x03/0x13/0x15 to security levels)
4. **SHA-256 implementation extraction** (function at 0x122622)

---

*Last updated: 2026-02-03 07:40 UTC*
