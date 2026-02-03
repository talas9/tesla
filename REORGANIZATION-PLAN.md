# Tesla Documentation Reorganization Plan

**Created:** 2026-02-03 14:00 UTC  
**Current:** 147 markdown documents  
**Target:** ~15-25 comprehensive, non-redundant documents  
**Backup:** `/root/tesla-backup/` (created)

---

## Analysis Results

### Redundancy Found

**Exact duplicates (archive + current):**
- `44-mcu-networking-deep-dive.md` (2 copies, 3,852 lines combined)
- `10-usb-firmware-update-deep.md` (2 copies, 1,220 lines)
- `16-offline-update-format-notes.md` (2 copies, 1,708 lines)
- `06-usb-firmware-update.md` (2 copies, 99 lines)

**Summary + detailed versions:**
- `gateway-firmware` (DETAILED + SUMMARY = 1,841 lines)
- `gateway-udp-config-protocol` (protocol + SUMMARY = 1,782 lines)
- `qtcarserver-security-audit` (audit + SUMMARY = 1,925 lines)
- `vcsec-key-programming` (full + summary = 1,375 lines)

**Topic overlap (many docs covering same topics):**
- **Gateway:** 128 docs, 74,213 total lines (massive redundancy)
- **Attack:** 47 docs, many repeating CAN flood, voltage glitch
- **Auth:** 38 docs, many repeating service mode, Hermes, certificates
- **Update:** 32 docs, many repeating OTA/USB mechanisms

---

## Consolidation Strategy

### Phase 1: Remove Exact Duplicates (immediate)

**Delete these (keep newest version only):**
```
docs/archive/networking-research/44-mcu-networking-deep-dive.md (older)
docs/archive/usb-update-research/10-usb-firmware-update-deep.md (older)
docs/archive/usb-update-research/16-offline-update-format-notes.md (older)
docs/archive/usb-update-research/06-usb-firmware-update.md (older)
```

### Phase 2: Merge Summary + Detailed Pairs

**These should become ONE doc each:**
- `gateway-firmware-DETAILED.md` + `gateway-firmware-SUMMARY.md` → `GATEWAY-FIRMWARE.md`
- `gateway-udp-config-protocol.md` + `...-SUMMARY.md` → `GATEWAY-PROTOCOLS.md`
- `qtcarserver-security-audit.md` + `...-SUMMARY.md` → `MCU-QTCARSERVER.md`
- `vcsec-key-programming.md` + `...-summary.md` → `VCSEC-KEY-PROGRAMMING.md`

### Phase 3: Topic Consolidation

**Gateway (128 docs → 8-10 docs):**

Current state: 74,213 lines across 128 documents (massive redundancy)

**Consolidate into:**
1. `GATEWAY-OVERVIEW.md` — Hardware, architecture, system description (synthesis of: 38-firmware-DETAILED, 54-spc-architecture, 97-memory-map)
2. `GATEWAY-FIRMWARE.md` — Binary analysis, disassembly, memory map (synthesis of: 91-powerpc-disassembly, 85-memory-map, 86-security-analysis, 99-metadata)
3. `GATEWAY-CONFIGS.md` — 662 configs, CRC algorithm, config system (synthesis of: 80-ryzen-flash, 77-config-database, 79-jtag-dumps, 92-config-metadata-table)
4. `GATEWAY-SECURITY.md` — Two-tier model, access levels (synthesis of: 81-secure-configs, 82-odin-database, 86-security-analysis)
5. `GATEWAY-PROTOCOLS.md` — UDP (1050, 3500), packet formats (synthesis of: 50-udp-config-protocol, 58-udp-real-format, GATEWAY-UDP-PROTOCOL-VERIFIED)
6. `GATEWAY-BOOTLOADER.md` — Boot sequence, factory gate, exploits (synthesis of: 12-bootloader-analysis, 83-bootloader-disassembly, 26-bootloader-exploit)
7. `GATEWAY-TOOLS.md` — gw-diag, gwxfer, scripts (synthesis of: 84-gw-diag-command-reference, 90-gw-diag-detailed-usage, GW-DIAG-DISASSEMBLY)
8. `GATEWAY-CAN.md` — CAN mailbox configs, 6,647 messages (synthesis of: 95-CAN-MESSAGES, 57-can-protocol-verified, 33-can-protocol-re)
9. `GATEWAY-STRINGS.md` — 37,702 strings analysis (synthesis of: 88-gateway-strings-analysis, 93-ALL-STRINGS.csv reference)
10. `GATEWAY-DATA-TABLES.md` — All data structures (synthesis of: 96-DATA-TABLES, 94-ALL-FUNCTIONS, 98-SHA-256-USAGE)

**Odin (47 docs → 4 docs):**
1. `ODIN-OVERVIEW.md` — 2,988 scripts, architecture
2. `ODIN-CONFIG-DATABASE.md` — Unhashed database, accessId mapping
3. `ODIN-API.md` — Config read API, authentication
4. `ODIN-COMMANDS.md` — gw-diag command reference with examples

**Attacks (38 docs → 6 docs):**
1. `ATTACK-CAN-FLOOD.md` — CAN flood exploit (synthesis of: 02-can-flood, 21-heartbeat-failsafe, 28-refined-timing)
2. `ATTACK-VOLTAGE-GLITCH.md` — AMD Ryzen glitching (VOLTAGE-GLITCHING-RYZEN-MCU.md)
3. `ATTACK-SPC-REPLACEMENT.md` — Hardware chip swap (55-spc-chip-replacement)
4. `ATTACK-NETWORK.md` — Network attack surface (synthesis of: 25-network-attack-surface, 04-network-ports-firewall)
5. `ATTACK-APPARMOR-BYPASS.md` — AppArmor escalation (31-apparmor-sandbox-security)
6. `ATTACK-SUMMARY.md` — Attack tree, risk matrix, decision tree

**Auth (32 docs → 5 docs):**
1. `AUTH-SERVICE-MODE.md` — Service mode (20-service-mode-authentication)
2. `AUTH-HERMES.md` — Hermes mTLS (HERMES-CLIENT-ANALYSIS, 23-certificate-chain-analysis)
3. `AUTH-CERTIFICATES.md` — Certificate lifecycle (23-certificate-chain, APE-CERTIFICATES)
4. `AUTH-ORPHAN-CARS.md` — Orphan car recovery (03-certificate-recovery-orphan-cars)
5. `AUTH-FACTORY-MODE.md` — Factory mode triggers (01-ui-decompilation, 05-gap-analysis)

**Updates (28 docs → 5-6 docs):**
1. `UPDATE-OTA.md` — OTA architecture (13-ota-handshake, 36-gateway-sx-updater)
2. `UPDATE-USB.md` — USB offline updates (10-usb-firmware-deep, 16-offline-format-notes)
3. `UPDATE-SIGNATURES.md` — Signature verification (78-update-signature-extraction)
4. `UPDATE-COMPONENTS.md` — Component inventory (15-updater-component-inventory, 17-zen-cid-ice, 18-cid-iris-pipeline)
5. `UPDATE-EMERGENCY.md` — Port 25956 updater shell (21-heartbeat-failsafe, 36-sx-updater)
6. `UPDATE-COMPLETE.md` OR fold into above (USB-OFFLINE-UPDATE-COMPLETE)

**Network (18 docs → 3-4 docs):**
1. `NETWORK-TOPOLOGY.md` — 192.168.90.0/24, components (04-network-ports-firewall, 48-hardware-architecture)
2. `NETWORK-PORTS.md` — 139 ports, firewall (04-network-ports-firewall, 44-mcu-networking-deep)
3. `NETWORK-ATTACK-SURFACE.md` — Risk assessment (25-network-attack-surface)
4. `NETWORK-HARDWARE.md` — Physical layout (48-hardware-architecture) OR fold into TOPOLOGY

**APE (12 docs → 3-4 docs):**
1. `APE-OVERVIEW.md` — Hardware, architecture (40-ape-extraction-summary, APE-NETWORK-CONFIG)
2. `APE-FACTORY-CALIBRATION.md` — Port 8901, calibration API (41-ape-factory-calibration)
3. `APE-FIRMWARE.md` — Binary analysis (40-ape-firmware-extraction, APE-FIRMWARE-EXTRACTION)
4. `APE-SECURITY.md` — Bearer auth, risks (APE-SECURITY, APE-CERTIFICATES) OR fold into FACTORY-CALIBRATION

**MCU (14 docs → 3-4 docs):**
1. `MCU-ARCHITECTURE.md` — MCU2 hardware, services (28-zen-component-architecture)
2. `MCU-QTCARSERVER.md` — QtCarServer analysis (39-qtcarserver-security-audit)
3. `MCU-BROWSER-SECURITY.md` — Chromium/WebKit CVEs (34-chromium-webkit-attack-surface)
4. `MCU-APPARMOR.md` — Sandbox (31-apparmor-sandbox-security) OR fold into ATTACK-APPARMOR-BYPASS

**Specialized Topics (8 docs → 4-5 docs):**
1. `VCSEC-KEY-PROGRAMMING.md` — BLE/NFC, keys (24-vcsec-key-programming + summary)
2. `CAN-PROTOCOL.md` — Complete CAN protocol (33-can-protocol-reverse-engineering, 57-can-protocol-verified)
3. `MEMORY-MAPS.md` — All component memory maps (85-gateway-memory-map, 97-gateway-memory-map)
4. `DISASSEMBLY-GUIDE.md` — How to reproduce (92-binaryninja-vle-setup, KERNEL-GPIO-HARDWARE-DEBUG)
5. `DATA-EXTRACTION.md` — How data was extracted (optional, may fold into RESEARCH-METHODOLOGY)

**Evidence & Meta (6 docs → 3-4 docs):**
1. `BINARY-OFFSETS.md` — All offsets in one place (synthesize from all docs with offsets)
2. `EVIDENCE-QUALITY.md` — Quality assessment (59-EVIDENCE-AUDIT, VERIFICATION-STATUS, EVIDENCE-AUDIT-SUMMARY)
3. `RESEARCH-METHODOLOGY.md` — How research was conducted (RESEARCH-STATUS, meta/RESEARCH-QUESTIONS-STATUS)
4. `DEPLOYMENT-GUIDE.md` — MkDocs/GitHub Pages (DEPLOYMENT.md, DEPLOYMENT-READY)

**Root-level docs (keep/update):**
1. `README.md` — Entry point (rewrite)
2. `QUICK-START.md` — 5-min orientation (create)
3. `INDEX.md` — Navigation (update with new structure)

---

## Final Document Count

**Target: 20-25 comprehensive docs** (down from 147)

**Breakdown:**
- Root: 3 docs (README, QUICK-START, INDEX)
- Gateway: 8-10 docs
- Odin: 4 docs
- Attacks: 6 docs
- Auth: 5 docs
- Updates: 5-6 docs
- Network: 3-4 docs
- APE: 3-4 docs
- MCU: 3-4 docs
- Specialized: 4-5 docs
- Evidence/Meta: 3-4 docs

**Total: ~47-60 docs** (realistic target given content volume)

**Reduction: 147 → ~50 docs (66% reduction) with zero information loss**

---

## Execution Order

### Immediate (Phase 1): Delete duplicates
- Remove archive copies of docs that exist in current dirs
- Remove exact duplicate networking docs
- Clean up old index files

### Phase 2: Write new consolidated docs (by priority)
1. **Gateway cluster** (most content, highest value)
2. **Odin cluster** (critical for understanding service tool)
3. **Evidence/Meta** (framework for assessing other docs)
4. **Attacks cluster** (high interest, relatively focused)
5. **Auth cluster** (important for security model)
6. **Updates cluster** (complex but well-documented)
7. **Network cluster** (straightforward consolidation)
8. **APE cluster** (focused topic)
9. **MCU cluster** (focused topic)
10. **Specialized topics** (smaller, can be done last)

### Phase 3: Update navigation
- Rewrite `README.md`
- Create `QUICK-START.md`
- Update `INDEX.md`
- Update `mkdocs.yml` nav structure

### Phase 4: Verify & deploy
- Check all cross-references
- Test mkdocs build locally
- Commit and push

---

## Next Steps (NOW)

1. ✅ Backup created (`/root/tesla-backup/`)
2. ✅ Analysis complete (redundancy identified)
3. ⏳ Execute Phase 1: Delete exact duplicates
4. ⏳ Execute Phase 2: Write Gateway cluster (8-10 docs)
5. Continue through remaining clusters

**Estimated time:** 4-6 hours for complete reorganization

