# EVIDENCE AUDIT REPORT

Generated: 2026-02-03T05:31:46.552237

Total documents analyzed: 75

---

## SUMMARY STATISTICS

- ⚠️ INFERRED: 28 documents (37%)
- ✅ VERIFIED: 19 documents (25%)
- ❌ UNTESTED: 15 documents (20%)
- 🔍 NEEDS RE-ANALYSIS: 13 documents (17%)

- Total uncertain phrases found: 378
- Total evidence markers found: 1809
- Average evidence per document: 24

---

## DETAILED FINDINGS


### 03-certificate-recovery-orphan-cars.md

**Quality:** ❌ UNTESTED (Score: 20/100)

**Statistics:**
- Lines: 827
- Uncertain phrases: 22
- Evidence markers: 2
- Memory addresses: 0
- Citations: 0
- Code blocks: 20

**Top Uncertain Phrases:**
- Line 17: 6. [Theoretical Recovery Procedures](#6-theoretical-recovery-procedures)
- Line 90: | **Used vehicle purchase** | 🟡 Medium | Unknown cert age, may be near expiry |
- Line 114: ├── car.key              # Private key (CRITICAL, may be TPM-protected)
- Line 271: ## 6. Theoretical Recovery Procedures
- Line 316: # This is THEORETICAL - actual frames would need reverse engineering

**Sample Evidence:**
- Line 419: -subj "/CN=$(cat /etc/tesla/vehicle.json | jq -r '.vin')/O=Tesla Motors"
- Line 479: VIN=$(cat /etc/tesla/vehicle.json | jq -r '.vin')


### 04-network-ports-firewall.md

**Quality:** ❌ UNTESTED (Score: 20/100)

**Statistics:**
- Lines: 943
- Uncertain phrases: 2
- Evidence markers: 0
- Memory addresses: 0
- Citations: 0
- Code blocks: 42

**Top Uncertain Phrases:**
- Line 525: - MQTT services (50666, 50877) could be exploited for command injection
- Line 689: ├─ NAT/Routing (assumed)


### 07-usb-map-installation.md

**Quality:** ❌ UNTESTED (Score: 20/100)

**Statistics:**
- Lines: 217
- Uncertain phrases: 0
- Evidence markers: 0
- Memory addresses: 0
- Citations: 0
- Code blocks: 5


### 08-key-programming-vcsec.md

**Quality:** ❌ UNTESTED (Score: 20/100)

**Statistics:**
- Lines: 41
- Uncertain phrases: 0
- Evidence markers: 0
- Memory addresses: 0
- Citations: 0
- Code blocks: 0


### 09-gateway-sdcard-log-analysis.md

**Quality:** ❌ UNTESTED (Score: 20/100)

**Statistics:**
- Lines: 380
- Uncertain phrases: 3
- Evidence markers: 0
- Memory addresses: 0
- Citations: 0
- Code blocks: 5

**Top Uncertain Phrases:**
- Line 142: - Likely size-based rotation with limited history
- Line 151: | **VIN** | Not visible in sample but likely in full logs | High - Unique identifier |
- Line 154: | **Map Region** | Config ID 66 = 0 (likely North America) | Low - Coarse location |


### 11-vcsec-keycard-routines.md

**Quality:** ❌ UNTESTED (Score: 20/100)

**Statistics:**
- Lines: 197
- Uncertain phrases: 0
- Evidence markers: 0
- Memory addresses: 0
- Citations: 0
- Code blocks: 0


### 14-offline-update-practical-guide.md

**Quality:** ❌ UNTESTED (Score: 20/100)

**Statistics:**
- Lines: 80
- Uncertain phrases: 1
- Evidence markers: 0
- Memory addresses: 0
- Citations: 0
- Code blocks: 1

**Top Uncertain Phrases:**
- Line 24: ## 3. Unknown or Unverified Elements (Evidence Gaps)


### 23-certificate-chain-analysis.md

**Quality:** ❌ UNTESTED (Score: 20/100)

**Statistics:**
- Lines: 1531
- Uncertain phrases: 18
- Evidence markers: 17
- Memory addresses: 0
- Citations: 0
- Code blocks: 39

**Top Uncertain Phrases:**
- Line 59: - **Renewal Window:** Starts ~90 days before expiry (estimated)
- Line 331: - May be TPM-protected (hardware security module)
- Line 382: **Key Functions (inferred from strings and logic):**
- Line 385: 3. `create_additional_csrs()` — Possibly for backup/rollback CSRs
- Line 397: **Hypothesized `ShouldRenew()` Logic:**

**Sample Evidence:**
- Line 254: - `1.3.6.1.4.1.49279.2.4.x` — VCSEC-related (appears in binary strings)
- Line 371: # Certificate-related functions (from strings analysis)
- Line 382: **Key Functions (inferred from strings and logic):**


### 39-attack-tree-diagram.md

**Quality:** ❌ UNTESTED (Score: 20/100)

**Statistics:**
- Lines: 465
- Uncertain phrases: 1
- Evidence markers: 0
- Memory addresses: 0
- Citations: 0
- Code blocks: 6

**Top Uncertain Phrases:**
- Line 310: - ⭐ = Very difficult (theoretical/research-level)


### 44-mcu-networking-enhanced.md

**Quality:** ❌ UNTESTED (Score: 20/100)

**Statistics:**
- Lines: 186
- Uncertain phrases: 0
- Evidence markers: 0
- Memory addresses: 0
- Citations: 0
- Code blocks: 1


### 48-hardware-architecture.md

**Quality:** ❌ UNTESTED (Score: 20/100)

**Statistics:**
- Lines: 523
- Uncertain phrases: 17
- Evidence markers: 3
- Memory addresses: 0
- Citations: 0
- Code blocks: 3

**Top Uncertain Phrases:**
- Line 7: > **Evidence vs inference:**
- Line 9: > - **Inference** items are architectural hypotheses consistent with evidence but not directly prove
- Line 15: This MCU2 generation appears to be a **two‑processor “main board”** that combines:
- Line 174: - `gw` is a hostname resolving to the Gateway ECU (likely `192.168.90.102`).
- Line 207: **Interpretation (inference):**

**Sample Evidence:**
- Line 8: > - **Evidence** items are backed by paths/strings/scripts in the extracted filesystem or by prior d
- Line 205: - MCU software parses Gateway update logs (`parse_gateway_update_log` strings referenced in `/root/t
- Line 222: - `ofono` configuration exists at `/root/downloads/mcu2-extracted/etc/ofono/iris.conf`.


### 55-gateway-spc-chip-replacement.md

**Quality:** ❌ UNTESTED (Score: 20/100)

**Statistics:**
- Lines: 283
- Uncertain phrases: 6
- Evidence markers: 0
- Memory addresses: 0
- Citations: 0
- Code blocks: 0

**Top Uncertain Phrases:**
- Line 9: This document discusses a **hardware-based attack class** (microcontroller replacement + debug acces
- Line 57: - Reading fuse state is usually possible (at least partially) via privileged registers; however, rea
- Line 81: This may be performed by:
- Line 144: - There may be additional paired components (external flash/EEPROM/secure element) that complicate s
- Line 145: - Firmware may be device-bound (unique IDs, key derivation, checksums).


### QUICK_REFERENCE_NETWORK.md

**Quality:** ❌ UNTESTED (Score: 20/100)

**Statistics:**
- Lines: 101
- Uncertain phrases: 1
- Evidence markers: 0
- Memory addresses: 0
- Citations: 0
- Code blocks: 2

**Top Uncertain Phrases:**
- Line 10: - No encryption (likely)


### TASK_COMPLETION_REPORT.md

**Quality:** ❌ UNTESTED (Score: 20/100)

**Statistics:**
- Lines: 170
- Uncertain phrases: 0
- Evidence markers: 0
- Memory addresses: 0
- Citations: 0
- Code blocks: 0


### VERIFICATION-STATUS.md

**Quality:** ❌ UNTESTED (Score: 20/100)

**Statistics:**
- Lines: 106
- Uncertain phrases: 16
- Evidence markers: 7
- Memory addresses: 0
- Citations: 0
- Code blocks: 0

**Top Uncertain Phrases:**
- Line 12: ### ⚠️ INFERRED (Logical Deduction)
- Line 14: - Timing estimated from multiple sources
- Line 35: - ⚠️ Packet format hypothesized (not captured)
- Line 40: - ⚠️ gwmon timeout: estimated 15-30s (not exact)
- Line 47: - Algorithm is speculative

**Sample Evidence:**
- Line 6: - Binary strings extracted
- Line 13: - Protocol format reconstructed from strings
- Line 25: - 47-gateway-debug-interface.md - Pin measurements, strings, bootloader code


### 02-gateway-can-flood-exploit.md

**Quality:** 🔍 NEEDS RE-ANALYSIS (Score: 40/100)

**Statistics:**
- Lines: 379
- Uncertain phrases: 0
- Evidence markers: 1
- Memory addresses: 0
- Citations: 0
- Code blocks: 19

**Sample Evidence:**
- Line 340: | `handshake/signature.json` | Additional signature entries (437KB) |


### 06-usb-firmware-update.md

**Quality:** 🔍 NEEDS RE-ANALYSIS (Score: 40/100)

**Statistics:**
- Lines: 41
- Uncertain phrases: 1
- Evidence markers: 2
- Memory addresses: 0
- Citations: 0
- Code blocks: 0

**Top Uncertain Phrases:**
- Line 24: - The updater appears to support an **“offline” package mode** (distinct from normal online update f

**Sample Evidence:**
- Line 7: From `sx-updater` strings (MCU2 / S-X firmware):
- Line 26: - The presence of signature-verification strings implies that even in offline mode, packages are exp


### 18-cid-iris-update-pipeline.md

**Quality:** 🔍 NEEDS RE-ANALYSIS (Score: 40/100)

**Statistics:**
- Lines: 66
- Uncertain phrases: 4
- Evidence markers: 4
- Memory addresses: 0
- Citations: 0
- Code blocks: 0

**Top Uncertain Phrases:**
- Line 10: - Not directly tied to a runit service; instead accessible to escalator and likely triggered by serv
- Line 27: - Signed via `/etc/verity-breakout-prod.pub` with optional dev key (if `is-fused --no-fuse-sentinel`
- Line 37: - Performs cleanup of CID updater staging: deletes `/home/cid-updater/ape.ssq`, `/home/cid-updater/i
- Line 52: - No service references found; likely invoked from OTA installer or maintenance scripts when bootloa

**Sample Evidence:**
- Line 6: - Performs modem SKU detection, signature-domain matching, and triggers `/usr/bin/QFirehose -f /depl
- Line 51: - Binary uses `heci_ifwi_update_stage/clear` to stage Intel IFWI updates from `DEV:PART:FILE` argume
- Line 52: - No service references found; likely invoked from OTA installer or maintenance scripts when bootloa


### 28-can-flood-refined-timing.md

**Quality:** 🔍 NEEDS RE-ANALYSIS (Score: 40/100)

**Statistics:**
- Lines: 573
- Uncertain phrases: 0
- Evidence markers: 2
- Memory addresses: 1
- Citations: 0
- Code blocks: 17

**Sample Evidence:**
- Line 19: From bootloader disassembly at `0x2410` (vTaskSwitchContext):
- Line 21: ```c


### 32-log-exfiltration-data-mining.md

**Quality:** 🔍 NEEDS RE-ANALYSIS (Score: 40/100)

**Statistics:**
- Lines: 1510
- Uncertain phrases: 0
- Evidence markers: 3
- Memory addresses: 0
- Citations: 0
- Code blocks: 52

**Sample Evidence:**
- Line 515: `strings hermes_eventlogs` output contains:
- Line 1450: ### Appendix E: Binary Analysis Strings (Sample)
- Line 1503: 6. Binary analysis: `/opt/hermes/hermes_*` (strings, file analysis)


### 34-chromium-analysis-checklist.md

**Quality:** 🔍 NEEDS RE-ANALYSIS (Score: 40/100)

**Statistics:**
- Lines: 147
- Uncertain phrases: 1
- Evidence markers: 2
- Memory addresses: 0
- Citations: 0
- Code blocks: 0

**Top Uncertain Phrases:**
- Line 42: - innerHTML usage in web apps (theoretical)

**Sample Evidence:**
- Line 102: - **Version extraction:** strings command on tesla-chromium-main
- Line 103: - **Dependency analysis:** readelf shared library enumeration


### 39-INDEX.md

**Quality:** 🔍 NEEDS RE-ANALYSIS (Score: 40/100)

**Statistics:**
- Lines: 260
- Uncertain phrases: 1
- Evidence markers: 3
- Memory addresses: 2
- Citations: 0
- Code blocks: 1

**Top Uncertain Phrases:**
- Line 199: - Estimated Reward: $5,000-$15,000

**Sample Evidence:**
- Line 165: - [ ] Disassemble setServicePIN() function (offset 0x3bc4bc)
- Line 166: - [ ] Disassemble set_factory_mode() (offset 0x451d7e)
- Line 177: - [ ] Full Ghidra disassembly project


### 43-ape-network-services.md

**Quality:** 🔍 NEEDS RE-ANALYSIS (Score: 40/100)

**Statistics:**
- Lines: 1200
- Uncertain phrases: 7
- Evidence markers: 7
- Memory addresses: 0
- Citations: 3
- Code blocks: 36

**Top Uncertain Phrases:**
- Line 112: **Note:** Uses DHCP for IP assignment (likely static DHCP reservation via Gateway/MCU)
- Line 542: **Default Policy:** Not explicitly shown - likely **ACCEPT** (permissive default).
- Line 730: **Port:** Unknown (not in firewall rules - likely localhost-only)
- Line 773: **Mitigation:** Tesla likely uses OpenSSL 1.1.x (not 3.0.x), but version should be verified.
- Line 785: **Exploitability:** If service-api-tls supports HTTP/2, it may be vulnerable to DoS attacks.

**Sample Evidence:**
- Line 6: **Source:** APE firmware extraction (`/root/downloads/ape-extracted/`)
- Line 7: **Cross-reference:** MCU2 network analysis ([25-network-attack-surface.md](25-network-attack-surface
- Line 158: | **111** | TCP/UDP | portmapper/rpc.bind | NFS RPC | 🟠 HIGH |


### 44-mcu-networking-deep-dive.md

**Quality:** 🔍 NEEDS RE-ANALYSIS (Score: 40/100)

**Statistics:**
- Lines: 1917
- Uncertain phrases: 7
- Evidence markers: 4
- Memory addresses: 1
- Citations: 3
- Code blocks: 25

**Top Uncertain Phrases:**
- Line 980: - 🟡 API likely allows diagnostic commands
- Line 1013: - 🔴 Factory mode opens 10.0.0.0/8:443 - could be used for data exfil
- Line 1255: - Likely for guest WiFi hotspot or similar
- Line 1375: - "DV traffic" likely = Data Visualization (multicast to 127.255.255.255)
- Line 1465: - Likely allows status queries, maybe command injection

**Sample Evidence:**
- Line 3: **Source:** `/root/downloads/mcu2-extracted`
- Line 1024: - Source: 192.168.90.103/105
- Line 1230: CGROUP_QTCAR=0x10001


### ANALYSIS-COMPLETION-REPORT.md

**Quality:** 🔍 NEEDS RE-ANALYSIS (Score: 40/100)

**Statistics:**
- Lines: 454
- Uncertain phrases: 0
- Evidence markers: 4
- Memory addresses: 1
- Citations: 2
- Code blocks: 3

**Sample Evidence:**
- Line 17: 2. ✅ **Updated Reference:** `/root/tesla/04-network-ports-firewall.md` (Appendix B added)
- Line 221: - Reference: `ChromiumAdapterWebSocketImpl` in Tesla MCU2
- Line 249: # Listen 127.0.0.1:631 in /etc/cups/cupsd.conf


### PRACTICAL-EXPLOIT-GUIDE-COMPLETION.md

**Quality:** 🔍 NEEDS RE-ANALYSIS (Score: 40/100)

**Statistics:**
- Lines: 599
- Uncertain phrases: 0
- Evidence markers: 1
- Memory addresses: 0
- Citations: 0
- Code blocks: 2

**Sample Evidence:**
- Line 175: - Ghidra/IDA Pro (Free/$500)


### README.md

**Quality:** 🔍 NEEDS RE-ANALYSIS (Score: 40/100)

**Statistics:**
- Lines: 197
- Uncertain phrases: 0
- Evidence markers: 2
- Memory addresses: 0
- Citations: 0
- Code blocks: 1

**Sample Evidence:**
- Line 125: - `kb/index/INDEX.json` - Cross-reference database
- Line 174: │   ├── index/INDEX.json


### TASK-research-status-tracker-COMPLETE.md

**Quality:** 🔍 NEEDS RE-ANALYSIS (Score: 40/100)

**Statistics:**
- Lines: 479
- Uncertain phrases: 3
- Evidence markers: 3
- Memory addresses: 1
- Citations: 0
- Code blocks: 7

**Top Uncertain Phrases:**
- Line 124: - Research paths suggested for unknowns
- Line 222: - Estimated effort
- Line 237: - **7.6 Time Investment:** ~77 hours estimated

**Sample Evidence:**
- Line 20: 7. Statistics: files analyzed, strings extracted, exploits found
- Line 143: | 0x00010000 | Boot entry point | PowerPC reset vector | 12, 26 |
- Line 226: ### ✅ Objective 7: Statistics - files analyzed, strings extracted, exploits found


### 00-master-cross-reference.md

**Quality:** ⚠️ INFERRED (Score: 60/100)

**Statistics:**
- Lines: 488
- Uncertain phrases: 9
- Evidence markers: 27
- Memory addresses: 17
- Citations: 8
- Code blocks: 3

**Top Uncertain Phrases:**
- Line 7: > This is a **living** synthesis document. It prioritizes: (1) what is evidenced, (2) what is inferr
- Line 69: - Service Mode Auth state is stored in `GUI_serviceModeAuth` and tied to **signed command infrastruc
- Line 93: - It is mediated by signed commands / DoIP tooling and likely backend entitlements.
- Line 107: - Evidence shows **overloads** exist (`set_factory_mode(context)` and `set_factory_mode(context, on)
- Line 108: - Whether any caller can supply a context that bypasses fuse checks remains **unverified**.

**Sample Evidence:**
- Line 43: **Port reference:** see [04](04-network-ports-firewall.md).
- Line 111: - D‑Bus interface + disassembly of factory mode handler: [01](01-ui-decompilation-service-factory.md
- Line 124: Primary source: [05](05-gap-analysis-missing-pieces.md)


### 01-ui-decompilation-service-factory.md

**Quality:** ⚠️ INFERRED (Score: 60/100)

**Statistics:**
- Lines: 427
- Uncertain phrases: 7
- Evidence markers: 41
- Memory addresses: 31
- Citations: 1
- Code blocks: 17

**Top Uncertain Phrases:**
- Line 233: The `VehicleUtils::isServiceModeAllowedOutsideGeofence()` function suggests service mode may be rest
- Line 233: The `VehicleUtils::isServiceModeAllowedOutsideGeofence()` function suggests service mode may be rest
- Line 352: - Implementation is stripped; likely uses secure hash comparison
- Line 359: - Logging of state changes suggests audit trail
- Line 360: - No visible authentication in D-Bus interface (auth may be at lower level)

**Sample Evidence:**
- Line 4: **Source:** `/root/downloads/mcu2-extracted/usr/tesla/UI/`
- Line 15: ```cpp
- Line 29: ```cpp


### 05-gap-analysis-missing-pieces.md

**Quality:** ⚠️ INFERRED (Score: 60/100)

**Statistics:**
- Lines: 253
- Uncertain phrases: 2
- Evidence markers: 9
- Memory addresses: 1
- Citations: 1
- Code blocks: 8

**Top Uncertain Phrases:**
- Line 34: The authentication appears to use:
- Line 199: - Likely uses certificate-based authentication

**Sample Evidence:**
- Line 12: **Password/code validation strings in binaries:**
- Line 22: - **CRC32("service") = 0x63A888F9** - NOT FOUND in any binary
- Line 27: From D-Bus interface strings found in UI binaries:


### 12-gateway-bootloader-analysis.md

**Quality:** ⚠️ INFERRED (Score: 60/100)

**Statistics:**
- Lines: 432
- Uncertain phrases: 8
- Evidence markers: 149
- Memory addresses: 177
- Citations: 0
- Code blocks: 13

**Top Uncertain Phrases:**
- Line 12: 1. **Architecture:** Power Architecture Book-E MCU firmware (Freescale/NXP MPC55xx / SPC5x-class; ea
- Line 276: This appears to be a command accumulation mechanism - bytes are collected until 8 are received, then
- Line 308: This is likely the CAN message handler dispatch table - each index corresponds to a CAN arbitration 
- Line 339: While specific CAN ID handlers aren't explicitly visible in strings, the jump table structure sugges
- Line 346: ### Likely CAN ID Mapping (based on table indices):

**Sample Evidence:**
- Line 16: 5. **Memory Layout:** Code at 0x40000000, RAM at 0x4002xxxx
- Line 29: 0x08    4     Unknown flags (0x0001609c for R4, 0x0001709c for R7)
- Line 31: 0x10    4     Size field (0x0000002c = 44 bytes header?)


### 15-updater-component-inventory.md

**Quality:** ⚠️ INFERRED (Score: 60/100)

**Statistics:**
- Lines: 106
- Uncertain phrases: 5
- Evidence markers: 15
- Memory addresses: 0
- Citations: 0
- Code blocks: 0

**Top Uncertain Phrases:**
- Line 35: - Strings show HTTP endpoints under `/signature-redeploy`, `/handshake`, `/set_handshake`, handshake
- Line 50: - Strings: `strings -n 8 /usr/bin/updater-envoy` output includes `http://localhost.../packages/signa
- Line 52: - Inter-component communication: `updaterctl` communicates to `localhost:20564` and `localhost:28496
- Line 52: - Inter-component communication: `updaterctl` communicates to `localhost:20564` and `localhost:28496
- Line 56: - Basic info: `file /usr/bin/updaterctl` -> Bash script. Script uses default HOST=localhost, PORT=20

**Sample Evidence:**
- Line 26: - Strings covering offline roles:
- Line 27: - Contains numerous `offline`, `service.upd`, `factory.upd`, `verity`, `handshake`, `signature` stri
- Line 28: - Handles USB/factory override markers: `factory_usb`, `factory_usb_check`, `/factory.upd`, `/servic


### 20-service-mode-authentication.md

**Quality:** ⚠️ INFERRED (Score: 60/100)

**Statistics:**
- Lines: 894
- Uncertain phrases: 9
- Evidence markers: 36
- Memory addresses: 15
- Citations: 2
- Code blocks: 46

**Top Uncertain Phrases:**
- Line 22: **KEY FINDING:** There is NO hardcoded PIN, CRC32 hash, or simple comparison. The "service code" is 
- Line 70: **Analysis:** The `doip-gateway` user (Diagnostic over IP gateway) has special permission to trigger
- Line 171: **Field Type:** `optional int32 service_mode_auth` (appears to be enum/state)
- Line 316: Service mode authentication **may be geofence-restricted**:
- Line 318: - Possibly restricted in certain regions (China export compliance?)

**Sample Evidence:**
- Line 40: 0x00000000006e3f90  CenterDisplayDbusServiceAdaptor::setServicePIN(QString const&, bool&, QString&)
- Line 41: 0x0000000000655ec0  CenterDisplayDbusServiceImpl::setServicePIN(QString const&, bool&, QString&)
- Line 42: 0x0000000000641620  CenterDisplayHandlerImplCommon::setServicePIN(QString const&, bool&, QString&)


### 21-gateway-heartbeat-failsafe.md

**Quality:** ⚠️ INFERRED (Score: 60/100)

**Statistics:**
- Lines: 1037
- Uncertain phrases: 18
- Evidence markers: 41
- Memory addresses: 0
- Citations: 16
- Code blocks: 41

**Top Uncertain Phrases:**
- Line 165: 2. **Threshold:** Exact timeout value **NOT FOUND** in strings (likely 5-30 seconds based on behavio
- Line 254: **Likely Value:** 5-15 seconds based on typical UI watchdog patterns
- Line 261: 3. **Likely:** UI process restart via service manager
- Line 312: **Estimated:** 2-10 seconds (critical component requires tight monitoring)
- Line 319: 2. **Action:** Likely triggers vehicle safe mode

**Sample Evidence:**
- Line 65: **Source:** `/root/downloads/mcu2-extracted/etc/sysctl.conf`
- Line 65: **Source:** `/root/downloads/mcu2-extracted/etc/sysctl.conf`
- Line 70: **Source:** `/root/downloads/mcu2-extracted/etc/sv/watchdog/run`


### 24-vcsec-key-programming-summary.md

**Quality:** ⚠️ INFERRED (Score: 60/100)

**Statistics:**
- Lines: 331
- Uncertain phrases: 7
- Evidence markers: 12
- Memory addresses: 0
- Citations: 1
- Code blocks: 3

**Top Uncertain Phrases:**
- Line 116: - All operations logged (inferred from error strings)
- Line 224: 1. **Exact CAN Message Structures:** Only inferred formats documented
- Line 226: 3. **All-Keys-Lost ODJ Routine:** Not in public ODJ definitions (likely service-only)
- Line 245: ### Medium Confidence (Inferred from Context)
- Line 246: - ⚠️ CAN message formats (inferred from similar Tesla systems)

**Sample Evidence:**
- Line 35: - 14 error strings documenting authorization failures
- Line 50: **Source:** Extracted from libSharedProto.so strings section
- Line 50: **Source:** Extracted from libSharedProto.so strings section


### 24-vcsec-key-programming.md

**Quality:** ⚠️ INFERRED (Score: 60/100)

**Statistics:**
- Lines: 1044
- Uncertain phrases: 13
- Evidence markers: 25
- Memory addresses: 0
- Citations: 2
- Code blocks: 38

**Top Uncertain Phrases:**
- Line 84: - Typical capacity: **32 slots** (inferred from similar Tesla implementations)
- Line 414: Output: (not defined in ODJ, likely status flags)
- Line 529: **Inferred CAN Message Structure (based on similar Tesla systems):**
- Line 624: **Not exposed in standard ODJ routines.** Emergency reset likely requires:
- Line 630: **Inferred from error messages:** Tesla's backend systems can remotely invalidate keys, but this req

**Sample Evidence:**
- Line 8: - `/root/downloads/mcu2-extracted/usr/tesla/UI/lib/libSharedProto.so`
- Line 56: ```cpp
- Line 126: ```cpp


### 31-apparmor-sandbox-security.md

**Quality:** ⚠️ INFERRED (Score: 60/100)

**Statistics:**
- Lines: 1580
- Uncertain phrases: 3
- Evidence markers: 5
- Memory addresses: 0
- Citations: 3
- Code blocks: 57

**Top Uncertain Phrases:**
- Line 458: **🚨 VULNERABILITY:** `rm -rf "$CHROOT"` without validation could be exploited if `$CHROOT_DIR` is at
- Line 991: **Theoretical Attack:**
- Line 1023: - Process runs with whatever profile kernel assigns (may be none!)

**Sample Evidence:**
- Line 37: **Source:** `/root/downloads/mcu2-extracted/etc/apparmor.d/abstractions/`
- Line 374: /tmp/odin.sock rw,
- Line 919: /etc/apparmor.compiled/usr.bin.service-shell-* r,


### 33-can-protocol-reverse-engineering.md

**Quality:** ⚠️ INFERRED (Score: 60/100)

**Statistics:**
- Lines: 301
- Uncertain phrases: 15
- Evidence markers: 17
- Memory addresses: 14
- Citations: 0
- Code blocks: 1

**Top Uncertain Phrases:**
- Line 14: > **Important constraints:** Many binaries used for this research are **stripped**, and some conclus
- Line 85: **Likely interpretation (INFERRED):**
- Line 85: **Likely interpretation (INFERRED):**
- Line 107: - Is ISO-TP used for multi-frame UDS on this segment (likely) vs single-frame only?
- Line 115: **Format (INFERRED):**

**Sample Evidence:**
- Line 57: | `0x00` | `0x800` | `0x4000150C` | Init/Boot handler | **CONFIRMED** (from `26-bootloader-exploit-r
- Line 58: | `0x87` | `0x8A0` | `0x40005400` | Diagnostic mode entry | **CONFIRMED** |
- Line 59: | `0x8A` | `0x8A8` | `0x40005408` | Extended diagnostic | **CONFIRMED** |


### 34-chromium-webkit-attack-surface.md

**Quality:** ⚠️ INFERRED (Score: 60/100)

**Statistics:**
- Lines: 1219
- Uncertain phrases: 11
- Evidence markers: 19
- Memory addresses: 0
- Citations: 0
- Code blocks: 64

**Top Uncertain Phrases:**
- Line 45: **Severity:** High (CVSS likely 8.1+)
- Line 108: - Likely requires specific HTML parser state
- Line 272: **Exposed Functions (inferred from symbols):**
- Line 354: **Inferred CSP (default Chromium):**
- Line 377: **Type:** ELF executable (likely embeds web view)

**Sample Evidence:**
- Line 30: $ strings tesla-chromium-main | grep "Chrome/"
- Line 141: ```cpp
- Line 217: ```cpp


### 36-gateway-sx-updater-reversing.md

**Quality:** ⚠️ INFERRED (Score: 60/100)

**Statistics:**
- Lines: 1391
- Uncertain phrases: 12
- Evidence markers: 142
- Memory addresses: 136
- Citations: 1
- Code blocks: 65

**Top Uncertain Phrases:**
- Line 26: 3. **Watchdog Timeout:** Estimated **15-30 seconds** based on timing analysis (exact value requires 
- Line 87: - **Huge .bss section (38 MB):** Likely contains large buffers for firmware staging, session trackin
- Line 150: // Estimated structure (reverse-engineered)
- Line 309: **Function Name (inferred):** `set_kernel_watchdog_timeout`
- Line 407: **Inferred from Disassembly:**

**Sample Evidence:**
- Line 24: 1. **Emergency Session Address:** `0x415549` - string reference to `emergency_session` state
- Line 59: Entry Point: 0x671bd
- Line 78: .text           0x00067040  0x3abc74    R-E    Executable code (3.7 MB)


### 37-doip-gateway-reversing.md

**Quality:** ⚠️ INFERRED (Score: 60/100)

**Statistics:**
- Lines: 1300
- Uncertain phrases: 11
- Evidence markers: 101
- Memory addresses: 62
- Citations: 2
- Code blocks: 61

**Top Uncertain Phrases:**
- Line 405: // Calls another D-Bus service (likely com.tesla.PowerManager)
- Line 538: ### Packet Format (Inferred)
- Line 574: "192.168.90.102"  // Likely the vehicle's diagnostic network IP
- Line 688: // Logging function (inferred from __syslog_chk calls)
- Line 779: Tesla likely uses **extended CAN IDs** (29-bit) for proprietary ECUs.

**Sample Evidence:**
- Line 50: ```c
- Line 75: **Address:** `0x00006f60`
- Line 81: ```c


### 38-gateway-firmware-analysis-COMPLETE.md

**Quality:** ⚠️ INFERRED (Score: 60/100)

**Statistics:**
- Lines: 569
- Uncertain phrases: 6
- Evidence markers: 65
- Memory addresses: 54
- Citations: 0
- Code blocks: 15

**Top Uncertain Phrases:**
- Line 140: - **Port 3500** - 8 occurrences (likely internal CAN bridge)
- Line 234: - **Likely location:** `/usr/sbin/` or embedded in `sx-updater`
- Line 251: Not explicitly visible in disassembly - likely in FreeRTOS task (periodic write to 0xFFFE0000).
- Line 256: - **Estimated:** 5-10 seconds (typical for automotive ECU)
- Line 347: | Emergency mode bypass | ✅ Mechanism explained | ✅ Hypothesized |

**Sample Evidence:**
- Line 98: **Critical Strings Found:**
- Line 100: 0x1004: "Factory gate succeeded"
- Line 101: 0x101C: "Factory gate failed"


### 38-gateway-firmware-analysis.md

**Quality:** ⚠️ INFERRED (Score: 60/100)

**Statistics:**
- Lines: 1264
- Uncertain phrases: 13
- Evidence markers: 121
- Memory addresses: 120
- Citations: 0
- Code blocks: 43

**Top Uncertain Phrases:**
- Line 110: - **Port 25956 exploit** likely involves PowerPC triggering emergency mode on x86_64 side
- Line 188: Offset   │ CAN ID │ Handler Address  │ Likely Function
- Line 277: | (others unknown) | - | Debug mode, recovery mode, etc. | Hypothesized |
- Line 415: **Hardware:** Likely FlexCAN controller (standard on MPC55xx)
- Line 487: **CAN Interface:** Likely `can0` or `can1` (SocketCAN interface names)

**Sample Evidence:**
- Line 32: - ✅ **Port 22580 (0x5834)** is the primary DoIP port (not 25956)
- Line 125: | **Entry Point** | 0x48000040 (branch to 0x40) | 0x48000040 (branch to 0x40) |
- Line 126: | **Checksum** | 0x7D3F6B8C | Different |


### 39-qtcarserver-security-audit-SUMMARY.md

**Quality:** ⚠️ INFERRED (Score: 60/100)

**Statistics:**
- Lines: 372
- Uncertain phrases: 2
- Evidence markers: 8
- Memory addresses: 2
- Citations: 0
- Code blocks: 10

**Top Uncertain Phrases:**
- Line 310: **Estimated Reward:** $5,000-$15,000 for service mode bypass
- Line 337: 5. **Social engineering may be easier** - Stolen Toolbox credentials

**Sample Evidence:**
- Line 43: ```cpp
- Line 77: ```cpp
- Line 179: - String offset: 0x3bc4bc


### 40-INDEX.md

**Quality:** ⚠️ INFERRED (Score: 60/100)

**Statistics:**
- Lines: 487
- Uncertain phrases: 4
- Evidence markers: 9
- Memory addresses: 0
- Citations: 0
- Code blocks: 16

**Top Uncertain Phrases:**
- Line 186: - Likely no authentication in factory mode
- Line 213: | 8901 | factory-camera-calibration | None? | **HIGH** | Active during SD format, likely unauthentic
- Line 292: - [ ] Understand inference pipeline
- Line 401: **Note:** "unsigned" in filename suggests this is pre-signing build artifact

**Sample Evidence:**
- Line 175: strings /root/downloads/ape-extracted/opt/autopilot/bin/factory_camera_calibration | less
- Line 258: - [ ] Load in Ghidra/IDA Pro
- Line 288: - [ ] Identify TensorRT engine files (binwalk)


### 40-ape-extraction-summary.md

**Quality:** ⚠️ INFERRED (Score: 60/100)

**Statistics:**
- Lines: 323
- Uncertain phrases: 4
- Evidence markers: 5
- Memory addresses: 0
- Citations: 0
- Code blocks: 2

**Top Uncertain Phrases:**
- Line 22: | 8901 | factory-camera-calibration | Factory calibration HTTP | Unknown (likely none in factory mod
- Line 145: 1. **vision** (389MB) - Neural network engine, likely contains model weights
- Line 163: **Status:** Likely exposed during SD card format
- Line 164: **Authentication:** Unknown (probably none in factory mode)

**Sample Evidence:**
- Line 263: - Strings in service_api: "successfully cleared calibration files for '%s' camera, reboot requested"
- Line 278: - **Ghidra** - Primary RE tool
- Line 279: - **IDA Pro** - Alternative/comparison


### 40-ape-firmware-extraction.md

**Quality:** ⚠️ INFERRED (Score: 60/100)

**Statistics:**
- Lines: 1109
- Uncertain phrases: 11
- Evidence markers: 13
- Memory addresses: 0
- Citations: 1
- Code blocks: 66

**Top Uncertain Phrases:**
- Line 425: **Binary:** (TBD - likely shell script or separate binary)
- Line 456: **Security:** Likely requires authorized keys or factory mode
- Line 680: Purpose: Initialize GPU for neural network inference
- Line 738: - Likely contains TensorRT/CUDA inference code
- Line 738: - Likely contains TensorRT/CUDA inference code

**Sample Evidence:**
- Line 28: Source: /root/downloads/ape-firmware/2024.8.9.ice.ape25 (534MB)
- Line 545: /etc/resolv.conf        - DNS configuration
- Line 546: /etc/nsswitch.conf      - Name service switch


### 41-ape-factory-calibration.md

**Quality:** ⚠️ INFERRED (Score: 60/100)

**Statistics:**
- Lines: 1121
- Uncertain phrases: 6
- Evidence markers: 26
- Memory addresses: 5
- Citations: 2
- Code blocks: 44

**Top Uncertain Phrases:**
- Line 111: **Additional endpoints inferred:**
- Line 420: OpenCV/MatExpr: processing of multi-channel arrays might be changed...
- Line 503: /factory/.in-factory                     # Factory mode active marker (inferred)
- Line 857: | **2. Sentinel file creation** | LOW | HIGH | File system permissions (unverified) |
- Line 896: **Port 8901 NOT in firewall rules** - suggests:

**Sample Evidence:**
- Line 5: **Source:** APE firmware extraction + Odin bundle scripts
- Line 114: - `/factory_calibration/metrology.json` - Metrology data
- Line 190: **From `factory_camera_calibration` binary strings:**


### 49-modem-iris-tillit-analysis.md

**Quality:** ⚠️ INFERRED (Score: 60/100)

**Statistics:**
- Lines: 1169
- Uncertain phrases: 9
- Evidence markers: 12
- Memory addresses: 0
- Citations: 2
- Code blocks: 21

**Top Uncertain Phrases:**
- Line 36: - **Form Factor:** M.2 module (likely)
- Line 107: - **Transport:** Direct Ethernet connection (likely PCIe-to-Ethernet bridge or RGMII)
- Line 390: **Purpose:** "CMT" likely stands for "Cellular Modem Test" - diagnostic utility
- Line 405: - Developer build artifact (likely not production)
- Line 740: - POST operations likely have rate limiting (not confirmed)

**Sample Evidence:**
- Line 41: # /etc/ofono/iris.conf
- Line 210: **Source:**
- Line 244: | `AT+CCID` | Get SIM ICCID | cmt-iris strings |


### 50-gateway-udp-config-protocol-SUMMARY.md

**Quality:** ⚠️ INFERRED (Score: 60/100)

**Statistics:**
- Lines: 418
- Uncertain phrases: 5
- Evidence markers: 8
- Memory addresses: 7
- Citations: 0
- Code blocks: 10

**Top Uncertain Phrases:**
- Line 19: **Packet Format (Hypothesized):**
- Line 178: ### Tool 2: Factory Gate Scanner (⚠️ UNTESTED)
- Line 381: ❌ Exploits untested on live hardware
- Line 391: **Estimated Time to Working Exploit:**
- Line 416: **Exploit Status:** THEORETICAL - Requires factory gate extraction

**Sample Evidence:**
- Line 76: **Location:** Gateway bootloader offset 0x1044 (from 12-gateway-bootloader-analysis.md)
- Line 79: ```c
- Line 97: - String "Factory gate succeeded" at 0x0FC0


### 50-gateway-udp-config-protocol.md

**Quality:** ⚠️ INFERRED (Score: 60/100)

**Statistics:**
- Lines: 1364
- Uncertain phrases: 10
- Evidence markers: 28
- Memory addresses: 25
- Citations: 0
- Code blocks: 34

**Top Uncertain Phrases:**
- Line 281: This mechanism accumulates an 8-byte "magic sequence" that triggers privileged operations. The seque
- Line 505: The 8-byte factory gate may be:
- Line 537: ### Packet Structure (Hypothesized)
- Line 561: ### Command Codes (Inferred)
- Line 717: """Hypothesized factory gate derivation"""

**Sample Evidence:**
- Line 149: ```c
- Line 152: const char *GATEWAY_PORT = "1050"; // UDP port at offset 0x5004 in binary
- Line 154: .ai_family = AF_INET,     // IPv4 (0x0100 = 1)


### 54-gateway-spc-architecture.md

**Quality:** ⚠️ INFERRED (Score: 60/100)

**Statistics:**
- Lines: 252
- Uncertain phrases: 8
- Evidence markers: 24
- Memory addresses: 27
- Citations: 0
- Code blocks: 0

**Top Uncertain Phrases:**
- Line 49: If that JTAG ID is correct, then the Gateway MCU is likely:
- Line 65: - `models-GW_R7.hex` is referenced in `52-gateway-firmware-decompile.md`; it is more likely to inclu
- Line 152: ## 5) Security features (what exists vs what likely doesn’t)
- Line 164: - Therefore, crypto is likely **software-based** (or uses small accelerators if present).
- Line 168: - Production devices can fuse/lock debug access; unclear what Tesla did.

**Sample Evidence:**
- Line 10: > Despite earlier docs calling the core “e500”, multiple indicators (Book-E exception model, IVPR/IV
- Line 21: - Entry instruction at offset 0: `0x48000040` (branch to init)
- Line 24: - Signature/hash fields present (Tesla image format), but **no explicit MCU part-number string** fou


### RESEARCH-STATUS.md

**Quality:** ⚠️ INFERRED (Score: 60/100)

**Statistics:**
- Lines: 1015
- Uncertain phrases: 20
- Evidence markers: 22
- Memory addresses: 18
- Citations: 0
- Code blocks: 21

**Top Uncertain Phrases:**
- Line 51: | 04 | Certificate Recovery Orphan Cars | 03-certificate-recovery-orphan-cars.md | ✅ COMPLETE | 2026
- Line 61: | 14 | OTA Handshake Protocol | 13-ota-handshake-protocol.md | ✅ COMPLETE | 2026-02-02 | MEDIUM - Pr
- Line 100: | ID | Task | Priority | Dependencies | Estimated Effort |
- Line 251: | **3. Exact CAN message formats** | Inferred structure, 0x2xx VCSEC domain | Byte-level specificati
- Line 273: | **8. Exact bootloader exploit reliability** | Theoretical analysis only | Live hardware testing | 

**Sample Evidence:**
- Line 256: | **8. Service Mode Plus features** | Mentioned in strings | Feature set, access requirements | Doc 
- Line 304: | 0x00010000 | Boot entry point | PowerPC reset vector | 12, 26 |
- Line 305: | 0x00010100 | Factory gate check | Validates factory mode flag | 12, 26 |


### TASK-COMPLETION-CHECKLIST.md

**Quality:** ⚠️ INFERRED (Score: 60/100)

**Statistics:**
- Lines: 428
- Uncertain phrases: 6
- Evidence markers: 10
- Memory addresses: 0
- Citations: 0
- Code blocks: 5

**Top Uncertain Phrases:**
- Line 210: - **6.1 Key Authentication CAN Flow:** Inferred message structure
- Line 229: - Inferred from VCSEC_TPMS.proto references to encrypted CAN
- Line 355: - ✅ CAN message sequences inferred
- Line 364: - **Medium Confidence (Inferred):**
- Line 365: - CAN message formats (inferred from context)

**Sample Evidence:**
- Line 44: - **14 "Binary Evidence" sections** with specific strings and offsets
- Line 55: - Disassembly of key functions (WhitelistOperation logic)
- Line 157: - 14 error strings (WHITELISTOPERATION_INFORMATION_*)


### TASK-zen-component-analysis-COMPLETE.md

**Quality:** ⚠️ INFERRED (Score: 60/100)

**Statistics:**
- Lines: 390
- Uncertain phrases: 1
- Evidence markers: 8
- Memory addresses: 5
- Citations: 0
- Code blocks: 7

**Top Uncertain Phrases:**
- Line 56: **Key Insight**: The 4 KB difference is likely build timestamps and platform-specific string tables.

**Sample Evidence:**
- Line 53: | `ice-updater` | 6,004,624 bytes | 0x671bd | Baseline |
- Line 54: | `sx-updater` | 6,008,720 bytes | 0x671bd | +4 KB (metadata) |
- Line 143: ```c


### 00-bootloader-research-index.md

**Quality:** ✅ VERIFIED (Score: 90/100)

**Statistics:**
- Lines: 517
- Uncertain phrases: 0
- Evidence markers: 14
- Memory addresses: 19
- Citations: 0
- Code blocks: 7

**Sample Evidence:**
- Line 49: - Boot mode register identified (0xFFFEC04C)
- Line 194: Code:    0x40000000-0x4001FFFF (128KB, RWX ⚠️)
- Line 195: RAM:     0x40020000-0x4002FFFF (64KB, RW)


### 10-usb-firmware-update-deep.md

**Quality:** ✅ VERIFIED (Score: 90/100)

**Statistics:**
- Lines: 601
- Uncertain phrases: 4
- Evidence markers: 11
- Memory addresses: 0
- Citations: 0
- Code blocks: 21

**Top Uncertain Phrases:**
- Line 339: This suggests firmware updates follow a similar naming convention (likely `tesla_firmware_*.ssq` or 
- Line 339: This suggests firmware updates follow a similar naming convention (likely `tesla_firmware_*.ssq` or 
- Line 482: 3. Place firmware package with correct naming pattern (likely `tesla_firmware_*.ssq`)
- Line 594: The exact format of a Tesla-signed USB update package with embedded offline signatures remains undoc

**Sample Evidence:**
- Line 5: All statements below are backed by strings or logic found in the extracted MCU2 filesystem under `/r
- Line 34: * `/usr/bin/mounterd` contains the literal strings:
- Line 56: * `mounterd` binary strings


### 13-ota-handshake-protocol.md

**Quality:** ✅ VERIFIED (Score: 90/100)

**Statistics:**
- Lines: 670
- Uncertain phrases: 0
- Evidence markers: 10
- Memory addresses: 0
- Citations: 1
- Code blocks: 29

**Sample Evidence:**
- Line 218: ```c
- Line 219: // From strings analysis:
- Line 237: **Key location strings:**


### 16-offline-update-format-notes.md

**Quality:** ✅ VERIFIED (Score: 90/100)

**Statistics:**
- Lines: 845
- Uncertain phrases: 3
- Evidence markers: 26
- Memory addresses: 2
- Citations: 2
- Code blocks: 56

**Top Uncertain Phrases:**
- Line 687: ### 10.2 Signature Generation (Theoretical)
- Line 693: # Theoretical package signing process
- Line 748: - Signature replay may be blocked by freshness checks in newer versions

**Sample Evidence:**
- Line 6: > **Source:** `/root/downloads/mcu2-extracted/`
- Line 37: strings -n 6 deploy/sx-updater | grep -n "update\.upd"
- Line 67: ```c


### 17-zen-cid-ice-updaters-findings.md

**Quality:** ✅ VERIFIED (Score: 90/100)

**Statistics:**
- Lines: 771
- Uncertain phrases: 4
- Evidence markers: 49
- Memory addresses: 32
- Citations: 0
- Code blocks: 37

**Top Uncertain Phrases:**
- Line 25: - No `/etc/sv/*/run` entry references `abl_update_dispatch` in the extracted tree (see `find /root/d
- Line 125: **Key Finding**: `sx-updater` and `ice-updater` are **the same binary** with only 4 KB difference (l
- Line 184: - Service may be dynamically created or symlinked to ice-updater
- Line 755: **Conclusion**: The 4 KB difference is likely:

**Sample Evidence:**
- Line 13: - Selected `strings -n 6` hits (hex offsets shown) reveal the updater's dependencies and CLI hints:
- Line 14: - `0x06c0 heci_ifwi_update_clear`
- Line 15: - `0x06a5 heci_ifwi_update_stage`


### 19-ice-updater-components.md

**Quality:** ✅ VERIFIED (Score: 90/100)

**Statistics:**
- Lines: 30
- Uncertain phrases: 0
- Evidence markers: 13
- Memory addresses: 0
- Citations: 9
- Code blocks: 0

**Sample Evidence:**
- Line 6: - Before forcing reboots, the helper checks the ICE/SX updater sentinel at `/var/spool/ice-updater/g
- Line 9: - The factory-reset flow reruns `update-cleanup-tasks` for `gw_feature_zero` and `SWR/DRIVE`, remove
- Line 12: - The deploy script unlocks SPI programming via `FPT`, refuses to run if the board is fused, and bui


### 25-network-attack-surface.md

**Quality:** ✅ VERIFIED (Score: 90/100)

**Statistics:**
- Lines: 1136
- Uncertain phrases: 2
- Evidence markers: 10
- Memory addresses: 5
- Citations: 0
- Code blocks: 56

**Top Uncertain Phrases:**
- Line 902: - ⚠️ Could be disabled if not needed
- Line 1080: └── gateway/ (assumed location)

**Sample Evidence:**
- Line 198: - **Turnstile**: Cloudflare CAPTCHA verification (secret key: 0x4AAAAAACW11wpuJ9aUXE8270_x7Ep2msc)
- Line 328: -A ts-postrouting -m mark --mark 0x40000/0xff0000 -j MASQUERADE
- Line 680: # Edit /etc/cups/cupsd.conf


### 26-bootloader-exploit-research.md

**Quality:** ✅ VERIFIED (Score: 90/100)

**Statistics:**
- Lines: 1513
- Uncertain phrases: 1
- Evidence markers: 149
- Memory addresses: 171
- Citations: 0
- Code blocks: 42

**Top Uncertain Phrases:**
- Line 960: #   0x02 = Recovery mode (hypothesized)

**Sample Evidence:**
- Line 55: **Clock:** ~150 MHz (derived from 0x09896800 clock divisor)
- Line 63: └─> 0x00000000 (Reset vector)
- Line 68: │   ├─> Map 0x40000000 (code, RWX)


### 27-bootloader-analysis-summary.md

**Quality:** ✅ VERIFIED (Score: 90/100)

**Statistics:**
- Lines: 705
- Uncertain phrases: 0
- Evidence markers: 42
- Memory addresses: 53
- Citations: 0
- Code blocks: 12

**Sample Evidence:**
- Line 88: **Location:** Function at `0x1044`
- Line 92: The factory gate accumulates bytes in a buffer at `0x40016000`. The buffer position counter is store
- Line 95: ```c


### 28-zen-component-architecture.md

**Quality:** ✅ VERIFIED (Score: 90/100)

**Statistics:**
- Lines: 815
- Uncertain phrases: 4
- Evidence markers: 23
- Memory addresses: 5
- Citations: 0
- Code blocks: 44

**Top Uncertain Phrases:**
- Line 59: **Key Observation**: The binary contains personality strings but no explicit `ZEN_UPDATER` constant.
- Line 59: **Key Observation**: The binary contains personality strings but no explicit `ZEN_UPDATER` constant.
- Line 533: **InfoZ/Zen Additions** (inferred from Odin scripts):
- Line 750: **Conclusion**: 4 KB difference likely represents:

**Sample Evidence:**
- Line 29: Entry Point: 0x671bd
- Line 33: ```c
- Line 59: **Key Observation**: The binary contains personality strings but no explicit `ZEN_UPDATER` constant.


### 29-usb-map-installation-deep.md

**Quality:** ✅ VERIFIED (Score: 90/100)

**Statistics:**
- Lines: 982
- Uncertain phrases: 4
- Evidence markers: 16
- Memory addresses: 0
- Citations: 0
- Code blocks: 51

**Top Uncertain Phrases:**
- Line 148: Maps likely use the **games signing keys** since they follow the same SSQ format:
- Line 515: ### 6.2 OTA Update (Theoretical)
- Line 721: Result:  Installation marked as FAIL, but map may be functional
- Line 779: **Note:** Partition name `tlc-amap.crypt` suggests **encrypted** storage, but details not fully docu

**Sample Evidence:**
- Line 96: 【/root/downloads/mcu2-extracted/usr/tesla/UI/assets/tesla_maps/valhalla.json†L3-L9】
- Line 106: **Key Functions (strings analysis):**
- Line 107: ```c


### 35-practical-exploit-guide.md

**Quality:** ✅ VERIFIED (Score: 90/100)

**Statistics:**
- Lines: 2319
- Uncertain phrases: 1
- Evidence markers: 25
- Memory addresses: 13
- Citations: 2
- Code blocks: 50

**Top Uncertain Phrases:**
- Line 1494: - Hardware fuse is correctly implemented but salvage vehicles may be unfused

**Sample Evidence:**
- Line 555: # [SUCCESS] Key paired: ID 0x1234ABCD
- Line 559: # Output: {"num_keys": 1, "keys": [{"id": "0x1234ABCD", "type": "fob"}]}
- Line 585: - New key ID stored: `0x1234ABCD`


### 39-QUICK-REF-security-findings.md

**Quality:** ✅ VERIFIED (Score: 90/100)

**Statistics:**
- Lines: 320
- Uncertain phrases: 1
- Evidence markers: 13
- Memory addresses: 2
- Citations: 0
- Code blocks: 17

**Top Uncertain Phrases:**
- Line 234: **Estimated Reward:** $5,000-$15,000 for service mode bypass

**Sample Evidence:**
- Line 33: → Offset: 0x3bc4bc (string table)
- Line 37: → Offset: 0x451d7e (string table)
- Line 166: ```cpp


### 39-qtcarserver-security-audit.md

**Quality:** ✅ VERIFIED (Score: 90/100)

**Statistics:**
- Lines: 1553
- Uncertain phrases: 3
- Evidence markers: 87
- Memory addresses: 37
- Citations: 0
- Code blocks: 100

**Top Uncertain Phrases:**
- Line 536: 1. **Filesystem:** `/var/tesla/keys/` (speculation)
- Line 1189: ⚠️ **No ECDSA curve specified:** Could be P-256 (secure) or P-192 (weak)
- Line 1384: ❌ Unclear certificate revocation system

**Sample Evidence:**
- Line 45: Location: String offset 0x3bc4bc
- Line 50: ```cpp
- Line 66: ```cpp


### 45-ape-networking-deep-dive.md

**Quality:** ✅ VERIFIED (Score: 90/100)

**Statistics:**
- Lines: 1291
- Uncertain phrases: 3
- Evidence markers: 15
- Memory addresses: 0
- Citations: 7
- Code blocks: 47

**Top Uncertain Phrases:**
- Line 773: # /etc/nsswitch.conf (inferred)
- Line 814: - `127.0.0.2` hosts are blocked (probably resolved by other services)
- Line 854: **In production:** AppArmor profiles (if any) are loaded, but unclear which services are confined.

**Sample Evidence:**
- Line 6: **Source:** APE firmware extraction (`/root/downloads/ape-extracted/`)
- Line 7: **Cross-reference:**
- Line 111: **Source:** `/root/downloads/ape-extracted/etc/network/interfaces`


### 47-gateway-debug-interface.md

**Quality:** ✅ VERIFIED (Score: 90/100)

**Statistics:**
- Lines: 1107
- Uncertain phrases: 1
- Evidence markers: 79
- Memory addresses: 94
- Citations: 0
- Code blocks: 30

**Top Uncertain Phrases:**
- Line 7: **Processor:** Freescale/NXP MPC55xx / SPC5x-class Power Architecture MCU (Book-E; likely e200z6 rat

**Sample Evidence:**
- Line 19: 2. ✅ **GPIO Configuration:** Pins mapped to MPC55xx SIU (System Integration Unit) at 0xC3F00000
- Line 146: 40000110:  mtspr  625, r0           ; MAS1 = 0xC0000500 (valid TLB entry)
- Line 147: 40000114:  lis    r0, 0xC3F0        ; Load high 16 bits


### 52-gateway-firmware-decompile.md

**Quality:** ✅ VERIFIED (Score: 90/100)

**Statistics:**
- Lines: 703
- Uncertain phrases: 1
- Evidence markers: 120
- Memory addresses: 121
- Citations: 1
- Code blocks: 18

**Top Uncertain Phrases:**
- Line 18: | **Bootloader** | `models-fusegtw-GW_R7.img` | 94 KB | Power Architecture Book-E MCU (MPC55xx/SPC5x

**Sample Evidence:**
- Line 52: **Base Address:** `0x40000000` (execution starts at reset vector)
- Line 56: 0x0000: 48 00 00 40    b 0x40          ; Branch to init
- Line 57: 0x0004: 57 8c d9 14    rlwinm r12,r12,27,4,10


### 52a-decompile-summary.md

**Quality:** ✅ VERIFIED (Score: 90/100)

**Statistics:**
- Lines: 351
- Uncertain phrases: 0
- Evidence markers: 27
- Memory addresses: 19
- Citations: 0
- Code blocks: 12

**Sample Evidence:**
- Line 12: ### 1. ✅ Extract Firmware Strings
- Line 14: **Extracted:** 491 strings from bootloader firmware
- Line 17: - "Factory gate succeeded" (0x0FC4)


### 52b-gateway-command-flow.md

**Quality:** ✅ VERIFIED (Score: 90/100)

**Statistics:**
- Lines: 389
- Uncertain phrases: 0
- Evidence markers: 15
- Memory addresses: 15
- Citations: 0
- Code blocks: 6

**Sample Evidence:**
- Line 69: │  (0x40005E34)  │         │   (varies)      │
- Line 88: │            Handler: factory_gate_trigger (0x400053BC)            │
- Line 91: │      uint32_t *pos = (uint32_t*)0x40016000;                     │

---

## PRIORITY RE-ANALYSIS LIST


### CRITICAL (❌ UNTESTED)

- **03-certificate-recovery-orphan-cars.md** - 22 uncertain, 2 evidence
- **04-network-ports-firewall.md** - 2 uncertain, 0 evidence
- **07-usb-map-installation.md** - 0 uncertain, 0 evidence
- **08-key-programming-vcsec.md** - 0 uncertain, 0 evidence
- **09-gateway-sdcard-log-analysis.md** - 3 uncertain, 0 evidence
- **11-vcsec-keycard-routines.md** - 0 uncertain, 0 evidence
- **14-offline-update-practical-guide.md** - 1 uncertain, 0 evidence
- **23-certificate-chain-analysis.md** - 18 uncertain, 17 evidence
- **39-attack-tree-diagram.md** - 1 uncertain, 0 evidence
- **44-mcu-networking-enhanced.md** - 0 uncertain, 0 evidence
- **48-hardware-architecture.md** - 17 uncertain, 3 evidence
- **55-gateway-spc-chip-replacement.md** - 6 uncertain, 0 evidence
- **QUICK_REFERENCE_NETWORK.md** - 1 uncertain, 0 evidence
- **TASK_COMPLETION_REPORT.md** - 0 uncertain, 0 evidence
- **VERIFICATION-STATUS.md** - 16 uncertain, 7 evidence

### MEDIUM (🔍 NEEDS RE-ANALYSIS)

- **02-gateway-can-flood-exploit.md** - 0 uncertain, 1 evidence
- **06-usb-firmware-update.md** - 1 uncertain, 2 evidence
- **18-cid-iris-update-pipeline.md** - 4 uncertain, 4 evidence
- **28-can-flood-refined-timing.md** - 0 uncertain, 2 evidence
- **32-log-exfiltration-data-mining.md** - 0 uncertain, 3 evidence
- **34-chromium-analysis-checklist.md** - 1 uncertain, 2 evidence
- **39-INDEX.md** - 1 uncertain, 3 evidence
- **43-ape-network-services.md** - 7 uncertain, 7 evidence
- **44-mcu-networking-deep-dive.md** - 7 uncertain, 4 evidence
- **ANALYSIS-COMPLETION-REPORT.md** - 0 uncertain, 4 evidence
- **PRACTICAL-EXPLOIT-GUIDE-COMPLETION.md** - 0 uncertain, 1 evidence
- **README.md** - 0 uncertain, 2 evidence
- **TASK-research-status-tracker-COMPLETE.md** - 3 uncertain, 3 evidence

### LOW (⚠️ INFERRED)

- **00-master-cross-reference.md** - Needs source citations
- **01-ui-decompilation-service-factory.md** - Needs source citations
- **05-gap-analysis-missing-pieces.md** - Needs source citations
- **12-gateway-bootloader-analysis.md** - Needs source citations
- **15-updater-component-inventory.md** - Needs source citations
- **20-service-mode-authentication.md** - Needs source citations
- **21-gateway-heartbeat-failsafe.md** - Needs source citations
- **24-vcsec-key-programming-summary.md** - Needs source citations
- **24-vcsec-key-programming.md** - Needs source citations
- **31-apparmor-sandbox-security.md** - Needs source citations
- **33-can-protocol-reverse-engineering.md** - Needs source citations
- **34-chromium-webkit-attack-surface.md** - Needs source citations
- **36-gateway-sx-updater-reversing.md** - Needs source citations
- **37-doip-gateway-reversing.md** - Needs source citations
- **38-gateway-firmware-analysis-COMPLETE.md** - Needs source citations
- **38-gateway-firmware-analysis.md** - Needs source citations
- **39-qtcarserver-security-audit-SUMMARY.md** - Needs source citations
- **40-INDEX.md** - Needs source citations
- **40-ape-extraction-summary.md** - Needs source citations
- **40-ape-firmware-extraction.md** - Needs source citations
- **41-ape-factory-calibration.md** - Needs source citations
- **49-modem-iris-tillit-analysis.md** - Needs source citations
- **50-gateway-udp-config-protocol-SUMMARY.md** - Needs source citations
- **50-gateway-udp-config-protocol.md** - Needs source citations
- **54-gateway-spc-architecture.md** - Needs source citations
- **RESEARCH-STATUS.md** - Needs source citations
- **TASK-COMPLETION-CHECKLIST.md** - Needs source citations
- **TASK-zen-component-analysis-COMPLETE.md** - Needs source citations

---

## CORRECTION TASKS


### Documents Needing Complete Re-Analysis

- [ ] 03-certificate-recovery-orphan-cars.md - Re-analyze with firmware binaries
- [ ] 04-network-ports-firewall.md - Re-analyze with firmware binaries
- [ ] 07-usb-map-installation.md - Re-analyze with firmware binaries
- [ ] 08-key-programming-vcsec.md - Re-analyze with firmware binaries
- [ ] 09-gateway-sdcard-log-analysis.md - Re-analyze with firmware binaries
- [ ] 11-vcsec-keycard-routines.md - Re-analyze with firmware binaries
- [ ] 14-offline-update-practical-guide.md - Re-analyze with firmware binaries
- [ ] 23-certificate-chain-analysis.md - Re-analyze with firmware binaries
- [ ] 39-attack-tree-diagram.md - Re-analyze with firmware binaries
- [ ] 44-mcu-networking-enhanced.md - Re-analyze with firmware binaries

### Documents Needing Source Citations

- [ ] 01-ui-decompilation-service-factory.md - Add specific binary/file sources
- [ ] 05-gap-analysis-missing-pieces.md - Add specific binary/file sources
- [ ] 12-gateway-bootloader-analysis.md - Add specific binary/file sources
- [ ] 15-updater-component-inventory.md - Add specific binary/file sources
- [ ] 20-service-mode-authentication.md - Add specific binary/file sources
- [ ] 24-vcsec-key-programming-summary.md - Add specific binary/file sources
- [ ] 24-vcsec-key-programming.md - Add specific binary/file sources

### Hypotheses Ready for Verification

- [ ] Cross-reference with available firmware dumps
- [ ] Verify CAN message IDs with actual captures
- [ ] Test exploit code in safe environment
- [ ] Validate memory addresses with disassembly