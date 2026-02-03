# Gateway SD-Card Log Analysis - EXPANDED

**Source log:** `/research/_docx_1711.txt`  
**Status:** Comprehensive Analysis with Logging Infrastructure Mapping  
**Related:** See `32-log-exfiltration-data-mining.md` for complete MCU logging analysis  
**Date:** February 3, 2026

## Quick Stats

- Total parsed lines: 2070
- Config rows written: 92
- TFTP starts: 21
- Transfer completions: 21
- Map match entries: 120
- Duration: ~23 minutes (11:15:45 → 11:38:44)

## Highlighted Config IDs
- id=15 name=devSecurityLevel len=1 last_value=3 first=HPick 11:15:45.679 last=HPick 11:15:45.679
- id=29 name=autopilot len=1 last_value=4 first=HPick 11:15:45.679 last=HPick 11:15:45.679
- id=37 name=prodCodeKey len=32 last_value='??;?eL?tH????`?sn??????^n?h?~???' first=HPick 11:15:45.680 last=HPick 11:15:45.680
- id=38 name=prodCmdKey len=32 last_value='_????????????0&lt;????? ??^??K??(ng' first=HPick 11:15:45.680 last=HPick 11:15:45.680
- id=39 name=altCodeKey len=32 last_value='' first=HPick 11:15:45.680 last=HPick 11:15:45.680
- id=40 name=altCmdKey len=32 last_value='' first=HPick 11:15:45.685 last=HPick 11:15:45.685
- id=57 name=gatewayApplicationConfig len=16 last_value='????????????????' first=HPick 11:15:45.685 last=HPick 11:15:45.685
- id=59 name=dasHw len=1 last_value=4 first=HPick 11:15:45.685 last=HPick 11:15:45.685
- id=66 name=mapRegion len=1 last_value=0 first=HPick 11:15:45.691 last=HPick 11:15:45.691

## Timeline anchors
- UpdT0 11:15:45.046: UpdT0 Spawn Update Task "UpdT0"
- UpdT0 11:15:45.046: UpdT0 Spawn Update Task "UpdT0"
- HPick 11:15:45.708: HPick tftp src:gtw3/192/cbreaker.map dest:cbreaker.map, attempt #1
- lwipT 11:15:47.014: lwipT Two-pass update, beginning HWIDAcq phase
- lwipT 11:15:48.221: lwipT VC/EPB* Entered OTA state, 500 msec
- HPick 11:15:55.092: HPick Begin hwidacq for gtw3 [12], attempt #1, flags 0x3, override 0
- HPick 11:17:02.462: HPick Queuing gtw3 [12]
- lwipT 11:38:44.132: lwipT Update completed [0000].
- lwipT 11:38:44.142: lwipT Called from File: /firmware/components/gateway3/update/shared/hashpicker.c, LineNumber: 922: Rebooting ...

## Error keyword counts
- err: 68
- mismatch: 36
- error: 7
- refused: 2

## TFTP transfers
| timestamp | src → dest | attempt |
|---|---|---|
| HPick 11:15:45.708 | gtw3/192/cbreaker.map → cbreaker.map | 1 |
| HPick 11:15:45.772 | signed_metadata_map.tsv → map.tsv | 1 |
| HPick 11:15:58.992 | gtw3/191/gwapp.img → 000c | 1 |
| HPick 11:17:06.779 | vcleft/303/VCLEFT_ConfigID_303_crc_formatted_lithium-signed.bhx → 0010 | 1 |
| HPick 11:17:17.287 | vcright/302/VCRIGHT_ConfigID_302_crc_formatted_lithium-signed.bhx → 001a | 1 |
| HPick 11:17:29.125 | hvbms/7241/HVBMS_CONFIG_7241_CRCFormatted_lithium-signed.bhx → 0000 | 1 |
| HPick 11:17:50.179 | di/13248/DIF_32-97-1_Coriander_Unit_Perf_crc_lithium-signed.bhx → 0004 | 1 |
| HPick 11:17:55.310 | di/13251/DIREL_32-98-0_Coriander_Unit_Perf_crc_lithium-signed.bhx → 0057 | 1 |
| HPick 11:18:00.905 | di/13254/DIRER_32-99-0_Coriander_Unit_Perf_crc_lithium-signed.bhx → 0058 | 1 |
| HPick 11:18:12.514 | vcseat1/21/VCSEAT1_ConfigID_21_crc_formatted_lithium-signed.bhx → 0054 | 1 |
| HPick 11:18:17.171 | vcseat1/21/VCSEAT1_ConfigID_21_crc_formatted_lithium-signed.bhx → 0055 | 1 |
| HPick 11:19:01.366 | vcsec/13/subcomponent-id_103_vcsecramapp_lithium-signed.bhx → 002e | 1 |
| HPick 11:19:02.169 | vcsec/13/VCSEC_ConfigID_13_crc_formatted_lithium-signed.bhx → 001c | 1 |
| HPick 11:19:26.107 | bleep/21/BLEEP_ConfigID_21_crc_formated.bhx → 002f | 1 |
| HPick 11:19:34.456 | bleep/21/BLEEP_ConfigID_21_crc_formated.bhx → 0030 | 1 |
| HPick 11:19:43.254 | bleep/21/BLEEP_ConfigID_21_crc_formated.bhx → 0031 | 1 |
| HPick 11:19:53.187 | bleep/21/BLEEP_ConfigID_21_crc_formated.bhx → 0032 | 1 |
| HPick 11:20:03.569 | bleep/23/BLEEP_ConfigID_23_crc_formated.bhx → 0033 | 1 |
| HPick 11:20:18.401 | bleep/21/BLEEP_ConfigID_21_crc_formated.bhx → 0034 | 1 |
| HPick 11:20:26.557 | bleep/21/BLEEP_ConfigID_21_crc_formated.bhx → 0035 | 1 |
| HPick 11:20:33.002 | bleep/21/BLEEP_ConfigID_21_crc_formated.bhx → 0036 | 1 |

## Transfer completions (sample)
- HPick 11:15:45.761: gtw3/192/cbreaker.map
- HPick 11:15:46.910: signed_metadata_map.tsv
- HPick 11:16:55.282: gtw3/191/gwapp.img
- HPick 11:17:14.812: vcleft/303/VCLEFT_ConfigID_303_crc_formatted_lithium-signed.bhx
- HPick 11:17:26.388: vcright/302/VCRIGHT_ConfigID_302_crc_formatted_lithium-signed.bhx
- HPick 11:17:41.331: hvbms/7241/HVBMS_CONFIG_7241_CRCFormatted_lithium-signed.bhx
- HPick 11:17:52.905: di/13248/DIF_32-97-1_Coriander_Unit_Perf_crc_lithium-signed.bhx
- HPick 11:17:58.474: di/13251/DIREL_32-98-0_Coriander_Unit_Perf_crc_lithium-signed.bhx
- HPick 11:18:03.716: di/13254/DIRER_32-99-0_Coriander_Unit_Perf_crc_lithium-signed.bhx
- HPick 11:18:15.223: vcseat1/21/VCSEAT1_ConfigID_21_crc_formatted_lithium-signed.bhx

## Map matches (sample)
- HPick 11:17:02.462: 1 line(s) with gtw3:10 in map file
- HPick 11:17:03.298: 1 line(s) with vcbatt:1056964608 in map file
- HPick 11:17:04.098: 1 line(s) with lvbms:16842753 in map file
- HPick 11:17:05.471: 1 line(s) with vcfront:1056964608 in map file
- HPick 11:17:15.899: 1 line(s) with vcleft:1056964608 in map file
- HPick 11:17:27.667: 3 line(s) with vcright:1040187392 in map file
- HPick 11:17:43.018: 3 line(s) with hvbms:117571625 in map file
- HPick 11:17:43.778: 1 line(s) with hvp:117571625 in map file
- HPick 11:17:44.390: 4 line(s) with pcs:100859905 in map file
- HPick 11:17:44.947: 3 line(s) with cp:220069889 in map file

---

## Gateway Log Collection Infrastructure

### Storage Location

**SD Card Mount:** `/mnt/mmcblk0p1/` (on Gateway ECU)

**Files Stored:**

```
/mnt/mmcblk0p1/
├── bootlog.<timestamp>      # Gateway boot sequence (this log)
├── gwapp.log               # Gateway application logs
├── update_<version>.log    # OTA update session logs
├── cbreaker.map            # Circuit breaker configuration
└── signed_metadata_map.tsv # Firmware metadata & signatures
```

### Remote Access via Hermes

**Retrieval Script:** `/usr/local/bin/hermes-grablogs-gw`

```bash
#!/bin/sh
LOG_PATH=$1
OUTPUT_DIR=$2

/usr/local/bin/gwxfer gw:"$LOG_PATH" "$OUTPUT"
```

**Tesla Backend Can:**

- Request any file from Gateway SD card via WSS (Hermes)
- Pull logs remotely without physical access
- Example: `gwxfer gw:"/mnt/mmcblk0p1/bootlog.*" /tmp/output/`

### Log Rotation

**Gateway Logging Daemon:** `gtw-logger` service

**Firewall Rule:** `/etc/firewall.d/gtw-logger.iptables` (allows UDP logging from gateway)

**AppArmor Sandboxing:** `/etc/kafel/gtw-logger.kafel`

**Rotation Policy:**

- Not svlogd-based (embedded system on Gateway)
- Likely size-based rotation with limited history
- SD card capacity constrains retention (typically 1-4GB cards)

### PII & Sensitive Data in Gateway Logs

**Exposed Information:**

| Data Type | Evidence | Privacy Risk |
|-----------|----------|--------------|
| **VIN** | Not visible in sample but likely in full logs | High - Unique identifier |
| **Security Keys** | `prodCodeKey`, `prodCmdKey` (32 bytes each) | Critical - Firmware signing |
| **Hardware Config** | Config IDs 15, 29, 59, 66 | Medium - Vehicle fingerprinting |
| **Map Region** | Config ID 66 = 0 (likely North America) | Low - Coarse location |
| **Update History** | TFTP transfer log, firmware versions | Medium - Diagnostic tracking |
| **ECU Versions** | Component firmware versions (vcsec, hvbms, etc.) | Medium - Hardware inventory |

**Security Key Rotation Events:**

```
id=37 name=prodCodeKey len=32 last_value='<binary>'
id=38 name=prodCmdKey len=32 last_value='<binary>'
id=39 name=altCodeKey len=32 last_value=''
id=40 name=altCmdKey len=32 last_value=''
```

These logs capture cryptographic key updates during OTA, which could reveal:

- Key rotation schedules
- Compromise response events (emergency key updates)
- Dual-signing key infrastructure (prod vs. alt keys)

### Local Parsing Opportunities

**Parser Script:** `/research/scripts/parse_gateway_sd_log.py`

**Extractable Data:**

1. **OTA Update Timeline:**
   - Start time, end time, total duration
   - Component-by-component update order
   - TFTP transfer speeds (file size / transfer duration)

2. **ECU Inventory:**
   - List of all ECUs updated (gtw3, vcsec, hvbms, bleep, etc.)
   - Firmware version deployed to each
   - Config IDs and their values

3. **Error Analysis:**
   - Error keywords: "err" (68), "mismatch" (36), "error" (7), "refused" (2)
   - Identify problematic components or network issues
   - Diagnose failed updates

4. **Security Events:**
   - Key rotation timing
   - Signature verification outcomes
   - Security level changes (config ID 15)

**Example Python Analysis:**

```python
import re
from collections import defaultdict

# Parse TFTP transfers to build update timeline
tftp_pattern = re.compile(r'HPick (\d{2}:\d{2}:\d{2}\.\d+): .* tftp src:(.+?) dest:(.+?),')
transfers = defaultdict(list)

for line in log_lines:
    match = tftp_pattern.search(line)
    if match:
        time, src, dest = match.groups()
        transfers[src.split('/')[0]].append({
            'time': time,
            'component': src.split('/')[0],
            'version': src.split('/')[1] if '/' in src else 'unknown',
            'file': src,
            'target_ecu': dest
        })

# Identify slowest transfers (potential network issues)
for component, files in transfers.items():
    print(f"{component}: {len(files)} files transferred")
```

### Integration with MCU Logging

**Cross-ECU Log Correlation:**

1. **MCU Side:** `/var/log/updater-envoy/current`, `/var/log/gadget-updater/current`
2. **Gateway Side:** SD card bootlog, gwapp.log
3. **Correlation Key:** Timestamp, update version

**Complete Update Picture:**

- MCU initiates update (updater-envoy log)
- Gateway receives command, begins TFTP downloads (bootlog)
- Gateway updates sub-ECUs (bootlog TFTP transfers)
- MCU receives completion status (updater-envoy log)
- Both sides' logs uploaded to Tesla via Hermes

**Privacy Implication:** Tesla has synchronized multi-ECU logs for every update, enabling detailed vehicle behavior analysis.

---

## Advanced Analysis

### Update Orchestration Flow

```
11:15:45 - Update task spawned (UpdT0)
11:15:47 - Two-pass update begins (HWID acquisition phase)
11:15:48 - VC/EPB enter OTA state
11:15:55 - Gateway HWID acquisition starts
11:17:02 - Gateway queued for update
  └─ 11:17:06-11:20:33 - Sub-ECU updates (vcsec, hvbms, bleep, etc.)
11:38:44 - Update completed
11:38:44 - Gateway reboots
```

**Total Duration:** 23 minutes  
**TFTP Phase:** ~3.5 minutes (11:17:06 → 11:20:33)  
**Post-TFTP Processing:** ~18 minutes (verification, installation, reboot prep)

### Component Update Order

1. **Circuit Breaker Map** (metadata)
2. **Signed Metadata Map** (signature verification data)
3. **Gateway Application** (gtw3/191/gwapp.img)
4. **Body Controllers:** vcleft, vcright (Model 3/Y body control modules)
5. **Battery Management:** hvbms (High Voltage BMS)
6. **Drive Inverters:** DIF, DIREL, DIRER (front, rear-left, rear-right)
7. **Seats:** vcseat1 (seat controllers)
8. **Security:** vcsec (vehicle security controller, including keycard handling)
9. **BLEEP Controllers:** bleep (tire pressure monitoring or similar)

**Observation:** Critical safety systems (BMS, inverters) updated mid-sequence, not first or last. Could indicate phased rollback capability.

### Security Implications

**Cryptographic Key Logging:**

The gateway logs expose firmware signing keys (or their hashes/IDs) during updates. If an attacker:

1. Extracts SD card from gateway
2. Analyzes bootlogs for key rotation events
3. Correlates with known firmware versions

They could potentially:

- Identify when security keys were rotated (incident response timing)
- Map which keys sign which firmware versions
- Identify "alt" key slots (backup signing infrastructure)

**Mitigation:** Tesla should encrypt gateway SD card logs or store keys in secure element without logging.

### Log Exfiltration Timeline

**Local Storage:**

- Gateway SD card: Immediate (live logging)
- MCU `/var/log/`: Real-time (svlogd)

**Remote Upload:**

- `hermes_eventlogs`: 1-hour aggregation intervals
- `hermes_historylogs`: 31-day rolling window, uploaded periodically
- `hermes_grablogs`: On-demand (Tesla can request anytime)

**Worst-Case Scenario:**

- Gateway logs uploaded within hours of update completion
- MCU logs uploaded in near real-time if high-priority events flagged
- Tesla has complete multi-ECU update audit trail within 24 hours

---

## Comparison to MCU Logging

| Aspect | Gateway (SD Card) | MCU (Hermes) |
|--------|-------------------|--------------|
| **Storage** | Local SD card | `/var/log/` + upload queues |
| **Daemon** | Custom embedded logger | svlogd + Hermes Go binaries |
| **Rotation** | Size-based (limited space) | Size + time-based (svlogd) |
| **Upload** | Remote pull via gwxfer | Push via hermes_eventlogs/historylogs |
| **Retention** | SD card capacity (~1-4GB) | 31+ days local, indefinite cloud |
| **Accessibility** | Requires shell + gwxfer or physical access | Remote via Hermes WSS |
| **PII** | VIN, hardware config, keys | VIN, GPS, shell history, CAN data, more |

**Conclusion:** Gateway logs are less privacy-invasive (focused on firmware/hardware) but contain critical security data (signing keys). MCU logs are more comprehensive and privacy-invasive.

---

## Recommendations

### For Researchers

1. **Parse Gateway SD Logs:**
   - Extract key rotation events
   - Build ECU firmware version database
   - Identify update failure patterns

2. **Correlate with MCU Logs:**
   - Match timestamps between gateway bootlog and `/var/log/updater-envoy/`
   - Reconstruct complete update flow

3. **Monitor gwxfer Activity:**
   - Audit when Tesla requests gateway logs remotely
   - Identify triggering conditions (failed updates, diagnostics)

### For Privacy Advocates

1. **Demand SD Card Encryption:**
   - Gateway logs contain security keys (should be encrypted at rest)

2. **Limit Remote Access:**
   - gwxfer should require user consent via UI

3. **Transparent Log Retention:**
   - Tesla should disclose how long gateway logs are kept in cloud

### For Security Researchers

1. **Analyze Key Rotation:**
   - Study `prodCodeKey` / `prodCmdKey` update patterns
   - Identify backup key infrastructure (`altCodeKey` / `altCmdKey`)

2. **Exploit Research:**
   - Can SD card be extracted and modified (log injection)?
   - Can gwxfer be spoofed (MITM attack on log retrieval)?

3. **Firmware Signature Validation:**
   - Extract firmware from TFTP logs
   - Validate signatures with logged keys (if extractable)

---

**Document Updated:** February 3, 2026  
**See Also:** `32-log-exfiltration-data-mining.md` for complete Tesla logging analysis
