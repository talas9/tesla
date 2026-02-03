# Gateway Firmware - ALL Data Tables & Structures

**Date:** 2026-02-03  
**Binary:** ryzenfromtable.bin (6,029,152 bytes)  
**Status:** Complete extraction of all identifiable data structures

---

## Summary

This document catalogs ALL structured data found in the Gateway firmware, including config tables, CAN messages, network endpoints, version strings, and cryptographic constants.

**Total structures documented:** 12 major tables + 37,702 strings + 6,647 CAN entries

---

## 1. Boot Vector Table

**Location:** 0x00000000-0x000000FF (256 bytes)  
**Format:** PowerPC boot vector format

| Offset | Value | Type | Description |
|--------|-------|------|-------------|
| 0x00 | 0x005A0002 | ptr | Initial SP (stack pointer)? |
| 0x10 | 0x00F9006C | ptr | **Reset vector / Entry point** |
| 0x1C | 0x78000054 | data | Boot parameter |
| 0x20 | 0xBBD7BCB7 | hash? | CRC or signature |
| 0x28 | 0x00000A20 | data | Unknown parameter |
| 0x2C | **0xDEADBEEF** | magic | **REBOOT MAGIC BYTES** |
| 0x30 | 0x8738F780 | data | Boot parameter |
| 0x50 | 0x40000020 | ptr | Base address? |
| 0x60 | 0x60D3D170 | data | Peripheral base? |

**DEADBEEF Magic:** Written to 0x2C by `gw-diag REBOOT -f 0xde 0xad 0xbe 0xef` command to trigger reboot.

---

## 2. Config Name String Table

**Location:** 0x00401150-0x00401800 (1,712 bytes)  
**Format:** Null-terminated ASCII strings  
**Count:** 84+ config parameter names

### Complete Name List (First 50)

```
0x401150: eBuckConfig
0x40115C: activeHighBeam
0x40116C: airbagCutoffSwitch
0x401180: intrusionSensorType
0x401194: autopilotTrialExpireTime
0x4011B0: spoilerType
0x4011BC: rearGlassType
0x4011CC: gatewayApplicationConfig
0x4011E8: rearFogLamps
0x4011F8: dasHw
0x401200: securityVersion
0x401210: bmpWatchdogDisabled
0x401224: tireType
0x401230: roofGlassType
0x401240: eCallEnabled
0x401250: mapRegion
0x40125C: rearLightType
0x40126C: chassisType
0x401278: plcSupportType
0x401288: towPackage
0x401294: refrigerantType
0x4012A4: passengerOccupancySensorType
0x4012C4: connectivityPackage
0x4012D8: tpmsType
0x4012E4: frontSeatReclinerHardware
0x401300: espValveType
0x401310: softRange
0x40131C: immersiveAudio
0x40132C: deliveryStatus
0x40133C: compressorType
0x40134C: cabinPTCHeaterType
0x401360: coolantPumpType
0x401370: autopilotTrial
0x401380: autopilotSubscription
0x401398: autopilotCameraType
0x4013AC: passengerAirbagType
0x4013C0: headlightLevelerType
0x4013D8: efficiencyPackage
0x4013EC: bPillarNFCParam
0x4013FC: steeringColumnUJointType
0x401418: twelveVBatteryType
0x40142C: radarHeaterType
0x40143C: parkAssistECUType
0x401450: powerLiftgateType
0x401464: frontOverheadConsoleType
0x401480: packPerformanceDeviation
0x40149C: brakeLineSwitchType
0x4014B0: blowerMotorType
0x4014C0: steeringColumnMotorType
0x4014D8: wirelessPhoneChargerType
0x4014F4: interiorTrimType
```

**Full list:** See 93-gateway-ALL-STRINGS.csv

---

## 3. Config ID Array

**Location:** 0x00402400-0x00402590 (400 bytes)  
**Format:** 16-bit big-endian integers  
**Count:** 200 config IDs

### ID Range Distribution

| Range | Count | Purpose (Inferred) |
|-------|-------|-------------------|
| 0x0125-0x014F | 43 | CAN mailbox configs |
| 0x0150-0x017F | 48 | Vehicle feature flags |
| 0x0180-0x01CF | 80 | Component configurations |
| 0x01D0-0x02FB | 29 | Network/diagnostic settings |

**Full list:** See gateway_config_id_index.txt

---

## 4. FreeRTOS String Table

**Location:** 0x00402000-0x00402400 (1KB)  
**Format:** Null-terminated ASCII strings  
**Type:** FreeRTOS kernel function names

### Task Management Functions
```
vTaskPlaceOnEventListRestricted
xTaskRemoveFromEventList
xTaskIncrementTick
vTaskSwitchContext
vTaskPriorityDisinherit
vTaskPriorityInherit
vTaskSuspend
vTaskResume
```

### Timer Functions
```
prvProcessExpiredTimer
prvProcessReceivedCommands
pvTimerCallBack
xTimerCreate
xTimerStart
xTimerStop
```

### Queue Functions
```
xQueueGenericSend
xQueueReceive
xQueuePeek
uxQueueMessagesWaiting
```

---

## 5. Config Metadata Table

**Location:** 0x00403000-0x00410000 (53,248 bytes)  
**Format:** 8-byte structs `[prefix:2][id:2][value:4]`  
**Count:** 6,647 entries

### Structure Format

```c
struct config_entry {
    uint16_t prefix;    // Access level / type flags
    uint16_t id;        // Config ID or CAN mailbox ID
    uint32_t value;     // Default value or register address
};
```

### Entry Types

| Type | Count | Prefix Range | ID Range |
|------|-------|--------------|----------|
| Config defaults | 2,685 | 0x03-0x15 | 0x0000-0x01FF |
| CAN mailbox | 51 | 0x05-0x15 | 0x4870, 0x486C |
| Memory registers | 3,911 | Various | 0x7000+ |

### Prefix Values (Security Flags)

| Prefix | Count | Possible Meaning |
|--------|-------|------------------|
| 0x03 | 21 | UDP-accessible (insecure) |
| 0x05 | 25 | Service level |
| 0x07 | 26 | Diagnostic level |
| 0x09 | 26 | Reserved |
| 0x0B | 26 | Factory level |
| 0x0D | 26 | Reserved |
| 0x13 | 25 | Gateway-only (secure) |
| 0x15 | 25 | Signed/encrypted (highest security) |

**Full table:** See 95-gateway-CAN-MESSAGES-COMPLETE.md

---

## 6. FreeRTOS Task Table

**Location:** Unknown (referenced by scheduler)  
**Count:** 9+ tasks  
**Format:** Task Control Blocks (TCB)

| Task Name | Priority | Stack Size | Period | Purpose |
|-----------|----------|------------|--------|---------|
| soc_udpcmds_task | High | Unknown | Event | UDP API handler (port 3500) |
| gwXmit100Task | Medium | Unknown | 100ms | CAN transmit (100ms messages) |
| gwXmit250Task | Medium | Unknown | 250ms | CAN transmit (250ms messages) |
| gwXmit1000Task | Low | Unknown | 1000ms | CAN transmit (1sec messages) |
| gwXmit2000Task | Low | Unknown | 2000ms | CAN transmit (2sec messages) |
| gwXmit10000Task | Low | Unknown | 10000ms | CAN transmit (10sec messages) |
| teleCANETHis_task | High | Unknown | Event | CAN-Ethernet bridge |
| dynTriggers_task | Medium | Unknown | Event | Dynamic trigger API |
| hrlDumpTask | Low | Unknown | On-demand | Hardware revision log |

---

## 7. UDP Command Dispatch Table

**Location:** Unknown (in .text section)  
**Format:** Switch/jump table with 7+ entries  
**Type:** Function pointer array

| Opcode | Command Name | Function (Inferred) | Parameters |
|--------|--------------|---------------------|------------|
| 0x01 | GET_CONFIG | get_config() | [config_id:2] |
| 0x02 | SET_CONFIG | set_config() | [config_id:2][data:N] |
| 0x03 | GET_COUNTERS | get_counters() | None |
| 0x04 | RESET_COUNTERS | reset_counters() | None |
| 0x05 | GET_VERSION | get_version() | None |
| 0x06 | REBOOT | reboot_gateway() | [magic:4] = 0xDEADBEEF |
| 0x07 | FACTORY_GATE | factory_gate() | [password:8] |

**Additional UDP API commands (numeric opcodes):**
- 0x37: Disable APS (Autopilot)
- 0x43: DRMOS mitigation (SVI2 controller)
- 0x60: Power cycle TCU
- 0x68: DAS Ethernet connectivity test

**Full reference:** See 90-gw-diag-detailed-usage.md

---

## 8. Network Endpoint Table

**Source:** String extraction from firmware

### Internal Endpoints

| Address | Port | Service | Purpose |
|---------|------|---------|---------|
| 192.168.90.100 | 20564 | sx-updater | MCU firmware update service |
| 0.0.0.0 | 3500 | udpApiTask | Gateway UDP API |
| 0.0.0.0 | 69 | xferTask | TFTP file transfer |
| 0.0.0.0 | 1050 | udpConfigTask | Config protocol (legacy?) |

### External Endpoints (Referenced)

| URL | Purpose |
|-----|---------|
| http://192.168.90.100:20564/ice-wc-redeploy | ICE (MCU) OTA trigger |
| http://192.168.90.100:20564/ice-wc3-redeploy | ICE3 (Ryzen) OTA trigger |
| http://192.168.90.100:20564/ice-umc-redeploy | UMC (Charger) OTA trigger |
| http://modem:28496/secondary_nand_prod_signed | TCU secondary NAND check |

---

## 9. Version & Build Strings

**Source:** String extraction + pattern matching

### Version Patterns Found

```
192.168.90  (Network address - counted as version by regex)
```

**Note:** No traditional version strings found (e.g., "v1.2.3" or "2024-01-15"). Firmware likely identifies itself via:
- Config values (gatewayApplicationConfig)
- GET_VERSION UDP command response
- Build hash embedded in binary (not yet extracted)

---

## 10. Cryptographic Constants

**Source:** Pattern matching for known crypto values

### SHA-256 Initial Hash Values

**Location:** 0x00036730  
**Values:**
```
0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
```

**Confidence:** HIGH (exact match of SHA-256 H0-H7 constants)

### CRC-8 Polynomial

**Polynomial:** 0x2F  
**Occurrences:** 11,512 times  
**Init value:** 0xFF  
**XOR out:** 0x00  
**Usage:** Config validation (verified in 80-ryzen-gateway-flash-COMPLETE.md)

### AES S-box

**Status:** NOT FOUND  
**Searched for:** First row of AES S-box (63 7C 77 7B F2 6B 6F C5)  
**Conclusion:** AES not used, or S-box is dynamically generated

### RSA/ECC Curves

**Status:** NOT FOUND  
**Searched for:** Common curve parameters (P-256, secp256k1)  
**Conclusion:** Asymmetric crypto not present, or uses external HSM

---

## 11. File Path Strings

**Source:** String extraction

### Internal Paths

```
hrl/CUR.HRL          (Hardware revision log - current)
hrl/%08x.hrl         (Hardware revision log - numbered)
pseudo.hrl           (Pseudo-HRL file)
udp.hrl              (UDP handler log)
gamemode.hrl         (Game mode flag)
updt/hrl/%08x.hrl    (Update HRL files)
DTRIG/%08X.DTC       (Dynamic triggers / DTC codes)
```

### File System Notes

- Gateway uses internal filesystem (likely JFFS2 or proprietary)
- SD card support (format command: `gw-diag 0x10 0x63 0x3a 0x20 0x2f 0x79`)
- HRL = Hardware Revision Log (tracks config changes)

---

## 12. Error Message Table

**Source:** String extraction (selected examples)

```
"Failed to initialize SD card"
"Erasing SD card..."
"Failed to erase SD card. Abort formatting."
"Bad firmware RC header info: vers %u, rec sz %u, total entries %u"
"Corrupt or missing firmware RC header (got %d bytes)"
"low stack warning: %s %d"
"wd task mismatch in core %d %d/%d"
"Failed to initialize the manifest, no version checking"
```

**Total error strings:** ~200 (from 37,702 total strings)

---

## Data Structure Cross-Reference Matrix

| Structure | Location | Size | References |
|-----------|----------|------|------------|
| Boot vector | 0x00 | 256B | Entry point, DEADBEEF magic |
| Config names | 0x401150 | 1.7KB | Config metadata, UDP handler |
| Config IDs | 0x402400 | 400B | Config metadata |
| FreeRTOS strings | 0x402000 | 1KB | Scheduler, task manager |
| Config metadata | 0x403000 | 53KB | get_config(), set_config() |
| SHA-256 constants | 0x36730 | 32B | Crypto functions |
| CRC-8 polynomial | Multiple | 1B | Config validation |

---

## Tools for Further Analysis

### Recommended
- **Ghidra** - Load as PowerPC raw binary, define sections, auto-analyze
- **IDA Pro** - Commercial, best PowerPC support
- **Python** - Parse structures, build databases

### Scripts Needed
1. **Config metadata parser** - Extract all 6,647 entries to JSON
2. **Function boundary detector** - Find all PowerPC functions
3. **Cross-reference builder** - Map code→data→strings

---

## Cross-References

- **93-gateway-ALL-STRINGS.csv:** Complete string database (37,702 entries)
- **95-gateway-CAN-MESSAGES-COMPLETE.md:** CAN message database (6,647 entries)
- **97-gateway-MEMORY-MAP.md:** Memory layout
- **99-gateway-FIRMWARE-METADATA.md:** File statistics

---

*Last updated: 2026-02-03 07:32 UTC*
