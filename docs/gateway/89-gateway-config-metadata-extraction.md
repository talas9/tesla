# Gateway Config Metadata Extraction

**Date:** 2026-02-03  
**Binary:** `ryzenfromtable.bin` (6,029,152 bytes, PowerPC MPC5748G firmware)  
**Status:** IN PROGRESS - Config indexing structures identified, full disassembly needed

---

## Executive Summary

Mohammed identified critical config metadata structures at the end of the Gateway binary that we had not yet analyzed. This document tracks the extraction of:

1. **Config name string table** (0x401150-0x401800)
2. **Config ID index array** (0x402400+)
3. **Config metadata structures** (location TBD via disassembly)
4. **Command dispatch table** (numeric opcodes → command names)

---

## Config Name String Table

**Location:** `0x401150` - `0x401800` (1,712 bytes)  
**Format:** Null-terminated ASCII strings  
**Count:** ~150 config parameter names

### Verified Config Names (First 50)

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

**Pattern:** Names are stored sequentially, null-terminated, with no padding between entries.

---

## Config ID Index Array

**Location:** `0x402400` - `0x402590` (400 bytes)  
**Format:** Array of 16-bit big-endian config IDs  
**Count:** 200 entries

### Config ID Array (Full List)

```
Index  Config ID (Hex)  Config ID (Dec)
-----  ---------------  ---------------
0      0x0125           293
1      0x0126           294
2      0x0127           295
3      0x0128           296
4      0x0129           297
5      0x012A           298
6      0x012B           299
7      0x012C           300
8      0x012D           301
9      0x012E           302
10     0x0130           304
11     0x0131           305
12     0x0132           306
13     0x0133           307
14     0x0134           308
15     0x0135           309
16     0x0136           310
17     0x0137           311
18     0x0139           313
19     0x013A           314
20     0x013B           315
21     0x013C           316
22     0x013D           317
23     0x013E           318
24     0x013F           319
25     0x0140           320
26     0x0142           322
27     0x0143           323
28     0x0144           324
29     0x0145           325
30     0x0146           326
31     0x0147           327
32     0x0148           328
33     0x0149           329
34     0x014B           331
35     0x014C           332
36     0x014D           333
37     0x014E           334
38     0x014F           335
39     0x0150           336
40     0x0151           337
41     0x0152           338
42     0x0154           340
43     0x0155           341
44     0x0156           342
45     0x0157           343
46     0x0158           344
47     0x0159           345
48     0x015A           346
49     0x015B           347
50     0x015C           348
... (200 total - saved in gateway_config_id_index.txt)
```

**Observations:**
- IDs are mostly sequential but have gaps (e.g., 0x012F missing, 0x0141 missing)
- Range: 0x0125 (293) to 0x02FB (763)
- This appears to be a **subset** of all possible configs (we've seen IDs as low as 0x0000)
- May represent a specific category (e.g., user-configurable parameters)

---

## Config Metadata Structure (Status: NOT YET FOUND)

**Expected format:**
```c
struct config_metadata {
    uint16_t config_id;        // 2 bytes, big-endian
    uint16_t flags;            // Access level, type info
    uint32_t name_offset;      // Offset to string in 0x401150 table (or direct pointer)
    uint8_t  default_length;   // Default value size
    uint8_t  default_value[N]; // Default value data
};
```

**Search results:**
- Scanned 0x400000-0x420000 range for struct arrays
- No direct pointers to 0x401150 string table found
- Strings may be referenced via **relative offsets** or **index numbers**
- Full PowerPC disassembly needed to locate access code

---

## Post-String-Table Data Structures

### Region 0x402000-0x403000: FreeRTOS Symbols
- Contains FreeRTOS task management function names
- vTaskPlaceOnEventListRestricted, xTaskRemoveFromEventList, etc.
- Not config-related

### Region 0x402400-0x402590: Config ID Array
- **200 config IDs** as documented above

### Region 0x402600-0x403E00: Structured Data
- Repeating patterns suggest struct arrays
- Example at 0x402600: `02 c3 02 c4 02 c5...` (likely IDs 0x02C3, 0x02C4, 0x02C5)
- Example at 0x403000: `00 05 48 70 00 00 00 10...` (mixed data, possibly CAN mailbox configs)

**HYPOTHESIS:** Multiple config index arrays exist for different subsystems:
- 0x402400: User-configurable parameters (0x0125-0x02FB)
- 0x402600: Higher-level configs (0x02C3-0x02E2)
- 0x403000+: CAN/network configurations

---

## Command Dispatch Table (Status: NOT FOUND IN STRINGS)

**Goal:** Map numeric opcodes to command names

**Known commands from Odin Python scripts:**
```python
GET_CONFIG_DATA       # Read config value
SET_CONFIG_DATA       # Write config value  
REFRESH_CONFIG_MSG    # Refresh config cache
REBOOT                # Reboot Gateway (magic bytes 0xDEADBEEF at 0x2C)
GET_VERSION_INFO      # Firmware version query
OVERRIDE_DIAG_LEVEL   # Change diagnostic access level
```

**UDP API commands (numeric):**
```
0x37 - Disable APS (Autopilot)
0x43 - DRMOS mitigation
0x60 - Power cycle TCU
0x68 - DAS Ethernet test
0x10 0x63 0x3a 0x20 0x2f 0x79 - Format SD card
```

**String search results:**
- Command names NOT found as plaintext in binary
- Likely stored as **numeric opcodes** in dispatch table
- Function pointer table at unknown address
- Need disassembly of UDP handler (`soc_udpcmds_task` at 0x401B8C)

---

## PowerPC Disassembly Attempt

**Tool:** `powerpc-linux-gnu-objdump`

**Command:**
```bash
powerpc-linux-gnu-objdump -D -m powerpc -b binary \
  --adjust-vma=0x00000000 ryzenfromtable.bin
```

**Issue:** Binary doesn't have ELF headers, so objdump doesn't know:
- Correct base address (likely 0x00000000 or flash-mapped address)
- Code vs data sections
- Entry point

**Next steps:**
1. Find actual base address from boot vector table
2. Identify .text section boundaries
3. Locate `soc_udpcmds_task` function (string at 0x401B8C)
4. Disassemble UDP command handler
5. Extract switch/jump table for command dispatch

---

## Related Structures Found

### FreeRTOS Tasks (Strings)
```
0x401B8C: soc_udpcmds_task      (UDP API handler, port 3500)
0x4018F8: gwXmit100Task
0x401908: gwXmit250Task  
0x401918: gwXmit1000Task
0x401928: gwXmit2000Task
0x401938: gwXmit10000Task
0x401E20: teleCANETHis_task     (CAN-Ethernet bridge)
0x401F44: dynTriggers_task      (Dynamic trigger API)
```

### Network Endpoints (Strings)
```
0x401D2F: Host: 192.168.90.100:20564  (MCU sx-updater endpoint)
0x401D10: GET /ice-wc-redeploy HTTP/1.1
0x401D50: GET /ice-wc3-redeploy HTTP/1.1  
0x401D90: GET /ice-umc-redeploy HTTP/1.1
```

### File Paths (Strings)
```
0x40186C: hrl/CUR.HRL           (Hardware revision log)
0x401880: hrl/%08x.hrl
0x401890: pseudo.hrl
0x40189C: udp.hrl
0x4018A4: gamemode.hrl
0x4018BC: ModelY                (Vehicle type)
```

---

## Next Steps

### Immediate (High Priority)
1. **Find PowerPC boot vector** (first 32 bytes of binary)
   - Determine correct base address for disassembly
2. **Disassemble UDP handler** (`soc_udpcmds_task`)
   - Locate command dispatch switch table
   - Map opcodes to function pointers
3. **Locate config metadata struct array**
   - Search for code that accesses 0x401150 string table
   - Find struct that links config_id → name → defaults

### Medium Priority
4. **Extract CAN mailbox config tables** (0x403000+ region)
5. **Analyze Gateway-MCU communication protocol** (192.168.90.100:20564)
6. **Map config ID gaps** (why 0x012F missing but 0x0130 present?)

### Long-term
7. **Full firmware disassembly** (6MB PowerPC code)
8. **Function boundary extraction** (PowerPC prologue/epilogue detection)
9. **Create complete config database** (ID → name → type → defaults → access level)

---

## Tool Development

### Created Files
- `gateway_config_id_index.txt` (200 config IDs, tab-separated)
- `gateway_config_names_hex.txt` (8KB hexdump of string table region)
- `gateway_strings_analysis.md` (Doc #88, 38,291 strings extracted)

### Tools Installed
- `binutils-powerpc-linux-gnu` (PowerPC disassembler)

### Scripts Needed
1. **Config name extractor:** Parse 0x401150 string table into JSON
2. **Config ID mapper:** Link IDs to names using disassembly
3. **Command opcode extractor:** Parse dispatch table from disassembly
4. **PowerPC function boundary detector:** Identify function prologues

---

## Evidence Quality

| Finding | Quality | Evidence |
|---------|---------|----------|
| Config name strings at 0x401150 | ✅ VERIFIED | Hexdump shows 150+ null-terminated ASCII names |
| Config ID array at 0x402400 | ✅ VERIFIED | 200 sequential 16-bit IDs (0x0125-0x02FB range) |
| Config metadata struct | ❌ NOT FOUND | No pointers to string table found yet |
| Command dispatch table | ❌ NOT FOUND | Command names not in strings, need disassembly |
| PowerPC base address | ⚠️ UNKNOWN | Need boot vector analysis |

---

## Cross-References

- **81-gateway-secure-configs-CRITICAL.md:** Two-tier security model (UDP vs Hermes auth)
- **82-odin-routines-database-UNHASHED.md:** Odin accessId → config mappings
- **83-odin-config-api-analysis.md:** Config read API (no auth required)
- **84-gw-diag-command-reference.md:** 27 Gateway diagnostic commands
- **88-gateway-strings-analysis.md:** 38,291 strings extracted from binary

---

## Contributor Notes

**Mohammed's guidance:**
> "the same binary contains more indexing about config at near the end of it if you check it"  
> "this binary is machine code and not encrypted and can be desassembled back into methods and other very valuable information!!!"

**Confirmed:** Binary is unencrypted PowerPC machine code, fully disassembleable. Config indexing structures exist but require proper disassembly to map relationships.

**Status:** Document created, partial analysis complete, full disassembly in progress.

---

*Last updated: 2026-02-03 07:09 UTC*
