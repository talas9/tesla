# Tesla Gateway Diagnostic Tool (`gw-diag`) Command Reference

**Status**: 27 command usages extracted from Odin service scripts  
**Date**: 2026-02-03  
**Source**: Model 3/Y firmware Odin bundle (2,988 Python scripts)

---

## Binary Information

**Location**: `/usr/sbin/gw-diag`  
**User**: root (requires root privileges)  
**Whitelist Chars**: `_` (underscore allowed in args)

---

## Command Categories

### 1. Config Read/Write Operations

#### GET_CONFIG_DATA (Read Config)
**Format**: `gw-diag GET_CONFIG_DATA 00 <CONFIG_ID_HEX>`

**Purpose**: Read Gateway configuration value  
**Authentication**: **NONE REQUIRED** (UDP:3500 accessible configs)

**Examples**:
```bash
# Read DAS hardware config (0x003B = 59)
gw-diag GET_CONFIG_DATA 00 59
# Output: "01 00 3B 03" or "01 00 3B 04" (HW2.5 vs HW3)

# Read thermal config (0x0055 = 85)
gw-diag GET_CONFIG_DATA 00 85
# Output: "01 00 55 00" (legacy) or "01 00 55 01" (heat pump)

# Read map region (0x0014 = 20)
gw-diag GET_CONFIG_DATA 00 14

# Read BMP watchdog status (0x003D = 61)
gw-diag GET_CONFIG_DATA 00 61
```

**Response Format**:
```
<STATUS> <CONFIG_ID_MSB> <CONFIG_ID_LSB> <DATA_BYTES...>
```
- `STATUS`: `01` = success, `00` = failure
- Config ID echoed back in big-endian
- Data bytes follow (variable length)

**Known Config IDs**:
- `0` (VIN) - 17 bytes ASCII
- `6` (Country code) - 2 bytes ASCII
- `15` (Factory mode) - 1 byte (3=factory, 2=gated)
- `20` (Map region) - variable
- `59` (DAS hardware) - 1 byte (3=HW2.5, 4=HW3)
- `61` (BMP watchdog) - 1 byte boolean
- `81` (Delivery status) - 1 byte boolean
- `85` (Thermal config) - 1 byte (0=legacy, 1=heat pump)
- `199` (TCU config type) - 1 byte

#### SET_CONFIG_DATA (Write Config)
**Format**: `gw-diag SET_CONFIG_DATA 00 <CONFIG_ID> <DATA_HEX_BYTES>`

**Purpose**: Write Gateway configuration value  
**Authentication**: **FACTORY MODE REQUIRED** (or Hermes auth for secure configs)

**Examples**:
```bash
# Enter factory mode (config 15 = 0x0F)
gw-diag SET_CONFIG_DATA 0 15 3

# Exit factory mode
gw-diag SET_CONFIG_DATA 0 15 2

# Set delivery status to delivered (config 81 = 0x51)
gw-diag SET_CONFIG_DATA 0 81 1

# Set delivery status to undelivered
gw-diag SET_CONFIG_DATA 0 81 0

# Disable BMP watchdog (config 61 = 0x3D)
gw-diag SET_CONFIG_DATA 0 61 0

# Enable BMP watchdog
gw-diag SET_CONFIG_DATA 0 61 1
```

**Response Format**:
```
<STATUS> <ERROR_CODE>
```
- `01` = success
- `00` = failure, followed by error code:
  - `02` = bad command length
  - `04` = not in factory mode
  - `10` = level not supported

#### REFRESH_CONFIG_MSG (Apply Changes)
**Format**: `gw-diag REFRESH_CONFIG_MSG [IGNORE_FLAGS]`

**Purpose**: Apply config changes to Gateway without full reboot  
**Authentication**: Varies by config

**Options**:
```bash
# Standard refresh
gw-diag REFRESH_CONFIG_MSG

# Ignore power state checks (0x02 flag)
gw-diag REFRESH_CONFIG_MSG 02
```

**Response Codes**:
- `01` = success
- `00` + error code:
  - `02` = EPB fault or not parked
  - `04` = Vehicle power state = DRIVE
  - `08` = Brake pedal pressed

**Use Case**: After `SET_CONFIG_DATA`, call this to apply without rebooting Gateway

---

### 2. Gateway Control

#### GET_VERSION_INFO
**Format**: `gw-diag GET_VERSION_INFO`

**Purpose**: Read Gateway firmware version and hardware info  
**Authentication**: None

**Output**: Version string, part number, firmware hash

#### REBOOT (Gateway Reboot)
**Format**: `gw-diag REBOOT -f 0xde 0xad 0xbe 0xef`

**Purpose**: Reboot Gateway controller  
**Magic Bytes**: `0xDE 0xAD 0xBE 0xEF` (DEADBEEF)  
**Timeout**: 5 seconds (from Odin script)

**Response**:
- Exit status `1` = success (Gateway rebooting)
- Empty stdout/stderr = normal operation

**Safety Check**: Used in `SAFE_REBOOT_GTW.py` with verification:
1. Check stdout/stderr are empty
2. Verify exit status = 1
3. Wait for Gateway to come back online (loop with `GET_VERSION_INFO`)

#### OVERRIDE_DIAG_LEVEL (Bypass Security)
**Format**: `gw-diag OVERRIDE_DIAG_LEVEL <LEVEL> <MSB_TIMEOUT> <LSB_TIMEOUT>`

**Purpose**: Override Gateway diagnostic level for limited time  
**Authentication**: Factory mode required

**Diagnostic Levels**:
```python
FACTORY            = 0    # Full access
DIAG_LINK_ACTIVE   = 10   # Service mode active
SERVICE            = 25   # Service technician access
SERVICE_DRIVE      = 50   # Service with vehicle in drive
PARK               = 80   # Parked vehicle
NORMAL_OPERATION   = 100  # Normal user mode
```

**Timeout Calculation**:
```python
seconds = MSB * 256 + LSB
# Example: 5 minutes = 300 seconds
# MSB = 300 // 256 = 1
# LSB = 300 % 256 = 44
```

**Response**:
- `01` + `00` = success
- `01` + `08` = success, but duration reduced to max allowed
- `00` + error code:
  - `02` = bad command length
  - `04` = not in factory mode
  - `10` = level not supported

**Use Case**: Remote Odin service can temporarily elevate diag level without factory mode hardware

---

### 3. SD Card Operations

#### 0x10, 0x63, 0x3a, 0x20, 0x2f, 0x79 (Format SD Card)
**Format**: `gw-diag 0x10 0x63 0x3a 0x20 0x2f 0x79`

**Purpose**: Request SD card reformat  
**Context**: From `ICE_INFO_FORMAT-SD-CARD.py`

**Response**:
- `01` + data = reformat requested successfully
- `00` + data = reformat request failed

**Safety**: Script checks for SD card alerts (`alert_data` contains "sdcard" or "logwrite") before running

---

### 4. Autopilot System (APS) Commands

#### 0x37 (Disable APS)
**Format**: `gw-diag 0x37`

**Purpose**: Disable Autopilot Parking System  
**Context**: From `PROC_INFOZ_X_DISABLE-APS.py`

**Response**:
- `00` = APS disabled successfully
- `01` = APS already disabled
- `02` = Failed to disable APS

**Use Case**: Before certain service operations that require APS to be powered down

---

### 5. Hardware-Specific Commands

#### 0x43 (DRMOS Mitigation)
**Format**: `gw-diag 0x43 0x1`

**Purpose**: Apply AMD Ryzen DRMOS voltage mitigation  
**Context**: From `PROC_INFOZ_X_DRMOS-MITIGATION.py`  
**Applies To**: Ryzen MCU vehicles only

**Response Codes**:
- `00` = Mitigation applied successfully
- `01` = Mitigation not needed (previously applied)
- `02` = ICE not awake
- `03` = SVI2 controller register read failed
- `04` = SVI2 controller register write failed
- `05` = SVI2 controller registers write-protected
- `06` = SVI2 controller NVM write-protected
- `07` = Failed when writing to SVI2 controller NVM

**Critical**: AMD DRMOS power delivery issue fix, permanent hardware mitigation

#### 0x60 (Power Cycle TCU)
**Format**: `gw-diag 0x60 0x1`

**Purpose**: 12V power cycle the TCU (Telematics Control Unit / modem)  
**Context**: From `PROC_ICE_X_REMOTE-SET-CONFIGS.py`

**Use Case**: Attempt to recover connectivity if WiFi/cellular fails after config changes

#### 56 (Override EPAS Power - MonoCam/HW1)
**Format**: `gw-diag 56`

**Purpose**: Override EPAS (steering) power signal  
**Applies To**: DAS MonoCam (HW1) vehicles only  
**Context**: From `PROC_EPAS_ESP_CLEAR-ANGLE-OFFSETS.py`

**Response**:
- `0` in stdout[1] = success
- Non-zero = failure

**Use Case**: Required before clearing EPAS angle offsets on older vehicles

#### 68 (DAS Ethernet Link Test)
**Format**: `gw-diag 68 <LINK_INDEX>`

**Purpose**: Test APE-MCU Ethernet connectivity  
**Context**: From `PROC_INFOZ_X_DAS-ETH-CONNECTIVITY.py`

**Link Index**:
- `0` = All links (restore default routing)
- `1` = APE-MCU primary link (Black Jumper)
- `2` = APE-MCU secondary link (White Jumper)

**Response Format**:
```
<STATUS> <LINK1_STATUS> <LINK2_STATUS>
```
- `01` = command succeeded
- `00` = command failed
- Link status bytes: `bit 0 = link up/down` (odd = up, even = down)

**Use Case**: Diagnose Ethernet connectivity issues between Autopilot computer and MCU

---

### 6. OTA Update Support

#### OTA_KEEP_AWAKE
**Format**: `gw-diag OTA_KEEP_AWAKE <STATE>`

**Purpose**: Keep Gateway awake during OTA firmware updates  
**Context**: From `UPDATE_TCU.py`

**States**:
- `0` = disable keep-awake (allow normal sleep)
- `1` (implied) = enable keep-awake

**Response**:
- `01` in stdout = success

**Use Case**: TCU modem updates need Gateway to stay powered during install/fuse process

---

## Command Pattern Analysis

### UDP API Commands (Hex Format)
Commands using hex values (e.g., `0x37`, `0x43`, `0x60`) appear to be **UDP API command IDs** matching the Gateway UDP protocol (port 1050).

**Discovered UDP Command IDs**:
- `0x10` = Unknown (SD card related)
- `0x37` = Disable APS
- `0x43` = DRMOS mitigation
- `0x60` = Power cycle TCU
- `0x63` = SD card format (part of multi-byte sequence)
- `0x68` = DAS Ethernet link test

### ASCII Commands
Commands using string names (e.g., `GET_CONFIG_DATA`, `REBOOT`) are **high-level diagnostic functions** likely implemented as wrappers around UDP API.

---

## Security Model

### No Authentication Required
- `GET_CONFIG_DATA` (read-only configs)
- `GET_VERSION_INFO`
- `68` (DAS Ethernet test)

### Factory Mode Required
- `SET_CONFIG_DATA` (config writes)
- `OVERRIDE_DIAG_LEVEL`

### Implicit Auth (Hermes/Mothership)
- Config writes for secure fields (VIN, country, paid features) require remote Hermes auth even in factory mode

---

## Scripts Using `gw-diag`

**Total Found**: 27 usages across Odin service bundle

**Key Scripts**:
1. `PROC_EPAS_ESP_CLEAR-ANGLE-OFFSETS.py` - EPAS power override
2. `ICE_GATEWAY_SAFE_REBOOT.py` - Safe Gateway reboot routine
3. `DAS_SELF_TEST.py` - DAS hardware config check
4. `ICE_INFO_FORMAT-SD-CARD.py` - SD card reformat
5. `ICE_INFO_READ-GW-CONFIGS.py` - Batch config reading
6. `ICE_GTW_REFRESH_CONFIG_MSG.py` - Config refresh wrapper
7. `TEST_GTW_ENABLE-BMP-WATCHDOG.py` - BMP watchdog toggle
8. `PROC_ICE_X_SAFE-SET-VEHICLE-CONFIGS.py` - Safe config write with validation
9. `PROC_ICE_X_SOFT-FUSE.py` - Factory → production soft-fusing
10. `PROC_INFOZ_X_DISABLE-APS.py` - APS disable for service
11. `PROC_INFOZ_X_DRMOS-MITIGATION.py` - AMD voltage fix
12. `PROC_INFOZ_X_DAS-ETH-CONNECTIVITY.py` - Ethernet diagnostics
13. `UPDATE_TCU.py` - Modem firmware update
14. `PROC_ICE_X_REMOTE-SET-CONFIGS.py` - Remote config writing
15. `PROC_CID_X_OVERRIDE-DIAG-LEVEL.py` - Diagnostic level override

---

## Reverse Engineering Notes

### Config ID Format
- Decimal in Python code: `config_id = 81`
- Hex in gw-diag: `gw-diag GET_CONFIG_DATA 00 51`
- Big-endian in Gateway binary: `0x0051`

### Timeout Parameters
Multi-byte timeouts use MSB/LSB encoding:
```python
timeout_seconds = MSB * 256 + LSB
```

### Response Parsing
Scripts check multiple response fields:
```python
result = execute_application(path='/usr/sbin/gw-diag', args=[...])
exit_status = result['exit_status']  # 0 = success, 1 = failed
stdout = result['stdout'].strip()    # Command output
stderr = result['stderr']             # Errors
```

---

## Testing Safety

**WARNING**: These commands interact directly with critical vehicle systems.

**Safe to Test** (read-only):
- `GET_CONFIG_DATA`
- `GET_VERSION_INFO`

**DANGEROUS** (write operations):
- `SET_CONFIG_DATA` - Can brick Gateway or cause vehicle malfunction
- `REBOOT` - Power cycles Gateway (vehicle may lose functionality temporarily)
- `OVERRIDE_DIAG_LEVEL` - Security bypass
- `0x37`, `0x43`, `0x60` - Hardware control commands

**DO NOT TEST** without understanding implications and having recovery tools ready.

---

## Related Documents

- [81-gateway-secure-configs-CRITICAL.md](81-gateway-secure-configs-CRITICAL.md) - Gateway security model
- [82-odin-routines-database-UNHASHED.md](82-odin-routines-database-UNHASHED.md) - Odin database with security flags
- [83-odin-config-api-analysis.md](83-odin-config-api-analysis.md) - Config read API discovery
- [36-gateway-udp-protocol-EXTRACTED.md](36-gateway-udp-protocol-EXTRACTED.md) - UDP protocol specification

---

**End of Document**
