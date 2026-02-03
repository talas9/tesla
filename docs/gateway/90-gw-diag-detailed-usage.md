# gw-diag Detailed Usage Analysis

**Date:** 2026-02-03  
**Source:** Odin Python scripts (2,988 files)  
**Status:** Complete command catalog with usage examples

---

## Summary

Analyzed all `gw-diag` command usages across the Odin service tool codebase. Documented complete parameter patterns, security contexts, and vehicle state requirements.

**Total files analyzed:** 27 Python scripts containing `gw-diag` calls  
**Commands cataloged:** 27 unique commands + UDP API opcodes

---

## Commands Found in Odin Scripts

### 1. GET_CONFIG_DATA
**Usage:**
```bash
/usr/sbin/gw-diag GET_CONFIG_DATA 00 <config_id>
```

**Examples from code:**
- `GET_CONFIG_DATA 00 59` - Read dasHardware config (determines HW2.5 vs HW3)
- `GET_CONFIG_DATA 00 61` - Read BMP watchdog enabled status
- `GET_CONFIG_DATA 00 81` - Read delivery status

**Files:** `ICE_INFO_READ-GW-CONFIGS.py`, `TEST_GTW_BMP-WATCHDOG-ENABLED.py`

---

### 2. SET_CONFIG_DATA
**Usage:**
```bash
/usr/sbin/gw-diag SET_CONFIG_DATA 00 <config_id> <value>
```

**Examples from code:**
- `SET_CONFIG_DATA 00 15 3` - Enter factory mode
- `SET_CONFIG_DATA 00 15 2` - Exit factory mode (enter factory-gated)
- `SET_CONFIG_DATA 00 81 1` - Mark vehicle as delivered
- `SET_CONFIG_DATA 00 81 0` - Mark vehicle as undelivered
- `SET_CONFIG_DATA 00 61 00` - Disable BMP watchdog

**Security:** Requires factory diag level for most configs (config 15, 81 are gated)

**Files:** `PROC_ICE_X_SOFT-FUSE.py`, `TEST_GTW_ENABLE-BMP-WATCHDOG.py`

---

### 3. REFRESH_CONFIG_MSG
**Usage:**
```bash
/usr/sbin/gw-diag REFRESH_CONFIG_MSG [flags]
```

**Flags:**
- No flag: Standard refresh (checks vehicle state)
- `02`: `IGNORE_POWER_STATE` - Skip power state checks

**Examples from code:**
```bash
/usr/sbin/gw-diag REFRESH_CONFIG_MSG 02  # Ignore power state
```

**Response codes:**
- `01` + `00`: Success
- `01` + `02`: EPB fault or not parked
- `01` + `04`: Vehicle power state = Drive
- `01` + `08`: Brake pedal pressed

**Files:** `ICE_GTW_REFRESH_CONFIG_MSG.py`, `PROC_ICE_X_SAFE-SET-VEHICLE-CONFIGS.py`

---

### 4. REBOOT
**Usage:**
```bash
/usr/sbin/gw-diag REBOOT -f 0xde 0xad 0xbe 0xef
```

**Magic bytes:** `0xDEADBEEF` (required for reboot command)

**Files:** `ICE_GATEWAY_SAFE_REBOOT.py`

---

### 5. GET_VERSION_INFO
**Usage:**
```bash
/usr/sbin/gw-diag GET_VERSION_INFO
```

**Purpose:** Check if Gateway is responsive (returns firmware version)

**Files:** `ICE_GATEWAY_SAFE_REBOOT.py`

---

### 6. OVERRIDE_DIAG_LEVEL
**Usage:**
```bash
/usr/sbin/gw-diag OVERRIDE_DIAG_LEVEL <level> <msb> <lsb>
```

**Diagnostic levels:**
- `0`: FACTORY
- `10`: DIAG_LINK_ACTIVE
- `25`: SERVICE
- `50`: SERVICE_DRIVE
- `80`: PARK
- `100`: NORMAL_OPERATION

**Duration:** `<msb><lsb>` = seconds in big-endian (e.g., msb=0, lsb=60 = 60 seconds)

**Response codes:**
- `01 00`: Success
- `01 08`: Success, but duration reduced to maximum allowed
- `00 02`: Bad command length
- `00 04`: Unable to override (vehicle not in factory mode)
- `00 10`: Level not supported

**Example from code:**
```python
minutes = 5
seconds = minutes * 60  # 300
msb = str(seconds // 256)  # "1"
lsb = str(seconds % 256)   # "44"
# Command: gw-diag OVERRIDE_DIAG_LEVEL 25 1 44
```

**Files:** `PROC_CID_X_OVERRIDE-DIAG-LEVEL.py`

---

### 7. OTA_KEEP_AWAKE
**Usage:**
```bash
/usr/sbin/gw-diag OTA_KEEP_AWAKE <0|1>
```

**Purpose:** Keep Gateway awake during OTA updates

**Files:** `UPDATE_TCU.py`, `MODULE_ECU-REPLACEMENT.py`

---

## UDP API Commands (Numeric Opcodes)

These commands use numeric opcodes instead of string names.

### 0x37 - Disable APS (Autopilot)
**Usage:**
```bash
/usr/sbin/gw-diag 0x37
```

**Response codes:**
- `00`: APS disabled successfully
- `01`: APS already disabled
- `02`: Failed to disable APS

**Files:** `PROC_INFOZ_X_DISABLE-APS.py`

---

### 0x43 - DRMOS Mitigation
**Usage:**
```bash
/usr/sbin/gw-diag 0x43 0x1
```

**Purpose:** Apply SVI2 controller mitigation for DRMOS (AMD Ryzen power issue)

**Response codes:**
- `00`: Mitigation applied successfully
- `01`: Mitigation not needed (previously applied)
- `02`: ICE not awake
- `03`: SVI2 controller register read failed
- `04`: SVI2 controller register write failed
- `05`: SVI2 controller registers write protected
- `06`: SVI2 controller NVM write protected
- `07`: Failed to write to SVI2 controller NVM

**Files:** `PROC_INFOZ_X_DRMOS-MITIGATION.py`

---

### 0x60 - Power Cycle TCU
**Usage:**
```bash
/usr/sbin/gw-diag 60 1
```

**Purpose:** 12V power cycle the TCU (Telematics Control Unit) via Gateway

**Files:** `UPDATE_TCU.py`

---

### 0x68 - DAS Ethernet Connectivity Test
**Usage:**
```bash
/usr/sbin/gw-diag 68 <link_index>
```

**Link indices:**
- `0`: Test all links (return to default config)
- `1`: APE-MCU primary link (Black Jumper)
- `2`: APE-MCU secondary link (White Jumper)

**Response format:**
`<success_flag> <link1_status> <link2_status>`

**Status bits:**
- Even (0, 2, 4...): Link down
- Odd (1, 3, 5...): Link up

**Example:**
```bash
$ gw-diag 68 1
01 01 00  # Success, primary up, secondary down
```

**Files:** `PROC_INFOZ_X_DAS-ETH-CONNECTIVITY.py`

---

### 0x10 0x63 0x3a 0x20 0x2f 0x79 - Format SD Card
**Usage:**
```bash
/usr/sbin/gw-diag 0x10 0x63 0x3a 0x20 0x2f 0x79
```

**Purpose:** Reformat Gateway SD card

**Response pattern:**
- `01.*` (regex): Success

**Files:** `ICE_INFO_FORMAT-SD-CARD.py`

---

## Code Patterns

### Typical Command Flow

```python
# 1. Keep ICE alive during operation
execute_node(path='/usr/local/bin/keep-ice-alive', args=['5', 'odin'])

# 2. Execute Gateway command
result = execute_node(
    path='/usr/sbin/gw-diag',
    args=['GET_CONFIG_DATA', '00', '59'],
    timeout=3
)

# 3. Parse response
stdout = result['stdout'].strip().split()
if result['exit_status'] == 0:
    config_value = stdout[-1]  # Last token is the value
```

### Retry Pattern

```python
RETRIES = 3
for _ in range(RETRIES):
    try:
        result = await execute_node(
            path='/usr/sbin/gw-diag',
            args=['0x43', '0x1'],
            timeout=3
        )
        return result
    except Exception as err:
        await sleep(2)
return False
```

---

## Security Context Requirements

### Factory Mode Required
Commands that need factory diag level:
- `SET_CONFIG_DATA 00 15` (change factory mode)
- `SET_CONFIG_DATA 00 81` (set delivery status)
- Config writes for secure configs (VIN, country, etc.)

### Checking Diag Level
```python
diag_level = await can_signal_read(signal_name='GTW_diagLevel')
if diag_level['value'] in ['LEVEL_SERVICE', 'LEVEL_DIAG_LINK_ACTIVE', 'LEVEL_FACTORY']:
    # Proceed with privileged operations
```

### Vehicle State Checks

**Before REFRESH_CONFIG_MSG:**
```python
shift_state = await get_data_value(data_name='VAPI_shiftState')
if shift_state['value'] not in ['P', '<invalid>']:
    # ERROR: Vehicle not in park
```

**Before Gateway Reboot:**
```python
drive_rail_on = await get_data_value(data_name='VAPI_driveRailOn')
if drive_rail_on['value'] == 'true':
    # ERROR: Drive rail active
```

---

## Related APIs

### CID Config API (CarServer/DBus)
Odin uses these APIs alongside `gw-diag`:

**Read config:**
```python
config = await api.cid.get_vehicle_configuration(access_id=199)
# Returns: {'configuration': 'value'}
```

**Write config (DBus):**
```python
result = await api.cid.set_vehicle_config(
    configid=81,
    data='01',
    signature='...'  # For signed configs
)
```

**Validate config changes:**
```python
validation = await api.cid.validate_vehicle_configs(config_params=[...])
if not validation['valid']:
    # Config change not allowed
```

---

## Cross-References

- **83-odin-config-api-analysis.md:** Config read API (get_vehicle_configuration)
- **84-gw-diag-command-reference.md:** Initial command catalog (superseded by this document)
- **81-gateway-secure-configs-CRITICAL.md:** Two-tier security model
- **88-gateway-strings-analysis.md:** Gateway firmware strings

---

*Last updated: 2026-02-03 07:09 UTC*
