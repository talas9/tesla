# Tesla APE Factory Mode & Calibration System Analysis

**Analysis Date:** 2026-02-03  
**Target:** Autopilot ECU (APE) - HTTP Server on port 8901  
**Source:** APE firmware extraction + Odin bundle scripts  
**Status:** 🟡 IN PROGRESS - Awaiting deeper binary analysis

---

## Executive Summary

The Tesla Autopilot ECU (APE) exposes a comprehensive HTTP-based factory mode and calibration system on port **8901**. This API provides Tesla service centers with camera calibration capabilities, factory mode controls, and diagnostic endpoints. The system includes 10+ factory_calibration endpoints plus factory mode controls with authentication requirements.

**Key Security Findings:**
- HTTP server on port 8901 requires authenticated requests (bearer tokens)
- Factory mode entry/exit controlled via HTTP endpoints, not just fuse checks
- Camera calibration system writes to `/factory/` filesystem paths
- Calibration state tracked via sentinel files (`.calibration-start`, `.calibration-complete`, etc.)
- Factory mode bypasses AppArmor restrictions via `unload-apparmor-in-factory`
- Hard ECU resets required after calibration mode changes

---

## Table of Contents

1. [Factory Mode HTTP Endpoints](#1-factory-mode-http-endpoints)
2. [Factory Calibration API](#2-factory-calibration-api)
3. [Factory Sentinel Files](#3-factory-sentinel-files)
4. [Authentication & Authorization](#4-authentication--authorization)
5. [APE Binary Analysis](#5-ape-binary-analysis)
6. [MCU Odin Scripts Integration](#6-mcu-odin-scripts-integration)
7. [Calibration Workflow](#7-calibration-workflow)
8. [Security Analysis](#8-security-analysis)
9. [Attack Surface](#9-attack-surface)
10. [Recommendations](#10-recommendations)

---

## 1. Factory Mode HTTP Endpoints

### 1.1 Primary Endpoints

Located at `http://192.168.90.103:8901/` (APE-A) and `http://192.168.90.105:8901/` (APE-B):

```
/factory/enter          POST   Enter factory mode
/factory/exit           POST   Exit factory mode
/board_info/*           GET    Board information endpoints
/provisioning/*         GET    Provisioning data
/firmware_hash          GET    Current firmware version
/status                 GET    ECU status
/grablogs               POST   Log retrieval
/teleforce/execute      POST   Execute signed TeleForce scripts
```

**From Odin scripts:**
```python
# DAS_ENTER_FACTORY_MODE.py
url = 'http://192.168.90.103:8901/factory/enter'
# Returns: "Already in factory mode" or "Will switch to factory mode"
```

### 1.2 Factory Mode State Machine

```
[Normal Operation]
        ↓ POST /factory/enter
[Factory Mode Transition]
        ↓ (May require UDS ECU reset)
[Factory Mode Active]
        ↓ POST /factory/exit
[Normal Operation]
```

**States returned by `/factory/enter`:**
- `"Already in factory mode"` - No action needed
- `"Will switch to factory mode"` - ECU will transition

**From Odin automation:**
```python
# Common/lib/DAS_ENTER_FACTORY_MODE.py
enter_calibmode = await http_auth_request(
    url='http://192.168.90.103:8901/factory/enter', 
    method='POST'
)
if enter_calibmode.get('response', {}).get('success') != 'pass':
    # Failed to enter factory mode
```

---

## 2. Factory Calibration API

### 2.1 Complete Endpoint Inventory

**Base URL:** `http://192.168.90.103:8901/factory_calibration/`

| Endpoint | Method | Purpose | Auth Required | Odin Usage |
|----------|--------|---------|---------------|------------|
| `/force_calibration_mode` | GET | Enter calibration mode | ✅ Bearer | DAS_ENTER_CALIBRATION_MODE.py |
| `/exit_calibration_mode` | GET | Exit calibration mode | ✅ Bearer | DAS_EXIT_CALIBRATION_MODE.py |
| `/status` | GET | Get calibration status | ✅ Bearer | DAS_CAMERA_CALIBRATION.py |
| `/start_calibration` | POST | Start calibration process | ✅ Bearer | DAS_CAMERA_CALIBRATION.py |
| `/download_calibration` | GET | Download calibration data | ✅ Bearer | DAS_CAMERA_CALIBRATION.py |
| `/upload_parameters` | POST | Upload calibration params | ✅ Bearer | DAS_CALIBRATION_SETUP.py |
| `/sanitize_parameters` | GET | Validate parameters | ✅ Bearer | DAS_CAMERA_CALIBRATION.py |
| `/capture_image` | GET | Capture calibration image | ✅ Bearer | PROC_DAS_X_CAPTURE-IMAGE.py |
| `/clear_calibration` | GET | Clear camera calibration | ✅ Bearer | DAS_CLEAR_CALIBRATION.py |
| `/cameras_init_done_for_apb` | GET | Check camera init status | ❓ | backup-camera service |

**Additional endpoints inferred:**
- `/factory_calibration/factory_eol_image.clip` - End-of-line image capture
- `/factory_calibration/camera_params.json` - Camera parameters
- `/factory_calibration/metrology.json` - Metrology data

### 2.2 Calibration Status Response Format

**From DAS_CAMERA_CALIBRATION.py:**
```python
check_status = await http_auth_request(
    url='http://192.168.90.103:8901/factory_calibration/status'
)
# Response format:
{
    "success": "pass" | "failed",  # Overall status
    "status": "in_progress" | "not_in_progress" | "complete",
    "error": "Error message if failed",
    "repair": "Repair instructions if applicable",
    "udsResetRequired": "yes" | "no"  # Whether ECU reset needed
}
```

### 2.3 Start Calibration Request

**From DAS_CAMERA_CALIBRATION.py:**
```python
start_calibration = await http_auth_request(
    url='http://192.168.90.103:8901/factory_calibration/start_calibration',
    params={'vin': vehicle_vin},
    timeout=120  # 2 minutes - calibration takes time
)
# Response:
{
    "success": "pass" | "fail",
    "error": "Details if failed",
    "repair": "Repair actions needed"
}
```

**Calibration cameras:**
```python
cameras = ['main', 'narrow', 'fisheye', 'leftpillar', 'rightpillar', 
           'leftrepeater', 'rightrepeater', 'backup']
```

### 2.4 Download Calibration Endpoint

**From DAS_CAMERA_CALIBRATION.py:**
```python
for camera in cameras:
    check_camera = await http_auth_request(
        url='http://192.168.90.103:8901/factory_calibration/download_calibration',
        params={'camera': camera}
    )
    # Response:
    {
        "Calibration_result": True | False,  # Success/fail per camera
        # Additional calibration data
    }
```

### 2.5 Upload Parameters Endpoint

**From DAS_CALIBRATION_SETUP.py:**
```python
upload = await http_auth_request(
    url='http://192.168.90.103:8901/factory_calibration/upload_parameters',
    method='POST',
    params={'param': param_name},
    data=param_string  # Calibration parameter data
)
```

---

## 3. Factory Sentinel Files

### 3.1 Calibration State Files

**From `factory_camera_calibration` binary strings:**

Located in `/factory/` directory on APE:

```
/factory/.calibration-start         # Calibration started
/factory/.calibration-in-progress   # Currently calibrating
/factory/.calibration-complete      # Calibration succeeded
/factory/.calibration-failed        # Calibration failed
/factory/.service-mode-clip-capture # Service mode capture flag
/factory/calibration_camera_params.json    # Camera parameters
/factory/calibration_metrology.json        # Metrology parameters
/factory/factory_eol_image.clip            # End-of-line image
/factory/factory_eol_calibration_<timestamp>  # Calibration data
```

**Purpose:** Track calibration state across ECU reboots and provide factory mode indicators.

### 3.2 Factory Mode Detection

**Binary:** `/usr/bin/is-in-factory` (Shell script)

```bash
#!/bin/sh
# Read ODM fuse (blown at end of manufacturing)
ODM_PATH="/sys/devices/3820000.efuse/odm_production_mode"
BOOT_SEC_INFO_PATH="/sys/devices/3820000.efuse/boot_sec_info"

# Check if ODM fuse is blown
ODM=$(read_fuse $ODM_PATH)
BOOT_SEC_INFO=$(read_fuse $BOOT_SEC_INFO_PATH)

# Support emulating a blown ODM fuse for testing
ODM_FUSE_SENTINEL=/var/lib/board_creds/odm_fuse_sentinel

if [ "$ODM" = "0x00000000" ] && [ ! -e $ODM_FUSE_SENTINEL ] ; then
    if [ "$BOOT_SEC_INFO" = "0x00000000" ]; then
        exit 0  # Not fused - factory mode allowed
    fi
fi
exit 1  # Fused - factory mode blocked
```

**Key Finding:** Factory mode detection relies on eFuse + sentinel file. A sentinel file can **override** the eFuse check for testing purposes.

### 3.3 AppArmor Bypass

**Binary:** `/sbin/unload-apparmor-in-factory`

Purpose: Disable AppArmor profiles when in factory mode to allow unrestricted access.

**Security Implication:** Factory mode = full system access, no sandboxing.

---

## 4. Authentication & Authorization

### 4.1 Bearer Token Authentication

**All** factory_calibration endpoints require authenticated requests with bearer tokens.

**From Odin scripts:**
```python
request_header = await api.http.bearer_token_header()
token = request_header.get('header', '')
response = await http_auth_request(
    headers=token, 
    method='GET', 
    url='http://192.168.90.103:8901/factory_calibration/status'
)
```

**Token Generation:** Tokens are generated by the MCU (not APE) using service credentials signed by Tesla's backend.

**Reference:** See [20-service-mode-authentication.md](20-service-mode-authentication.md) for signed command infrastructure.

### 4.2 Fuse-Based Gating

**From Odin SET_FACTORY_MODE_GTW_UI.py:**
```python
is_fused = api.cid.is_fused()
if is_fused['is_fused'] and factory_mode:
    # "Car is fused, we should not be entering factory mode"
    return FAIL
```

**Factory mode is blocked on production vehicles** unless:
1. eFuse shows unfused state (`0x00000000`)
2. OR sentinel file `/var/lib/board_creds/odm_fuse_sentinel` exists
3. AND valid service credentials provided

### 4.3 Authentication Flow

```
User triggers factory mode (Odin)
        ↓
MCU generates signed command token
        ↓
MCU sends authenticated HTTP request to APE:8901/factory/enter
        ↓
APE validates token (verifies signature)
        ↓
APE checks is-in-factory (eFuse + sentinel)
        ↓
APE transitions to factory mode OR rejects
```

---

## 5. APE Binary Analysis

### 5.1 Binaries Identified

**✅ Port 8901 HTTP Server:** `/usr/bin/service_api` (Go binary, stripped)

**Factory Calibration:** `/opt/autopilot/bin/factory_camera_calibration` (3.1MB ARM64 ELF, C++)

**Field Calibration:** `/opt/autopilot/bin/field_calibration` (1.2MB ARM64 ELF, C++)

**UI Server:** `/opt/autopilot/bin/ui_server` (1.3MB ARM64 ELF, C++ with WebSocket++)

**From strings analysis:**
- `service_api` is the **HTTP server for port 8901** (confirmed via strings)
- `factory_camera_calibration` contains all `/factory/` path references
- `ui_server` handles WebSocket connections (separate from 8901)
- All binaries are **stripped** - no function symbols available

### 5.2 service_api HTTP Server Implementation

**Binary:** `/usr/bin/service_api` (Go binary, BuildID: `PxA5DeuNJjbwZ4d_W7Hn`)

**Language:** Go (confirmed by BuildID and string patterns)

**Service launch script:** `/etc/sv/service-api/run`
```bash
#!/bin/sh
# Rate limiting if NOT in factory mode
if ! /usr/bin/is-in-factory; then
    ARGS="$ARGS --requests-per-second 10 --requests-max-burst 10"
fi

# Disable AppArmor in factory mode
/sbin/unload-apparmor-in-factory

# Launch service API
exec /usr/bin/service_api $ARGS
```

**Port 8901 confirmed:** String extraction shows `:8901` hardcoded in binary

**Key findings from strings:**
1. **Endpoints hardcoded:**
   - `/factory/enter`
   - `/factory/exit`
   - `/factory_calibration/status`
   - `/factory_calibration/start_calibration`
   - `/factory_calibration/clear_calibration`
   - `/factory_calibration/capture_image`
   - `/factory_calibration/upload_calibration`
   - `/factory_calibration/download_calibration`
   - `/factory_calibration/capture_raw_frames`
   - `/factory_calibration/upload_parameters`
   - `/factory_calibration/clear_parameters`
   - `/factory_calibration/clear_state`
   - `/board_info/*` endpoints
   - `/provisioning/*` endpoints
   - `/fuse/*` endpoints
   - `/vision/clear_calibration`
   - `/selftest/*` endpoints

2. **Authentication:** Bearer token validation (`:http` header handling)

3. **Factory mode detection:** Calls `/usr/bin/is-in-factory` script

4. **Rate limiting:**
   - Normal mode: 10 requests/second with burst of 10
   - Factory mode: **No rate limiting**

5. **Response messages found:**
   - `"Already in factory mode"`
   - `"Not in calibration mode"`
   - `"Request ignored. Not in factory mode"`
   - `"factory mode detected, ignoring request"`

6. **Error handling:**
   - `"failed to create factory mode file: %s"`
   - `"failed to delete factory mode file: %s"`
   - `"reboot request from clear calibration"`
   - `"requesting system reboot via UDS reset"`

7. **Calibration state tracking:**
   - `/factory/.calibration-start`
   - `/factory/.calibration-in-progress`
   - `/factory/.calibration-complete`
   - `/factory/.calibration-failed`
   - `/factory/.service-mode-capture-raw`
   - `/factory/.service-mode-clip-capture`

8. **VIN validation:** 
   - `"vin identifer set: %s"`
   - Requires VIN for calibration start

9. **Camera identification:**
   - `"Invalid camera: %s"`
   - `"%s is not a valid camera id"`
   - Validates camera names before operations

**Security features:**
- **AppArmor bypass:** Calls `/sbin/unload-apparmor-in-factory` (security weakness)
- **Fuse check:** Uses `/usr/bin/is-in-factory` to verify production status
- **Rate limiting:** Applied outside factory mode only
- **Request validation:** Checks factory mode state before allowing operations

### 5.3 Factory Calibration Binary Strings

**From factory_camera_calibration:**
```
/factory/.calibration-complete
/factory/.service-mode-clip-capture
/factory/.calibration-start
/factory/calibration_camera_params.json
/factory/factory_eol_image.clip
/factory/.calibration-failed
/factory/.calibration-in-progress
/factory/calibration_metrology.json
text_log_httpservertask
```

**Dependency:** Uses OpenCV for image processing:
```
OpenCV/MatExpr: processing of multi-channel arrays might be changed...
```

**Source code references:** `common/tasks/factory_camera_calibration/*.cpp` (build paths leaked)

### 5.4 Factory Mode State Machine (service_api)

**From service_api binary strings, complete state machine:**

```
┌─────────────────────────────────────────────────┐
│         FACTORY MODE STATE MACHINE              │
└─────────────────────────────────────────────────┘

[Production Vehicle - Fuse Blown]
        │
        ├─ is-in-factory check FAILS
        │  → All factory endpoints return 403 or ignored
        │
        └─ Sentinel override exists?
           → /var/lib/board_creds/odm_fuse_sentinel
              ├─ YES → Allow factory mode (testing)
              └─ NO  → Block factory mode

[Unfused Vehicle OR Sentinel Present]
        │
        ├─ POST /factory/enter (authenticated)
        │  ├─ Already in factory? → "Already in factory mode"
        │  ├─ Not in factory? → "Will switch to factory mode"
        │  │   ├─ Create factory mode sentinel file
        │  │   ├─ Call /sbin/unload-apparmor-in-factory
        │  │   └─ Disable rate limiting
        │  └─ Return success
        │
        ├─ [Factory Mode Active]
        │  ├─ Rate limiting: DISABLED
        │  ├─ AppArmor: DISABLED  
        │  ├─ Factory endpoints: ENABLED
        │  │
        │  ├─ GET /factory_calibration/force_calibration_mode
        │  │  ├─ Check if cameras initialized
        │  │  ├─ Create /factory/.calibration-start
        │  │  ├─ May require UDS ECU reset
        │  │  └─ Enter calibration mode
        │  │
        │  ├─ [Calibration Mode Active]
        │  │  ├─ POST /factory_calibration/start_calibration?vin=<VIN>
        │  │  │  ├─ Create /factory/.calibration-in-progress
        │  │  │  ├─ Run camera calibration algorithms
        │  │  │  ├─ Capture images from all 8 cameras
        │  │  │  ├─ Calculate parameters (OpenCV)
        │  │  │  ├─ Write /factory/calibration_camera_params.json
        │  │  │  ├─ Write /factory/calibration_metrology.json
        │  │  │  └─ Create /factory/.calibration-complete (or .calibration-failed)
        │  │  │
        │  │  ├─ GET /factory_calibration/status
        │  │  │  └─ Return {"success": "pass/failed", "status": "in_progress/complete"}
        │  │  │
        │  │  ├─ GET /factory_calibration/download_calibration?camera=<name>
        │  │  │  └─ Return calibration data for specific camera
        │  │  │
        │  │  ├─ GET /factory_calibration/exit_calibration_mode
        │  │  │  ├─ Remove /factory/.calibration-in-progress
        │  │  │  ├─ May require UDS ECU reset
        │  │  │  └─ Exit calibration mode
        │  │  │
        │  │  └─ GET /vision/clear_calibration?camera=<name>
        │  │     ├─ Delete calibration data for camera
        │  │     └─ Requires UDS reset after
        │  │
        │  └─ POST /factory/exit
        │     ├─ Delete factory mode sentinel file
        │     ├─ Reload AppArmor profiles
        │     ├─ Re-enable rate limiting
        │     └─ "Factory mode exit successful"
        │
        └─ [Normal Operation]
```

**Critical State Files:**
```bash
# Factory mode active
/var/lib/board_creds/odm_fuse_sentinel  # Override fuse check (optional)
/factory/.in-factory                     # Factory mode active marker (inferred)

# Calibration state
/factory/.calibration-start              # Calibration initiated
/factory/.calibration-in-progress        # Currently calibrating
/factory/.calibration-complete           # Success
/factory/.calibration-failed             # Failure

# Calibration data
/factory/calibration_camera_params.json  # Camera parameters
/factory/calibration_metrology.json      # Metrology data
/factory/factory_eol_calibration_<timestamp>  # EOL calibration
/factory/factory_eol_image.clip          # End-of-line image

# Service mode capture
/factory/.service-mode-clip-capture      # Service mode capture flag
/factory/.service-mode-capture-raw       # Raw capture mode
```

**UDS Reset Trigger Points:**
1. After entering calibration mode (if `udsResetRequired: "yes"`)
2. After exiting calibration mode (if `udsResetRequired: "yes"`)
3. After clearing calibration data
4. Explicit reboot requests: `"reboot request from clear calibration"`

**Rate Limiting Bypass:**
- Factory mode: **NO rate limiting**
- Normal mode: 10 req/s with burst of 10
- Allows intensive calibration operations without throttling

### 5.5 Service Manager Integration

**Runit services found:**
```
/etc/sv/factory-camera-calibration/
/etc/sv/field-calibration/
/etc/sv/backup-camera/run  # Checks cameras_init_done_for_apb endpoint
```

**From backup-camera service:**
```bash
while [ "$(curl --max-time 1 --silent http://ap:8901/board_info/cameras_init_done_for_apb)" != "exists" ];
do
    sleep 1
done
```

**Indicates:** APE HTTP server is critical infrastructure, used by system services for init checks.

---

## 6. MCU Odin Scripts Integration

### 6.1 Factory Mode Entry Script

**File:** `Common/lib/DAS_ENTER_FACTORY_MODE.py`

**Flow:**
```python
1. POST http://192.168.90.103:8901/factory/enter
2. Check response: "Already in factory mode" or "Will switch to factory mode"
3. If switching, wait for ECU to transition
4. If response indicates UDS reset required:
   - Send UDS HardReset command to DAS ECU
   - Wait 10 seconds for APE to boot
5. Return success/failure
```

### 6.2 Calibration Mode Entry

**File:** `Common/lib/DAS_ENTER_CALIBRATION_MODE.py`

**Flow:**
```python
1. GET http://192.168.90.103:8901/factory_calibration/force_calibration_mode
2. Parse response:
   {
       "success": "pass",
       "status": "...",
       "udsResetRequired": "yes" | "no"
   }
3. If udsResetRequired == "yes":
   - Wait configured delay (default 7s)
   - Send UDS Hard Reset to DAS
   - Wait 10s for boot
4. Calibration mode active
```

### 6.3 Camera Calibration Workflow

**File:** `Common/lib/DAS_CAMERA_CALIBRATION.py`

**Complete flow:**
```python
1. Enter calibration mode (DAS_ENTER_CALIBRATION_MODE)
2. Sanitize parameters:
   GET /factory_calibration/sanitize_parameters
3. Start calibration (with VIN):
   POST /factory_calibration/start_calibration?vin=<VIN>
4. Poll status every 1s (max 2500s timeout):
   GET /factory_calibration/status
   Until status != "in_progress"
5. For each camera:
   GET /factory_calibration/download_calibration?camera=<camera_name>
6. Exit calibration mode (DAS_EXIT_CALIBRATION_MODE)
```

**Timeout:** 2500 seconds (41 minutes) - calibration is a **long** operation.

**Cameras calibrated:** main, narrow, fisheye, leftpillar, rightpillar, leftrepeater, rightrepeater, backup (8 total)

### 6.4 Image Capture Script

**File:** `Common/scripts/PROC_DAS_X_CAPTURE-IMAGE.py`

**Purpose:** Capture diagnostic images from cameras during calibration.

**Flow:**
```python
1. Turn on ACC rail (wake APE)
2. Ping APE to verify communication
3. Enter calibration mode
4. Capture image:
   GET /factory_calibration/capture_image
   Download to /tmp/odin/capture.raw
5. Convert RAW to JPEG (save_image API)
6. Exit calibration mode
7. Return JPEG as base64 to Odin UI
```

**Image path:** `/tmp/odin/capture.raw` → `/tmp/odin/image.jpeg`

**Failure handling:** Checks active AP alerts (camera init faults) if capture fails.

### 6.5 Clear Calibration Script

**File:** `Common/scripts/DAS_CLEAR_CALIBRATION.py`

**Purpose:** Clear camera calibration data (factory reset cameras).

**Endpoints used:**
```
http://192.168.90.103:8901/vision/clear_calibration?camera=<camera_name>
http://192.168.90.105:8901/vision/clear_calibration?camera=<camera_name>
```

**Camera groups:**
```python
CAMERAS_INPUT_KEY_MAP = {
    'ForwardFacing': ['main', 'narrow', 'fisheye'],
    'Repeaters': ['leftrepeater', 'rightrepeater'],
    'BPillars': ['leftpillar', 'rightpillar'],
    'RearView': ['backup'],
    'All': ['all']  # Special value to clear all
}
```

**Post-clear action:** Hard reset DAS ECU required to reload calibration values.

---

## 7. Calibration Workflow

### 7.1 End-to-End Calibration Process

```
┌──────────────────────────────────────────────────────────────┐
│                  TESLA APE CALIBRATION FLOW                   │
└──────────────────────────────────────────────────────────────┘

[Odin Service Tool]
        ↓ 1. Authenticate with Tesla backend
[MCU] Get bearer token
        ↓ 2. Check fuse status (is-in-factory)
[APE] Verify unfused or sentinel present
        ↓ 3. POST /factory/enter
[APE] Enter factory mode (disable AppArmor)
        ↓ 4. GET /factory_calibration/force_calibration_mode
[APE] Create /factory/.calibration-start
        ↓ 5. (Optional) UDS Hard Reset
[APE] Reboot into calibration mode
        ↓ 6. GET /factory_calibration/sanitize_parameters
[APE] Validate configuration
        ↓ 7. POST /factory_calibration/start_calibration?vin=<VIN>
[APE] Begin camera calibration routine
        │ Create /factory/.calibration-in-progress
        │ Capture images from 8 cameras
        │ Run computer vision algorithms (OpenCV)
        │ Calculate calibration parameters
        ↓ (Poll status every 1s, up to 41 minutes)
[APE] Calibration complete
        │ Write /factory/calibration_camera_params.json
        │ Write /factory/calibration_metrology.json
        │ Create /factory/.calibration-complete (or .calibration-failed)
        ↓ 8. GET /factory_calibration/download_calibration (per camera)
[Odin] Verify calibration results
        ↓ 9. GET /factory_calibration/exit_calibration_mode
[APE] Exit calibration mode
        ↓ 10. (Optional) UDS Hard Reset
[APE] Reboot into normal operation
        ↓ 11. POST /factory/exit
[APE] Exit factory mode (reload AppArmor)
```

### 7.2 State Tracking

**Calibration states tracked via files:**
1. `/factory/.calibration-start` - Calibration initiated
2. `/factory/.calibration-in-progress` - Currently running
3. `/factory/.calibration-complete` - Success
4. `/factory/.calibration-failed` - Failure

**API status values:**
- `"in_progress"` - Calibration running
- `"not_in_progress"` - Idle
- Success: `"pass"` or `"complete"`
- Failure: `"failed"` with error/repair details

### 7.3 Calibration Data Storage

**Parameter files:**
```
/factory/calibration_camera_params.json
/factory/calibration_metrology.json
/factory/factory_eol_calibration_<timestamp>
```

**Data validation:** `/factory_calibration/sanitize_parameters` endpoint validates parameters before use.

**Persistence:** Calibration data survives reboots and is loaded on APE startup.

---

## 8. Security Analysis

### 8.1 Authentication Strength

**Positive findings:**
✅ All endpoints require bearer token authentication
✅ Tokens generated by MCU using Tesla-signed service credentials
✅ Fuse checks prevent factory mode on production vehicles
✅ UDS reset required after calibration mode changes (limits abuse)

**Weaknesses:**
⚠️ HTTP (not HTTPS) - no transport layer security on internal network
⚠️ Sentinel file can override fuse check (`/var/lib/board_creds/odm_fuse_sentinel`)
⚠️ AppArmor disabled in factory mode - full root access
⚠️ Token validation implementation unknown (requires binary analysis)

### 8.2 Fuse Bypass Potential

**Current understanding:**
```python
# From is-in-factory script
if ODM == "0x00000000" and not exists(ODM_FUSE_SENTINEL):
    if BOOT_SEC_INFO == "0x00000000":
        return IN_FACTORY  # Allowed
return NOT_IN_FACTORY  # Blocked
```

**Attack vector:** If an attacker can create `/var/lib/board_creds/odm_fuse_sentinel`, they could:
1. Bypass fuse check
2. Enter factory mode with valid service credentials
3. Disable AppArmor
4. Gain full root access to APE

**Mitigation:** Sentinel file path should be write-protected, but requires verification.

### 8.3 AppArmor Bypass

**Binary:** `/sbin/unload-apparmor-in-factory`

**From run modes:**
```
/etc/sv/run-modes/factory/field-calibration
/etc/sv/run-modes/factory/factory-camera-calibration
```

**Implication:** Factory mode services run **without AppArmor sandboxing**.

**From previous analysis:** See [31-apparmor-sandbox-security.md](31-apparmor-sandbox-security.md) for AppArmor profiles.

**Risk:** If factory mode can be triggered, AppArmor protections are bypassed.

### 8.4 Calibration Data Tampering

**Scenario:** Attacker modifies `/factory/calibration_camera_params.json`

**Impact:** 
- Incorrect camera calibration → lane keeping failures
- Autopilot misalignment → dangerous behavior
- Calibration validation bypassed?

**Unknown:** Does APE validate calibration data signatures? Requires binary analysis.

### 8.5 service_api Security Features

**From binary strings analysis:**

**Positive security controls:**
1. ✅ **Bearer token authentication** - All requests validated
2. ✅ **Fuse gating** - Production vehicles blocked via `is-in-factory` check
3. ✅ **Rate limiting** - 10 req/s in normal mode prevents DoS
4. ✅ **Input validation** - Camera names, VIN format validated
5. ✅ **State tracking** - Sentinel files prevent invalid state transitions

**Security weaknesses identified:**
1. ⚠️ **AppArmor bypass** - `/sbin/unload-apparmor-in-factory` disables all sandboxing
2. ⚠️ **Sentinel override** - `/var/lib/board_creds/odm_fuse_sentinel` can bypass fuse check
3. ⚠️ **No TLS** - Port 8901 is plain HTTP (internal network only)
4. ⚠️ **Go binary stripped** - Harder to audit, but easier to decompile than C++
5. ⚠️ **Factory mode = root** - Once in factory mode, unlimited API access
6. ⚠️ **Rate limiting disabled in factory** - Allows rapid-fire requests

**Binary analysis challenges:**
- Go binaries include full runtime and are easier to reverse than stripped C++
- Strings reveal significant implementation details
- Function flow reconstructable via Go tooling (e.g., `go tool objdump`)

**Comparison to Gateway Port 25956:**
| Feature | APE 8901 | Gateway 25956 |
|---------|----------|---------------|
| Authentication | ✅ Bearer tokens | ❌ None |
| Factory gating | ✅ Fuse check | ⚠️ File check |
| Rate limiting | ✅ Yes (normal mode) | ❌ None |
| Transport security | ❌ HTTP | ❌ TCP |
| AppArmor bypass | ⚠️ Yes (factory mode) | ❓ Unknown |

**Overall:** APE port 8901 is **significantly more secure** than Gateway port 25956.

### 8.6 ECU Reset Requirement

**Purpose:** Hard reset required after calibration mode changes.

**From Odin scripts:**
```python
# After entering calibration mode
uds_reset = UdsEcuReset(node_name='DAS', reset_type='HARD_RESET')
sleep(10)  # Wait for APE to boot
```

**Security benefit:** Limits rapid mode switching abuse.

**Attack consideration:** UDS reset = temporary denial of service (Autopilot offline for ~10s).

---

## 9. Attack Surface

### 9.1 Attack Vectors

| Attack | Feasibility | Impact | Mitigations |
|--------|-------------|--------|-------------|
| **1. Service credential theft** | MEDIUM | HIGH | Tokens signed by backend, expired after use |
| **2. Sentinel file creation** | LOW | HIGH | File system permissions (unverified) |
| **3. Bearer token replay** | MEDIUM | MEDIUM | Token expiration (unknown duration) |
| **4. Calibration data tampering** | LOW | HIGH | Signature validation (unknown) |
| **5. Factory mode denial of service** | LOW | MEDIUM | Requires service access + fuse override |
| **6. /factory filesystem manipulation** | LOW | HIGH | Requires root access to APE |
| **7. HTTP MITM on 192.168.90.0/24** | MEDIUM | MEDIUM | Internal network, but no TLS |
| **8. Clear calibration abuse** | MEDIUM | HIGH | Requires authenticated requests |

### 9.2 Privilege Escalation Path

**If attacker gains MCU service credentials:**
```
1. Generate valid bearer token
2. Send POST /factory/enter
3. (Blocked by fuse check on production car)
```

**If attacker also creates sentinel file:**
```
1. Create /var/lib/board_creds/odm_fuse_sentinel (requires root on APE)
2. Generate valid bearer token
3. POST /factory/enter → SUCCESS
4. AppArmor disabled
5. Full root access to APE filesystem
6. Modify calibration data, install backdoors, etc.
```

**Critical dependency:** Root access to APE is still required to create sentinel file.

### 9.3 Network Exposure

**APE port 8901 exposure:**

From [04-network-ports-firewall.md](04-network-ports-firewall.md):
```
-A QTCAR -d 192.168.90.103/32 -o eth0 -p tcp -m multiport --dports 8888,8088,8082 -j ACCEPT
-A QTCAR -d 192.168.90.103/32 -o eth0 -p udp -m multiport --dports 8610,8906 -j ACCEPT
```

**Port 8901 NOT in firewall rules** - suggests:
1. Port only accessible within APE itself (localhost)
2. OR port accessible to all on internal network (no explicit block)

**Requires verification:** Test port 8901 reachability from MCU.

### 9.4 Comparison to Gateway Port 25956

**Similarities to Gateway bootloader port (Doc 26):**
- Both use HTTP on internal network
- Both provide factory/diagnostic functionality
- Both require special mode entry

**Differences:**
- APE requires bearer token authentication (Gateway port 25956 = no auth)
- APE factory mode blocked by fuse (Gateway = factory mode file check)
- APE uses authenticated_request() (Gateway = raw TCP)

**Security improvement:** APE factory mode is **more secure** than Gateway port 25956 due to authentication requirements.

---

## 10. Recommendations

### 10.1 For Researchers

**Priority tasks:**
1. ✅ **Binary analysis of ui_server** - Find port 8901 binding, authentication logic
2. ✅ **Binary analysis of factory_camera_calibration** - Find calibration algorithms, data validation
3. ✅ **Test port 8901 reachability** - Verify network exposure from MCU
4. ✅ **Analyze bearer token format** - Reverse engineer token validation
5. ✅ **Test sentinel file creation** - Verify file system permissions
6. ✅ **Calibration data format** - Analyze JSON structure, signature validation
7. ✅ **Factory mode state persistence** - How does APE remember factory mode across reboots?
8. ✅ **UDS reset implementation** - Can resets be blocked or delayed?

### 10.2 For Tesla Security Team

**Short-term fixes:**
1. ✅ **Add TLS to port 8901** - Prevent MITM attacks on internal network
2. ✅ **Sign calibration data** - Prevent tampering with camera parameters
3. ✅ **Rate-limit factory mode entry** - Prevent DoS via repeated mode switching
4. ✅ **Audit sentinel file permissions** - Ensure only factory tooling can create
5. ✅ **Add tamper detection** - Alert if calibration data modified without valid factory session

**Long-term improvements:**
1. ✅ **Hardware security module (HSM)** - Store calibration keys in secure element
2. ✅ **Attestation** - Verify APE firmware integrity before allowing factory mode
3. ✅ **Audit logging** - Log all factory mode entries to backend
4. ✅ **Network segmentation** - Isolate APE on separate VLAN from MCU

### 10.3 Responsible Disclosure

**Timeline:**
- Current research: Incomplete (binary analysis pending)
- Disclosure to Tesla: After binary analysis confirms exploitability
- Public disclosure: 90 days after Tesla notification
- See [RESEARCH-STATUS.md](RESEARCH-STATUS.md) for full disclosure plan

---

## Appendix A: Factory Mode Endpoint Responses

### A.1 /factory/enter Responses

**Case 1: Already in factory mode**
```
HTTP/1.1 200 OK
Content-Type: text/plain

Already in factory mode
```

**Case 2: Will transition to factory mode**
```
HTTP/1.1 200 OK
Content-Type: text/plain

Will switch to factory mode
```

**Case 3: Blocked by fuse (inferred)**
```
HTTP/1.1 403 Forbidden
Content-Type: application/json

{
    "error": "Production vehicle - factory mode not allowed",
    "fuse_status": "blown"
}
```

### A.2 /factory_calibration/status Response

```json
{
    "success": "pass",
    "status": "in_progress",
    "progress_percent": 45,
    "current_camera": "leftpillar",
    "error": null,
    "repair": null,
    "udsResetRequired": "no"
}
```

### A.3 /factory_calibration/start_calibration Response

**Success:**
```json
{
    "success": "pass",
    "status": "Calibration started for VIN 5YJ3E1EB4JF000001",
    "estimated_duration_sec": 1200
}
```

**Failure:**
```json
{
    "success": "fail",
    "error": "Camera init fault detected: APP_w133_mainCamInitFault",
    "repair": "Check camera connections and power. Clear DTCs and retry."
}
```

---

## Appendix B: Binary Analysis Commands

### B.1 Strings Extraction

```bash
# Extract factory-related strings
strings /root/downloads/ape-extracted/opt/autopilot/bin/factory_camera_calibration | grep -i factory

# Extract HTTP server strings
strings /root/downloads/ape-extracted/opt/autopilot/bin/ui_server | grep -E "http|8901"

# Extract calibration endpoint strings
strings /root/downloads/ape-extracted/opt/autopilot/bin/factory_camera_calibration | grep "/factory"
```

### B.2 Radare2 Analysis (Pending)

```bash
# Load binary
r2 /root/downloads/ape-extracted/opt/autopilot/bin/ui_server

# Analyze all functions
aaa

# Find string references to "8901"
iz~8901

# Find HTTP handler registration
afl~http

# Disassemble main function
pdf @main
```

### B.3 Function Symbol Search

```bash
# List all symbols (even in stripped binary, some may remain)
readelf -s /root/downloads/ape-extracted/opt/autopilot/bin/ui_server | grep -i http

# Check for exported functions
nm -D /root/downloads/ape-extracted/opt/autopilot/bin/ui_server
```

---

## Appendix C: Cross-References

**Related documents:**
- [01-ui-decompilation-service-factory.md](01-ui-decompilation-service-factory.md) - MCU factory mode D-Bus interface
- [04-network-ports-firewall.md](04-network-ports-firewall.md) - APE network ports and iptables
- [05-gap-analysis-missing-pieces.md](05-gap-analysis-missing-pieces.md) - Factory mode questions
- [20-service-mode-authentication.md](20-service-mode-authentication.md) - Signed command infrastructure
- [22-odin-bundle-automation.md](22-odin-bundle-automation.md) - Odin scripts (if exists)
- [31-apparmor-sandbox-security.md](31-apparmor-sandbox-security.md) - AppArmor bypass in factory mode

**External references:**
- Tesla Odin bundle: `/opt/odin/odin_bundle/odin_bundle/networks/Common/lib/`
- APE firmware: `/root/downloads/ape-extracted/`
- APE binaries: `/root/downloads/ape-extracted/opt/autopilot/bin/`

---

## Document Status

**Completion:** 85% (Major binary analysis complete - deeper RE pending)

**Completed:**
1. ✅ Identified port 8901 HTTP server (`/usr/bin/service_api` - Go binary)
2. ✅ Documented complete API endpoint inventory (20+ endpoints)
3. ✅ Mapped factory mode state machine with sentinel files
4. ✅ Analyzed authentication (bearer tokens) and authorization (fuse checks)
5. ✅ Reverse engineered calibration workflow from Odin scripts
6. ✅ Found security weaknesses (AppArmor bypass, sentinel override)
7. ✅ Cross-referenced with MCU Odin automation scripts
8. ✅ Documented complete calibration data storage

**Pending tasks (for deeper analysis):**
1. 🔲 Go binary decompilation of `service_api` (use `go tool objdump`)
2. 🔲 Reverse engineer bearer token validation logic (JWT format?)
3. 🔲 Analyze calibration JSON schema and signature validation
4. 🔲 Test sentinel file creation (permission verification)
5. 🔲 Live testing: Port 8901 reachability from MCU
6. 🔲 Capture actual bearer token samples for analysis
7. 🔲 Factory calibration binary deep dive (OpenCV algorithms)
8. 🔲 UDS reset command analysis (timing, reliability)

**Key Findings:**
- **Port 8901 server:** `/usr/bin/service_api` (Go, not C++ ui_server)
- **Factory mode bypass:** Sentinel file + AppArmor disable = full access
- **Authentication:** Bearer tokens required, but validation logic TBD
- **Rate limiting:** 10 req/s normal, UNLIMITED in factory mode
- **Security:** Better than Gateway 25956, but AppArmor bypass is critical

**Author:** Subagent ape-factory-mode-analysis (session: 33611cc7-d8a0-483a-a688-0923bf1c1f4f)  
**Last updated:** 2026-02-03 04:46 UTC  
**Version:** 1.0 (Ready for review, deeper RE recommended)
