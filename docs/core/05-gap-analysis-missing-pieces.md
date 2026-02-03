# Tesla MCU2 Gap Analysis - Missing Pieces

**Date:** 2026-02-02
**Purpose:** Systematic search for answers to key questions about factory mode, service code, and MCU failsafe logic

---

## 1. "Service" Code Validation

### Search Results

**Password/code validation strings in binaries:**
- Found in `lib/libQtCarMediaApi.V2.so.1.0.0`:
  - `Cannot find media service payload with service key. Try auth. service-key:`
  - `active profile changed but auth token file does not exist. logging out of all services`
  - `logout because username & password invalid`
  - Related protobuf: `tesla.media.api.v1.rpcs.auth.ServiceLogout.service_account_key`
  - Related protobuf: `tesla.media.api.v1.rpcs.auth.LoginSuccess.service_account_key`

**Hash/CRC comparison search:**
- Found 3,036 potential 8-digit hex values in binaries
- **CRC32("service") = 0x63A888F9** - NOT FOUND in any binary
- Searched both endian variations: `63a888f9` and `f988a863` - no matches

### Key Finding: Service Mode Authentication Flow

From D-Bus interface strings found in UI binaries:
```
GUI_serviceModeAuth=
optional_signed_cmd_service_modeB
set_factory_mode
```

The authentication appears to use:
1. **Signed commands** - `optional_signed_cmd_service_mode`
2. **D-Bus method** - `set_factory_mode` method on vehicle interface
3. **GUI data values** - `GUI_serviceModeAuth` stores authentication state

### Service Mode Protection Layers

From strings analysis:
```
!Service unavailable in Valet Mode
&Feature disabled while in Service Mode
+Enable Service Mode Plus to start recording
-Vehicle must be parked to toggle Service Mode
4Vehicle alarm must be disarmed to enter Service Mode
```

**Conclusion:** The "service" code is NOT a simple hash comparison. It's part of Tesla's signed command infrastructure that validates against Tesla's backend servers.

---

## 2. Factory Mode D-Bus Caller

### Found: Factory Mode Entry Points

**Odin bundle files that invoke factory mode:**
- `opt/odin/odin_bundle/odin_bundle/networks/Common/scripts/SET_FACTORY_MODE_GTW_UI.py`
- `opt/odin/odin_bundle/odin_bundle/networks/Common/tasks/PROC_ICE_X_ENTER-FACTORY-MODE.py`
- `opt/odin/odin_bundle/odin_bundle/networks/Common/tasks/PROC_ICE_X_EXIT-FACTORY-MODE.py`
- `opt/odin/odin_bundle/odin_bundle/networks/ModelSX/lib/DAS_ENTER_FACTORY_MODE.py`
- `opt/odin/odin_bundle/odin_bundle/networks/ModelSX/lib/DAS_REBOOT_APE_A.py`

### Factory Mode Implementation (SET_FACTORY_MODE_GTW_UI.py)

```python
# Key code flow:
is_fused = api.cid.is_fused()
if is_fused['is_fused'] and factory_mode:
    # "Car is fused, we should not be entering factory mode"
    return FAIL

# Set GUI data value
dv_set = set_data_value(data_name='GUI_factoryMode', value='true'/'false')

# For Gen3+ vehicles:
config_set = set_config(configid=FACTORY_MODE_CONFIG, data=FACTORY_MODE_VALUE)
# FACTORY_MODE_CONFIG = '15'
# FACTORY_MODE_VALUE = '03' (enter) or '02' (exit)

# For Gen2 (Model S/X):
# Uses PROC_ICE_X_ACCESS-INTERNAL-DAT with:
# FACTORY_MODE_CONFIG_SX = 'gtwSoftFactoryGated'
# FACTORY_MODE_VALUE_SX = '00' (enter) or '01' (exit)
```

### APE Factory Mode via HTTP

From `DAS_ENTER_FACTORY_MODE.py`:
```python
url = 'http://192.168.90.103:8901/factory/enter'
# Returns: "Already in factory mode" or "Will switch to factory mode"
```

### Tesla Toolbox Connections

Found references to diagnostic software:
- `Service Mode Plus adds to the capabilities of Service Mode, including advanced functionalities for repair professionals with a diagnostic software subscription.`
- Located in: `opt/odin/service_ui/static/translations/`

**Key IPs for APE communication:**
- `192.168.90.103` - APE (ape, ape-a) 
- `192.168.90.105` - APE-B (secondary autopilot)

**Factory calibration endpoints on APE (port 8901):**
- `/factory_calibration/force_calibration_mode`
- `/factory_calibration/exit_calibration_mode`
- `/factory_calibration/status`
- `/factory_calibration/start_calibration`
- `/factory_calibration/download_calibration`
- `/factory_calibration/upload_parameters`
- `/factory_calibration/sanitize_parameters`
- `/factory/enter`

---

## 3. MCU Failsafe Logic

### Heartbeat/Watchdog Strings Found

From UI binaries (`bin/*`):
```cpp
// Heartbeat mechanisms:
CenterDisplayDbusClient::chromiumAdapterHeartbeatFinished(QDBusError)
CenterDisplayDbusClient::vohicoHeartbeat(QDBusError)
CenterDisplayDbusClient::handleVohicoHeartbeatReply(QDBusPendingCallWatcher*)
ChromiumAdapterWebSocketImpl::heartbeatReceived()
ChromiumAdapterWebSocketImpl::heartbeat()
chromiumAdapterHeartbeat
vohicoHeartbeat

// Heartbeat alerts:
ParkerHeartbeatMissing
HeartbeatMissingStopped
LssEmergencyLaneKeep
```

### updater-envoy Service

**Location:** `/etc/sv/updater-envoy/run`

```bash
#!/bin/bash
LOG_TAG="updater-envoy"
SANDBOX_PROFILE="updater-envoy"
exec 2>&1
. /etc/sandbox/sandbox.bash "$LOG_TAG" "$SANDBOX_PROFILE"
StopSandbox
RunSandbox /usr/bin/updater-envoy
```

**updater-envoy binary:** ELF binary at `/usr/bin/updater-envoy`

From strings analysis of UI binaries, updater-related data values:
```
GUI_updaterActive
GUI_updaterReady
GUI_softwareUpdateReinstallRequestType
GUI_remoteSoftwareUpdateRequest
GUI_keyfobUpdateRequest
```

### Gateway Communication (Failsafe Context)

From firewall rules:
```
# APE communication allowed through eth0
-A QTCAR -d 192.168.90.103/32 -o eth0 -p tcp -m multiport --dports 8888,8088,8082 -j ACCEPT
-A QTCAR -d 192.168.90.103/32 -o eth0 -p udp -m multiport --dports 8610,8906 -j ACCEPT
```

### Service Shell Principal System

**Principal files found:**
- `/etc/service-shell/principals.d/tcp/service`
- `/etc/service-shell/principals.d/tcp/service-engineering`
- `/etc/service-shell/principals.d/unix/service-ui`

**AppArmor profiles for service shell:**
- `usr.bin.service-shell`
- `usr.bin.service-shell-service-engineering`
- `usr.bin.service-shell-autodiag`
- `usr.bin.service-shell-macgyver`
- `usr.bin.service-shell-mothership`

---

## 4. Summary of Gaps Still Unresolved

### What We Still Don't Know:

1. **Exact service code validation mechanism**
   - NOT a simple CRC32 hash
   - Uses signed command infrastructure
   - May require Tesla backend validation

2. **How Tesla Toolbox authenticates**
   - Likely uses certificate-based authentication
   - Connects to Odin engine on car
   - Requires "diagnostic software subscription"

3. **Gateway heartbeat timeout values**
   - Found heartbeat mechanism exists
   - Specific timeout values not extracted
   - `ParkerHeartbeatMissing` alert exists

4. **Complete failsafe state machine**
   - Multiple watchdog/heartbeat systems
   - Chromium adapter, vohico, Parker heartbeats
   - Emergency lane keep tie-in

### What We Confirmed:

1. **Factory mode is blocked on fused cars**
   - Explicit check: `if is_fused and factory_mode: FAIL`

2. **APE factory mode via HTTP endpoint**
   - `http://192.168.90.103:8901/factory/enter`
   - Returns status strings

3. **Gateway config IDs for factory mode**
   - Config ID 15, values 02/03
   - Or `gtwSoftFactoryGated` for Model S/X

4. **Service Mode Plus is subscription-based**
   - Requires Tesla diagnostic software subscription

---

## 5. Recommendations for Further Research

1. **Reverse engineer service-shell binary**
   - Look for authentication logic
   - Check certificate validation

2. **Analyze Gateway firmware**
   - Look for heartbeat timeout constants
   - Find failsafe state transitions

3. **Monitor D-Bus during service mode entry**
   - Capture actual authentication flow
   - See what gets signed and validated

4. **Check APE firmware**
   - Factory calibration implementation
   - Security validation on `/factory/enter`

---

*Document created: 2026-02-02*
*Source: MCU2 firmware extraction analysis*
