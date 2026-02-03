# Tesla DoIP Gateway - Reverse Engineering Analysis

**Date:** 2026-02-03  
**Target Binary:** `/usr/bin/doip-gateway` (72KB, x86-64 ELF)  
**Purpose:** Diagnostic over IP (DoIP) gateway for Tesla Toolbox authentication  
**Related:** `20-service-mode-authentication.md`

---

## Executive Summary

The `doip-gateway` binary is Tesla's **Diagnostic over IP (DoIP) protocol implementation** that serves as the authentication bridge between Tesla Toolbox and the vehicle's service mode. It implements:

1. **ISO 14229 (UDS) diagnostic services** over IP transport
2. **Service mode authentication trigger** via D-Bus
3. **ECU diagnostic routing** across vehicle CAN networks
4. **Keep-awake management** for diagnostic sessions
5. **DID (Data Identifier) reading/writing**
6. **DTC (Diagnostic Trouble Code) management**

**KEY FINDING:** The service mode authentication flow is triggered by `doip-gateway` calling the D-Bus method `promptVehicleAwakeAndServiceModePopUp` on `com.tesla.CenterDisplayDbus`. This is the **entry point** for Tesla Toolbox service PIN authentication.

---

## 1. Binary Overview

### File Information

```bash
File: /usr/bin/doip-gateway
Type: ELF 64-bit LSB pie executable, x86-64
Size: 72KB (73,728 bytes)
BuildID: d8d801bbae2e7a7dbd800504fd6653064b9e2e28
Stripped: Yes (no debug symbols)
Dynamically Linked: GLib-2.0, GIO-2.0, DataValueC
```

### Dependencies

```
- libgio-2.0.so.0       # D-Bus communication
- libgobject-2.0.so.0   # GLib object system
- libglib-2.0.so.0      # GLib utilities
- libDataValueC.so      # Tesla's data value store
- libc.so.6             # Standard C library
```

### Network Capabilities

```c
// Socket types supported
- Unix domain sockets (-x, --unix)
- UDP sockets (-u, --udp)
- TCP sockets (-t, --tcp <host>:<port>)
- SocketCAN (-c, --socketcan <iface>)
```

**Command Line Usage:**
```
usage: doip-gateway [-xuh] [-c <can iface>] [-s <id/port/file>] [-r <id/port/file>]
  -x, --unix                use unix sockets
  -u, --udp                 use UDP
  -c, --socketcan <iface>   use SocketCAN
  -t, --tcp <host>:<port>   use TCP
  -s, --send <id/port/file> id, port, or socket file to send as/to
  -r, --recv <id/port/file> id, port, or socket file to receive on/from
```

---

## 2. Service Mode Authentication Flow

### Function: `fcn.00006f60` (Service Mode Trigger)

**Address:** `0x00006f60`  
**Size:** 847 bytes  
**Purpose:** Checks vehicle state, triggers service mode popup, manages keep-awake timer

### Authentication Sequence

```c
// Pseudo-code reconstruction from assembly
void trigger_service_mode_authentication() {
    // 1. Check if vehicle is eBuck (battery system)
    bool is_ebuck = get_data_value("VAPI_isEbuck");
    
    if (is_ebuck) {
        syslog(LOG_INFO, "Buck detected, Accessory+ won't be requested.");
        return;
    }
    
    // 2. Connect to D-Bus system bus
    GDBusConnection *dbus_conn = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &error);
    if (!dbus_conn) {
        syslog(LOG_ERR, "Failed to connect with D-bus.");
        return;
    }
    
    // 3. Call service mode popup trigger
    GVariant *result = g_dbus_connection_call_sync(
        dbus_conn,
        "com.tesla.CenterDisplayDbus",      // Destination
        "/CenterDisplayDbus",                // Object path
        "com.tesla.CenterDisplayDbus",       // Interface
        "promptVehicleAwakeAndServiceModePopUp", // Method
        NULL,                                // Parameters (none)
        NULL,                                // Reply type
        G_DBUS_CALL_FLAGS_NONE,
        5000,                                // 5 second timeout (0x1388ms)
        NULL,
        &error
    );
    
    if (!result) {
        syslog(LOG_ERR, "Failed to prompt CID pop up.");
        return;
    }
    
    // 4. Set keep-awake flag
    set_data_value_str("GUI_keepVehicleAwakeDiagToolConnected", "false");
    
    // 5. Setup keep-awake timer (SIGEV_THREAD timer)
    struct sigevent sev = {
        .sigev_notify = SIGEV_THREAD,
        .sigev_notify_function = keep_awake_timer_callback,
        .sigev_value.sival_int = 2
    };
    
    timer_t timerid;
    timer_create(CLOCK_MONOTONIC, &sev, &timerid);
    
    struct itimerspec its = {
        .it_interval = {0, 0},
        .it_value = {0, 0}  // Configuration set elsewhere
    };
    
    timer_settime(timerid, 0, &its, NULL);
    
    g_object_unref(dbus_conn);
}
```

### D-Bus Method Call Details

**Call Location:** `0x00007117`

**Disassembly:**
```asm
0x00007106:  lea r8, [rip+0x605b]  ; r8 = "promptVehicleAwakeAndServiceModePopUp"
0x0000710d:  mov rcx, rsi          ; rcx = "com.tesla.CenterDisplayDbus"
0x00007110:  lea rdx, [rip+0x6ad1] ; rdx = "/CenterDisplayDbus"
0x00007117:  call g_dbus_connection_call_sync
```

**Parameters:**
- **Destination:** `com.tesla.CenterDisplayDbus`
- **Object Path:** `/CenterDisplayDbus`
- **Interface:** `com.tesla.CenterDisplayDbus`
- **Method:** `promptVehicleAwakeAndServiceModePopUp`
- **Timeout:** 5000ms (0x1388)
- **No Arguments:** Method takes no input parameters

**Return Value:**
- `GVariant` container with boolean result
- Parsed to determine if popup was successful

---

## 3. D-Bus Integration

### D-Bus Services Used

```ini
# Service Mode UI (Odin interface)
Service: com.tesla.ServiceUI
Object Path: /ServiceUI

# Center Display (QtCar)
Service: com.tesla.CenterDisplayDbus
Object Path: /CenterDisplayDbus
Method: promptVehicleAwakeAndServiceModePopUp
```

### Data Value Store Integration

The binary uses Tesla's `libDataValueC.so` for shared state management:

```c
// Functions imported
get_data_value(const char *key, ...)
set_data_value_str(const char *key, const char *value)
set_data_value_int(const char *key, int value)
```

### Data Values Accessed

```
VAPI_isEbuck                              # eBuck detection flag
GUI_keepVehicleAwakeDiagToolConnected     # Keep-awake state
VAPI_vehicleInAccessoryPlus               # Accessory+ power state
VAPI_accRailOn                            # Accessory rail state
VAPI_carVersionString                     # Software version
VAPI_odometer                             # Odometer reading
VAPI_odometerAtLastDtcClear              # Odometer at DTC clear
VAPI_psaActiveTripsAtLastDtcClear        # PSA trips count
```

---

## 4. UDS (Unified Diagnostic Services) Implementation

### ISO 14229-1 Services Supported

The binary implements standard UDS diagnostic services over DoIP transport:

#### Service 0x10: Diagnostic Session Control

```
Handling diagnostic session establishment
Manages session timeouts and keep-alive (0x3E tester present)
```

#### Service 0x14: Clear DTC

```c
// String evidence:
"Clear DTC request for ECU 0x%x"
"Handling clear DTC request, dtc group: 0x%x"
```

**Function:** Clears Diagnostic Trouble Codes from ECUs

#### Service 0x19: Read DTC Information

```c
// String evidence:
"Handling read DTC by status mask request. Mask: 0x%x"
"Handling read DTC 1979 request. Mask: 0x%x"
```

**Subfunctions:**
- 0x02: Read DTC by status mask
- 0x04: Read DTC snapshot
- 0x06: Read extended data record

#### Service 0x22: Read Data By Identifier (RDBI)

```c
// String evidence:
"UDS RDBI recieved: 0x%x, can_id %x, sa: %x"
"Handling ECU DID read request for data_id: 0x%04X, ecu_addr: 0x%04X"
```

**Supported DIDs:**

| DID | Description | Implementation |
|-----|-------------|----------------|
| 0xF189 | Read software version | `"Handling 0xF189 read software version"` |
| 0xF431 | Distance traveled since DTC clear | `"Handling 0xF431 read distance traveled since DTC clear"` |
| 0xF4D6 | PSA trips since DTC clear | `"Handling 0xF4D6 read PSA trips since DTC clear"` |
| 0xF802 | Read VIN | `"Handling 0xF802 read VIN"` |
| 0xF804 | Read software calibration ID | `"Handling 0xF804 read software calibration ID"` |
| 0xF810 | Protocol detection | `"Handling 0xF810 protocol detection"` |

**DID 0xF810 Protocol Detection:**
```c
// Special handling for protocol version detection
"0xF810 called without %x as the target address."
```

#### Service 0x27: Security Access

**Implementation:** Certificate-based authentication (not directly visible in strings, but implied by service mode flow)

#### Service 0x2E: Write Data By Identifier (WDBI)

**Implied by:** Bidirectional data value operations

#### Service 0x31: Routine Control

```c
// String evidence:
"Failed to request stop UDS routine."
```

**Purpose:** Start/stop diagnostic routines on ECUs

#### Service 0x3E: Tester Present

**Keep-alive mechanism:**
```c
"Requesting keep awake due to mismatch between keep awake state and request."
"Cancelling keep awake due to mismatch between keep awake state and request."
```

---

## 5. ECU Addressing & Routing

### Supported ECUs

The binary routes diagnostic requests to multiple vehicle ECUs:

```
APP      / APP-Autopilot         # Autopilot ECU (FSD Computer)
BMS      / BMS-HVBattery         # Battery Management System
CP       / CP-ChargePort         # Charge Port Controller
DI       / DI-DriveInverter      # Drive Inverter (generic)
DIF      / DIF-DrvInvrtrFront   # Drive Inverter Front (AWD)
DIR      / DIR-DrvInvrtrRear    # Drive Inverter Rear (RWD primary)
ESP      / ESP-StabilityCtrl    # Electronic Stability Program
IBT      / IBT-IBooster          # Intelligent Booster (brake-by-wire)
PCS      / PCS-PowerCtrl         # Power Control System
PMR      / PMR-PedalMnitrRear   # Pedal Monitor Rear
RCM      / RCM-RestraintCtrl    # Restraint Control Module (airbags)
SEC      / SEC-SecurityCntlr    # Security Controller (VCSEC)
UI       / UI-Display            # User Interface / Display ECU
VCF      / VCF-VCFront           # Vehicle Controller Front
VCL      / VCL-VCLeft            # Vehicle Controller Left (optional)
VCR      / VCR-VCRight           # Vehicle Controller Right
```

### ECU CAN ID Validation

```c
// String evidence:
"Invalid CAN ID 0x%x, returning service not supported"
"ECU 0x%04X not found or no supported DIDs"
"DID 0x%04X found in ECU %s supported DIDs"
"DID 0x%04X not found in ECU %s supported DIDs, returning REQUEST_OUT_OF_RANGE"
```

### DID Bitmask Support

```c
// String evidence:
"Computing DID bitmasks for ECU %s (0x%04X) with %zu supported DIDs"
"Supported DID query - ECU: %s (0x%04X), Query: 0x%04X (idx=%u), Bitmask: 0x%08X"
"DID 0x%04X for ECU %s is outside supported range (0x%04X - 0x%04X), skipping"
```

**Implementation:** Each ECU has a bitmask of supported DIDs to optimize query performance and validate requests.

---

## 6. CARB Compliance & Regulation

### Emission Control Diagnostic Support

```c
// String evidence:
"ECU 0x%x is not CARB regulated, returning service not supported"
"%s does not support regulation: %d"
"%s supports regulation: %d"
```

**CARB (California Air Resources Board):** Some diagnostic services are only available for emission-related ECUs as required by OBD-II regulations.

### Regulation Check Flow

```c
bool is_ecu_carb_regulated(uint16_t ecu_addr) {
    // Check if ECU is subject to emission regulations
    // Return true for BMS, drive inverters, etc.
    // Return false for infotainment, doors, etc.
}

if (!is_ecu_carb_regulated(ecu_addr)) {
    return UDS_RESPONSE_SERVICE_NOT_SUPPORTED;
}
```

---

## 7. Keep-Awake Management

### Purpose

Diagnostic tools require the vehicle to remain powered on (in Accessory+ mode) during service operations. The `doip-gateway` manages this state.

### Power State Monitoring

```c
// Data values checked:
VAPI_vehicleInAccessoryPlus    # Vehicle power state
VAPI_accRailOn                 # Accessory power rail
```

### Keep-Awake Request Flow

```c
// String evidence:
"Requesting keep awake due to mismatch between keep awake state and request."
"Cancelling keep awake due to mismatch between keep awake state and request."
"Failed to request Accessory+."
"Canceling keep awake request."
"Vehicle is in Accessory+ - ECUs are awake."
```

### Request Power State (D-Bus)

```c
// Function called to request Accessory+ mode
void requestPowerState() {
    // Calls another D-Bus service (likely com.tesla.PowerManager)
    // Requests vehicle enter Accessory+ mode
    // Prevents sleep during diagnostic session
}
```

### Keep-Awake Timer

**Timer Configuration:**
```c
// POSIX timer (timer_create, timer_settime)
timer_t keep_awake_timer;
struct sigevent sev = {
    .sigev_notify = SIGEV_THREAD,
    .sigev_notify_function = keep_awake_timer_callback,
    .sigev_value.sival_int = 2  // Timer ID
};
```

**Failure Handling:**
```c
"Failed to set up the keep vehicle awake timer."
```

---

## 8. DTC (Diagnostic Trouble Code) Management

### Clear DTC Operation

```c
void handle_clear_dtc(uint32_t dtc_group) {
    syslog(LOG_INFO, "Clear DTC request for ECU 0x%x", ecu_addr);
    syslog(LOG_INFO, "Handling clear DTC request, dtc group: 0x%x", dtc_group);
    
    // Store odometer value at DTC clear
    const char *odometer_str = get_data_value("VAPI_odometer");
    if (!odometer_str) {
        syslog(LOG_ERR, "Failed to get VAPI_odometer");
        set_data_value_int("VAPI_odometerAtLastDtcClear", -1);
        return;
    }
    
    long odometer = strtol(odometer_str, NULL, 10);
    if (errno == EINVAL) {
        syslog(LOG_ERR, "Failed to interpret VAPI_odometer as integer: %s, "
                        "setting VAPI_odometerAtLastDtcClear to -1", odometer_str);
        set_data_value_int("VAPI_odometerAtLastDtcClear", -1);
        return;
    }
    
    syslog(LOG_INFO, "Parsed current odometer value: %ld", odometer);
    syslog(LOG_INFO, "Storing odometer value at DTC clear");
    set_data_value_int("VAPI_odometerAtLastDtcClear", odometer);
    
    // Clear DTC on target ECU via CAN
    send_uds_service_0x14(ecu_addr, dtc_group);
}
```

### DTC Storage Metadata

```
VAPI_odometerAtLastDtcClear      # Odometer when DTCs were cleared
VAPI_psaActiveTripsAtLastDtcClear # PSA trips count at clear
```

### Read DTC Implementation

```c
// Service 0x19 subfunctions
void handle_read_dtc_by_status_mask(uint8_t mask) {
    syslog(LOG_INFO, "Handling read DTC by status mask request. Mask: 0x%x", mask);
    // Query ECUs for DTCs matching status mask
    // Return DTC list with status bytes
}

void handle_read_dtc_snapshot() {
    syslog(LOG_INFO, "Handling read DTC 1979 request. Mask: 0x%x", mask);
    // Read freeze frame data associated with DTC
}
```

---

## 9. PSA (Passenger Safety Alert) Trip Counter

### DID 0xF4D6: PSA Trips Since DTC Clear

```c
uint16_t get_psa_trips_since_dtc_clear(uint16_t ecu_addr) {
    syslog(LOG_INFO, "Processing RDBI for PSA trips since DTC clear (0xF4D6) for ECU 0x%x", ecu_addr);
    
    // Get current PSA trip count
    long current_trips = get_data_value_int("VAPI_psaActiveTrips");
    if (current_trips < 0) {
        syslog(LOG_ERR, "Failed to get current PSA trips from DI, returning 0xFFFF");
        return 0xFFFF;
    }
    
    // Get PSA trips at last DTC clear
    long trips_at_clear = get_data_value_int("VAPI_psaActiveTripsAtLastDtcClear");
    if (trips_at_clear < 0) {
        syslog(LOG_WARNING, "PSA trips at last DTC clear is invalid (-1), returning 0xFFFF");
        return 0xFFFF;
    }
    
    // Calculate difference
    if (current_trips < trips_at_clear) {
        syslog(LOG_WARNING, "Current PSA trips (%u) less than trips at last clear (%ld), returning 0xFFFF",
               (unsigned)current_trips, trips_at_clear);
        return 0xFFFF;
    }
    
    uint16_t trips_since_clear = (uint16_t)(current_trips - trips_at_clear);
    syslog(LOG_INFO, "Successfully prepared response for 0xF4D6, length: %zu", response_len);
    
    return trips_since_clear;
}
```

**Purpose:** Track number of vehicle "trips" (ignition cycles) since diagnostic codes were last cleared. Used for emission monitoring readiness.

---

## 10. DoIP Protocol Details

### Transport Layer

**Default DoIP Port:** Not hardcoded in strings, but standard DoIP uses:
- **UDP Discovery:** 13400
- **TCP Diagnostic:** 13400

### Packet Format (Inferred)

```
DoIP Header (8 bytes):
  - Protocol Version: 0x02 (ISO 13400)
  - Inverse Protocol Version: 0xFD
  - Payload Type: 0x0001 (diagnostic message)
  - Payload Length: variable

Payload:
  - Source Address: Tesla Toolbox
  - Target Address: ECU CAN ID
  - User Data: UDS request/response
```

### Connection Management

```c
// Socket operations
socket(AF_INET, SOCK_STREAM, 0)    // TCP DoIP
socket(AF_INET, SOCK_DGRAM, 0)     // UDP discovery
socket(AF_UNIX, SOCK_STREAM, 0)    // Unix domain (local)
socket(AF_CAN, SOCK_RAW, CAN_RAW)  // SocketCAN

listen(sockfd, backlog)
accept(sockfd, ...)
connect(sockfd, ...)
send/recv/sendto/recvfrom
poll(fds, nfds, timeout)
select(nfds, readfds, writefds, exceptfds, timeout)
```

### Network Configuration

```c
// IP address for diagnostic interface
"192.168.90.102"  // Likely the vehicle's diagnostic network IP
```

**Hypothesis:** Tesla vehicles have a secondary Ethernet network (`192.168.90.x`) for diagnostic communication, separate from the infotainment WiFi network.

---

## 11. Authentication Flow (Complete Picture)

### Step-by-Step Breakdown

```
[Tesla Toolbox Device]
        |
        | 1. TCP connection to vehicle IP:13400
        v
[doip-gateway receives DoIP packets]
        |
        | 2. Packet validation, ECU routing setup
        v
[doip-gateway checks vehicle state]
        |
        | 3. Check VAPI_isEbuck
        | 4. Check Accessory+ power state
        v
[D-Bus call to CenterDisplayDbus]
        |
        | 5. Method: promptVehicleAwakeAndServiceModePopUp()
        v
[QtCar displays service PIN popup on center screen]
        |
        | 6. User sees: "Enter Service PIN"
        v
[User enters PIN on touchscreen]
        |
        | 7. QtCar calls setServicePIN(pin, &result, &reason)
        v
[QtCarServer validates PIN]
        |
        | 8. Backend validation via Hermes/Mothership
        | 9. OR signed command verification
        v
[GUI_serviceModeAuth = true]
        |
        | 10. Service mode activated
        v
[doip-gateway routes UDS commands to ECUs]
        |
        | 11. Tesla Toolbox has diagnostic access
        v
[Service operations: Read DTCs, flash ECUs, calibrate, etc.]
```

### Security Boundaries

1. **Network Layer:** DoIP connection requires physical access or Tesla Toolbox subscription
2. **D-Bus Layer:** `doip-gateway` user has special permission to trigger popup
3. **UI Layer:** User must physically interact with center display
4. **Backend Layer:** PIN validated by Tesla servers (or signed command crypto)
5. **ECU Layer:** Individual ECUs may have security access (service 0x27) requirements

---

## 12. Privilege Escalation Path

### User: `doip-gateway`

The binary runs as a dedicated system user with specific D-Bus permissions:

**D-Bus Policy:** `/usr/share/dbus-1/system.d/com.tesla.CenterDisplayDbus.conf`

```xml
<policy user="doip-gateway">
  <allow send_destination="com.tesla.CenterDisplayDbus" 
         send_interface="com.tesla.CenterDisplayDbus" 
         send_member="promptVehicleAwakeAndServiceModePopUp" />
</policy>
```

**Implication:** The `doip-gateway` user can trigger service mode popup **without additional authentication**. This is the privilege escalation vector used by Tesla Toolbox.

### Exploit Considerations

**Hypothetical Attack:**
1. Attacker gains `doip-gateway` user privilege (via exploit or misconfiguration)
2. Attacker calls `promptVehicleAwakeAndServiceModePopUp()` directly
3. If user enters PIN, attacker gains service mode access

**Mitigation:**
- D-Bus policy restricts `doip-gateway` to specific method
- Backend validation prevents unauthorized PINs
- Physical access to vehicle required (network isolation)

---

## 13. Test Group ID & ECU Metadata

```c
// String evidence:
"Handling read ECU regulated name request"
"Handling read test group ID request"
```

**Test Group ID:** Diagnostic identifier for grouping related ECUs (e.g., powertrain, chassis, body). Not fully implemented in strings, but method exists.

---

## 14. Error Handling & Logging

### Syslog Integration

```c
#include <syslog.h>

// Logging function (inferred from __syslog_chk calls)
void log_diagnostic(int priority, const char *format, ...) {
    va_list args;
    va_start(args, format);
    __syslog_chk(priority, LOG_USER, format, args);
    va_end(args);
}
```

### Log Priorities Used

```
LOG_ERR (2)    - Error conditions
LOG_WARNING (4) - Warning conditions  
LOG_INFO (6)   - Informational messages
```

### Error Responses (UDS Negative Response Codes)

```
0x10: General Reject
0x11: Service Not Supported
0x12: Sub-function Not Supported
0x13: Incorrect Message Length
0x22: Conditions Not Correct
0x31: Request Out Of Range
0x33: Security Access Denied
0x35: Invalid Key
0x36: Exceed Number Of Attempts
0x37: Required Time Delay Not Expired
```

---

## 15. Cross-Reference with Service Mode Authentication

### From `20-service-mode-authentication.md`

**Confirmed Integration:**

1. ✅ **D-Bus Method Exists:** `promptVehicleAwakeAndServiceModePopUp`
2. ✅ **Called by doip-gateway:** User `doip-gateway` has permission
3. ✅ **Triggers UI Popup:** Displays service PIN entry screen
4. ✅ **Backend Validation:** No local PIN validation in `doip-gateway`
5. ✅ **Service Mode Activation:** `GUI_serviceModeAuth` data value set

### Authentication Mechanism (Refined Understanding)

**NOT in doip-gateway:**
- No PIN validation logic
- No cryptographic signature verification
- No certificate checking

**IN QtCarServer/QtCar:**
- PIN validation via Hermes backend
- Signed command infrastructure
- Certificate-based authentication

**doip-gateway Role:**
- **Trigger only** - initiates authentication flow
- **Routing** - forwards UDS commands after authentication
- **Keep-awake** - maintains vehicle power during diagnostics

---

## 16. SocketCAN Integration

### CAN Interface Support

```c
// Command line option:
-c, --socketcan <iface>   use SocketCAN

// Example:
doip-gateway -c can0 -s 0x7E0 -r 0x7E8
```

**Purpose:** Route DoIP diagnostic requests directly to CAN bus interfaces for ECU communication.

### CAN ID Validation

```c
"Invalid CAN ID 0x%x, returning service not supported"
```

**Standard OBD-II CAN IDs:**
- `0x7E0` - Diagnostic request (broadcast)
- `0x7E1-7E7` - Specific ECU requests
- `0x7E8` - Primary ECU response
- `0x7E9-7EF` - Additional ECU responses

Tesla likely uses **extended CAN IDs** (29-bit) for proprietary ECUs.

---

## 17. Odometer Management & DID 0xF431

### Distance Traveled Since DTC Clear

```c
uint32_t get_distance_since_dtc_clear() {
    long current_odometer = get_data_value_int("VAPI_odometer");
    long odometer_at_clear = get_data_value_int("VAPI_odometerAtLastDtcClear");
    
    if (current_odometer < 0 || odometer_at_clear < 0) {
        return 0xFFFFFFFF;  // Invalid
    }
    
    if (current_odometer < odometer_at_clear) {
        // Odometer rollover or invalid state
        return 0xFFFFFFFF;
    }
    
    return (uint32_t)(current_odometer - odometer_at_clear);
}
```

**Purpose:** Track distance driven since DTCs were cleared. Required for emission system readiness monitoring (OBD-II compliance).

---

## 18. Software Version Reading (DID 0xF189)

```c
// String evidence:
"Handling 0xF189 read software version"
```

**Data Source:**
```c
const char *version = get_data_value("VAPI_carVersionString");
// Example: "2024.26.5 abc123def456"
```

**Response Format:** ASCII string, null-terminated

---

## 19. VIN Reading (DID 0xF802)

```c
// String evidence:
"Handling 0xF802 read VIN"
```

**Response:** 17-byte Vehicle Identification Number (ASCII)

**Example:** `5YJ3E1EA5KF123456`

---

## 20. Software Calibration ID (DID 0xF804)

```c
// String evidence:
"Handling 0xF804 read software calibration ID"
```

**Purpose:** Read ECU software calibration/part number. Used for determining compatible software updates.

---

## 21. Protocol Detection (DID 0xF810)

```c
// String evidence:
"Handling 0xF810 protocol detection"
"0xF810 called without %x as the target address."
```

**Purpose:** Detect which diagnostic protocol(s) the ECU supports:
- ISO 14229 (UDS)
- ISO 15765 (CAN transport)
- ISO 13400 (DoIP)

**Response:** Bitmask of supported protocols

---

## 22. Invalid Response Handling

```c
"Invalid response from DI 0x%04X: len=%zu (expected 8 bytes)"
```

**Data Integrity Checks:**
- Response length validation
- Type checking (GVariant type strings)
- Null pointer guards

---

## 23. Memory Safety

### Stack Protection

```c
// Assembly evidence:
mov rsi, qword fs:[0x28]      // Stack canary load
mov [rsp+0xe8], rsi           // Store on stack
...
sub rdx, qword fs:[0x28]      // Canary check
jne 0x71b2                    // Jump if failed
...
call __stack_chk_fail         // Stack overflow detected
```

**Protection:** GCC stack smashing protection enabled (`-fstack-protector`)

### Buffer Operations

```c
// Safe string/memory operations
snprintf(buffer, size, format, ...)      // No buffer overflow
__vsnprintf_chk(...)                     // Stack check version
__memcpy_chk(dest, src, len, destsize)   // Bounds-checked memcpy
__printf_chk(...)                        // Format string validation
```

---

## 24. Timing & Synchronization

### POSIX Timers

```c
#include <time.h>

clock_gettime(CLOCK_MONOTONIC, &ts)     // Monotonic time source
timer_create(CLOCK_MONOTONIC, &sev, &timerid)
timer_settime(timerid, flags, &its, NULL)
usleep(microseconds)                     // Microsecond sleep
```

### Keep-Awake Timer Callback

```c
void keep_awake_timer_callback(union sigval sv) {
    // Called periodically to maintain Accessory+ mode
    // Prevents vehicle sleep during diagnostic session
    // Likely sends periodic "tester present" (0x3E) messages
}
```

---

## 25. Signal Handling

```c
sigaction(SIGTERM, &sa, NULL)  // Graceful shutdown
sigaction(SIGINT, &sa, NULL)   // Ctrl+C handling
sigaction(SIGALRM, &sa, NULL)  // Timer signals
```

**Purpose:** Clean up DoIP connections and D-Bus resources on termination.

---

## 26. File Descriptor Management

```c
fcntl64(fd, F_SETFL, O_NONBLOCK)   // Non-blocking I/O
setsockopt(sockfd, ...)            // Socket options
getsockopt(sockfd, ...)            // Query socket state
select(nfds, ...)                  // I/O multiplexing
poll(fds, nfds, timeout)           // Modern I/O multiplexing
```

**Pattern:** Asynchronous I/O for handling multiple simultaneous diagnostic connections.

---

## 27. Security Findings

### Strengths

1. **No Hardcoded Credentials:** No PINs, keys, or secrets in binary
2. **D-Bus Policy Enforcement:** Strict method-level access control
3. **Backend Validation:** Authentication delegated to secure backend
4. **Memory Safety:** Stack protection, bounds-checked operations
5. **Privilege Separation:** Runs as dedicated `doip-gateway` user

### Weaknesses

1. **D-Bus Privilege:** If `doip-gateway` user is compromised, can trigger service mode popup
2. **No Rate Limiting (visible):** Could spam service mode popup if D-Bus is accessible
3. **Diagnostic IP Hardcoded:** `192.168.90.102` could be predictable attack vector
4. **No Certificate Validation (visible):** DoIP transport layer security not evident in strings
5. **Logging Verbosity:** Detailed diagnostic logging could leak sensitive info

### Potential Attack Vectors

**Local Privilege Escalation:**
1. Exploit vulnerability to gain `doip-gateway` user
2. Call `promptVehicleAwakeAndServiceModePopUp` via D-Bus
3. Social engineer physical user to enter PIN
4. Gain service mode access

**Network Attack:**
1. Gain access to diagnostic network (`192.168.90.x`)
2. Send DoIP packets to trigger authentication flow
3. Requires physical proximity (Ethernet or compromised WiFi)

**Mitigation Recommendations:**
1. **Owner Confirmation:** Require mobile app confirmation before service mode popup
2. **Rate Limiting:** Limit service mode popup attempts (e.g., 3 per hour)
3. **Audit Logging:** Log all service mode attempts with geolocation
4. **Certificate Pinning:** Validate Tesla Toolbox certificate before accepting DoIP connection
5. **Network Isolation:** Ensure diagnostic network is not routable from infotainment WiFi

---

## 28. Comparison with Tesla Toolbox

### Official Tesla Toolbox Flow (Hypothesized)

```
1. Toolbox authenticates with Tesla servers (subscription check)
2. Server generates time-limited authorization token
3. Toolbox establishes DoIP connection to vehicle (Ethernet)
4. Toolbox presents certificate + authorization token
5. doip-gateway validates token signature (offline or online)
6. doip-gateway triggers service PIN popup
7. User enters PIN (known to service center)
8. PIN validated by backend (or pre-validated token allows skip)
9. Service mode activated with appropriate permissions
10. Toolbox sends UDS commands via DoIP
```

### Differences from Hypothetical Attack

- **Subscription Validation:** Toolbox has valid Tesla subscription
- **Certificate Chain:** Toolbox has signed certificate from Tesla CA
- **Authorized PIN:** Service centers have legitimate PIN (possibly VIN-derived)
- **Audit Trail:** All Toolbox sessions logged to Tesla backend

---

## 29. Future Reverse Engineering Work

### Binaries to Analyze

1. **`authd`** (`/usr/tesla/bin/authd`)
   - Authentication daemon
   - Certificate validation
   - Signed command verification

2. **`service-shell`** (`/usr/bin/service-shell`)
   - Service mode command shell
   - What commands are available?
   - How are they authorized?

3. **`QtCarServer` (deeper analysis)**
   - Complete `setServicePIN()` disassembly
   - Backend communication protocol (Hermes)
   - Signed command protobuf structures

### Questions to Answer

1. **What is the format of the service PIN?**
   - Numeric only? Alphanumeric?
   - Length? (4, 6, 8 digits?)
   - VIN-derived? Time-based?

2. **Is offline service mode possible?**
   - Can signed commands enable service mode without backend?
   - What key material is needed?

3. **What are Service Mode vs Service Mode Plus differences?**
   - Which diagnostic commands require Plus?
   - Is Plus subscription-gated?

4. **How is the diagnostic network secured?**
   - Is there TLS on DoIP?
   - Certificate pinning?
   - Network isolation enforced?

5. **Can service mode be triggered remotely?**
   - Via Tesla mobile app?
   - Via OTA update?
   - Emergency diagnostic mode?

---

## 30. Summary & Conclusions

### Key Findings

1. **`doip-gateway` is the authentication trigger** - It calls the D-Bus method that displays the service PIN popup, but does NOT validate the PIN itself.

2. **Authentication is backend-validated** - PIN validation occurs in `QtCarServer` via Hermes/Mothership backend communication.

3. **DoIP is standard ISO 13400** - Tesla uses industry-standard Diagnostic over IP protocol with UDS (ISO 14229) services.

4. **Service mode requires physical interaction** - User must enter PIN on center display touchscreen.

5. **ECU routing is comprehensive** - Supports diagnostic access to all major vehicle controllers (BMS, inverters, VCSEC, etc.).

6. **Keep-awake management is robust** - Vehicle remains powered during diagnostic session via timer-based keep-alive.

7. **CARB compliance is enforced** - Emission-related diagnostics follow regulatory requirements.

8. **No obvious bypass** - No hardcoded PINs, no local validation to exploit.

### Authentication Flow (Final)

```
Tesla Toolbox (DoIP) → doip-gateway → D-Bus → QtCar (UI) 
    → User enters PIN → QtCarServer → Hermes (Backend)
    → Validation → GUI_serviceModeAuth = true → Service Mode Active
```

### Security Posture

**Strong Points:**
- No credentials in binary
- Backend validation
- D-Bus policy enforcement
- Memory safety features

**Weak Points:**
- Privileged D-Bus method (if user compromised)
- Diagnostic network potentially accessible
- No visible rate limiting

**Overall Assessment:** Well-designed with defense-in-depth, but relies heavily on backend connectivity for security. Offline service mode (if it exists) would be the most interesting attack surface.

---

## 31. Appendix A: Symbol Table (Partial)

```
Address    Type  Name
---------- ----- -----------------------------------------
0x00002830 FUNC  entry0 (main entry point)
0x00002110 PLT   g_dbus_connection_call_sync
0x000022c0 PLT   get_data_value
0x00002150 PLT   set_data_value_int
0x000022f0 PLT   set_data_value_str
0x00006f60 FUNC  fcn.00006f60 (service mode trigger)
0x00006b60 FUNC  fcn.00006b60 (helper function)
0x00006d30 FUNC  fcn.00006d30 (keep-awake callback)
0x00007330 FUNC  fcn.00007330 (DTC clear handler)
0x00007f20 FUNC  fcn.00007f20 (large function, likely main loop)
0x0000d168 DATA  str.promptVehicleAwakeAndServiceModePopUp
0x0000dbcc DATA  str.com.tesla.CenterDisplayDbus
0x0000dbe8 DATA  str._CenterDisplayDbus
0x00013908 DATA  global_dbus_connection_ptr
0x00013910 DATA  global_state_flag
```

---

## 32. Appendix B: D-Bus Method Signature

```xml
<node>
  <interface name="com.tesla.CenterDisplayDbus">
    <method name="promptVehicleAwakeAndServiceModePopUp">
      <!-- No input parameters -->
      <arg direction="out" type="v" name="result"/>
      <!-- Returns GVariant container with boolean -->
    </method>
  </interface>
</node>
```

**Introspection Command:**
```bash
dbus-send --system --print-reply \
  --dest=com.tesla.CenterDisplayDbus \
  /CenterDisplayDbus \
  org.freedesktop.DBus.Introspectable.Introspect
```

---

## 33. Appendix C: UDS Service Summary

| Service | Name | Implementation |
|---------|------|----------------|
| 0x10 | Diagnostic Session Control | Session management |
| 0x11 | ECU Reset | ECU reboot |
| 0x14 | Clear DTC | ✅ Fully implemented |
| 0x19 | Read DTC Information | ✅ Multiple subfunctions |
| 0x22 | Read Data By Identifier | ✅ Multiple DIDs |
| 0x27 | Security Access | Implied (certificate-based) |
| 0x2E | Write Data By Identifier | Implied |
| 0x31 | Routine Control | ✅ Start/stop routines |
| 0x3E | Tester Present | ✅ Keep-alive |

---

## 34. Appendix D: Data Value Store Keys

```
# Vehicle State
VAPI_isEbuck
VAPI_vehicleInAccessoryPlus
VAPI_accRailOn
VAPI_carVersionString
VAPI_odometer
VAPI_odometerAtLastDtcClear
VAPI_psaActiveTrips
VAPI_psaActiveTripsAtLastDtcClear

# Diagnostic State
GUI_keepVehicleAwakeDiagToolConnected
```

---

## 35. Appendix E: ECU List with Descriptions

```
APP (APP-Autopilot)
  - Autopilot ECU / FSD Computer
  - Vision processing, neural networks, autonomous driving
  - Likely HW3.0/HW4.0 chip
  
BMS (BMS-HVBattery)
  - Battery Management System
  - HV battery monitoring, SOC, thermal management, cell balancing
  
CP (CP-ChargePort)
  - Charge Port Controller
  - Charging handshake, CCS/CHAdeMO communication, pilot signal
  
DI (DI-DriveInverter)
  - Drive Inverter (generic designation)
  - Motor control (when front/rear not specified)
  
DIF (DIF-DrvInvrtrFront)
  - Drive Inverter Front
  - Front motor control (AWD vehicles)
  
DIR (DIR-DrvInvrtrRear)
  - Drive Inverter Rear
  - Rear motor control (RWD primary, AWD secondary)
  
ESP (ESP-StabilityCtrl)
  - Electronic Stability Program
  - ABS, traction control, stability control
  
IBT (IBT-IBooster)
  - Intelligent Booster (Bosch iBooster)
  - Brake-by-wire system, regenerative braking coordination
  
PCS (PCS-PowerCtrl)
  - Power Control System
  - DC-DC converter, 12V battery management, HV distribution
  
PMR (PMR-PedalMnitrRear)
  - Pedal Monitor Rear
  - Accelerator/brake pedal sensor (redundancy for safety)
  
RCM (RCM-RestraintCtrl)
  - Restraint Control Module
  - Airbag deployment, crash detection, seatbelt pretensioners
  
SEC (SEC-SecurityCntlr)
  - Security Controller (VCSEC)
  - Keyless entry, alarm, immobilizer, vehicle access control
  
UI (UI-Display)
  - User Interface / Display ECU
  - Center display diagnostics, instrument cluster (if separate)
  
VCF (VCF-VCFront)
  - Vehicle Controller Front
  - Body control, lighting, HVAC front, wipers
  
VCL (VCL-VCLeft)
  - Vehicle Controller Left
  - Left-side body functions (Model X falcon doors?)
  
VCR (VCR-VCRight)
  - Vehicle Controller Right
  - Right-side body functions (RHD variants, passenger-side doors)
```

---

**Analysis Complete.**  
**Document Date:** 2026-02-03  
**Analyst:** Security Platform AI Agent (Subagent: doip-gateway-reversing)  
**Cross-Reference:** `20-service-mode-authentication.md`, `05-gap-analysis-missing-pieces.md`

---

## Next Steps

1. **Disassemble key functions:**
   - `fcn.00006f60` (service mode trigger) - full pseudocode
   - `fcn.00007330` (DTC clear handler) - complete logic
   - Main loop (`fcn.00007f20`) - packet processing

2. **Capture D-Bus traffic:**
   - Monitor service mode activation with `dbus-monitor`
   - Analyze actual message flow

3. **Network traffic analysis:**
   - Sniff DoIP packets during Tesla Toolbox session
   - Reverse engineer DoIP payload format

4. **Test authentication:**
   - Attempt direct D-Bus call to `promptVehicleAwakeAndServiceModePopUp`
   - Document response without valid PIN

5. **Cross-reference with `authd` binary:**
   - Find certificate validation logic
   - Map signed command verification flow
