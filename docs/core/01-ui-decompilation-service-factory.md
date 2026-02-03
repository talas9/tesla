# Tesla MCU2 UI Decompilation: Service Code & Factory Mode Triggers

**Analysis Date:** 2026-02-02  
**Source:** `/firmware/mcu2-extracted/usr/tesla/UI/`  
**Binaries:** QtCarServer (27.7MB), libQtCarGUI.so (56.8MB), libQtCarVAPI.so (17.9MB)  
**Note:** All binaries are stripped - analysis based on string references and PLT symbols

---

## 1. Service PIN Validation System

### 1.1 Core Classes and Functions

#### PINToDriveManager (libQtCarGUI.so)
```cpp
// Key validation methods (demangled from symbols)
PINToDriveManager::checkPINToAllowDrive(QString)     // Main PIN validation
PINToDriveManager::isPasswordValid(QString const&)   // Password hash check
PINToDriveManager::enablePINToDrive(bool, QString const&, QString&)
PINToDriveManager::clearPINToDriveAuth()             // Clear auth state
PINToDriveManager::isServicePINActive()              // Check if service PIN active
PINToDriveManager::setServicePIN(QString const&, QString&)
PINToDriveManager::createServicePinPopupToAllowDrive(DisplayView*)
PINToDriveManager::checkConditionsToRequestPIN()
PINToDriveManager::resetPINToDrive()
```

#### ServicePINToDrivePopupToAllowDrive (UI Popup)
```cpp
// Qt Meta-object registered popup class
ServicePINToDrivePopupToAllowDrive::ServicePINToDrivePopupToAllowDrive(DisplayView*)
// Connected to PINToDriveManager for validation callbacks
```

#### Other PIN Managers
```cpp
SpeedLimitModeManager::isPasswordValid(QString const&)  // Speed limit PIN
GloveboxManager::checkPINToOpenGlovebox(QString)        // Glovebox PIN
GloveboxManager::isPasswordValid(QString const&)
```

### 1.2 PIN Validation Call Flow

```
User enters PIN in UI
        ↓
PINToDrivePopupToAllowDrive::pinEntered()
        ↓
PINToDriveManager::checkPINToAllowDrive(QString)  @ 0xfc82a0 (PLT)
        ↓
PINToDriveManager::isPasswordValid(QString const&)
        ↓
[Internal hash comparison - stripped]
        ↓
Returns bool success/failure
```

### 1.3 Lockout Mechanism

**Data Values:**
- `GUI_PINToDriveBlockedDriveAttempt` - Tracks blocked attempts
- `ServicePINLockout` - Lockout state string
- `PINToDriveBlockedDriveAttemptTimerTimeout()` - Timeout signal

---

## 2. Factory Mode D-Bus Interface

### 2.1 D-Bus Service Definition (from QtCarServer strings)

**Interface:** `com.tesla.CarAPI`

```xml
<method name="set_factory_mode">
    <arg direction="in" type="a{sv}" name="context_param"/>
</method>
<method name="set_factory_mode">
    <arg direction="in" type="a{sv}" name="context_param"/>
    <arg direction="in" type="b" name="on"/>
</method>
```

### 2.2 Implementation Hierarchy

```
D-Bus Call: set_factory_mode(QVariantMap, bool)
        ↓
CarAPIServiceAdaptor::set_factory_mode(QMap<QString,QVariant>, bool)
        ↓
CarAPIServiceImpl::set_factory_mode(QMap<QString,QVariant>, bool)  @ 0xd7cc80
        ↓
CarAPIHandlerImpl::set_factory_mode(bool const&, int const&)  @ 0xdd1020
        ↓
ensureBusesOn("set_factory_mode", timeout=500, ...)  @ 0xdcab20
        ↓
GUI_factoryMode.setValue(bool)  @ 0x1b091c0 (global DataValue)
```

### 2.3 Factory Mode Disassembly (CarAPIHandlerImpl::set_factory_mode)

```asm
# Function @ 0xdd1020
0xdd1020: push %r15, %r14, %r13, %r12, %rbp, %rbx
0xdd102b: lea "set_factory_mode" -> %rdi
0xdd1054: call QString::fromAscii_helper      # Convert string
0xdd106e: call CarAPIHandlerImpl::ensureBusesOn(QString, int, int, int)
          # timeout=0x1f4 (500ms), wake=0x7d0 (2000ms)
          
# Log factory mode state
0xdd111f: lea "set_factory_mode state=" -> %rsi
0xdd1134: call QTextStream::operator<<(QString)

# Check if value is true/false
0xdd1156: cmpb $0x0, 0x0(%r13)     # Check bool parameter
0xdd1162: lea "true"/"false" based on condition

# Check FEATURE_latchedDelivered flag
0xdd11bb: lea FEATURE_latchedDelivered -> %rsi  @ 0x1aeb940
0xdd11ca: movzbl FEATURE_latchedDelivered+0x49 -> %r15d

# Finally set the global factory mode DataValue
0xdd1241: lea GUI_factoryMode -> %rdi  @ 0x1b091c0
0xdd124a: jmp TypedDataValue<BoolDataValueHolder>::setValue(bool)
```

### 2.4 Key Factory Mode Data Values

| Symbol | Address (relative) | Description |
|--------|-------------------|-------------|
| `GUI_factoryMode` | 0x1b091c0 | Main factory mode flag |
| `GUI_serviceMode` | - | Service mode flag |
| `GUI_serviceModePlus` | - | Enhanced service mode |
| `GUI_serviceModeAuth` | - | Service mode authentication state |
| `GUI_signedCmdServiceMode` | - | Signed command service mode |
| `GUI_factoryModeLimitOverride` | - | Override speed limits in factory |
| `GUI_serviceModeCleanup` | - | Cleanup needed flag |
| `VAPI_gtwFactoryMode` | - | Gateway factory mode |
| `FEATURE_latchedDelivered` | 0x1aeb940 | Feature flag for delivery state |

---

## 3. Service Mode System

### 3.1 Service Mode Types

```cpp
// From CarServer protobuf definitions
CarServer.VehicleState {
    bool service_mode;           // Basic service mode
    bool service_mode_plus;      // Enhanced service mode
    bool service_mode_auth;      // Authenticated service mode
    bool signed_cmd_service_mode; // Signed command service mode
    bool factory_mode;           // Factory mode
}

// Legacy support
CarServer.LegacyVehicleState {
    // Same fields as VehicleState
}
```

### 3.2 Service Mode D-Bus Methods

**Service PIN Methods:**
```cpp
// D-Bus interface com.tesla.CarAPI
set_service_pin_to_drive(QVariantMap context_param, 
                         bool& result, QString& reason)

// Implementation chain:
CarAPIServiceAdaptor::set_service_pin_to_drive()
    → CarAPIServiceImpl::set_service_pin_to_drive()
    → CarAPIHandlerImpl::set_service_pin_to_drive(QString const&, bool&, QString&, int const&)
```

### 3.3 Signed Command Grace Period

**VehicleService D-Bus Interface:**
```xml
<method name="DisableSignedCmdGracePeriod">
</method>
```

**Implementation:**
```cpp
VehicleServiceDbusServiceImpl::DisableSignedCmdGracePeriod()
VehicleServiceDbusServiceAdaptor::DisableSignedCmdGracePeriod()
```

**Related Feature Flag:**
- `FEATURE_HARDLOCK_UNSIGNED_CMDS` - When enabled, unsigned commands are blocked

---

## 4. Service Mode Signals and Handlers

### 4.1 UI Signal Handlers (libQtCarGUI.so)

```cpp
CenterDisplay::checkFactoryMode()
CenterDisplay::factoryModeChanged()
CenterDisplay::serviceModeChanged()

ServiceModeDisclaimerPopup(DisplayView*)  // Popup for disclaimer

VehicleRequestsManager::serviceModeChanged()
VehicleRequestsManager::factoryModeChanged()
VehicleRequestsManager::updateWiperServiceMode()

WifiManager::factoryModeChanged()
VehicleSleepTestManager::factoryModeChanged()
BluetoothManager::serviceModeChanged()
ServiceSettingsManager::serviceModeCleanupNeeded()
ServiceSettingsManager::serviceModeAuthChanged()
```

### 4.2 VAPI Layer (libQtCarVAPI.so)

```cpp
VehicleUtils::isServiceModeAllowedOutsideGeofence()  // Geofence check
VehicleUtils::shouldPowerOffAmpInServiceMode()       // Power management
DriveMetricCollector::serviceMode()
DriveMetricCollector::serviceModePlus()

// Bluetooth service mode
Bluetooth::selectServiceMode(int const&, ServiceCallContext*)
Bluetooth::asyncSelectServiceMode(int const&, void*, bool)
Bluetooth::selectServiceModeCompleted(ServiceCallContext*)
```

### 4.3 Service Mode Geofence Check

The `VehicleUtils::isServiceModeAllowedOutsideGeofence()` function suggests service mode may be restricted 
to specific geographic locations (e.g., Tesla service centers). Potential bypass vectors:
1. GPS spoofing to a service center location
2. Feature flag to disable geofence check
3. Factory mode may override geofence restrictions

---

## 5. Remote Service Access

### 5.1 Protobuf Command Structure

```protobuf
// From center_display namespace
message RemoteServiceAccessCommand {
    // Allows remote service technician access
    // Full structure stripped, but command exists
}

// Request wrapping
message Request {
    RemoteServiceAccessCommand remote_service_access_command = N;
}
```

### 5.2 Whitelist Operations

**Important Warning String:**
```
WHITELISTOPERATION_INFORMATION_SERVICE_KEY_ATTEMPTING_TO_ADD_SERVICE_TECH_OUTSIDE_SERVICE_MODE
```

This indicates that adding service technician keys requires active service mode.

---

## 6. Access Code Entry (AccessPopup)

### 6.1 AccessPopup Class

```cpp
// From libQtCarGUI.so
AccessPopup::accessCodeEntered()  // Signal when code entered
// Base popup class for PIN/code entry
```

---

## 7. Complete Call Graph

```
┌─────────────────────────────────────────────────────────────────────┐
│                        USER INTERFACE                                │
├─────────────────────────────────────────────────────────────────────┤
│  ServicePINToDrivePopupToAllowDrive  ←→  PINToDriveManager          │
│  PINToDrivePopupToAllowDrive        ←→  PINToDriveManager          │
│  PINToDrivePopupToChangeSetting     ←→  PINToDriveManager          │
│  AccessPopup                        ←→  [Generic code entry]       │
│  ServiceModeDisclaimerPopup         ←→  CenterDisplay              │
└───────────────────────────────┬─────────────────────────────────────┘
                                │
                                ↓
┌─────────────────────────────────────────────────────────────────────┐
│                     D-BUS SERVICE LAYER                             │
├─────────────────────────────────────────────────────────────────────┤
│  com.tesla.CarAPI                                                    │
│    ├─ set_factory_mode(context, on)                                 │
│    ├─ set_service_pin_to_drive(context) → result, reason            │
│    └─ [other vehicle control methods]                               │
│                                                                      │
│  com.tesla.VehicleService                                           │
│    └─ DisableSignedCmdGracePeriod()                                 │
└───────────────────────────────┬─────────────────────────────────────┘
                                │
                                ↓
┌─────────────────────────────────────────────────────────────────────┐
│                    HANDLER IMPLEMENTATION                            │
├─────────────────────────────────────────────────────────────────────┤
│  CarAPIHandlerImpl::set_factory_mode(bool, int)                     │
│    ├─ ensureBusesOn("set_factory_mode", 500, 2000)                  │
│    ├─ Log "set_factory_mode state=true/false"                       │
│    ├─ Check FEATURE_latchedDelivered                                │
│    └─ GUI_factoryMode.setValue(on)                                  │
│                                                                      │
│  CarAPIHandlerImpl::set_service_pin_to_drive(QString, bool&, QString&)│
└───────────────────────────────┬─────────────────────────────────────┘
                                │
                                ↓
┌─────────────────────────────────────────────────────────────────────┐
│                      DATA VALUE LAYER                                │
├─────────────────────────────────────────────────────────────────────┤
│  GUI_factoryMode           (BoolDataValueHolder)  @ 0x1b091c0       │
│  GUI_serviceMode           (BoolDataValueHolder)                    │
│  GUI_serviceModePlus       (BoolDataValueHolder)                    │
│  GUI_serviceModeAuth       (BoolDataValueHolder)                    │
│  GUI_signedCmdServiceMode  (BoolDataValueHolder)                    │
│  FEATURE_latchedDelivered  (Feature flag)         @ 0x1aeb940       │
└───────────────────────────────┬─────────────────────────────────────┘
                                │
                                ↓
┌─────────────────────────────────────────────────────────────────────┐
│               CARSERVER PROTOBUF STATE                               │
├─────────────────────────────────────────────────────────────────────┤
│  CarServer.VehicleState {                                            │
│    service_mode: bool                                                │
│    service_mode_plus: bool                                           │
│    service_mode_auth: bool                                           │
│    signed_cmd_service_mode: bool                                     │
│    factory_mode: bool                                                │
│  }                                                                   │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 8. Security Observations

### 8.1 PIN Validation
- PIN validation occurs in `PINToDriveManager::isPasswordValid()`
- Implementation is stripped; likely uses secure hash comparison
- Lockout mechanism exists (`ServicePINLockout`, timer-based)
- Multiple PIN types: drive PIN, speed limit PIN, glovebox PIN

### 8.2 Factory Mode Entry
- Factory mode requires D-Bus call to `set_factory_mode`
- Checks `FEATURE_latchedDelivered` flag before allowing
- Logging of state changes suggests audit trail
- No visible authentication in D-Bus interface (auth may be at lower level)

### 8.3 Service Mode Authentication
- `GUI_serviceModeAuth` tracks authentication state
- `signed_cmd_service_mode` suggests signed command requirement
- `DisableSignedCmdGracePeriod` can bypass signed command requirement
- Service tech whitelist operations require active service mode

### 8.4 Potential Vulnerabilities
1. **D-Bus Interface Exposure**: `set_factory_mode` takes only context and bool
2. **Grace Period**: `DisableSignedCmdGracePeriod` could be exploited if D-Bus accessible
3. **Feature Flags**: `FEATURE_latchedDelivered` state affects factory mode entry

---

## 9. Key Addresses Reference

| Function/Symbol | Binary | Address |
|-----------------|--------|---------|
| `CarAPIServiceImpl::set_factory_mode` | QtCarServer | 0xd7cc80 |
| `CarAPIHandlerImpl::set_factory_mode` | QtCarServer | 0xdd1020 |
| `CarAPIHandlerImpl::ensureBusesOn` | QtCarServer | 0xdcab20 |
| `GUI_factoryMode` | QtCarServer | 0x1b091c0 |
| `FEATURE_latchedDelivered` | QtCarServer | 0x1aeb940 |
| `PINToDriveManager::checkPINToAllowDrive` | libQtCarGUI.so | PLT @ 0xfc82a0 |
| `PINToDrivePopupToAllowDrive::pinEntered` | libQtCarGUI.so | 0x1ce5ee0 |

---

## 10. Critical Feature Flags

### 10.1 Security-Related Feature Flags

| Flag | Description | Location |
|------|-------------|----------|
| `FEATURE_HARDLOCK_UNSIGNED_CMDS` | Blocks unsigned commands when enabled | libSharedProto.so |
| `FEATURE_mobileAccessEnabled` | Controls mobile app access | libQtCarGUI.so |
| `FEATURE_mobileAccessDisableViaContactInfoEnabled` | Contact info can disable mobile access | libQtCarGUI.so |
| `FEATURE_dinerAppAuthMode` | Authentication mode for apps | Both |

### 10.2 Service/Factory Related Feature Flags

| Flag | Description |
|------|-------------|
| `FEATURE_earlyAccess` | Early access features enabled |
| `FEATURE_fsdBetaEarlyAccess` | FSD Beta early access |
| `FEATURE_enableTestDriveMode` | Test drive mode support |
| `FEATURE_latchedDelivered` | Vehicle delivered state (affects factory mode) |

### 10.3 Mobile App Feature Flags

| Flag | Description |
|------|-------------|
| `MOBILE_APP_FEATURE_TOGGLE_REMOTE_SERVICE_ACCESS_COMMAND` | Toggle remote service access |
| `MOBILE_APP_FEATURE_HMAC_AUTHENTICATION` | HMAC auth support |
| `MOBILE_APP_FEATURE_SIGNED_VIDEO_REQUEST` | Signed video requests |
| `MOBILE_APP_FEATURE_SPEED_LIMIT_PIN_RESET_SIGNED_COMMAND` | Signed speed limit PIN reset |

---

## 11. Next Steps for Further Analysis

1. **Dynamic Analysis**: Run in emulator to trace actual PIN validation logic
2. **Ghidra Deep Dive**: Import full binary for control flow graph analysis
3. **D-Bus Monitoring**: Capture actual D-Bus traffic during service mode entry
4. **Feature Flag Mapping**: Map all FEATURE_* flags and their effects
5. **Protobuf Schema Recovery**: Extract full CarServer.VehicleState schema
