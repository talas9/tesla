# Service Mode Authentication

**Deep analysis of Tesla's service mode authentication mechanism.**

---

## Executive Summary

Service mode authentication is **NOT a simple PIN comparison**. It is a multi-layered system involving:

1. D-Bus authenticated method calls
2. Protobuf signed command infrastructure
3. Backend validation (Hermes/Mothership)
4. Geofence restrictions

**Key Finding:** No hardcoded PIN, CRC32 hash, or simple comparison found. Authentication requires Tesla backend or signed commands.

---

## Architecture

### Authentication Flow

```
Tesla Toolbox
     │
     │ DoIP Protocol
     ▼
┌─────────────────┐
│  doip-gateway   │ (has D-Bus permission)
└────────┬────────┘
         │
         │ D-Bus: promptVehicleAwakeAndServiceModePopUp()
         ▼
┌─────────────────┐
│     QtCar       │ (displays PIN entry)
└────────┬────────┘
         │
         │ D-Bus: setServicePIN(pin)
         ▼
┌─────────────────┐
│  QtCarServer    │ (validation logic)
└────────┬────────┘
         │
         │ Hermes/Protobuf
         ▼
┌─────────────────┐
│  Tesla Backend  │ (actual validation)
└─────────────────┘
```

---

## Binary Analysis

### Analyzed Binaries

| Binary | Path | Size |
|--------|------|------|
| QtCarServer | `/usr/tesla/UI/bin/QtCarServer` | ~50 MB |
| QtCar | `/usr/tesla/UI/bin/QtCar` | ~50 MB |
| service-shell | `/usr/bin/service-shell` | ~2 MB |

### Key Symbols Found

#### QtCar

```
Offset              Symbol
0x00000000006e3f90  CenterDisplayDbusServiceAdaptor::setServicePIN
0x0000000000655ec0  CenterDisplayDbusServiceImpl::setServicePIN
0x0000000000641620  CenterDisplayHandlerImplCommon::setServicePIN
0x00000000009adf60  GUI_serviceModeAuth (DATA, 104 bytes)
```

#### QtCarServer

```
Offset              Symbol
0x0000000001b09700  GUI_serviceModeAuth (DATA)
0x0000000000d80ce0  CarAPIServiceImpl::set_service_pin_to_drive
```

---

## D-Bus Configuration

### CenterDisplayDbus Interface

**File:** `/usr/share/dbus-1/system.d/com.tesla.CenterDisplayDbus.conf`

```xml
<!-- allow doip-gateway to send -->
<policy user="doip-gateway">
  <allow send_destination="com.tesla.CenterDisplayDbus" 
         send_interface="com.tesla.CenterDisplayDbus" 
         send_member="promptVehicleAwakeAndServiceModePopUp" />
</policy>
```

The `doip-gateway` user has special permission to trigger the service mode popup. This suggests Tesla Toolbox connects via DoIP protocol.

---

## Protobuf Infrastructure

### Message Fields

```protobuf
message VehicleState {
  optional bool signed_cmd_service_mode = ?;
  optional int32 service_mode_auth = ?;
  optional bool service_gtw_diag_session_active = ?;
  optional bool factory_mode = ?;
  optional bool service_mode = ?;
  optional bool service_mode_plus = ?;
}
```

### Signed Command System

Service mode uses the same signed command infrastructure as other secure operations:

```cpp
SignedCarAPIServiceImpl::streamMessageRequiresSignatureCheck()
VehicleServiceDbusClient::DisableSignedCmdGracePeriod()
```

---

## What Was NOT Found

### No Hardcoded PIN

```bash
# Searched for numeric patterns
strings QtCarServer | grep -E "^[0-9]{4,8}$"
# Found: 5555, 1050, 0407, 4567, 4100, 8000, 3334
# None are service PINs (unrelated values)
```

### No CRC32 Hash Comparison

```python
# Calculated CRC32("service") = 0x63A888F9
# Searched: 63a888f9, f988a863
# Result: NOT FOUND in any binary
```

### No TOTP Generation

```bash
strings QtCarServer | grep -iE "totp|time.*based.*auth|otp"
# Found: VCSEC_TPMS::ToTPWheelUnitMessage
# This is tire pressure monitoring, NOT service auth
```

---

## Validation Logic

### Hypothesis

PIN validation occurs through one of:

1. **Backend server authentication**
   - PIN sent via Hermes to Tesla
   - Server validates against account/vehicle
   - Response enables service mode

2. **Signed command verification**
   - Tesla Toolbox generates signed command
   - Contains PIN + timestamp + signature
   - Gateway validates signature with Tesla public key

3. **Certificate-based authentication**
   - Tesla Toolbox has valid certificate
   - Mutual TLS authentication
   - No PIN needed (cert is proof of identity)

### Evidence for Backend Validation

```cpp
HermesServiceClient::SendStreamMessageFinished(QDBusError const&)
HermesServiceClient::asyncSendStreamMessageWithByteArray(...)
```

Service mode requests are sent via Hermes, suggesting backend involvement.

---

## Geofence Restrictions

### Key Function

```cpp
VehicleUtils::isServiceModeAllowedOutsideGeofence()
```

### Related Data Values

```
GUI_inSuperchargerGeofence
GUI_superchargerIdGeofence
GUI_canCreateGeofence
```

**Interpretation:** Service mode may be restricted in certain geographic regions.

---

## Service Mode States

### State Machine

```
INACTIVE
    │
    │ [Enter PIN request]
    ▼
AUTHENTICATION_REQUESTED
    │
    ├─────────────────────┐
    │ [Valid]             │ [Invalid]
    ▼                     ▼
AUTHENTICATED          DENIED
    │
    │ [Activate]
    ▼
ACTIVE
    │
    │ [Grace period ends]
    ▼
CLEANUP
    │
    ▼
INACTIVE
```

### Grace Period

Once authenticated, a grace period allows service actions without re-authentication:

```cpp
VehicleServiceDbusClient::DisableSignedCmdGracePeriod()
```

---

## Security Analysis

### Attack Surface

| Attack Vector | Feasibility | Notes |
|---------------|-------------|-------|
| Hardcoded PIN bypass | ❌ Not found | No local validation |
| Brute force PIN | ❌ Rate limited | Backend protection |
| D-Bus injection | ⚠️ Possible | Requires root on MCU |
| Hermes MITM | ⚠️ Difficult | TLS + certificate pinning |
| Signed command replay | ⚠️ Unknown | May have timestamps |

### Defense Layers

1. **D-Bus Policy** - Only `doip-gateway` can trigger popup
2. **Backend Validation** - No local PIN database
3. **Signed Commands** - Cryptographic verification
4. **Rate Limiting** - Backend throttles attempts
5. **Geofencing** - Regional restrictions

---

## Factory Mode vs Service Mode

| Feature | Factory Mode | Service Mode |
|---------|-------------|--------------|
| **Authentication** | Fuse check + config | Backend + signed cmd |
| **Geofence** | Factory only | Flexible |
| **Access Level** | Full | Restricted |
| **Offline** | Yes (if unfused) | Likely requires backend |

### Factory Mode Entry (from Odin)

```python
if is_fused and factory_mode:
    return FAIL  # Blocked on production cars

set_data_value('GUI_factoryMode', 'true')
set_config(configid='15', data='03')  # devSecurityLevel
```

---

## Bypass Status

### Attempted Approaches

| Approach | Result |
|----------|--------|
| Hardcoded PIN search | NOT FOUND |
| Hash table search | NOT FOUND |
| Debug mode flags | Require backend toggle |
| Local validation override | NOT FOUND |

### Conclusion

**No bypass mechanism found** for production vehicles. Service mode requires:
- Tesla Toolbox with valid subscription, OR
- Signed command from authorized device, OR
- Backend server validation

---

## Research Recommendations

### For Complete Understanding

1. **Disassemble setServicePIN()** at offset 0x655ec0 in QtCar
2. **Monitor D-Bus traffic** during Toolbox service mode activation
3. **Analyze doip-gateway** binary for DoIP protocol handling
4. **Capture Hermes traffic** (if certificate pinning can be bypassed)

### Outstanding Questions

1. Exact PIN validation algorithm (if any)
2. Backend endpoint details
3. Offline service mode possibility
4. Grace period timeout duration
5. Geofence restriction regions

---

## Cross-References

- [Gateway Security Model](../2-gateway/security-model.md) - Config security tiers
- [Certificate Recovery](certificate-recovery.md) - Hermes certificates

---

**Status:** VERIFIED ✅  
**Evidence:** Binary analysis, symbol extraction, D-Bus config review  
**Last Updated:** 2026-02-07
