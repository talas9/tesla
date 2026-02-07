# Key Findings

**Major discoveries from Tesla Gateway and Odin research.**

---

## 1. Gateway Configuration System ✅ COMPLETE

### Summary

The Gateway ECU stores 662 configuration entries in flash, validated with CRC-8.

### Details

| Finding | Evidence |
|---------|----------|
| 662 configs extracted | Flash dump analysis |
| CRC-8 polynomial 0x2F | 100% validation rate |
| Two-tier security model | Odin database + testing |
| Entry format: `[CRC][Len][ID][Data]` | Binary parsing |

### Security Implication

**Insecure configs** (map region, units) can be modified via UDP:3500 without authentication.

**Secure configs** (VIN, country, supercharger) require Hermes authentication.

**Source:** [Gateway Config System](../2-gateway/config-system.md)

---

## 2. Odin Config Hashing ✅ COMPLETE

### Summary

Tesla obfuscates Odin config names using SHA256 hashing with a per-firmware salt.

### Algorithm

```python
# Key hash
key_hash = SHA256(key + salt)

# Value hash (value comes FIRST)
value_hash = SHA256(value + key + salt)
```

### Impact

- All 62-64 public configs decoded
- 94-96 hashes remain unknown (no enum definitions)
- Algorithm decompiled from Python bytecode

**Source:** [Odin Config Decoder](../3-odin/config-decoder.md)

---

## 3. ODJ File Encryption ✅ CRACKED

### Summary

Odin job files (.odj) use Fernet encryption with a hardcoded password.

### Credentials

| Parameter | Value |
|-----------|-------|
| Password | `cmftubxi7wlvmh1wmbzz00vf1ziqezf6` |
| KDF | PBKDF2-HMAC-SHA256 |
| Iterations | 123456 |
| Salt | First 16 bytes of file |

### Impact

All ODJ files can be decrypted without Tesla access.

**Source:** [ODJ Encryption](../3-odin/odj-encryption.md)

---

## 4. Service Mode Authentication ✅ VERIFIED

### Summary

Service mode does NOT use a simple PIN comparison. Authentication requires Tesla backend validation.

### Key Findings

| Finding | Evidence |
|---------|----------|
| No hardcoded PIN | Binary string search |
| No CRC32 hash validation | Binary search |
| Backend validation via Hermes | D-Bus + symbol analysis |
| Geofence restrictions exist | Function references |

### Impact

**No bypass found** for production vehicles. Requires Tesla Toolbox with valid subscription.

**Source:** [Service Mode Analysis](../5-attacks/service-mode.md)

---

## 5. USB Update Package Format ✅ COMPLETE

### Summary

USB offline updates use SquashFS with Ed25519 signatures and dm-verity verification.

### Package Structure

```
[SquashFS (LZ4)] + [Padding] + [0xba01ba01 + Ed25519 sig] + [dm-verity hash table]
```

### Key Details

| Component | Format |
|-----------|--------|
| Filesystem | SquashFS, LZ4 compression |
| Signature | NaCl/Ed25519 (64 bytes) |
| Magic | 0xba01ba01 |
| Integrity | dm-verity SHA-256 |

### Impact

**Cannot forge signatures** without Tesla's private key. Pre-signed packages can be replayed.

**Source:** [USB Updates](../4-firmware/ice/usb-updates.md)

---

## 6. CAN Flood Exploit ⚠️ PARTIAL

### Summary

Flooding specific CAN message IDs can open Gateway port 25956, enabling firmware access.

### Attack Parameters

| CAN ID | Rate | Purpose |
|--------|------|---------|
| 0x3C2 | 10,000/sec | Diagnostic trigger |
| 0x622 | 33/sec | UDS tester-present |

### Impact

- Opens emergency updater port
- Allows firmware handshake redirection
- Reliability varies by firmware version

**Source:** [CAN Flood Attack](../5-attacks/can-flood.md)

---

## 7. Odin Access Levels ✅ DOCUMENTED

### Summary

The Odin routines database reveals which configs are protected.

### Access Level Flags

| Flag | Meaning | Example |
|------|---------|---------|
| `accessLevel: "UDP"` | No authentication | ecuMapVersion |
| `accessLevel: "GTW"` | Hardware locked | devSecurityLevel |
| No special flag | May require auth | superchargingAccess |

### Impact

Identifies exactly which configs can be modified remotely vs require Tesla authentication.

**Source:** [Odin Routines Database](../3-odin/routines-database.md)

---

## 8. Network Topology ✅ MAPPED

### Summary

Tesla vehicles use internal network 192.168.90.0/24 with identified components.

### Key Components

| IP | Component | Ports |
|----|-----------|-------|
| .100 | MCU (ICE/MCU2) | Various |
| .102 | Gateway | 3500, 69, 25956 |
| .103 | APE | 8901 |
| .60 | Modem | 49503 |

### Impact

Any device on internal network can access Gateway UDP API.

---

## 9. CAN Message Database ✅ EXTRACTED

### Summary

6,647 CAN message entries extracted from Gateway firmware.

### Details

| Metric | Value |
|--------|-------|
| Total entries | 6,647 |
| ID range | 0x000 - 0x7FF |
| Format | CSV with handlers |

**Source:** [data/gateway/can-message-database-VERIFIED.csv](https://github.com/talas9/tesla/blob/master/data/gateway/)

---

## 10. Firmware String Database ✅ EXTRACTED

### Summary

37,702 strings extracted from 6MB Gateway firmware binary.

### Contents

- Config function names
- Error messages
- Debug strings
- CAN message identifiers

**Source:** [data/gateway/strings.csv](https://github.com/talas9/tesla/blob/master/data/gateway/)

---

## Summary Table

| Finding | Status | Impact |
|---------|--------|--------|
| Gateway 662 configs | ✅ Complete | Full config access |
| CRC-8 algorithm | ✅ Verified | Config validation |
| Two-tier security | ✅ Verified | Attack surface mapping |
| SHA256 config hashing | ✅ Complete | Odin decoding |
| ODJ encryption | ✅ Cracked | Job file access |
| Service mode auth | ✅ Analyzed | No bypass found |
| USB update format | ✅ Complete | Package structure |
| CAN flood exploit | ⚠️ Partial | Port 25956 access |

---

**Last Updated:** 2026-02-07
