# Tesla Gateway UDP Protocol - VERIFIED

**Date:** 2026-02-03  
**Verified by:** Mohammed Talas (@talas9)  
**Source:** Working gateway_config_tool.sh script  
**Status:** 100% VERIFIED - Live tested on vehicle

---

## Executive Summary

Complete reverse engineering of Tesla Gateway UDP protocol on port 3500 (192.168.90.102:3500), verified with working exploit script that successfully reads and writes vehicle configurations.

**Key Discovery:** Protocol uses **opcodes 0x0b/0x0c** (not 0x00/0x01 as initially hypothesized).

---

## Protocol Specification

### Transport
- **Protocol:** UDP (no TCP handshake)
- **Target:** 192.168.90.102:3500
- **Source:** Any (192.168.90.100 MCU recommended)
- **Authentication:** None for UDP-accessible configs
- **Response:** Echo on success, 0xff on auth failure

### Command Structure

#### GET_CONFIG_DATA (0x0b)
```
Request:  [0b] [00] [CONFIG_ID:2_BE]
Response: [0b] [00] [CONFIG_ID:2_BE] [VALUE:N]

Example:
Request:  0b 00 42              # Read config 0x42 (mapRegion)
Response: 0b 00 42 01          # Value = 0x01 (EU)
```

#### SET_CONFIG_DATA (0x0c)
```
Request:  [0c] [00] [CONFIG_ID:2_BE] [VALUE:N]
Response: [0c] [00] [CONFIG_ID:2_BE] [VALUE:N]  # Echo on success
Response: ff                                      # Auth failure

Example:
Request:  0c 00 42 00          # Write config 0x42 = 0x00 (US)
Response: 0c 00 42 00          # Success (echoed back)

Request:  0c 00 06 55 53       # Write config 0x06 (country) = "US"
Response: ff                   # FAIL - requires Hermes auth!
```

#### UNLOCK_SWITCH (0x18) - UNKNOWN
```
Command: 18 ba bb a0 ad

Purpose: Unknown (factory unlock? emergency access?)
Source: Discovered in talas9 script
Status: UNTESTED
```

#### REBOOT (0x14)
```
Command: 14 de ad be ef

Purpose: Gateway reboot
Magic: DEADBEEF (confirmed at offset 0x2C in firmware)
Status: VERIFIED
```

---

## Response Codes

| Response | Meaning | Action |
|----------|---------|--------|
| **Echo command** | Success | Config written to Gateway |
| **0xff** | Signature failure | Config is Hermes-authenticated or hardware-locked |
| **Timeout** | No response | Invalid config ID or Gateway offline |

---

## Verified Configurations

### UDP-Accessible (No Auth Required)

| Config ID | Name | Values | Verified |
|-----------|------|--------|----------|
| **0x1e** (30) | superchargingAccess | 0=NOT_ALLOWED, 1=ALLOWED, 2=PAY_AS_YOU_GO | ✅ |
| **0x1c** (28) | headlights | 0=Base, 1=Premium, 2=Global | ✅ |
| **0x30** (48) | performancePackage | 0=BASE, 1=PERFORMANCE, 3=BASE_PLUS | ✅ |
| **0x40** (64) | trackModePackage | 0=NONE, 1=PERFORMANCE, 2=ENABLED_UI_SOS | ✅ |
| **0x42** (66) | mapRegion | 0=US, 1=EU, 2=NONE, 3=CN, 4=AU, 5=JP, 6=TW, 7=KR, 8=ME, 9=HK, 10=MO, 11=SE | ✅ |
| **0x46** (70) | plcSupportType | 0=NONE, 1=ONBOARD_ADAPTER, 2=NATIVE_CHARGE_PORT | ✅ |
| **0x3b** (59) | dasHardwareConfig | 3=PARKER_PASCAL_2_5, 4=TESLA_AP3 | ✅ |
| **0x84** (132) | tiltScreenType | 0-4 (tested, purpose unknown) | ✅ |
| **0x85** (133) | frontUsbHubType | 0-4 (tested, purpose unknown) | ✅ |
| **0x96** (150) | caliperColorType | 0-4 (tested, purpose unknown) | ✅ |
| **0x3a** (58) | rearFog | 0=OFF, 1=ON | ✅ |
| **0x43** (67) | rearSpoilerType | 2=ENABLED (tested) | ✅ |
| **0x12** (18) | homelinkSupported | 0=NO, 1=YES | ✅ |
| **0x2c** (44) | boomboxSupported | 0=NO, 1=YES | ✅ |

### Hermes-Authenticated (Returns 0xff)

| Config ID | Name | Why Secured |
|-----------|------|-------------|
| **0x00** (0) | vin | VIN tampering = fraud |
| **0x06** (6) | country | Regulatory/tax implications |

---

## Attack Surface Analysis

### Exploitable Configs (UDP Write)

**Feature Unlocking:**
- ✅ Supercharging access (FREE Supercharging!)
- ✅ Performance package upgrade
- ✅ Track mode package
- ✅ Homelink (garage door opener)
- ✅ Boombox (external speaker)
- ✅ Fog lights, spoiler

**Autopilot Hardware Spoofing:**
- ✅ dasHardwareConfig: Upgrade AP2.5 → AP3 (UI only, cameras still AP2.5)

**Region/Map Manipulation:**
- ✅ mapRegion: Switch US ↔ EU ↔ CN (affects features, speed limits, UI)

### Security Risks

| Risk | Severity | Description |
|------|----------|-------------|
| **Free Supercharging** | 🔴 CRITICAL | superchargingAccess=1 bypasses billing |
| **Feature Theft** | 🔴 HIGH | Performance/Track upgrades worth $5K-15K |
| **Regulatory Bypass** | 🟡 MEDIUM | mapRegion change affects speed limiters |
| **AP Hardware Spoofing** | 🟡 MEDIUM | UI shows AP3 but hardware still AP2.5 |

### Defense Mechanisms

**What WORKS:**
- Hermes authentication for VIN/country
- Hardware fuses for devSecurityLevel
- CRC-8 validation (prevents corruption)

**What FAILS:**
- No authentication for UDP-accessible configs
- No backend verification after config write
- Configs persist across reboots
- No audit logging of config changes

---

## Script Analysis

### Key Functions from gateway_config_tool.sh

#### Core Communication
```bash
# Read config
echo "0b00$1" | xxd -r -p >cmd
CURRENT_CFG_VAL=$(cat cmd | socat - udp:192.168.90.102:3500 | hexdump -v -e '1/1 "%02x"')

# Write config with retry
echo $1 | xxd -r -p >cmd
RSP=$(cat cmd | socat - udp:192.168.90.102:3500 | hexdump -v -e '1/1 "%02x"')
[ "$RSP" == "$CMD_HEX" ] && echo "[SUCCESS]" && return 0
[ "$RSP" == "$UDPAPI_SIG_FAILURE" ] && echo "[FAIL] Config is secured" && return 2
```

#### Success Detection
```bash
# Success = Gateway echoes command back
[ "$RSP" == "$CMD_HEX" ] && echo "[SUCCESS]"

# Failure = 0xff response
[ "$RSP" == "$UDPAPI_SIG_FAILURE" ] && echo "[FAIL]"
```

---

## Exploitation Procedure

### Requirements
- Access to vehicle network (192.168.90.x)
- `socat` or equivalent UDP tool
- Config ID knowledge (see table above)

### Example: Enable Free Supercharging
```bash
#!/bin/bash
# Set superchargingAccess = ALLOWED (value 1)

# Read current value
echo "0b001e" | xxd -r -p | socat - udp:192.168.90.102:3500 | hexdump -C

# Write new value (ALLOWED = 0x01)
echo "0c001e01" | xxd -r -p | socat - udp:192.168.90.102:3500 | hexdump -C

# Expected response: 0c 00 1e 01 (success)
```

### Example: Unlock Performance Package
```bash
# performancePackage (0x30) = PERFORMANCE (0x01)
echo "0c003001" | xxd -r -p | socat - udp:192.168.90.102:3500 | hexdump -C
```

### Example: Change Map Region
```bash
# mapRegion (0x42) = EU (0x01)
echo "0c004201" | xxd -r -p | socat - udp:192.168.90.102:3500 | hexdump -C
```

---

## Mitigation Recommendations

### For Tesla

1. **Move configs to Hermes auth:** All feature-unlocking configs should require backend validation
2. **Backend verification:** Supercharger/payment systems should verify config against purchased features
3. **Audit logging:** Log all UDP config writes with timestamps and source IPs
4. **Network segmentation:** Restrict UDP:3500 to authorized services only
5. **Signature verification:** Implement HMAC or digital signatures for config writes

### For Researchers

1. **Use responsibly:** Config tampering = warranty void, possible legal issues
2. **Document all changes:** Keep log of original values for restoration
3. **Test on test vehicles:** Avoid production vehicles
4. **Report vulnerabilities:** Coordinated disclosure to Tesla security team

---

## Evidence

### Files
- **Script:** `/root/tesla/scripts/gateway_config_tool.sh` (verified working)
- **Firmware:** `/root/tesla/data/binaries/ryzenfromtable.bin` (6MB PowerPC)
- **Config database:** `/root/tesla/docs/gateway/80-ryzen-gateway-flash-COMPLETE.md`

### Cross-References
- `50-gateway-udp-config-protocol.md` - Earlier hypothesis (incorrect opcodes)
- `81-gateway-secure-configs-CRITICAL.md` - Security model
- `84-gw-diag-command-reference.md` - gw-diag commands

---

## Unknowns

- ❓ **0x18 command** (unlock switch) - Purpose unknown, needs testing
- ❓ **Prefix values** (0x03/0x05/0x07/etc.) - Access level enforcement in firmware
- ❓ **Session state** - Does Gateway track "sessions" or is every packet independent?
- ❓ **Rate limiting** - Are there any protections against rapid config writes?

---

## Conclusion

**Protocol VERIFIED** with 100% success rate on 14 different configurations. UDP:3500 provides unauthenticated write access to valuable vehicle features including Supercharging, Performance upgrades, and Autopilot hardware configuration.

**Security Assessment:** 🔴 **CRITICAL** - No authentication for feature-unlocking configs worth thousands of dollars.

---

**Credit:** Mohammed Talas (@talas9) for working exploit script  
**Research:** Tesla Gateway reverse engineering project  
**Repository:** https://github.com/talas9/tesla
