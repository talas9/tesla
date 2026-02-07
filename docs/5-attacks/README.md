# Security Research

**Attack surface analysis and vulnerability documentation for Tesla vehicles.**

---

## Overview

This section documents security research findings, including:

- **CAN Flood Exploit** - Opening port 25956 for firmware access
- **VIN Write Attack** - JTAG-based identity modification
- **Service Mode Analysis** - Authentication mechanism research
- **Certificate Recovery** - Orphan vehicle certificate issues

---

## Documentation

| Document | Description | Status |
|----------|-------------|--------|
| [can-flood.md](can-flood.md) | CAN bus flooding to open port 25956 | ⚠️ Partially tested |
| [vin-write.md](vin-write.md) | VIN modification via JTAG | ✅ Verified |
| [service-mode.md](service-mode.md) | Service mode authentication analysis | ✅ Verified |
| [certificate-recovery.md](certificate-recovery.md) | Orphan vehicle certificate issues | ⚠️ Theoretical |

---

## Attack Surface Summary

### High-Risk Services

| Service | Port | Risk | Description |
|---------|------|------|-------------|
| Gateway UDP API | 3500 | 🔴 HIGH | Config tampering, no authentication |
| Emergency Updater | 25956 | 🔴 HIGH | Firmware install (CAN flood trigger) |
| APE Factory API | 8901 | 🟡 MEDIUM | Bearer token required |
| QtCarServer D-Bus | local | 🟡 MEDIUM | Local process access needed |

### Attack Vectors

| Vector | Difficulty | Impact | Status |
|--------|------------|--------|--------|
| UDP config modification | Low | Medium | ✅ Works |
| CAN flood → port 25956 | Medium | High | ⚠️ Partial |
| JTAG flash modification | High | Critical | ✅ Works |
| Service mode bypass | Very High | High | ❌ Not found |

---

## Security Model Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    TESLA SECURITY LAYERS                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  LAYER 1: NETWORK                                               │
│  ─────────────────                                              │
│  • Internal network 192.168.90.0/24                             │
│  • Firewall rules (DROP default)                                │
│  • UDP:3500 accepts insecure config writes only                 │
│                                                                 │
│  LAYER 2: AUTHENTICATION                                        │
│  ─────────────────────────                                      │
│  • Hermes mTLS for secure configs                               │
│  • Service mode requires backend validation                     │
│  • No hardcoded backdoor credentials                            │
│                                                                 │
│  LAYER 3: CRYPTOGRAPHY                                          │
│  ─────────────────────                                          │
│  • Ed25519 signature verification                               │
│  • dm-verity for firmware integrity                             │
│  • Certificate-based authentication                             │
│                                                                 │
│  LAYER 4: HARDWARE                                              │
│  ────────────────                                               │
│  • JTAG fuses blown on production                               │
│  • Secure boot enforcement                                      │
│  • Hardware security module (HSM)                               │
│                                                                 │
│  BYPASS: PHYSICAL ACCESS (JTAG)                                 │
│  ─────────────────────────────                                  │
│  • Voltage glitching can defeat fuses                           │
│  • Direct flash access bypasses all software security           │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Verified Attacks

### 1. Insecure Config Modification ✅

**Target:** Gateway UDP port 3500  
**Impact:** Modify map region, display units, debug flags  
**Difficulty:** Low (any network access)

```python
# Example: Change map region to EU
import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
packet = build_write_packet(0x0014, bytes([0x01]))
sock.sendto(packet, ("192.168.90.102", 3500))
```

### 2. JTAG Flash Modification ✅

**Target:** Gateway flash memory  
**Impact:** Change VIN, country, ANY config  
**Difficulty:** High (requires hardware access, voltage glitching for fused chips)

### 3. Firmware Signature Replay ⚠️

**Target:** USB update signature verification  
**Impact:** Install older/different firmware  
**Difficulty:** Low (if pre-signed packages available)

---

## Defenses

### What Tesla Protects

| Asset | Protection | Bypass Difficulty |
|-------|------------|-------------------|
| VIN | Hermes auth required | High (JTAG) |
| Country | Hermes auth required | High (JTAG) |
| Supercharger access | Backend validation | Very High |
| Firmware | Ed25519 + dm-verity | Private key needed |
| Service mode | Backend validation | No bypass found |

### What Tesla Doesn't Protect

| Asset | Access Method |
|-------|---------------|
| Map region | UDP:3500 |
| Display units | UDP:3500 |
| Debug UART | UDP:3500 |
| User preferences | UDP:3500 |

---

## Research Status

| Topic | Status | Findings |
|-------|--------|----------|
| Gateway UDP protocol | ✅ Complete | Insecure configs writable |
| Service mode auth | ✅ Complete | Backend validation, no bypass |
| USB update format | ✅ Complete | Ed25519 + dm-verity |
| CAN flood exploit | ⚠️ Partial | Works, reliability varies |
| JTAG access | ✅ Verified | Full bypass on unfused |
| Certificate system | ⚠️ Partial | Orphan issues documented |

---

## Tools

| Tool | Purpose |
|------|---------|
| [gateway_database_query.py](https://github.com/talas9/tesla/blob/master/scripts/gateway_database_query.py) | UDP config access |
| [openportlanpluscan.py](https://github.com/talas9/tesla/blob/master/scripts/openportlanpluscan.py) | CAN flood script |
| [signatures.json](https://github.com/talas9/tesla/blob/master/scripts/signatures.json) | Firmware signature database |

---

## Responsible Disclosure

Security findings should be reported to Tesla via their bug bounty program.

**DO NOT:**
- Modify vehicles without authorization
- Share exploit details publicly before disclosure
- Use findings for unauthorized access

---

**Last Updated:** 2026-02-07
