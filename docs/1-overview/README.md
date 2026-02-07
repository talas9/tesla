# Research Overview

**Complete reverse engineering of Tesla Gateway ECU and Odin diagnostic system.**

---

## What This Research Covers

This repository documents security research on Tesla vehicle systems:

| Area | Status | Key Findings |
|------|--------|--------------|
| Gateway Configuration | ✅ Complete | 662 configs, CRC-8 verified |
| Odin Diagnostic Tool | ✅ Complete | SHA256 hashing cracked |
| ODJ File Encryption | ✅ Complete | Fernet password extracted |
| USB Update Format | ✅ Complete | Ed25519 + dm-verity |
| Service Authentication | ✅ Analyzed | Backend validation required |
| CAN Flood Exploit | ⚠️ Partial | Works, reliability varies |

---

## Target Vehicles

| Platform | Models | MCU Type |
|----------|--------|----------|
| ICE | Model 3, Model Y | Intel/AMD Ryzen |
| MCU2 | Model S (2018+), Model X (2018+) | NVIDIA Tegra |

---

## Research Artifacts

### Extracted Data

| Data | Count | Description |
|------|-------|-------------|
| Gateway Configs | 662 entries | All vehicle settings |
| Firmware Strings | 37,702 | Debug messages, function names |
| CAN Messages | 6,647 | Vehicle bus communications |
| Odin Scripts | 2,988 | Diagnostic routines |
| Decoded Configs | 62-64 | Config name mappings |

### Created Tools

| Tool | Purpose |
|------|---------|
| `decode_gateway_config.py` | Decode SHA256 config hashes |
| `decrypt_odj.py` | Decrypt Odin job files |
| `gateway_crc_validator.py` | Validate config CRCs |
| `gateway_database_query.py` | UDP config access |

---

## Documentation Structure

| Section | Content |
|---------|---------|
| [1-overview/](.) | This overview, evidence quality |
| [2-gateway/](../2-gateway/) | Gateway ECU analysis |
| [3-odin/](../3-odin/) | Odin tool research |
| [4-firmware/](../4-firmware/) | Platform-specific firmware |
| [5-attacks/](../5-attacks/) | Security vulnerabilities |
| [6-tools/](../6-tools/) | Tool documentation |

---

## Key Documents

| Document | Description |
|----------|-------------|
| [key-findings.md](key-findings.md) | Major discoveries |
| [evidence-quality.md](evidence-quality.md) | Verification standards |
| [Gateway Config System](../2-gateway/config-system.md) | 662 configs |
| [Odin Config Decoder](../3-odin/config-decoder.md) | SHA256 algorithm |
| [CAN Flood Attack](../5-attacks/can-flood.md) | Port 25956 exploit |

---

## Quick Navigation

### By Topic

| Topic | Link |
|-------|------|
| How does Gateway work? | [Gateway Architecture](../2-gateway/architecture.md) |
| What configs can I modify? | [Security Model](../2-gateway/security-model.md) |
| How does Odin hash configs? | [Config Decoder](../3-odin/config-decoder.md) |
| How do USB updates work? | [USB Updates](../4-firmware/ice/usb-updates.md) |
| What attacks are possible? | [Attacks Overview](../5-attacks/README.md) |

### By Task

| Task | Link |
|------|------|
| Read a Gateway config | [UDP Protocol](../2-gateway/udp-protocol.md) |
| Decode Odin hashes | [Config Decoder](../3-odin/config-decoder.md) |
| Decrypt ODJ files | [ODJ Encryption](../3-odin/odj-encryption.md) |
| Validate config CRC | [Config System](../2-gateway/config-system.md) |

---

## Research Methodology

### Binary Analysis

- Static analysis with Ghidra (PowerPC VLE for Gateway)
- Symbol extraction from ELF binaries
- String analysis for function identification

### Protocol Analysis

- UDP packet capture and reconstruction
- CAN bus message identification
- D-Bus interface enumeration

### Cryptographic Analysis

- SHA256 hash algorithm reversal (Odin configs)
- Fernet encryption key extraction (ODJ files)
- CRC-8 polynomial identification (Gateway configs)

### Source Code Review

- Python bytecode decompilation (Odin scripts)
- JavaScript analysis (handshake servers)
- Configuration file parsing

---

## Limitations

### Not Covered

| Topic | Reason |
|-------|--------|
| Autopilot vision system | Different research area |
| Mobile app security | Separate attack surface |
| Tesla server infrastructure | Out of scope |
| Physical hardware attacks | Limited equipment |

### Theoretical Only

| Topic | Status |
|-------|--------|
| Certificate recovery | Documented, not tested |
| Voltage glitching | Hardware not available |
| Some CAN messages | Not validated on vehicle |

---

## Contributing

1. All claims must cite sources
2. Use firmware-relative paths
3. Label platforms clearly (ICE/MCU2)
4. Test links before committing
5. Follow evidence quality standards

---

**Last Updated:** 2026-02-07
