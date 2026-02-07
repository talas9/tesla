# Tesla Firmware Reverse Engineering

Complete reverse engineering documentation for Tesla Model 3/Y (ICE platform) firmware, Gateway, and Odin diagnostic system.

## 📚 Documentation

**Live documentation site:** [talas9.github.io/tesla](https://talas9.github.io/tesla)

## 🚀 Quick Start

Want to dive in? Read the [5-minute quickstart guide](https://talas9.github.io/tesla/quickstart/).

Key topics:
- [Gateway Architecture](https://talas9.github.io/tesla/2-gateway/architecture/) - Understanding the central controller
- [Odin Diagnostic System](https://talas9.github.io/tesla/3-odin/) - Complete decompiled source code
- [VIN Write Attack](https://talas9.github.io/tesla/5-attacks/vin-write/) - Complete UDS attack chain
- [Config Decoder](https://talas9.github.io/tesla/3-odin/config-decoder/) - 97% Gateway config decoded

## 📖 What's Inside

### Gateway Research
- Complete firmware disassembly (PowerPC VLE instruction set)
- UDP configuration protocol (localhost:3500)
- Config hashing algorithm (SHA256-based, fully reversible)
- Security model and attack surface analysis

### Odin Diagnostic Tool
- **262 Python modules decompiled** from old firmware (Python 3.6)
- **68 decrypted ODJ files** (diagnostic routine definitions)
- Complete UDS/ISO-TP implementation
- Security algorithms (tesla_hash, pektron_hash)
- Gateway TCP protocol (localhost:10001)

### Attack Research
- VIN write via RCM (no security required!)
- CAN bus flood exploit
- Service Mode activation paths
- Certificate recovery for orphaned vehicles

### Tools & Scripts
- `decode_gateway_config.py` - Decode hashed Gateway configs
- `decrypt_odj.py` - Decrypt Odin diagnostic files
- `bruteforce_unknown_hashes.py` - Find unknown enum values
- Gateway string extraction tools
- Complete decompiled Odin source code

## 📊 Repository Stats

- **24 documentation files** (consolidated from 177 scattered docs)
- **8.8 MB of decompiled Odin source code**
- **68 decrypted ODJ files** covering all major ECUs
- **419 CAN messages, 3936+ signals** documented
- **97% Gateway config values decoded**

## 🔬 Research Highlights

### Gateway Config Decoder (COMPLETE)
- Reverse engineered SHA256-based hashing algorithm
- Decoded 62-64 config keys (97% success rate)
- Salt extracted from firmware: `gj55iz2tgghun9nyw2sa8s5oxsykmfwo` (Model 3)
- Config organized by model (Model 3 / Model Y)

### Odin Decompilation (COMPLETE)
- **1312/1348 files decompiled** (97% success)
- ODJ encryption password found: `cmftubxi7wlvmh1wmbzz00vf1ziqezf6`
- Complete UDS→ISO-TP→CAN flow documented
- Security algorithm implementations extracted

### VIN Write Attack Chain
Complete procedure for writing VIN to RCM (Restraint Control Module):
1. ISO-TP Setup: `tx_id=0x641, rx_id=0x649, bus=CH`
2. Extended Diagnostic Session: `10 03`
3. LEARN_VIN Routine: `31 01 04 04` (security level 0 - no auth needed!)
4. MCU provides VIN to RCM automatically
5. Verify: `22 F1 90` to read VIN back

## 🛠️ Platform Details

**Target Vehicles:**
- Tesla Model 3 (2017-2023)
- Tesla Model Y (2020-2023)
- Platform: ICE (In-Car Entertainment)
- MCU: Ryzen APU (x86_64)
- Gateway: NXP MPC5748G (PowerPC VLE)

**Firmware Sources:**
- `/usr/tesla/UI/` (MCU filesystem)
- `/opt/odin/` (diagnostic tool)
- Gateway firmware (disassembled from binary)

## 📝 Evidence Quality

All documentation follows strict evidence-based standards:
- ✅ File paths from actual firmware extractions
- ✅ Decompiled source code references
- ✅ Binary offsets and disassembly listings
- ✅ CAN message IDs from real traffic captures
- ❌ No speculation or unverified claims

## 🏗️ Repository Structure

```
tesla/
├── docs/               # MkDocs documentation source
│   ├── 1-overview/     # Research summary, key findings
│   ├── 2-gateway/      # Gateway architecture, security, protocols
│   ├── 3-odin/         # Odin decompilation, ODJ decryption
│   ├── 4-firmware/     # Firmware extraction, USB updates
│   ├── 5-attacks/      # Attack procedures, exploits
│   └── 6-tools/        # Tool documentation
├── data/               # Research data files
│   ├── configs/        # Decoded Gateway configs (by model)
│   └── gateway/        # CAN messages, strings, config IDs
├── odin/               # Odin diagnostic system
│   └── decompiled/src/ # 262 Python files (8.8 MB)
└── scripts/            # Analysis and decoding tools
```

## 🤝 Contributing

This is an active research project. Contributions welcome:
- Additional firmware versions (Model S/X MCU2 configs)
- Unknown Gateway enum values
- CAN message database extensions
- Attack vector research

## ⚠️ Legal Notice

This research is for **educational and security research purposes only**. Do not use these techniques on vehicles you don't own. Modifying vehicle configurations may:
- Void warranty
- Violate local laws
- Create safety hazards
- Brick expensive hardware

## 📄 License

Research documentation and tools are provided as-is for educational purposes.

---

**Built by:** [@talas9](https://github.com/talas9)  
**Documentation:** [talas9.github.io/tesla](https://talas9.github.io/tesla)  
**Last Updated:** February 2026
