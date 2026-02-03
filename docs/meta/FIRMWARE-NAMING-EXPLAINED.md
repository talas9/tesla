# Tesla Firmware Package Naming - Explained

## The Confusion

Tesla's firmware package naming is **confusing** because it doesn't match the actual hardware.

## Actual Hardware (MCU = Media Control Unit)

All Teslas have an MCU (computer), but the hardware varies:

| Hardware | Chip | Vehicles | Years |
|----------|------|----------|-------|
| MCU1 | NVIDIA Tegra 3 | Model S/X | 2012-2018 |
| MCU2 | Intel Atom | Model S/X (upgrade) | 2018-2021 |
| MCU3/Ryzen | AMD Ryzen | **All vehicles** | 2021+ |

**Current state (2025+):**
- Model S/X: Ryzen-based MCU
- Model 3/Y: Ryzen-based MCU
- All use the same AMD Ryzen APU

## Firmware Package Naming (Confusing!)

Tesla uses two firmware package formats:

| Package Extension | Target Vehicles | Actual Hardware | Signature Key |
|-------------------|-----------------|-----------------|---------------|
| `.mcu2` | Model S/X | Ryzen (2021+), Intel (2018-2021), Tegra (2012-2018) | `/etc/verity-prod.pub` |
| `.ice` | Model 3/Y | Ryzen (2021+) | `/etc/verity-prod.pub` |

**Why .mcu2?**
- Historical naming from MCU2 (Intel Atom) era
- Still used for S/X even though hardware is now Ryzen
- Just means "Model S/X firmware package format"

**Why .ice?**
- "ICE" = Internal Combustion Engine (Tesla's internal project name for Model 3)
- Used for all Model 3/Y firmware regardless of MCU hardware
- Just means "Model 3/Y firmware package format"

## The Correct Way to Describe Them

❌ **WRONG:**
- "MCU2 (Tegra) firmware"
- "ICE (Ryzen) firmware"
- "MCU2 is Tegra, ICE is Ryzen"

✅ **CORRECT:**
- "Model S/X firmware (.mcu2 packages)"
- "Model 3/Y firmware (.ice packages)"
- "Both use Ryzen hardware (2021+)"

## Package Format Details

Both formats are identical in structure:

```
[SquashFS Filesystem] + [Padding] + [NaCl Signature] + [dm-verity Hash]
```

The only difference is:
1. **Target vehicle** (S/X vs 3/Y)
2. **File extension** (.mcu2 vs .ice)
3. **Minor differences** in partition layout and update scripts

## Examples

**2025.32.3.1.mcu2:**
- Target: Model S/X
- Hardware: Ryzen APU (if 2021+), Intel Atom (if 2018-2021), or Tegra (if pre-2018)
- Package format: .mcu2
- Size: ~1.8 GB

**2025.26.8.ice:**
- Target: Model 3/Y
- Hardware: Ryzen APU (2021+)
- Package format: .ice
- Size: ~2.1 GB

## Summary

- **MCU** = The computer hardware (exists in all Teslas)
- **MCU1/MCU2/MCU3** = Hardware generations (Tegra → Intel → Ryzen)
- **.mcu2** = Firmware package format for Model S/X (naming is historical, doesn't indicate hardware)
- **.ice** = Firmware package format for Model 3/Y (project codename, doesn't indicate hardware)

**All modern Teslas (2021+) use Ryzen, regardless of package format.**

---

*This document clarifies the confusing firmware naming conventions.*

## Common Mistakes to Avoid

❌ **WRONG:**
- ".mcu3 packages" - This does NOT exist
- "MCU3 firmware files" - Wrong, it's .ice or .mcu2
- Confusing hardware generations with file extensions

✅ **CORRECT:**
- Only TWO package extensions: .ice and .mcu2
- .ice = Model 3/Y
- .mcu2 = Model S/X
- No .mcu3, .mcu1, or other extensions in modern firmware

## File Extension Summary

| Extension | Exists? | Target Vehicles | Notes |
|-----------|---------|-----------------|-------|
| `.ice` | ✅ YES | Model 3/Y | Current format |
| `.mcu2` | ✅ YES | Model S/X | Current format |
| `.mcu3` | ❌ NO | N/A | Does not exist |
| `.mcu1` | ⚠️ LEGACY | Very old S/X | Discontinued, pre-2018 |
| `.mcu` | ⚠️ LEGACY | Very old S/X | Discontinued, pre-2018 |

**Only .ice and .mcu2 are used in modern (2021+) firmware!**

## Additional Firmware Package Types

Beyond the main MCU firmware, Tesla uses other package extensions:

| Extension | Purpose | Target | Notes |
|-----------|---------|--------|-------|
| `.ice` | MCU firmware | Model 3/Y | Main computer firmware |
| `.mcu2` | MCU firmware | Model S/X | Main computer firmware |
| `.APExx` | Autopilot firmware | All vehicles | APE = Autopilot ECU (e.g., .APE1, .APE2) |
| `.ssq` | Map data | All vehicles | Navigation/map packages (SquashFS format) |

**APE Firmware:**
- APE = Autopilot Processing Engine
- Different generations: .APE1, .APE2, etc.
- Separate computer for FSD/Autopilot processing
- Independent update packages from main MCU

**Map Files:**
- .ssq = SquashFS format (same as .ice/.mcu2)
- Contains navigation map data
- Updates separately from main firmware
- Can be very large (multi-GB)

## Complete Package Type Reference

```
Vehicle Computer (MCU):
├── .ice  → Model 3/Y MCU firmware
└── .mcu2 → Model S/X MCU firmware

Autopilot Computer (APE):
└── .APExx → FSD/Autopilot firmware (all vehicles)

Navigation:
└── .ssq → Map data packages (all vehicles)

Legacy (discontinued):
├── .mcu1 → Very old Model S/X (pre-2018)
└── .mcu  → Very old Model S/X (pre-2018)
```

**Installation:**
All package types can be installed via USB using the same offline update mechanism documented in USB-OFFLINE-UPDATE-COMPLETE.md.
