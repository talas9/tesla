# Tesla Hidden Service Codes

**Date:** 2026-02-03  
**Source:** Model 3/Y firmware (2025.26.8.ice) - `/usr/tesla/UI/bin/QtCarUI`  
**Status:** Extracted from binary strings

---

## Verified Working Codes

| Code | Status | Function | Source |
|------|--------|----------|--------|
| `dynotest` | ✅ VERIFIED | Dynamometer test mode | User confirmed working |

---

## Discovered Text Codes

**Found in QtCarUI binary strings:**

| Code | Type | Likely Function |
|------|------|-----------------|
| `factory` | Mode | Factory mode access |
| `service` | Mode | Service mode access |
| `selftest` | Test | Self-test diagnostics |
| `markermode` | Mode | Marker/calibration mode |
| `lidmode` | Mode | Lid/trunk mode |
| `daymode` | Mode | Day display mode |
| `readmode` | Mode | Read-only mode |
| `perfmodel` | Config | Performance model settings |
| `voicemodel` | Config | Voice recognition model |

**Evidence:** All codes extracted via:
```bash
strings usr/tesla/UI/bin/QtCarUI | grep -E "^[a-z]{6,12}$" | sort -u
```

---

## Potential Numeric Access Codes

**Found in UI library strings:**

```
0000, 0011, 1000, 1010, 1011, 1022, 1023, 1080, 1100, 1111, 
1210, 1234, 1312, 14020, 20180, 27182, 31415, 50000, 65535
```

**Status:** UNTESTED  
**Note:** User tried `007` (not in list) - didn't work

---

## Access Method

### Text Codes
**Location:** Unknown UI element (long-press 2-3 seconds triggers input)  
**Entry:** Type code directly (no confirmation needed for dynotest)

### Numeric Codes  
**Location:** Same UI element after long-press  
**Entry:** Enter digits when prompted for "access code"

---

## What We DON'T Know

❌ **UI element location** - Which screen element requires 2-3 second press?  
❌ **Code validation logic** - Binary is stripped, exact validation unclear  
❌ **Full code list** - Compiled QML may contain more codes  
❌ **Code-to-function mapping** - What each code actually unlocks

**Would need:**
- Vehicle UI access to identify long-press element
- Binary disassembly/decompilation of QtCarUI
- Dynamic analysis or vehicle logs

---

## Related Research

- **Gateway factory mode:** `SET_CONFIG_DATA 0 15 3` (enter) / `0 15 2` (exit)
- **Service mode markers:** `/service.upd` on USB
- **Factory mode markers:** `/factory.upd` on USB

See: `81-gateway-secure-configs-CRITICAL.md` for config-level service access

---

*Findings based on static string extraction only. Dynamic validation needed for complete mapping.*
