# Binary Ninja VLE Setup for Tesla Gateway Firmware

**Date:** 2026-02-03  
**Binary:** `ryzenfromtable.bin` (6MB MPC5748G PowerPC VLE firmware)  
**Status:** Investigation - Binary Ninja licensing required for local analysis

---

## Problem Statement

The existing disassembly (`gateway_full_disassembly.txt`) used standard PowerPC mode, resulting in incorrect instruction boundaries and misalignment. The MPC5748G uses **PowerPC VLE (Variable Length Encoding)**, which has different instruction formats:

- **Standard PowerPC:** All instructions are 4 bytes
- **PowerPC VLE:** Instructions are 2 or 4 bytes (variable length)

**Proof VLE works:** Binary Ninja Cloud successfully disassembled it at https://cloud.binary.ninja/bn/0c8cf4cf-2e27-42e7-89d8-c76bc84fe14c

---

## Binary Ninja Options

### Option 1: Binary Ninja Cloud (Already Working)
**Status:** ✅ Successfully analyzed  
**URL:** https://cloud.binary.ninja/bn/0c8cf4cf-2e27-42e7-89d8-c76bc84fe14c  
**Architecture:** PowerPC VLE  
**Limitations:**
- Cannot export full disassembly (cloud interface only)
- No API access for scripting
- Must upload binary to Vector 35 servers

**Advantages:**
- Free
- Already configured and working
- Can manually browse and screenshot findings

### Option 2: Binary Ninja Personal License ($299)
**Features:**
- PowerPC 32/64 support including VLE extensions
- API access for scripting
- Headless export possible (GUI required for plugins)
- Local analysis (no upload required)
- Perpetual license + 1 year updates

**Limitations:**
- Cannot run headless without GUI
- Non-commercial use only

### Option 3: Binary Ninja Commercial License ($1,499)
**Features:**
- All Personal features
- Headless processing (`import binaryninja` without GUI)
- Commercial use allowed
- Perfect for automation

### Option 4: Radare2 with PowerPC VLE Plugin
**Status:** ⚠️ Investigating  
**Radare2 version:** 5.5.0 (already installed)  
**VLE support:** Need to verify if PowerPC VLE is built-in or requires plugin

---

## Radare2 VLE Investigation

Current status: radare2 is installed but VLE architecture support unclear.

### Testing Commands

```bash
# List all PowerPC architectures
r2 -L | grep -i ppc

# Try loading with VLE
r2 -a ppc.vle -b 32 /data/binaries/ryzenfromtable.bin

# If VLE not available, check plugins
r2pm -l | grep -i vle
r2pm -s vle
```

### If VLE Plugin Needed

Radare2 PowerPC VLE plugin: https://github.com/radareorg/radare2-extras/tree/master/libr/asm/arch/ppc.vle

Installation:
```bash
r2pm -ci ppc-vle
```

---

## Alternative: Ghidra with PowerPC VLE

Ghidra supports PowerPC VLE through the NXP MPC5xxx processor module.

### Installation
```bash
# Check if Ghidra is installed
which ghidra || which ghidraRun

# If not, install (requires Java)
wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.0_build/ghidra_11.0_PUBLIC_20231215.zip
unzip ghidra_*.zip
cd ghidra_*
./ghidraRun
```

### Ghidra VLE Setup
1. Create new project
2. Import `ryzenfromtable.bin`
3. Select language: `PowerPC:VLE:32:default`
4. Base address: `0x00000000` (or `0x40000000` based on boot vector)
5. Auto-analyze
6. Export disassembly: File → Export Program → ASCII

**Advantages:**
- Free and open source
- Excellent PowerPC VLE support
- Decompiler included
- Scriptable (Python/Java)

**Disadvantages:**
- Slower than Binary Ninja
- Steeper learning curve
- Heavier resource usage

---

## Recommended Approach

### Short-term: Use Binary Ninja Cloud + Manual Extraction
Since the cloud version already works, manually extract key findings:

1. **Search for UDP port 3500 handler**
   - Search for constant `0x0DAC` (3500 in hex)
   - Look for `bind()` or socket initialization
   - Find packet dispatch switch/table

2. **Find authentication checks**
   - Search for Hermes-related strings
   - Look for `access_id` validation
   - Find config permission checks

3. **Document with screenshots**
   - Take screenshots of key functions
   - Copy assembly snippets manually
   - Note function addresses

### Medium-term: Install Ghidra for Full Export
If Binary Ninja license is not available, use Ghidra:

```bash
# Install Ghidra
./scripts/install-ghidra.sh

# Analyze with VLE
./scripts/analyze-vle-ghidra.py /data/binaries/ryzenfromtable.bin

# Export full disassembly
# (via Ghidra GUI: File → Export Program → ASCII)
```

### Long-term: Binary Ninja Commercial License
For production research and automation:
- Purchase Commercial license ($1,499)
- Install PowerPC VLE plugin: https://github.com/Martyx00/PowerPC-VLE-Extension
- Automate analysis with Python API

---

## PowerPC VLE Extension Details

**GitHub:** https://github.com/Martyx00/PowerPC-VLE-Extension  
**Description:** Binary Ninja plugin for PowerPC VLE (Variable Length Encoding)  
**Author:** Martyx00  

### Installation (requires Binary Ninja Commercial/Personal)

```bash
git clone https://github.com/Martyx00/PowerPC-VLE-Extension
cd PowerPC-VLE-Extension
git submodule update --init --recursive
mkdir build && cd build
cmake .. -DBN_INSTALL_DIR=/opt/binaryninja  # Adjust path
make -j4
cp libVLE_Extension.so ~/.binaryninja/plugins/
```

### Usage in Binary Ninja

1. Open Binary Ninja
2. Load `ryzenfromtable.bin`
3. Select architecture: "PowerPC VLE"
4. Set base address: `0x00000000`
5. Analyze
6. Export: Tools → Export → Disassembly

---

## Current Blockers

### Blocker 1: Binary Ninja License Required
- **Issue:** Free version only supports x86/x86_64/ARMv7, not PowerPC
- **Impact:** Cannot replicate cloud analysis locally
- **Workaround:** Use cloud version manually OR purchase license OR use Ghidra

### Blocker 2: Radare2 VLE Support Unknown
- **Issue:** Need to verify if r2 5.5.0 includes PowerPC VLE
- **Impact:** May need plugin installation
- **Test:** Run `r2 -a ppc.vle -b 32 ryzenfromtable.bin`

### Blocker 3: No Automated Export from Cloud
- **Issue:** Binary Ninja Cloud doesn't expose API for export
- **Impact:** Cannot script extraction
- **Workaround:** Manual copy-paste of key sections

---

## Next Steps

### Immediate (using existing tools)

1. **Verify radare2 VLE support**
   ```bash
   r2 -L | grep ppc
   r2 -a ppc.vle -b 32 /data/binaries/ryzenfromtable.bin
   ```

2. **If VLE works in r2, export disassembly**
   ```bash
   r2 -a ppc.vle -b 32 -w /data/binaries/ryzenfromtable.bin << EOF
   aaa
   s 0x0
   pdf @@ sym.*
   EOF > /data/disassembly/radare2-vle-full.asm
   ```

3. **Manual analysis from Binary Ninja Cloud**
   - Open https://cloud.binary.ninja/bn/0c8cf4cf-2e27-42e7-89d8-c76bc84fe14c
   - Search for `0x0DAC` (port 3500)
   - Screenshot relevant functions
   - Document in new markdown file

### Short-term (if r2 VLE doesn't work)

4. **Install and test Ghidra**
   ```bash
   cd tools
   wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.2_build/ghidra_11.2_PUBLIC_20241105.zip
   unzip ghidra_*.zip
   ```

5. **Analyze with Ghidra VLE**
   - Import binary
   - Select PowerPC:VLE:32:default
   - Auto-analyze
   - Export disassembly

### Long-term (if budget allows)

6. **Purchase Binary Ninja Personal ($299) or Commercial ($1,499)**
   - Personal: Good for manual analysis
   - Commercial: Needed for headless automation
   - Install VLE extension
   - Automate analysis pipeline

---

## Documentation Requirements

Once disassembly is obtained, document:

1. **UDP Port 3500 Handler**
   - Function address
   - Assembly code
   - Packet parsing logic
   - Command dispatch table

2. **Authentication Checks**
   - Where access_id is validated
   - Hermes integration points
   - Permission bitmask checks
   - Bypass opportunities

3. **Config Handler Implementation**
   - CRC-8 calculation function
   - EEPROM read/write wrappers
   - Config metadata structure
   - Validation logic

4. **Memory Map**
   - .text section boundaries
   - .data section locations
   - String tables
   - Function pointers

---

## Related Documents

- **91-gateway-powerpc-disassembly-summary.md:** Existing (incorrect) PowerPC disassembly
- **52-gateway-firmware-decompile.md:** UDP protocol commands
- **88-gateway-strings-analysis.md:** Extracted strings
- **89-gateway-config-metadata-extraction.md:** Config structures

---

## Cost-Benefit Analysis

| Option | Cost | Time | Quality | Automation |
|--------|------|------|---------|------------|
| Binary Ninja Cloud (manual) | $0 | 8-16 hours | Medium | None |
| Radare2 VLE | $0 | 4-8 hours | Medium | Possible |
| Ghidra VLE | $0 | 2-4 hours | High | Good |
| Binary Ninja Personal | $299 | 1-2 hours | High | GUI only |
| Binary Ninja Commercial | $1,499 | 1-2 hours | High | Full |

**Recommendation:** Try Ghidra first (free + high quality), fall back to radare2 if Ghidra is too slow, purchase Binary Ninja only if automation is critical.

---

*Status: Investigation phase - awaiting tool selection decision*  
*Last updated: 2026-02-03 12:08 UTC*
