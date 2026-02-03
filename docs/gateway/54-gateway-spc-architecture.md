# Tesla Gateway SPC (PowerPC MCU) Chip Architecture

**Document:** 54-gateway-spc-architecture.md  
**Created:** 2026-02-03  
**Scope:** Document the Gateway’s *microcontroller* platform (Power Architecture / “SPC-class” automotive MCU), its boot flow, memory/peripheral map, security features, and implications for reverse engineering.

> **Important clarification (current evidence):**
> The PowerPC firmware we have (`models-fusegtw-GW_R7.img`, 94 KB) looks like it runs on an **NXP/Freescale automotive Power Architecture MCU in the MPC55xx/SPC5 lineage**.
>
> Despite earlier docs calling the core “e500”, multiple indicators (Book-E exception model, IVPR/IVOR use, SIU peripheral base) are more consistent with an **e200 core (e200z3/z6 family)** and a **classic MPC55xx-style memory map** (SIU @ `0xC3F00000`).
>
> **We do not currently have a definitive silicon part number from the bootloader image alone.** The best candidate in existing project notes is **MPC5534** (based on a claimed JTAG ID), but that must be treated as *probable* until we read SVR/MIDR from hardware or from the larger application firmware.

---

## 1) What we can identify from `models-fusegtw-GW_R7.img`

### 1.1 Firmware header (Tesla-specific)
From `/root/downloads/seed-extracted/gtw/114/models-fusegtw-GW_R7.img` (see `12-gateway-bootloader-analysis.md` and `52-gateway-firmware-decompile.md`):

- Entry instruction at offset 0: `0x48000040` (branch to init)
- Version string: `"GW R7"`
- Firmware size: ~94 KB
- Signature/hash fields present (Tesla image format), but **no explicit MCU part-number string** found via `strings`.

### 1.2 Strongest platform fingerprints
These constants/instructions in early init are the most useful to classify the MCU family:

- **Peripheral window mapped at `0xC3F00000`** via TLB entry
  - Observed in init sequence (TLB MAS2/MAS3 set to `0xC3F00000…`)
  - This matches **classic Freescale MPC55xx “SIU”** style addressing.
  - Newer SPC56/SPC57/SPC58 families more typically expose **SIUL / SIUL2** at different bases (often `0xFFFC0000` etc.).

- **Control/clock/watchdog MMIO** in `0xFFFE_****` and `0xFFF3_****` regions
  - Early init writes to `0xFFFE0000`, `0xFFFE C000`, and `0xFFF3 8000`-like ranges.
  - Again aligns with older MPC55xx-era maps.

- **Book-E exception model:** IVPR/IVOR usage
  - Boot code configures **IVPR** (interrupt vector prefix) and **IVOR** offsets.
  - That is characteristic of **Power Architecture Book E** (e200/e500 class).

**Conclusion:** The *memory map* evidence is much stronger for **MPC55xx/SPC5x-class** than for SPC56/57/58.

### 1.3 Candidate chip (probable)
Existing debug-interface notes (`47-gateway-debug-interface.md`) state:

- **TAP Device ID:** `0x01570C0D` → labeled as **MPC5534**

If that JTAG ID is correct, then the Gateway MCU is likely:

- **Family:** Freescale/NXP **MPC5534** (MPC55xx)
- **Core:** Power Architecture **e200z6** (Book E)
- **Typical clock:** ~132–150 MHz class (project notes mention 150 MHz)

**Status:** *Probable, not proven from the bootloader blob alone.*

### 1.4 How to prove the exact part number
To move from “probable” to “exact”, we need one of:

1. **Read SVR (System Version Register) / PVR** at runtime
   - Via JTAG/Nexus, or via a tiny diagnostic routine.
2. **Read SIU/MIDR (Module ID Register)**
   - Many MPC55xx parts expose an MCU identification register under SIU.
3. **Search the larger application firmware** (3.3 MB `.hex`) for explicit IDs
   - `models-GW_R7.hex` is referenced in `52-gateway-firmware-decompile.md`; it is more likely to include silicon checks.

---

## 2) Core architecture (Power Architecture Book E)

### 2.1 e200 vs e500 note
Earlier docs used “e500v2”; however:

- **MPC55xx parts are e200-based** (z0/z3/z6 variants)
- The code uses Book-E features shared across e200/e500 families (IVPR/IVOR, MAS/TLB on higher-end e200 cores).

**Working model for Gateway:** Power Architecture **e200z6-like** core.

### 2.2 Memory protection / MMU
The bootloader sets up TLB entries (MAS0–MAS3 + `tlbwe`), indicating:

- A **Book-E TLB-based MMU** (not a simple fixed MPU-only core)
- Explicit mapping of:
  - execution region (code/RAM window)
  - peripheral MMIO window

**Security implication:** If TLB entries mark code RAM as RWX (common in early init), exploitation is easier (no W^X).

---

## 3) Memory map (as observed in R7 bootloader)

> Addresses below are the **runtime virtual map used by the bootloader**. The physical/flash mapping depends on the SoC’s boot ROM/BAM configuration.

### 3.1 Regions used by the bootloader
From `12-gateway-bootloader-analysis.md` / `38-gateway-firmware-analysis.md`:

| Region | Range | Notes |
|---|---:|---|
| Bootloader runtime (mapped) | `0x4000_0000 …` | Boot code executes with IVPR at `0x4000_0000` |
| Factory gate buffer | `0x4001_6000 – 0x4001_7FFF` | 8 KB command buffer used by “factory gate” logic |
| RAM/BSS/heap | `0x4002_0000 – 0x4002_FFFF` | FreeRTOS data structures, stacks |
| lwIP buffers | `0x4003_0000 – 0x4003_FFFF` | Network pools / PCB pools |
| Peripherals (SIU/MMIO) | `0xC3F0_0000 – 0xC3FF_FFFF` | Classic MPC55xx peripheral window |
| Watchdog / system MMIO | `0xFFFE_0000 …` | Used very early in init |
| Clock / mode control MMIO | `0xFFF3_0000 …` | Used in early clock init |

### 3.2 Boot sequence highlights (R7)
High-level:

1. Reset → branch to init (`b 0x40`)
2. Early system init
   - watchdog enable/config via `0xFFFE_****`
   - clock init via `0xFFF3_****`
   - TLB entries for code and peripherals
3. Set IVPR/IVORs
4. Clear BSS
5. Start FreeRTOS + lwIP threads (strings: `mainTask`, `tcpip_thread`, `rxTask`)

---

## 4) Peripherals & hardware features (MPC55xx/SPC5-class reference)

> The bootloader itself is small; it does not enumerate every module. The list below is based on the *identified family* and common Gateway ECU requirements.

### 4.1 CAN (FlexCAN)
- MPC55xx/SPC5-class devices commonly include **multiple FlexCAN controllers**.
- Observed project-wide behavior:
  - Gateway routes CAN between multiple vehicle networks.
  - Bootloader includes a CAN message dispatch/jump table.

**What to document/verify next in the app firmware:**
- Number of CAN controllers enabled
- MB (message buffer) layout and acceptance filters
- Whether RX uses DMA (some parts support eDMA; others use interrupt-driven MB servicing)

### 4.2 LIN, SPI, I2C, GPIO
- LIN: often provided via eSCI/eLIN modules depending on part.
- SPI: DSPI common on MPC55xx.
- I2C: some MPC55xx have I2C; many use enhanced serial modules.
- GPIO: via **SIU** (Pad config + GPDO/GPDI arrays), matching the `0xC3F0_0000` base.

### 4.3 Watchdogs
MPC55xx-class typically has:
- software watchdog / system watchdog
- possible windowed watchdog modes

Bootloader writes to watchdog registers very early.

---

## 5) Security features (what exists vs what likely doesn’t)

### 5.1 Secure boot & code signatures (Tesla layer)
The Tesla image format includes signature/hash fields. Bootloader implements:

- “factory gate” mechanism (privileged command pathway)
- configuration-driven security modes (see `devSecurityLevel` in UDP config docs)

This is *system security*, not necessarily silicon HSM.

### 5.2 HSM / hardware crypto
- **MPC55xx-era parts generally do not include a modern HSM** like later SPC57/58 families.
- Therefore, crypto is likely **software-based** (or uses small accelerators if present).

### 5.3 Debug protection (JTAG/Nexus)
- MPC55xx uses **Nexus/JTAG** debug.
- Production devices can fuse/lock debug access; unclear what Tesla did.
- The mini-HDMI debug connector strongly suggests Tesla maintained a physical debug path.

**To verify on hardware:** JTAG lock state + any password/challenge for Nexus.

---

## 6) Flash layout (conceptual)

We have two firmware “worlds” in the project:

1. **PowerPC MCU bootloader**: ~94 KB (`models-fusegtw-GW_R7.img`)
2. **PowerPC application firmware**: ~3.3 MB (`models-GW_R7.hex`, referenced)

A typical automotive MCU flash layout:

- Boot Assist/ROM (silicon)
- Bootloader region (Tesla)
- Application region (Tesla)
- Config/NVM region (EEPROM emulation)
- Update staging / redundant slot (for safe updates)

`52-gateway-firmware-decompile.md` claims app flash offsets for config + staging; these must be validated against the `.hex` memory ranges.

---

## 7) Update mechanism (SPC/MPC-class)

Likely sequence:

1. Update payload delivered via x86_64 side (DoIP/UDP) or via CAN diagnostics
2. Payload written into *staging* area
3. Bootloader verifies integrity / signatures (unless devSecurityLevel / factory gate disables)
4. Bootloader programs internal flash (erase/write) in blocks
5. Optional rollback protection (unknown; not confirmed)

**Note:** On MPC55xx/SPC5-class MCUs, flash programming must run from RAM and obey flash controller timing and lock bits.

---

## 8) Debug interfaces & mini-HDMI mapping

See `47-gateway-debug-interface.md` for the physical connector mapping.

From an MCU standpoint, expect:

- **UART** console via an eSCI-like module
- **JTAG/Nexus** signals (TCK/TMS/TDI/TDO/TRST)

**Critical clarification:** The connector provides *a hardware path*; whether it is usable depends on lifecycle lock bits.

---

## 9) Cross-reference corrections & TODOs

### 9.1 Corrections needed in existing docs
- Replace “x86 assumptions” in PowerPC bootloader docs (where present).
- Replace “e500v2” with **Book-E Power Architecture (likely e200z6)** where appropriate.
- Treat “MPC5534” as **probable** unless we have SVR/MIDR evidence.

### 9.2 TODO checklist (to fully satisfy SPC chip identification)
1. Locate and parse `models-GW_R7.hex` (3.3 MB) and search for:
   - SVR/PVR read sequences
   - MIDR/SIU ID checks
   - explicit strings mentioning MPC/SPC part number
2. If hardware is available:
   - read JTAG IDCODE and SVR/PVR
   - confirm clock frequency
3. Document actual FlexCAN base addresses + number of controllers from app firmware.

---

## Appendix A: Evidence excerpts

### A.1 Peripheral TLB mapping in early init (R7)
The bootloader builds a TLB entry that maps the peripheral window to `0xC3F00000…`.

### A.2 lwIP and FreeRTOS strings
Strings embedded in bootloader include:

- `RAW_PCB`, `UDP_PCB`, `TCP_PCB`, `tcpip_thread`
- `mainTask`, `blinky`

These support the RTOS + lwIP model seen throughout the project.
