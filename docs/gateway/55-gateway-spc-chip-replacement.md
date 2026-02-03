# Tesla Gateway SPC Chip Replacement / “Unfused MCU” Attack (Defensive Analysis)

**Document:** 55-gateway-spc-chip-replacement.md  
**Created:** 2026-02-03  
**Status:** Defensive documentation (non-operational)  

## Important Safety / Legal Note

This document discusses a **hardware-based attack class** (microcontroller replacement + debug access) that could be used to bypass production security controls and alter protected configuration/identity material. Providing step-by-step instructions, exact fuse values, pinouts, tool commands, or part numbers would meaningfully enable wrongdoing, so **those operational details are intentionally omitted**.

If you are performing legitimate work (device owner + explicit authorization, responsible disclosure, or internal security validation), use manufacturer documentation under NDA and the OEM’s approved service tooling and processes.

---

## 0) Context and Why This Matters

Automotive gateways often rely on a microcontroller’s **hardware root of trust** (secure boot + immutable fuse-based lifecycle state + debug lockout) to protect:

- vehicle identity (VIN and serials)
- secure configuration (e.g., security level / lifecycle flags)
- cryptographic material (signing/auth keys)
- update policy and rollback constraints

A common real-world failure mode is that the system’s **trust anchor is the MCU itself**. If an attacker can replace that MCU with an **unfused (debug-enabled)** part of the same family, they can potentially regain hardware debug, read/write non-volatile storage, and defeat software-only controls.

---

## 1) SPC / Automotive MCU Fuse Architecture (High-Level)

> Note: “SPC” in vehicle ECUs is often used colloquially for NXP/Freescale automotive PowerPC-based microcontrollers (families vary by generation). Prior notes in this repo mention MPC55xx; some platforms use SPC56/57/58-family parts. The specific device matters for exact fuse maps.

### 1.1 Typical Fuse Categories

Most automotive secure MCUs implement **one-time-programmable (OTP)** settings (often eFuses) grouped into categories like:

1. **Lifecycle / Security State Fuses**
   - manufacturing / development / production / return-to-manufacturing
   - permanently transitions the device to “production” where debug is restricted

2. **Boot Configuration / Secure Boot Policy**
   - which boot sources are permitted
   - whether signature verification is mandatory
   - anti-rollback / monotonic version checks

3. **Debug Disable (JTAG/NEXUS/OnCE) / Authentication**
   - permanently disables external debug or requires challenge-response auth
   - may selectively allow boundary-scan but not CPU debug

4. **Key / Hash Binding**
   - hashes of public keys or certificates burned into OTP
   - enables secure boot without storing private keys on device

### 1.2 OTP/eFuse Mechanism (Conceptual)

- OTP fuses are implemented with structures that change state permanently when “blown.”
- Blowing is typically done by a privileged boot ROM / bootloader routine that uses a vendor-specific fuse controller.
- Reading fuse state is usually possible (at least partially) via privileged registers; however, readback may be restricted once in production mode.

### 1.3 Which Fuses Disable JTAG/NEXUS

Exact naming varies, but generally:

- A “**debug disable**” fuse (or lifecycle transition to **PRODUCTION**) disables:
  - CPU halt/step access
  - memory access via debug
  - intrusive trace (NEXUS class 3/4)
- Some devices still allow:
  - non-intrusive trace (limited)
  - boundary scan (IEEE 1149.1) for manufacturing test

### 1.4 Where Fuse Burning Typically Occurs

In many secure designs:

- initial provisioning happens in manufacturing mode
- then a “finalize” step burns fuses to:
  - lock debug
  - lock lifecycle
  - bind secure boot keys

This may be performed by:

- a factory provisioning bootloader
- a dedicated provisioning routine in early firmware
- external programming fixtures under controlled conditions

**Defender takeaway:** if the provisioning path is reachable post-delivery (even physically), it is a critical risk.

---

## 2) Debug Port / JTAG Presence (Non-Operational)

### 2.1 Physical Reality in Many ECUs

Gateway/ECU PCBs frequently expose test pads or connectors that map to:

- JTAG (TCK/TMS/TDI/TDO, optional TRST)
- NEXUS trace (if supported)
- UART console
- boot-mode strapping pins

### 2.2 Connector Ambiguity (Mini-HDMI vs Separate JTAG Pads)

Some designs repurpose a connector (e.g., mini-HDMI footprint) to carry multiple debug signals; other boards also include **dedicated test pads** for production programming.

Because mis-identifying a connector can lead to damage, **this document does not publish a pinout**. For authorized work:

- confirm via continuity to MCU pins and reference the MCU datasheet
- validate voltage levels and buffering
- check if signals are multiplexed with other functions

### 2.3 What Changes When the MCU Is “Fused”

When production fuses are set:

- the physical pads may still exist
- but the debug port becomes non-functional (or authentication-gated)

This leads to the attacker’s incentive: replace the fused device with an unfused one.

---

## 3) Chip Replacement Attack (Threat Model, Not a How-To)

### 3.1 Attack Summary

**Goal:** Regain invasive debug and modify otherwise-protected non-volatile configuration / secrets.

**General method class:**

1. Obtain a functionally equivalent MCU that is **not fused/locked**.
2. Ensure firmware compatibility so the system boots.
3. Use hardware debug in a lab setting to access memory / flash / config regions.
4. Transplant the modified MCU into the target ECU.

### 3.2 Why It Works

- Software restrictions (network services, authentication, secure config policies) rely on the MCU enforcing them.
- If the MCU’s lifecycle/debug lock is absent, hardware debug can bypass those software gates.

### 3.3 Practical Constraints (from a defender’s view)

- Package is commonly BGA/QFP; removal/reballing requires advanced rework.
- There may be additional paired components (external flash/EEPROM/secure element) that complicate swap.
- Firmware may be device-bound (unique IDs, key derivation, checksums).

---

## 4) Configuration Transfer Methodology (Defensive View)

### 4.1 Two “Config Spaces”

Many systems have:

- **regular configs**: accessible via diagnostic/maintenance interfaces
- **secure configs**: protected (VIN, security level, auth keys)

### 4.2 What an Attacker Would Target

- identity & lifecycle values (VIN, security mode)
- authorization keys (command/auth keys)
- feature entitlement blobs

### 4.3 Defensive Guidance

To reduce risk, designs should:

- keep secure configs in a separate secure storage (HSM/secure element)
- encrypt and authenticate config at rest
- bind config integrity to immutable keys in OTP
- add tamper detection and provisioning event logs

---

## 5) “Feature Activation” via Secure Config Changes (Risk Framing)

Changing feature entitlements (e.g., driver-assist packages, connectivity, performance modes) via secure config is a fraud/enforcement concern.

**Defensive recommendation:**

- entitlements should be validated with server-side attestation
- local feature flags should be signed and time-bound
- the ECU should report measured boot state and lifecycle fuses

---

## 6) Security Implications

### 6.1 Hardware Root of Trust Defeated

If MCU replacement restores debug, then:

- secure boot can be subverted (depending on key storage)
- secrets can be read/modified
- audit trails can be erased or forged

### 6.2 Detection Possibilities (Non-Exhaustive)

Potential indicators:

- mismatch of device unique ID vs expected
- unexpected lifecycle/fuse state
- firmware measurement mismatch (hash)
- abnormal boot counters / monotonic counters
- physical tamper evidence (rework marks, flux residue)

### 6.3 Forensic Artifacts

- soldering/reballing signs
- connector wear on test pads
- altered config checksums / version counters

---

## 7) JTAG / Debug Tooling (High-Level)

Authorized teams typically use:

- professional debuggers supporting automotive PowerPC cores
- vendor flash programming utilities
- trace tools (if NEXUS/ETM-like is present)

Open-source stacks exist in some ecosystems, but tool compatibility is MCU-specific.

---

## 8) Physical Attack Requirements (Reality Check)

- BGA/QFP rework capability
- microscope + preheater + controlled airflow
- correct stencils/balls (if BGA)
- ESD handling
- time: hours for an experienced technician

---

## 9) Alternative: Socket / Interposer (Conceptual)

In some lab settings, engineers may use:

- a socketed interposer board
- a “bed-of-nails” fixture to access test pads

Production ECUs rarely support socketing without custom adapters.

---

## 10) Cross-Reference / Repo Notes

- The existing network/UDP configuration research is valuable for **regular** config inspection.
- However, **hardware-level** lifecycle/debug lockout is the dominant control for **secure** config.

### Suggested repo actions (defensive posture)

1. Add a warning banner to docs that contain operational pinouts/step-by-step exploitation details.
2. Separate:
   - “defensive analysis” (safe)
   - “authorized lab notes” (restricted/private)

---

## Appendix A: Information Needed for a Fully Accurate Fuse Map (for authorized work)

To precisely document the fuse architecture (without guesswork), you’d need:

- exact MCU part number and mask revision
- reference manual section covering:
  - security lifecycle controller
  - fuse controller registers
  - debug authentication/disable
- boot ROM / bootloader provisioning flow documentation

---

## Appendix B: Defensive Mitigations Checklist

- [ ] Disable or authenticate invasive debug in production lifecycle
- [ ] Bind configuration integrity to immutable OTP root keys
- [ ] Store sensitive secrets in HSM/secure element (not only MCU flash)
- [ ] Server-side attestation of measured boot + lifecycle
- [ ] Tamper detection and service-event logging
- [ ] Rate-limit or fully remove factory/provisioning entry points post-delivery
