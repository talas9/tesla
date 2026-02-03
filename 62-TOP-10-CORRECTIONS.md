# Top 10 Documents Needing Immediate Correction

**Generated:** 2026-02-03


Specific line numbers for uncertain language that needs fixing.


---


## 03-certificate-recovery-orphan-cars.md

**Uncertain phrases found:** 17


**Lines needing correction:**

- Line 17: `6. [Theoretical Recovery Procedures](#6-theoretical-recovery-procedures)`

- Line 90: `| **Used vehicle purchase** | 🟡 Medium | Unknown cert age, may be near expiry |`

- Line 114: `├── car.key              # Private key (CRITICAL, may be TPM-protected)`

- Line 271: `## 6. Theoretical Recovery Procedures`

- Line 316: `# This is THEORETICAL - actual frames would need reverse engineering`

- Line 329: `**Status:** Theoretical; specific CAN frames and updater commands undocumented.`

- Line 407: `**Theoretical Approach:**`

- Line 432: `**Status:** Theoretical; provisioning endpoints likely restricted to factory networks or require special credentials.`

- Line 442: `- Likely to be detected and rejected by Hermes servers`

- Line 461: `**Theoretical Process (UNTESTED):**`

- Line 487: `# (Likely to fail without factory credentials)`

- Line 538: `echo "Vehicle is likely in orphan state - service intervention needed"`

- Line 570: `| **Clock manipulation** | 🔴 High - likely to void |`

- Line 571: `| **Factory reset** | 🔴 High - likely to void |`

- Line 572: `| **CAN flooding** | 🔴 High - likely to void |`


---


## 04-network-ports-firewall.md

**Uncertain phrases found:** 2


**Lines needing correction:**

- Line 525: `- MQTT services (50666, 50877) could be exploited for command injection`

- Line 689: `├─ NAT/Routing (assumed)`


---


## 26-bootloader-exploit-research.md

**Uncertain phrases found:** 1


**Lines needing correction:**

- Line 960: `#   0x02 = Recovery mode (hypothesized)`


---


## 47-gateway-debug-interface.md

**Uncertain phrases found:** 1


**Lines needing correction:**

- Line 7: `**Processor:** Freescale/NXP MPC55xx / SPC5x-class Power Architecture MCU (Book-E; likely e200z6 rather than a general-p`


---


## 48-hardware-architecture.md

**Uncertain phrases found:** 9


**Lines needing correction:**

- Line 15: `This MCU2 generation appears to be a **two‑processor “main board”** that combines:`

- Line 174: `- `gw` is a hostname resolving to the Gateway ECU (likely `192.168.90.102`).`

- Line 208: `- Gateway likely uses SD for:`

- Line 212: `- MCU likely accesses SD-backed *data* only through Gateway-provided services (network API, log extraction, update flows`

- Line 236: `- Recovery/updater terminal likely acts as a constrained frontend to the same underlying update state machine ("gostaged`

- Line 298: `- The config API described in research appears to rely on a **magic unlock token**, which is a weak form of authorizatio`

- Line 341: `**Interpretation (inference):** Recovery/updater terminal likely provides a restricted command interface to the same und`

- Line 393: `### 7.2 How the MCU likely accesses SD-backed data (inference)`

- Line 395: `Because the MCU lacks the physical SD interface, it likely consumes SD-backed artifacts via:`


---


## 23-certificate-chain-analysis.md

**Uncertain phrases found:** 8


**Lines needing correction:**

- Line 331: `- May be TPM-protected (hardware security module)`

- Line 385: `3. `create_additional_csrs()` — Possibly for backup/rollback CSRs`

- Line 397: `**Hypothesized `ShouldRenew()` Logic:**`

- Line 404: `// Threshold likely 30-90 days before expiry`

- Line 577: `# Staging/Engineering (possibly)`

- Line 644: `**Hypothesized Endpoint:**`

- Line 677: `- Likely requires factory/service credentials`

- Line 1194: `echo "ERROR: Checksum mismatch — backup may be corrupted"`


---


## VERIFICATION-STATUS.md

**Uncertain phrases found:** 5


**Lines needing correction:**

- Line 35: `- ⚠️ Packet format hypothesized (not captured)`

- Line 52: `**Line 245:** "Hypothesized packet format"`

- Line 57: `- Mark as THEORETICAL`

- Line 70: `- ❌ THEORETICAL (UNTESTED)`

- Line 75: `- THEORETICAL (untested logic)`


---


## 55-gateway-spc-chip-replacement.md

**Uncertain phrases found:** 5


**Lines needing correction:**

- Line 9: `This document discusses a **hardware-based attack class** (microcontroller replacement + debug access) that could be use`

- Line 57: `- Reading fuse state is usually possible (at least partially) via privileged registers; however, readback may be restric`

- Line 81: `This may be performed by:`

- Line 144: `- There may be additional paired components (external flash/EEPROM/secure element) that complicate swap.`

- Line 145: `- Firmware may be device-bound (unique IDs, key derivation, checksums).`


---


## 43-ape-network-services.md

**Uncertain phrases found:** 7


**Lines needing correction:**

- Line 112: `**Note:** Uses DHCP for IP assignment (likely static DHCP reservation via Gateway/MCU)`

- Line 542: `**Default Policy:** Not explicitly shown - likely **ACCEPT** (permissive default).`

- Line 730: `**Port:** Unknown (not in firewall rules - likely localhost-only)`

- Line 773: `**Mitigation:** Tesla likely uses OpenSSL 1.1.x (not 3.0.x), but version should be verified.`

- Line 785: `**Exploitability:** If service-api-tls supports HTTP/2, it may be vulnerable to DoS attacks.`

- Line 791: `**Version:** Unknown (likely Linux kernel NFS server)`

- Line 1108: `| **sshd** | /usr/sbin/sshd | 22/tcp (likely disabled in prod) | SSH server |`


---

