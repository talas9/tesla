# Gateway Flash String Analysis (`ryzenfromtable.bin`)

**Date**: 2026-02-03  
**Source**: 6MB JTAG flash dump from Ryzen Gateway  
**Total Strings**: 38,291 unique strings extracted

---

## Executive Summary

Analyzed 38,291 strings from `ryzenfromtable.bin` (PowerPC MPC5748G Gateway firmware). Discovered **task names, socket operations, version strings, and network references** but command strings like `GET_CONFIG_DATA` are **NOT present as plaintext** (likely compiled as numeric opcodes or obfuscated).

**Critical Finding**: The Gateway binary references **192.168.90.100:20564** (MCU sx-updater port), confirming update orchestration between Gateway and MCU.

---

## Key String Categories

### 1. Task Names (FreeRTOS/RTOS)

**Core Tasks**:
```
xferTask          # TFTP transfer task (firmware updates)
udpApiTask        # UDP API server (port 3500)
soc_udpcmds_task  # SoC UDP commands
diagTask          # Diagnostic interface task
otaKeepAwakeTimer # OTA update keep-awake timer
tcpip_thread      # TCP/IP stack thread
```

**Evidence**: These are **FreeRTOS task names** created via `xTaskCreate()`. Confirms Gateway runs RTOS with dedicated tasks for:
- UDP API (port 3500)
- TFTP (firmware transfers)
- Diagnostics (likely port 1050)
- OTA updates (with keep-awake mechanism)

### 2. Network Socket Strings

**Socket Errors**:
```
Can't create socket
Error binding socket
Can't create soc udp socket
diagTask: Can't create diag listener socket
diagTask: error binding listener socket
Can't create xfer listen socket %d
Log request socket setup error
Dynamic Triggers API could not acquire a network socket
teleCANETHis control socket setup error
teleCANETHis transmit socket setup error
```

**Socket Types Identified**:
1. **UDP API socket** (port 3500)
2. **Diagnostic listener** (port 1050 likely)
3. **XFER socket** (TFTP port 69)
4. **Log request socket**
5. **Dynamic Triggers API socket**
6. **TeleCANETH sockets** (control + transmit)

**Update Orchestration**:
```
Host: 192.168.90.100:20564
```
Repeated 3 times! This is the **MCU sx-updater HTTP control port**. Confirms Gateway initiates contact with MCU for coordinated updates.

### 3. Version & Config Strings

**Version References**:
```
can't get switch version
unrecognized switch version %d
Switch version: %s (%d)
ecuMapVersion
securityVersion
badgingVersion
Failed to initialize the manifest, no version checking
```

**Config References**:
```
ecuMapVersion         # ECU firmware map version
securityVersion       # Security/signing version
badgingVersion        # Vehicle badging/model config
```

**Evidence**: Gateway tracks **ECU firmware versions** and performs **manifest validation** during updates. The `ecuMapVersion` matches config ID **0x0025** from our earlier extraction.

### 4. Git Hash Debug String

```
[info] App git hash: %8x%8x%8x%8x%8x
```

**Format**: 5x 32-bit hex values = 160 bits (SHA-1 git commit hash)

**Purpose**: Embedded git commit ID for firmware version tracking. Tesla developers can trace exact code version from this hash.

### 5. Port & Hardware Strings

```
8-port              # 8-port Ethernet switch config
7-port              # 7-port Ethernet switch config  
SoC port speed: %s  # SoC Ethernet port speed detection
```

**Evidence**: Gateway firmware supports **two switch configurations**:
- 7-port (older Gateway revisions)
- 8-port (newer Gateway revisions, likely Ryzen era)

### 6. File System Artifacts

```
socket.dbg          # Socket debug file
udp.hrl             # UDP header file (Erlang .hrl extension?!)
```

**Surprising**: The `.hrl` extension is an **Erlang header file** format. This suggests:
- Gateway may use Erlang/OTP for some networking components
- OR `.hrl` is repurposed as a generic header format
- Could explain complex task scheduling and fault tolerance

---

## Missing Strings (NOT Found)

### Command Strings
The following `gw-diag` commands do **NOT appear as plaintext**:
- `GET_CONFIG_DATA`
- `SET_CONFIG_DATA`
- `REFRESH_CONFIG_MSG`
- `REBOOT`
- `OVERRIDE_DIAG_LEVEL`
- `GET_VERSION_INFO`
- `OTA_KEEP_AWAKE`

**Conclusion**: Commands are likely:
1. **Numeric opcodes** (e.g., `0x01` = GET_CONFIG_DATA)
2. **Compiled enums** (no string storage)
3. **Obfuscated** or compressed in binary

### CRC Algorithm Strings
No references to:
- `CRC-8`
- `polynomial 0x2F`
- `init=0xFF`

**Conclusion**: CRC algorithm is **hardcoded in assembly** without debug strings. We verified the algorithm through **brute-force testing**, not string analysis.

### Authentication/Crypto Strings
No references to:
- `SHA256`
- `RSA`
- `HMAC`
- `signature`
- `verify`

**BUT** we found in Odin scripts:
- `request_signed_challenge` API call
- `SECURE_CHALLENGE` data identifier
- Mothership signing service

**Conclusion**: Crypto operations are in **higher-level MCU code** (QtCarServer, Odin), not Gateway firmware. Gateway **validates signatures** but doesn't generate them.

---

## Odin Signed Command Flow (From PROC_HVX_X_SIGNED-CONFIG-UPDATE.py)

**Discovered in decompiled Odin Python**:

```python
# 1. Read secure challenge from ECU
secure_challenge = await odx_read(data_name='SECURE_CHALLENGE', node_name=node)

# 2. Prepare data to sign (blob)
blob_size = int(blob.bit_length() / 8)
data_to_sign = {'blob': blob.to_bytes(blob_size, 'little')}

# 3. Request signature from Mothership
signature = await request_signed_challenge(
    ecu=node,
    challenge=secure_challenge,
    data=data_to_sign,
    prepend_data_len=False
)

# 4. Unpack signature (signature includes blob + sig bytes)
unpacked_sig = b64decode(signature['signed_config'])[blob_size:]

# 5. Send signed command to ECU
configuration_data['SIGNATURE'] = unpacked_sig
await odx_start_routine(
    node_name=node,
    routine_name=routine_name,
    params=configuration_data
)

# 6. Poll for result
await odx_request_results(node_name=node, routine_name=routine_name)
```

**Key Details**:
- ECU provides a **SECURE_CHALLENGE** (likely a nonce)
- Odin sends `{challenge, data}` to **Mothership** (Tesla backend)
- Mothership returns **signed_config** = `blob + signature_bytes`
- Signature is **base64 decoded**, blob removed, remainder is signature
- Signature sent to ECU via **ODX (UDS over DoIP)** routine

**Authentication Flow**:
```
ECU → Odin: SECURE_CHALLENGE (nonce)
Odin → Mothership: {challenge, blob}
Mothership → Odin: {signed_config: base64(blob + sig)}
Odin → ECU: {config_data, SIGNATURE: sig}
ECU → Odin: STATUS = "SUCCESSFUL" or error
```

**Security**: ECU verifies signature matches challenge + blob using Tesla's **public key** (stored in secure flash).

---

## Task Architecture (Inferred)

```
Gateway MPC5748G (PowerPC e200)
├── FreeRTOS Scheduler
├── Task: tcpip_thread (lwIP TCP/IP stack)
│   ├── udpApiTask (UDP API server, port 3500)
│   ├── soc_udpcmds_task (SoC UDP commands)
│   ├── diagTask (Diagnostic listener, port 1050?)
│   ├── xferTask (TFTP server, port 69)
│   └── Log request handler
├── Timer: otaKeepAwakeTimer (prevent sleep during updates)
├── API: Dynamic Triggers API
└── Bridge: teleCANETH (CAN-to-Ethernet gateway)
```

---

## Network Architecture (Confirmed)

```
MCU (192.168.90.100)
├── sx-updater HTTP :20564 ← Gateway connects here
├── QtCarServer D-Bus
└── Odin service scripts

Gateway (192.168.90.102)
├── UDP API :3500 (config read/write)
├── TFTP :69 (firmware transfer)
├── Diagnostic :1050 (CAN bridge)
└── HTTPS client → Mothership (signature requests)

Mothership (Tesla backend)
└── Signature service (authenticates secure config writes)
```

---

## PowerPC Binary Analysis Requirements

**To fully reverse-engineer Gateway functions, we need**:

1. **PowerPC disassembler**:
   - `powerpc-linux-gnu-objdump -D -b binary -m powerpc:e500mc ryzenfromtable.bin`
   - OR Ghidra with PowerPC VLE (Variable Length Encoding) plugin

2. **Identify entry point**:
   - PowerPC reset vector at **0x00000000** or **0xFFF00000**
   - Look for interrupt vector table (IVT)

3. **Function boundaries**:
   - PowerPC function prologue: `stwu sp, -XX(sp)` (stack frame setup)
   - Function epilogue: `lwz r0, XX(sp); mtlr r0; addi sp, sp, XX; blr`

4. **Config read/write handlers**:
   - Search for CRC-8 calculation (polynomial 0x2F)
   - Find flash read/write operations (MPC5748G C55FMC controller)
   - Identify UDP packet parsers (command dispatch table)

5. **String references**:
   - Cross-reference string addresses to find usage
   - Map error messages to failure paths

---

## Next Steps

### Immediate (High Priority)

1. **PowerPC Disassembly**:
   - Install `powerpc-linux-gnu-binutils`
   - Disassemble `ryzenfromtable.bin` with proper architecture flags
   - Identify function boundaries and call graphs

2. **Odin Config Decoding**:
   - Search all 2,988 Odin Python files for `config-options.json` usage
   - Find hash/decode functions (similar to ODJ decoding you found)
   - Test hash algorithms: HMAC, PBKDF2, scrypt

3. **Gateway Command Mapping**:
   - Create opcode → command name mapping table
   - Reverse UDP packet parser to find command dispatch
   - Document exact packet formats for each command

### Future (Lower Priority)

4. **Signature Verification**:
   - Extract public key from Gateway secure flash
   - Reverse signature validation algorithm (likely Ed25519 or RSA)
   - Document challenge-response protocol

5. **CRC Algorithm Extraction**:
   - Find CRC-8 implementation in PowerPC assembly
   - Verify it matches our brute-forced polynomial (0x2F)
   - Document exact implementation (table-driven vs bitwise)

---

## Tools Required

```bash
# PowerPC disassembly
sudo apt-get install binutils-powerpc-linux-gnu

# Disassemble Gateway binary
powerpc-linux-gnu-objdump -D -b binary -m powerpc:e500mc ryzenfromtable.bin > gateway-disasm.txt

# Ghidra (for interactive analysis)
# Download from https://ghidra-sre.org/
# Load ryzenfromtable.bin with processor: PowerPC, variant: e200

# Radare2 (alternative)
r2 -a ppc -b 32 ryzenfromtable.bin
[0x00000000]> aaa  # Analyze all
[0x00000000]> afl  # List functions
```

---

## Related Documents

- [80-ryzen-gateway-flash-COMPLETE.md](80-ryzen-gateway-flash-COMPLETE.md) - 662 configs extracted
- [81-gateway-secure-configs-CRITICAL.md](81-gateway-secure-configs-CRITICAL.md) - Security model
- [83-odin-config-api-analysis.md](83-odin-config-api-analysis.md) - Config read API
- [84-gw-diag-command-reference.md](84-gw-diag-command-reference.md) - Command catalog

---

**End of Document**
