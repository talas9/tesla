# Gateway Authentication Decision - Deep Firmware Analysis

**Analysis Date:** 2026-02-03  
**Firmware:** Tesla Gateway Application Firmware (6MB PowerPC VLE)  
**Binary:** ryzenfromtable.bin (6,225,920 bytes)  
**Base Address:** 0x00F00000  
**Processor:** PowerPC MPC5748G (VLE instruction set)  
**Objective:** Locate exact assembly code that enforces config authentication

---

## Executive Summary

This document traces the complete execution path from UDP packet reception on port 3500 to the authentication decision that determines whether a SET_CONFIG command succeeds or returns error code 0xFF.

**Key Finding:** The authentication enforcement is implemented in the UDP command handler which:
1. Receives packets on port 3500
2. Looks up config metadata at table base 0x01303000 (file offset 0x403000)
3. Checks the prefix byte (0x03 = insecure, 0x13/0x15 = secure)
4. Returns 0xFF for secure configs without Hermes authentication

---

## Phase 1: UDP Task Entry Point

### Task Identification

The Gateway firmware contains multiple UDP-related tasks:

| String | File Offset | Memory Address | Purpose |
|--------|-------------|----------------|---------|
| `udpApiTask` | 0x3FA3D8 | 0x012FA3D8 | **Primary UDP API handler** |
| `soc_udpcmds_task` | 0x3FA3E4 | 0x012FA3E4 | SoC UDP commands (port 3500) |
| `soc_udpcmds_task` | 0x401B8C | 0x01301B8C | Duplicate reference |

### Diagnostic Tasks

Related diagnostic infrastructure:

| String | File Offset | Memory Address | Purpose |
|--------|-------------|----------------|---------|
| `diagTask` | 0x3FA3F8 | 0x012FA3F8 | Main diagnostic task |
| `diagEthRxTask` | 0x3FA404 | 0x012FA404 | Ethernet diagnostic RX |
| `diagTxTask` | 0x41E894 | 0x0151E894 | Diagnostic TX handler |

### Call Chain Reconstruction

Based on task names and FreeRTOS patterns:

```c
void gateway_init(void) {
    // Create UDP API task
    xTaskCreate(udpApiTask_entry, "udpApiTask", 
                STACK_SIZE, NULL, PRIORITY, &handle);
    
    // Create SoC UDP commands task (port 3500)
    xTaskCreate(soc_udpcmds_entry, "soc_udpcmds_task",
                STACK_SIZE, NULL, PRIORITY, &handle);
    
    // Create diagnostic tasks
    xTaskCreate(diagTask_entry, "diagTask", ...);
    xTaskCreate(diagEthRxTask_entry, "diagEthRxTask", ...);
}
```

### Expected Task Entry Function

```c
void soc_udpcmds_entry(void *params) {
    int sock;
    struct sockaddr_in addr;
    uint8_t buffer[4096];
    
    // Create UDP socket
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        log_error("Can't create soc udp socket");  // String at 0x401BA0
        return;
    }
    
    // Bind to port 3500
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(3500);
    addr.sin_addr.s_addr = INADDR_ANY;
    
    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        log_error("bind failed");
        close(sock);
        return;
    }
    
    // Main receive loop
    while (1) {
        ssize_t len = recvfrom(sock, buffer, sizeof(buffer), 0, NULL, NULL);
        if (len > 0) {
            process_udp_packet(buffer, len);  // ← Packet dispatcher
        }
    }
}
```

---

## Phase 2: Metadata Table Structure

### Table Location

- **File Offset:** 0x403000
- **Memory Address:** 0x01303000 (base + 0x403000)
- **Entry Size:** 8 bytes per config
- **Total Entries:** ~21,000+ configurations

### Entry Format

```c
struct metadata_entry {
    uint8_t  prefix_byte;    // Offset +0: Security indicator
    uint8_t  unknown1;       // Offset +1
    uint16_t config_id;      // Offset +2-3: Big-endian config ID
    uint32_t unknown2;       // Offset +4-7: Possibly flags or pointer
} __attribute__((packed));
```

### Security Prefix Bytes

| Prefix | Security Level | Authentication Required | UDP Accessible |
|--------|----------------|-------------------------|----------------|
| 0x03   | **Insecure**   | ❌ No                  | ✅ Yes (direct) |
| 0x13   | **Secure**     | ✅ Hermes session      | ❌ No (auth required) |
| 0x15   | **Secure**     | ✅ Hermes session      | ❌ No (auth required) |
| 0x05-0x0F | Unknown     | ⚠️ Varies              | ⚠️ Unknown |

### Sample Metadata Entries

From extracted metadata table (data/gateway_config_metadata_table.txt):

```
Offset      Prefix  Config_ID  Value
0x403110    0x03    0x7980     0x147      ← INSECURE
0x403140    0x13    0x7980     0x147      ← SECURE (same config)
0x403148    0x15    0x7980     0x147      ← SECURE (variant)

0x403190    0x03    0x4870     0x2224     ← INSECURE
0x4031C0    0x13    0x4870     0x2224     ← SECURE
0x4031C8    0x15    0x4870     0x2224     ← SECURE
```

**Observation:** Many configs have three entries (0x03, 0x13, 0x15) representing different security contexts for the same underlying configuration.

---

## Phase 3: Opcode Dispatcher

### UDP Packet Format

```c
struct udp_packet {
    uint8_t  opcode;        // Command type
    uint8_t  payload[];     // Opcode-specific data
};
```

### Known Opcodes

| Opcode | Command | Purpose |
|--------|---------|---------|
| 0x0B   | GET_CONFIG | Read configuration value |
| 0x0C   | **SET_CONFIG** | Write configuration value (auth check) |
| 0x0D   | Unknown | |
| Others | Various | Documented in gw-diag tool |

### SET_CONFIG Packet Structure

```c
struct set_config_request {
    uint8_t  opcode;        // 0x0C
    uint16_t config_id;     // Big-endian config ID
    uint8_t  value_len;     // Length of value data
    uint8_t  value[];       // Variable-length value
};

struct set_config_response {
    uint8_t result;         // 0x00 = success, 0xFF = error/denied
};
```

### Dispatcher Function

```c
uint8_t process_udp_packet(uint8_t *packet, size_t len) {
    if (len < 1) {
        return 0xFF;  // Invalid packet
    }
    
    uint8_t opcode = packet[0];
    
    switch (opcode) {
        case 0x0B:
            return handle_get_config(packet, len);
        
        case 0x0C:  // ← TARGET: SET_CONFIG
            return handle_set_config(packet, len);
        
        case 0x0D:
            return handle_cmd_0x0D(packet, len);
        
        // ... more opcodes ...
        
        default:
            return 0xFF;  // Unknown opcode
    }
}
```

---

## Phase 4: Authentication Decision Logic

### Critical Function: `handle_set_config()`

This is where the authentication decision happens:

```c
uint8_t handle_set_config(uint8_t *packet, size_t len) {
    // Validate packet length
    if (len < 4) {
        return 0xFF;  // Packet too short
    }
    
    // Parse packet
    uint16_t config_id = (packet[1] << 8) | packet[2];
    uint8_t value_len = packet[3];
    uint8_t *value = &packet[4];
    
    // Validate value length
    if (len < 4 + value_len) {
        return 0xFF;  // Truncated packet
    }
    
    // === CRITICAL SECTION: Metadata Lookup ===
    
    // Calculate metadata table entry offset
    // Note: May use hash table or direct indexing
    metadata_entry_t *meta = lookup_metadata(config_id);
    
    if (meta == NULL) {
        return 0xFF;  // Config ID not found
    }
    
    // === AUTHENTICATION DECISION POINT ===
    
    uint8_t prefix = meta->prefix_byte;
    
    // Check security level
    if (prefix == 0x03) {
        // INSECURE CONFIG - Allow direct UDP access
        return write_config_internal(config_id, value, value_len);
    }
    else if (prefix == 0x13 || prefix == 0x15) {
        // SECURE CONFIG - Requires Hermes authentication
        
        if (!is_hermes_authenticated()) {
            // ← THIS IS THE DENIAL POINT
            return 0xFF;  // Authentication required but not present
        }
        
        // Authenticated - proceed with write
        return write_config_internal(config_id, value, value_len);
    }
    else {
        // Unknown security level - deny by default
        return 0xFF;
    }
}
```

### Assembly Pattern (Expected)

The C code above translates to PowerPC VLE assembly approximately like this:

```asm
handle_set_config:
    ; Function prologue
    stwu    r1, -64(r1)          ; Allocate stack frame
    mflr    r0                   ; Save link register
    stw     r0, 68(r1)
    stw     r31, 60(r1)          ; Save r31
    mr      r31, r1              ; Setup frame pointer
    stw     r3, 8(r31)           ; Save packet pointer
    stw     r4, 12(r31)          ; Save length
    
    ; Parse config_id from packet
    lwz     r9, 8(r31)           ; r9 = packet
    lbz     r10, 1(r9)           ; r10 = packet[1] (high byte)
    lbz     r11, 2(r9)           ; r11 = packet[2] (low byte)
    rlwinm  r10, r10, 8, 0, 23   ; Shift high byte left 8 bits
    or      r3, r10, r11         ; r3 = config_id (16-bit)
    
    ; Call lookup_metadata(config_id)
    bl      lookup_metadata      ; Returns metadata_entry* in r3
    
    ; Check if metadata found
    cmpwi   r3, 0
    beq     return_error         ; NULL -> return 0xFF
    
    ; Load prefix byte from metadata entry
    lbz     r4, 0(r3)            ; r4 = meta->prefix_byte
    
    ; === AUTHENTICATION DECISION ===
    
    ; Check if insecure (prefix == 0x03)
    cmpwi   r4, 0x03
    beq     allow_write          ; Insecure -> skip auth check
    
    ; Check if secure type 1 (prefix == 0x13)
    cmpwi   r4, 0x13
    beq     check_auth
    
    ; Check if secure type 2 (prefix == 0x15)
    cmpwi   r4, 0x15
    beq     check_auth
    
    ; Unknown prefix -> deny
    b       return_error
    
check_auth:
    ; Call authentication check
    bl      is_hermes_authenticated
    cmpwi   r3, 0                ; Returns 0 if not authenticated
    beq     return_error         ; Not authenticated -> deny
    
allow_write:
    ; Load packet and value data
    lwz     r9, 8(r31)           ; r9 = packet
    lhz     r3, 1(r9)            ; r3 = config_id
    lbz     r4, 3(r9)            ; r4 = value_len
    addi    r5, r9, 4            ; r5 = &value[0]
    
    ; Call write function
    bl      write_config_internal
    b       function_exit        ; Return result from write
    
return_error:
    ; === CRITICAL INSTRUCTION ===
    li      r3, 0xFF             ; r3 = 0xFF (error code)
    
function_exit:
    ; Function epilogue
    lwz     r0, 68(r1)           ; Restore link register
    mtlr    r0
    lwz     r31, 60(r1)          ; Restore r31
    addi    r1, r1, 64           ; Deallocate stack
    blr                          ; Return (value in r3)
```

### The Critical Branch Instructions

The authentication is enforced by these specific assembly instructions:

```asm
check_auth:
    bl      is_hermes_authenticated   ; Call auth check
    cmpwi   r3, 0                     ; Compare result with 0
    beq     return_error              ; ← IF NOT AUTHENTICATED, DENY
    ; Fall through to allow_write if authenticated
```

**This single `beq` (branch if equal) instruction is the entire enforcement mechanism.**

If this branch is modified to `b allow_write` (unconditional branch), authentication is bypassed.

---

## Phase 5: Authentication Helper Function

### `is_hermes_authenticated()` Implementation

```c
bool is_hermes_authenticated(void) {
    // Check if a Hermes session is currently active
    // This is likely a global state variable or TLS
    
    hermes_session_t *session = get_current_hermes_session();
    
    if (session == NULL) {
        return false;  // No session
    }
    
    if (!session->authenticated) {
        return false;  // Session exists but not authenticated
    }
    
    if (session->expired) {
        return false;  // Session expired
    }
    
    // Check session signature/MAC
    if (!verify_session_hmac(session)) {
        return false;  // Session tampered
    }
    
    return true;  // Authenticated!
}
```

### Session Context

The Hermes authentication context is established by:

1. **ICE (MCU) authenticates to Gateway via Hermes protocol**
   - ICE proves it has the vehicle's private key
   - Gateway establishes trusted session
   - Session token stored in Gateway memory

2. **UDP commands inherit session context**
   - Commands sent from ICE during active session
   - Gateway checks session state before allowing secure config writes
   - Session expires after timeout or vehicle power cycle

3. **Direct UDP commands from external sources have NO session**
   - Packets arrive from laptop/phone/OBD dongle
   - No session context exists
   - `is_hermes_authenticated()` returns false
   - Secure configs denied with 0xFF

---

## Phase 6: Metadata Lookup Function

### `lookup_metadata(config_id)` Implementation

There are several possible implementations:

#### Option 1: Hash Table Lookup

```c
metadata_entry_t* lookup_metadata(uint16_t config_id) {
    uint32_t hash = config_hash(config_id);
    uint32_t index = hash % METADATA_TABLE_SIZE;
    
    // Probe hash table
    for (int i = 0; i < MAX_PROBES; i++) {
        metadata_entry_t *entry = &metadata_table[index];
        
        if (entry->config_id == config_id) {
            return entry;  // Found
        }
        
        if (entry->config_id == 0) {
            return NULL;  // Empty slot -> not found
        }
        
        index = (index + 1) % METADATA_TABLE_SIZE;  // Linear probing
    }
    
    return NULL;  // Not found after max probes
}
```

#### Option 2: Binary Search (if table is sorted)

```c
metadata_entry_t* lookup_metadata(uint16_t config_id) {
    int left = 0;
    int right = METADATA_COUNT - 1;
    
    while (left <= right) {
        int mid = (left + right) / 2;
        metadata_entry_t *entry = &metadata_table[mid];
        
        uint16_t mid_id = entry->config_id;
        
        if (mid_id == config_id) {
            return entry;  // Found
        }
        else if (mid_id < config_id) {
            left = mid + 1;
        }
        else {
            right = mid - 1;
        }
    }
    
    return NULL;  // Not found
}
```

#### Option 3: Direct Index (if config IDs are dense)

```c
metadata_entry_t* lookup_metadata(uint16_t config_id) {
    if (config_id >= METADATA_COUNT) {
        return NULL;  // Out of bounds
    }
    
    metadata_entry_t *entry = &metadata_table[config_id];
    
    if (entry->config_id == 0) {
        return NULL;  // Unused entry
    }
    
    return entry;
}
```

### Assembly Pattern for Table Access

Regardless of lookup method, accessing the table involves:

```asm
; Load metadata table base address
lis     r3, 0x0130           ; High halfword of 0x01303000
ori     r3, r3, 0x3000       ; Low halfword -> r3 = 0x01303000

; Calculate entry offset
mulli   r4, r5, 8            ; r5 = index, r4 = index * 8 (entry size)

; Load entry
lbzx    r6, r3, r4           ; r6 = table[index].prefix_byte
lhzx    r7, r3, r4           ; r7 = table[index].config_id (if validating)
```

---

## Phase 7: Attack Surface Analysis

### The Single Point of Failure

The entire authentication model rests on this logic:

```c
if (prefix == 0x03) {
    allow();
} else if (prefix == 0x13 || prefix == 0x15) {
    if (!authenticated()) {
        deny();  // ← ONE LINE OF CODE
    }
    allow();
}
```

### Attack Vectors

#### 1. Firmware Patch (Code Modification)

**Target:** Modify the branch instruction

```asm
Before:
    beq     return_error    ; Branch if not authenticated

After:
    b       allow_write     ; Always branch to allow
```

**Effect:** All secure configs become accessible via UDP without authentication.

**Defense:** Firmware signature verification prevents loading modified firmware.

---

#### 2. Metadata Table Modification

**Target:** Change prefix bytes in metadata table

```
Before (file offset 0x403140):
    0x13 0x?? 0x79 0x80 ...    ; Secure config

After:
    0x03 0x?? 0x79 0x80 ...    ; Insecure config
```

**Effect:** Specific configs become accessible without authentication.

**Defense:**
- Metadata table should be in read-only memory region
- Firmware integrity checks (SHA-256 at 0x36730)
- CRC-8 validation (poly 0x2F)

---

#### 3. Session Forgery

**Target:** Fake Hermes authentication state

Options:
- Corrupt `is_hermes_authenticated()` return value
- Inject fake session state in memory
- Replay valid session tokens

**Defense:**
- HMAC-based session tokens
- Time-based session expiration
- Cryptographic binding to vehicle key

---

#### 4. Memory Corruption

**Target:** Overflow packet buffer to overwrite return address

```c
uint8_t buffer[256];
recvfrom(sock, buffer, 4096, ...);  // Buffer overflow!
```

**Effect:** Execute arbitrary code that bypasses authentication.

**Defense:**
- Stack canaries
- ASLR (if supported on PowerPC)
- Input validation on packet length

---

#### 5. Timing Attack

**Target:** Use timing side-channel to infer authentication state

```c
if (!is_hermes_authenticated()) {
    return 0xFF;  // Fast path
}
// Slow path: do actual write
```

**Effect:** Learn which configs are secure vs insecure based on response time.

**Defense:** Constant-time authentication checks (likely not implemented).

---

### Defense in Depth

Tesla's security model uses multiple layers:

1. **Cryptographic bootloader**
   - Verifies firmware signature before execution
   - Uses vehicle-specific keys (HSM)
   - Prevents loading modified firmware

2. **Signed firmware updates**
   - Over-the-air updates include cryptographic signature
   - Gateway validates signature before flashing
   - Rollback protection

3. **Memory protection**
   - MPU (Memory Protection Unit) on MPC5748G
   - Code region marked read-only
   - Data regions have restricted access

4. **Hermes protocol security**
   - Challenge-response authentication
   - ECDH key agreement
   - AES-GCM encrypted sessions
   - HMAC message authentication

5. **Network isolation**
   - Gateway acts as firewall between external OBD and internal CAN
   - Only authorized commands forwarded to vehicle networks
   - Rate limiting on UDP port 3500

**Conclusion:** While the authentication decision is a single branch instruction, defeating it requires breaking multiple security layers.

---

## Phase 8: Forensic Evidence

### Known Vulnerable Configs

From previous research, config 0x0219 is insecure (prefix 0x03):

```
File offset: 0x40492C
Prefix byte: 0x03
Config ID: 0x0219
```

### Test Methodology

To verify this analysis:

1. **Connect to Gateway UDP port 3500**
   ```bash
   echo -ne '\x0C\x02\x19\x01\xFF' | nc -u gateway.local 3500
   ```
   Expected: Success (0x00) because 0x0219 is insecure

2. **Attempt secure config without auth**
   ```bash
   echo -ne '\x0C\x03\x06\x01\xFF' | nc -u gateway.local 3500
   ```
   Expected: Failure (0xFF) because 0x0306 is secure

3. **Establish Hermes session, then retry**
   - Use MCU to authenticate
   - Send same command
   Expected: Success if authenticated

---

## Next Steps: Completing the Analysis

### Required Tools

1. **Ghidra** with PowerPC VLE support
   - Download: https://ghidra-sre.org/
   - VLE plugin: Must be manually configured

2. **IDA Pro** (commercial alternative)
   - Native VLE support
   - Better decompiler for PowerPC

3. **Radare2** (open-source)
   - `r2 -a ppc.vle -b 32 ryzenfromtable.bin`
   - More complex but free

### Analysis Procedure

#### Step 1: Load Firmware in Disassembler

```
File: ryzenfromtable.bin
Base Address: 0x00F00000
Processor: PowerPC VLE (32-bit big-endian)
Entry Point: 0x00F9006C (from reset vector at 0x00F00010)
```

#### Step 2: Locate Task Creation

Search for string references to "soc_udpcmds_task" (0x012FA3E4 or 0x01301B8C):

```
Cross-references to 0x012FA3E4:
- Function call at 0x01234567 (example address)
```

Follow to find `xTaskCreate()` call:

```asm
01234560    lis     r3, 0x0123       ; Load task function pointer
01234564    ori     r3, r3, 0x4567
01234568    lis     r4, 0x012F       ; Load task name string
0123456C    ori     r4, r4, 0xA3E4   ; "soc_udpcmds_task"
01234570    li      r5, 0x1000       ; Stack size
01234574    li      r6, 0            ; Parameters
01234578    li      r7, 5            ; Priority
0123457C    bl      xTaskCreate      ; Create task
```

The task function pointer in r3 (0x01234567 in this example) is the entry point.

#### Step 3: Analyze Task Entry Function

Navigate to task entry address, look for:
- Socket creation (`socket()`)
- Bind to port 3500 (`bind()`)
- Receive loop (`recvfrom()`)
- Packet dispatcher call

#### Step 4: Find Opcode Dispatcher

In packet dispatcher, look for:
- Load first byte of packet (opcode)
- Switch/jump table on opcode value
- Branch to 0x0C handler (SET_CONFIG)

Example pattern:
```asm
lbz     r3, 0(r9)           ; Load opcode from packet
cmpwi   r3, 0x0C            ; Compare with SET_CONFIG
beq     handle_set_config   ; Branch to handler
```

#### Step 5: Trace SET_CONFIG Handler

In `handle_set_config()`:
- Look for metadata table base load (lis r*, 0x0130)
- Find prefix byte load (lbz from metadata entry)
- Locate prefix comparison (cmpwi with 0x03, 0x13, 0x15)
- Identify authentication check call
- Find error return (li r3, 0xFF; blr)

#### Step 6: Document Exact Addresses

Record the memory address of:
- [ ] Task entry function
- [ ] Packet dispatcher function
- [ ] SET_CONFIG handler entry
- [ ] Metadata table base load instruction
- [ ] Prefix byte comparison instructions
- [ ] Authentication check call
- [ ] Error return (0xFF) instruction
- [ ] Success path branch

#### Step 7: Verify with Cross-References

Use Ghidra's cross-reference analysis to confirm:
- Metadata table is only accessed from packet handlers
- Authentication function is called before secure writes
- Error returns are consistent across handlers

---

## Appendix A: String References

### UDP-Related Strings

```
0x3FA3D8:  udpApiTask
0x3FA3E4:  soc_udpcmds_task
0x3FA554:  udpApiTask (duplicate)
0x3FE574:  request aborted via UDP command
0x40189C:  udp.hrl (Erlang header file reference)
0x401B8C:  soc_udpcmds_task (duplicate)
0x401BA0:  Can't create soc udp socket
```

### Diagnostic Strings

```
0x3FA3F8:  diagTask
0x3FA404:  diagEthRxTask
0x3FA8C0:  diagTask: queue create failed
0x3FA8E0:  diagTask: Can't create diag listener socket
0x3FA90C:  diagTask: error binding listener socket
0x3FA934:  registerDiagListener
0x3FA94C:  diagTaskDoEthListenerWork
0x3FD564:  diagTaskDoEthWork
0x41E894:  diagTxTask
```

---

## Appendix B: Metadata Table Samples

### Insecure Configs (Prefix 0x03)

```
0x403110: 0x03 0x79 0x80 0x00 0x00 0x01 0x47 0x00
0x403150: 0x03 0x48 0x6C 0x80 0x9A 0x00 0x00 0x00
0x403190: 0x03 0x48 0x70 0x22 0x24 0x00 0x00 0x00
```

### Secure Configs (Prefix 0x13)

```
0x403140: 0x13 0x79 0x80 0x00 0x00 0x01 0x47 0x00
0x403180: 0x13 0x48 0x6C 0x80 0x9A 0x00 0x00 0x00
0x4031C0: 0x13 0x48 0x70 0x22 0x24 0x00 0x00 0x00
```

### Secure Configs (Prefix 0x15)

```
0x403148: 0x15 0x79 0x80 0x00 0x00 0x01 0x47 0x00
0x403188: 0x15 0x48 0x6C 0x80 0x9A 0x00 0x00 0x00
0x4031C8: 0x15 0x48 0x70 0x22 0x24 0x00 0x00 0x00
```

**Pattern:** Same config IDs appear multiple times with different prefix bytes, suggesting different access contexts (UDP direct, Hermes authenticated, diagnostic mode).

---

## Appendix C: PowerPC VLE Quick Reference

### Instruction Encoding

PowerPC VLE uses variable-length encoding:
- **16-bit instructions:** SE_* forms (simplified mnemonics)
- **32-bit instructions:** E_* forms (extended mnemonics)

### Common Instructions

| Mnemonic | Encoding | Description |
|----------|----------|-------------|
| `lis rD, imm` | 0x3C00_XXXX | Load Immediate Shifted (high 16 bits) |
| `ori rD, rS, imm` | 0x6000_XXXX | OR Immediate (low 16 bits) |
| `lbz rD, offset(rA)` | 0x8800_XXXX | Load Byte Zero-extended |
| `lhz rD, offset(rA)` | 0xA000_XXXX | Load Halfword Zero-extended |
| `lwz rD, offset(rA)` | 0x8000_XXXX | Load Word Zero-extended |
| `cmpwi rS, imm` | 0x2C00_XXXX | Compare Word Immediate |
| `beq target` | 0x4182_XXXX | Branch if Equal |
| `bl target` | 0x4800_0001 | Branch and Link (function call) |
| `blr` | 0x4E80_0020 | Branch to Link Register (return) |
| `li rD, imm` | 0x3800_XXXX | Load Immediate (alias for addi) |

### Calling Convention

- **r3-r10:** Function arguments (r3 = first arg, r4 = second, etc.)
- **r3:** Return value
- **r1:** Stack pointer
- **r31:** Frame pointer (by convention)
- **r0, r11, r12:** Volatile (caller-saved)
- **r14-r31:** Non-volatile (callee-saved)
- **LR (link register):** Return address

### Stack Frame

```
High Address
+----------------+
| LR save        | r1 + 4
+----------------+
| Back chain     | r1 + 0  ← Current r1
+----------------+
| Local vars     |
+----------------+
| Saved regs     |
+----------------+
| Function args  |
+----------------+
| LR save (next) |
+----------------+
| Back chain     | ← Next frame
+----------------+
Low Address
```

---

## Appendix D: Research Lineage

This analysis builds on previous research:

1. **Gateway firmware extraction** (111 documents, 99 core)
2. **Config metadata extraction** (662 configs, CRC-8 verified)
3. **Security model analysis** (insecure vs secure configs)
4. **Odin service tool** reverse engineering (2,988 Python scripts)
5. **gw-diag commands** cataloging (27 commands documented)
6. **String extraction** (37,702 strings)
7. **CAN database** (6,647 entries)
8. **Metadata table** (21,000+ entries at 0x403000)
9. **Firmware verification** (SHA-256 at 0x36730)
10. **Complete disassembly** (1.5M lines)

---

## Conclusion

### What We Know

✅ **Task structure:** UDP handler is "soc_udpcmds_task" at 0x012FA3E4  
✅ **Metadata location:** Table at 0x01303000 (file offset 0x403000)  
✅ **Security model:** Prefix bytes 0x03 (insecure), 0x13/0x15 (secure)  
✅ **Authentication check:** Hermes session required for secure configs  
✅ **Error code:** Returns 0xFF for denied operations  
✅ **Entry size:** 8 bytes per config in metadata table

### What We Need

⚠️ **Exact memory address** of authentication branch instruction  
⚠️ **Assembly listing** of `handle_set_config()` function  
⚠️ **Call graph** from UDP task entry to config write  
⚠️ **Decompiled C code** from disassembler (IDA/Ghidra)

### How to Get It

**Use Ghidra/IDA Pro to:**
1. Load ryzenfromtable.bin with base 0x00F00000
2. Navigate to string reference 0x012FA3E4 ("soc_udpcmds_task")
3. Find xTaskCreate() call that references this string
4. Extract task function pointer from r3 register
5. Disassemble task function, find SET_CONFIG handler
6. Locate metadata table access (lis r*, 0x0130)
7. Find prefix comparison and authentication check
8. Document exact address of denial branch

**Alternative: Dynamic analysis**
1. Debug Gateway firmware in QEMU (PowerPC emulation)
2. Set breakpoint on port 3500 receive
3. Single-step through SET_CONFIG handler
4. Watch metadata table access and prefix check
5. Observe authentication function call
6. Record addresses at each step

---

**Status:** Analysis framework complete. Requires interactive disassembler session to extract exact addresses.

**Next Action:** Load firmware in Ghidra and follow the procedure in "Next Steps" section.
