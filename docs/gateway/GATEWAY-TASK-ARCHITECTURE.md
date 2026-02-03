# Gateway Task Architecture & Authentication Context

**Analysis Date:** 2026-02-03  
**Firmware:** Tesla Gateway Application (ryzenfromtable.bin, 6MB)  
**Focus:** Task structure and authentication context propagation

---

## Task Hierarchy

### Primary Network Tasks

The Gateway firmware runs multiple FreeRTOS tasks for different network interfaces:

```
gateway_main()
  │
  ├─> udpApiTask (0x3FA3D8)
  │     └─> Primary UDP API handler
  │
  ├─> soc_udpcmds_task (0x3FA3E4)
  │     └─> SoC UDP commands (port 3500)
  │           ├─> handle_get_config() [opcode 0x0B]
  │           ├─> handle_set_config() [opcode 0x0C] ← AUTH CHECK
  │           └─> handle_cmd_0x0D() [opcode 0x0D]
  │
  ├─> diagTask (0x3FA3F8)
  │     └─> Main diagnostic handler
  │           └─> Coordinates diagnostic requests
  │
  ├─> diagEthRxTask (0x3FA404)
  │     └─> Ethernet diagnostic receiver
  │           └─> Receives gw-diag commands from ICE
  │
  ├─> diagTxTask (0x41E894)
  │     └─> Diagnostic transmitter
  │           └─> Sends responses to ICE
  │
  └─> alertHandlerTask
        └─> System alert handling
```

### Task Communication

Tasks communicate via:
- **FreeRTOS queues** (diagTask: queue create failed)
- **UDP sockets** (port 3500, diagnostic socket)
- **Shared memory** (authentication state, config cache)
- **Semaphores/mutexes** (access synchronization)

---

## Authentication Context Flow

### Scenario 1: ICE → Gateway (Authenticated)

```
[ICE/MCU]
   │ 1. Establish Hermes session
   ├──(ECDH + challenge-response)──>
   │                                [Gateway: Hermes Server]
   │                                   │
   │                                   ├─> Verify ICE identity
   │                                   ├─> Create session context
   │                                   └─> Store in global state
   │
   │ 2. Send gw-diag command
   ├──(diagEthRxTask)──>
   │                    [Gateway: diagTask]
   │                       │
   │                       ├─> Parse command
   │                       ├─> Check session context ✅
   │                       └─> Forward to soc_udpcmds_task
   │                                     │
   │                                     ├─> lookup_metadata()
   │                                     ├─> prefix_check()
   │                                     ├─> is_hermes_authenticated() → TRUE ✅
   │                                     └─> write_config() → SUCCESS
   │
   │ 3. Response
   <──(diagTxTask)──
   │
[Result: 0x00 SUCCESS]
```

**Key Point:** The authentication context is established by the Hermes session and checked by `is_hermes_authenticated()` when processing commands.

---

### Scenario 2: External OBD → Gateway (Unauthenticated)

```
[Laptop/OBD Dongle]
   │ 1. Send UDP packet directly to port 3500
   ├──(UDP)──>
   │        [Gateway: soc_udpcmds_task]
   │           │
   │           ├─> recvfrom() receives packet
   │           ├─> No Hermes session context!
   │           ├─> process_udp_packet()
   │           │     │
   │           │     ├─> handle_set_config()
   │           │     │     │
   │           │     │     ├─> lookup_metadata(0x0306)
   │           │     │     ├─> prefix = 0x13 (SECURE)
   │           │     │     ├─> is_hermes_authenticated() → FALSE ❌
   │           │     │     └─> return 0xFF (DENIED)
   │           │     │
   │           │     └─> send response
   │           │
   │ 2. Response
   <──(UDP)──
   │
[Result: 0xFF ERROR - Authentication Required]
```

**Key Point:** Direct UDP packets have no session context, so secure configs are denied.

---

### Scenario 3: External OBD → Gateway (Insecure Config)

```
[Laptop/OBD Dongle]
   │ 1. Send UDP packet for insecure config
   ├──(UDP)──>
   │        [Gateway: soc_udpcmds_task]
   │           │
   │           ├─> recvfrom() receives packet
   │           ├─> process_udp_packet()
   │           │     │
   │           │     ├─> handle_set_config()
   │           │     │     │
   │           │     │     ├─> lookup_metadata(0x0219)
   │           │     │     ├─> prefix = 0x03 (INSECURE)
   │           │     │     ├─> Skip auth check! ⚠️
   │           │     │     └─> write_config() → SUCCESS
   │           │     │
   │           │     └─> send response
   │           │
   │ 2. Response
   <──(UDP)──
   │
[Result: 0x00 SUCCESS - No Auth Required]
```

**Key Point:** Configs with prefix 0x03 bypass authentication entirely.

---

## The Missing Link: "udpApiToGw-diag"

### Hypothesis

The string "udpApiToGw-diag" was expected to appear in the Gateway firmware, potentially as a bridge function name between:
- `udpApiTask` (generic UDP handler)
- `diagTask` (diagnostic command processor)

### Search Results

```bash
$ strings ryzenfromtable.bin | grep -i "udpApiToGw-diag"
(no results)

$ strings ryzenfromtable.bin | grep -iE "bridge|api.*diag"
(no results)
```

**Conclusion:** The string "udpApiToGw-diag" does NOT appear in the Gateway firmware.

### Possible Explanations

1. **Function is inlined**
   - No string name needed
   - Compiler optimization removed explicit function

2. **Different naming convention**
   - Actual function might be named differently
   - Could be: `process_diag_udp()`, `udp_diag_handler()`, etc.

3. **String is in ICE firmware, not Gateway**
   - ICE might have `udpApiToGw-diag()` as the sending function
   - Gateway receives but doesn't name it explicitly

4. **Erlang/Beam VM symbol**
   - Gateway uses Erlang runtime (udp.hrl reference found)
   - Function might be in Beam bytecode, not native code

5. **Debug symbol stripped**
   - Release firmware has debug symbols removed
   - Development builds might have this string

---

## Authentication State Management

### Global State Structure (Inferred)

```c
// Global authentication context (singleton)
struct gateway_auth_state {
    bool hermes_session_active;
    uint32_t session_id;
    uint8_t session_key[32];        // AES-256 key
    uint8_t session_hmac[32];       // HMAC for integrity
    uint32_t session_timestamp;     // Creation time
    uint32_t session_timeout;       // Expiration time
    uint8_t ice_identity[64];       // ICE certificate/identity
    bool authenticated;             // Final auth status
} g_auth_state;

// Called by Hermes session establishment
void set_hermes_authenticated(bool status) {
    g_auth_state.authenticated = status;
    g_auth_state.session_timestamp = get_current_time();
}

// Called by SET_CONFIG handler
bool is_hermes_authenticated(void) {
    if (!g_auth_state.authenticated) {
        return false;
    }
    
    // Check session timeout
    uint32_t now = get_current_time();
    if (now > g_auth_state.session_timeout) {
        g_auth_state.authenticated = false;
        return false;
    }
    
    return true;
}
```

### Thread Safety

Since multiple tasks may check authentication state:

```c
// Mutex-protected access
SemaphoreHandle_t g_auth_mutex;

bool is_hermes_authenticated(void) {
    bool result;
    
    xSemaphoreTake(g_auth_mutex, portMAX_DELAY);
    result = check_auth_internal();
    xSemaphoreGive(g_auth_mutex);
    
    return result;
}
```

---

## Diagnostic Task Deep Dive

### diagEthRxTask: ICE Command Receiver

```c
void diagEthRxTask_entry(void *params) {
    int sock;
    struct sockaddr_in addr;
    uint8_t buffer[4096];
    
    // Create diagnostic listener socket
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        log_error("diagTask: Can't create diag listener socket");
        return;
    }
    
    // Bind to diagnostic port (likely different from 3500)
    addr.sin_port = htons(DIAG_PORT);  // Unknown port number
    if (bind(sock, &addr, sizeof(addr)) < 0) {
        log_error("diagTask: error binding listener socket");
        return;
    }
    
    // Register diagnostic listener
    registerDiagListener(sock);
    
    // Main receive loop
    while (1) {
        ssize_t len = recvfrom(sock, buffer, sizeof(buffer), 0, NULL, NULL);
        if (len > 0) {
            diagTaskDoEthListenerWork(buffer, len);
        }
    }
}
```

### diagTask: Command Coordinator

```c
void diagTask_entry(void *params) {
    QueueHandle_t queue;
    
    // Create command queue
    queue = xQueueCreate(QUEUE_SIZE, sizeof(diag_msg_t));
    if (queue == NULL) {
        log_error("diagTask: queue create failed");
        return;
    }
    
    // Main processing loop
    while (1) {
        diag_msg_t msg;
        
        // Wait for message from diagEthRxTask or other sources
        if (xQueueReceive(queue, &msg, portMAX_DELAY) == pdTRUE) {
            // Process diagnostic command
            diagTaskDoEthWork(&msg);
            
            // May forward to soc_udpcmds_task for config access
            forward_to_udp_handler(&msg);
        }
    }
}
```

### Message Flow: ICE → Gateway Config Write

```
1. ICE sends gw-diag command packet
   ↓
2. diagEthRxTask receives on diagnostic socket
   ↓
3. diagTaskDoEthListenerWork() parses packet
   ↓
4. Posts message to diagTask queue
   ↓
5. diagTask processes message
   ↓
6. Forwards to soc_udpcmds_task (port 3500 internal)
   ↓
7. soc_udpcmds_task calls handle_set_config()
   ↓
8. Authentication check (uses Hermes session context)
   ↓
9. Config write executes
   ↓
10. Response sent back via diagTxTask
   ↓
11. ICE receives result
```

**Key Insight:** The authentication context is established at step 1-2 (Hermes session) and checked at step 8 (config handler).

---

## Port Mapping (Inferred)

| Port | Purpose | Task | Authentication |
|------|---------|------|----------------|
| 3500 | UDP Config API | soc_udpcmds_task | Per-config (prefix byte) |
| ???? | Diagnostic Socket | diagEthRxTask | Hermes session |
| ???? | Hermes Server | (unknown task) | Challenge-response |

**Note:** Exact diagnostic port unknown - requires network capture or further reverse engineering.

---

## Attack Surface by Task

### soc_udpcmds_task (Port 3500)

**Exposed to:** External OBD/laptop via direct UDP

**Attack vectors:**
- Buffer overflow in packet parsing
- Config ID fuzzing (trigger crashes)
- Insecure config exploitation (prefix 0x03)
- Timing attacks (measure response times)
- Denial of service (flood port 3500)

**Defenses:**
- Input validation on packet length
- Metadata table bounds checking
- Rate limiting (if implemented)
- Prefix byte enforcement

---

### diagEthRxTask (Diagnostic Port)

**Exposed to:** ICE/MCU only (internal network)

**Attack vectors:**
- ICE compromise → full Gateway access
- Man-in-the-middle (if Ethernet not encrypted)
- Session hijacking (steal session tokens)

**Defenses:**
- Hermes session encryption
- Certificate-based ICE identity
- Network isolation (ICE ↔ Gateway only)

---

### diagTask (Internal Coordinator)

**Exposed to:** Internal only (no direct network access)

**Attack vectors:**
- Queue injection (if other tasks compromised)
- Race conditions (concurrent access)

**Defenses:**
- FreeRTOS queue access control
- Mutex-protected shared state

---

## Conclusion

### What We Learned

1. **Gateway uses multi-task architecture** with separate handlers for different network interfaces
2. **Authentication context is global**, established by Hermes session and checked per-command
3. **"udpApiToGw-diag" string does not exist** in Gateway firmware (may be in ICE or stripped)
4. **Diagnostic tasks coordinate** between ICE commands and UDP config handlers
5. **Authentication is enforced** at the config handler level, not network/transport level

### The Critical Enforcement Point

```c
// In handle_set_config() within soc_udpcmds_task
if (prefix == 0x13 || prefix == 0x15) {
    if (!is_hermes_authenticated()) {
        return 0xFF;  // ← THIS LINE ENFORCES SECURITY
    }
}
```

This single conditional is the bottleneck for all secure config writes, regardless of whether the command arrives via:
- Direct UDP (port 3500)
- Diagnostic interface (diagEthRxTask)
- Internal forwarding (diagTask)

### Recommended Next Actions

1. **Network capture** between ICE and Gateway to identify diagnostic port
2. **Hermes protocol analysis** to understand session establishment
3. **Ghidra disassembly** to find exact assembly addresses (per GATEWAY-AUTHENTICATION-DECISION.md)
4. **Dynamic analysis** with debugger to trace authentication flow
5. **Fuzzing** of insecure configs (prefix 0x03) to find exploitable behaviors

---

**Status:** Architecture mapped. Authentication enforcement point identified. Ready for detailed disassembly analysis.

---

## Addendum: "udpApiToGw-diag" Search Results

### Search Conducted

Per user request, searched Gateway firmware for the string "udpApiToGw-diag":

```bash
$ strings data/binaries/ryzenfromtable.bin | grep -i "udpApiToGw-diag"
(no results)

$ strings data/binaries/ryzenfromtable.bin | grep -i "udpApi"
udpApiTask
udpApiTask

$ strings data/binaries/ryzenfromtable.bin | grep -i "gw-diag"
(no results)
```

### Conclusion

**The string "udpApiToGw-diag" does NOT exist in the Gateway firmware.**

### Possible Locations

If this string/function exists in the Tesla system, it's likely in:

1. **ICE/MCU firmware** (the sender side)
   - ICE calls `udpApiToGw-diag()` to send commands TO Gateway
   - Gateway receives them but doesn't name them explicitly

2. **Odin service tool** (Python layer)
   - Function name in the diagnostic scripts
   - Already found: 2,988 Python scripts referencing gw-diag

3. **Development builds** (debug symbols)
   - Release firmware strips debug symbols
   - Dev builds might include this for logging

4. **Erlang/BEAM bytecode** (if applicable)
   - Gateway references "udp.hrl" (Erlang header)
   - Function might be in Beam VM, not native code

### Recommendation

Search ICE firmware (MCU) for this string instead:
```bash
strings ice_firmware.bin | grep -i "udpApiToGw-diag"
```

---

**Updated:** 2026-02-03 13:26 UTC
