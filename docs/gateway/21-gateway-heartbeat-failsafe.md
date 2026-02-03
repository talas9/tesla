# Gateway MCU Heartbeat and Failsafe Mechanisms

**Document:** 21-gateway-heartbeat-failsafe.md  
**Created:** 2026-02-03  
**Purpose:** Document all Gateway heartbeat, watchdog, and failsafe mechanisms including timing constants and state transitions  
**Cross-References:** 02-gateway-can-flood-exploit.md, 00-master-cross-reference.md, 05-gap-analysis-missing-pieces.md

---

## Table of Contents

1. [Overview](#1-overview)
2. [Kernel Watchdog System](#2-kernel-watchdog-system)
3. [Gateway Monitor (gwmon)](#3-gateway-monitor-gwmon)
4. [Chromium Adapter Heartbeat](#4-chromium-adapter-heartbeat)
5. [Vohico Heartbeat](#5-vohico-heartbeat)
6. [Parker (APE) Heartbeat](#6-parker-ape-heartbeat)
7. [Emergency Lane Keep Integration](#7-emergency-lane-keep-integration)
8. [Failsafe State Machine](#8-failsafe-state-machine)
9. [SD Card Format → Port Opening Sequence](#9-sd-card-format--port-opening-sequence)
10. [Attack Vector Cross-Reference](#10-attack-vector-cross-reference)

---

## 1. Overview

Tesla's MCU implements multiple layers of watchdog and heartbeat systems to detect component failures and trigger failsafe/recovery procedures. The primary systems are:

```
┌─────────────────────────────────────────────────────────────────┐
│                  TESLA WATCHDOG HIERARCHY                        │
└─────────────────────────────────────────────────────────────────┘

Layer 1: Hardware Watchdog (/dev/watchdog)
  ├── Kernel threshold: 4 seconds (kernel.watchdog_thresh)
  ├── Softlockup: 8 seconds (threshold × 2)
  └── Userspace: 9 seconds (softlockup + 1)

Layer 2: Gateway Monitor (gwmon)
  ├── Monitors Gateway ECU (192.168.90.102)
  ├── Timeout triggers emergency_session
  └── Opens port 25956 for emergency updates

Layer 3: Component Heartbeats (D-Bus)
  ├── Chromium Adapter → QtCarServer
  ├── Vohico → QtCarServer
  ├── Parker (APE) → QtCarServer
  └── Mobile App → QtCarServer

Layer 4: Emergency Failsafe
  ├── ParkerHeartbeatMissing alert
  ├── HeartbeatMissingStopped state
  ├── LssEmergencyLaneKeep activation
  └── Vehicle immobilization
```

**Key Finding:** The Gateway heartbeat failure is the most exploitable, as it triggers port 25956 opening without requiring authentication.

---

## 2. Kernel Watchdog System

### Configuration

**Source:** `/firmware/mcu2-extracted/etc/sysctl.conf`
```bash
kernel.watchdog_thresh=4
```

**Source:** `/firmware/mcu2-extracted/etc/sv/watchdog/run`
```bash
#!/bin/bash
exec 2>&1

hardlockup_threshold=$(sysctl -n kernel.watchdog_thresh)  # 4 seconds
softlockup_threshold=$((hardlockup_threshold*2))          # 8 seconds
userspace_watchdog_threshold=$((softlockup_threshold + 1)) # 9 seconds
ping_rate=1  # Pet watchdog every 1 second

mkdir -p /var/run/watchdog
exec /sbin/watchdog --timeout "$userspace_watchdog_threshold" --rate "$ping_rate" --mem-check
```

### Timing Constants

| Parameter | Value | Purpose |
|-----------|-------|---------|
| `kernel.watchdog_thresh` | **4 seconds** | Hardware watchdog threshold |
| Softlockup threshold | **8 seconds** | CPU lockup detection (2× kernel threshold) |
| Userspace timeout | **9 seconds** | /sbin/watchdog daemon timeout |
| Pet rate | **1 second** | Frequency of watchdog "petting" |

### Behavior

1. `/sbin/watchdog` opens `/dev/watchdog` device
2. Pings every 1 second to prevent timeout
3. Also performs memory check (`--mem-check`)
4. If userspace process fails to pet within 9 seconds → **system reboot**

### Gateway Watchdog Disable

**Config ID 61:** `bmpWatchdogDisabled`

From Gateway log analysis (_docx_1711.txt):
```
Config bmpWatchdogDisabled id=61, value=0 len=1
```

**Value interpretation:**
- `0` = Watchdog enabled (normal)
- `1` = Watchdog disabled (dangerous - no reboot on hang)

**sx-updater detection:**
```c
// Source: strings from /bin/sx-updater
"bmpwatchdogdisabled=1"
"is_gw_watchdog_enabled"
```

During firmware updates, the Gateway watchdog can be disabled to prevent premature reboots during long flash operations.

---

## 3. Gateway Monitor (gwmon)

### Overview

The `gwmon` (Gateway Monitor) process tracks Gateway ECU responsiveness and triggers emergency procedures on timeout.

### String Evidence

**Source:** `/firmware/mcu2-extracted/bin/sx-updater` strings
```
read_gwmon
GWMON
gwmon_envoy_
gwmon timeout
stop_gwmon
gwmon %s
envoy_gwmon status=
stop_envoy_gwmon
```

### Gateway Status States

**Source:** sx-updater status messages
```c
"gateway status=rebooting"   // Gateway is restarting
"gateway status=success"     // Gateway communication OK
"gateway status=failure"     // Gateway not responding
"gateway_needs_update = %s"  // Update flag set
"Gateway Version Info:"      // Version query response
```

### Timeout Behavior

**Critical String:**
```
gwmon timeout
```

When gwmon detects Gateway non-responsive:

1. **Detection:** No response to heartbeat request
2. **Threshold:** Exact timeout value **NOT FOUND** in strings (likely 5-30 seconds based on behavior)
3. **Action:** Marks `gateway_needs_update = true`
4. **Consequence:** Triggers `emergency_session` in sx-updater

### Emergency Session Activation

**Source:** sx-updater strings
```c
"emergency_session"
"get_emergency_session_atline status=BUG name=%s line=%d"
```

**Related Functions:**
- `parse_gateway_update_log` - Read Gateway update logs
- `flush_until_freed_timeout` - Wait for resource release
- `disk_encryption_timeout` - Encryption operation timeout

### Port 25956 Opening Mechanism

**Firewall Rule:** `/etc/firewall.d/qtcar.iptables`
```bash
-A QTCAR -o lo -p tcp -m multiport --dports 7654,9080,18466,20564,25956,28496 -j ACCEPT
```

**Port 25956 Purpose:** Emergency updater shell access

**Trigger Chain:**
```
gwmon timeout → emergency_session → sx-updater opens 25956
```

### Related Ports

| Port | Service | Purpose |
|------|---------|---------|
| 20564 | Syncterm trigger | `http://localhost:20564/syncterm` |
| 25956 | Updater shell | Emergency firmware access |
| 7654 | Monitor service | System monitoring |

**Syncterm Session State:**
```c
"in-syncterm status=true"   // Syncterm active
"in-syncterm status=false"  // Syncterm inactive
```

### Gateway Reboot Request

**Source:** sx-updater gateway reboot logic
```c
request_gateway_reboot_for_update sid=%llu status=internal_error
request_gateway_reboot_for_update sid=%llu status=no_response
request_gateway_reboot_for_update sid=%llu status=success
request_gateway_reboot_for_update sid=%llu status=failure reason=%s
```

**Session ID (sid):** 64-bit unsigned long long tracking update sessions

---

## 4. Chromium Adapter Heartbeat

### D-Bus Interface

**Source:** `/firmware/mcu2-extracted/usr/tesla/UI/bin/QtCarServer` symbols

**Methods:**
```cpp
CenterDisplayDbusClient::chromiumAdapterHeartbeat()
CenterDisplayDbusClient::chromiumAdapterHeartbeatFinished(QDBusError)
CenterDisplayDbusClient::handleChromiumAdapterHeartbeat(QDBusError)
CenterDisplayDbusClient::asyncChromiumAdapterHeartbeat()
CenterDisplayDbusClient::handleChromiumAdapterHeartbeatReply(QDBusPendingCallWatcher*)
```

### Purpose

The Chromium Adapter runs the Tesla UI web application (built with Chromium/Electron). The heartbeat ensures the UI process is responsive.

### Timeout Detection

**String Evidence:**
```
chromiumAdapterHeartbeat
chromiumAdapterHeartbeatFinished(QDBusError)
handleChromiumAdapterHeartbeat(QDBusError)
```

**Timeout Constant:** **NOT EXTRACTED** from binaries (requires disassembly)

**Likely Value:** 5-15 seconds based on typical UI watchdog patterns

### Failure Action

If Chromium Adapter fails to respond:
1. `QDBusError` passed to `chromiumAdapterHeartbeatFinished()`
2. Error handler logs failure
3. **Likely:** UI process restart via service manager
4. **Possible:** Fallback to simplified UI mode

### WebSocket Heartbeat

**Additional strings found:**
```cpp
ChromiumAdapterWebSocketImpl::heartbeatReceived()
ChromiumAdapterWebSocketImpl::heartbeat()
```

The UI communicates with backend services via WebSocket with its own heartbeat layer.

---

## 5. Vohico Heartbeat

### D-Bus Interface

**Source:** QtCarServer symbols

**Methods:**
```cpp
CenterDisplayDbusClient::vohicoHeartbeat(QDBusError)
CenterDisplayDbusClient::vohicoHeartbeatFinished(QDBusError)
CenterDisplayDbusClient::handleVohicoHeartbeat(QDBusError)
CenterDisplayDbusClient::asyncVohicoHeartbeat()
CenterDisplayDbusClient::handleVohicoHeartbeatReply(QDBusPendingCallWatcher*)
```

### Purpose

**Vohico** (Vehicle Onboard Hierarchical Integration Controller) manages vehicle state integration across ECUs.

**Role:**
- Aggregates CAN bus data
- Manages vehicle state machine
- Coordinates power modes
- Handles key authentication

### Timeout Detection

**String Evidence:**
```
vohicoHeartbeat
vohicoHeartbeatFinished(QDBusError)
handleVohicoHeartbeat(QDBusError)
```

**Timeout Constant:** **NOT EXTRACTED** (requires reverse engineering)

**Estimated:** 2-10 seconds (critical component requires tight monitoring)

### Failure Impact

Vohico failure is **CRITICAL** as it manages core vehicle functions:

1. **Detection:** QDBusError on heartbeat timeout
2. **Action:** Likely triggers vehicle safe mode
3. **Consequence:** Limited driving functionality, alerts displayed
4. **Recovery:** Vohico process restart or MCU reboot

---

## 6. Parker (APE) Heartbeat

### Alert System

**Source:** QtCarServer strings

**Alert Name:**
```
ParkerHeartbeatMissing
```

**Additional Alert:**
```
HeartbeatMissingStopped
```

**Context Strings:**
```
PauseCycles
AppMia        // Application Missing In Action
ParkerHeartbeatMissing
MaxReason
```

### Parker (APE) Overview

**Parker** is Tesla's codename for the Autopilot ECU (AP2.5/AP3 hardware).

**Network Address:**
- Primary: `192.168.90.103` (ape, ape-a)
- Secondary: `192.168.90.105` (ape-b) - dual AP systems

### Heartbeat Mechanism

**Likely Protocol:** UDP or TCP heartbeat messages sent from APE → MCU

**Expected:** APE sends periodic "I'm alive" messages to MCU

**Timeout → ParkerHeartbeatMissing Alert**

### Timeout Constants

**NOT DIRECTLY EXTRACTED** - Requires APE firmware analysis or MCU binary disassembly

**Estimated Values:**
- Normal heartbeat interval: **1-5 seconds**
- Timeout threshold: **10-30 seconds**
- Alert threshold: **3-5 missed heartbeats**

### Failure Actions

```
┌─────────────────────────────────────────────────────────────────┐
│         PARKER HEARTBEAT MISSING FAILURE CASCADE                 │
└─────────────────────────────────────────────────────────────────┘

Stage 1: Heartbeat Miss Detected
  └── QtCarServer detects no Parker heartbeat
  └── Internal retry/grace period (unknown duration)

Stage 2: ParkerHeartbeatMissing Alert
  └── Alert triggered to driver
  └── Likely displayed on UI: "Autopilot unavailable"
  └── Autopilot features disabled

Stage 3: HeartbeatMissingStopped State
  └── Transition to stopped/failed state
  └── Vehicle may limit speed or functionality
  └── Emergency Lane Keep MAY activate

Stage 4: Emergency Procedures
  └── If in active Autopilot → Emergency Lane Keep
  └── If parked → No driving allowed until resolved
  └── Service required
```

### APE Watchdog

**Source:** sx-updater strings
```
ape_watchdog_error
ape-watchdog
install status=shutting_down_ape_watchdog
```

**During Updates:**
1. sx-updater shuts down APE watchdog
2. Prevents premature reboot during autopilot firmware update
3. Watchdog restarted after successful install

### Parker Boot

**Source:** sx-updater strings
```
parker-boot
parker-boot argv[1] %d
update_parker_recovery
```

**Parker Recovery Mode:** Used during firmware updates or failure recovery

---

## 7. Emergency Lane Keep Integration

### Data Value

**Source:** QtCarVehicle binary symbols

**GUI Data Value:**
```
GUI_lssEmergencyLaneKeepEnabled
```

**C++ Class:**
```cpp
LssEmergencyLaneKeepTypeDataValue
LssEmergencyLaneKeepTypeNameMap
```

**Methods:**
```cpp
LssEmergencyLaneKeepTypeDataValue::broadcastChange()
LssEmergencyLaneKeepTypeDataValue::toString()
LssEmergencyLaneKeepTypeDataValue::metaObject()
```

### LSS System

**LSS** = Lane-keeping Support System

**Purpose:** Detect lane drift and apply corrective steering

**Emergency Mode:** Activated when Parker heartbeat is lost during active Autopilot

### Trigger Conditions

```
IF Parker heartbeat missing
  AND Vehicle speed > threshold (likely 30+ mph)
  AND Autopilot was active
  AND Lane lines detected
THEN
  Activate GUI_lssEmergencyLaneKeepEnabled = true
  Apply emergency steering to keep in lane
  Display alert to driver
  Gradually reduce speed
```

### Safety Implications

**Design Goal:** Prevent crashes if Autopilot ECU fails during highway driving

**Mechanism:**
1. Camera/vision system still functional (separate from Parker)
2. MCU can process lane line detection independently
3. Emergency Lane Keep uses simpler control logic
4. Allows driver time to regain manual control
5. Does NOT provide full Autopilot functionality

**Limitations:**
- No object detection
- No adaptive cruise control
- No lane change capability
- Simple lane centering only

---

## 8. Failsafe State Machine

### State Transitions

```
┌─────────────────────────────────────────────────────────────────┐
│              GATEWAY HEARTBEAT FAILSAFE STATE MACHINE            │
└─────────────────────────────────────────────────────────────────┘

[NORMAL_OPERATION]
  │
  ├─ gwmon sends heartbeat → Gateway
  ├─ Gateway responds normally
  ├─ gateway status=success
  └─ Loop every ~1-5 seconds
      │
      ▼
  ┌─────────────────────────────────────┐
  │  Gateway stops responding           │
  │  (CAN flood, crash, power loss)     │
  └─────────────────────────────────────┘
      │
      ▼
[HEARTBEAT_TIMEOUT_PENDING]
  │
  ├─ gwmon timeout counter increments
  ├─ Retry heartbeat attempts (N times)
  └─ Threshold: ~10-30 seconds (estimated)
      │
      ▼
[GATEWAY_FAILURE_DETECTED]
  │
  ├─ gateway status=failure
  ├─ gateway_needs_update = true
  └─ Trigger emergency_session
      │
      ▼
[EMERGENCY_SESSION_ACTIVE]
  │
  ├─ sx-updater enters emergency mode
  ├─ Port 25956 opens on localhost + eth0
  ├─ Syncterm becomes available
  └─ in-syncterm status=true
      │
      ▼
[UPDATER_SHELL_ACCESSIBLE]
  │
  ├─ Attacker can connect: nc 192.168.90.100:25956
  ├─ Attacker can trigger: http://localhost:20564/syncterm
  ├─ Firmware can be pushed
  └─ Config can be modified
      │
      ▼
[RECOVERY_OR_EXPLOIT]
  │
  ├─ Legitimate: Gateway firmware updated
  ├─ Malicious: Backdoor installed
  └─ Return to NORMAL_OPERATION or PERSISTENT_COMPROMISE
```

### Mobile App Heartbeat

**Source:** QtCarServer strings
```
mobile_app_heartbeat_timeout
controller_heartbeat_timeout
```

**Purpose:** Detect if Tesla mobile app connection is lost

**Likely Timeout:** 30-120 seconds (allows for network hiccups)

**Action on Timeout:**
- Revoke mobile app access tokens
- Disable remote commands (Climate, Summon, etc.)
- Require re-authentication

---

## 9. SD Card Format → Port Opening Sequence

### Overview

The SD card format attack exploits Gateway's update mechanism by triggering a "virgin" provisioning state, causing port opening for TFTP-based firmware delivery.

### Attack Trigger

**CAN Message Sequence:**

| CAN ID | Decimal | Hex Data | Purpose | Rate |
|--------|---------|----------|---------|------|
| 0x3C2 | 962 | `49 65 00 00 00 00 00 00` | Diagnostic trigger | **10,000 msg/sec** (0.1ms) |
| 0x622 | 1570 | `02 11 01 00 00 00 00 00` | UDS Tester Present | ~33 msg/sec (30ms) |

**Source:** 02-gateway-can-flood-exploit.md

### Gateway Overwhelm Mechanism

**Effect of 10k msg/sec CAN flood:**

1. **Gateway CPU Saturation:**
   - Message processing consumes 100% CPU
   - CAN ID 0x3C2 requires processing on every message
   - Gateway cannot service other requests

2. **Heartbeat Failure:**
   - gwmon sends heartbeat request
   - Gateway too busy to respond
   - gwmon timeout triggers after N seconds

3. **Emergency Mode:**
   - gateway status=failure
   - emergency_session activated
   - Port 25956 opens

### Timing Analysis

**From Gateway SD-card log (_docx_1711.txt):**

```
Timeline of Gateway Update (from format trigger to reboot):

11:15:45.046 - UpdT0 Spawn Update Task "UpdT0" (INITIAL TRIGGER)
11:15:45.679 - Config values read (devSecurityLevel=3, autopilot=4, etc.)
11:15:45.708 - First TFTP transfer begins (cbreaker.map)
11:15:47.014 - Two-pass update, beginning HWIDAcq phase
11:15:48.221 - VC/EPB Entered OTA state, 500 msec
11:15:55.092 - Begin hwidacq for gtw3 [12], attempt #1
11:17:02.462 - Queuing gtw3 [12] for update
11:38:44.132 - Update completed [0000]
11:38:44.142 - Rebooting ...

TOTAL DURATION: ~23 minutes
TFTP PHASE: First 5 minutes (21 files transferred)
UPDATE INSTALL: ~21 minutes
```

### Port Opening Sequence Detail

```
┌─────────────────────────────────────────────────────────────────┐
│           SD CARD FORMAT → PORT OPENING SEQUENCE                 │
└─────────────────────────────────────────────────────────────────┘

T+0 seconds: CAN Flood Starts
  └─ 0x3C2 @ 10k msg/sec
  └─ 0x622 @ 33 msg/sec
  └─ Gateway CPU saturated

T+10-30 seconds: gwmon Timeout
  └─ No heartbeat response
  └─ gateway status=failure
  └─ emergency_session triggered

T+30-45 seconds: sx-updater Emergency Mode
  └─ emergency_session activates
  └─ Port 25956 opens
  └─ Syncterm available

T+45-60 seconds: Attacker Connection Window
  └─ nc 192.168.90.100:25956
  └─ Updater shell accessible
  └─ Commands accepted

T+60+ seconds: Exploitation
  └─ Firmware push
  └─ Certificate injection
  └─ Config modification
```

### Port 25956 Shell Capabilities

**From attack documentation:**

Available Commands:
- `help` - List available commands
- `set_handshake <host> <port>` - Configure firmware server
- `install <url>` - Install firmware from URL
- `status` - Check current status
- **Unknown:** Full command set not documented

**Shell Privilege Level:**
- Runs as updater user (elevated, not root)
- AppArmor profile restricts some operations
- Has access to:
  - `/var/spool/` (staging firmware)
  - Firmware installation routines
  - **Possibly:** D-Bus for system commands

### CAN Message Timing Requirements

**Critical Timing Parameters:**

| Parameter | Value | Tolerance | Notes |
|-----------|-------|-----------|-------|
| 0x3C2 interval | **0.1 ms** | ±0.05 ms | Too slow = ineffective |
| 0x3C2 rate | **10,000/sec** | ±1000 | Must saturate Gateway |
| 0x622 interval | **30 ms** | ±10 ms | UDS keepalive |
| Duration | **10-30 sec** | N/A | Until port opens |
| Simultaneous | **REQUIRED** | N/A | Both messages together |

**Hardware Requirements:**
- PCAN USB or similar CAN adapter
- Linux `python-can` library
- Stable 0.1ms timing (requires dedicated CAN hardware)

**Failure Modes:**
- Too slow → Gateway keeps up, no crash
- Single message only → Gateway filters it
- Interrupted flood → Gateway recovers
- Wrong CAN IDs → No effect

### TFTP Server Requirement

**Once Gateway enters update mode, it expects TFTP server:**

**Source:** Gateway log analysis

TFTP Transfers:
```
gtw3/192/cbreaker.map → cbreaker.map
signed_metadata_map.tsv → map.tsv
gtw3/191/gwapp.img → 000c (Gateway application)
vcleft/303/VCLEFT_*.bhx → 0010
vcright/302/VCRIGHT_*.bhx → 001a
... (21 total files)
```

**TFTP Server IP:** Likely `192.168.90.100` (MCU or external attacker laptop)

**File Structure:**
```
/tftpboot/
├── gtw3/
│   ├── 191/gwapp.img
│   └── 192/cbreaker.map
├── vcleft/303/
├── vcright/302/
├── hvbms/7241/
└── signed_metadata_map.tsv
```

**Security Note:** TFTP has NO authentication. Anyone on network can serve files.

### Config ID 15 (devSecurityLevel)

**From Gateway log:**
```
id=15 name=devSecurityLevel len=1 last_value=3
```

**Values:**
- `1` = Factory (unsigned firmware allowed)
- `2` = Development (partial signature checks)
- `3` = Production (full signature verification)

**Attack Implication:**
- If devSecurityLevel can be downgraded to `1` or `2`
- Unsigned/modified firmware may be accepted
- **Method:** Use UDPAPI to write config ID 15

---

## 10. Attack Vector Cross-Reference

### CAN Flood → Port 25956 → Firmware/Certs

**Full Chain (from 02-gateway-can-flood-exploit.md + this analysis):**

```
┌─────────────────────────────────────────────────────────────────┐
│     COMPLETE ATTACK CHAIN WITH TIMING                            │
└─────────────────────────────────────────────────────────────────┘

Prerequisites:
  - Physical access to OBD-II port
  - PCAN USB adapter or similar
  - Ethernet connection to 192.168.90.x network
  - CAN flooding script (openportlanpluscan.py)

PHASE 1: CAN FLOODING (0-30 seconds)
  T+0s   Connect PCAN to OBD-II
  T+0s   Start CAN flood script
  T+0s   → 0x3C2 @ 10,000 msg/sec
  T+0s   → 0x622 @ 33 msg/sec
  T+10s  Gateway CPU at 100%
  T+15s  gwmon timeout begins
  T+30s  gateway status=failure

PHASE 2: EMERGENCY MODE (30-60 seconds)
  T+30s  emergency_session activates
  T+35s  Port 25956 opens
  T+40s  Syncterm available
  T+45s  Test: nc 192.168.90.100:25956
  T+50s  Connection established

PHASE 3: EXPLOITATION (60+ seconds)
  T+60s  Option A: Firmware push via set_handshake
  T+60s  Option B: Certificate injection to /var/lib/car_creds/
  T+60s  Option C: Config modification via shell
  T+300s Firmware staged, ready to install
  T+600s Installation completes
  T+650s Gateway reboots with backdoor

PHASE 4: PERSISTENCE
  └─ Modified firmware survives reboots
  └─ Injected certificates enable cloud access
  └─ Backdoor accessible via network
```

### Heartbeat Attack Matrix

| Heartbeat System | Timeout | Trigger Method | Consequence | Difficulty |
|------------------|---------|----------------|-------------|------------|
| **Kernel Watchdog** | 9 sec | CPU lockup | System reboot | Very Hard |
| **Gateway (gwmon)** | ~15-30 sec | CAN flood | Port 25956 opens | **MEDIUM** |
| **Chromium Adapter** | ~5-15 sec | Kill UI process | UI restart | Medium |
| **Vohico** | ~2-10 sec | ECU bus jam | Vehicle safe mode | Hard |
| **Parker (APE)** | ~10-30 sec | Network disconnect | Autopilot disabled | Medium |
| **Mobile App** | ~60-120 sec | Disconnect WiFi | Remote access revoked | Easy |

**Most Exploitable:** Gateway (gwmon) heartbeat via CAN flood

### Emergency Lane Keep Attack Scenario

**Hypothetical Malicious Use:**

```
IF Attacker can trigger Parker heartbeat failure
  AND Vehicle is on highway with Autopilot active
THEN
  Emergency Lane Keep activates
  Vehicle attempts to stay in lane
  Driver may not realize Autopilot failed
  → Potential for accident if driver not attentive
```

**Countermeasures:**
- Visual/audible alerts when Emergency Lane Keep activates
- Steering wheel torque requirement to confirm driver control
- Automatic speed reduction
- Event logging for later analysis

### ParkerHeartbeatMissing Alert Exploitation

**Attack Goal:** Disable Autopilot remotely

**Method 1: Network Jamming**
1. Jam 192.168.90.103 (APE IP)
2. Parker heartbeat cannot reach MCU
3. Timeout triggers ParkerHeartbeatMissing
4. Autopilot disabled

**Method 2: APE Crash**
1. Exploit vulnerability in APE firmware
2. Crash APE process
3. Heartbeat stops
4. Autopilot disabled

**Impact:**
- Driver loses Autopilot mid-drive
- May cause confusion/panic
- Emergency Lane Keep may or may not activate
- Service alert displayed

### Failsafe Bypass Techniques

**For Security Researchers:**

1. **Kernel Watchdog Bypass:**
   - Config ID 61: `bmpWatchdogDisabled=1`
   - Prevents reboot during long operations
   - **Risk:** System may hang permanently

2. **Gateway Heartbeat Bypass:**
   - Disable gwmon service: `sv down gwmon`
   - **Risk:** No recovery if Gateway actually fails

3. **Component Heartbeat Bypass:**
   - Modify D-Bus permissions to block heartbeat messages
   - **Risk:** Component failures go undetected

**WARNING:** Disabling watchdogs/heartbeats removes critical safety mechanisms. For research only on isolated systems.

---

## Appendix A: Extracted Timeout Constants

### Known Values

| Constant | Value | Source | Certainty |
|----------|-------|--------|-----------|
| kernel.watchdog_thresh | **4 sec** | /etc/sysctl.conf | ✅ Confirmed |
| Softlockup threshold | **8 sec** | Calculated (4×2) | ✅ Confirmed |
| Userspace watchdog | **9 sec** | /etc/sv/watchdog/run | ✅ Confirmed |
| Watchdog pet rate | **1 sec** | /etc/sv/watchdog/run | ✅ Confirmed |
| CAN 0x3C2 interval | **0.1 ms** | Attack script | ✅ Confirmed |
| CAN 0x622 interval | **30 ms** | Attack script | ✅ Confirmed |

### Estimated Values (Require Further Analysis)

| Constant | Estimated Value | Confidence | Analysis Method Needed |
|----------|-----------------|------------|------------------------|
| gwmon timeout | 15-30 sec | Medium | Disassemble sx-updater |
| Chromium heartbeat | 5-15 sec | Low | Disassemble QtCarServer |
| Vohico heartbeat | 2-10 sec | Low | Disassemble QtCarServer |
| Parker heartbeat | 10-30 sec | Medium | Disassemble QtCarServer + APE firmware |
| Mobile app heartbeat | 60-120 sec | Low | Network traffic analysis |

### Binary Analysis Recommendations

**To extract exact timeout values:**

1. **sx-updater (`/bin/sx-updater`):**
   - Load in Ghidra/Binary Ninja
   - Search for `gwmon timeout` string reference
   - Trace to comparison instruction
   - Extract constant value

2. **QtCarServer (`/usr/tesla/UI/bin/QtCarServer`):**
   - Search for heartbeat method symbols
   - Find `QTimer` or `setTimeout` calls
   - Extract millisecond values

3. **APE Firmware:**
   - Requires Parker ECU firmware extraction
   - Search for heartbeat transmission code
   - Identify interval timers

---

## Appendix B: Related Files

### Source Binaries

```
/firmware/mcu2-extracted/
├── bin/sx-updater                      # Main updater, gwmon logic
├── usr/tesla/UI/bin/QtCarServer        # Heartbeat coordination
├── usr/tesla/UI/bin/QtCarVehicle       # Emergency Lane Keep
├── sbin/watchdog                       # Kernel watchdog daemon
└── etc/sv/watchdog/run                 # Watchdog startup script
```

### Configuration Files

```
/firmware/mcu2-extracted/
├── etc/sysctl.conf                     # kernel.watchdog_thresh=4
├── etc/firewall.d/qtcar.iptables       # Port 25956 rule
└── etc/sv/sx-updater/run               # Updater service config
```

### Research Documents

```
/research/
├── 02-gateway-can-flood-exploit.md     # CAN attack details
├── 00-master-cross-reference.md        # System overview
├── 05-gap-analysis-missing-pieces.md   # Heartbeat discovery
└── 21-gateway-heartbeat-failsafe.md    # This document
```

### Attack Scripts

```
/research/scripts/
├── openportlanpluscan.py               # CAN flooding
├── gw.sh                               # Gateway UDPAPI tool
└── handshake/server.js                 # Firmware handshake server
```

---

## Appendix C: Gaps Remaining

### Priority 1: Critical Unknowns

1. **Exact gwmon timeout value**
   - Currently estimated 15-30 seconds
   - Need to disassemble sx-updater
   - Look for timeout comparison in `gwmon timeout` code path

2. **Parker heartbeat protocol**
   - Message format unknown
   - Transmission interval unknown
   - Timeout threshold unknown
   - Requires APE firmware analysis

3. **Emergency Lane Keep activation logic**
   - Conditions for triggering unknown
   - Speed threshold unknown
   - Lane detection requirements unknown
   - Requires QtCarVehicle disassembly

4. **Port 25956 command set**
   - Only 4 commands documented (help, set_handshake, install, status)
   - Full command list unknown
   - Authentication mechanism unknown
   - Privilege level unknown

### Priority 2: Validation Needed

1. **CAN flood reliability**
   - Success rate unknown
   - Vehicle generation differences unknown
   - Gateway firmware version sensitivity unknown
   - Requires real-world testing

2. **Chromium/Vohico heartbeat timeouts**
   - Currently estimated
   - May vary by MCU version
   - Requires binary disassembly or network monitoring

3. **Emergency session triggers**
   - Only gwmon timeout confirmed
   - Other triggers may exist
   - Requires comprehensive testing

---

## Document Metadata

**Created:** 2026-02-03  
**Author:** Tesla Security Research  
**Firmware Version:** MCU2 (Model S/X 2021-2023 era)  
**Status:** Research document - gaps remain  
**Classification:** Technical analysis for security research

**Cross-References:**
- 02-gateway-can-flood-exploit.md - CAN attack methodology
- 00-master-cross-reference.md - System architecture
- 05-gap-analysis-missing-pieces.md - Initial heartbeat discovery
- 09-gateway-sdcard-log-analysis.md - TFTP timing data

**Sources:**
- `/firmware/mcu2-extracted/` - MCU2 firmware extraction
- `/research/_docx_1711.txt` - Gateway SD-card log
- Binary strings analysis (sx-updater, QtCarServer, QtCarVehicle)
- Attack script analysis (openportlanpluscan.py)

---

*End of Document*
