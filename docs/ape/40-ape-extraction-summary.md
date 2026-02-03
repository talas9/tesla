# APE Firmware Extraction - Quick Summary

**Firmware:** 2024.8.9.ice.ape25  
**Extracted:** 2026-02-03  
**Location:** `/root/downloads/ape-extracted/`

## Extraction Statistics

- **Compressed Size:** 534 MB (SquashFS)
- **Uncompressed Size:** 962 MB
- **Total Files:** 2,988
- **Directories:** 379
- **Symlinks:** 984
- **Largest Binary:** vision (389 MB)

## Key Findings

### Network Services
| Port | Service | Purpose | Authentication |
|------|---------|---------|----------------|
| 8081 | service-api-tls | HTTPS API | mTLS (client cert required) |
| 8901 | factory-camera-calibration | Factory calibration HTTP | Unknown (likely none in factory mode) |
| 8902 | apeb-file-server | APE-B file sharing | Internal network only |
| 27694 | canrx | CAN bus UDP | Firewall-restricted (Longboard only) |
| 28205 | - | Aurix data logging | Firewall-restricted (Aurix only) |

### Security-Sensitive Binaries

**SUID Root (5 binaries):**
1. `/opt/autopilot/bin/read_device_key` (52KB) - **TPM access - HIGH RISK**
2. `/opt/autopilot/bin/package_signer` (60KB, SGID) - Firmware signing
3. `/bin/busybox` - Standard utilities
4. `/bin/traceroute6` - Network diagnostic
5. `/bin/ping` - Network diagnostic

### Services (62 total)

**Critical Autopilot Services:**
- autopilot, autopilot-b, autopilot-state-machine
- vision (389MB neural network engine)
- perception, camera, backup-camera
- factory-camera-calibration ⚠️

**Planning & Control:**
- mission-planner, lane-change, stay-in-lane
- parking-behavior, controller, active-safety

**Backend Communication (Hermes):**
- hermes (21MB main daemon)
- hermes-eventlogs (12MB)
- hermes-teleforce (9.6MB - remote commands)
- hermes-grablogs (9.8MB)
- hermes-fileupload (9.1MB)

**API Servers:**
- service-api (HTTP)
- service-api-tls (HTTPS port 8081)

### Certificate Infrastructure

**Tesla CA Hierarchy:**
- Product Access CA (mTLS authentication)
- Products CA (backend services)
- Services CA (prod/eng/mfg)
- Supercharger CA
- Fleet Management CA
- Legacy CAs (backward compatibility)

**Board Credentials:**
- `/var/lib/board_creds/board.crt` - Device certificate
- `/var/lib/board_creds/board.key` - TPM-backed private key

**TPM Engine:** `fsdtpm` (FSD TPM Engine)

### Factory Mode

**Detection Scripts:**
- `/usr/bin/is-in-factory`
- `/usr/bin/is-development-ape`
- `/sbin/detect-ecu-benchtop`
- `/sbin/detect-ecu-unfused`
- `/sbin/unload-apparmor-in-factory`

**Factory Mode Behaviors:**
- AppArmor security disabled
- Rate limiting disabled on service_api
- Port 8901 active (factory calibration)
- Calibration file clearing permitted

**Calibration State:**
- `/factory/.calibration-in-progress` - Lock file during calibration

### Build Information

```
Git Commit: 0cac3042b6cd3c716601e6ed6d3d0be65ab47d74
Build Date: 1712350968 (April 6, 2024 21:42:48 UTC)
Build Path: /mnt/firmware_artifacts/jenkins-job/firmware-repo-feature-2024-8-9/git/.../build/7/ui-artifacts/model3-rootfs-unsigned-parker.ssq
Product: ap (Autopilot Processor)
Platform: parker (NVIDIA Tegra)
Timezone: America/Los_Angeles
```

### Users (52 total)
Notable users:
- root
- factorycameracalibration
- (Additional 50 service users - see 40-ape-users.txt)

### Groups (85 total)
Notable groups:
- camera - Camera device access
- gpgpu - GPU access
- rtdv - Real-time device access
- autopilot - Autopilot service group
- factorycameracalibration - Factory calibration service
- (Additional groups - see 40-ape-groups.txt)

### Network Topology

```
┌─────────────────────────────────────────┐
│  Internal Autopilot Network             │
│  192.168.90.0/24                        │
├─────────────────────────────────────────┤
│                                         │
│  192.168.90.103 - APE-A (this system)  │
│    ├─ Port 8081 (service-api-tls)      │
│    ├─ Port 8901 (factory-calibration)  │
│    └─ Port 8902 (apeb-file-server)     │
│                                         │
│  192.168.90.104 - Longboard/Aurix      │
│    ├─ UDP 27694 → APE (CAN RX)         │
│    └─ UDP 28205 → APE (Aurix logging)  │
│                                         │
│  192.168.90.105 - APE-B (redundant)    │
│    └─ TCP 8902 → APE-A (file access)   │
│                                         │
└─────────────────────────────────────────┘
```

## Priority Reverse Engineering Targets

### Tier 1 (Critical)
1. **vision** (389MB) - Neural network engine, likely contains model weights
2. **factory_camera_calibration** (3.1MB) - Port 8901 HTTP server, **active during SD format**
3. **service_api** (6.9MB) - Go binary, mTLS API server on port 8081

### Tier 2 (High Priority)
4. **hermes_teleforce** (9.6MB) - Remote command execution
5. **read_device_key** (52KB) - SUID root, TPM access
6. **autopilot_state_machine** (1.4MB) - FSD mode control

### Tier 3 (Important)
7. **hermes** (21MB) - Main backend daemon
8. **perception** (2.8MB) - Object detection
9. **localizer** (1.9MB) - Vehicle positioning
10. **cantx** (1.1MB) - CAN bus output to vehicle

## Attack Surface Analysis

### Port 8901 (Factory Calibration)
**Status:** Likely exposed during SD card format  
**Authentication:** Unknown (probably none in factory mode)  
**Risk:** HIGH - Potential unauthenticated access  
**Endpoints Found:**
- `/board_info/cameras_init_done_for_apb`

**Next Steps:**
- Reverse engineer factory_camera_calibration binary
- Enumerate all HTTP endpoints
- Test for authentication bypass
- Attempt to trigger factory mode remotely

### Port 8081 (Service API)
**Status:** Always active  
**Authentication:** mTLS (client certificate required)  
**Risk:** MEDIUM - Certificate validation bypass opportunities  
**Capabilities:**
- Clear calibration files (triggers factory mode)
- Query board info
- (Full enumeration required)

**Next Steps:**
- Reverse engineer Go binary (use go-unstrip)
- Map all API endpoints
- Test certificate validation
- Attempt to obtain client certificate

### SUID Binary (read_device_key)
**Status:** SUID root  
**Risk:** HIGH - Privilege escalation vector  
**Purpose:** Read TPM device key  

**Next Steps:**
- Static analysis for buffer overflows
- Input validation testing
- Race condition analysis

### Factory Mode Trigger
**Hypothesis:** Clearing calibration files triggers factory mode  
**Method:** Service API endpoint or direct filesystem access  

**Next Steps:**
- Identify exact trigger mechanism
- Test remote factory mode activation
- Exploit factory mode for persistent access

## File Inventory

### Primary Documentation
- **40-ape-firmware-extraction.md** (33KB) - Full detailed analysis
- **40-ape-extraction-summary.md** (this file) - Quick reference

### Reference Lists
- **40-ape-binaries-list.txt** - All autopilot binaries (45 files)
- **40-ape-binary-types.txt** - File types for all binaries
- **40-ape-services-list.txt** - All runit services (62 services)
- **40-ape-suid-sgid-binaries.txt** - Privilege escalation targets (5 files)
- **40-ape-certificates.txt** - Certificate store inventory (28 files)
- **40-ape-users.txt** - User accounts (52 users)
- **40-ape-groups.txt** - Group definitions (85 groups)
- **40-ape-filesystem-tree.txt** - Directory structure

## Next Phase: Dynamic Analysis

### Environment Setup
1. Set up QEMU ARM aarch64 emulation
2. Create chroot environment
3. Attach debugger (gdb-multiarch)
4. Set up network bridge for internal network simulation

### Testing Plan
1. **Port 8901 Fuzzing:**
   - Enumerate endpoints via directory bruteforce
   - Fuzz HTTP parameters
   - Test for authentication bypass

2. **Service API Analysis:**
   - Reverse engineer Go binary
   - Test mTLS validation
   - Attempt certificate spoofing

3. **Factory Mode Triggering:**
   - Test calibration file clearing
   - Monitor filesystem changes
   - Capture factory mode activation sequence

4. **CAN Bus Simulation:**
   - Replay captured CAN messages
   - Test vehicle control commands
   - Analyze safety boundaries

## Critical Security Findings

### ⚠️ AppArmor Disabled in Factory Mode
- `/sbin/unload-apparmor-in-factory` removes all security profiles
- Factory mode = full system access
- **Impact:** Complete security bypass if factory mode can be triggered

### ⚠️ Service API Can Clear Calibration
- Clearing calibration files forces factory calibration mode
- Strings in service_api: "successfully cleared calibration files for '%s' camera, reboot requested"
- **Impact:** Remote factory mode activation possible

### ⚠️ SUID Root TPM Access
- `read_device_key` runs as root
- Direct TPM access
- **Impact:** Potential for privilege escalation

### ⚠️ Remote Command Execution
- hermes_teleforce (9.6MB) executes commands from Tesla backend
- **Impact:** Depends on command authentication/authorization (requires analysis)

## Recommended Deep Dive Tools

### Static Analysis
- **Ghidra** - Primary RE tool
- **IDA Pro** - Alternative/comparison
- **Binary Ninja** - Modern RE platform
- **go-unstrip** - Recover Go symbols from service_api
- **strings** - Quick string extraction
- **binwalk** - Embedded file extraction

### Dynamic Analysis
- **QEMU** - ARM emulation
- **gdb-multiarch** - Cross-architecture debugging
- **strace** - System call tracing
- **ltrace** - Library call tracing
- **tcpdump** - Network traffic capture
- **Wireshark** - Traffic analysis

### Fuzzing
- **AFL++** - Coverage-guided fuzzing
- **Radamsa** - General-purpose fuzzer
- **ffuf** - HTTP endpoint fuzzing
- **Burp Suite** - Web API testing

### Specialized
- **nsight** - NVIDIA GPU debugging (for vision binary)
- **TensorRT** - Analyze embedded neural networks
- **openssl** - Certificate manipulation
- **tpm2-tools** - TPM interaction

## References

### Related Documents
- `10-tesla-firmware-sources.md` - Original firmware acquisition
- `20-gateway-firmware-analysis.md` - Gateway ECU analysis
- `30-sd-card-attack.md` - SD format attack vector

### External Resources
- Tesla Motors OID: 1.3.6.1.4.1.49279 (IANA-assigned)
- NVIDIA Tegra Parker documentation
- ARM AArch64 instruction set reference
- Go binary reverse engineering guides

---

**Status:** ✅ PHASE 1 & 2 COMPLETE  
**Next Task:** Binary reverse engineering (Phase 3)  
**Priority Target:** factory_camera_calibration (port 8901)
