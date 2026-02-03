# APE Firmware Extraction - Document Index

**Task:** Extract and catalog Tesla Autopilot ECU firmware  
**Firmware:** 2024.8.9.ice.ape25 (534MB SquashFS)  
**Status:** ✅ COMPLETE  
**Date:** 2026-02-03

---

## Primary Documentation

### 📋 40-ape-extraction-summary.md (11KB)
**Quick reference guide** - Start here!

Key contents:
- Extraction statistics (2,988 files, 962MB)
- Network services (ports 8081, 8901, 8902)
- Security findings (SUID binaries, factory mode)
- Attack surface analysis
- Next steps for reverse engineering

### 📖 40-ape-firmware-extraction.md (33KB)
**Comprehensive deep-dive analysis** - Full details!

Sections:
- Phase 1: Extraction results
- Phase 2: Filesystem structure
- Key binaries catalog (60+ services)
- Network services & ports
- Certificate stores (Tesla CA hierarchy)
- Update mechanisms
- Debugging interfaces
- Security analysis
- Hardware interfaces
- Data flows
- Reverse engineering targets
- Boot process
- User/group analysis

---

## Reference Lists (Quick Lookups)

### 40-ape-binaries-list.txt (45 files)
Complete list of autopilot binaries in `/opt/autopilot/bin/`

Notable entries:
- vision (389MB) - Neural network engine
- factory_camera_calibration (3.1MB) - Port 8901 server
- service_api (6.9MB) - Port 8081 API server
- hermes binaries (21MB-9MB) - Backend communication

### 40-ape-binary-types.txt (8KB)
File type analysis for all binaries (output of `file` command)

### 40-ape-services-list.txt (62 services)
All runit-managed services in `/etc/sv/`

Critical services:
- autopilot, autopilot-b, autopilot-state-machine
- vision, perception, camera
- factory-camera-calibration ⚠️
- service-api, service-api-tls
- hermes, hermes-teleforce

### 40-ape-suid-sgid-binaries.txt (5 files)
**SECURITY CRITICAL** - Privilege escalation targets

Files:
1. `/opt/autopilot/bin/read_device_key` (SUID root) - **HIGH RISK**
2. `/opt/autopilot/bin/package_signer` (SGID)
3. `/bin/busybox` (SUID root)
4. `/bin/traceroute6` (SUID root)
5. `/bin/ping` (SUID root)

### 40-ape-certificates.txt (28 files)
Tesla certificate store inventory

Key CAs:
- ProductAccessCAs.pem (mTLS authentication)
- ProductsCAs.pem (backend services)
- ServicesCAsPrd/Eng/Mfg.pem
- SuperchargerCAs.pem
- FleetManagementCAs.pem

### 40-ape-users.txt (52 users)
User account enumeration from `/etc/passwd`

Notable users:
- root
- factorycameracalibration
- (50 service-specific users)

### 40-ape-groups.txt (85 groups)
Group definitions from `/etc/group`

Notable groups:
- camera (camera device access)
- gpgpu (GPU access)
- rtdv (real-time device access)
- autopilot
- factorycameracalibration

### 40-ape-filesystem-tree.txt (62 directories)
Directory structure (2 levels deep)

---

## Source & Extraction Locations

### Source Firmware
```
Path: /root/downloads/ape-firmware/2024.8.9.ice.ape25
Size: 534 MB (SquashFS compressed)
Type: Linux filesystem image
Format: SquashFS
```

### Extracted Filesystem
```
Path: /root/downloads/ape-extracted/
Size: 962 MB (uncompressed)
Files: 2,988
Directories: 379
Symlinks: 984
```

### Documentation Output
```
Path: /root/tesla/40-ape-*.md, 40-ape-*.txt
Files: 10 documents
Total Size: ~60KB
```

---

## Quick Commands Reference

### Re-extract firmware
```bash
unsquashfs -d /root/downloads/ape-extracted /root/downloads/ape-firmware/2024.8.9.ice.ape25
```

### Browse extracted filesystem
```bash
cd /root/downloads/ape-extracted
ls -la
```

### Find specific binaries
```bash
find /root/downloads/ape-extracted/opt/autopilot/bin -name "*calibration*"
```

### List all services
```bash
ls -1 /root/downloads/ape-extracted/etc/sv/
```

### Check SUID binaries
```bash
find /root/downloads/ape-extracted -perm -4000 -ls
```

### View build metadata
```bash
cat /root/downloads/ape-extracted/etc/build-info
cat /root/downloads/ape-extracted/etc/commit
date -d @$(cat /root/downloads/ape-extracted/etc/build-date)
```

### Analyze binary
```bash
file /root/downloads/ape-extracted/opt/autopilot/bin/factory_camera_calibration
strings /root/downloads/ape-extracted/opt/autopilot/bin/factory_camera_calibration | less
```

---

## Key Findings Summary

### 🚨 Critical Security Findings

1. **Port 8901 Exposure (Factory Calibration)**
   - HTTP server active during SD card format
   - Likely no authentication in factory mode
   - Attack vector: Exploit during service mode SD format

2. **Factory Mode Security Bypass**
   - AppArmor disabled: `/sbin/unload-apparmor-in-factory`
   - Rate limiting disabled on service_api
   - Full system access when in factory mode

3. **Remote Factory Mode Triggering**
   - Service API can clear calibration files
   - Clearing calibration forces factory calibration mode
   - String found: "successfully cleared calibration files for '%s' camera, reboot requested"

4. **SUID Root TPM Access**
   - `/opt/autopilot/bin/read_device_key` runs as root
   - Direct TPM device key access
   - Privilege escalation potential

5. **Remote Command Execution**
   - `hermes_teleforce` (9.6MB) - Tesla backend remote control
   - Command authentication/authorization needs analysis

### 🔌 Network Attack Surface

| Port | Service | Auth | Risk | Notes |
|------|---------|------|------|-------|
| 8081 | service-api-tls | mTLS | MED | Client cert required, bypass opportunities |
| 8901 | factory-camera-calibration | None? | **HIGH** | Active during SD format, likely unauthenticated |
| 8902 | apeb-file-server | Internal | LOW | Restricted to 192.168.90.105 |
| 27694 | canrx (UDP) | Firewall | MED | Restricted to Longboard (192.168.90.104) |
| 28205 | Aurix logging (UDP) | Firewall | LOW | Restricted to Aurix (192.168.90.104) |

### 🎯 Top Priority Reverse Engineering Targets

1. **factory_camera_calibration** (3.1MB)
   - Port 8901 HTTP server
   - Enumerate all endpoints
   - Test authentication bypass
   - Map calibration workflow

2. **vision** (389MB)
   - Neural network engine
   - Extract model weights
   - Analyze TensorRT engines
   - Understand FSD vision stack

3. **service_api** (6.9MB)
   - Go binary (stripped)
   - Recover symbols with go-unstrip
   - Map all API endpoints
   - Test mTLS validation bypass

4. **read_device_key** (52KB, SUID)
   - TPM access
   - Buffer overflow analysis
   - Privilege escalation exploit

5. **hermes_teleforce** (9.6MB)
   - Remote command execution
   - Authentication analysis
   - Command injection testing

---

## Next Phase: Reverse Engineering Plan

### Phase 3: Binary Analysis (Current Priority)

#### Step 1: factory_camera_calibration (Port 8901)
**Goal:** Enumerate HTTP API endpoints

Tasks:
- [ ] Load in Ghidra/IDA Pro
- [ ] Identify HTTP server library (libmicrohttpd? custom?)
- [ ] Find route/endpoint registration
- [ ] Map all URL handlers
- [ ] Identify authentication checks (or lack thereof)
- [ ] Document API parameters
- [ ] Test endpoints dynamically (if possible)

**Expected Endpoints:**
- `/board_info/cameras_init_done_for_apb` (confirmed)
- `/calibrate` (hypothesis)
- `/status` (hypothesis)
- `/upload` (hypothesis)
- `/download` (hypothesis)

#### Step 2: service_api (Port 8081)
**Goal:** Map Go API surface

Tasks:
- [ ] Run go-unstrip to recover symbols
- [ ] Identify HTTP framework (net/http, gin, echo?)
- [ ] Enumerate routes and handlers
- [ ] Analyze mTLS certificate validation
- [ ] Find calibration file clearing logic
- [ ] Test certificate spoofing

#### Step 3: vision (389MB)
**Goal:** Extract neural network models

Tasks:
- [ ] Identify TensorRT engine files (binwalk)
- [ ] Extract model architectures
- [ ] Analyze input/output tensors
- [ ] Document camera preprocessing
- [ ] Understand inference pipeline

### Phase 4: Dynamic Analysis

#### Environment Setup
1. **QEMU ARM Emulation**
   ```bash
   qemu-system-aarch64 -M virt -cpu cortex-a57 \
     -kernel vmlinuz -initrd initrd.img \
     -append "root=/dev/vda console=ttyAMA0" \
     -drive file=rootfs.img,format=raw,id=hd0 \
     -device virtio-blk-device,drive=hd0 \
     -netdev user,id=net0 -device virtio-net-device,netdev=net0 \
     -nographic
   ```

2. **Chroot Environment**
   ```bash
   sudo chroot /root/downloads/ape-extracted /bin/sh
   ```

3. **GDB Debugging**
   ```bash
   gdb-multiarch /root/downloads/ape-extracted/opt/autopilot/bin/factory_camera_calibration
   ```

#### Testing Scenarios

**Scenario 1: Port 8901 Fuzzing**
- Start factory_camera_calibration in debugger
- Fuzz HTTP endpoints with ffuf/Burp Suite
- Capture crashes and interesting responses
- Test for directory traversal, command injection

**Scenario 2: Factory Mode Triggering**
- Monitor filesystem with inotifywait
- Trigger calibration file clearing via service_api
- Observe factory mode activation sequence
- Document state changes

**Scenario 3: mTLS Bypass**
- Generate self-signed client certificate
- Test service_api with invalid cert
- Analyze certificate validation logic
- Attempt certificate pinning bypass

### Phase 5: Exploit Development

**Target 1: Port 8901 Unauthenticated Access**
- Exploit: Direct HTTP access during SD format
- Payload: Upload malicious calibration data
- Goal: Code execution or persistence

**Target 2: Remote Factory Mode Activation**
- Exploit: Service API calibration file clearing
- Payload: Trigger factory mode via API
- Goal: Disable security (AppArmor bypass)

**Target 3: SUID Privilege Escalation**
- Exploit: read_device_key buffer overflow
- Payload: Arbitrary code execution as root
- Goal: Full system compromise

---

## Integration with Other Research

### Related Documents
- **10-tesla-firmware-sources.md** - Original firmware acquisition notes
- **20-gateway-firmware-analysis.md** - Gateway ECU analysis
- **30-sd-card-attack.md** - SD format attack vector (where port 8901 is exposed)

### Attack Chain
```
1. Trigger service mode SD format (from 30-sd-card-attack.md)
   ↓
2. During format, port 8901 becomes accessible
   ↓
3. Exploit factory_camera_calibration HTTP API (this research)
   ↓
4. Upload malicious calibration data OR trigger factory mode
   ↓
5. Gain code execution or persistent access
   ↓
6. Escalate privileges via read_device_key (SUID exploit)
   ↓
7. Full APE compromise
```

---

## Build Metadata

### Version Information
```
Version: 2024.8.9.ice.ape25
Git Commit: 0cac3042b6cd3c716601e6ed6d3d0be65ab47d74
Build Date: 1712350968 (Fri Apr  5 21:42:48 UTC 2024)
Product: ap (Autopilot Processor)
Platform: parker (NVIDIA Tegra)
Architecture: ARM aarch64 (64-bit)
Timezone: America/Los_Angeles
```

### Build Path
```
/mnt/firmware_artifacts/jenkins-job/firmware-repo-feature-2024-8-9/git/0cac3042b6cd3c716601e6ed6d3d0be65ab47d74/build/7/ui-artifacts/model3-rootfs-unsigned-parker.ssq
```

**Note:** "unsigned" in filename suggests this is pre-signing build artifact

---

## Tools & Resources

### Static Analysis
- **Ghidra** - Free, powerful RE framework
- **IDA Pro** - Commercial standard
- **Binary Ninja** - Modern alternative
- **go-unstrip** - Recover Go symbols
- **strings** - Quick string extraction
- **binwalk** - Embedded file detection
- **radare2** - CLI-based RE

### Dynamic Analysis
- **QEMU** - CPU emulation
- **gdb-multiarch** - Cross-arch debugging
- **strace** - System call tracing
- **ltrace** - Library call tracing
- **frida** - Dynamic instrumentation
- **valgrind** - Memory debugging

### Network/Fuzzing
- **tcpdump/Wireshark** - Traffic capture
- **Burp Suite** - Web API testing
- **ffuf** - HTTP fuzzing
- **AFL++** - Coverage-guided fuzzing
- **radamsa** - General fuzzer

### Specialized
- **nsight** - NVIDIA GPU debugging
- **TensorRT** - Neural network analysis
- **openssl** - Certificate tools
- **tpm2-tools** - TPM interaction
- **go-unstrip** - Go symbol recovery

---

## Status & Next Actions

### ✅ Completed
- [x] Extract SquashFS firmware (2,988 files)
- [x] Document filesystem structure
- [x] Catalog all binaries and services
- [x] Identify network services and ports
- [x] Analyze certificate infrastructure
- [x] Find SUID/SGID binaries
- [x] Map security mechanisms
- [x] Create comprehensive documentation

### 🔄 In Progress
- [ ] None (extraction complete)

### 📋 Next Tasks (Priority Order)
1. **Reverse engineer factory_camera_calibration** (port 8901)
   - Load in Ghidra
   - Map HTTP endpoints
   - Test authentication

2. **Analyze service_api** (port 8081)
   - Recover Go symbols
   - Enumerate API routes
   - Test mTLS bypass

3. **Extract vision models** (389MB binary)
   - Run binwalk for embedded files
   - Identify TensorRT engines
   - Extract neural network architectures

4. **Set up dynamic analysis environment**
   - QEMU ARM emulation
   - Network simulation
   - Debugging infrastructure

5. **Develop port 8901 exploit**
   - Test during SD format scenario
   - Fuzz endpoints
   - Achieve code execution

---

**Document Created:** 2026-02-03  
**Analyst:** OpenClaw Subagent (ape-firmware-extraction)  
**Task Status:** ✅ COMPLETE (Phase 1 & 2)  
**Next Phase:** Binary Reverse Engineering (Phase 3)
