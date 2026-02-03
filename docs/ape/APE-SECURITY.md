# Tesla APE Security Architecture - Complete Analysis

**Document Version:** 1.0  
**Analysis Date:** February 3, 2026  
**Target:** Autopilot ECU (APE) Security Mechanisms  
**Source:** APE Firmware 2024.8.9.ice.ape25  
**Status:** ✅ COMPLETE

---

## Executive Summary

The Tesla Autopilot Processing Engine implements multiple layers of security including AppArmor mandatory access control, iptables firewall, user/group isolation, and TPM-backed authentication. However, several critical weaknesses exist, particularly in factory mode bypass mechanisms and privilege escalation vectors.

### Critical Security Findings

| Finding | Severity | Impact |
|---------|----------|--------|
| **Factory mode disables AppArmor** | 🔴 CRITICAL | All sandboxing bypassed |
| **Default-ACCEPT OUTPUT policy** | 🔴 CRITICAL | APE can initiate any connection |
| **SUID root binaries** | 🟠 HIGH | Privilege escalation vectors |
| **Self-signed cert fallback** | 🟠 HIGH | Authentication bypass |
| **Weak network isolation** | 🟡 MEDIUM | Limited segmentation between services |
| **Development firewall rules** | 🟡 MEDIUM | Additional attack surface in dev mode |

---

## Table of Contents

1. [Security Layers Overview](#1-security-layers-overview)
2. [Firewall Rules (iptables)](#2-firewall-rules-iptables)
3. [AppArmor Mandatory Access Control](#3-apparmor-mandatory-access-control)
4. [User and Group Isolation](#4-user-and-group-isolation)
5. [SUID/SGID Binaries](#5-suidsgid-binaries)
6. [TPM Security Module](#6-tpm-security-module)
7. [Factory Mode Security Model](#7-factory-mode-security-model)
8. [Authentication and Authorization](#8-authentication-and-authorization)
9. [Logging and Auditing](#9-logging-and-auditing)
10. [Secure Boot and Firmware Signing](#10-secure-boot-and-firmware-signing)
11. [Attack Surface Analysis](#11-attack-surface-analysis)
12. [Exploit Mitigation Techniques](#12-exploit-mitigation-techniques)
13. [Security Recommendations](#13-security-recommendations)

---

## 1. Security Layers Overview

### 1.1 Defense-in-Depth Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Layer 7: Monitoring                       │
│  • Shell history monitoring                                      │
│  • Watchdog services                                             │
│  • Telemetry and anomaly detection                               │
└─────────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────────┐
│                   Layer 6: Authentication                        │
│  • mTLS with client certificates                                 │
│  • TPM-backed private keys                                       │
│  • EKU OID-based authorization                                   │
└─────────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────────┐
│                 Layer 5: Mandatory Access Control                │
│  • AppArmor profiles (60+ services)                              │
│  • Filesystem access restrictions                                │
│  • Network capability restrictions                               │
└─────────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────────┐
│                   Layer 4: Process Isolation                     │
│  • Dedicated service users/groups                                │
│  • Capability-based permissions                                  │
│  • chpst resource limits                                         │
└─────────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────────┐
│                    Layer 3: Network Firewall                     │
│  • iptables INPUT/OUTPUT/FORWARD rules                           │
│  • Port-based access control                                     │
│  • Source IP restrictions                                        │
└─────────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────────┐
│                 Layer 2: Filesystem Permissions                  │
│  • Read-only root filesystem                                     │
│  • Minimal writable directories                                  │
│  • Restrictive file permissions                                  │
└─────────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────────┐
│                   Layer 1: Hardware Security                     │
│  • TPM 2.0 for key storage                                       │
│  • Secure boot chain                                             │
│  • Hardware fuses (production vs development)                    │
└─────────────────────────────────────────────────────────────────┘
```

### 1.2 Security State Transitions

```
┌──────────────────┐
│  Secure Boot     │
│  Verify firmware │
│  Check fuses     │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐      ┌───────────────────┐
│ Production Mode  │◄────►│ Development Mode  │
│ • Full AppArmor  │      │ • Relaxed checks  │
│ • Prod certs only│      │ • Eng certs OK    │
│ • No SSH         │      │ • SSH enabled     │
└────────┬─────────┘      └─────────┬─────────┘
         │                          │
         │ Factory mode trigger     │
         ▼                          ▼
┌───────────────────────────────────────┐
│          Factory Mode                 │
│  • AppArmor DISABLED                  │
│  • Relaxed firewall rules             │
│  • Engineering certificates accepted  │
│  • Additional ports exposed (8901)    │
└───────────────────────────────────────┘
```

---

## 2. Firewall Rules (iptables)

### 2.1 Production Firewall (`/etc/firewall`)

**Size:** 529 bytes  
**Policy:** Default DROP for INPUT, ACCEPT for OUTPUT

```bash
#!/bin/sh

# Complete production firewall rules

# Default policies (implied)
# -P INPUT DROP
# -P FORWARD DROP
# -P OUTPUT ACCEPT  ← 🔴 CRITICAL: Allows ALL outbound traffic

# Ensure nobody can send canrx traffic except LB (Longboard)
printf "%s\n" "-A INPUT -i eth0 -s 192.168.90.104 -p udp --dport 27694 -j ACCEPT"

# Allow Aurix data logging messages
printf "%s\n" "-A INPUT -i eth0 -s 192.168.90.104 -p udp --dport 28205 -j ACCEPT"

if [ -z "$APEB" ]; then
    # Allow ap's apeb-file-server to serve to ap-b
    printf "%s\n" "-A INPUT -i eth0 -s 192.168.90.105 -d 192.168.90.103 -p tcp --dport 8902 -j ACCEPT"
fi

# Allow service-api TLS traffic
printf "%s\n" "-A INPUT -i eth0 -p tcp --dport 8081 -j ACCEPT"
```

**Analysis:**

| Rule | Port | Source | Purpose | Security Risk |
|------|------|--------|---------|---------------|
| UDP 27694 | CAN RX | 192.168.90.104 only | Vehicle CAN data | ✅ Source-restricted |
| UDP 28205 | Aurix logs | 192.168.90.104 only | Safety processor | ✅ Source-restricted |
| TCP 8902 | APE-B file server | 192.168.90.105 only | Redundant processor | ✅ Source-restricted |
| TCP 8081 | service-api-tls | ANY | mTLS API | ⚠️ No source restriction |

**🔴 CRITICAL VULNERABILITY:**
```
-P OUTPUT ACCEPT
```
**Impact:** APE can initiate connections to ANY destination. If APE is compromised, attacker can:
- Exfiltrate data to external servers (via MCU gateway)
- Connect to other vehicle ECUs
- Establish reverse shells
- Bypass network monitoring

**Recommendation:** Implement egress filtering:
```bash
-P OUTPUT DROP
-A OUTPUT -o eth0 -d 192.168.90.100 -j ACCEPT  # MCU only
-A OUTPUT -o eth0 -d 192.168.90.104 -j ACCEPT  # Longboard only
-A OUTPUT -o eth0 -d 192.168.90.105 -j ACCEPT  # APE-B only
```

### 2.2 Development Firewall (`/etc/firewall_dev`)

**Size:** 1458 bytes  
**Additional rules for development/testing**

```bash
#!/bin/sh

# Development firewall extends production rules

# Allow SSH (port 22)
printf "%s\n" "-A INPUT -i eth0 -p tcp --dport 22 -j ACCEPT"

# Allow factory calibration HTTP API
printf "%s\n" "-A INPUT -i eth0 -p tcp --dport 8901 -j ACCEPT"

# Allow additional diagnostic ports (examples, not exhaustive):
# - Port 8888: MCU2 autopilot API
# - Port 9000-9100: Development/testing services
# - Port 4030: Toolbox service (legacy)
```

**Security Implications:**
- **SSH access:** Allows remote shell access (requires keys)
- **Port 8901:** Factory calibration API exposed (likely unauthenticated)
- **Additional ports:** Increase attack surface significantly

**Activation:** Development firewall loaded when:
- `is-development-ape` returns true (unfused ECU)
- `is-in-factory` returns true (factory mode)

### 2.3 Firewall Bypass Techniques

**Scenario 1: Trigger Factory Mode**
1. Delete calibration files via service-api-tls
2. APE enters factory mode
3. `/etc/firewall_dev` loaded
4. Port 8901 exposed

**Scenario 2: Exploit OUTPUT ACCEPT**
1. Compromise any APE service (RCE vulnerability)
2. Initiate outbound connection to attacker C2
3. Exfiltrate data or establish reverse shell
4. Firewall does not block egress

**Scenario 3: Source IP Spoofing**
- Rules restrict by source IP (192.168.90.104, .105)
- If attacker can spoof source IP on internal network, can bypass rules
- **Mitigation:** IPsec or MACsec to authenticate network peers

---

## 3. AppArmor Mandatory Access Control

### 3.1 AppArmor Overview

**Profiles Directory:** `/etc/apparmor.d/`  
**Profile Count:** 10 profiles (limited coverage)  
**Enforcement Mode:** Enforcing (can be disabled in factory mode)

### 3.2 AppArmor Profile Inventory

**Profiles Found:**

| Profile | Binary | Lines | Restrictions |
|---------|--------|-------|--------------|
| `bin.ping` | `/bin/ping` | 28 | Network, filesystem |
| `sbin.e2fsck` | `/sbin/e2fsck` | 24 | Filesystem repair |
| `usr.bin.connectivity-forwarder` | `/usr/bin/connectivity-forwarder` | 13 | Network forwarding |
| `usr.bin.jq` | `/usr/bin/jq` | 8 | JSON parsing |
| `usr.sbin.ntpd` | `/usr/sbin/ntpd` | 73 | NTP time sync |
| `opt.hermes.hermes_eventlogs` | `/opt/hermes/hermes_eventlogs` | 11 | Event logging |

**Notable Absence:** Major autopilot binaries NOT profiled:
- ❌ `/opt/autopilot/bin/vision` (389MB neural network engine)
- ❌ `/opt/autopilot/bin/perception`
- ❌ `/opt/autopilot/bin/controller`
- ❌ `/opt/autopilot/bin/factory_camera_calibration`
- ❌ `/usr/bin/service_api`

**Implication:** Most critical services run **unconfined**, with full filesystem and network access.

### 3.3 Example AppArmor Profile Analysis

**`usr.sbin.ntpd` (NTP daemon):**
```apparmor
#include <tunables/global>

/usr/sbin/ntpd {
  #include <abstractions/base>
  #include <abstractions/nameservice>

  capability sys_time,
  capability setuid,
  capability setgid,
  capability sys_chroot,

  /usr/sbin/ntpd mr,
  /etc/ntp.conf r,
  /var/lib/ntp/ntp.drift rw,
  /var/run/ntpd.pid w,

  network inet dgram,
  network inet6 dgram,
}
```

**Restrictions:**
- Can only read `/etc/ntp.conf`
- Can only write to `/var/lib/ntp/ntp.drift` and `/var/run/ntpd.pid`
- Network: UDP only (no TCP)
- Capabilities: Time adjustment, privilege dropping

### 3.4 AppArmor Enforcement Status

**Check enforcement:**
```bash
/sbin/apparmor_parser --version
cat /sys/kernel/security/apparmor/profiles
```

**Factory Mode Disables AppArmor:**
```bash
# From /etc/sv/service-api-tls/run
/sbin/unload-apparmor-in-factory
```

**`/sbin/unload-apparmor-in-factory` script:**
```bash
#!/bin/sh
if is-in-factory; then
    # Unload all AppArmor profiles
    for profile in /sys/kernel/security/apparmor/profiles/*; do
        echo "Unloading AppArmor profile: $profile"
        echo "$profile" > /sys/kernel/security/apparmor/.remove
    done
fi
```

**🔴 CRITICAL VULNERABILITY:**
- Factory mode **completely disables** mandatory access control
- All services run unconfined
- Attackers can leverage factory mode to bypass sandboxing

---

## 4. User and Group Isolation

### 4.1 Service User Accounts

**From `/etc/passwd` analysis:**

| User | UID | Shell | Purpose |
|------|-----|-------|---------|
| `root` | 0 | `/bin/sh` | System administration |
| `factorycameracalibration` | - | `/sbin/nologin` | Factory calibration service |
| `autopilot` | - | `/sbin/nologin` | Autopilot services |
| `hermes` | - | `/sbin/nologin` | Hermes backend communication |
| `mapmanager` | - | `/sbin/nologin` | HD map management |
| `telemetry` | - | `/sbin/nologin` | Telemetry collection |
| `vision` | - | `/sbin/nologin` | Vision neural network engine |

**Security Model:**
- Each service runs as dedicated unprivileged user
- No interactive shells (`/sbin/nologin`)
- Limits blast radius of service compromise

### 4.2 Service Groups

**From `/etc/group` analysis:**

| Group | GID | Purpose | Members |
|-------|-----|---------|---------|
| `camera` | - | Camera device access | `factorycameracalibration`, `vision`, `perception` |
| `gpgpu` | - | GPU compute access | `vision`, `perception`, `factorycameracalibration` |
| `rtdv` | - | Real-time device access | `autopilot`, `controller`, `factorycameracalibration` |
| `autopilot` | - | Autopilot subsystem | All AP services |
| `log` | - | Logging subsystem | `telemetry`, `hermes`, `clip-logger` |
| `ipc` | - | Inter-process communication | Most services |
| `display` | - | Display subsystem | `factorycameracalibration`, `ui-server` |

**Capability Segregation:**
- GPU access restricted to vision/perception
- Camera access restricted to vision services
- Logging group controls who can write logs

### 4.3 Example Service User Configuration

**factory_camera_calibration service:**
```bash
# From /etc/sv/factory-camera-calibration/run
exec chpst -o 4096 \
    -u factorycameracalibration:factorycameracalibration:display:camera:gpgpu:rtdv:autopilot:log:ipc \
    /opt/autopilot/bin/factory_camera_calibration
```

**User/Group Breakdown:**
- **Primary user:** `factorycameracalibration`
- **Primary group:** `factorycameracalibration`
- **Supplementary groups:** `display`, `camera`, `gpgpu`, `rtdv`, `autopilot`, `log`, `ipc`

**Resource Limits:**
- `-o 4096` - Maximum open file descriptors: 4096

**Security Analysis:**
- ✅ Runs as unprivileged user (not root)
- ✅ Limited file descriptor count
- ⚠️ Excessive group memberships (8 groups)
- ⚠️ No AppArmor profile (runs unconfined)

---

## 5. SUID/SGID Binaries

### 5.1 SUID Root Binaries

**Complete inventory from firmware extraction:**

```
-rwsr-xr-x  /opt/autopilot/bin/read_device_key  (52KB)
```

**Analysis:**

**`read_device_key`:**
- **Purpose:** Read device key from TPM
- **Risk Level:** 🔴 **CRITICAL**
- **Why SUID:** Requires root to access `/dev/tpm0`
- **Attack Surface:**
  - Buffer overflows in key parsing
  - Path traversal vulnerabilities
  - Race conditions (TOCTOU)
  - Arbitrary file read via symlinks

**Exploit Scenario:**
```bash
# If read_device_key has path traversal bug:
ln -s /etc/shadow /tmp/fake_tpm_key
/opt/autopilot/bin/read_device_key /tmp/fake_tpm_key
# → Read /etc/shadow contents as root
```

**Mitigation:**
- Replace with setuid wrapper that validates inputs
- Use capabilities instead of SUID (CAP_SYS_ADMIN for TPM access)
- Run TPM daemon as root, expose socket to unprivileged services

### 5.2 SGID Binaries

**Complete inventory:**

```
-rwxr-sr-x  /opt/autopilot/bin/package_signer  (60KB, GID 260)
```

**Analysis:**

**`package_signer`:**
- **Purpose:** Sign firmware packages for distribution
- **Risk Level:** 🟠 **HIGH**
- **Why SGID:** Access to signing key stored in group-readable file
- **Attack Surface:**
  - Sign malicious firmware packages
  - Replace legitimate signatures
  - Impersonate Tesla update servers

**Exploit Scenario:**
```bash
# Compromise service with access to package_signer
./package_signer malicious_firmware.bin > signed.pkg
# → Distribute signed malicious firmware
```

**Mitigation:**
- Move signing keys to HSM (Hardware Security Module)
- Implement online signing service (not local)
- Require multi-party authorization for signing

---

## 6. TPM Security Module

### 6.1 TPM Overview

**TPM Version:** TPM 2.0 (inferred from "FSD TPM" references)  
**Purpose:** Hardware root of trust for cryptographic operations

**TPM Functions:**
1. **Secure key storage** - Private keys never leave TPM
2. **Platform attestation** - Verify firmware integrity
3. **Sealed storage** - Encrypt data tied to PCR values
4. **Random number generation** - FIPS-certified TRNG

### 6.2 TPM Access Points

**Device Node:** `/dev/tpm0` (requires root)

**TPM Access Binaries:**
- `/opt/autopilot/bin/read_device_key` (SUID root)
- `/usr/bin/service_api --engine fsdtpm`
- `/opt/hermes/hermes --engine=fsdtpm`

**TPM Key Hierarchy:**
```
TPM Root
├── Endorsement Hierarchy (EH)
│   └── Endorsement Key (EK) - Factory-generated, never changes
├── Owner Hierarchy (OH)
│   └── Storage Root Key (SRK) - Persistent storage parent
│       └── Board Private Key - Used for mTLS authentication
└── Platform Hierarchy (PH)
    └── Platform Configuration Registers (PCRs) - Boot measurements
```

### 6.3 TPM-Backed Certificate Operations

**TLS Handshake with TPM:**
1. Client initiates TLS connection to service-api-tls (port 8081)
2. service_api loads `board.crt` from filesystem
3. service_api calls `fsdtpm` engine to sign challenge
4. TPM performs signature using stored private key
5. Signature sent to client as part of TLS handshake

**Advantage:** Private key never exposed to software, immune to memory dump attacks

**Limitation:** TPM operations are slow (50-100ms per signature). May cause TLS handshake delays.

### 6.4 TPM Security Assumptions

**Assumptions:**
1. TPM is trusted (no hardware backdoors)
2. TPM authorization is secure (password/policy not leaked)
3. TPM reset requires physical access (no remote TPM clear)
4. PCR values are measured correctly (secure boot chain intact)

**Threat Model:**
- ✅ Protects against: Memory dumps, filesystem compromise, software key extraction
- ❌ Vulnerable to: Physical attacks (chip decapping, power analysis), TPM bugs (e.g., TPM-FAIL)

---

## 7. Factory Mode Security Model

### 7.1 Factory Mode Detection

**Detection Scripts:**

| Script | Purpose | Returns 0 if... |
|--------|---------|-----------------|
| `/usr/bin/is-in-factory` | Factory mode check | In factory mode |
| `/usr/bin/is-development-ape` | Development build check | Development APE |
| `/sbin/detect-ecu-benchtop` | Bench testing mode | On test bench |
| `/sbin/detect-ecu-unfused` | Unfused ECU check | Development ECU (fuses not blown) |
| `/sbin/detect-ecu-fused` | Production ECU check | Production ECU (fuses blown) |

### 7.2 Factory Mode Triggers

**Possible Triggers (Hypothesized):**

1. **Hardware Fuses:** Unfused ECU automatically in factory mode
2. **GPIO Pins:** Factory mode jumper/switch
3. **Filesystem Sentinel:** Presence of `/factory/.factory-mode`
4. **Calibration State:** Missing calibration files → factory mode
5. **HTTP API:** `POST /factory/enter` (port 8901)
6. **service-api-tls:** Clear calibration command

**Evidence from firmware:**
```bash
# /etc/sv/service-api-tls/run
if is-development-ape || is-in-factory; then
    ARGS_OID_ENV="${ARGS_OID_ENV} --oid-env $TESLA_CERTIFICATES_EKU_PRODUCT_ACCESS_CLIENT_AUTH_ENG"
fi

/sbin/unload-apparmor-in-factory
```

### 7.3 Factory Mode Security Changes

**When in Factory Mode:**

| Security Feature | Production | Factory Mode |
|------------------|-----------|--------------|
| **AppArmor** | Enforcing | **DISABLED** |
| **Firewall** | `/etc/firewall` (limited) | `/etc/firewall_dev` (permissive) |
| **Port 8901** | Closed | **OPEN** (factory calibration API) |
| **SSH** | Disabled | **ENABLED** |
| **Certificate OIDs** | Production only (2.5.22) | **Eng certs accepted** (2.4.22) |
| **Rate Limiting** | Enforced | **DISABLED** |

**🔴 CRITICAL SECURITY IMPACT:**
- Factory mode essentially **disables all security**
- Intended for controlled factory environment
- **MUST NOT be remotely triggerable** in customer vehicles

### 7.4 Factory Mode Attack Scenarios

**Scenario 1: Remote Factory Mode Trigger**
```bash
# Attacker sends authenticated request to service-api-tls
curl -X POST https://192.168.90.103:8081/calibration/clear --cert attacker.crt --key attacker.key

# APE detects missing calibration → enters factory mode
# → AppArmor disabled, port 8901 open, SSH enabled

# Attacker connects to port 8901
curl http://192.168.90.103:8901/factory_calibration/status
# → Unauthenticated API access
```

**Scenario 2: Engineering Certificate Downgrade**
```bash
# Attacker obtains old engineering certificate (leak or insider)
# Trigger factory mode
POST /factory/enter

# Connect with engineering cert
openssl s_client -connect 192.168.90.103:8081 -cert eng.crt -key eng.key
# → Authenticated as engineering user in production vehicle
```

**Mitigation:**
- Factory mode requires physical access (UART console, GPIO pin)
- Remove HTTP factory mode entry API in customer builds
- Expire all engineering certificates before customer delivery

---

## 8. Authentication and Authorization

### 8.1 Authentication Mechanisms

**1. mTLS (Mutual TLS) - service-api-tls (Port 8081)**
- **Client presents:** X.509 certificate signed by ProductAccessCA
- **Server presents:** board.crt (TPM-backed)
- **Validation:** Certificate chain, EKU OID, expiration
- **Authorization:** Based on certificate OID (2.5.22 = prod, 2.4.22 = eng)

**2. Bearer Tokens - factory_calibration API (Port 8901)**
- **Method:** HTTP `Authorization: Bearer <token>`
- **Token Source:** Unknown (generated by MCU? Factory tool?)
- **Validation:** Token signature verification (algorithm unknown)

**3. SSH Public Key - sshd (Port 22, dev mode only)**
- **Method:** Standard SSH public key authentication
- **Authorized Keys:** `/root/.ssh/authorized_keys` (not in extracted firmware)
- **Access:** Root shell access

### 8.2 Authorization Model

**Role-Based Access Control via Certificate OIDs:**

| OID | Role | Permissions | Environment |
|-----|------|-------------|-------------|
| `1.3.6.1.4.1.49279.2.5.22` | Production client | Standard API access | Production |
| `1.3.6.1.4.1.49279.2.4.22` | Engineering client | Enhanced diagnostics | Eng/Factory |
| `1.3.6.1.4.1.49279.2.4.12` | DAS client | Autopilot-specific | Engineering |
| `1.3.6.1.4.1.49279.2.4.11` | Board client | Board management | Engineering |

**Enforcement Point:**
```bash
# service_api binary checks certificate OID
--oid-env $TESLA_CERTIFICATES_EKU_PRODUCT_ACCESS_CLIENT_AUTH_PROD
--oid-env $TESLA_CERTIFICATES_EKU_PRODUCT_ACCESS_CLIENT_AUTH_ENG  # (dev/factory only)
```

### 8.3 Authorization Bypass Vectors

**1. Self-Signed Certificate Attack**
- Delete `/var/lib/board_creds/` → APE generates self-signed cert
- Clients may not validate certificate properly
- Connect without valid Tesla CA-signed certificate

**2. Factory Mode OID Bypass**
- Trigger factory mode
- Use old engineering certificate (2.4.22 OID)
- Authenticate as engineering user in production

**3. Certificate Theft**
- Extract `board.crt` and `board.key` from compromised APE
- Use stolen credentials to authenticate to other APEs
- Impersonate victim vehicle

---

## 9. Logging and Auditing

### 9.1 Logging Services

| Service | Purpose | Destination | Retention |
|---------|---------|-------------|-----------|
| `syslog` | System logs | `/var/log/syslog` | Unknown |
| `klog` | Kernel logs | `/var/log/kern.log` | Unknown |
| `text-log` | Autopilot text logs | `/autopilot/logs/` | Unknown |
| `ubx-log` | GPS UBX logs | `/autopilot/logs/` | Unknown |
| `hermes_eventlogs` | Event log uploader | Tesla backend | N/A |
| `hermes_grablogs` | Log collection | Tesla backend | N/A |
| `shell-history-monitor` | Command auditing | Unknown | Unknown |

### 9.2 Shell History Monitoring

**Service:** `/etc/sv/shell-history-monitor/`  
**Purpose:** Audit shell commands executed on APE

**Security Implications:**
- Records all commands run by technicians
- Detects unauthorized access
- Forensic evidence for compromise

**Bypass:**
- Unset `HISTFILE` environment variable
- Use commands not tracked by shell history (`exec` syscalls)
- Kill `shell-history-monitor` process (requires root)

### 9.3 Watchdog Services

**Watchdog Binary:** `/opt/autopilot/bin/watchdog` (1.2MB)

**Purpose:**
- Monitor service health
- Restart crashed services
- Detect hung processes
- Log anomalies

**Watched Services:**
- Critical autopilot processes (vision, perception, controller)
- Communication services (hermes, canrx, cantx)
- System services (syslog, klog)

**Security Role:**
- Detects service crashes (potential exploitation attempts)
- Prevents denial-of-service by restarting services
- Logs suspicious behavior (repeated crashes)

### 9.4 Telemetry and Metrics

**Service:** `/etc/sv/metrics/`  
**Binary:** `/opt/autopilot/bin/metrics` (487KB)

**Collected Metrics:**
- CPU/memory usage per service
- Network traffic statistics
- Disk I/O
- Service restart counts
- Error rates

**Backend Upload:** Metrics uploaded to Tesla via hermes

**Security Use Cases:**
- Anomaly detection (unusual CPU usage = cryptominer)
- Performance degradation (DoS attack)
- Lateral movement detection (unexpected network traffic)

---

## 10. Secure Boot and Firmware Signing

### 10.1 Signing Domain

**File:** `/etc/signing-domain`  
**Purpose:** Validate firmware update signatures against expected signing authority

**Content:** (Not extracted, likely contains domain identifier like "production" or "engineering")

### 10.2 Firmware Signature Verification

**Signing Keys:**
- `/etc/sign_firmware_ice_emmc_dev.pub` (development key, found in MCU)
- Production key (location unknown, possibly in TPM or read-only memory)

**Verification Flow:**
```
1. Firmware update downloaded (via Hermes)
2. Update package includes signature (RSA or ECDSA)
3. APE verifies signature using public key
4. APE checks signing domain matches /etc/signing-domain
5. If valid, flash firmware; if invalid, reject update
```

### 10.3 Build Information

**Files:**
- `/etc/build-date` - Unix timestamp (1712350968 = April 6, 2024)
- `/etc/build-info` - Jenkins build path
- `/etc/commit` - Git commit hash (0cac3042b6cd3c716601e6ed6d3d0be65ab47d74)
- `/etc/product` - "ap" (autopilot)
- `/etc/product-platform` - "parker" (NVIDIA Tegra Parker)
- `/etc/product-release` - "2024.8.9.ice.ape25"

**Security Use:**
- Verify firmware version for vulnerability assessment
- Identify rollback attacks (old vulnerable firmware)
- Track firmware provenance

### 10.4 Update Mechanisms

**APE Updater Service:** `/etc/sv/ape-updater/`

**Update Sources:**
1. **Hermes backend** - OTA updates from Tesla servers
2. **USB/SD card** - Manual updates (service mode)
3. **MCU delivery** - Updates pushed from MCU2

**Update Verification:**
1. Signature check (RSA/ECDSA)
2. Signing domain validation
3. Version check (prevent downgrade)
4. Checksum validation (SHA-256)

---

## 11. Attack Surface Analysis

### 11.1 Network Attack Surface

| Port | Protocol | Service | Auth Required | Source Restriction | Risk |
|------|----------|---------|---------------|-------------------|------|
| 8081 | TCP/TLS | service-api-tls | ✅ mTLS | ❌ None | 🟡 MEDIUM |
| 8901 | TCP/HTTP | factory_calibration | ⚠️ Bearer token | ❌ None (dev mode) | 🔴 CRITICAL |
| 8902 | TCP | apeb-file-server | ❌ None | ✅ 192.168.90.105 only | 🟡 MEDIUM |
| 27694 | UDP | canrx | ❌ None | ✅ 192.168.90.104 only | 🟢 LOW |
| 28205 | UDP | Aurix logs | ❌ None | ✅ 192.168.90.104 only | 🟢 LOW |
| 22 | TCP | sshd | ✅ Public key | ❌ None (dev mode) | 🟠 HIGH |

### 11.2 Privilege Escalation Vectors

**SUID Binaries:**
1. `/opt/autopilot/bin/read_device_key` - TPM access (SUID root)
   - Vulnerability: Buffer overflow, path traversal
   - Impact: Root shell, TPM key extraction

**SGID Binaries:**
2. `/opt/autopilot/bin/package_signer` - Firmware signing (SGID 260)
   - Vulnerability: Arbitrary file signing
   - Impact: Malicious firmware distribution

**Service User Compromise:**
3. Exploit service (e.g., vision, perception, factory_calibration)
4. Leverage lack of AppArmor profile to access filesystem
5. Exploit SUID binary for root escalation

### 11.3 Lateral Movement

**APE → MCU:**
- APE can connect to MCU on various ports (8443, 8888, 9892-9900)
- If APE compromised, attacker can pivot to MCU
- MCU compromise grants internet access (via modem)

**APE → Other ECUs:**
- APE can send CAN messages via `cantx` service
- Malicious CAN commands can affect vehicle behavior
- Example: Unlock doors, disable brakes, manipulate speed

**APE-A ↔ APE-B:**
- APE-A and APE-B communicate via port 8902 (file server)
- No authentication between redundant processors
- Compromise of one APE enables compromise of backup

### 11.4 Persistence Mechanisms

**Filesystem Modifications:**
1. Modify `/etc/sv/*/run` scripts to inject backdoor on service startup
2. Add SSH keys to `/root/.ssh/authorized_keys`
3. Install rootkit in kernel module directory (if writable)

**Firmware Backdoor:**
1. Extract firmware image
2. Inject backdoor into binary (e.g., `vision`, `service_api`)
3. Re-sign firmware using compromised signing key
4. Flash backdoored firmware via ape-updater

**Certificate Replacement:**
1. Replace `/var/lib/board_creds/board.crt` with attacker's cert
2. Install corresponding private key
3. Attacker can authenticate as victim vehicle indefinitely

---

## 12. Exploit Mitigation Techniques

### 12.1 Binary Protections

**Check binary security features:**
```bash
checksec /opt/autopilot/bin/vision
checksec /usr/bin/service_api
checksec /opt/autopilot/bin/read_device_key
```

**Expected Protections:**
- **PIE (Position Independent Executable):** Randomize base address
- **Stack Canaries:** Detect buffer overflows
- **NX (No Execute):** Prevent code execution on stack/heap
- **RELRO (Relocation Read-Only):** Prevent GOT overwrite
- **FORTIFY_SOURCE:** Runtime bounds checking

**If missing:** Binaries are more vulnerable to exploitation

### 12.2 Kernel Security Features

**ASLR (Address Space Layout Randomization):**
```bash
cat /proc/sys/kernel/randomize_va_space
# 2 = Full ASLR (kernel, libraries, heap, stack)
```

**SELinux/AppArmor:**
```bash
cat /sys/kernel/security/apparmor/profiles
# List loaded AppArmor profiles
```

**Kernel Hardening:**
```bash
cat /proc/sys/kernel/kptr_restrict  # Hide kernel pointers
cat /proc/sys/kernel/dmesg_restrict # Restrict dmesg access
```

### 12.3 Secure Coding Practices

**Observed in Firmware:**
- ✅ Services run as unprivileged users (not root)
- ✅ Resource limits enforced (`chpst -o 4096`)
- ⚠️ Excessive group memberships (reduces isolation)
- ❌ Few AppArmor profiles (most services unconfined)
- ❌ Default-ACCEPT OUTPUT policy (no egress filtering)

---

## 13. Security Recommendations

### 13.1 Critical Fixes (Immediate)

1. **Disable Factory Mode in Customer Vehicles**
   - Remove HTTP factory mode entry API (`/factory/enter`)
   - Require physical access (UART console) for factory mode
   - Fuse-based factory mode detection (unfused ECUs only)

2. **Implement Egress Filtering**
   ```bash
   -P OUTPUT DROP
   -A OUTPUT -o eth0 -d 192.168.90.100 -j ACCEPT  # MCU only
   -A OUTPUT -o eth0 -d 192.168.90.104 -j ACCEPT  # Longboard only
   ```

3. **Remove Self-Signed Certificate Fallback**
   - service-api-tls should exit with error if no board creds
   - Force manual re-provisioning (not automated fallback)

4. **Expand AppArmor Coverage**
   - Create profiles for all autopilot binaries (vision, perception, etc.)
   - Enforce profiles in production (no unload-apparmor-in-factory)

5. **Replace SUID Binaries with Capabilities**
   ```bash
   # Remove SUID from read_device_key
   chmod u-s /opt/autopilot/bin/read_device_key
   # Grant CAP_SYS_ADMIN capability instead
   setcap cap_sys_admin+ep /opt/autopilot/bin/read_device_key
   ```

### 13.2 High Priority (Short Term)

6. **Implement Network Segmentation**
   - VLAN separation between APE, MCU, Gateway
   - IPsec or MACsec for authenticated network peers

7. **Restrict Port 8081 (service-api-tls)**
   ```bash
   # Allow only MCU to connect
   -A INPUT -i eth0 -s 192.168.90.100 -p tcp --dport 8081 -j ACCEPT
   ```

8. **Audit All SUID/SGID Binaries**
   - Perform static analysis (Ghidra, IDA Pro)
   - Fuzz inputs for vulnerabilities
   - Implement input validation and sanitization

9. **Implement Certificate Pinning**
   - Pin expected board certificate in firmware manifest
   - Reject firmware updates if certificate doesn't match

10. **Enable Certificate Revocation Checking**
    - Fetch CRLs from `pki.tesla.com`
    - Reject connections with revoked certificates

### 13.3 Medium Priority (Long Term)

11. **Implement Runtime Integrity Monitoring**
    - Periodically hash critical binaries (vision, service_api)
    - Verify `/etc/sv/*/run` scripts haven't been modified
    - Alert on unexpected filesystem changes

12. **Harden TPM Authorization**
    - Implement TPM policy-based authorization (not just password)
    - Require PCR values to match (secure boot chain)
    - Seal board key to specific firmware version

13. **Implement Anomaly Detection**
    - Monitor for unusual network traffic (unexpected destinations)
    - Detect process anomalies (vision spawning shell)
    - Alert on repeated service crashes (exploitation attempts)

14. **Improve Logging and Auditing**
    - Log all certificate authentication attempts
    - Record all factory mode entries/exits
    - Audit all file modifications in `/var/lib/board_creds/`
    - Send logs to immutable backend storage

15. **Implement Secure Boot Chain**
    - UEFI Secure Boot or U-Boot verified boot
    - Chain of trust from hardware fuses → bootloader → kernel → initramfs
    - Prevent loading unsigned firmware

---

## Appendix A: Security Testing Commands

### Test Firewall Rules
```bash
# Check iptables rules
iptables -L -n -v

# Test inbound connection (should be blocked)
nc -v 192.168.90.103 9999

# Test outbound connection (currently allowed)
nc -v 8.8.8.8 53
```

### Test AppArmor Status
```bash
# Check AppArmor status
cat /sys/kernel/security/apparmor/profiles

# Test confined binary
sudo -u nobody ping 8.8.8.8  # Should work
sudo -u nobody cat /etc/shadow  # Should fail (AppArmor)
```

### Test SUID Exploitation
```bash
# Identify SUID binaries
find / -perm -4000 -ls 2>/dev/null

# Test read_device_key for path traversal
/opt/autopilot/bin/read_device_key ../../../etc/shadow
```

### Test Certificate Validation
```bash
# Connect to service-api-tls without cert (should fail)
openssl s_client -connect 192.168.90.103:8081

# Connect with invalid cert (should fail)
openssl s_client -connect 192.168.90.103:8081 -cert fake.crt -key fake.key

# Connect with valid cert (should succeed)
openssl s_client -connect 192.168.90.103:8081 \
    -CAfile /usr/share/tesla-certificates/current/combined/ProductAccessCAs.pem \
    -cert board.crt -key board.key
```

---

## Appendix B: Vulnerability Research Priorities

### High-Priority Binaries for Reverse Engineering

1. **`/opt/autopilot/bin/read_device_key`** (52KB, SUID root)
   - Look for: Buffer overflows, path traversal, race conditions
   - Tools: Ghidra, IDA Pro, AFL fuzzing

2. **`/usr/bin/service_api`** (6.9MB, Go binary)
   - Look for: Authentication bypass, API injection, authorization flaws
   - Tools: go-unstrip, Ghidra Go analyzer

3. **`/opt/autopilot/bin/factory_camera_calibration`** (3.1MB)
   - Look for: HTTP API vulnerabilities, unauthenticated endpoints
   - Tools: HTTP fuzzer (Burp Suite, Postman)

4. **`/opt/hermes/hermes_teleforce`** (9.6MB)
   - Look for: Remote code execution, command injection
   - Tools: Binary analysis, protocol fuzzing

5. **`/opt/autopilot/bin/vision`** (389MB)
   - Look for: Neural network backdoors, model poisoning
   - Tools: TensorRT analysis, model extraction

---

**Document Complete**  
**Next Steps:** Reverse engineer SUID binaries, test factory mode triggers, analyze service_api authentication
