# APE Network Configuration

## Overview

Tesla's Autopilot Compute (APE) operates on a private vehicle network isolated from the MCU (CID/IC). This document details the network configuration extracted from the APE firmware.

## Network Topology

```
┌─────────────────────────────────────────────────────────────────┐
│                        Vehicle Network                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────┐     ┌──────────┐     ┌──────────┐     ┌────────┐│
│  │   CID    │     │   IC     │     │   GTW    │     │   LB   ││
│  │ (MCU/UI) │     │ (Cluster)│     │ (Gateway)│     │ (Body) ││
│  │ .90.100  │     │ .90.101  │     │ .90.102  │     │ .90.104││
│  └────┬─────┘     └────┬─────┘     └────┬─────┘     └────┬───┘│
│       │                │                │                │    │
│       └────────────────┴────────────────┴────────────────┘    │
│                            eth0                                │
│  ┌────────────────────────────────────────────────────────┐   │
│  │                  AP (Primary Autopilot)                │   │
│  │                     192.168.90.103                      │   │
│  │  ┌──────────┬──────────┬──────────┬──────────────┐    │   │
│  │  │ hermes   │ service- │ canrx    │ apeb-file-   │    │   │
│  │  │          │ api-tls  │ :27694   │ server :8902 │    │   │
│  │  └──────────┴──────────┴──────────┴──────────────┘    │   │
│  └──────────────────────────┬─────────────────────────────┘   │
│                              │ eth1                            │
│  ┌──────────────────────────┴─────────────────────────────┐   │
│  │                 AP-B (Redundant Autopilot)             │   │
│  │                     192.168.90.105                      │   │
│  └────────────────────────────────────────────────────────┘   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Network Interfaces

### Configuration: `/etc/network/interfaces`

```bash
auto lo
iface lo inet loopback

auto eth1
iface eth1 inet dhcp
```

**Notes:**
- Only `eth1` is auto-configured with DHCP
- `eth0` is configured elsewhere (likely by init scripts)
- Loopback interface (127.0.0.1) for local services

## IP Addressing Scheme

### Primary Network (192.168.90.0/24)

| Device | IP Address | Hostname | Role |
|--------|------------|----------|------|
| CID (MCU) | 192.168.90.100 | `cid`, `ice` | Center Information Display (touchscreen) |
| IC | 192.168.90.101 | `ic` | Instrument Cluster (driver display) |
| GTW | 192.168.90.102 | `gtw` | Gateway (PowerPC MPC5748G) |
| AP (Primary) | 192.168.90.103 | `ap` | Autopilot Compute (Tegra/Drive) |
| LB | 192.168.90.104 | `lb` | Left Body Controller |
| AP-B (Redundant) | 192.168.90.105 | `ap-b` | Secondary Autopilot Compute (HW3+) |

### MACSec Network (192.168.91.0/24)
Encrypted ethernet layer for secure communication:

| Device | IP Address | Hostname | Purpose |
|--------|------------|----------|---------|
| AP (MACSec) | 192.168.91.103 | `ap-macsec` | Encrypted primary AP interface |
| AP-B (MACSec) | 192.168.91.105 | `ap-b-macsec` | Encrypted redundant AP interface |

### eth0.1 VLAN (192.168.92.0/24)

| Device | IP Address | Hostname | Purpose |
|--------|------------|----------|---------|
| AP (VLAN1) | 192.168.92.103 | `ap-eth0.1` | VLAN 1 on eth0 |
| AP-B (VLAN1) | 192.168.92.105 | `ap-b-eth0.1` | VLAN 1 on eth0 (redundant) |

### eth1 Network (192.168.95.0/24)

| Device | IP Address | Hostname | Purpose |
|--------|------------|----------|---------|
| AP (eth1) | 192.168.95.103 | `ap-eth1` | Secondary ethernet interface |
| AP-B (eth1) | 192.168.95.105 | `ap-b-eth1` | Secondary ethernet (redundant) |

### eth1 MACSec (192.168.96.0/24)

| Device | IP Address | Hostname | Purpose |
|--------|------------|----------|---------|
| AP (eth1 MACSec) | 192.168.96.103 | `ap-eth1-macsec` | Encrypted eth1 interface |
| AP-B (eth1 MACSec) | 192.168.96.105 | `ap-b-eth1-macsec` | Encrypted eth1 (redundant) |

### eth1.1 VLAN (192.168.97.0/24)

| Device | IP Address | Hostname | Purpose |
|--------|------------|----------|---------|
| AP (eth1 VLAN1) | 192.168.97.103 | `ap-eth1.1` | VLAN 1 on eth1 |
| AP-B (eth1 VLAN1) | 192.168.97.105 | `ap-b-eth1.1` | VLAN 1 on eth1 (redundant) |

## Hosts File: `/etc/hosts`

```
127.0.0.1	localhost
192.168.90.103	ap
192.168.90.105	ap-b
192.168.91.103	ap-macsec
192.168.91.105	ap-b-macsec
192.168.92.103	ap-eth0.1
192.168.92.105	ap-b-eth0.1
192.168.95.103	ap-eth1
192.168.95.105	ap-b-eth1
192.168.96.103	ap-eth1-macsec
192.168.96.105	ap-b-eth1-macsec
192.168.97.103	ap-eth1.1
192.168.97.105	ap-b-eth1.1
192.168.90.104	lb
192.168.90.100	cid ice
192.168.90.101	ic
192.168.90.102	gtw
127.0.0.1	firmware.vn.teslamotors.com
```

**Critical Entry:**
```
127.0.0.1	firmware.vn.teslamotors.com
```
This redirects firmware update checks to localhost, preventing unauthorized updates and enabling local update server control.

## DNS Configuration: `/etc/resolv.conf`

```bash
# Name resolution is handled by nss-autopilot, not DNS.
# See SW-277567 for more information.
nameserver 192.168.90.100
```

**Notes:**
- DNS handled by `nss-autopilot` custom resolver
- CID (192.168.90.100) acts as fallback nameserver
- Most resolution done via `/etc/hosts`

## Firewall Rules: `/etc/firewall`

```bash
# Ensure nobody can send canrx traffic except LB.
-A INPUT -i eth0 -s 192.168.90.104 -p udp --dport 27694 -j ACCEPT

# Allow Aurix data logging messages
-A INPUT -i eth0 -s 192.168.90.104 -p udp --dport 28205 -j ACCEPT

# Allow ap's apeb-file-server to serve to ap-b (if primary APE)
-A INPUT -i eth0 -s 192.168.90.105 -d 192.168.90.103 -p tcp --dport 8902 -j ACCEPT

# Allow service-api TLS traffic
-A INPUT -i eth0 -p tcp --dport 8081 -j ACCEPT
```

### Port Mappings & Security

| Port | Protocol | Source | Destination | Service | Security |
|------|----------|--------|-------------|---------|----------|
| 27694 | UDP | LB (192.168.90.104) | AP | canrx | **Restricted** - Only LB can send CAN traffic |
| 28205 | UDP | LB (192.168.90.104) | AP | aurix-console | **Restricted** - Aurix safety data logging |
| 8902 | TCP | AP-B (192.168.90.105) | AP (192.168.90.103) | apeb-file-server | **Restricted** - Redundant APE file sharing |
| 8081 | TCP | Any (eth0) | AP | service-api-tls | **Open** - TLS-secured API endpoint |

**Default Policy:** All other incoming traffic on eth0 is **DENIED** (implicit drop).

### Security Analysis

1. **CAN Bus Isolation**
   - Only LB (Left Body Controller) can send CAN messages to APE
   - Prevents rogue devices on vehicle network from injecting CAN traffic
   - Critical for preventing CAN bus attacks from compromised MCU

2. **Aurix Safety Channel**
   - Port 28205 restricted to LB source
   - Aurix Tricore microcontroller provides safety-critical redundancy
   - Data logging channel for safety validation

3. **Redundant APE Communication**
   - Port 8902 only for AP-B → AP file transfers
   - Enables firmware/config synchronization between redundant boards
   - Not bidirectional (primary serves to redundant)

4. **Public API Surface**
   - Port 8081 (service-api-tls) only open port
   - TLS encryption required
   - Rate-limited (10 req/sec outside factory)

## VPN & Hermes Endpoints

### Hermes Cloud Configuration (`/etc/hermes.vars`)

Hermes is Tesla's cloud communication protocol (WebSocket over TLS).

#### Production Environment
```bash
HERMES_CMD_SERVER="wss://hermes-prd.ap.tesla.services:8443"
HERMES_STREAM_SERVER="wss://telemetry-prd.ap.tesla.services:8443"
HERMES_API_GATEWAY_HOST="api-prd.ap.tesla.services"
```

#### Development Environment
```bash
HERMES_CMD_SERVER="wss://hermes-eng.ap.tesla.services:8443"
HERMES_STREAM_SERVER="wss://telemetry-eng.ap.tesla.services:8443"
HERMES_API_GATEWAY_HOST="api-eng.ap.tesla.services"
```

#### China Market
```bash
HERMES_CMD_SERVER="wss://hermes-x2-api.prd.vn.cloud.tesla.cn:8443"
HERMES_API_GATEWAY_HOST="api-ap-prd.vn.cloud.tesla.cn"
```

### SNI Proxy Configuration
```bash
HERMES_PLATFORM_ARGS="-sniproxy-ip=192.168.90.100 -sniproxy-port-wifi-only=8444"
```

- SNI proxy runs on CID (192.168.90.100)
- Port 8444 for WiFi-only connections
- Enables TLS connection multiplexing

### Authentication
```bash
HERMES_CREDS_DIR=/var/lib/board_creds
HERMES_CREDS_KEY=$HERMES_CREDS_DIR/board.key
HERMES_CREDS_CRT=$HERMES_CREDS_DIR/board.crt
```

Each APE board has unique TLS client certificate for mutual TLS authentication.

## Network Isolation & Bridging

### MCU ↔ APE Isolation

The APE and MCU are **network-isolated** by design:

1. **Separate Network Segments**
   - MCU: Runs its own network stack (192.168.90.100)
   - APE: Isolated 192.168.90.103 with restricted firewall
   - Gateway: 192.168.90.102 mediates between vehicle CAN and ethernet

2. **CAN Bus as Communication Channel**
   - MCU cannot directly connect to APE services
   - All MCU ↔ APE communication goes through CAN messages
   - Left Body Controller (LB) forwards CAN to UDP (port 27694)

3. **Firewall Enforcement**
   - APE firewall only allows specific sources
   - MCU (CID) cannot directly access APE services except:
     - SNI proxy for Hermes (WiFi routing)
     - No direct service-api access from MCU

### Connectivity Forwarder Service

The `connectivity-forwarder` service bridges network traffic:

- **Purpose:** Route internet traffic from APE through MCU's WiFi/LTE
- **Direction:** APE → MCU → Internet
- **Use Case:** Hermes cloud connections, OTA updates
- **Security:** SNI proxy validates destinations

### MACSec Encryption

APE supports **MACSec (IEEE 802.1AE)** for ethernet layer encryption:

- **Purpose:** Prevent eavesdropping on vehicle ethernet
- **Endpoints:** AP ↔ AP-B encrypted channel
- **Use Case:** Redundant autopilot synchronization
- **Network:** 192.168.91.0/24 (MACSec overlay)

## Routing Tables

(Not directly available in extracted firmware, inferred from configuration)

### Default Routes
```
# Primary internet route via MCU
default via 192.168.90.100 dev eth0

# Redundant APE route
192.168.90.105 dev eth1 scope link
```

### VLAN Routes
```
# VLAN 1 on eth0
192.168.92.0/24 dev eth0.1

# VLAN 1 on eth1  
192.168.97.0/24 dev eth1.1
```

## Network Services Summary

| Service | Port | Protocol | Interface | Purpose |
|---------|------|----------|-----------|---------|
| canrx | 27694 | UDP | eth0 | CAN bus receive (from LB) |
| aurix-console | 28205 | UDP | eth0 | Aurix safety logging |
| service-api-tls | 8081 | TCP | eth0 | Vehicle configuration API |
| apeb-file-server | 8902 | TCP | eth0 | Redundant APE file sharing |
| hermes (IPC) | - | Unix socket | /var/ipc/hermes.sock | Local Hermes client API |
| sshd | 22 | TCP | eth0 | SSH (development builds only) |

## Security Model

### Defense in Depth

1. **Network Layer**
   - Firewall whitelist (deny-by-default)
   - Port-specific source IP restrictions
   - MACSec encryption for sensitive channels

2. **Transport Layer**
   - TLS 1.2+ for all cloud connections
   - Mutual TLS authentication (client certificates)
   - SNI proxy for connection validation

3. **Application Layer**
   - Rate limiting on service-api (10 req/sec)
   - AppArmor profiles (disabled in factory)
   - Credential storage in `/var/lib/board_creds`

### Attack Surface Reduction

**Exposed Services:**
- Only port 8081 (service-api-tls) accepts connections from any vehicle network device
- All other services restricted by source IP or disabled

**Mitigations:**
- CID (MCU) cannot inject CAN traffic (must go through LB)
- Firmware updates intercepted by localhost redirect
- SSH disabled in production builds

## Diagnostics

### Network Testing Commands
```bash
# Check interface status
ip addr show

# View routing table
ip route show

# Test connectivity to MCU
ping 192.168.90.100

# Test CAN reception (requires LB traffic)
tcpdump -i eth0 udp port 27694

# Check firewall rules
iptables -L INPUT -v -n

# Test Hermes connectivity
curl -v https://hermes-prd.ap.tesla.services:8443
```

### Common Issues

1. **No CAN Traffic**
   - Check LB (192.168.90.104) is reachable
   - Verify firewall allows port 27694 from LB
   - Ensure canrx service is running

2. **Hermes Connection Failure**
   - Verify board credentials exist in `/var/lib/board_creds/`
   - Check SNI proxy is reachable (192.168.90.100:8444)
   - Confirm internet route via MCU

3. **Redundant APE Sync Failure**
   - Check eth1 interface status
   - Verify apeb-file-server is running on primary APE
   - Test connectivity to 192.168.90.105:8902

## Related Documentation

- [APE Services Documentation](APE-SERVICES.md)
- [APE Firmware Extraction](APE-FIRMWARE-EXTRACTION.md)
- [Hermes Protocol Analysis](../core/HERMES-CLIENT-ANALYSIS.md)
- [Network Topology](../core/04-network-ports-firewall.md)
- [Gateway Security Analysis](../firmware/86-gateway-security-analysis-DETAILED.md)
