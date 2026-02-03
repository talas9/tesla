# Tesla MCU2 Network Architecture & Port Reference

**Document Version:** 1.0  
**Last Updated:** February 2, 2026  
**Vehicle Platform:** Model S/X MCU2 (2024.x firmware)  
**Source Analysis:** `/root/downloads/firewall-analysis-report.md`

---

## Table of Contents

1. [Network Topology](#network-topology)
2. [Critical Ports & Services](#critical-ports--services)
3. [Internal Network Map](#internal-network-map)
4. [Complete Port Matrix](#complete-port-matrix)
5. [Firewall Rules Analysis](#firewall-rules-analysis)
6. [Service Dependencies](#service-dependencies)
7. [Attack Surface Diagram](#attack-surface-diagram)
8. [Security Recommendations](#security-recommendations)

---

## Network Topology

### Physical Network Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    192.168.90.0/24 - Vehicle Network            │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  ┌──────────────┐      ┌──────────────┐      ┌──────────────┐  │
│  │   Gateway    │      │   MCU2 ICE   │      │  Autopilot   │  │
│  │ .90.102      │◄────►│  .90.100     │◄────►│  APE .103    │  │
│  │              │      │  (THIS)      │      │  APE .105    │  │
│  └──────────────┘      └──────┬───────┘      └──────────────┘  │
│                               │                                  │
│                               ├──────────────┐                  │
│  ┌──────────────┐             │              │  ┌────────────┐ │
│  │    Modem     │◄────────────┘              └─►│   Tuner    │ │
│  │  .90.60      │                               │  .90.30    │ │
│  │ (CELLULAR)   │                               │  (RADIO)   │ │
│  └──────────────┘                               └────────────┘ │
│         ▲                                                        │
└─────────┼────────────────────────────────────────────────────────┘
          │
          │ Cellular Network
          ▼
   ┌──────────────┐
   │    Tesla     │
   │   Servers    │
   └──────────────┘
```

### Network Interfaces

#### **eth0** - Primary Vehicle Network
- **Network:** 192.168.90.0/24
- **Purpose:** Inter-ECU communication backbone
- **Security:** Internal only, firewall-protected

#### **wlan0** - WiFi Interface
- **Network:** Variable (user/Tesla WiFi)
- **Purpose:** User connectivity, over-the-air updates
- **Security:** Restricted services, 10.0.0.0/8 filtering

#### **eth0.2** - VLAN 2
- **Purpose:** Isolated radio services
- **Security:** Separate segment for Harman tuner

#### **lo** - Loopback (127.0.0.1)
- **Purpose:** Inter-process communication
- **Security:** Local only

---

## Critical Ports & Services

### 🔴 CRITICAL RISK PORTS

#### **Port 49503 TCP - Modem Update Server**
```
Service:  modem-update-server
Access:   192.168.90.60 (Modem) → 192.168.90.100 (MCU)
Protocol: HTTP
Risk:     CRITICAL - Direct firmware update path
```

**Attack Vector:**
```
Compromise Modem → Access Port 49503 → Push Malicious Firmware
```

**Firewall Rules:**
```bash
-A MODEM_INPUT -p tcp -i eth0 -s 192.168.90.60 -d 192.168.90.100 --dport 49503 -j ACCEPT
```

**Mitigation:** Requires cryptographic signature verification on all updates.

---

#### **Ports 80/443 TCP - HTTP/HTTPS (UNRESTRICTED)**
```
Service:  connmand, qtcar, qtcar-connman
Access:   NO SOURCE RESTRICTIONS (!)
Protocol: HTTP/HTTPS
Risk:     HIGH - Potential external exposure
```

**Firewall Rules:**
```bash
-A CONNMAND -p tcp --dport 80 -j ACCEPT
-A QTCAR_CLUSTER -p tcp -m multiport --dport 80,443 -j ACCEPT
-A QTCAR-CONNMAN -p tcp --dport 80 -j ACCEPT
```

**Issue:** No `-s` (source) restriction. Could accept from ANY interface if routing allows.

**Recommendation:** Add source filtering:
```bash
-A CONNMAND -i eth0 -s 192.168.90.0/24 -p tcp --dport 80 -j ACCEPT
```

---

### 🟠 HIGH RISK PORTS

#### **Port 25956 TCP - Updater Shell**
```
Service:  updater-shell
Access:   Internal network
Protocol: Shell/TCP
Risk:     HIGH - Direct shell access, CAN flood trigger
```

**Context:** This port was discovered as part of the CAN flood vulnerability. Opening this port triggers system stress.

---

#### **Port 20564 TCP - SX-Updater HTTP**
```
Service:  sx-updater
Access:   192.168.90.30 (Tuner)
Protocol: HTTP
Risk:     HIGH - syncterm exploit trigger
```

**Context:** Accessing this service can trigger system instability (syncterm/valhalla-ctrl crashes).

---

#### **Ports 4030+ TCP - Toolbox API**
```
Service:  toolbox-api (diagnostics)
Access:   192.168.90.103, .105 (Autopilot only)
Protocol: HTTP/JSON API
Risk:     HIGH - System diagnostics & control
Status:   ⚠️ REMOVED IN MODEL 3/Y FIRMWARE
```

**Accessible Ports:**
- 4030: APE/DRM/Video services
- 4035: Mount daemon
- 4050: Audio daemon  
- 4060: Connection manager
- 4090, 4094: Bluetooth services
- 7654: Monitor service

**Firewall Rules:**
```bash
-A INPUT -i eth0 -p tcp -d 192.168.90.100 -m multiport --dports 4030,4035,4050,4060,4090,4094,7654 -j TOOLBOX-API-INPUT
-A TOOLBOX-API-INPUT -s 192.168.90.103,192.168.90.105 -j TOOLBOX-API-APE-INPUT
-A TOOLBOX-API-APE-INPUT -p tcp --dport 4030 -j ACCEPT
```

**Note:** Tesla removed this service in Model 3/Y firmware, recognizing the security risk.

---

### 🟡 MEDIUM RISK PORTS

#### **Port 8081 TCP - Service Shell**
```
Service:  service-shell
Access:   Internal network (restricted)
Protocol: Shell/Diagnostics
Risk:     MEDIUM - Diagnostic interface
```

**Firewall Rules:**
```bash
-A INPUT -p tcp --dport 8081 -j SERVICE-SHELL-INPUT
# Explicitly BLOCKS:
-A SERVICE-SHELL-INPUT -s 192.168.90.30,192.168.90.60 -j REJECT  # Tuner, Modem
-A SERVICE-SHELL-INPUT -s 192.168.90.101-107 -j REJECT          # All computers
# Allows:
-A SERVICE-SHELL-INPUT -i eth0 -s 192.168.90.0/24 -j ACCEPT     # Other ECUs
-A SERVICE-SHELL-INPUT -i lo -j ACCEPT                          # Localhost
-A SERVICE-SHELL-INPUT -j REJECT                                # Default deny
```

**Security Posture:** Reasonably well-restricted, but exploitable if attacker gains access to an allowed ECU.

---

#### **Port 8901 TCP - Provisioning API / iris-api**
```
Service:  iris-api, ape-deliver
Access:   Multiple sources (modem return traffic, APE)
Protocol: HTTP/JSON API
Risk:     MEDIUM - Provisioning & control
```

---

#### **Port 3500 UDP - Gateway UDPAPI**
```
Service:  gateway-udpapi
Access:   Internal network
Protocol: UDP
Risk:     MEDIUM - Real-time vehicle data
```

---

#### **Port 8080 TCP - Firmware Server / Service UI**
```
Service:  Service UI HTTP, local webserver
Access:   Internal
Protocol: HTTP
Risk:     MEDIUM - Local web interface
```

---

## Internal Network Map

### IP Address Allocation (192.168.90.0/24)

| IP Address       | Component         | Function                          | Attack Surface |
|------------------|-------------------|-----------------------------------|----------------|
| **192.168.90.100** | **MCU2 ICE**      | **Infotainment, Primary System** | **HIGH**       |
| 192.168.90.102   | Gateway           | Logging, system coordination      | Medium         |
| 192.168.90.103   | Autopilot APE #1  | Self-driving computer             | HIGH           |
| 192.168.90.105   | Autopilot APE #2  | Self-driving computer             | HIGH           |
| 192.168.90.60    | Cellular Modem    | **External connectivity**         | **CRITICAL**   |
| 192.168.90.30    | Tuner/Radio       | Harman entertainment system       | Medium         |
| 192.168.90.101   | ECU (various)     | Vehicle control units             | Low            |
| 192.168.90.104   | ECU (various)     | Vehicle control units             | Low            |
| 192.168.90.106   | ECU (various)     | Vehicle control units             | Low            |
| 192.168.90.107   | ECU (various)     | Vehicle control units             | Low            |

### Trust Boundaries

```
┌─────────────────────────────────────────────────────┐
│                 TRUSTED ZONE                        │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐         │
│  │  MCU2    │  │ Gateway  │  │ ECU .101 │         │
│  │ .90.100  │  │ .90.102  │  │ .104/.106│         │
│  └──────────┘  └──────────┘  └──────────┘         │
└─────────────────────────────────────────────────────┘
          ▲                ▲
          │ Partial Trust  │
          ▼                ▼
┌─────────────────────────────────────────────────────┐
│            SEMI-TRUSTED ZONE                        │
│  ┌──────────┐            ┌──────────┐              │
│  │ Autopilot│            │  Tuner   │              │
│  │APE .103  │            │  .90.30  │              │
│  │    .105  │            │          │              │
│  └──────────┘            └──────────┘              │
└─────────────────────────────────────────────────────┘
                    ▲
                    │ UNTRUSTED
                    ▼
         ┌──────────────────┐
         │   Cellular Modem │
         │     .90.60       │
         │   (EXTERNAL)     │
         └──────────────────┘
```

**Key Insights:**
- **Modem (.60)** is UNTRUSTED - has most restrictions, but still dangerous access
- **Autopilot (.103/.105)** is SEMI-TRUSTED - extensive access to MCU services
- **Tuner (.30)** is SEMI-TRUSTED - limited access, blocked from sensitive services
- **Gateway & ECUs** are TRUSTED - full internal network access

---

## Complete Port Matrix

### MCU2 (192.168.90.100) - Listening Services

#### External-Facing (eth0) Ports

| Port(s) | Proto | Service | Source Allowed | Auth | Risk |
|---------|-------|---------|----------------|------|------|
| 80, 443 | TCP | HTTP/HTTPS (connmand, qtcar) | **UNRESTRICTED** | None | 🔴 HIGH |
| 49503 | TCP | Modem Update Server | 192.168.90.60 only | None | 🔴 CRITICAL |
| 8081 | TCP | Service Shell | Internal network (restricted) | Limited | 🟡 MEDIUM |
| 4030,4035,4050,4060,4090,4094,7654 | TCP | Toolbox API | APE .103/.105 only | None | 🟠 HIGH |
| 8901 | TCP | iris-api / ape-deliver | APE, Modem (return) | Token? | 🟡 MEDIUM |
| 3500 | UDP | Gateway UDPAPI | Internal | None | 🟡 MEDIUM |
| 8080 | TCP | Service UI HTTP | Internal | None | 🟡 MEDIUM |
| 53 | TCP/UDP | DNS (dnsmasq) | Internal | None | 🟢 LOW |
| 67 | UDP | DHCP (connmand) | Internal | None | 🟢 LOW |
| 123 | UDP | NTP | Internal/Modem | None | 🟢 LOW |
| 5801 | TCP/UDP | linuxvm-logger | Modem .60 | None | 🟡 MEDIUM |
| 50960 | TCP | modemvm-logger | Modem .60 | None | 🟡 MEDIUM |
| 50666 | TCP | mqtt-logger | Modem .60 | None | 🟡 MEDIUM |
| 50877 | TCP | mqtt-config | Modem .60 | None | 🟡 MEDIUM |
| 50950 | TCP | AT Commands (modem control) | Modem .60 (return) | None | 🟡 MEDIUM |
| 7891 | TCP | RIL over TCP | Modem .60 (return) | None | 🟡 MEDIUM |
| 50911, 50101 | TCP | ecall-server (emergency call) | Modem .60 | None | 🟢 LOW |
| 20564 | TCP | Tuner control | Tuner .30 | None | 🟡 MEDIUM |
| 5555 | TCP | Tuner service | Tuner .30 (both) | None | 🟡 MEDIUM |
| 30490 | UDP | Radio data | Tuner .30 | None | 🟢 LOW |
| 69 | UDP | TFTP (updater) | Tuner .30 | None | 🟡 MEDIUM |
| 4599 | UDP | Tuner sync | Tuner .30 | None | 🟢 LOW |
| 5354 | UDP | mDNS | APE .103/.105 | None | 🟢 LOW |

#### Outbound Connection Ports (MCU → Others)

| Dest Port(s) | Proto | Dest IP | Service | Purpose |
|--------------|-------|---------|---------|---------|
| 8443,8444,8885,8888,19004 | TCP | APE .103/.105 | Autopilot API | Autopilot control |
| 9892-9900 | TCP | APE .103/.105 | Dashcam | Video recording |
| 8082,8088,8888 | TCP | APE .103/.105 | qtcar | Qt services |
| 8610,8906,8611 | UDP | APE .103/.105 | UDP services | Real-time data |
| 443 | TCP | 10.0.0.0/8 via wlan0 | HTTPS | Autopilot API (WiFi) |
| 30508-30513 | TCP | Tuner .30 | Tuner streams | Audio streaming |
| 30520,30530 | TCP | Tuner .30 | Radio services | Radio control |
| 2345 | TCP | Tuner .30 (return) | Debug interface | Debugging |
| 22 | TCP | Modem .60, Tuner .30 (return) | SSH | Remote access (return) |
| 6789 | TCP | Tesla servers | Updater-Envoy | OTA updates |

#### Localhost Services (127.0.0.1)

| Port | Service | Purpose |
|------|---------|---------|
| 4030 | APE/DRM/Video/Webcam | Multimedia services |
| 4035 | Mount daemon | Filesystem management |
| 4050 | Audio daemon | Audio control |
| 4060 | Connection manager | Network management |
| 4070 | Bluetooth | BT services |
| 4090, 4094, 4096 | Bluetooth services | Additional BT functionality |
| 4220 | Spotify | Music streaming |
| 4400 | Autopilot API | Local autopilot interface |
| 4567 | Download services | OTA content (manual, release notes, TTS) |
| 8000-8002 | Service UI, Valhalla API | System UI |
| 8080 | Service UI HTTP | Web interface |
| 9000-9006 | Media adapters | Content delivery |
| 18466 | Audio daemon | Secondary audio interface |
| 49503 | Modem update server | Update interface (also on eth0) |
| 49505, 49507 | Release notes, owners manual | Documentation HTTP servers |

---

## Firewall Rules Analysis

### Rule Files (84 total from `/etc/firewall.d/`)

#### Critical Service Rules

**connmand.iptables** - Connection Manager
```bash
-A CONNMAND -p tcp --dport 80 -j ACCEPT              # ⚠️ UNRESTRICTED HTTP
-A CONNMAND -p udp -m multiport --dports 53,67 -j ACCEPT  # DNS + DHCP
```

**modem.iptables** - Cellular Modem Access
```bash
-A MODEM_INPUT -p tcp -i eth0 -s 192.168.90.60 -d 192.168.90.100 --dport 49503 -j ACCEPT  # 🔴 UPDATE SERVER
-A MODEM_INPUT -p tcp -i eth0 -s 192.168.90.60 -d 192.168.90.100 --dport 5801 -j ACCEPT   # Logger
-A MODEM_INPUT -p tcp -i eth0 -s 192.168.90.60 -d 192.168.90.100 --dport 50960 -j ACCEPT  # Modem VM logger
-A MODEM_INPUT -p udp -i eth0 -s 192.168.90.60 -d 192.168.90.100 --dport 123 -j ACCEPT    # NTP
-A MODEM_INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT  # Return traffic (TCUD, iris-api, AT, RIL, ecall)
```

**service-shell.iptables** - Diagnostic Shell
```bash
-A INPUT -p tcp --dport 8081 -j SERVICE-SHELL-INPUT
-A SERVICE-SHELL-INPUT -s 192.168.90.30,192.168.90.60 -j REJECT                    # Block tuner, modem
-A SERVICE-SHELL-INPUT -s 192.168.90.101,192.168.90.102,192.168.90.103,192.168.90.104,192.168.90.105,192.168.90.106,192.168.90.107 -j REJECT  # Block all computers
-A SERVICE-SHELL-INPUT -i eth0 -s 192.168.90.0/24 -j ACCEPT  # Allow other internal devices
-A SERVICE-SHELL-INPUT -i lo -j ACCEPT                       # Allow localhost
-A SERVICE-SHELL-INPUT -j REJECT                             # Default deny
```

**toolbox-api.iptables** - System Diagnostics (MCU2 only)
```bash
-A INPUT -i eth0 -p tcp -d 192.168.90.100 -m multiport --dports 4030,4035,4050,4060,4090,4094,7654 -j TOOLBOX-API-INPUT
-A TOOLBOX-API-INPUT -s 192.168.90.103,192.168.90.105 -j TOOLBOX-API-APE-INPUT  # Only autopilot
-A TOOLBOX-API-APE-INPUT -p tcp --dport 4030 -j ACCEPT
```
**Status:** ⚠️ **Removed in Model 3/Y firmware** (security improvement)

**qtcar.iptables / qtcar-connman.iptables** - Qt Car UI
```bash
-A QTCAR_CLUSTER -p tcp -m multiport --dport 80,443 -j ACCEPT  # ⚠️ UNRESTRICTED HTTPS
-A QTCAR-CONNMAN -p tcp --dport 80 -j ACCEPT                   # ⚠️ UNRESTRICTED HTTP
```

**harman-tuner.iptables** - Radio/Tuner Access
```bash
-A HARMAN_TUNER -i eth0 -p tcp -s 192.168.90.30 -d 192.168.90.100 --dport 20564 -j ACCEPT
-A HARMAN_TUNER -i eth0 -p tcp -s 192.168.90.30 -d 192.168.90.100 --dport 5555 -j ACCEPT
# ... various other tuner-specific ports
```

**updater-envoy.iptables** - OTA Update Client
```bash
-A UPDATER_ENVOY -p tcp -m tcp --sport 6789 -m conntrack --ctstate ESTABLISHED -j ACCEPT
-A OUTPUT -m owner --uid-owner envoy -j UPDATER_ENVOY
```
✅ **Secure design:** Outbound-only, ESTABLISHED state

---

### Modem Access Matrix

Complete matrix of what the **Cellular Modem (192.168.90.60)** can access on **MCU (192.168.90.100)**:

| Port | Proto | Direction | Service | Auth | Risk Level |
|------|-------|-----------|---------|------|------------|
| 49503 | TCP | INPUT | **Modem Update Server** | None | 🔴 **CRITICAL** |
| 5801 | TCP+UDP | INPUT | linuxvm-logger | None | 🟡 MEDIUM |
| 50960 | TCP | INPUT | modemvm-logger | None | 🟡 MEDIUM |
| 123 | UDP | INPUT | NTP | None | 🟢 LOW |
| 38888 | TCP | RETURN | TCUD (return traffic) | ? | 🟡 MEDIUM |
| 8901 | TCP | RETURN | iris-api (return traffic) | Token? | 🟡 MEDIUM |
| 50666 | TCP | RETURN | mqtt-logger | None | 🟡 MEDIUM |
| 50877 | TCP | RETURN | mqtt-config | None | 🟡 MEDIUM |
| 7891 | TCP | RETURN | RIL over TCP | None | 🟡 MEDIUM |
| 50950 | TCP | RETURN | AT Commands | None | 🟡 MEDIUM |
| 50911, 50101 | TCP | RETURN | ecall-server | None | 🟢 LOW |
| 22 | TCP | RETURN | SSH (return traffic) | Key | 🟡 MEDIUM |

**Notes:**
- **RETURN** = ESTABLISHED state only (MCU initiates, safer)
- **INPUT** = Modem can initiate connection (higher risk)
- **Port 49503** is the most dangerous - direct update path

---

### Autopilot Access Matrix

Complete matrix of what **Autopilot APE (192.168.90.103, .105)** can access on **MCU (192.168.90.100)**:

#### APE → MCU (Autopilot can access)

| Port(s) | Proto | Service | Purpose | Risk |
|---------|-------|---------|---------|------|
| 4030 | TCP | Toolbox API | System diagnostics (MCU2 only) | 🟠 HIGH |
| 8901 | TCP | APE-DELIVER | Data delivery from APE | 🟡 MEDIUM |
| 5354 | UDP | mDNS | Service discovery | 🟢 LOW |

#### MCU → APE (MCU can access)

| Port(s) | Proto | Service | Purpose | Risk |
|---------|-------|---------|---------|------|
| 8443, 8444, 8885, 8888, 19004 | TCP | Autopilot API | Autopilot control & telemetry | 🟠 HIGH |
| 9892-9900 | TCP | Dashcam | Video recording services | 🟡 MEDIUM |
| 8082, 8088, 8888 | TCP | qtcar | Qt car UI services | 🟢 LOW |
| 8610, 8906, 8611 | UDP | Real-time services | Live data streams | 🟡 MEDIUM |
| 443 | TCP | HTTPS (over wlan0) | WiFi-based API (10.0.0.0/8) | 🟡 MEDIUM |

**Security Concern:** Bidirectional trust between MCU and APE. Compromise of either enables lateral movement to the other.

---

## Service Dependencies

### Critical Service Chains

#### **OTA Update Chain**
```
Tesla Server → Cellular Network → Modem (.60) → [Port 49503] → modem-update-server → MCU Firmware
                                                 [Port 6789] ← updater-envoy ← Tesla Server
```

**Vulnerabilities:**
- Port 49503 allows modem to push updates (no signature verification visible)
- Port 6789 is safer (outbound-only, ESTABLISHED state)

---

#### **Autopilot Integration Chain**
```
Autopilot APE (.103/.105) ←→ [Ports 8443,8888,etc] ←→ MCU (.100)
                         ←→ [Port 4030 Toolbox API] ←→ MCU (MCU2 only)
                         ←→ [Port 9892-9900 Dashcam] ←→ MCU
```

**Vulnerabilities:**
- Toolbox API (port 4030) provides deep system access to APE
- Removed in Model 3/Y (security improvement)
- Dashcam services create data flow from MCU → APE

---

#### **Radio/Entertainment Chain**
```
Tuner (.30) ←→ [Ports 20564, 5555, 30508-30513, etc] ←→ MCU (.100)
            ←→ [Port 69 TFTP] ←→ MCU (updater only)
```

**Vulnerabilities:**
- Port 20564 is the `syncterm` exploit trigger
- TFTP (port 69) provides another update path (restricted to updater service)

---

#### **Logging Chain**
```
Modem (.60) → [Ports 5801, 50960, 50666] → Logging services → MCU (.100)
                                                            ↓
                                                     Gateway (.102)
```

**Vulnerabilities:**
- MQTT services (50666, 50877) could be exploited for command injection
- Extensive logging creates data exfiltration risk

---

### Service Startup Dependencies

Based on `/etc/sv/` analysis:

```
1. Basic System
   ├─ firewall-setup → All services (required first)
   ├─ dnsmasq → Network services
   └─ connmand → Network connectivity

2. Update Services
   ├─ updater-envoy (outbound, safe)
   ├─ modem-update-server (inbound, CRITICAL)
   ├─ sx-updater (file-based)
   └─ gadget-updater (file-based)

3. Communication
   ├─ mqtt-logger (port 50666)
   ├─ mqtt-config (port 50877)
   └─ tcud (Tesla Control Unit Daemon)

4. Autopilot Integration
   ├─ ape-deliver (port 8901)
   └─ toolbox-api (ports 4030+, MCU2 only)

5. Entertainment
   ├─ radioserver
   ├─ harman-tuner
   └─ qtcar services
```

---

## Attack Surface Diagram

### Attack Surface by Network Interface

```
┌────────────────────────────────────────────────────────────────┐
│                         EXTERNAL                               │
├────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────────────┐                                  │
│  │   Cellular Network      │                                  │
│  │   (Internet)            │                                  │
│  └────────────┬────────────┘                                  │
│               │                                                 │
│               ▼                                                 │
│  ┌─────────────────────────┐                                  │
│  │   Modem (192.168.90.60) │ ◄─── UNTRUSTED                   │
│  │   Attack Surface: HIGH  │                                   │
│  └────────────┬────────────┘                                  │
└───────────────┼────────────────────────────────────────────────┘
                │
                │ Filtered via modem.iptables
                ▼
┌────────────────────────────────────────────────────────────────┐
│                       VEHICLE NETWORK                          │
│                      192.168.90.0/24                           │
├────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐ │
│  │  MCU2 (192.168.90.100) - PRIMARY TARGET                  │ │
│  │  Attack Surface: CRITICAL                                 │ │
│  │                                                            │ │
│  │  Exposed Services:                                        │ │
│  │  🔴 49503/tcp - Modem Update Server (CRITICAL)           │ │
│  │  🔴 80,443/tcp - HTTP/HTTPS (UNRESTRICTED!)              │ │
│  │  🟠 4030+/tcp - Toolbox API (from APE only, MCU2)        │ │
│  │  🟠 8081/tcp - Service Shell (restricted)                │ │
│  │  🟡 8901/tcp - iris-api / ape-deliver                    │ │
│  │  🟡 50666,50877/tcp - MQTT services (from modem)         │ │
│  │  🟢 53,67/udp - DNS/DHCP (internal services)             │ │
│  └──────────────────────────────────────────────────────────┘ │
│         ▲                ▲                 ▲                    │
│         │                │                 │                    │
│  ┌──────┴─────┐   ┌──────┴──────┐   ┌────┴──────┐            │
│  │ Autopilot  │   │   Tuner     │   │  Gateway  │            │
│  │ APE .103   │   │   .90.30    │   │  .90.102  │            │
│  │     .105   │   │             │   │           │            │
│  │ SEMI-TRUST │   │ SEMI-TRUST  │   │  TRUSTED  │            │
│  └────────────┘   └─────────────┘   └───────────┘            │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Attack Paths by Risk

#### 🔴 CRITICAL Attack Paths

**Path 1: Cellular → Firmware Compromise**
```
Internet → Cellular Modem (.60) → Port 49503 → Modem Update Server → Push Malicious Firmware
```
**Requirements:** Modem exploit  
**Impact:** Full persistent compromise  
**Likelihood:** Low | **Impact:** Critical

---

**Path 2: Unrestricted HTTP/HTTPS**
```
??? → Port 80/443 → Web Exploit → Code Execution → Lateral Movement
```
**Requirements:** Network access (depends on routing/NAT)  
**Impact:** Code execution, system compromise  
**Likelihood:** Medium | **Impact:** High

---

#### 🟠 HIGH Attack Paths

**Path 3: Autopilot → Toolbox API (MCU2 only)**
```
Autopilot Exploit → APE .103/.105 → Port 4030+ (Toolbox API) → System Diagnostics → Privilege Escalation
```
**Requirements:** Autopilot vulnerability  
**Impact:** Deep system access, control  
**Likelihood:** Medium | **Impact:** High  
**Status:** ⚠️ **Mitigated in Model 3/Y** (toolbox-api removed)

---

**Path 4: Modem → MQTT Command Injection**
```
Cellular Modem (.60) → Ports 50666/50877 (MQTT) → Command Injection → Code Execution
```
**Requirements:** Modem exploit + MQTT vulnerability  
**Impact:** Remote code execution  
**Likelihood:** Low | **Impact:** High

---

#### 🟡 MEDIUM Attack Paths

**Path 5: Physical → CAN → Service Shell**
```
Physical Access → OBD-II Port → CAN Injection → Internal Network (.90.x) → Port 8081 (Service Shell) → Diagnostics
```
**Requirements:** Physical access  
**Impact:** Diagnostic access, limited control  
**Likelihood:** Medium | **Impact:** Medium

---

**Path 6: Tuner Exploit → Syncterm Trigger**
```
Radio Signal → Tuner Exploit → Port 20564 (sx-updater) → syncterm Crash → Denial of Service
```
**Requirements:** Tuner vulnerability  
**Impact:** System instability  
**Likelihood:** Low | **Impact:** Medium

---

### Defense in Depth Analysis

```
Layer 1: External (Cellular/WiFi)
├─ NAT/Routing (assumed)
├─ Modem isolation (partial)
└─ WiFi network segmentation

Layer 2: Firewall (iptables)
├─ ✅ Modem restrictions (mostly ESTABLISHED state)
├─ ❌ HTTP/HTTPS unrestricted (WEAKNESS)
├─ ✅ Service shell blocks untrusted ECUs
├─ ❌ Toolbox API trusts autopilot (WEAKNESS, MCU2)
└─ ✅ Most services properly scoped to internal network

Layer 3: Service Authentication
├─ ❌ Most services have NO authentication
├─ ? iris-api may have token-based auth
├─ ✅ SSH requires key (return traffic only)
└─ ❌ Update server (49503) - no visible auth

Layer 4: Application Security
├─ ? Update signature verification (not visible in firewall)
├─ ? Input validation on API services
└─ ? Exploit mitigations (ASLR, DEP, etc.)

Layer 5: Monitoring & Detection
├─ ✅ Extensive logging (50960, 5801, 50666)
├─ ? Anomaly detection
└─ ? Intrusion detection
```

**Overall Assessment:**
- **Strong:** Firewall segmentation, logging
- **Weak:** Authentication, HTTP/HTTPS exposure, modem update path
- **Missing:** Application-layer security details (not visible in firewall analysis)

---

## Security Recommendations

### Immediate Actions (High Priority)

#### 1. **Restrict HTTP/HTTPS Ports (80/443)**
```bash
# BEFORE (VULNERABLE):
-A CONNMAND -p tcp --dport 80 -j ACCEPT

# AFTER (SECURE):
-A CONNMAND -i eth0 -s 192.168.90.0/24 -p tcp --dport 80 -j ACCEPT
-A CONNMAND -i lo -p tcp --dport 80 -j ACCEPT
-A CONNMAND -p tcp --dport 80 -j REJECT
```

#### 2. **Enhance Modem Update Server Security (Port 49503)**
- **Add cryptographic signature verification** for all firmware updates
- **Implement rate limiting** on update attempts
- **Add integrity checking** before firmware installation
- **Log all update attempts** with alert on failures

#### 3. **Backport Model 3/Y Security Improvements to MCU2**
- **Remove toolbox-api** (ports 4030+) or add stronger authentication
- **Review and update other changed services** from Model 3/Y firmware

#### 4. **Implement MQTT Authentication (Ports 50666/50877)**
- Add TLS + client certificate authentication
- Implement message signing
- Rate limit MQTT messages from modem

---

### Medium Priority

#### 5. **Network Segmentation Enhancements**
- Isolate modem on separate VLAN with strict routing rules
- Separate autopilot network from MCU (if architecturally feasible)
- Implement network traffic monitoring between segments

#### 6. **Service Shell Hardening (Port 8081)**
- Add authentication (at minimum, shared secret)
- Implement session logging with alerts
- Consider removal in production firmware (keep in service mode only)

#### 7. **Autopilot API Security**
- Audit ports 8443, 8888, 19004 for vulnerabilities
- Implement mutual TLS between MCU and APE
- Add input validation and rate limiting

---

### Long-Term Improvements

#### 8. **Zero Trust Architecture**
- Implement certificate-based authentication for all inter-ECU communication
- Deploy microsegmentation with per-service firewall rules
- Add runtime integrity monitoring

#### 9. **Secure Update Pipeline**
- Multi-signature requirement for firmware updates
- Rollback capability for failed updates
- Secure boot chain validation

#### 10. **Monitoring & Alerting**
- Deploy intrusion detection system (IDS) on vehicle network
- Alert on:
  - Unexpected port 49503 access
  - Service shell access (port 8081)
  - Toolbox API usage (port 4030+, MCU2)
  - Unusual MQTT traffic patterns
  - Failed authentication attempts

#### 11. **Regular Security Audits**
- Quarterly firewall rule reviews
- Penetration testing of critical services
- Vulnerability scanning of all network services
- Third-party security assessments

---

## Appendix: Comparison with Model 3/Y

### Removed Services (Security Improvements)
- ✅ **toolbox-api.iptables** - High-risk diagnostic API removed
- ✅ **ubloxd.iptables** - u-blox GPS daemon removed
- ✅ **qtcar-cluster.iptables** - Cluster display service refactored

### Added Services (New Features)
- **car-assist.iptables** - Car assistance features
- **lightshow-parser.iptables** - Light show functionality
- **vaultd.iptables** - Vault daemon (credential storage)
- **qtcar-ecallclient.iptables** - Emergency call client

### Port Changes
- **infohealthd:** Port 20100 (MCU2) → Port 4321 (Model 3/Y)

### Security Posture Evolution
```
MCU2 (Model S/X 2024.x)           Model 3/Y (2024.x)
├─ Toolbox API exposed            ├─ Toolbox API REMOVED ✅
├─ Port 20100 (infohealthd)       ├─ Port 4321 (infohealthd)
├─ More open diagnostic access    ├─ Tighter access controls
└─ Larger attack surface          └─ Reduced attack surface ✅
```

**Recommendation:** Backport Model 3/Y security improvements to MCU2 firmware.

---

## Appendix B: Security Platform Gateway Server Comparison

### Purpose
This section compares the Tesla MCU2 vehicle network architecture with the Security Platform Gateway monitoring server (c.wgg.co) to highlight different security models.

### Security Platform Gateway Network (c.wgg.co)

**Server Type:** Cloud-based monitoring/gateway (Ubuntu Linux)  
**Environment:** DigitalOcean VPS (public internet)  
**Security Model:** Default-deny firewall with selective service exposure

#### Network Interfaces (Security Platform)
```
eth0:        178.128.115.127/20 (Public Internet)
eth0:        10.15.0.5/16 (DigitalOcean anchor)
eth1:        10.130.53.98/16 (Private VPC)
tailscale0:  100.127.14.89/32 (VPN mesh)
lo:          127.0.0.1/8 (Localhost)
```

#### Port Matrix (Security Platform vs Tesla MCU2)

| Port | Service | Security Platform Status | Tesla MCU2 Status | Security Comparison |
|------|---------|----------------|-------------------|---------------------|
| **22** | SSH | ✅ Public (key-auth) | ⚠️ Internal only | Security Platform: Remote access required |
| **80** | HTTP | ✅ Public (allowed) | ⚠️ UNRESTRICTED | Both: Need source filtering |
| **443** | HTTPS | ✅ Public (NGINX) | ⚠️ UNRESTRICTED | Both: TLS + auth needed |
| **631** | CUPS/IPP | 🔴 Public (CRITICAL) | ❌ Not present | Security Platform: Should disable |
| **8888** | Dashboard | 🟡 Public (JWT+Turnstile) | ❌ Not present | Security Platform: Monitoring UI |
| **18789** | Security Platform API | ✅ Localhost only | ❌ Not present | Good: Internal isolation |
| **25956** | Updater Shell | ❌ Not present | 🔴 Internal (exploit) | Tesla: High-risk diagnostic |
| **49503** | Update Server | ❌ Not present | 🔴 Modem→MCU (critical) | Tesla: Firmware update path |
| **4030-7654** | Toolbox API | ❌ Not present | 🔴 APE→MCU (removed 3/Y) | Tesla: Removed in newer models |
| **50666/50877** | MQTT | ❌ Not present | 🟡 Internal logging | Tesla: Command injection risk |

#### Firewall Comparison

**Security Platform Gateway (UFW/iptables):**
```
Default Policy: DROP (20,419 packets blocked)
Allowed Services: 22, 80, 443, 8888 (explicit whitelist)
VPN Integration: Tailscale bypass (authenticated)
```

**Tesla MCU2 (iptables):**
```
Default Policy: DROP
Allowed Services: Complex ruleset (84 files)
Network Segments: 192.168.90.0/24 (internal only)
```

#### Key Differences

| Aspect | Security Platform Gateway | Tesla MCU2 |
|--------|------------------|------------|
| **Threat Model** | Internet-exposed, public attacks | Internal vehicle network, physical proximity |
| **Authentication** | JWT, SSH keys, VPN | Mostly none (network segmentation) |
| **Firewall Strategy** | Minimal exposure | Segmented trust zones |
| **Update Security** | Package manager (apt) | Custom firmware with signing |
| **Remote Access** | Required (SSH, VPN) | Prohibited (safety-critical) |

#### Security Lessons

**From Tesla MCU2 → Security Platform:**
1. ✅ **Network segmentation** - Security Platform uses localhost isolation effectively
2. ✅ **Service authentication** - Security Platform requires JWT (Tesla often doesn't)
3. ⚠️ **CUPS exposure** - Security Platform repeats Tesla's HTTP/HTTPS unrestricted mistake

**From Security Platform → Tesla MCU2:**
1. ✅ **Strong authentication** - Tesla could benefit from API token systems
2. ✅ **VPN access model** - Tailscale-like secure diagnostics access
3. ✅ **Rate limiting** - Security Platform implements DDoS protection (Tesla should too)

#### Additional Ports Found (Security Platform-Specific)

| Port | Protocol | Service | Version | Risk | Notes |
|------|----------|---------|---------|------|-------|
| **53** | TCP/UDP | systemd-resolved | Ubuntu systemd | 🟢 Low | Localhost DNS only (127.0.0.53, 127.0.0.54) |
| **5353** | UDP | mDNS | openclaw-gateway | 🟢 Low | Service discovery (3 instances) |
| **8317** | TCP | cli-proxy-api | Security Platform | 🟢 Low | Localhost-only CLI proxy |
| **18792** | TCP | openclaw-gateway | Security Platform | 🟢 Low | Secondary API endpoint (localhost) |
| **45729** | TCP | tailscaled | Tailscale 1.94.1 | 🟢 Low | VPN control (100.127.14.89) |
| **57654** | TCP | tailscaled (IPv6) | Tailscale 1.94.1 | 🟢 Low | VPN control (fd7a:115c:a1e0::e01:e8d) |
| **41641** | UDP | tailscaled | Tailscale 1.94.1 | 🟢 Low | DERP relay (encrypted NAT traversal) |

**Detailed Analysis:** See `/root/tesla/25-network-attack-surface.md`

---

## Document Revision History

| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 1.0 | 2026-02-02 | Initial comprehensive documentation | Security Platform Security Analysis |
| 1.1 | 2026-02-03 | Added Security Platform Gateway comparison (Appendix B) | Security Platform Network Analysis Subagent |

---

## References

- **Source Report:** `/root/downloads/firewall-analysis-report.md`
- **Firewall Rules:** `/etc/firewall.d/` (84 rule files analyzed)
- **Service Definitions:** `/etc/sv/` directory structure
- **Previous Analysis:** `01-exploit-chain-summary.md`, `02-vulnerability-deep-dive.md`, `03-firmware-update-analysis.md`

---

**Document prepared by:** Security Platform Tesla Security Research  
**Classification:** Internal Technical Documentation  
**Last Updated:** February 2, 2026, 20:51 UTC
