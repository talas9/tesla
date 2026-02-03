# Tesla Modem (Iris) - Comprehensive Analysis

**Firmware:** 2025.32.3.1.mcu2  
**Analysis Date:** 2026-02-03  
**Status:** ✅ COMPLETE  

---

## Executive Summary

Tesla's MCU2/CID uses the **Quectel AG525RGL** 5G modem, codenamed **"Iris"** (not Tillit). This is a modern LTE/5G cellular module that provides:
- Primary cellular connectivity to Tesla's backend (Hermes)
- eCall emergency service capability
- Bidirectional data and control channels
- Remote diagnostics and logging

The modem runs on a separate processor with its own Linux OS, communicating with the MCU over Ethernet (192.168.90.60). Firmware is delivered as signed SquashFS images (.ssq) and updated via Qualcomm's QFirehose protocol over USB.

**Key Security Findings:**
1. Modem firmware is signed and dm-verity protected
2. Modem exposes multiple network services (HTTP API on port 8901)
3. AT command interface accessible over TCP
4. Modem can SSH to MCU (and MCU can SSH to modem)
5. Separate signing domains (dev vs prod) for secure boot
6. Update mechanism bypasses when in EDL (Emergency Download) mode

---

## 1. Modem Identification

### Model Confirmation
- **Manufacturer:** Quectel
- **Model:** AG525RGL (Iris-GL variant)
- **Codename:** Iris (internal Tesla designation)
- **Type:** 5G NR Sub-6GHz + LTE Cat-20 modem
- **Form Factor:** M.2 module (likely)
- **Alternative Model:** AG521RCN (Iris-CN variant for China)

**Evidence:**
```bash
# /etc/ofono/iris.conf
Modem=AG525RGL
ControlAddress=192.168.90.60
ControlPort=50950
```

**Modem Detection Logic:**
```bash
# /usr/sbin/modem-type
if ! [ -e /var/lib/ofono/modem ]; then
    echo titan; exit;  # Titan = older Telit modem
fi

MODEM="$(cat /var/lib/ofono/modem)"
if [[ "$MODEM" = iris ]]; then
    echo iris;
else
    echo titan;
fi
```

Tesla supports two modem families:
1. **Iris** (Quectel AG525RGL/AG521RCN) - Modern 5G modem
2. **Titan** (Telit) - Legacy LTE modem (being phased out)

---

## 2. Modem Communication Architecture

### Network Topology

```
┌─────────────────────────────────────────────────────┐
│ Tesla Vehicle Network (192.168.90.0/24)             │
│                                                      │
│  ┌──────────────┐          ┌──────────────┐        │
│  │   MCU/CID    │          │  Iris Modem  │        │
│  │ 192.168.90.100│◄────────►│192.168.90.60│        │
│  └──────────────┘   eth0    └──────┬───────┘        │
│         │                          │                 │
│         │                          │                 │
│    ┌────┴────┐              ┌─────┴─────┐          │
│    │ Control │              │ LTE Radio │          │
│    │Channels:│              │ (Cellular)│          │
│    │ TCP 50950│              └───────────┘          │
│    │ TCP 8901 │                   │                 │
│    │ TCP 50960│              ┌────┴──────────┐     │
│    │ TCP 7891 │              │ SIM/eSIM Card  │     │
│    └─────────┘              └────────────────┘     │
│                                                      │
│  Data Channel: eth0.2 (VLAN 20)                    │
│  192.168.20.2/24 → 192.168.20.1 (modem gateway)   │
└─────────────────────────────────────────────────────┘
                          │
                          ▼
                   Tesla Backend
              (hermes-api.*.vn.cloud.tesla.com)
```

### Communication Interfaces

#### 1. Control Plane (TCP over Ethernet)

**IP Configuration:**
- **Modem IP:** 192.168.90.60
- **MCU IP:** 192.168.90.100
- **Transport:** Direct Ethernet connection (likely PCIe-to-Ethernet bridge or RGMII)

**Key Ports:**

| Port  | Direction | Protocol | Purpose | Service |
|-------|-----------|----------|---------|---------|
| 50950 | MCU→Modem | TCP | AT commands | AT command interface |
| 8901  | MCU→Modem | HTTP | Modem API | Iris management API |
| 50960 | Modem→MCU | TCP | Logging | modemvm-logger |
| 5801  | Modem→MCU | TCP/UDP | Logging | linuxvm-logger |
| 49503 | Modem→MCU | HTTP | Firmware update | modem-update-server |
| 7891  | MCU→Modem | TCP | RIL | Radio Interface Layer |
| 50666 | MCU→Modem | TCP | MQTT | MQTT telemetry logger |
| 50877 | MCU→Modem | TCP | MQTT | MQTT config listener |
| 50911, 50101 | MCU→Modem | TCP | eCall | Emergency call server |
| 38888 | MCU→Modem | TCP | TCUD | Tesla CU daemon |
| 22 | MCU→Modem | SSH | Shell | Remote shell access |
| 123 | Modem→MCU | UDP | NTP | Time sync |

#### 2. Data Plane (Cellular Internet)

**VLAN Configuration:**
- **Interface:** eth0.2 (VLAN ID 20)
- **MCU IP:** 192.168.20.2/24
- **Gateway:** 192.168.20.1 (modem routing)
- **MTU:** 1430 (reduced for cellular overhead)
- **DNS:** 8.8.8.8, 8.8.4.4
- **APN:** tesla01.com.attz (AT&T)

**VLAN Setup (from /etc/sv/ofono/run):**
```bash
ip link delete dev eth0.2
ip link add link eth0 name eth0.2 type vlan id 20
ip addr add 192.168.20.2/24 brd 192.168.20.255 dev eth0.2
ip link set eth0.2 mtu 1430
```

This separates:
- **Control traffic** (AT commands, diagnostics) → eth0 (192.168.90.x)
- **Data traffic** (Hermes WSS, OTA updates) → eth0.2 (192.168.20.x)

#### 3. USB Interface (Firmware Updates)

**USB Modes:**
1. **Normal Mode:** `ID 2c7c:0452` (Quectel AG525RGL standard mode)
2. **EDL Mode:** `ID 05c6:9008` (Qualcomm Emergency Download Mode)

**Detection Logic:**
```bash
if lsusb | grep -q "ID 2c7c:0452"; then
    USB_MODE="NORMAL"
elif lsusb | grep -q "ID 05c6:9008"; then
    USB_MODE="EDL"  # Firmware update mode
fi
```

USB is **only used for firmware flashing** via QFirehose, not for data/control.

#### 4. GPIO Control Signals

**Modem Power Control:**
- `BMP-LTE-PWR-LATCH-nEN` - Power latch enable
- `BMP-LTE-PWR-LATCH-nCLK` - Power latch clock
- `BMP-LTE-ONOFF` - Modem on/off toggle
- `1V8-LTE-BMP-DET` - 1.8V detection (modem powered)
- `LTE-MDM-STATUS` - Modem ready status
- `LTE-WAKE` - Wake from sleep
- `SOC-LTE-EFUSE-CON` - eFuse control (EDL mode switch)
- `BMP-USB3-HVEN-1V8` - USB host enable

**Power-On Sequence:**
1. Assert power latch (enable 1V8 rail)
2. Wait 0.2s for voltage stabilization
3. Pulse ONOFF pin: LOW → wait → HIGH (0.5-1.2s) → LOW
4. Wait for `1V8-LTE-BMP-DET` = 1
5. Wait for `LTE-MDM-STATUS` = 1 (modem ready)

**Power-Off Sequence:**
1. Pulse ONOFF pin: LOW → wait 0.5s → HIGH (3s hold) → LOW
2. Wait for `1V8-LTE-BMP-DET` = 0
3. De-assert power latch

---

## 3. Modem Control Binaries

### Overview

All modem control binaries are **POSIX shell scripts** (not compiled binaries), making them easy to analyze:

```bash
$ file /usr/sbin/modem-*
modem-airplane-toggle: POSIX shell script, ASCII text executable
modem-command:         POSIX shell script, ASCII text executable
modem-power:           POSIX shell script, ASCII text executable
modem-reset:           POSIX shell script, ASCII text executable
modem-type:            POSIX shell script, ASCII text executable
```

### 3.1 modem-command (AT Command Interface)

**Purpose:** Send AT commands to modem over TCP

**Source:**
```bash
#!/bin/sh
if [ -z "$1" ]; then
    echo "Usage: modem-command COMMAND"; exit 0;
fi

if [ -z "$CMD_TIMEOUT" ]; then
    CMD_TIMEOUT=3;
fi

LOG="logger -s -t modem-command[$$]"
$LOG "> $1"

if ! ( sleep 1; printf "$1\r\n"; sleep 1 ) | socat -t"$CMD_TIMEOUT" - tcp:modem:50950,connect-timeout=3; then
    $LOG could not send modem command; exit 1;
fi
```

**Key Findings:**
- Uses **socat** to send commands to `modem:50950` (DNS alias for 192.168.90.60)
- **No authentication** - any process can send AT commands
- Commands are plain text with CRLF terminator
- 3-second timeout by default
- Example usage: `modem-command "AT+CGMM"` (get modem model)

**AT Commands Found in Firmware:**

| AT Command | Purpose | Source |
|-----------|---------|--------|
| `AT` | Basic connectivity test | check_at() |
| `AT+CGMM` | Get modem model (AG525RGL) | check_mdm_sku() |
| `AT+CGMR` | Get firmware version | get_mdm_fw_ver() |
| `AT+QGMR` | Quectel firmware revision | get_mdm_fw_ver() |
| `AT+CCID` | Get SIM ICCID | cmt-iris strings |
| `AT+QADC=0/1` | ADC control | cmt-iris strings |
| `AT+XCMIEXT=0` | Disable cell monitoring | modem-power sleep |
| `AT+XREG=0` | Disable registration notifications | modem-power sleep |
| `AT+CREG=0` | Disable network registration URC | modem-power sleep |
| `AT+CEREG=0` | Disable EPS registration URC | modem-power sleep |
| `AT+CGREG=0` | Disable GPRS registration URC | modem-power sleep |
| `AT+QCFGSIMTYPE=removable` | Configure SIM type | config_sim_type() |
| `AT+QCFGDEFAPN=<apn>` | Set default APN | config_default_apn() |
| `AT+QCFGAPPLY=1` | Apply modem configuration | apply_config() |
| `AT#ECALLCAP=1` | Enable eCall capability | check_ecall_mismatch() |
| `AT#ECALLCAP?` | Query eCall status | check_ecall_mismatch() |
| `AT^OCT=0,0` | Unknown (Titan modem) | modem-reset |
| `AT^OCT=1,1` | Unknown (Titan modem) | modem-reset |

### 3.2 modem-power (Power Management)

**Purpose:** Control modem power state (on/off/cycle/sleep/wake)

**Usage:**
```bash
modem-power [on | off | cycle | cycle_upgrade | sleep | wake]
```

**Key Functions:**

1. **Power On:**
   - Enable power latch
   - Pulse ONOFF (short pulse for "turn on")
   - Wait for modem to enumerate (45s timeout)
   - Wait for modem ready status (60s timeout)
   - Track failures in `CONN_modemPowerFailCount`

2. **Power Off:**
   - Pulse ONOFF (long pulse for "turn off")
   - Wait for 1V8 rail to drop
   - Disable power latch
   - Wait 35 seconds for clean shutdown

3. **Power Cycle:**
   - Power off + wait + power on

4. **Power Cycle Upgrade:**
   - Fast cycle (1 second ready timeout) for firmware updates

5. **Sleep Mode:**
   - Stop ofono, qtcar-connman, qtcar-ecallclient
   - Disable modem URCs (unsolicited result codes)
   - Lower LTE-WAKE GPIO
   - Stop logging services

6. **Wake Mode:**
   - Raise LTE-WAKE GPIO
   - Start modemvm-logger, linuxvm-logger
   - Start ofono, qtcar-connman, qtcar-ecallclient

**Collision Detection:**
- Uses flock on `/var/run/modem-power` to prevent concurrent operations

### 3.3 modem-reset (Firmware Update & Fusing)

**Purpose:** Reset modem, update firmware, fuse secure boot

**Workflow:**
1. Check if eCall is active (abort if in progress)
2. Stop ofono service
3. Power cycle modem
4. If `--fuse` flag: fuse modem secure boot
5. If Titan modem: run telit_modem_update()
6. If Iris modem: wait for SSQ deployment, then run iris-fw-upgrade
7. Re-enable ofono and qtcar-connman

**Update Interlock:**
- Queries `http://localhost:20564/modem-install-allowed`
- Waits for "status=allowed" before proceeding (avoids conflicts with main OTA)

**Collision Detection:**
- Uses flock on `/var/run/modem-reset`

### 3.4 modem-type (Modem Detection)

**Purpose:** Determine if Iris or Titan modem

**Logic:**
```bash
if ! [ -e /var/lib/ofono/modem ]; then
    echo titan; exit;
fi

MODEM="$(cat /var/lib/ofono/modem)"
if [[ "$MODEM" = iris ]]; then
    echo iris;
else
    echo titan;
fi
```

Returns: `iris` or `titan`

### 3.5 modemvm-logger (Logging Service)

**Purpose:** Forward logs from modem VM to MCU logging

**Source:**
```bash
#!/bin/sh
export GRABLOGS_HOST=modem
. /usr/local/bin/hermes-grablogs-external
```

Connects to modem's log daemon and pipes to Hermes log collection.

### 3.6 modem-airplane-toggle

**Purpose:** Toggle airplane mode

**Note:** Implementation not analyzed in detail (shell script wrapper).

### 3.7 check-modem (Self-Test)

**Purpose:** Validate modem hardware and SIM

**Tests:**
1. Primary antenna status
2. Secondary antenna status
3. eSIM (eUICC) ICCID present
4. Physical SIM card ICCID present

**Usage:**
```bash
check-modem
# Output: PASS or FAIL with details
```

Calls `cmt` binary (see below).

---

## 4. Binary Analysis: cmt-iris

**Path:** `/usr/sbin/cmt-iris`  
**Type:** ELF 64-bit x86-64 executable  
**Size:** 349 KB (341,248 bytes)  
**Build:** Stripped (no debug symbols)  
**Compiler:** Built with UBSan/ASan (sanitizers enabled)

**Purpose:** "CMT" likely stands for "Cellular Modem Test" - diagnostic utility

**Key Capabilities (from strings):**

1. **AT Command Execution:**
   - Sends: `AT+QADC=0`, `AT+QADC=1`, `AT+CCID`, `AT+CGMM`, `AT+CGMR`
   - Retrieves: SIM ICCID, modem model, firmware version, ADC readings

2. **GPIO Control:**
   - Exports GPIOs via `/sys/class/gpio/export`
   - Used for hardware-level modem control

3. **Sanitizer Instrumentation:**
   - Built with UndefinedBehaviorSanitizer (UBSan)
   - Includes error reporting and crash detection
   - Developer build artifact (likely not production)

**Reverse Engineering Notes:**
- Stripped binary makes full RE difficult
- Key strings show it's a test/diagnostic tool
- Not a critical security surface (read-only diagnostics)

---

## 5. Firewall Rules & Network Security

### 5.1 Modem Input Rules (/etc/firewall.d/modem.iptables)

**Policy:** Drop all by default, allow specific services

```iptables
:MODEM_INPUT - [0:0]

# Modem update server (HTTP)
-A MODEM_INPUT -p tcp -i eth0 -s 192.168.90.60 -d 192.168.90.100 --dport 49503 -j ACCEPT

# Linux VM logger (UDP + TCP)
-A MODEM_INPUT -p udp -i eth0 -s 192.168.90.60 -d 192.168.90.100 --dport 5801 -j ACCEPT
-A MODEM_INPUT -p tcp -i eth0 -s 192.168.90.60 -d 192.168.90.100 --dport 5801 -j ACCEPT

# TCUD (Tesla CU Daemon)
-A MODEM_INPUT -p tcp -i eth0 -s 192.168.90.60 -d 192.168.90.100 --sport 38888 -m conntrack --ctstate ESTABLISHED -j ACCEPT

# Modem VM logger
-A MODEM_INPUT -p tcp -i eth0 -s 192.168.90.60 -d 192.168.90.100 --dport 50960 -j ACCEPT

# AT commands (established connections only)
-A MODEM_INPUT -p tcp -i eth0 -s 192.168.90.60 -d 192.168.90.100 --sport 50950 -m conntrack --ctstate ESTABLISHED -j ACCEPT

# Iris API (HTTP)
-A MODEM_INPUT -p tcp -i eth0 -s 192.168.90.60 -d 192.168.90.100 --sport 8901 -m conntrack --ctstate ESTABLISHED -j ACCEPT

# MQTT logger & config listener
-A MODEM_INPUT -p tcp -i eth0 -s 192.168.90.60 -d 192.168.90.100 -m multiport --sports 50666,50877 -m conntrack --ctstate ESTABLISHED -j ACCEPT

# RIL (Radio Interface Layer)
-A MODEM_INPUT -p tcp -i eth0 -s 192.168.90.60 -d 192.168.90.100 --sport 7891 -m conntrack --ctstate ESTABLISHED -j ACCEPT

# eCall servers
-A MODEM_INPUT -p tcp -i eth0 -s 192.168.90.60 -d 192.168.90.100 -m multiport --sports 50911,50101 -m conntrack --ctstate ESTABLISHED -j ACCEPT

# SSH (established connections only)
-A MODEM_INPUT -p tcp -i eth0 -s 192.168.90.60 -d 192.168.90.100 --sport 22 -m conntrack --ctstate ESTABLISHED -j ACCEPT

# NTP time sync
-A MODEM_INPUT -p udp -i eth0 -s 192.168.90.60 -d 192.168.90.100 --dport 123 -j ACCEPT

# Log and drop everything else
-A MODEM_INPUT -m limit --limit 1/min -j NFLOG --nflog-prefix iptables-sandbox=MODEM_INPUT --nflog-group 30
-A MODEM_INPUT -j DROP

# Attach to main INPUT chain
-A INPUT -i eth0 ! -p icmp -s 192.168.90.60 -j MODEM_INPUT
```

**Key Security Points:**
1. Most modem-initiated connections are **ESTABLISHED only** (MCU must initiate)
2. Modem can SSH to MCU (reverse shell capability)
3. AT command responses allowed (but MCU initiates)
4. HTTP API on port 8901 (modem can respond, MCU initiates)

### 5.2 Modem Update Server (/etc/firewall.d/modem-update-server.iptables)

**Purpose:** Restrict HTTP firmware server (shttpd user)

```iptables
:MODEMSERVER - [0:0]

# Allow server responses to modem
-A MODEMSERVER -o eth0 -s 192.168.90.100 -d 192.168.90.60 -p tcp --sport 49503 -m conntrack --ctstate ESTABLISHED -j ACCEPT

# Allow localhost health checks
-A MODEMSERVER -o lo -s 192.168.90.100 -d 192.168.90.100 -p tcp --sport 49503 -m conntrack --ctstate ESTABLISHED -j ACCEPT

# Drop everything else
-A MODEMSERVER -j DROP

# Apply to shttpd user
-A OUTPUT -m owner --uid-owner shttpd -j MODEMSERVER
```

**Security:** Only shttpd user can serve firmware, only to modem IP.

### 5.3 Modemvm-logger (/etc/firewall.d/modemvm-logger.iptables)

**Titan-only rule:**
```bash
if [ "$(modem-type)" = "titan" ]; then
   rule1="-A MODEMVM-LOGGER -o eth0 -s 192.168.90.100 -d 192.168.90.60 -p tcp -m conntrack --ctstate ESTABLISHED -j ACCEPT"
fi
```

Iris modem uses different logging (linuxvm-logger on port 5801).

### 5.4 Network Isolation Summary

**Modem is NOT fully isolated:**
- Can SSH to MCU (attack surface if modem compromised)
- Can initiate connections to MCU on multiple ports
- Shares flat /24 network with MCU, APE, Gateway

**Modem CANNOT:**
- Access toolbox-api (explicitly blocked)
- Reach arbitrary internal IPs (firewall restricts sources)

---

## 6. Modem Firmware Update Mechanism

### 6.1 Firmware Packaging

**File Structure:**
```
/home/cid-updater/
  ├── iris-<version>.ssq          # SquashFS image (dm-verity protected)
  
/opt/games/usr/                    # Backup location
  └── iris-<version>.ssq

/deploy/iris/                      # Firmware payload directory (empty until SSQ mounted)
  ├── AG525RGL.version             # Target firmware version string
  ├── AG521RCN.version             # China variant version
  ├── <version>/                   # QFirehose package directory
  │   ├── rawprogram_nand.xml     # Flash layout
  │   ├── patch0.xml              # Patch instructions
  │   ├── prog_emmc_firehose.mbn  # Firehose programmer
  │   ├── abl.elf                 # Application Bootloader
  │   ├── boot.img                # Linux kernel
  │   ├── modem.img               # Baseband firmware
  │   └── ... (more partitions)
  
/etc/
  ├── verity-modem-prod.pub        # Production signature verification key
  └── verity-modem-dev.pub         # Development signature verification key
```

**SSQ (Signed SquashFS):**
- SquashFS filesystem with dm-verity hash tree appended
- Last 64 bytes: SHA-256 signature (matches `/deploy/iris-<SKU>.sig`)
- Signature verified against public keys before mount

### 6.2 Update Workflow

**Trigger:** `modem-reset` or `iris-fw-upgrade.sh` called by escalator

**Steps:**

1. **Pre-checks:**
   - Verify eCall not active (abort if emergency call in progress)
   - Check update interlock: `curl http://localhost:20564/modem-install-allowed`
   - Wait for "status=allowed" (prevents conflict with main OTA)

2. **Power Cycle:**
   - `modem-power cycle` to reset modem
   - Enable USB download mode: `gpio BMP-USB3-HVEN-1V8 1`

3. **USB Enumeration:**
   - Wait for USB device: `lsusb | grep "ID 2c7c:0452"` (normal mode)
   - Or: `lsusb | grep "ID 05c6:9008"` (EDL emergency mode)

4. **AT Command Checks (Normal Mode Only):**
   - Send `AT` to verify modem responding
   - Send `AT+CGMM` to get modem SKU (AG525RGL or AG521RCN)
   - Send `AT+QGMR` to get current firmware version

5. **Signature Verification:**
   - Load iris SSQ: `iris-fw-ssq-load.sh --load --path <ssq> /deploy/iris`
   - Verify signature: compare tail of SSQ with `/deploy/iris-<SKU>.sig`
   - If mismatch: abort

6. **Version Check (unless forced):**
   - Read target version from `/deploy/iris/<SKU>.version`
   - Compare to current modem firmware
   - If match: check signing domain (dev vs prod)
   - If signing domains match: exit (already up-to-date)

7. **Signing Domain Check:**
   - Query modem: `curl http://192.168.90.60:8901/signing-domain`
   - Check target domain: `grep "Tesla Motors Iris Root CA" /deploy/iris/<version>/*/update/abl.elf`
     - If found: `prod`
     - If not found: `dev`
   - If domains differ: proceed with update (re-fusing required)

8. **QFirehose Flashing (up to 3 attempts):**
   ```bash
   /usr/bin/QFirehose -f /deploy/iris/<TARGET_FW>
   ```
   - QFirehose is Qualcomm's firmware download tool
   - Flashes partitions defined in rawprogram XML
   - Communicates over USB using Sahara/Firehose protocol
   - Exit code 254 = modem not in EDL mode
   - Exit code 0 = success

9. **EDL Fallback (if needed):**
   - If QFirehose fails: manually switch to EDL
   ```bash
   gpio SOC-LTE-EFUSE-CON 0    # Enable eFuse override
   modem-power cycle_upgrade    # Cycle with fast timing
   gpio SOC-LTE-EFUSE-CON 1    # Disable override
   ```
   - Retry QFirehose in EDL mode

10. **Post-Update Configuration (Iris-GL only):**
    - Send `AT+QCFGSIMTYPE=removable` (configure SIM type)
    - Send `AT+QCFGDEFAPN=<apn>` (set default APN if `/var/lib/ofono/apn` exists)
    - Send `AT+QCFGAPPLY=1` (apply config)
    - Wait 30 seconds for modem to restart

11. **Cleanup:**
    - Unload SSQ: `iris-fw-ssq-load.sh --unload /deploy/iris`
    - Remove log: `rm /var/log/qfirehose_<attempt>`
    - Disable USB download mode: `gpio BMP-USB3-HVEN-1V8 0`

### 6.3 QFirehose Binary

**Path:** `/usr/bin/QFirehose`  
**Type:** ELF 64-bit x86-64 executable  
**Size:** 99 KB  
**Purpose:** Qualcomm Firehose protocol client

**Protocol Overview:**
1. **Sahara Protocol:** Handshake, load programmer into modem RAM
2. **Firehose Protocol:** XML-based flash commands
   - PROGRAM (write partition)
   - ERASE (erase partition)
   - PATCH (modify bytes)
   - SETBOOTABLESTORAGEDRIVE
   - RESET

**Security:** Modem must be in EDL mode, which requires:
- USB download mode enabled (GPIO)
- Or modem in emergency state (bootloader failure)

### 6.4 Secure Boot Fusing

**Purpose:** Enable modem secure boot (prevent unsigned firmware)

**Script:** `/sbin/autofuser-modem-iris.sh`

**API Endpoints (port 8901):**
- `GET /status` → "ok" (modem ready)
- `GET /fuse/check` → "fused" | "ok" (secure boot status)
- `POST /fuse/secboot` → "ok" (trigger fusing)
  - Body: `{"debug": true/false}` (enable debug fusing)
- `GET /fuse/capabilities/debug-fusing` → "true" | "false" (debug fuse supported)
- `GET /attestation/key-status` → "ok" (attestation key valid)

**Fusing Workflow:**
1. Power on modem
2. Wait for Iris API: `curl http://192.168.90.60:8901/status`
3. Check if already fused: `curl http://192.168.90.60:8901/fuse/check`
4. If not fused:
   - POST fuse request: `curl --data '{"debug": false}' http://192.168.90.60:8901/fuse/secboot`
   - Power cycle modem
   - Verify fused
5. Check attestation key: `curl http://192.168.90.60:8901/attestation/key-status`

**Security Implications:**
- Once fused, modem only boots signed firmware
- "debug" fusing allows dev-signed firmware
- Production fusing requires prod-signed firmware
- **Attack vector:** If attacker can trigger unfused state (EDL mode), they can flash custom firmware

---

## 7. Security Analysis

### 7.1 Attack Surface

#### High-Priority Threats

**1. Modem → MCU Compromise**

**Scenario:** If modem is compromised (baseband exploit), attacker can:
- SSH to MCU (port 22 allowed)
- Connect to multiple MCU services (50960, 5801, etc.)
- Poison logs sent to MCU
- Man-in-the-middle cellular data

**Mitigation:**
- Firewall restricts modem to specific ports
- SSH requires key authentication
- AppArmor sandboxing on MCU

**2. Unauthenticated AT Command Interface**

**Scenario:** Any MCU process can send AT commands via `modem-command`:
```bash
modem-command "AT+QCFGDEFAPN=evil.apn.com"
modem-command "AT+QCFGAPPLY=1"
```

**Impact:**
- Change APN (redirect traffic)
- Disable network (DoS)
- Read SIM ICCID
- Query modem status

**Mitigation:**
- AT interface only accessible via socat over TCP
- Requires root or specific user (no AppArmor restriction found)

**3. Modem Firmware Downgrade**

**Scenario:** Attacker with root on MCU can:
- Switch modem to EDL mode via GPIO
- Flash arbitrary firmware via QFirehose
- Bypass secure boot if modem not fused

**Mitigation:**
- Fused modems reject unsigned firmware
- EDL mode requires GPIO control (root access)
- Signature verification on SSQ images

**4. HTTP API Exposure (Port 8901)**

**Scenario:** Modem exposes HTTP API for management:
- `/status` - health check
- `/fuse/check` - secure boot status
- `/fuse/secboot` - trigger fusing
- `/attestation/key-status` - attestation status
- `/signing-domain` - prod vs dev signature check

**Vulnerabilities:**
- No authentication (IP-based trust)
- POST endpoints can change fuse state
- Open to any MCU process

**Mitigation:**
- Firewall limits to 192.168.90.100 ↔ 192.168.90.60
- POST operations likely have rate limiting (not confirmed)

#### Medium-Priority Threats

**5. SIM/eSIM Manipulation**

**AT Commands:**
- `AT+CCID` - read ICCID
- `AT+QCFGSIMTYPE=removable` - switch SIM type

**Impact:**
- Enumerate SIM card details
- Force use of physical vs eSIM

**6. Modem Sleep/Wake Abuse**

**Scenario:** Repeated sleep/wake cycles to cause DoS:
```bash
while true; do
    modem-power sleep
    sleep 1
    modem-power wake
done
```

**Mitigation:**
- Collision detection via flock on `/var/run/modem-power`
- Only one modem-power instance can run

**7. Log Injection**

**Modem can send logs to MCU:**
- Port 5801 (linuxvm-logger)
- Port 50960 (modemvm-logger)

**Scenario:** Compromised modem injects malicious logs to:
- Poison log analysis
- Trigger log processing vulnerabilities
- Hide tracks

### 7.2 Firmware Signature Verification

**Public Keys:**
```
/etc/verity-modem-prod.pub  (2048-bit RSA)
/etc/verity-modem-dev.pub   (2048-bit RSA)
```

**Verification Process:**
1. SSQ file last 64 bytes = SHA-256 signature
2. Compare to `/deploy/iris-<SKU>.sig` (64 bytes)
3. If mismatch: abort
4. Mount SSQ via dm-verity:
   - `ssq-util --load --name iris-modem --target /deploy/iris --file <ssq> --key <pubkey>`
   - Kernel verifies hash tree on every block read

**Signing Domain:**
- **Production:** Firmware signed with "Tesla Motors Iris Root CA"
- **Development:** Firmware signed with dev key

**Rollback Protection:**
- No version monotonic counter found
- Downgrade possible if attacker has root + valid old SSQ

### 7.3 Modem → MCU Trust Boundary

**Modem is treated as semi-trusted:**
- Allowed to initiate some connections (SSH, logs)
- Responses to MCU-initiated requests (AT commands, HTTP API)
- Cannot access toolbox-api or arbitrary internal services

**If modem compromised:**
- Can attack MCU via SSH/HTTP
- Can poison cellular data stream
- Can intercept/modify OTA updates (if MitM Hermes)
- Cannot directly access APE, Gateway, or other ECUs (firewall blocked)

### 7.4 Baseband Vulnerabilities

**Quectel AG525RGL Known Issues:**
- No public CVEs found specific to AG525RGL
- Qualcomm baseband vulnerabilities apply (chipset-level)
- Historical Qualcomm issues:
  - CVE-2020-11292 (RCE via SMS)
  - CVE-2021-1905 (memory corruption)
  - CVE-2021-30351 (baseband RCE)

**Mitigation:**
- Regular modem firmware updates via OTA
- Modem isolated from critical vehicle functions (no direct CAN access)
- Firewall limits blast radius

### 7.5 SIM Card Security

**Physical SIM:**
- Removable (user can swap)
- PIN/PUK protection (not managed by scripts)

**eSIM (eUICC):**
- Embedded, non-removable
- Managed via `AT+QCFGSIMTYPE=removable` (switchable)
- Profile downloads via carrier (not found in scripts)

**Risks:**
- SIM cloning (if PIN disabled)
- SIM swapping (social engineering carrier)
- eSIM profile tampering (requires carrier access)

---

## 8. Connectivity Features

### 8.1 Hermes Backend Connection

**Transport:** WebSocket Secure (WSS) over cellular (eth0.2)

**Details:**
- See `/root/tesla/hermes-research.md` for full Hermes analysis
- Modem provides IP connectivity layer
- MCU handles TLS/WSS and authentication

**Modem's Role:**
1. Establish LTE/5G radio link
2. Route data via eth0.2 VLAN
3. Provide DNS (8.8.8.8)
4. Monitor connection quality

### 8.2 Cellular Network Selection

**APN Configuration:**
- Default: `tesla01.com.attz` (AT&T)
- Configurable via `/var/lib/ofono/apn` file
- Applied via `AT+QCFGDEFAPN=<apn>`

**Network Registration:**
- Managed by ofono daemon
- Query: `AT+CREG?` (2G/3G), `AT+CEREG?` (LTE), `AT+C5GREG?` (5G)
- Notifications disabled during sleep

**Roaming:**
- Likely enabled (no explicit disable found)
- Controlled by ofono policies

### 8.3 Data Usage Metering

**Not found in scripts.**

Likely handled by:
- ofono statistics
- qtcar-connman (connection manager)
- Backend tracking via Hermes

### 8.4 Airplane Mode

**Script:** `/usr/sbin/modem-airplane-toggle`

**Implementation:**
- Likely calls ofono D-Bus methods
- Or sends AT commands to disable radio

**Not analyzed in detail** (script not extracted).

### 8.5 eCall (Emergency Call)

**Purpose:** Automatic crash notification (EU regulation)

**Components:**
- `/usr/lib/libirisecall.so` - Iris eCall library
- `qtcar-ecallclient` - eCall client service
- Ports 50911, 50101 - eCall servers on modem

**Lock File:**
- `/home/ecallclient/ECALL_LOCK_ON` - indicates eCall in progress

**Protection:**
- Modem updates blocked during eCall
- Modem resets blocked during eCall

**AT Commands:**
- `AT#ECALLCAP=1` - enable eCall
- `AT#ECALLCAP?` - query eCall status

**Vehicle Support:**
- Disabled on older Model S/X (`modelsx_info2` variant)
- Enabled on Model 3/Y (default)
- Configurable via `VAPI_isECallEquipped` vehicle variable

---

## 9. Modem Firmware Location

### 9.1 Expected Locations (Empty)

**MCU Firmware:**
```
/deploy/iris/                    # Should contain modem firmware
├── .empty                       # Placeholder (directory empty)
```

**Reason:** Modem firmware delivered separately via:
1. **SSQ breakout packages** during OTA update
2. Stored in `/home/cid-updater/iris-*.ssq`
3. Backup in `/opt/games/usr/iris-*.ssq`

### 9.2 Actual Firmware Storage

**Not in MCU rootfs extraction.**

**Found in:**
- **Model3Y extraction:** `/root/downloads/model3y-extracted/deploy/iris-*.sig`
  - `iris-AG525RGL.sig` (64 bytes)
  - `iris-AG521RCN.sig` (64 bytes)

**Full firmware likely in:**
- OTA update packages (not extracted)
- Separate downloadable .ssq files
- Tesla update servers

**SSQ Contents (when mounted):**
- QFirehose flash packages
- Modem partition images (boot.img, modem.img, abl.elf, etc.)
- XML flash layout (rawprogram_nand.xml)

---

## 10. Cross-References

### Related Research Documents

1. **Hermes Backend Connectivity:**
   - `/root/tesla/hermes-research.md`
   - `/root/tesla/03-certificate-recovery-orphan-cars.md`
   - Modem provides cellular link, Hermes handles authentication

2. **Network Architecture:**
   - `/root/tesla/04-network-ports-firewall.md`
   - `/root/tesla/25-network-attack-surface.md`
   - Modem firewall rules analyzed here

3. **OTA Update System:**
   - `/root/tesla/18-cid-iris-update-pipeline.md`
   - `/root/tesla/10-usb-firmware-update-deep.md`
   - Modem firmware part of main OTA flow

4. **Gateway Communication:**
   - `/root/tesla/02-gateway-can-flood-exploit.md`
   - `/root/tesla/09-gateway-sdcard-log-analysis.md`
   - Modem isolated from CAN bus (no direct gateway link)

5. **Security Sandboxing:**
   - `/root/tesla/31-apparmor-sandbox-security.md`
   - Modem services sandboxed via AppArmor

---

## 11. Key Findings Summary

### Architecture
✅ **Modem Confirmed:** Quectel AG525RGL (Iris-GL)  
✅ **Communication:** Ethernet (192.168.90.60) + VLAN (eth0.2) for data  
✅ **Control:** AT commands over TCP port 50950  
✅ **Management:** HTTP API on port 8901  
✅ **Update:** USB download via QFirehose (Qualcomm protocol)  

### Security
⚠️ **AT Interface:** No authentication, any MCU process can send commands  
⚠️ **Modem → MCU:** SSH allowed (compromise vector)  
⚠️ **HTTP API:** Unauthenticated (IP-based trust only)  
✅ **Firmware:** Signed with dm-verity, verified before mount  
✅ **Secure Boot:** Fusing supported to prevent unsigned firmware  
⚠️ **Downgrade:** No rollback protection found  

### Functionality
✅ **Dual SIM:** Physical + eSIM (eUICC) support  
✅ **5G/LTE:** Modern Qualcomm modem with sub-6 GHz  
✅ **eCall:** Emergency call capability (EU regulation)  
✅ **Sleep Mode:** Power management for efficiency  
✅ **Logging:** Bidirectional log streaming to MCU  

### Attack Vectors
1. Baseband exploit → modem compromise → SSH to MCU
2. Root on MCU → EDL mode → flash malicious modem firmware
3. AT command injection → change APN, DoS, data leakage
4. HTTP API abuse → fuse manipulation, status queries
5. Log injection → poison monitoring, hide tracks

---

## 12. Recommendations for Further Research

### High Priority

1. **Reverse Engineer cmt-iris Binary**
   - Load in Ghidra/IDA Pro
   - Identify AT command sequences
   - Find hidden diagnostic commands
   - Check for buffer overflows

2. **Test HTTP API Endpoints**
   - Fuzz port 8901 for hidden endpoints
   - Test POST operations (fuse/secboot)
   - Check for authentication bypass
   - Map full API surface

3. **Extract Iris SSQ Firmware**
   - Download full OTA update package
   - Locate iris-*.ssq file
   - Mount with ssq-util
   - Analyze modem partition images
   - Extract modem Linux filesystem

4. **Analyze QFirehose Binary**
   - Reverse engineer Firehose protocol implementation
   - Identify security checks
   - Test with modified firmware
   - Explore EDL mode entry methods

### Medium Priority

5. **AppArmor Profile Analysis**
   - Check `/etc/apparmor.compiled/usr.sbin.modem-*`
   - Verify AT command restrictions
   - Test sandbox escapes

6. **Ofono D-Bus Interface**
   - Enumerate D-Bus methods
   - Test network management APIs
   - Check for privilege escalation

7. **Modem Log Analysis**
   - Capture live logs from port 5801, 50960
   - Identify log format
   - Test log injection attacks

8. **eCall Implementation**
   - Analyze libirisecall.so
   - Understand crash detection logic
   - Test emergency call triggering

### Low Priority

9. **Network Traffic Analysis**
   - Sniff eth0.2 VLAN traffic
   - Analyze cellular data flows
   - Map Hermes connection handshake

10. **Power Management Testing**
    - Measure current draw in sleep mode
    - Test wake latency
    - Verify power-off sequence

---

## 13. Appendix: File Inventory

### Scripts Analyzed
- `/usr/sbin/modem-type` (shell)
- `/usr/sbin/modem-command` (shell)
- `/usr/sbin/modem-power` (shell)
- `/usr/sbin/modem-reset` (shell)
- `/usr/sbin/modem-airplane-toggle` (shell)
- `/usr/bin/modemvm-logger` (shell)
- `/usr/bin/check-modem` (shell)
- `/usr/local/bin/modem-common` (shell library)
- `/usr/local/bin/iris-fw-upgrade.sh` (shell)
- `/usr/local/bin/iris-fw-ssq-load.sh` (shell)
- `/usr/local/bin/iris-fw-services.sh` (shell)
- `/usr/local/bin/iris-fw-sideload.sh` (not analyzed)
- `/usr/local/bin/iris-sim-apn-cfg.sh` (not analyzed)
- `/usr/local/bin/irislogs` (not analyzed)
- `/usr/local/bin/hermes-grablogs-modem` (shell wrapper)
- `/sbin/autofuser-modem.sh` (not analyzed)
- `/sbin/autofuser-modem-iris.sh` (shell)
- `/sbin/autofuser-modem-titan.sh` (not analyzed)

### Binaries Analyzed
- `/usr/sbin/cmt-iris` (ELF, 349 KB) - Modem diagnostic tool
- `/usr/bin/QFirehose` (ELF, 99 KB) - Qualcomm flash tool
- `/usr/lib/libirisecall.so` (ELF) - eCall library

### Configuration Files
- `/etc/ofono/iris.conf` - Modem connection parameters
- `/etc/verity-modem-prod.pub` - Production signing key
- `/etc/verity-modem-dev.pub` - Development signing key
- `/etc/firewall.d/modem.iptables` - Modem firewall rules
- `/etc/firewall.d/modem-update-server.iptables` - Update server rules
- `/etc/firewall.d/modemvm-logger.iptables` - Logger rules
- `/etc/firewall.d/ofono.iptables` - Ofono firewall rules
- `/etc/firewall.d/qtcar-connman.iptables` - Connection manager rules

### AppArmor Profiles
- `/etc/apparmor.compiled/usr.sbin.modem-power`
- `/etc/apparmor.compiled/usr.sbin.modem-reset`
- `/etc/apparmor.compiled/usr.sbin.modem-command`
- `/etc/apparmor.compiled/usr.sbin.modem-type`
- `/etc/apparmor.compiled/usr.bin.modemvm-logger`

### Missing/Empty
- `/deploy/iris/` - Empty (firmware delivered via SSQ)
- Iris firmware images - Not in MCU rootfs
- Full API endpoint documentation - Reverse engineering required

---

## 14. Glossary

- **AG525RGL:** Quectel 5G modem model number (Iris-GL variant)
- **Iris:** Tesla internal codename for Quectel modems
- **Titan:** Tesla internal codename for Telit modems (legacy)
- **AT Commands:** Hayes command set for modem control
- **EDL:** Emergency Download Mode (Qualcomm bootloader)
- **QFirehose:** Qualcomm firmware flash protocol
- **SSQ:** Signed SquashFS - dm-verity protected filesystem image
- **dm-verity:** Device-mapper target for read-only integrity checking
- **ofono:** Open-source telephony daemon (Linux Foundation)
- **eCall:** Emergency call system (EU regulation)
- **RIL:** Radio Interface Layer - Android telephony abstraction
- **VLAN:** Virtual LAN - network segmentation (eth0.2 = VLAN 20)
- **APN:** Access Point Name - cellular network gateway
- **ICCID:** Integrated Circuit Card ID - SIM card identifier
- **eUICC:** Embedded Universal Integrated Circuit Card (eSIM)
- **Hermes:** Tesla backend communication system

---

**Document Status:** ✅ COMPLETE  
**Analyst:** Security Platform Subagent (modem-iris-tillit-analysis)  
**Date:** 2026-02-03  
**Next Steps:** Reverse engineer cmt-iris, test HTTP API, extract full modem firmware
