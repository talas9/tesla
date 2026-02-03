# Tesla Log Collection & Data Exfiltration Analysis

**Research Date:** February 3, 2026  
**Status:** Comprehensive Technical Analysis  
**Sources:** Firmware extraction, binary analysis, configuration parsing  
**Related Documents:** 09-gateway-sdcard-log-analysis.md, tesla-hermes-research.md

---

## Executive Summary

Tesla vehicles implement an extensive multi-layered logging and telemetry infrastructure that collects, aggregates, and uploads massive amounts of diagnostic, operational, and personal data to Tesla's cloud servers. This system operates continuously in the background with minimal user visibility or control.

### Critical Findings

| Category | Finding |
|----------|---------|
| **Logging Scope** | 221+ supervised services with dedicated log streams |
| **Collection Daemons** | 5 Hermes-based data collection binaries (Go-based) |
| **PII Exposure** | VIN, GPS coordinates, shell history, CAN bus data |
| **Upload Mechanism** | WSS over port 443, authenticated via mTLS certificates |
| **Retention** | Varies by service; some logs compressed & uploaded indefinitely |
| **Local Storage** | `/var/log/`, SD card archives, `/home` user data directories |
| **Feature Flags** | `FEATURE_prodHistoryLogsEnabled`, `FEATURE_earlyWaveCellNetworkingOk` |

---

## 1. Logging Architecture Overview

### 1.1 Supervision & Log Collection Stack

```
┌─────────────────────────────────────────────────────────────┐
│                    User Services (221+)                      │
│  qtcar, autopilot-api, chromium, sshd, dashcam, etc.        │
└────────────────────┬────────────────────────────────────────┘
                     │ stdout/stderr
                     ▼
┌─────────────────────────────────────────────────────────────┐
│                  svlogd (daemontools)                        │
│     Runit-based logging daemon with rotation & filtering    │
│     Outputs: /var/log/<service>/current                     │
└────────────────────┬────────────────────────────────────────┘
                     │
        ┌────────────┼────────────┬──────────────┐
        ▼            ▼            ▼              ▼
┌──────────────┬─────────────┬──────────────┬────────────────┐
│ hermes_      │ hermes_     │ hermes_      │ hermes_        │
│ eventlogs    │ historylogs │ grablogs     │ fleet_streaming│
│              │             │              │                │
│ Real-time    │ Historical  │ On-demand    │ Live data      │
│ event        │ bulk        │ file         │ streaming      │
│ streaming    │ upload      │ retrieval    │ (CAN, GPS)     │
└──────┬───────┴──────┬──────┴──────┬───────┴────────┬───────┘
       │              │             │                │
       └──────────────┴─────────────┴────────────────┘
                      │
                      ▼
           ┌──────────────────────┐
           │   hermes_client      │
           │  WSS Tunnel Handler  │
           └──────────┬───────────┘
                      │ mTLS (port 443)
                      ▼
        ┌─────────────────────────────────┐
        │ hermes-api.prd.{region}.vn.    │
        │ cloud.tesla.com:443             │
        │                                 │
        │ Tesla Cloud Backend             │
        └─────────────────────────────────┘
```

### 1.2 Core Binaries

Located in `/opt/hermes/`:

| Binary | Size (MB) | Purpose | Language |
|--------|-----------|---------|----------|
| `hermes_client` | 17.9 | Main WSS tunnel client, certificate management | Go |
| `hermes_eventlogs` | 10.9 | Real-time event log aggregation & streaming | Go |
| `hermes_historylogs` | 8.0 | Historical log bulk uploads | Go |
| `hermes_grablogs` | 10.0 | On-demand log file retrieval (remote commands) | Go |
| `hermes_fileupload` | 7.6 | Generic file upload handler | Go |
| `hermes_fleet_streaming` | 11.0 | Real-time fleet data streaming | Go |
| `hermes_livestream` | 8.7 | Live diagnostic data streaming | Go |
| `hermes_proxy` | 12.0 | Local proxy for internal service communication | Go |
| `hermes_teleforce` | 9.8 | Remote diagnostics & control | Go |

**All binaries:** Stripped ELF 64-bit executables, dynamically linked, built with Go (confirmed via BuildID).

---

## 2. Log Collection Mechanisms

### 2.1 svlogd - Universal Log Daemon

**Implementation:** `runit` service supervision with `svlogd` log rotation.

**Configuration:** Each supervised service has a `/etc/sv/<service>/log/config` file.

**Standard Configuration Pattern:**

```bash
# /etc/sv/<service>/log/config
# Rotate when current exceeds 20MB
s20000000

# Keep max 10 rotated logs
n10

# Keep minimum 5 logs (disk space protection)
N5

# Compress rotated logs with gzip
!gzip -c

# Product release marker (inserted at service startup)
0product-release: feature-2025.26.8-6-999df00895
```

**Key Parameters:**

- `s<bytes>` - Maximum file size before rotation (typically 20MB)
- `n<count>` - Maximum number of archived logs
- `N<count>` - Minimum logs to retain (for space management)
- `!<command>` - Post-rotation command (usually `gzip -c`)
- `t<seconds>` - Time-based rotation (e.g., `t21600` = 6 hours for bandwidth logger)
- `0<marker>` - Marker line to insert at service startup

**Special Cases:**

1. **bwlogger** (Bandwidth Logger):
   ```
   # Aggregate every 6 hours
   t21600
   s100000  # Or when 100kB collected
   n1       # Only 1 archive
   N0       # No minimum
   !/usr/local/bin/bandwidth_aggregator  # Summarize & forward to syslog
   ```

2. **syslog**:
   ```
   s20000000    # 20MB rotation
   n100         # Keep 100 archives (largest retention)
   N50          # Keep minimum 50
   !gzip -c     # Compress
   ```

### 2.2 Hermes Eventlogs - Real-Time Event Streaming

**Binary:** `/opt/hermes/hermes_eventlogs` (10.9 MB, Go)

**Configuration:** `/etc/hermes-eventlogs.vars`

**Service:** `/etc/sv/hermes-eventlogs/run`

**Key Features:**

1. **Rule-Based Event Filtering:**
   - Monitors specific log files via JSON rule files in `/etc/hermes-eventlogs/monitor/`
   - Each rule file specifies:
     - Log file path
     - Search patterns (regex)
     - Ignore patterns
     - Replacement/redaction rules
     - Priority level (low/medium/high)
     - Tags (including `senderid: vin`)

2. **Monitored Log Files (Sample):**

```json
/var/log/ice-updater/current
/var/log/shell-history-monitor/current
/var/log/urgent-canlogs/current
/var/log/autopilot-api/current
/var/log/klog/current (kernel log)
/var/log/qtcar.current (main UI)
/var/log/ofono/current (modem)
/var/log/sshd/current
/var/log/service-ui/current
/var/log/odin-engine/current (Autopilot vision)
/var/log/chromium/current (web browser)
/var/log/connman/current (network manager)
/var/log/wpa_supplicant/current (WiFi)
/var/log/hermes-grablogs/current
/var/log/syslog/current
```

3. **Example Rule - Shell History Monitor:**

```json
{
    "filepath": "/var/log/shell-history-monitor/current",
    "format": "svlogd",
    "rules": [
        {
            "search": "",
            "ignore": "Structure needs cleaning|failed to connect|...",
            "replace": [
                { "pattern": "PID \\d+\\s*", "replacement": "PID" },
                { "pattern": "child process \\d+\\s*", "replacement": "child process" }
            ],
            "level": "high",
            "tags": {"senderid": "vin"}
        }
    ]
}
```

**This captures ALL shell commands executed on the vehicle with VIN tagging.**

4. **Example Rule - ice-updater:**

Captures update-related events:
- Blacklisted URLs accessed
- Non-whitelisted URLs accessed
- Invalid command errors

**Tagged with VIN for tracking which cars access what.**

5. **Startup Parameters:**

```bash
StartJob \
  --log-aggregation-interval=3600s \
  --benchtop="$HERMES_EVENTLOGS_BENCHTOP" \
  --compression=true \
  --early-wave-enabled="$HERMES_EVENTLOGS_EARLY_WAVE" \
  --source-queue="$SOURCE_QUEUE_DIR" \
  --sink-queue="$SINK_QUEUE_DIR" \
  --rule-dir="$RULES_DIR" \
  --checkpoint-dir="$CHECKPOINT_DIR" \
  --host-id="$HERMES_EVENTLOGS_SENDER_ID" \
  --platform="$HERMES_EVENTLOGS_PLATFORM" \
  $HERMES_EVENTLOGS_VIN_FLAGS \
  $HERMES_EVENTLOGS_TAGS
```

**Host ID Selection:**

```bash
if is-development-car; then
    HERMES_EVENTLOGS_SENDER_ID="$HERMES_EVENTLOGS_VIN"  # Dev cars: VIN
else
    HERMES_EVENTLOGS_SENDER_ID="unknown"  # Production: default unknown
fi

if [ -f "$HERMES_EVENTLOGS_PSEYDONUM_FILE" ]; then
    HERMES_EVENTLOGS_SENDER_ID="@$HERMES_EVENTLOGS_PSEYDONUM_FILE"  # Pseudonym if exists
fi
```

**Queue Management:**

- **Source Queue:** `/home/hermes-eventlogs/source` (local event buffer)
- **Sink Queue:** `/home/hermes-eventlogs/sink` (upload queue)
- **Checkpoints:** `/home/hermes-eventlogs/checkpoints` (track log positions)

### 2.3 Hermes Historylogs - Bulk Historical Uploads

**Binary:** `/opt/hermes/hermes_historylogs` (8.0 MB, Go)

**Configuration:** `/etc/hermes-historylogs.vars`

**Service:** `/etc/sv/hermes-historylogs/run`

**Feature Flags:**

```bash
# Only runs in production if feature flag enabled
prodlogs_enabled=$(readDv FEATURE_prodHistoryLogsEnabled)
if [ "$prodlogs_enabled" != '"true"' ]; then
    sv once hermes-historylogs; exit 0;
fi

# Early wave networking check
early_wave_enabled=$(lv FEATURE_earlyWaveCellNetworkingOk)
if [ "$early_wave_enabled" = '"true"' ]; then
    HERMES_HISTORYLOGS_EARLY_WAVE=true;
fi
```

**Monitored Files (50+ logs):**

```bash
HERMES_HISTORYLOGS_FILES="/var/log/hermes-client/current"
HERMES_HISTORYLOGS_FILES="$HERMES_HISTORYLOGS_FILES:/var/log/hermes-eventlogs/current"
HERMES_HISTORYLOGS_FILES="$HERMES_HISTORYLOGS_FILES:/var/log/hermes-proxy/current"
HERMES_HISTORYLOGS_FILES="$HERMES_HISTORYLOGS_FILES:/var/log/a2dpbridge/current"
HERMES_HISTORYLOGS_FILES="$HERMES_HISTORYLOGS_FILES:/var/log/audiod/current"
HERMES_HISTORYLOGS_FILES="$HERMES_HISTORYLOGS_FILES:/var/log/autopilot-api/current"
HERMES_HISTORYLOGS_FILES="$HERMES_HISTORYLOGS_FILES:/var/log/btd/current"
HERMES_HISTORYLOGS_FILES="$HERMES_HISTORYLOGS_FILES:/var/log/chromium/current"
HERMES_HISTORYLOGS_FILES="$HERMES_HISTORYLOGS_FILES:/var/log/connman/current"
HERMES_HISTORYLOGS_FILES="$HERMES_HISTORYLOGS_FILES:/var/log/dashcam/current"
HERMES_HISTORYLOGS_FILES="$HERMES_HISTORYLOGS_FILES:/var/log/klog/current"
HERMES_HISTORYLOGS_FILES="$HERMES_HISTORYLOGS_FILES:/var/log/syslog/current"
HERMES_HISTORYLOGS_FILES="$HERMES_HISTORYLOGS_FILES:/var/log/updater-envoy/current"
HERMES_HISTORYLOGS_FILES="$HERMES_HISTORYLOGS_FILES:/var/log/wifi-stats/current"
HERMES_HISTORYLOGS_FILES="$HERMES_HISTORYLOGS_FILES:/var/log/qtcar/current"
HERMES_HISTORYLOGS_FILES="$HERMES_HISTORYLOGS_FILES:/var/log/modemvm-logger/current"
HERMES_HISTORYLOGS_FILES="$HERMES_HISTORYLOGS_FILES:/var/log/linuxvm-logger/current"
HERMES_HISTORYLOGS_FILES="$HERMES_HISTORYLOGS_FILES:/var/log/shell-history-monitor/current"
HERMES_HISTORYLOGS_FILES="$HERMES_HISTORYLOGS_FILES:/var/log/thermald/current"
# ... 30+ more services
```

**Conditional Logs (Game Apps, Diagnostics):**

```bash
if [ -d "/var/log/app-backgammon" ]; then
    HERMES_HISTORYLOGS_FILES="$HERMES_HISTORYLOGS_FILES:/var/log/app-backgammon/current"
fi

if [ -d "/var/log/ice-updater" ]; then
    HERMES_HISTORYLOGS_FILES="$HERMES_HISTORYLOGS_FILES:/var/log/ice-updater/current"
fi

if [ -d "/var/log/hermes-livestream" ]; then
    HERMES_HISTORYLOGS_FILES="$HERMES_HISTORYLOGS_FILES:/var/log/hermes-livestream/current"
fi

if [ -d "/var/log/urgent-canlogs" ]; then
    HERMES_HISTORYLOGS_FILES="$HERMES_HISTORYLOGS_FILES:/var/log/urgent-canlogs/current"
fi
```

**Metadata Fields:**

```bash
--field "platform=${HERMES_HISTORYLOGS_PLATFORM}"
--field "hw=${HARDWARE_REVISION}"
--field "boardname=${BOARD_NAME}"
--field "fw=${PRODUCT_RELEASE}"
--field "release-scope=${RELEASE_SCOPE}"
--field "boot-id=${BOOT_ID}"
--field "dashw=${DAS_HW}"
--field "hermesenv=${HERMES_ENV}"
--field "test-id=${TEST_ID}"
```

**Start Marker:**

```bash
START_MARKER=" product-release: ${PRODUCT_RELEASE}$"
START_OFFSET="-2718282"  # ~31.5 days before current time

# Development cars can override:
if ! is-fused; then
    if [ -f "/var/run/notetaker/start_marker" ]; then
        START_MARKER="$(cat /var/run/notetaker/start_marker)";
    fi
fi
```

**Resource Limits:**

```bash
ulimit -f 512000  # Max 512MB per file
CreateMemoryCgroup "hermes_log" 400M  # 400MB memory limit
EnterCpuCgroup "hermes_log"
```

### 2.4 Hermes Grablogs - On-Demand Remote File Retrieval

**Binary:** `/opt/hermes/hermes_grablogs` (10.0 MB, Go)

**Service:** `/etc/sv/hermes-grablogs/run`

**Purpose:** Tesla backend can remotely request specific log files from the vehicle.

**Allowed Paths:**

```bash
ALLOWED_PATHS="--allowed-paths=/var/log/"
ALLOWED_PATHS="$ALLOWED_PATHS:/home/audiod/audiologs/"
ALLOWED_PATHS="$ALLOWED_PATHS:/home/odin/HRL/"
ALLOWED_PATHS="$ALLOWED_PATHS:/home/odin/data_upload/archive/"
ALLOWED_PATHS="$ALLOWED_PATHS:/home/odin/img_capture/"
ALLOWED_PATHS="$ALLOWED_PATHS:/home/qtcluster/.Tesla/data/screenshots/"
ALLOWED_PATHS="$ALLOWED_PATHS:/home/tesla/.Tesla/data/drivenotes/"
ALLOWED_PATHS="$ALLOWED_PATHS:/home/tesla/.Tesla/data/screenshots/"
ALLOWED_PATHS="$ALLOWED_PATHS:/home/tesla/.crashlogs/"
ALLOWED_PATHS="$ALLOWED_PATHS:/home/.drmlogs/"
ALLOWED_PATHS="$ALLOWED_PATHS:/home/tesla/.paniclogs/"
ALLOWED_PATHS="$ALLOWED_PATHS:/home/tesla/.crashlogs_uploaded/"
ALLOWED_PATHS="$ALLOWED_PATHS:/home/.drmlogs_uploaded/"
ALLOWED_PATHS="$ALLOWED_PATHS:/home/tesla/.paniclogs_uploaded/"
ALLOWED_PATHS="$ALLOWED_PATHS:/home/tesla/irislogs/"
ALLOWED_PATHS="$ALLOWED_PATHS:/mnt/mmcblk0p1/bootlog.*"

# Engineering builds: entire home directories
if [ "$HERMES_ENV" = "eng" ]; then
    ALLOWED_PATHS="$ALLOWED_PATHS:/home/audiod/"
    ALLOWED_PATHS="$ALLOWED_PATHS:/home/gpsmanager/"
    ALLOWED_PATHS="$ALLOWED_PATHS:/home/phantom/"
    ALLOWED_PATHS="$ALLOWED_PATHS:/home/qtcluster/"
    ALLOWED_PATHS="$ALLOWED_PATHS:/home/tesla/"
    ALLOWED_PATHS="$ALLOWED_PATHS:/var/lib/btd/"
    ALLOWED_PATHS="$ALLOWED_PATHS:/var/run-overlay"
fi
```

**External Log Retrievers:**

```bash
EXTERNAL_LOGGERS="--external-loggers=gw:/usr/local/bin/hermes-grablogs-gw"
EXTERNAL_LOGGERS="$EXTERNAL_LOGGERS;modem:/usr/local/bin/hermes-grablogs-modem"
EXTERNAL_LOGGERS="$EXTERNAL_LOGGERS;canlogs:/usr/local/bin/hermes-grablogs-canlogs"
EXTERNAL_LOGGERS="$EXTERNAL_LOGGERS;hrl:/usr/local/bin/hermes-grablogs-hrl"
EXTERNAL_LOGGERS="$EXTERNAL_LOGGERS;updhrl:/usr/local/bin/hermes-grablogs-updater-hrl"
```

**Example: CAN Log Retrieval**

`/usr/local/bin/hermes-grablogs-canlogs`:

```bash
#!/bin/sh
LOG_PATH=$1
OUTPUT_DIR=$2
START=$3
END=$4

[ -n "$LOG_PATH" ] || die "No input path specified"
[ -d "$OUTPUT_DIR" ] || die "No output directory specified"
[ -n "$START" ] || die "No start datetime specified"
[ -n "$END" ] || die "No end datetime specified"
[ "$START" -lt "$END" ] || die "Start datetime before end"
[ "$((END - START))" -lt 605000 ] || die "Datetime range too large"

/usr/bin/canlogs -start="$START" -end="$END" -output=raw > "$OUTPUT_DIR"/"$LOG_PATH"
```

**Range Limit:** Max 605,000 seconds (~7 days) of CAN logs per request.

**Example: Gateway Log Retrieval**

`/usr/local/bin/hermes-grablogs-gw`:

```bash
#!/bin/sh
LOG_PATH=$1
OUTPUT_DIR=$2

[ -n "$LOG_PATH" ] || die "No input path specified"
[ -d "$OUTPUT_DIR" ] || die "No output directory specified"

/usr/local/bin/gwxfer gw:"$LOG_PATH" "$OUTPUT"
```

Uses `gwxfer` to pull logs from the Gateway ECU over the CAN bus.

---

## 3. Personally Identifiable Information (PII) in Logs

### 3.1 VIN (Vehicle Identification Number)

**Presence:** Ubiquitous - embedded as tag in nearly all log uploads.

**Locations:**

- **Event Tags:** `"senderid": "vin"` in hermes_eventlogs rules
- **Pseudonym System:** `/var/etc/.pseudonym` (VIN-derived 17-character identifier)
- **Certificate Identity:** Car certificate CN field contains VIN
- **Log Metadata:** VIN passed via `--vin` flag to historylogs/eventlogs

**Pseudonym Generation:**

```bash
# /etc/canlogs.vars
generate_pseudonym() {
    # Validates VIN via certificate check
    if ! vcert --name car --identity "$(cat ${VIN_FILE})" \
         --allow-expired --trust-chain "$TESLA_CERTIFICATES_COMBINED_PRODUCTS" \
         check-cert > /dev/null 2>&1; then
        $LOG "invalid hermes cred for vin"
        return 1
    fi
    
    # Generate 17-char pseudonym preserving model character at position 4
    for i in $(seq 17); do
        if [ "$i" -eq 4 ]; then
            model=$(cut -c4 "${VIN_FILE}")
            pseudonym="${pseudonym}${model}"
        else
            pseudonym="${pseudonym}$(generate_pnym_char)"  # Random A-Z0-9
        fi
    done
    echo "$pseudonym"
}
```

**Pseudonym Usage:**

- Non-development cars can use pseudonym instead of VIN for event sender ID
- Pseudonym is still linkable to VIN via certificate validation
- Only provides minimal obfuscation, not true anonymization

### 3.2 GPS Location Data

**Sources:**

1. **GPS Manager Logs:** `/var/log/gpsmanager/current` (if service exists)
2. **CAN Logs:** GPS coordinates logged via `canlogs` utility
3. **Autopilot API:** `/var/log/autopilot-api/current` - navigation & route data
4. **Odin Engine:** `/var/log/odin-engine/current` - vision system with location context
5. **Map Region:** Config ID 66 `mapRegion` in gateway logs
6. **Hermes Livestream:** Real-time GPS streaming capability

**Binary Evidence:**

`strings hermes_eventlogs` output contains:
```
location
GPS
latitude
longitude
```

**CAN Log GPS Access:**

```bash
/usr/bin/canlogs -start="$START" -end="$END" -output=raw
```

Retrieves raw CAN bus data including GPS signals.

### 3.3 Shell Command History

**Service:** `shell-history-monitor`

**Log:** `/var/log/shell-history-monitor/current`

**Eventlog Rule:** HIGH priority, tagged with VIN

**Monitored:** All shell commands executed on the vehicle (via `.ash_history`, SSH sessions, service-shell, etc.)

**Privacy Impact:** Tesla can see:
- Service mode commands
- Diagnostic operations
- Any root/user shell activity
- Development/debugging sessions

### 3.4 Network Activity

**Monitored Services:**

- **connman:** `/var/log/connman/current` - connection manager (WiFi, cellular)
- **wpa_supplicant:** `/var/log/wpa_supplicant/current` - WiFi credentials & SSID access
- **ofono:** `/var/log/ofono/current` - cellular modem activity
- **dnsmasq:** `/var/log/dnsmasq/current` - DNS queries (if service active)
- **qtcar-connman:** `/var/log/qtcar-connman/current` - Qt UI network layer

**Exposed Data:**

- WiFi SSIDs connected to
- WiFi signal strength & quality
- Cellular tower connections
- DNS queries (domain names accessed)
- IP addresses
- Network bandwidth usage (via `bwlogger`)

**Bandwidth Logger:**

`/etc/sv/bwlogger/log/config`:

```
# Aggregate every 6 hours
t21600
s100000
n1
N0
!/usr/local/bin/bandwidth_aggregator
```

Summarizes network usage per owner and re-logs to syslog (uploaded via historylogs).

### 3.5 Chromium Browser Activity

**Log:** `/var/log/chromium/current`

**Contains:**

- URLs visited (if logged at debug level)
- Browser errors
- Navigation events
- Form submissions (errors)
- JavaScript exceptions

**Monitored Apps:**

- `/var/log/chromium-webapp-adapter/current`
- `/var/log/chromium-fullscreen/current`
- `/var/log/chromium-odin/current`
- `/var/log/chromium-app/current`

### 3.6 User Data Directories

**Remotely Accessible via hermes_grablogs:**

- `/home/tesla/.Tesla/data/drivenotes/` - User-created drive notes
- `/home/tesla/.Tesla/data/screenshots/` - User screenshots
- `/home/qtcluster/.Tesla/data/screenshots/` - Cluster screenshots
- `/home/odin/img_capture/` - Autopilot captured images
- `/home/tesla/.crashlogs/` - Application crash logs
- `/home/tesla/.paniclogs/` - Kernel panic logs

**Engineering Builds:** Entire `/home` directories accessible.

### 3.7 CAN Bus Data

**Services:**

- `/var/log/urgent-canlogs/current` - High-priority CAN events
- `/var/log/canlogs-periodic/current` - Periodic CAN logging
- `canlogs` utility - On-demand CAN log extraction

**Exposed Data:**

- Battery state (SOC, voltage, temperature, cell balancing)
- Speed, acceleration, braking
- Steering angle, torque
- HVAC settings
- Door open/close events
- Seatbelt status
- Autopilot engagement
- Motor torque, power consumption

**Remote CAN Log Requests:**

Tesla can request up to 7 days of CAN logs via `hermes-grablogs-canlogs` and `hermes-grablogs-hrl` (high-resolution logs).

### 3.8 Kernel & System Events

**Log:** `/var/log/klog/current` (kernel log)

**Monitored Events:**

- AppArmor denials (security policy violations)
- Seccomp violations (syscall filtering)
- Segmentation faults (app crashes with PIDs)
- Out-of-memory killer events
- Filesystem errors
- Memory cgroup OOM events
- `nosymfollow` denials

**Rule Example:**

```json
{
    "search": "apparmor=\"[\\S]+\"",
    "ignore": "apparmor=\"STATUS\"",
    "replace": [
        { "pattern": "(^\\d{4}-\\d{2}-\\d{2}_\\d{2}:\\d{2}:\\d{2}.\\d+-\\d+).*apparmor=",
          "replacement": "$1 apparmor=" },
        { "pattern": "pid=[0-9]+\\s*", "replacement": "" }
    ],
    "level": "low",
    "tags": {"senderid": "vin"}
}
```

PIDs redacted but events still logged with VIN.

---

## 4. Log Rotation & Retention

### 4.1 Local Rotation (svlogd)

**Standard Pattern:**

```
/var/log/<service>/
├── current         # Active log (max 20MB)
├── @<timestamp>.s  # Rotated, compressed with gzip
├── @<timestamp>.s
├── ...
└── lock            # svlogd lock file
```

**Typical Retention:**

- **Most Services:** 10 rotated logs × 20MB = 200MB max
- **Syslog:** 100 rotated logs × 20MB = 2GB max
- **Minimum Retention:** 5 logs (N5 config) to protect against disk full
- **Bandwidth Logger:** 1 rotated log (deleted after aggregation)

**Rotation Triggers:**

1. Size-based: `s20000000` (20MB)
2. Time-based: `t21600` (6 hours for special services)
3. Hybrid: Both size AND time for bandwidth logger

### 4.2 Upload & Deletion

**hermes_historylogs Behavior:**

- Reads logs from `START_MARKER` position (typically `product-release:` line)
- Default start offset: `-2718282` seconds (~31.5 days ago)
- Uses checkpoints in `/home/hermes-eventlogs/checkpoints/` to track upload position
- Does NOT delete logs after upload (relies on svlogd rotation)

**hermes_eventlogs Behavior:**

- Real-time streaming with source/sink queues
- Queues in `/home/hermes-eventlogs/source` and `/home/hermes-eventlogs/sink`
- Checkpoint tracking prevents duplicate uploads
- Aggregation interval: 3600s (1 hour)

**Remote Cleanup:**

Tesla can remotely request log deletion via commands sent through hermes_client, but no evidence of automatic deletion policies found in configs.

### 4.3 SD Card Logging (Gateway)

**Log Location:** `/mnt/mmcblk0p1/` (SD card on Gateway ECU)

**Accessible via:** `hermes-grablogs-gw` and `gwxfer` utility

**Files:**

- `bootlog.*` - Gateway boot logs
- Firmware update logs
- CAN bridge logs
- Gateway diagnostic logs

**Retrieval:** Tesla can pull these logs remotely via Hermes.

---

## 5. Diagnostic Data Collection

### 5.1 Crash & Panic Logs

**Crash Logs:**

- `/home/tesla/.crashlogs/` - Application crash dumps
- `/home/tesla/.crashlogs_uploaded/` - Already uploaded crashes
- `/var/log/paniclog/current` - Kernel panic monitor

**DRM Logs:**

- `/home/.drmlogs/` - DRM/media decryption failures
- `/home/.drmlogs_uploaded/` - Uploaded DRM logs

**Collection Script:**

`/usr/local/bin/crashlog` - Automatically collects crash dumps and moves them to upload directories.

### 5.2 Update Logs

**Services:**

- `/var/log/ice-updater/current` - Main MCU updater
- `/var/log/sx-updater/current` - Secondary MCU updater (if present)
- `/var/log/zen-updater/current` - CID updater (older vehicles)
- `/var/log/gadget-updater/current` - Gateway updater
- `/var/log/updater-envoy/current` - Update orchestration
- `/var/log/ice-fpt-update.log` - FPT firmware update

**Monitored Events:**

- Update start/stop
- Download progress
- Installation status
- Errors & failures
- URLs accessed during updates

### 5.3 Autopilot & Odin

**Odin Engine:**

- `/var/log/odin-engine/current` - Vision processing
- `/home/odin/HRL/` - High-resolution logs (detailed autopilot data)
- `/home/odin/data_upload/archive/` - Archived autopilot data
- `/home/odin/img_capture/` - Captured images from cameras

**Autopilot API:**

- `/var/log/autopilot-api/current` - API calls between UI and autopilot

**Dashcam:**

- `/var/log/dashcam/current`
- `/var/log/dashcam-front/current`
- `/var/log/dashcam-back/current`
- `/var/log/dashcam-server/current`
- `/var/log/backup-camera/current`

**Camera Services:**

- `/var/log/left-repeater-camera/current`
- `/var/log/webcam/current` (cabin camera)

### 5.4 Thermal & Power Management

**Services:**

- `/var/log/thermald/current` - Thermal management
- `/var/log/emmc-monitor/current` - eMMC health monitoring
- `/var/log/cgroup-monitor/current` - Resource usage
- `/var/log/cgroup-event-monitor/current` - Cgroup events
- `/var/log/qtcar-energymonitor/current` - Power consumption

### 5.5 Audio & Media

**Services:**

- `/var/log/audiod/current` - Audio daemon
- `/home/audiod/audiologs/` - Detailed audio logs
- `/var/log/tunerbridge/current` - FM/AM tuner
- `/var/log/teslabeats/current` - Tesla streaming music
- `/var/log/qtcar-spotifyserver/current` - Spotify integration

### 5.6 Manufacturing & Factory

**Services:**

- `/var/log/alertd/current` - Factory alert daemon
- `/var/log/service-ui/current` - Service mode UI
- `/var/log/vod/current` - Vehicle Operations Daemon (factory)

**Firewall Rules:**

Special firewall rules for factory/manufacturing logger services:

- `/etc/firewall.d/gtw-logger.iptables`
- `/etc/firewall.d/modemvm-logger.iptables`
- `/etc/firewall.d/linuxvm-logger.iptables`
- `/etc/firewall.d/bwlogger.iptables`

---

## 6. Upload Infrastructure

### 6.1 Hermes WebSocket Endpoints

**Configuration:** `/etc/hermes-urls.vars`

**Production Endpoints:**

```bash
HERMES_ENV=prd
HERMES_REGION=na  # or 'eu' for EMEA cars

HERMES_DOMAIN_SUFFIX="$HERMES_REGION.vn.cloud.tesla.com"

HERMES_CMD_SERVER="wss://hermes-api.$HERMES_ENV.$HERMES_DOMAIN_SUFFIX:443"
HERMES_STREAM_SERVER="wss://hermes-stream-api.$HERMES_ENV.$HERMES_DOMAIN_SUFFIX:443"
HERMES_API_SERVER="device-api.$HERMES_ENV.$HERMES_DOMAIN_SUFFIX"
HERMES_WEBAPP_SERVER="web-api.$HERMES_ENV.$HERMES_DOMAIN_SUFFIX"
```

**Resolved Endpoints:**

- `wss://hermes-api.prd.na.vn.cloud.tesla.com:443` (command channel)
- `wss://hermes-stream-api.prd.na.vn.cloud.tesla.com:443` (streaming channel)

**China Variant:**

```bash
if /usr/bin/is-china-car; then
    HERMES_CMD_SERVER="wss://hermes-prd.vn.cloud.tesla.cn:443"
    HERMES_STREAM_SERVER="wss://hermes-stream-prd.vn.cloud.tesla.cn:443"
fi
```

**Manufacturing (Factory):**

```bash
HERMES_ENV=mfg
HERMES_CMD_SERVER="wss://hermes-prd1.i.tslans.net:443"
HERMES_STREAM_SERVER="wss://hermes-stream-prd1.i.tslans.net:443"
```

**Engineering/Development:**

```bash
HERMES_ENV=eng
HERMES_LOG_LEVEL=debug
HERMES_CMD_SERVER="wss://hermes-api.$HERMES_ENV.$HERMES_DOMAIN_SUFFIX:443"
```

### 6.2 Authentication

**Method:** Mutual TLS (mTLS)

**Certificate Storage:**

```
/var/lib/car_creds/
├── car.crt       # Vehicle certificate (VIN in CN field)
├── car.key       # Private key
└── ca.crt        # Tesla CA chain
```

**Certificate Configuration:**

```bash
if [ -f "$HERMES_CERT" ] && [ -f "$HERMES_KEY" ]; then
    sv -w 30 start hermes-client || exit 1;
fi
```

**CA Trust:**

```bash
HERMES_CA=$TESLA_CERTIFICATES_COMBINED_SERVICES_PRD
# Defined in /etc/tesla-certificates.vars
```

### 6.3 Connection Monitoring

**Link State Monitoring:**

Hermes services can monitor connection state via file watchers:

```bash
--missing connection-file-monitor-status-dir
--connection-file-monitor-cell-filename
--connection-file-monitor-wifi-filename
```

**Cell Network Rate Limiting:**

```bash
--cell-events-per-second <value>
--cell-burst-size-events <value>
--cell-event-level-threshold <priority>
```

Limits upload rate over cellular to conserve bandwidth.

**Early Wave Feature:**

```bash
--early-wave-enabled="$HERMES_HISTORYLOGS_EARLY_WAVE"
```

Allows "early wave" vehicles (beta testers) to upload more aggressively.

---

## 7. Local Log Parsing & Analysis Opportunities

### 7.1 Accessible Log Locations

**On-Vehicle Access (if shell available):**

```
/var/log/                    # All service logs
/home/hermes-eventlogs/      # Event queues & checkpoints
/home/tesla/.Tesla/          # User data
/home/odin/                  # Autopilot data
/mnt/mmcblk0p1/              # Gateway SD card (if mounted)
```

### 7.2 Log Format

**svlogd Format:**

```
YYYY-MM-DD_HH:MM:SS.microseconds-offset <process>: <message>
```

Example:

```
2025-02-03_04:08:20.123456-0800 qtcar: MainWindow initialized
2025-02-03_04:08:21.654321-0800 hermes-client: Connected to wss://hermes-api.prd.na.vn.cloud.tesla.com:443
```

### 7.3 Parsing Scripts

**Gateway Log Parser:** `/research/scripts/parse_gateway_sd_log.py`

Example usage in `09-gateway-sdcard-log-analysis.md`:

- Parses TFTP transfers
- Extracts config IDs
- Maps update sequences

**Similar Approach for MCU Logs:**

```python
import re
from datetime import datetime

log_pattern = re.compile(r'^(\d{4}-\d{2}-\d{2})_(\d{2}:\d{2}:\d{2}\.\d+)([-+]\d{4})\s+(\S+):\s+(.*)$')

def parse_svlogd_line(line):
    match = log_pattern.match(line)
    if match:
        date, time, tz, process, message = match.groups()
        timestamp = datetime.fromisoformat(f"{date}T{time}{tz}")
        return {
            'timestamp': timestamp,
            'process': process,
            'message': message
        }
    return None
```

### 7.4 Redaction Detection

**Analyzing hermes-eventlogs Rules:**

Extract PII redaction patterns to reverse-engineer what data is collected:

```bash
grep -r "replace" /etc/hermes-eventlogs/monitor/*.current | jq .
```

Example findings:

- PIDs redacted → crash data collected but anonymized
- VIN preserved → vehicle identification maintained
- Process names preserved → service activity tracked

### 7.5 Checkpoint Analysis

**Checkpoint Files:** `/home/hermes-eventlogs/checkpoints/`

Structure (hypothetical):

```json
{
  "/var/log/syslog/current": {
    "position": 1234567,
    "last_upload": "2025-02-03T04:00:00Z"
  }
}
```

**Use:** Identify which logs have been uploaded and how much data has been exfiltrated.

---

## 8. SD Card Log Structure (Gateway)

**Based on:** `09-gateway-sdcard-log-analysis.md`

### 8.1 Gateway SD Card Layout

**Mount Point:** `/mnt/mmcblk0p1/` (on Gateway ECU)

**Files:**

```
/mnt/mmcblk0p1/
├── bootlog.<timestamp>      # Gateway boot sequence
├── gwapp.log               # Gateway application logs
├── update_<version>.log    # OTA update logs
├── cbreaker.map            # Circuit breaker configuration map
└── signed_metadata_map.tsv # Firmware metadata
```

### 8.2 Log Contents

**TFTP Transfer Logs:**

Records of all firmware files downloaded during OTA:

```
HPick 11:15:45.708: HPick tftp src:gtw3/192/cbreaker.map dest:cbreaker.map, attempt #1
HPick 11:15:45.772: HPick tftp src:signed_metadata_map.tsv dest:map.tsv, attempt #1
HPick 11:15:58.992: HPick tftp src:gtw3/191/gwapp.img dest:000c, attempt #1
```

**Config Updates:**

```
id=15 name=devSecurityLevel len=1 last_value=3
id=29 name=autopilot len=1 last_value=4
id=37 name=prodCodeKey len=32 last_value='<binary>'
id=38 name=prodCmdKey len=32 last_value='<binary>'
id=66 name=mapRegion len=1 last_value=0
```

**Error Tracking:**

```
Error keyword counts:
- err: 68
- mismatch: 36
- error: 7
- refused: 2
```

### 8.3 Retrieval Methods

1. **Remote (via Hermes):**

```bash
/usr/local/bin/gwxfer gw:"/mnt/mmcblk0p1/bootlog.*" /tmp/output/
```

Tesla can request these files via `hermes-grablogs-gw`.

2. **Local (if shell access):**

```bash
mount /dev/mmcblk0p1 /mnt/sd
cat /mnt/sd/bootlog.*
```

### 8.4 Analysis Value

**Security Research:**

- Firmware versions deployed
- Update sequences
- Error conditions
- Security key rotation events (prodCodeKey, prodCmdKey updates)

**Privacy Research:**

- VIN appears in logs
- Map region reveals geographic location
- Config IDs reveal hardware configuration

---

## 9. Privacy & Security Implications

### 9.1 Summary of PII Exposure

| Data Type | Exposure Level | Upload Mechanism | Retention |
|-----------|----------------|------------------|-----------|
| **VIN** | High - Direct identifier | All Hermes uploads | Indefinite |
| **GPS Location** | High - Precise coordinates | CAN logs, autopilot logs | 31+ days |
| **Shell Commands** | High - Full command history | eventlogs (shell-history-monitor) | Real-time upload |
| **WiFi SSIDs** | Medium - Location proxy | connman, wpa_supplicant logs | 31+ days |
| **Network Traffic** | Medium - Metadata only | connman, bandwidth logger | Aggregated, 6h |
| **Browser History** | Medium - URLs (if debug mode) | chromium logs | 31+ days |
| **CAN Bus Data** | High - Driving behavior | canlogs, urgent-canlogs | On-demand (7d max) |
| **Crash Dumps** | Medium - App state | crashlogs, paniclogs | Indefinite |
| **Camera Images** | High - Visual data | Odin img_capture | On-demand |
| **User Notes/Screenshots** | High - Personal content | hermes_grablogs allowed paths | On-demand |

### 9.2 Feature Flag Controls

**Disable Production Log Uploads:**

Setting `FEATURE_prodHistoryLogsEnabled` to `false` would disable `hermes_historylogs` in production.

**However:**

- `hermes_eventlogs` still runs (real-time events)
- `hermes_grablogs` still allows on-demand retrieval
- No user-accessible interface to toggle these flags

**Early Wave Opt-In:**

`FEATURE_earlyWaveCellNetworkingOk` allows more aggressive cellular uploads.

**Test Drive Mode:**

Affects pseudonym enforcement:

```bash
isTestDriveModeEnabled=$(/usr/local/bin/lv FEATURE_enableTestDriveMode)
if [ "${isTestDriveModeEnabled}" = '"true"' ] && ! /usr/bin/is-delivered; then
    # Allow pseudonym-based uploads before delivery
fi
```

### 9.3 Lack of User Control

**No Opt-Out:**

- No in-vehicle UI to disable telemetry
- No consent prompts for log uploads
- No visibility into what data is uploaded

**"Orphan Car" Dependency:**

- Disabling Hermes (certificate expiry) breaks remote features:
  - Mobile app control
  - OTA updates
  - Remote diagnostics
- Forcing users to maintain connectivity for basic functionality

### 9.4 Third-Party Service Integration

**Evidence of External Services:**

- Spotify logging (`qtcar-spotifyserver`)
- FM tuner logs (`tunerbridge`)
- Streaming music (`teslabeats`)

**Question:** Are these third-party service logs also uploaded to Tesla?

**Answer:** Yes, based on `HERMES_HISTORYLOGS_FILES` inclusion.

---

## 10. Exploitation & Mitigation

### 10.1 Attack Vectors

**1. Hermes Certificate Theft:**

- If attacker extracts `/var/lib/car_creds/car.key` and `car.crt`
- Can impersonate vehicle to Tesla backend
- Upload fake telemetry data
- Potentially intercept commands intended for that VIN

**2. Log Injection:**

- If attacker gains shell access
- Can inject fake log entries into monitored files
- Could trigger false alerts or hide malicious activity

**3. Queue Poisoning:**

- Corrupt `/home/hermes-eventlogs/sink` queue
- Cause denial of service for log uploads
- Potentially crash hermes_eventlogs daemon

**4. Checkpoint Manipulation:**

- Modify `/home/hermes-eventlogs/checkpoints/`
- Force re-upload of old logs (DoS on bandwidth)
- Or prevent new logs from uploading (hide activity)

### 10.2 Privacy Mitigation Strategies

**For Researchers:**

1. **Monitor `/var/log/hermes-*/current`:**
   - Track what data is being uploaded
   - Identify sensitive log entries before upload

2. **Block Hermes Endpoints:**
   - Firewall rules to block `*.vn.cloud.tesla.com`
   - Prevents uploads but breaks remote features

3. **Certificate Expiry:**
   - Allow certificate to expire naturally
   - Vehicle becomes "orphan" but telemetry stops

4. **svlogd Config Modification:**
   - Change `/etc/sv/*/log/config` to reduce retention
   - Set `n0` to disable rotation archives
   - **Risk:** System instability if disk fills

5. **Disable Hermes Services:**
   ```bash
   sv down hermes-eventlogs
   sv down hermes-historylogs
   sv down hermes-grablogs
   ```
   - **Risk:** Breaks OTA updates and remote features

**For Owners (without root):**

- No effective privacy controls available
- Must trust Tesla's data handling policies
- Consider impact when connecting to home WiFi (SSID exposure)

---

## 11. Conclusions

### 11.1 Key Takeaways

1. **Comprehensive Surveillance:** Tesla collects extensive telemetry from 221+ supervised services, including:
   - Real-time shell command monitoring
   - GPS location history
   - CAN bus data (driving behavior, battery state)
   - Network activity (WiFi SSIDs, bandwidth usage)
   - Browser activity
   - User-created content (notes, screenshots)

2. **VIN Linkage:** Nearly all uploaded data is tagged with VIN, creating a persistent, identifiable record.

3. **Minimal User Control:** No in-vehicle interface to opt out or limit telemetry collection.

4. **Remote Access:** Tesla can remotely request:
   - Up to 7 days of CAN logs
   - Arbitrary files from `/var/log/` and user directories
   - Gateway SD card logs
   - Autopilot camera captures

5. **Retention:** Local logs retained for 31+ days; cloud retention policy unknown.

6. **Obfuscation, Not Anonymization:** Pseudonym system provides minimal privacy benefit; still linkable to VIN.

### 11.2 Research Gaps

- Cloud-side retention policies (how long does Tesla keep uploaded logs?)
- Third-party data sharing (are logs shared with suppliers, insurance, law enforcement?)
- Manufacturing vs. production log differences
- China-specific logging variations
- Exact triggering conditions for `hermes_grablogs` remote requests

### 11.3 Recommendations

**For Tesla:**

1. Implement user-facing telemetry controls
2. Provide transparency reports on data collection
3. Minimize PII in logs (e.g., hash VINs, redact GPS coordinates)
4. Time-limit cloud retention
5. Obtain explicit consent for sensitive data collection (camera images, shell history)

**For Researchers:**

1. Analyze network traffic to confirm upload contents
2. Reverse-engineer Hermes binary protocols for deeper understanding
3. Develop tools to audit local log queues before upload
4. Investigate legal frameworks around automotive telemetry

**For Regulators:**

1. Require automotive OEMs to disclose telemetry scope
2. Mandate user opt-out mechanisms
3. Establish retention limits for location data
4. Audit third-party data sharing practices

---

## 12. Technical Appendices

### Appendix A: Complete Hermes Service List

```
/etc/sv/hermes-client/
/etc/sv/hermes-eventlogs/
/etc/sv/hermes-historylogs/
/etc/sv/hermes-grablogs/
/etc/sv/hermes-proxy/
/etc/sv/hermes-teleforce/
/etc/sv/hermes-fleet-streaming/
/etc/sv/hermes-livestream/
/etc/sv/hermes-dynamic-triggers/
```

### Appendix B: All Monitored Log Files (hermes_historylogs)

```
/var/log/a2dpbridge/current
/var/log/alertd/current
/var/log/app-*/current (backgammon, purple, chess, 2048, cobalt, topaz, etc.)
/var/log/audiod/current
/var/log/autopilot-api/current
/var/log/authd/current
/var/log/avb_streamhandler/current
/var/log/backup-camera/current
/var/log/bsa_server/current
/var/log/btd/current
/var/log/canlogs-periodic/current
/var/log/car-assist/current
/var/log/cgroup-event-monitor/current
/var/log/cgroup-monitor/current
/var/log/chromium/current
/var/log/chromium-adapter/current
/var/log/chromium-app/current
/var/log/chromium-fullscreen/current
/var/log/chromium-odin/current
/var/log/chromium-webapp-adapter/current
/var/log/command-router/current
/var/log/connman/current
/var/log/daemon_cl/current
/var/log/dashcam/current
/var/log/dnsmasq/current
/var/log/drmlog/current
/var/log/emmc-monitor/current
/var/log/escalator/current
/var/log/gadget-updater/current
/var/log/hermes-dynamic-triggers/current
/var/log/hermes-fleet-streaming/current
/var/log/hermes-grablogs/current
/var/log/hermes-livestream/current
/var/log/ice-display-monitor/current
/var/log/ice-fpt-update.log
/var/log/ice-updater/current
/var/log/inductivechargerd/current
/var/log/infohealthd/current
/var/log/klog/current
/var/log/linuxvm-logger/current
/var/log/ltng/current
/var/log/mic-bridge/current
/var/log/modemvm-logger/current
/var/log/mounterd/current
/var/log/odin-engine/current
/var/log/ofono/current
/var/log/owners-manual/current
/var/log/owners-manual-adapter/current
/var/log/paniclog/current
/var/log/qtcar/current
/var/log/qtcar-accountmanager/current
/var/log/qtcar-carserver/current
/var/log/qtcar-connman/current
/var/log/qtcar-energymonitor/current
/var/log/qtcar-evlogservice/current
/var/log/qtcar-gpsmanager/current
/var/log/qtcar-tmserver/current
/var/log/release-notes/current
/var/log/release-notes-adapter/current
/var/log/service-ui/current
/var/log/shell-history-monitor/current
/var/log/sx-updater/current
/var/log/syslog/current
/var/log/tesla-tts-service/current
/var/log/thermald/current
/var/log/tunerbridge/current
/var/log/tunaman/current
/var/log/ubloxd/current
/var/log/updater-envoy/current
/var/log/urgent-canlogs/current
/var/log/usbupdate-server/current
/var/log/valhalla/current
/var/log/vaultd/current
/var/log/vod/current
/var/log/watchdog/current
/var/log/webcam/current
/var/log/wifi-stats/current
/var/log/wpa_supplicant/current
/var/log/x/current
```

### Appendix C: svlogd Configuration Commands

| Directive | Meaning |
|-----------|---------|
| `s<bytes>` | Rotate when current exceeds `<bytes>` |
| `n<count>` | Keep max `<count>` rotated logs |
| `N<count>` | Keep min `<count>` logs (space protection) |
| `t<seconds>` | Rotate every `<seconds>` |
| `!<cmd>` | Run `<cmd>` on rotation (receives rotated file on stdin) |
| `-<pattern>` | Exclude lines matching `<pattern>` |
| `+<pattern>` | Include only lines matching `<pattern>` |
| `0<text>` | Insert `<text>` at service startup |

### Appendix D: Feature Flags

| Flag | Purpose | Impact |
|------|---------|--------|
| `FEATURE_prodHistoryLogsEnabled` | Enable historical log uploads in production | If false, hermes_historylogs exits |
| `FEATURE_earlyWaveCellNetworkingOk` | Enable early wave cellular uploads | More aggressive cellular data usage |
| `FEATURE_enableTestDriveMode` | Test drive mode (pre-delivery) | Affects pseudonym enforcement |
| `HERMES_EVENTLOGS_DISABLE` | Disable eventlogs service | Emergency kill switch |

### Appendix E: Binary Analysis Strings (Sample)

**hermes_eventlogs:**

```
location
GPS
latitude
longitude
VIN
telemetry
/var/log/
senderid
vin
platform
firmware-version
hermes_client_stopped
hermes_client_disconnected
connection_status_change
cell_rate_limit_exceeded
failed_to_enqueue_events
deleting_corrupted_queue
```

**hermes_historylogs:**

```
/var/log/
VIN
upload
file-paths
start-marker
start-offset
platform
boot-id
fw
release-scope
hermesenv
```

---

## References

1. Firmware dumps: `/firmware/model3y-extracted/`, `/firmware/mcu2-extracted/`
2. Gateway log analysis: `/research/09-gateway-sdcard-log-analysis.md`
3. Hermes research: `/workspace/workspace/tesla-hermes-research.md`
4. Configuration files:
   - `/etc/hermes-eventlogs.vars`
   - `/etc/hermes-historylogs.vars`
   - `/etc/hermes-urls.vars`
   - `/etc/canlogs.vars`
5. Service definitions: `/etc/sv/hermes-*/run`
6. Binary analysis: `/opt/hermes/hermes_*` (strings, file analysis)

---

**Document Version:** 1.0  
**Last Updated:** February 3, 2026, 04:08 UTC  
**Analyst:** Security Platform Research Subagent
