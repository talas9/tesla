# APE Services Documentation

## Overview

Tesla's Autopilot Compute (APE) runs a Linux-based operating system with 62 runit-managed services located in `/etc/sv/`. This document catalogs all services discovered in the APE firmware extraction.

## Service Inventory

Total services found: **62 services**

### Critical Core Services

#### 1. **autopilot** (Main Autopilot Stack)
- **Location:** `/etc/sv/autopilot/`
- **Command:** Complex launch script (`/etc/sv/autopilot/run`)
- **Purpose:** Primary autopilot orchestrator that launches all vision, planning, and control tasks
- **Dependencies:** 
  - Camera buffer initialization (IBQ)
  - Vehicle configuration detection
  - GPU initialization (Pascal on HW2)
  - Temperature monitoring
- **Key Components:**
  - Vision task (neural network inference)
  - Perception, localization, road estimation
  - Mission planner, behaviors (stay-in-lane, lane-change, parking)
  - Controller, arbiter, state machine
  - Driver monitoring, UI server
- **Boot Sequence:**
  - Checks for bootloop conditions (panic reboots, watchdog triggers)
  - Sets CPU governors to "performance" (max frequency)
  - Initializes GPU driver
  - Waits for camera IBQ initialization (60s timeout)
  - Spawns all autopilot tasks in dependency order
- **Environment:**
  - Real-time CPU priority configuration
  - Interrupt affinity tuning via `/sbin/configure-interrupts`
  - Memory and stack limits via `chpst`

#### 2. **hermes** (Tesla Cloud Communication)
- **Location:** `/etc/sv/hermes/`
- **Command:** `/opt/hermes/hermes` with TLS credentials
- **Purpose:** WebSocket connection to Tesla's cloud (command/telemetry)
- **Dependencies:** Board credentials (`/var/lib/board_creds/board.{key,crt}`)
- **Configuration:** `/etc/hermes.vars`
  - Development: `wss://hermes-eng.ap.tesla.services:8443`
  - Production: `wss://hermes-prd.ap.tesla.services:8443`
  - China: `wss://hermes-x2-api.prd.vn.cloud.tesla.cn:8443`
  - Stream server: `wss://telemetry-prd.ap.tesla.services:8443`
- **Arguments:**
  - `-ca`: CA certificate for TLS validation
  - `-cert`/`-key`: Board authentication credentials
  - `-socket-path=/var/ipc/hermes.sock`: Local IPC socket (Unix packet mode)
  - `--stream-message-buffer-size=1000`
  - `--engine=fsdtpm`: TPM engine for key operations
- **User/Group:** `hermes:hermes:autopilot:ipc:telemetry:credentials:tpm`
- **Boot Delay:** 30 seconds if credentials missing

#### 3. **service-api** (Local REST API)
- **Location:** `/etc/sv/service-api/`
- **Command:** `/usr/bin/service_api`
- **Purpose:** HTTP API for vehicle configuration and diagnostics
- **Rate Limiting:** 10 requests/sec, max burst 10 (outside factory)
- **Arguments:** `--build-date` from `/etc/build-date`

#### 4. **service-api-tls** (Secure API Endpoint)
- **Location:** `/etc/sv/service-api-tls/`
- **Purpose:** TLS-wrapped version of service-api
- **Firewall Rule:** Port 8081 (allowed from eth0)

### Vision & Perception Services

#### 5. **camera**
- **Location:** `/etc/sv/camera/`
- **Purpose:** Camera buffer server (IBQ - Inter-Buffer Queue)
- **Dependencies:** None (must start early)
- **Critical:** Other services wait for `/dev/shm/ibq_init_done` before starting
- **Early Start:** Model 3/Y HW3.0A starts before config detection

#### 6. **backup-camera**
- **Location:** `/etc/sv/backup-camera/`
- **Purpose:** Rear camera for reversing

#### 7. **vision**
- **Location:** `/etc/sv/vision/`
- **Purpose:** Neural network inference on camera feeds
- **Dependencies:** Camera IBQ, GPU initialization
- **Not Started:** Calibration mode, benchtop replay boards

#### 8. **perception**
- **Location:** `/etc/sv/perception/`
- **Purpose:** Object detection and tracking from vision outputs

#### 9. **driver-monitor**
- **Location:** `/etc/sv/driver-monitor/`
- **Purpose:** Cabin camera driver attention monitoring

### CAN Bus Services

#### 10. **cantx** (CAN Transmit)
- **Location:** `/etc/sv/cantx/`
- **Purpose:** Sends CAN messages to vehicle network
- **Early Start:** Model 3/Y HW3.0A (for backup camera liveness)
- **Port Mapping:** UDP port for CAN forwarding

#### 11. **canrx** (CAN Receive)
- **Location:** `/etc/sv/canrx/`
- **Purpose:** Receives CAN messages from vehicle
- **Critical:** Required for sleep command detection
- **Firewall Rule:** UDP port 27694 (only from LB 192.168.90.104)

### Localization & Sensors

#### 12. **gps**
- **Location:** `/etc/sv/gps/`
- **Purpose:** GPS receiver for location services
- **Early Start:** Required by other tasks during init
- **Always Running:** Even during consecutive fail reboots

#### 13. **imu**
- **Location:** `/etc/sv/imu/`
- **Purpose:** Inertial Measurement Unit data processing

#### 14. **inertiator**
- **Location:** `/etc/sv/inertiator/`
- **Purpose:** Sensor fusion for motion estimation

#### 15. **localizer**
- **Location:** `/etc/sv/localizer/`
- **Purpose:** Vehicle position estimation (GPS + dead reckoning)

### Planning & Behavior Services

#### 16. **mission-planner**
- **Location:** `/etc/sv/mission-planner/`
- **Purpose:** High-level route planning

#### 17. **stay-in-lane**
- **Location:** `/etc/sv/stay-in-lane/`
- **Purpose:** Lane-keeping behavior

#### 18. **lane-change**
- **Location:** `/etc/sv/lane-change/`
- **Purpose:** Lane change decision and execution

#### 19. **parking-behavior**
- **Location:** `/etc/sv/parking-behavior/`
- **Purpose:** Parking maneuvers (Summon, Autopark)

#### 20. **arbiter**
- **Location:** `/etc/sv/arbiter/`
- **Purpose:** Behavior arbitration (which planner has control)

#### 21. **controller**
- **Location:** `/etc/sv/controller/`
- **Purpose:** Low-level steering/throttle/brake commands

#### 22. **autopilot-state-machine**
- **Location:** `/etc/sv/autopilot-state-machine/`
- **Purpose:** Autopilot engagement state management

### Safety & Monitoring Services

#### 23. **active-safety**
- **Location:** `/etc/sv/active-safety/`
- **Purpose:** Emergency braking, collision avoidance

#### 24. **watchdog**
- **Location:** `/etc/sv/watchdog/`
- **Purpose:** Monitors autopilot tasks, triggers reboot on hang
- **Bootloop Protection:** Increments `/autopilot/watchdog-system-reboots`
- **Not Started:** Calibration mode, benchtop replay

#### 25. **hw-monitor**
- **Location:** `/etc/sv/hw-monitor/`
- **Purpose:** Hardware health checks (PCIe AER errors)

#### 26. **temperature-monitor**
- **Location:** `/etc/sv/temperature-monitor/`
- **Purpose:** Board temperature monitoring and thermal throttling

#### 27. **fanctrl**
- **Location:** `/etc/sv/fanctrl/`
- **Purpose:** Cooling fan control

### Telemetry & Logging Services

#### 28. **telemetry**
- **Location:** `/etc/sv/telemetry/`
- **Purpose:** Real-time telemetry streaming to Tesla cloud

#### 29. **telemetry-packager**
- **Location:** `/etc/sv/telemetry-packager/`
- **Purpose:** Prepares telemetry data for upload

#### 30. **snapshot**
- **Location:** `/etc/sv/snapshot/`
- **Purpose:** Captures system snapshots for debugging
- **Triggered By:**
  - Vehicle config timeout
  - IBQ init timeout
  - Git commit changes
  - Bootloop conditions

#### 31. **snapshot-trigger-client**
- **Location:** `/etc/sv/snapshot-trigger-client/`
- **Purpose:** Client for remote snapshot requests
- **Not Started:** HW3.0B

#### 32. **text-log**
- **Location:** `/etc/sv/text-log/`
- **Purpose:** Text log aggregation

#### 33. **ubx-log**
- **Location:** `/etc/sv/ubx-log/`
- **Purpose:** UBX (u-blox GPS protocol) logging

#### 34. **klog**
- **Location:** `/etc/sv/klog/`
- **Purpose:** Kernel log monitoring

#### 35. **syslog**
- **Location:** `/etc/sv/syslog/`
- **Purpose:** System log daemon

#### 36. **clip-logger**
- **Location:** `/etc/sv/clip-logger/`
- **Purpose:** Dashcam/Sentry Mode video clip recording
- **Not Started:** Calibration mode

#### 37. **metrics**
- **Location:** `/etc/sv/metrics/`
- **Purpose:** System metrics collection

### Update & Configuration Services

#### 38. **ape-updater**
- **Location:** `/etc/sv/ape-updater/`
- **Purpose:** OTA update client for APE firmware

#### 39. **gadget-updater**
- **Location:** `/etc/sv/gadget-updater/`
- **Purpose:** Updates for external hardware (cameras, etc.)

#### 40. **updater-proxy**
- **Location:** `/etc/sv/updater-proxy/`
- **Purpose:** Proxy for update traffic

#### 41. **apeb-file-server**
- **Location:** `/etc/sv/apeb-file-server/`
- **Purpose:** File sharing between primary and redundant APE
- **Firewall Rule:** TCP port 8902 (192.168.90.103 → 192.168.90.105)

### Network Services

#### 42. **hermes-eventlogs**
- **Location:** `/etc/sv/hermes-eventlogs/`
- **Purpose:** Event log upload via Hermes

#### 43. **hermes-grablogs**
- **Location:** `/etc/sv/hermes-grablogs/`
- **Purpose:** Log retrieval via Hermes commands

#### 44. **hermes-teleforce**
- **Location:** `/etc/sv/hermes-teleforce/`
- **Purpose:** Remote diagnostics/control interface

#### 45. **connectivity-forwarder**
- **Location:** `/etc/sv/connectivity-forwarder/`
- **Purpose:** Network traffic forwarding between APE and MCU

#### 46. **sshd**
- **Location:** `/etc/sv/sshd/`
- **Purpose:** SSH daemon (development builds only)

#### 47. **clock-sync**
- **Location:** `/etc/sv/clock-sync/`
- **Purpose:** Time synchronization with vehicle CAN network

### UI & User Interaction

#### 48. **ui-server**
- **Location:** `/etc/sv/ui-server/`
- **Purpose:** Autopilot UI state provider

#### 49. **emergency-audio**
- **Location:** `/etc/sv/emergency-audio/`
- **Purpose:** Audio alerts for autopilot events

### Mapping & Navigation

#### 50. **map-manager**
- **Location:** `/etc/sv/map-manager/`
- **Purpose:** HD map data management

#### 51. **road-estimator**
- **Location:** `/etc/sv/road-estimator/`
- **Purpose:** Road geometry estimation

#### 52. **drivable-space-tracker**
- **Location:** `/etc/sv/drivable-space-tracker/`
- **Purpose:** Free space detection

### Calibration Services

#### 53. **field-calibration**
- **Location:** `/etc/sv/field-calibration/`
- **Purpose:** Online camera calibration refinement

#### 54. **factory-camera-calibration**
- **Location:** `/etc/sv/factory-camera-calibration/`
- **Purpose:** Factory calibration mode
- **Only Started:** When `/autopilot/.calibration-mode` exists

#### 55. **rain-light-sensing**
- **Location:** `/etc/sv/rain-light-sensing/`
- **Purpose:** Automatic wipers and headlights

### Compression & Data Management

#### 56. **compressor**
- **Location:** `/etc/sv/compressor/`
- **Purpose:** Video/telemetry compression
- **Not Started:** Calibration mode

### Boot & System Services

#### 57. **0001-ureadahead**
- **Location:** `/etc/sv/0001-ureadahead/`
- **Purpose:** Boot optimization (preload frequently accessed files)

#### 58. **getty-console**
- **Location:** `/etc/sv/getty-console/`
- **Purpose:** Console terminal (serial/TTY)

#### 59. **aurix-console**
- **Location:** `/etc/sv/aurix-console/`
- **Purpose:** Communication with Aurix safety microcontroller
- **Firewall Rule:** UDP port 28205 (Aurix data logging from LB)

#### 60. **shell-history-monitor**
- **Location:** `/etc/sv/shell-history-monitor/`
- **Purpose:** Monitors shell command history (security/diagnostics)

### Autopilot Redundancy (HW3+)

#### 61. **autopilot-b**
- **Location:** `/etc/sv/autopilot-b/`
- **Purpose:** Secondary autopilot instance (redundant APE board)
- **Network:** 192.168.90.105 (vs primary at 192.168.90.103)

#### 62. **run-modes**
- **Location:** `/etc/sv/run-modes/`
- **Purpose:** Manages autopilot run mode states

## Service Startup Order

### Phase 1: Pre-Configuration (Before Vehicle Detection)
1. **Basic CAN services** (cantx, canrx) - Model 3/Y HW3.0A only
2. **Camera** - Model 3/Y HW3.0A only (for backup camera alerts)
3. **Interrupt configuration**
4. **Vehicle configuration detection** (`/sbin/detect-vehicle-config`)

### Phase 2: Basic Services (Always Start)
1. **text-log**
2. **cantx** (if not already started)
3. **canrx**
4. **gps** (early start for other tasks)
5. **ubx-log**
6. **temperature-monitor**

### Phase 3: Bootloop Prevention Checks
- Check `/autopilot/kernel-panic-reboots` (max 3)
- Check `/autopilot/watchdog-system-reboots` (max 3)
- If threshold exceeded: Start telemetry/snapshot only, sleep 7 days

### Phase 4: Performance Tuning
- Set CPU governors to "performance" (max frequency)
- Apply sysctl tunings from `/etc/sysctl-ap-tunables.conf`
- Initialize GPU driver (HW2 Pascal GPUs)

### Phase 5: Vision Stack
1. **camera** (if not already started)
2. **imu**
3. **ultrasonics** (if present)
4. **Wait for IBQ initialization** (`/dev/shm/ibq_init_done`, 60s timeout)
   - Timeout triggers snapshot and reboot

### Phase 6: Telemetry & Monitoring
1. **telemetry-packager**
2. **telemetry**
3. **snapshot**
4. **snapshot-trigger-client**

### Phase 7: Main Autopilot Stack
1. **active-safety**
2. **compressor**
3. **clip-logger**
4. **watchdog**
5. **vision** (not in calibration mode)
6. **rain-light-sensing**
7. **drivable-space-tracker**
8. **map-manager**
9. **inertiator**
10. **perception**
11. **localizer**
12. **road-estimator**
13. **mission-planner**
14. **field-calibration**

### Phase 8: Behaviors
1. **stay-in-lane**
2. **lane-change**
3. **parking-behavior**
4. **city-streets-behavior** (HW3+ only)
5. **bev-graph** (HW3+ only)

### Phase 9: Control & UI
1. **controller**
2. **arbiter**
3. **autopilot-state-machine**
4. **driver-monitor**
5. **ui-server**
6. **metrics**

### Phase 10: Hardware Monitoring
1. **hw-monitor** (PCIe AER error detection)
2. **Reconfigure interrupts** (after all threads started)

## Key Configuration Files

- `/etc/hermes.vars` - Hermes cloud endpoint configuration
- `/etc/tesla-certificates.vars` - TLS certificate paths
- `/etc/sysctl-ap-tunables.conf` - Kernel tuning parameters
- `/etc/firewall` - IPtables rules
- `/autopilot/parameters/vehicle_config.json` - Detected vehicle configuration
- `/autopilot/.calibration-mode` - Factory calibration flag
- `/autopilot/simulation_ecu` - Simulation mode flag
- `/var/lib/board_creds/board.{key,crt}` - Board authentication credentials

## Bootloop Protection Mechanism

APE implements bootloop protection to prevent infinite crash loops:

1. **Kernel Panic Detection**
   - Checks `/dev/pstore/dmesg*` for panic records
   - Increments `/autopilot/kernel-panic-reboots`
   - After 3 consecutive panics: Stop autopilot startup

2. **Watchdog Reboot Detection**
   - Checks for `/autopilot/.dirty-reboot` flag
   - Increments `/autopilot/watchdog-system-reboots`
   - After 3 consecutive watchdog reboots: Stop autopilot startup

3. **Recovery Mode**
   - Starts minimal services: hw-monitor, telemetry-packager, snapshot
   - Creates diagnostic snapshot
   - Sleeps for 7 days (prevents CPU thrashing)
   - Requires clean boot to resume normal operation

## Service Management

APE uses **runit** for service management:

- `sv status /service/SERVICE_NAME` - Check service status
- `sv up /service/SERVICE_NAME` - Start service
- `sv down /service/SERVICE_NAME` - Stop service
- `sv once /service/SERVICE_NAME` - Start service once (no restart)
- `sv restart /service/SERVICE_NAME` - Restart service

Services are symlinked from `/etc/sv/` to `/service/` when enabled.

## Security Notes

- Most services run as dedicated users (e.g., `hermes:hermes`)
- AppArmor profiles disabled in factory mode (`/sbin/unload-apparmor-in-factory`)
- SSH daemon only runs on development builds
- TLS connections use hardware TPM for key storage (`--engine=fsdtpm`)
- Rate limiting applied to service-api outside factory

## Diagnostics

Key files for debugging service issues:

- `/var/log/SERVICE_NAME/current` - Service logs
- `/dev/shm/ibq_init_done` - Camera initialization flag
- `/dev/shm/camera_exited` - Camera failure flag
- `/tmp/spawnonce` - All services spawned at least once
- `/run/early-vehicle-config-success` - Early config detection success

## Related Documentation

- [APE Network Configuration](APE-NETWORK-CONFIG.md)
- [APE Firmware Extraction](APE-FIRMWARE-EXTRACTION.md)
- [Hermes Protocol Analysis](../core/HERMES-CLIENT-ANALYSIS.md)
- [Autopilot Architecture](../core/18-cid-iris-update-pipeline.md)
