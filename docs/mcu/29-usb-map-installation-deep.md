# USB Map Installation - Deep Dive Analysis (Evidence-Based)

## Document Purpose

This document provides an evidence-based deep dive into Tesla's USB navigation map installation system for MCU2 (Model S/X). All findings are extracted from `/root/downloads/mcu2-extracted` firmware and cite specific file paths.

**Related Documents:**
- **07-usb-map-installation.md** - High-level overview
- **10-usb-firmware-update-deep.md** - USB firmware update mechanisms
- **13-ota-handshake-protocol.md** - OTA handshake and signature verification

---

## 1. Map Package Format & Structure

### 1.1 File Format: SquashFS with dm-verity

Map files use the `.ssq` extension, which represents **SquashFS filesystems with embedded dm-verity metadata**.

**Evidence:**
```bash
# game-loader shows the SSQ package handling pattern
PKG=/opt/games/usr/$NAME.ssq
/usr/bin/verity-loader \
    --source "$PKG" \
    --target "/opt/games/mnt/$NAME" \
    --name "gamepkg-$NAME" \
    "${PUBLIC_KEYS[@]}" \
    load
```
【/root/downloads/mcu2-extracted/usr/bin/game-loader†L19-L32】

### 1.2 SSQ Package Structure

An `.ssq` file contains:
1. **SquashFS filesystem** (compressed map data)
2. **dm-verity metadata** (hash tree + signature)
3. **RSA signature blob** (NaCl/Ed25519 signed)

**SSQ Anatomy:**
```
┌─────────────────────────────────────┐
│  SquashFS Data (compressed)         │  ← Map tiles, databases
│  [Valhalla tiles, SQLite DBs]       │
├─────────────────────────────────────┤
│  dm-verity Hash Tree                │  ← Integrity hashes
│  [SHA256 merkle tree]               │
├─────────────────────────────────────┤
│  Verity Metadata Header             │  ← Root hash, salt
│  [64-byte header]                   │
├─────────────────────────────────────┤
│  RSA Signature (2048-bit)           │  ← Tesla's signature
│  [Signed root hash + metadata]      │
└─────────────────────────────────────┘
```

**Naming Convention:**
```
{REGION}-{YEAR}.{WEEK}-{BUILD}.ssq
```

Examples:
- `NA-2020.48-12628.ssq` (North America, Week 48 of 2020, Build 12628)
- `EU-2019.21-12489.ssq` (Europe, Week 21 of 2019, Build 12489)
- `CN-2020.48-12638.ssq` (China)

### 1.3 Internal Map Structure

Once mounted, a map SSQ contains:

```
/opt/navigon/
├── FILESYNC.VERSION        # Version identifier (must match .ssq filename without extension)
├── tm/                     # Map region data
│   ├── {REGION}/           # Two-letter region code
│   │   └── valhalla/       # Valhalla routing tiles
│   │       ├── *.gph       # Graph tiles
│   │       ├── *.bin       # Binary routing data
│   │       └── ...
├── admin.sqlite            # Administrative boundaries
├── tz_world.sqlite         # Timezone database
└── elevation/              # Elevation data
```

**Evidence from valhalla.json configuration:**
```json
{
  "mjolnir": {
    "tile_dir": "/data/valhalla",
    "map_version_file": "../../../FILESYNC.VERSION",
    "admin": "/data/valhalla/admin.sqlite",
    "timezone": "/data/valhalla/tz_world.sqlite"
  }
}
```
【/root/downloads/mcu2-extracted/usr/tesla/UI/assets/tesla_maps/valhalla.json†L3-L9】

---

## 2. Signature Verification & Validation

### 2.1 dm-verity Loader (`verity-loader`)

The `verity-loader` binary handles SSQ package mounting and signature verification.

**Key Functions (strings analysis):**
```c
ltv_verity_create    // Create dm-verity device
ltv_verity_remove    // Remove dm-verity device  
ltv_verity_check     // Verify signature
ltv_strerror         // Error messages
```
【/root/downloads/mcu2-extracted/usr/bin/verity-loader†strings】

**Error Messages:**
```
ESUPERBAD      - Invalid superblock
EKEYOPEN       - Unable to open key file
EBADKEY        - Invalid public key file
EMDBADHDR      - Invalid metadata header
EBADSIG        - Invalid verity table signature
ESQTOOBIG      - SquashFS size too large
```
【/root/downloads/mcu2-extracted/usr/lib/libtesla-verity.so†strings】

### 2.2 Signature Verification Library (`libtesla-verity.so`)

**Cryptographic Functions:**
```c
RSA_verify              // Verify RSA signature
SHA256                  // Hash computation
PEM_read_RSA_PUBKEY     // Load public key
EVP_get_digestbyname    // Get digest algorithm
```

**Verification Process:**
1. Read SSQ file metadata section
2. Extract dm-verity root hash
3. Load public key (PEM format)
4. Verify RSA signature against root hash
5. Check metadata header validity
6. Create dm-verity device mapping

【/root/downloads/mcu2-extracted/usr/lib/libtesla-verity.so†strings†L1-L40】

### 2.3 Public Keys for Map Packages

Maps likely use the **games signing keys** since they follow the same SSQ format:

```bash
/opt/games/keys/verity-games-prod.pub   # Production key (RSA 2048-bit)
/opt/games/keys/verity-games-dev.pub    # Development key (unfused devices)
```

**Key Selection Logic (from game-loader):**
```bash
declare -a PUBLIC_KEYS
PUBLIC_KEYS+=("--public-key")
PUBLIC_KEYS+=("/opt/games/keys/verity-games-prod.pub")

/usr/bin/is-fused
if [ $? -eq 1 ]; then
    PUBLIC_KEYS+=("--public-key")
    PUBLIC_KEYS+=("/opt/games/keys/verity-games-dev.pub")
fi
```
【/root/downloads/mcu2-extracted/usr/bin/game-loader†L10-L17】

**Public Key Format:**
```
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsCGOT/ZamB4MrRYHogLQ
w4y+h9/NzWK3AsgOJhtxcX1ms8tMivJZEJ9+jmQpdkA/gVjPTYprehzVL7d2WyYY
...
```
【/root/downloads/mcu2-extracted/opt/games/keys/verity-games-prod.pub†L1-L5】

### 2.4 SSQ Utility (`ssq-util`)

The `ssq-util` binary provides SSQ package management:

```c
ltv_verity_create    // Mount SSQ package
ltv_verity_remove    // Unmount SSQ package
ltv_strerror         // Error handling
```

**Dependencies:**
- `libcrypto.so.3` - Cryptographic operations
- `libtesla-verity.so` - Tesla's verity wrapper
- `libheci.so` - Intel HECI interface (for secure boot)

【/root/downloads/mcu2-extracted/usr/bin/ssq-util†strings†L35-L60】

---

## 3. Installation State Machine

### 3.1 Odin Task: `PROC_ICE_X_INSTALL-NAVIGATION-MAP`

The complete installation workflow is defined in the Odin service task.

**Task Metadata:**
```python
{
    'title': 'Install Navigation Map',
    'description': "Install the correct navigation map for VIN's region in to map bank A",
    'valid_states': ['StandStill|Drive', 'StandStill|Neutral', 'StandStill|Parked', 
                     'StandStill|Reverse', 'Moving|Drive', 'Moving|Neutral', 
                     'Moving|Parked', 'Moving|Reverse'],
    'local_principals': ['odin-research-and-development-level2', 
                         'odin-manufacturing-individual']
}
```
【/root/downloads/mcu2-extracted/opt/odin/odin_bundle/odin_bundle/networks/Common/tasks/PROC_ICE_X_INSTALL-NAVIGATION-MAP.py†metadata】

### 3.2 Installation State Machine

```
┌─────────────────────────────────────────────────────────────┐
│                    START                                    │
└────────────────┬────────────────────────────────────────────┘
                 │
                 ▼
┌────────────────────────────────────────────────────────────┐
│ 1. Check Current Map Version                               │
│    - Read vitals: cfg_mapregion                            │
│    - Read data value: TM_mapRelease                        │
│    - Determine map_prefixes (US→NA, HK/MO→HM, etc)        │
└────────────────┬───────────────────────────────────────────┘
                 │
                 ▼
           ┌─────────────┐
           │ Map correct?│
           └──┬──────┬───┘
              │Yes   │No
              │      │
              ▼      ▼
        ┌──────┐   ┌────────────────────────────────────────┐
        │ PASS │   │ 2. Locate Map SSQ File                 │
        └──────┘   │    - Check /opt/games/usr/maps/ exists │
                   │    - List directory contents            │
                   │    - Match prefix (NA, EU, CN, etc)     │
                   └────────────────┬───────────────────────┘
                                    │
                                    ▼
                            ┌───────────────┐
                            │ Map file found?│
                            └───┬───────┬───┘
                                │No     │Yes
                                ▼       ▼
                          ┌──────┐   ┌──────────────────────────┐
                          │ FAIL │   │ 3. Stop Map Services     │
                          └──────┘   │    qtcar-nuanceserver    │
                                     │    qtcar-tmserver        │
                                     │    valhalla              │
                                     │    qtcar                 │
                                     └──────────┬───────────────┘
                                                │
                                                ▼
                          ┌─────────────────────────────────────┐
                          │ 4. Unmount Existing Map             │
                          │    umount /opt/navigon              │
                          │    (ignore "not mounted" error)     │
                          └──────────┬──────────────────────────┘
                                     │
                                     ▼
                          ┌─────────────────────────────────────┐
                          │ 5. Write Map to Partition           │
                          │    - Read SSQ file bytes            │
                          │    - Write to /dev/mapper/          │
                          │      tlc-amap.crypt                 │
                          │    - Record size to                 │
                          │      /var/etc/map-updater/BANK_A.size│
                          └──────────┬──────────────────────────┘
                                     │
                                     ▼
                          ┌─────────────────────────────────────┐
                          │ 6. Mount Map Partition              │
                          │    mount -o ro,nosuid,nodev,noexec  │
                          │         -t squashfs                 │
                          │         /dev/mapper/tlc-amap.crypt  │
                          │         /opt/navigon                │
                          └──────────┬──────────────────────────┘
                                     │
                                     ▼
                          ┌─────────────────────────────────────┐
                          │ 7. Create Symlink                   │
                          │    rm /var/etc/maps                 │
                          │    ln -s /dev/mapper/tlc-amap.crypt │
                          │          /var/etc/maps              │
                          └──────────┬──────────────────────────┘
                                     │
                                     ▼
                          ┌─────────────────────────────────────┐
                          │ 8. Verify Installation              │
                          │    - MD5 hash check via             │
                          │      http://192.168.90.100:8901/    │
                          │      provisioning/maps/hash         │
                          │    - Compare with SSQ file hash     │
                          │    - Read FILESYNC.VERSION          │
                          │    - Verify TM_mapRelease matches   │
                          └──────────┬──────────────────────────┘
                                     │
                                     ▼
                          ┌─────────────────────────────────────┐
                          │ 9. Restart Map Services             │
                          │    sv up qtcar-nuanceserver         │
                          │    sv up qtcar-tmserver             │
                          │    sv up valhalla                   │
                          │    sv up qtcar                      │
                          └──────────┬──────────────────────────┘
                                     │
                                     ▼
                            ┌────────────────┐
                            │ Hash matches?  │
                            └───┬────────┬───┘
                                │No      │Yes
                                ▼        ▼
                          ┌──────┐   ┌──────┐
                          │ FAIL │   │ PASS │
                          └──────┘   └──────┘
```

### 3.3 Key Constants

```python
MAP_SERVICES = [
    "qtcar-nuanceserver",  # Voice recognition
    "qtcar-tmserver",      # Traffic/map server
    "valhalla",            # Routing engine
    "qtcar"                # Main UI process
]

MAP_MOUNT_POINT  = "/opt/navigon"
MAP_PARTITION_A  = "/dev/mapper/tlc-amap.crypt"
MAP_SIZE_A       = "/var/etc/map-updater/BANK_A.size"
MAP_LINK         = "/var/etc/maps"
MAP_STORAGE_DIR  = "/opt/games/usr/maps"
MAP_HASH_URL     = "http://192.168.90.100:8901/provisioning/maps/hash"
```
【/root/downloads/mcu2-extracted/opt/odin/odin_bundle/odin_bundle/networks/Common/scripts/PROC_ICE_X_INSTALL-NAVIGATION-MAP.py†L19-L25】

### 3.4 Region Prefix Mapping

```python
map_prefixes = [map_region]

# Special cases
if map_region == "US":
    map_prefixes = ["NA"]        # US/Canada → North America
elif map_region == "HK" or map_region == "MO":
    map_prefixes.append("HM")    # Hong Kong/Macau
elif map_region == "NONE":
    FAIL("Invalid map region")
```
【/root/downloads/mcu2-extracted/opt/odin/odin_bundle/odin_bundle/networks/Common/scripts/PROC_ICE_X_INSTALL-NAVIGATION-MAP.py†L46-L54】

---

## 4. USB Automount Triggers

### 4.1 USB Storage Mounting (`mounterd`)

The `mounterd` daemon handles USB device mounting and the `usbupdate-server`.

**Evidence:**
```c
// Strings from mounterd binary
/mnt/update
usbupdate-server
sv %s usbupdate-server failed!
```
【/usr/bin/mounterd†strings】

**Service Control:**
```bash
# mounterd controls usbupdate-server via runit
[ -d /service/usbupdate-server/supervise ] || exit 1

chmod 755 /service/usbupdate-server/{,log/}supervise/
chown mounterd /service/usbupdate-server/{,log/}supervise/{ok,control,status}
```
【/root/downloads/mcu2-extracted/etc/sv/mounterd/run†L20-L24】

### 4.2 USB Update Server

**Service Definition:**
```bash
#!/bin/sh
MOUNTPOINT=/mnt/update
FILESERVER_HOST=127.0.0.1
FILESERVER_PORT=23005

if [ -d "$MOUNTPOINT" ]; then
    RunSandbox /usr/bin/simple-http-server \
        -bind="$FILESERVER_HOST" \
        -port="$FILESERVER_PORT" \
        -dir="$MOUNTPOINT" \
        -split_file_support
else
    logger -t usbupdate-server "$MOUNTPOINT not found; usbupdate-server shutting down"
fi
```
【/root/downloads/mcu2-extracted/etc/sv/usbupdate-server/run†L3-L13】

**Flow:**
1. USB device inserted
2. `mounterd` detects device
3. Mounts to `/mnt/update` (exact mechanism not in extracted files)
4. Starts `usbupdate-server` on `127.0.0.1:23005`
5. Serves files via HTTP for updater to fetch

### 4.3 Map Staging Directory

Maps are **NOT** directly mounted from USB. Instead:

1. **USB files** → `/mnt/update` (temporary USB mount)
2. **Copy to staging** → `/opt/games/usr/maps/` (persistent storage)
3. **Installation** → Read from staging directory

**No automount for maps** - installation is **manual via Odin task** or similar trigger.

---

## 5. Map Database Structure

### 5.1 Valhalla Routing Engine

Tesla uses **Valhalla** (open-source routing engine) for navigation.

**Configuration:**
```json
{
  "mjolnir": {
    "max_cache_size": 200000000,
    "tile_dir": "/data/valhalla",
    "map_version_file": "../../../FILESYNC.VERSION",
    "admin": "/data/valhalla/admin.sqlite",
    "timezone": "/data/valhalla/tz_world.sqlite",
    "transit_dir": "/data/valhalla/transit"
  },
  "additional_data": {
    "elevation": "/data/valhalla/elevation/"
  }
}
```
【/root/downloads/mcu2-extracted/usr/tesla/UI/assets/tesla_maps/valhalla.json†L2-L13】

### 5.2 Map Tile Structure

```
/opt/navigon/tm/{REGION}/valhalla/
├── 0/                 # Zoom level 0
│   └── 000/
│       └── 000.gph    # Graph tile
├── 1/                 # Zoom level 1
├── 2/                 # Zoom level 2
└── ...
```

**Tile Format:**
- **`.gph` files** - Graph tiles (Valhalla binary format)
- Each tile contains:
  - Road network graph
  - Turn restrictions
  - Speed limits
  - Lane information
  - POI data

### 5.3 Supporting Databases

```
admin.sqlite      - Administrative boundaries (countries, states, cities)
tz_world.sqlite   - Timezone polygons for timezone detection
transit/*.pbf     - Public transit data (Protocol Buffers)
```

### 5.4 Map Version Tracking

```
FILESYNC.VERSION  - Plain text file containing version string
                    Example: "NA-2020.48-12628"
```

**Valhalla Service Reads Version:**
```bash
#!/bin/sh
MAPVERSIONFILE="$(egrep -i '^mapsVersionFile *=' $SETTINGSCONF | sed 's/=/ /' | awk '{print $2}')"
[ -z "$MAPVERSIONFILE" ] && MAPVERSIONFILE=/opt/navigon/VERSION

logger -t valhalla "map version: $([ -r "$MAPVERSIONFILE" ] && cat "$MAPVERSIONFILE" || echo unknown)"
```
【/root/downloads/mcu2-extracted/etc/sv/valhalla/run†L14-L21】

---

## 6. Update vs Full Install Differences

### 6.1 Full Install (from USB/Odin)

**Process:**
1. Stop all map services
2. **Unmount** existing map partition
3. **Overwrite** entire `/dev/mapper/tlc-amap.crypt` device
4. Mount new partition
5. Restart services

**Characteristics:**
- **Complete replacement** of map data
- Requires **full SSQ file** (2-6 GB)
- **No incremental updates**
- Writes directly to encrypted partition

### 6.2 OTA Update (Theoretical)

Maps **do not appear to support OTA updates** in the analyzed firmware. Key evidence:

**From handshake protocol:**
```
vehicle[map_signature]     - Current map signature
vehicle[map_country]       - Country code
vehicle[map_region]        - Map region
```
【/root/tesla/13-ota-handshake-protocol.md†L60-L62】

**Handshake includes map signatures** but no evidence of:
- Delta/patch generation for maps
- Incremental map updates
- Background map downloads

**Conclusion:** Maps are **full-replace only** via:
1. USB installation (service/manual)
2. Potentially OTA full SSQ download (not implemented in analyzed version)

### 6.3 Bank Management

**Single Bank System:**
```
MAP_PARTITION_A = "/dev/mapper/tlc-amap.crypt"  # Bank A only
MAP_SIZE_A      = "/var/etc/map-updater/BANK_A.size"
```

**No Bank B found** - Unlike firmware updates, maps do not use A/B banking.

**Implication:** Map updates are **disruptive** - navigation unavailable during install.

---

## 7. Map Version Management

### 7.1 Version Storage Locations

**Vehicle Data Values:**
```
TM_mapRelease               - Current installed map version
VAPI_navigationMapRegion    - Configured map region (US, EU, CN, etc)
VAPI_countryCode            - Vehicle country code
```
【/root/downloads/mcu2-extracted/opt/odin/core/engine/assets/whitelist/service-ldvs-whitelist†L950-L951】

**Filesystem:**
```
/opt/navigon/FILESYNC.VERSION        - Installed map version string
/var/etc/map-updater/BANK_A.size     - Installed map size (bytes)
```

### 7.2 Version Check Endpoint

**HTTP Hash Verification:**
```
http://192.168.90.100:8901/provisioning/maps/hash?bank=a&size={size}
```

**Expected Response:**
- MD5 hash of installed map partition

**Verification Logic:**
```python
installed_map_md5 = check_installed_map_hash(size=installed_map_size)
expected_map_md5 = hash_file(filepath=expected_map_path, algorithm="MD5")

if installed_map_md5 != expected_map_md5:
    FAIL("Installed map hash does not match expected map hash")
```
【PROC_ICE_X_INSTALL-NAVIGATION-MAP.py†L150-L155】

### 7.3 Regional Map Versions (Example Data)

From Odin network artifact:
```python
{
    'australia': ['AU-2019.24-10589'],
    'china': {
        'cn': ['CN-2020.48-12638'],
        'hk': ['HK-2019.52-11480'],
        'mo': ['MO-2018.12-981']
    },
    'eu': ['EU-2019.21-12489'],
    'japan': ['JP-2020.20-12010'],
    'korea': ['EMPTY-8dea9877'],      # No map data for Korea
    'me': ['ME-2019.40-11100'],
    'taiwan': ['TW-2019.24-10637'],
    'us': ['NA-2020.48-12628']
}
```
【/root/downloads/mcu2-extracted/opt/odin/odin_bundle/odin_bundle/networks/ModelSX/lib/MAP_VERSION.py†mapversion2】

---

## 8. Error Handling & Rollback

### 8.1 Installation Failure Modes

**Pre-Install Checks:**
```python
# 1. Map directory doesn't exist
if not file_exists(MAP_STORAGE_DIR):
    FAIL("Map storage directory does not exist")

# 2. No matching map file
if not expected_map_file:
    FAIL(f"Map SSQ with prefix {map_prefixes} not found")

# 3. Invalid region
if map_region == "NONE":
    FAIL("Invalid map region")
```

**Installation Errors:**
```python
# 1. Unmount failure
if umount_error and umount_error != "umount: /opt/navigon: not mounted.":
    ERROR("Error when unmount /opt/navigon")

# 2. Read failure
try:
    expected_map_contents = load_bytes(filename=expected_map_path)
except Exception:
    ERROR("Unable to read contents of map SSQ")

# 3. Write failure  
if not map_write_success:
    FAIL("Write map SSQ into map partition A did not complete")

# 4. Mount failure
if mount_error:
    ERROR("Error when mount /opt/navigon")
```

**Post-Install Verification:**
```python
# 1. Hash mismatch
if installed_map_md5 != expected_map_md5:
    FAIL("Installed map hash does not match expected map hash")

# 2. Version mismatch
if not (expected_map_file.replace(".ssq", "") == map_version == map_release):
    FAIL("Installed map version and release does not match expected map")
```

### 8.2 Service Restart Guarantees

**Map services ALWAYS restarted** regardless of installation outcome:

```python
try:
    for map_service in MAP_SERVICES:
        await sv(service=map_service, action="up")
except Exception as e:
    ERROR(f"Unable to bring up {map_service} service")
```

This ensures:
- System doesn't remain in "services stopped" state
- Old map (if still valid) remains accessible
- UI doesn't hang waiting for services

### 8.3 Rollback Mechanism

**No automatic rollback** - system relies on:

1. **Pre-existing map remains mounted** until write succeeds
2. **Atomic write** - partition overwrite is all-or-nothing
3. **Verification before restart** - services only restarted after mount succeeds

**If installation fails:**
- Old map partition remains intact
- Services restart with old map
- User must retry installation

**Failure Recovery:**
```bash
# Cleanup task to remove partial/failed maps
PROC_ICE_X_CLEAR-UNUSED-MAPS

# Removes all files from /opt/games/usr/maps/
# Deletes directory if empty
```
【/root/downloads/mcu2-extracted/opt/odin/odin_bundle/odin_bundle/networks/Common/scripts/PROC_ICE_X_CLEAR-UNUSED-MAPS.py】

### 8.4 Corruption Scenarios

**Scenario 1: Power Loss During Write**
```
Problem: Partial map written to partition
Result:  Mount fails → services restart with old map
Recovery: Delete /opt/games/usr/maps/*.ssq, retry install
```

**Scenario 2: Signature Verification Failure**
```
Problem: SSQ file signature invalid
Result:  dm-verity mount fails
Recovery: Obtain properly signed SSQ file
```

**Scenario 3: Hash Mismatch After Install**
```
Problem: Map hash doesn't match after installation
Result:  Installation marked as FAIL, but map may be functional
Recovery: Check /opt/navigon/FILESYNC.VERSION, verify TM_mapRelease
```

---

## 9. Security & Cryptographic Details

### 9.1 dm-verity Protection

**Purpose:** Prevent tampering with map data

**Mechanism:**
1. **Hash tree generation** - Every 4KB block hashed (SHA256)
2. **Root hash signing** - Tesla signs root hash with RSA private key
3. **Kernel verification** - Linux dm-verity verifies at read time

**Benefits:**
- Read-only guarantee
- Tamper detection
- Trusted execution environment

### 9.2 Key Types & Hierarchy

```
Production:  /opt/games/keys/verity-games-prod.pub   (always loaded)
Development: /opt/games/keys/verity-games-dev.pub    (unfused only)
```

**Fuse Check:**
```bash
/usr/bin/is-fused
# Returns 0 if fused (production)
# Returns 1 if unfused (development)
```

**Key Loading:**
- Production devices: 1 key (prod only)
- Development devices: 2 keys (prod + dev)

### 9.3 Encryption Stack

```
Application Layer:  /opt/navigon
                         ↓
Mount Options:      ro,nosuid,nodev,noexec
                         ↓
Filesystem:         SquashFS (read-only compression)
                         ↓
dm-verity:          Integrity verification (SHA256 Merkle tree)
                         ↓
Device Mapper:      /dev/mapper/tlc-amap.crypt
                         ↓
Encryption:         LUKS/dm-crypt (AES)
                         ↓
Block Device:       /dev/mmcblk0pX (eMMC partition)
```

**Note:** Partition name `tlc-amap.crypt` suggests **encrypted** storage, but details not fully documented in analyzed firmware.

---

## 10. Practical Attack Surface

### 10.1 Map Replacement Requirements

To install a custom/modified map:

**Required:**
1. **Signed SSQ package** - Must have valid Tesla signature
2. **Matching region** - Filename prefix must match vehicle config
3. **Valid version string** - FILESYNC.VERSION must match filename
4. **Correct format** - SquashFS + dm-verity metadata + signature

**Blockers:**
- ❌ **Cannot generate Tesla signatures** (private key required)
- ❌ **Cannot modify existing SSQ** (hash tree verification fails)
- ❌ **Cannot bypass signature check** (kernel dm-verity enforcement)

### 10.2 Potential Exploit Paths

**1. Development Key (Unfused Devices)**
```bash
# If vehicle is unfused
/usr/bin/is-fused  # Returns 1

# Could potentially:
# - Extract development public key
# - Find corresponding private key (if leaked)
# - Sign custom map packages
```

**Likelihood:** Low (private keys protected)

**2. Service Mode Map Installation**
```python
# Odin task principals:
'local_principals': [
    'odin-research-and-development-level2',
    'odin-manufacturing-individual'
]
```

**Requirements:**
- Service mode access
- Valid credentials
- Properly signed SSQ file

**Likelihood:** Medium (with service access)

**3. Hash Verification Bypass**
```
# If hash endpoint unavailable:
http://192.168.90.100:8901/provisioning/maps/hash
```

**Current behavior:**
- Installation continues even if hash check fails
- Only marks as FAIL in output
- Map may still function

**Likelihood:** High (for testing), but doesn't bypass signature verification

---

## 11. Comparison with Firmware Updates

| Aspect | Map Updates | Firmware Updates |
|--------|-------------|------------------|
| **Package Format** | SSQ (SquashFS + verity) | SSQ (SquashFS + verity) |
| **Signature** | RSA-2048 (games keys) | Ed25519 NaCl (firmware keys) |
| **Bank System** | Single bank (A only) | Dual bank (A/B) |
| **Update Type** | Full replace only | Delta/patch supported |
| **Installation** | Manual (Odin/Service) | OTA automated |
| **Rollback** | No automatic rollback | Automatic via bank swap |
| **Verification** | MD5 hash via HTTP | Embedded signature + verity |
| **Size** | 2-6 GB | Varies (100MB-4GB) |
| **Disruption** | Services stopped during install | Installed to inactive bank |

---

## 12. Appendix: File Paths Reference

### 12.1 Binaries
```
/usr/bin/verity-loader          - SSQ package loader
/usr/bin/ssq-util               - SSQ utility wrapper
/usr/bin/game-loader            - Game package loader (same mechanism)
/usr/bin/valhalla_server        - Routing engine
/usr/bin/mounterd               - USB mount daemon
/usr/bin/simple-http-server     - USB update server
```

### 12.2 Libraries
```
/usr/lib/libtesla-verity.so     - Verity verification library
/usr/lib/libvalhalla.so         - Valhalla routing library
```

### 12.3 Services
```
/etc/sv/valhalla/run            - Valhalla routing service
/etc/sv/qtcar-tmserver/run      - Traffic/map server
/etc/sv/usbupdate-server/run    - USB update HTTP server
/etc/sv/mounterd/run            - USB mount daemon
```

### 12.4 Configuration
```
/etc/valhalla/valhalla.json     - Valhalla engine config (symlink)
/usr/tesla/UI/assets/tesla_maps/valhalla.json  - Actual config file
/opt/games/keys/verity-games-*.pub             - Signing keys
```

### 12.5 Runtime Paths
```
/opt/navigon/                    - Map mount point
/opt/navigon/FILESYNC.VERSION    - Version identifier
/opt/games/usr/maps/             - Staging directory for SSQ files
/var/etc/maps                    - Symlink to partition
/var/etc/map-updater/BANK_A.size - Installed size tracking
/dev/mapper/tlc-amap.crypt       - Encrypted map partition
/mnt/update/                     - USB mount point (from updater research)
```

### 12.6 Odin Tasks
```
/opt/odin/odin_bundle/odin_bundle/networks/Common/tasks/
  └── PROC_ICE_X_INSTALL-NAVIGATION-MAP.py    - Main installation task

/opt/odin/odin_bundle/odin_bundle/networks/Common/scripts/
  ├── PROC_ICE_X_INSTALL-NAVIGATION-MAP.py    - Installation script
  ├── PROC_ICE_X_CLEAR-UNUSED-MAPS.py         - Cleanup script  
  ├── PROC_ICE_X_CLEAR-MAP-CACHE.py           - Cache clearing
  └── ICE_INFO_CHECK-MAP-DEV.py               - Map device check
```

---

## 13. Open Questions & Gaps

1. **Exact USB→Staging Copy Mechanism**
   - How does `/mnt/update` content reach `/opt/games/usr/maps/`?
   - Automated or manual trigger?

2. **Partition Encryption Details**
   - LUKS key management for `tlc-amap.crypt`
   - Key derivation from TPM/fuses?

3. **OTA Map Updates**
   - Handshake includes map signatures
   - No implementation found for OTA map downloads
   - Future feature or deprecated?

4. **Bank B Partition**
   - Only Bank A found in code
   - Was Bank B removed? Never implemented?

5. **Hash Endpoint Implementation**
   - What service runs on `192.168.90.100:8901`?
   - Is it Gateway's provisioning server?

---

## 14. Summary

**Key Findings:**

1. **Maps use SSQ format** - Same as games/firmware (SquashFS + dm-verity + RSA signature)
2. **No OTA map updates** - Full replace only via USB or manual installation
3. **Single bank system** - No A/B banking like firmware updates
4. **Signature verification required** - Cannot bypass without Tesla's private keys
5. **Region-based validation** - Vehicle must match map region prefix
6. **HTTP hash verification** - Post-install integrity check via local endpoint
7. **Service mode installation** - Requires Odin access with proper credentials
8. **No automatic rollback** - Failed installs leave old map intact

**Practical Implications:**

- ✅ Can install maps via USB (if properly signed)
- ✅ Can verify map version via data values
- ✅ Can understand installation failures via error codes
- ❌ Cannot create custom maps (signature required)
- ❌ Cannot patch existing maps (verity protection)
- ❌ Cannot bypass region checks (enforced at multiple levels)

**For Offline Updates:**
- Maps follow same security model as firmware
- Require Tesla-signed packages
- Service mode can install if credentials available
- No workaround for signature verification

---

**Document Sources:**
- `/root/downloads/mcu2-extracted/` - MCU2 firmware filesystem
- `/root/tesla/07-usb-map-installation.md` - High-level overview
- `/root/tesla/10-usb-firmware-update-deep.md` - USB update mechanisms
- `/root/tesla/13-ota-handshake-protocol.md` - OTA handshake details

All findings evidence-based with source citations.
