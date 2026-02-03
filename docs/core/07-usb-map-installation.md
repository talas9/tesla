# USB Map Installation - Tesla Model S/X

## Overview

Tesla vehicles can have navigation map files installed via USB drive. The map installation process uses a storage directory on an internal partition for staging map files before installation to the encrypted map partition.

## Map File Storage & Format

### Storage Location
- **USB staging directory**: `/opt/games/usr/maps/`
- **Map partition (encrypted)**: `/dev/mapper/tlc-amap.crypt`
- **Mount point**: `/opt/navigon`
- **Map version file**: `/opt/navigon/FILESYNC.VERSION`
- **Symlink**: `/var/etc/maps` → `/dev/mapper/tlc-amap.crypt`

### Map File Format
- **Extension**: `.ssq` (SquashFS compressed filesystem)
- **Naming convention**: `{REGION}-{YEAR}.{WEEK}-{BUILD}.ssq`
  - Example: `NA-2020.48-12628.ssq` (North America, Week 48 of 2020, Build 12628)
  - Example: `EU-2019.21-12489.ssq` (Europe)
  - Example: `CN-2020.48-12638.ssq` (China)

### Regional Map Versions
Based on the vehicle's configured map region (`cfg_mapregion` vitals), different map files are required:

| Region Code | Map Key | Example Version |
|-------------|---------|-----------------|
| US/Canada | `us` or `NA` | NA-2020.48-12628 |
| EU | `eu` | EU-2019.21-12489 |
| CN | `china` | CN-2020.48-12638 |
| HK/MO | `hk`/`mo` | HK-2019.52-11480, MO-2018.12-981 |
| AU | `australia` | AU-2019.24-10589 |
| JP | `japan` | JP-2020.20-12010 |
| TW | `taiwan` | TW-2019.24-10637 |
| KR | `korea` | EMPTY-8dea9877 |
| ME | `me` | ME-2019.40-11100 |

## Installation Process

### 1. Pre-Installation Steps

The vehicle determines which map file to install based on:
1. **Vehicle region** (`VAPI_navigationMapRegion`)
2. **Country code** (`VAPI_countryCode`) 
3. **Current map release** (`TM_mapRelease`)

### 2. Map Services

The following services must be stopped before installation:
- `qtcar-nuanceserver`
- `qtcar-tmserver`
- `valhalla`
- `qtcar`

### 3. Installation Workflow

```
1. Check current map version (TM_mapRelease)
   ├─ If correct version installed → Skip installation
   └─ If update needed → Continue

2. Check for map files in /opt/games/usr/maps/
   ├─ Look for .ssq file matching vehicle region
   └─ Fail if no matching map found

3. Stop map services
   └─ Force-stop: qtcar-nuanceserver, qtcar-tmserver, valhalla, qtcar

4. Unmount /opt/navigon
   └─ Handle "not mounted" gracefully

5. Write map file to encrypted partition
   ├─ Read map .ssq file from USB staging area
   ├─ Write to /dev/mapper/tlc-amap.crypt
   └─ Record size to /var/etc/map-updater/BANK_A.size

6. Mount map partition
   └─ mount -o ro,nosuid,nodev,noexec -t squashfs /dev/mapper/tlc-amap.crypt /opt/navigon

7. Create symlink
   └─ ln -s /dev/mapper/tlc-amap.crypt /var/etc/maps

8. Verify installation
   ├─ Calculate MD5 hash of installed map
   ├─ Compare with expected hash
   ├─ Read version from /opt/navigon/FILESYNC.VERSION
   └─ Verify TM_mapRelease matches installed version

9. Restart map services
   └─ Start: qtcar-nuanceserver, qtcar-tmserver, valhalla, qtcar
```

### 4. Map Hash Verification

After installation, the system verifies the map integrity:
- **Hash check URL**: `http://192.168.90.100:8901/provisioning/maps/hash?bank=a&size={size}`
- Compares installed map MD5 against expected hash
- Ensures `FILESYNC.VERSION` matches the expected map file name (without `.ssq`)

## USB Installation Procedure

### For Users/Service

1. **Obtain map file**
   - Download region-appropriate `.ssq` file
   - Verify filename matches expected format

2. **Prepare USB drive**
   - Format: exFAT or FAT32 recommended
   - Create directory structure: `/maps/` (if needed)
   - Copy `.ssq` file to root or `/maps/` directory

3. **Install via vehicle**
   - Insert USB drive into vehicle
   - System automatically detects map files in `/opt/games/usr/maps/`
   - Run installation routine via service menu or Odin

4. **Verification**
   - Check `TM_mapRelease` data value
   - Confirm version matches installed `.ssq` file
   - Verify navigation functionality

### Odin Service Task

The installation can be triggered via:
- **Task**: `PROC_ICE_X_INSTALL-NAVIGATION-MAP`
- **Requirements**: Map file present in `/opt/games/usr/maps/`
- **Inputs**: None (automatic region detection)
- **Verification**: Checks TM_mapRelease and FILESYNC.VERSION

## Diagnostic Commands

### Check Current Map Version
```python
# Via Odin/Service Mode
data_name: TM_mapRelease
# Returns: e.g., "NA-2020.48-12628"
```

### List Available Maps
```bash
ls -lh /opt/games/usr/maps/
```

### Check Map Installation Status
```bash
# Check if map is mounted
mount | grep navigon

# Read installed version
cat /opt/navigon/FILESYNC.VERSION

# Check symlink
ls -l /var/etc/maps
```

### Map Version Test
- **Task**: `TEST_CID_X_MAP-VERSION`
- Verifies installed map version matches vehicle configuration

## Troubleshooting

### Common Issues

1. **No map file found**
   - Verify `.ssq` file is in `/opt/games/usr/maps/`
   - Check filename matches region prefix (NA, EU, CN, etc.)

2. **Hash mismatch**
   - Map file corrupted during copy
   - Re-download and copy map file

3. **Services won't stop**
   - May need multiple stop attempts
   - Check for active navigation or services

4. **Mount failure**
   - Encrypted partition may need reformatting
   - Check for disk errors

5. **Version mismatch after install**
   - Map file name doesn't match internal version
   - Verify correct file for vehicle year/build

## Security Notes

- Map partition is **encrypted** (`tlc-amap.crypt`)
- Mounted as **read-only** for security
- Installation requires **service mode** or **ODJ access**
- Hash verification prevents corrupted/tampered maps

## File System Structure

```
/opt/navigon/              # Map mount point (read-only)
├── FILESYNC.VERSION       # Version identifier
├── [map data files]       # Navigation database

/opt/games/usr/maps/       # USB staging directory
└── [region].ssq           # Map files from USB

/var/etc/maps              # Symlink to map device
/var/etc/map-updater/
└── BANK_A.size            # Installed map size

/dev/mapper/
└── tlc-amap.crypt         # Encrypted map partition
```

## Notes

- Map updates typically provided by Tesla via OTA
- USB installation primarily for service/recovery scenarios
- Map files are region-locked by vehicle configuration
- Some regions (like Korea) may have "EMPTY" maps
- Map size typically ranges from 2-6 GB depending on region
