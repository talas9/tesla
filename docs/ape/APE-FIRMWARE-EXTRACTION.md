# APE Firmware Extraction Methodology

## Overview

This document details the methodology used to extract and analyze Tesla Autopilot Compute (APE) firmware. The extraction process involves obtaining a SquashFS filesystem image and unpacking it for analysis.

## Firmware Source

**Firmware File:** `2024.8.9.ice.ape25`  
**Location:** `/root/downloads/ape-firmware/2024.8.9.ice.ape25`  
**Size:** 534 MB (555,099,242 bytes)  
**Type:** SquashFS filesystem (little-endian, zlib compressed)  
**SquashFS Version:** 4.0  
**Block Size:** 131,072 bytes (128 KB)  
**Inodes:** 4,351  
**Created:** Saturday, April 6, 2024, 00:34:33 UTC

## Acquisition Methods

There are several methods to obtain APE firmware:

### Method 1: OTA Update Interception
1. Intercept firmware download during Tesla OTA update
2. Firmware downloaded to `/var/spool/update/` on MCU or APE
3. Extract before installation completes
4. **Advantage:** Legitimate firmware, exact vehicle match
5. **Disadvantage:** Requires active update window

### Method 2: Service Mode Access
1. Enable service mode via diagnostic menu
2. SSH access to APE (development builds)
3. Copy firmware from `/opt/autopilot/` partition
4. **Advantage:** Direct access to running system
5. **Disadvantage:** Requires service mode enablement

### Method 3: Physical Extraction
1. Remove APE board from vehicle
2. UART/JTAG access to Tegra SoC
3. Dump flash partitions
4. **Advantage:** Full control, no software restrictions
5. **Disadvantage:** Requires hardware disassembly

### Method 4: Tesla Toolbox / Service Tool
1. Use Tesla internal tools (Odin, Toolbox)
2. Download firmware packages from Tesla servers
3. Extract from update packages
4. **Advantage:** Access to multiple firmware versions
5. **Disadvantage:** Requires Tesla service access

## Extraction Process

### Prerequisites

**Required Tools:**
```bash
apt-get install squashfs-tools
```

**Disk Space Requirements:**
- Compressed firmware: ~534 MB
- Extracted filesystem: ~1.2 GB
- Total recommended: 2 GB free space

### Step 1: Verify Firmware Integrity

```bash
cd /root/downloads/ape-firmware

# Check file type
file 2024.8.9.ice.ape25

# Expected output:
# 2024.8.9.ice.ape25: Squashfs filesystem, little endian, version 4.0, 
# zlib compressed, 555099242 bytes, 4351 inodes, blocksize: 131072 bytes, 
# created: Sat Apr  6 00:34:33 2024
```

### Step 2: Extract SquashFS Image

```bash
cd /root/downloads

# Extract with unsquashfs
unsquashfs -d ape-extracted ape-firmware/2024.8.9.ice.ape25

# Extraction will take 1-3 minutes depending on CPU
# Output: 4351 files extracted to ape-extracted/
```

**Extraction Output:**
```
Parallel unsquashfs: Using 4 processors
4351 inodes (4629 blocks) to write

[==================================================] 4629/4629 100%

created 3421 files
created 456 directories
created 324 symlinks
created 150 devices
created 0 fifos
```

### Step 3: Verify Extraction

```bash
cd ape-extracted

# Check directory structure
ls -la

# Expected top-level directories:
# bin/      - System binaries
# boot/     - Boot configuration (minimal)
# dev/      - Device nodes (for chroot)
# etc/      - Configuration files (services, network, firewall)
# home/     - User home directories
# lib/      - Shared libraries
# opt/      - Autopilot binaries (/opt/autopilot/, /opt/hermes/)
# proc/     - Proc mount point
# root/     - Root user home
# run/      - Runtime files
# sbin/     - System administration binaries
# srv/      - Service data
# sys/      - Sysfs mount point
# tmp/      - Temporary files
# usr/      - User binaries and libraries
# var/      - Variable data (logs, caches)
```

### Step 4: Catalog Key Components

```bash
# Count runit services
ls /root/downloads/ape-extracted/etc/sv | wc -l
# Output: 62 services

# List service directories
ls /root/downloads/ape-extracted/etc/sv/
# Output: autopilot, hermes, camera, canrx, cantx, etc.

# Check autopilot binaries
ls -lh /root/downloads/ape-extracted/opt/autopilot/bin/ | head -20

# Check hermes binaries
ls -lh /root/downloads/ape-extracted/opt/hermes/

# Examine network configuration
cat /root/downloads/ape-extracted/etc/network/interfaces
cat /root/downloads/ape-extracted/etc/hosts
cat /root/downloads/ape-extracted/etc/resolv.conf

# Review firewall rules
cat /root/downloads/ape-extracted/etc/firewall
```

## Filesystem Structure

### Critical Directories

```
ape-extracted/
├── bin/                     # Core system binaries (bash, ls, etc.)
├── boot/                    # Boot configuration (minimal, no kernel)
├── etc/
│   ├── sv/                  # Runit service definitions (62 services)
│   ├── network/             # Network interface configuration
│   ├── firewall             # IPtables rules
│   ├── hermes.vars          # Hermes cloud endpoints
│   ├── hosts                # Static hostname mappings
│   └── resolv.conf          # DNS configuration
├── opt/
│   ├── autopilot/           # Autopilot binaries and libraries
│   │   ├── bin/             # Autopilot executables (vision, perception, etc.)
│   │   ├── lib/             # Autopilot shared libraries
│   │   ├── etc/             # Autopilot configuration
│   │   └── share/           # Autopilot data files (models, maps)
│   └── hermes/              # Hermes cloud client
│       └── hermes           # Hermes binary
├── sbin/                    # System administration binaries
│   ├── detect-vehicle-config
│   ├── boardid
│   ├── bootcount
│   └── configure-interrupts
├── usr/
│   ├── bin/                 # User binaries
│   ├── lib/                 # User libraries
│   └── share/               # Shared data
└── var/
    ├── lib/                 # Variable state data
    │   └── board_creds/     # Board authentication credentials
    └── log/                 # Log files (empty in extracted image)
```

### Key Files for Analysis

| File Path | Purpose | Analysis Value |
|-----------|---------|----------------|
| `/etc/sv/*/run` | Service startup scripts | Service dependencies, command-line args |
| `/etc/firewall` | IPtables rules | Attack surface, port mappings |
| `/etc/hermes.vars` | Cloud endpoints | Command & control infrastructure |
| `/opt/autopilot/bin/*` | Autopilot binaries | Reverse engineering targets |
| `/sbin/detect-vehicle-config` | Vehicle detection logic | Configuration extraction method |
| `/usr/bin/service_api` | REST API server | Unauthenticated API surface |

## Verification Steps

### 1. Service Inventory
```bash
# Count all service run scripts
find /root/downloads/ape-extracted/etc/sv -name "run" | wc -l
# Expected: 120 (62 services × ~2 files each: run, log/run)

# Verify each service has run script
for svc in /root/downloads/ape-extracted/etc/sv/*; do
    [ ! -f "$svc/run" ] && echo "Missing run script: $svc"
done
```

### 2. Binary Integrity
```bash
# Check autopilot binaries are not corrupted
cd /root/downloads/ape-extracted/opt/autopilot/bin
for bin in *; do
    file "$bin" | grep -q "ELF" || echo "Not ELF: $bin"
done

# Check for stripped symbols (expected in production)
readelf -S /root/downloads/ape-extracted/opt/hermes/hermes | grep -q ".symtab" && \
    echo "Symbols present" || echo "Stripped binary (expected)"
```

### 3. Configuration Consistency
```bash
# Verify all referenced hosts exist in /etc/hosts
grep -Eo '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' \
    /root/downloads/ape-extracted/etc/firewall | sort -u | while read ip; do
    grep -q "$ip" /root/downloads/ape-extracted/etc/hosts || \
        echo "IP not in hosts: $ip"
done

# Check for dangling symlinks
find /root/downloads/ape-extracted -xtype l
```

### 4. Permissions & Ownership
```bash
# Check setuid/setgid binaries (potential privilege escalation)
find /root/downloads/ape-extracted -type f \( -perm -4000 -o -perm -2000 \) -ls

# Check world-writable files (security risk)
find /root/downloads/ape-extracted -type f -perm -002 -ls
```

## Advanced Analysis

### Static Analysis

```bash
# Extract strings from binaries
strings /root/downloads/ape-extracted/opt/hermes/hermes > hermes_strings.txt

# Search for interesting patterns
grep -E "(password|secret|key|token)" hermes_strings.txt

# Find hardcoded IPs
grep -Eo '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' hermes_strings.txt | sort -u

# Find URLs
grep -Eo 'https?://[^"]+' hermes_strings.txt | sort -u
```

### Dependency Mapping

```bash
# Map library dependencies
for bin in /root/downloads/ape-extracted/opt/autopilot/bin/*; do
    echo "=== $(basename $bin) ==="
    ldd "$bin" 2>/dev/null | grep -v "not found" || echo "Static binary"
done
```

### Service Dependency Graph

```bash
# Extract service startup order from autopilot/run script
grep "logged_service_start" /root/downloads/ape-extracted/etc/sv/autopilot/run | \
    sed 's/.*logged_service_start //' | nl
```

### Network Endpoint Discovery

```bash
# Find all network endpoints referenced
grep -rh "wss://\|https://\|http://" /root/downloads/ape-extracted/etc/ | \
    grep -Eo '(wss?|https?)://[^"]+' | sort -u

# Expected output:
# wss://hermes-prd.ap.tesla.services:8443
# wss://hermes-eng.ap.tesla.services:8443
# wss://telemetry-prd.ap.tesla.services:8443
# wss://hermes-x2-api.prd.vn.cloud.tesla.cn:8443
```

## Common Issues & Solutions

### Issue 1: Permission Denied During Extraction
```bash
# Solution: Extract as root or with sudo
sudo unsquashfs -d ape-extracted ape-firmware/2024.8.9.ice.ape25
```

### Issue 2: Insufficient Disk Space
```bash
# Check available space
df -h /root/downloads

# Clean up old extractions
rm -rf /root/downloads/ape-extracted-old
```

### Issue 3: Corrupted SquashFS Image
```bash
# Verify image integrity
md5sum ape-firmware/2024.8.9.ice.ape25

# Re-download if hash mismatch
# (Original hash should be documented separately)
```

### Issue 4: Unsquashfs Not Found
```bash
# Install squashfs-tools
apt-get update
apt-get install squashfs-tools

# Verify installation
unsquashfs -version
```

## Forensic Preservation

### Creating Analysis Archive

```bash
cd /root/downloads

# Create tarball with metadata preservation
tar czf ape-extracted-2024.8.9.tar.gz \
    --preserve-permissions \
    --preserve-order \
    --numeric-owner \
    ape-extracted/

# Verify archive
tar tzf ape-extracted-2024.8.9.tar.gz | head -20

# Calculate checksums for integrity
sha256sum ape-extracted-2024.8.9.tar.gz > ape-extracted-2024.8.9.tar.gz.sha256
sha256sum ape-firmware/2024.8.9.ice.ape25 > ape-firmware-2024.8.9.ice.ape25.sha256
```

### Documentation Requirements

For each firmware extraction, document:

1. **Firmware Metadata**
   - Version: 2024.8.9
   - Build date: April 6, 2024
   - Source: OTA update / service tool / physical extraction
   - Vehicle VIN (if applicable)
   - Hardware revision (HW2.0, HW2.5, HW3.0, HW4.0)

2. **Extraction Environment**
   - Tool versions: `unsquashfs -version`
   - Host OS: `uname -a`
   - Extraction date: `date -u`

3. **Checksums**
   - Original SquashFS: SHA-256
   - Extracted archive: SHA-256
   - Critical binaries: SHA-256 of `/opt/autopilot/bin/*`

## Comparison Across Versions

### Diffing Firmware Versions

```bash
# Extract two versions
unsquashfs -d ape-2024.8.9 ape-firmware/2024.8.9.ice.ape25
unsquashfs -d ape-2024.7.1 ape-firmware/2024.7.1.ice.ape25

# Compare directory structures
diff -r ape-2024.8.9 ape-2024.7.1 > firmware-diff-2024.8.9-vs-2024.7.1.txt

# Compare service configurations
diff -u ape-2024.7.1/etc/sv/hermes/run ape-2024.8.9/etc/sv/hermes/run

# Compare binary versions
ls -l ape-2024.7.1/opt/autopilot/bin/ > v7.1-binaries.txt
ls -l ape-2024.8.9/opt/autopilot/bin/ > v8.9-binaries.txt
diff -u v7.1-binaries.txt v8.9-binaries.txt
```

## Security Considerations

### Safe Analysis Environment

1. **Isolated Analysis Host**
   - Do NOT extract on production systems
   - Use dedicated VM or container
   - No network access during analysis

2. **Malware Scanning**
   - Scan extracted binaries before execution
   - Check for backdoors or trojans
   - Verify checksums against known-good hashes

3. **Attribution**
   - Do NOT upload firmware to public repositories
   - Respect Tesla's intellectual property
   - Use extracted knowledge for security research only

## Legal & Ethical Notes

⚠️ **Important:**
- Firmware extraction may violate DMCA or CFAA (U.S. law)
- Only extract firmware from vehicles you own or have authorization to research
- Do not redistribute Tesla proprietary binaries
- Derived knowledge (configurations, protocols) is generally fair use for security research
- Consult legal counsel before publishing detailed reverse engineering

## Tools & Resources

### Required Tools
- `squashfs-tools` (unsquashfs)
- `file` (file type detection)
- `binutils` (readelf, objdump)
- `strings` (string extraction)
- `grep`, `find` (search utilities)

### Optional Tools
- **Ghidra** - Reverse engineering framework
- **IDA Pro** - Disassembler
- **Binary Ninja** - Binary analysis platform
- **Radare2** - Reverse engineering framework
- **Binwalk** - Firmware analysis tool

### Related Documentation
- [APE Services Documentation](APE-SERVICES.md)
- [APE Network Configuration](APE-NETWORK-CONFIG.md)
- [Hermes Protocol Analysis](../core/HERMES-CLIENT-ANALYSIS.md)
- [Firmware Update Pipeline](../core/18-cid-iris-update-pipeline.md)

## Changelog

| Date | Version | Changes |
|------|---------|---------|
| 2024-04-06 | 2024.8.9 | Initial extraction documented |
| 2025-02-03 | - | Methodology document created |
