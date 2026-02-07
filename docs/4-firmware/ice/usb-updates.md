# USB Offline Updates (ICE Platform)

**Complete analysis of Tesla USB update package format for Model 3/Y.**

---

## Overview

Tesla offline USB update packages use a combination of SquashFS, Ed25519 signatures, and dm-verity for integrity verification.

| Metric | Value |
|--------|-------|
| File Extension | `.ice` |
| Typical Size | 2.0-2.2 GB |
| Compression | LZ4 (High Compression) |
| Signature | Ed25519/NaCl |
| Integrity | dm-verity (SHA-256) |

---

## Package Structure

### Complete Format

```
Offset          Size        Component
─────────────────────────────────────────────────
0x00000000      ~2.1 GB     SquashFS filesystem
(aligned)       ~2 KB       Padding (to 4K boundary)
(sig_offset)    ~35 MB      Signature + dm-verity region
```

### Example: 2025.26.8.ice

```
Total file size:     2,241,335,360 bytes (2.09 GB)
SquashFS size:       2,206,369,806 bytes (2.05 GB)
Padding:                     2,034 bytes
Signature region:       34,963,520 bytes (33.34 MB)
```

---

## SquashFS Filesystem

### Header

```
Magic:          hsqs (0x73717368)
Version:        4.0
Compression:    lz4 with High Compression (-Xhc)
Block size:     131072 bytes (128 KB)
Inodes:         ~28,500
```

### Hex Dump

```
Offset   Hex                                ASCII
000000   68 73 71 73 60 6f 00 00 04 05...   hsqs`o......
         └──────────┘
         SquashFS magic (little-endian)
```

---

## Signature Region

### Location

```python
signature_offset = align_to_4k(squashfs_end)
# Example: 2,206,369,806 → aligned → 2,206,371,840
```

### Signature Blob Header

```
Offset   Size    Field
───────────────────────────────────────
+0x00    4       Magic: 0xba01ba01
+0x04    4       Flags/Version: 0x00000000
+0x08    64      Ed25519 signature
+0x48    32      Public key hash
+0x68    ???     dm-verity table data
```

### Hex Dump

```
00000000  01 ba 01 ba 00 00 00 00 79 87 cd 11 c4 36 66 ce
          └───────────────────┘  └──────────────────────
          Magic (0xba01ba01)     Ed25519 signature start
```

---

## dm-verity Hash Table

### Location

Found at offset **+0x108 (268 bytes)** from signature region start.

### Table Format

```
1 4096 4096 538665 538666 sha256 
2e7572e853d5f80f83759288aaacdc12f6e18fca68f7993fccc3e63beb4e4d88 
283f2ca91f05fb581c61ae2a7814fe8359cf26b7fc9228c253a21d32159d78f7
```

### Decoded Parameters

| Parameter | Value |
|-----------|-------|
| Version | 1 |
| Data block size | 4096 bytes |
| Hash block size | 4096 bytes |
| Data blocks | 538,665 |
| Hash blocks | 538,666 |
| Hash algorithm | sha256 |
| Root hash | 64-char hex |
| Salt | 64-char hex |

---

## Verification Flow

### On Vehicle

```
1. USB inserted → udev triggers check-usb-devices
2. check-usb-devices scans for *.ice files
3. updaterctl signature-install <file>
4. Load SquashFS size from superblock
5. Calculate signature offset (align to 4K)
6. Extract Ed25519 signature (64 bytes)
7. Load public key (/etc/verity-prod.pub)
8. Verify Ed25519 signature
   ├─ PASS → Continue
   └─ FAIL → Reject package
9. Parse dm-verity table
10. Create device mapper target
11. Mount with dm-verity verification
12. Install firmware
```

---

## Public Key Locations

| Key | Path | Purpose |
|-----|------|---------|
| Production | `/etc/verity-prod.pub` | Fused vehicles |
| Development | `/etc/verity-dev.pub` | Unfused units |
| Modem | `/etc/verity-modem-prod.pub` | Modem firmware |

**Key Format:** Ed25519 public key (32 bytes, base64 in PEM)

---

## Creating Packages

### Requirements

1. SquashFS filesystem with correct parameters
2. NaCl/Ed25519 signature (requires Tesla private key)
3. dm-verity hash table
4. Correct alignment and structure

### SquashFS Creation

```bash
mksquashfs firmware/ update.sqfs \
    -comp lz4 -Xhc \
    -b 131072 \
    -noappend \
    -no-xattrs \
    -all-root
```

### dm-verity Generation

```bash
veritysetup format update.sqfs update.hash \
    --data-block-size=4096 \
    --hash-block-size=4096 \
    --hash=sha256 \
    --salt=$(openssl rand -hex 32)
```

### Signature (Requires Tesla Key)

```python
import nacl.signing

# This requires Tesla's private key (NOT publicly available)
signing_key = nacl.signing.SigningKey(TESLA_PRIVATE_KEY)
signature = signing_key.sign(package_data)
```

---

## The Blocker: Tesla's Private Key

### What's Needed

| Item | Status |
|------|--------|
| Package format | ✅ Known |
| Signature algorithm | ✅ Known (Ed25519) |
| dm-verity format | ✅ Known |
| **Tesla private key** | ❌ NOT available |

### Why This Matters

- Production vehicles have fused keys
- Only Tesla's key can create valid signatures
- No bypass exists for signature verification

### Workarounds

| Method | Feasibility | Notes |
|--------|-------------|-------|
| Use pre-signed packages | ✅ Works | Download from Tesla/Lunar |
| Development unit | ⚠️ Rare | Accepts dev key |
| MCU replacement | ⚠️ Expensive | $600-5,200 |
| Voltage glitching | ⚠️ Complex | May bypass fuses |

---

## Using Pre-Signed Packages

### Available Sources

Tesla-signed packages from Lunar's website and other sources can be used directly:

```bash
# 1. Download package
wget https://example.com/2025.26.8.ice

# 2. Copy to USB drive (FAT32/exFAT)
cp 2025.26.8.ice /media/usb/

# 3. Insert into vehicle
# Vehicle auto-detects and installs
```

### Why This Works

- Packages are already Tesla-signed
- Signature verification passes
- dm-verity hash matches
- No private key needed for replay

---

## Updater Components

### MCU Binaries

| Binary | Path | Purpose |
|--------|------|---------|
| updater-envoy | `/usr/bin/updater-envoy` | Main orchestrator (Go) |
| updaterctl | `/usr/bin/updaterctl` | CLI tool |
| sx-updater | `/deploy/sx-updater` | MCU-specific |
| ice-updater | `/usr/bin/ice-updater` | ICE-specific |

### Key Functions (from updater-envoy)

```
AddPackage
GetPackageSignature
GetOfflineBank
MarkOfflineBankValid
SetOfflineHash
```

---

## Package Validation Script

```python
#!/usr/bin/env python3
"""Validate Tesla USB update package structure."""

import struct
import sys

def validate_package(path):
    with open(path, 'rb') as f:
        # Check SquashFS magic
        magic = f.read(4)
        if magic != b'hsqs':
            print(f"ERROR: Not a SquashFS file (magic: {magic.hex()})")
            return False
        
        # Get SquashFS size
        f.seek(40)
        sqfs_size = struct.unpack('<Q', f.read(8))[0]
        print(f"SquashFS size: {sqfs_size:,} bytes")
        
        # Calculate signature offset
        sig_offset = ((sqfs_size + 4095) // 4096) * 4096
        print(f"Signature offset: {sig_offset:,} bytes")
        
        # Check signature magic
        f.seek(sig_offset)
        sig_magic = struct.unpack('<I', f.read(4))[0]
        
        if sig_magic != 0xba01ba01:
            print(f"ERROR: Invalid signature magic: 0x{sig_magic:08x}")
            return False
        
        print(f"Signature magic: 0x{sig_magic:08x} ✓")
        
        # Read signature
        f.seek(4, 1)  # Skip flags
        signature = f.read(64)
        print(f"Signature length: {len(signature)} bytes ✓")
        
        return True

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <package.ice>")
        sys.exit(1)
    
    if validate_package(sys.argv[1]):
        print("\nPackage structure valid!")
    else:
        print("\nPackage validation failed!")
        sys.exit(1)
```

---

## Cross-References

- [Gateway Architecture](../../2-gateway/architecture.md) - Gateway firmware updates
- [CAN Flood Attack](../../5-attacks/can-flood.md) - Alternative update path

---

**Status:** COMPLETE ✅  
**Evidence:** Real package analysis (2025.26.8.ice)  
**Last Updated:** 2026-02-07
