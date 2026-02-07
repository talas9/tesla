# Gateway UDP Protocol

**Protocol specification for Gateway configuration API on UDP port 3500.**

---

## Overview

The Gateway exposes a UDP API on port 3500 for reading and writing configuration values. This protocol is used by Tesla service tools and can be accessed by any device on the vehicle's internal network.

| Parameter | Value |
|-----------|-------|
| Port | 3500 (UDP) |
| Gateway IP | 192.168.90.102 |
| Access | Insecure configs only (no authentication) |

---

## Message Format

### General Structure

```
Offset  Size    Field       Description
+0x00   2       Length      Total message length (little-endian)
+0x02   1       Command     Command byte (READ=0x01, WRITE=0x02)
+0x03   2       Config ID   Configuration ID (big-endian)
+0x05   N       Data        Variable-length data (for writes)
```

### Read Request

```
Length: 3 bytes (fixed)
Format: [0x03, 0x00] [0x01] [ID_HI, ID_LO]

Example - Read VIN (0x0000):
03 00 01 00 00
│  │  │  └──┴── Config ID 0x0000 (BE)
│  │  └──────── Command: READ (0x01)
└──┴─────────── Length: 3 (LE)
```

### Read Response

```
Format: [Length:2] [Status:1] [Data:N]

Example - VIN response:
14 00 00 37 53 41 59 47 44 45 45 58 50 41 30 35 32 34 36 36
│  │  │  └─────────────────────────────────────────────────┘
│  │  │  ASCII: "7SAYGDEEXPA052466" (17 bytes)
│  │  └── Status: 0x00 (success)
└──┴───── Length: 20 (LE)
```

### Write Request

```
Length: 3 + data_length bytes
Format: [Length:2] [0x02] [ID:2] [CRC:1] [Data:N]

Example - Write map region to EU (0x0014 = 0x01):
06 00 02 00 14 XX 01
│  │  │  └──┴── Config ID 0x0014 (BE)
│  │  └──────── Command: WRITE (0x02)
└──┴─────────── Length: 6 (LE)
         XX = CRC-8 of [0x0014] + [0x01]
```

### Write Response

```
Format: [Length:2] [Status:1]

Success: 03 00 00
Error:   03 00 XX (XX = error code)
```

---

## Commands

### Command Bytes

| Command | Value | Description |
|---------|-------|-------------|
| READ | 0x01 | Read configuration value |
| WRITE | 0x02 | Write configuration value |
| ENUMERATE | 0x03 | List configs (hypothetical) |

### Status Codes

| Status | Value | Description |
|--------|-------|-------------|
| SUCCESS | 0x00 | Operation completed |
| INVALID_ID | 0x01 | Config ID not found |
| PERMISSION_DENIED | 0x02 | Secure config, auth required |
| CRC_ERROR | 0x03 | Invalid CRC checksum |
| INVALID_LENGTH | 0x04 | Data length mismatch |

---

## Python Implementation

### Read Config

```python
import socket
import struct

GATEWAY_IP = "192.168.90.102"
GATEWAY_PORT = 3500

def read_config(config_id: int) -> bytes:
    """Read a configuration value from Gateway."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2.0)
    
    # Build read packet
    packet = struct.pack('<H', 3)  # Length = 3
    packet += bytes([0x01])        # Command = READ
    packet += struct.pack('>H', config_id)  # Config ID (BE)
    
    sock.sendto(packet, (GATEWAY_IP, GATEWAY_PORT))
    response, _ = sock.recvfrom(1024)
    
    # Parse response
    length = struct.unpack('<H', response[:2])[0]
    status = response[2]
    data = response[3:] if len(response) > 3 else b''
    
    if status != 0x00:
        raise Exception(f"Read failed with status {status:#x}")
    
    return data
```

### Write Config (Insecure Only)

```python
def calculate_crc8(config_id: int, data: bytes) -> int:
    """Calculate CRC-8 with polynomial 0x2F."""
    POLY = 0x2F
    crc = 0x00
    
    # Process config ID (big-endian)
    for byte in config_id.to_bytes(2, 'big'):
        crc ^= byte
        for _ in range(8):
            if crc & 0x80:
                crc = ((crc << 1) ^ POLY) & 0xFF
            else:
                crc = (crc << 1) & 0xFF
    
    # Process data
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x80:
                crc = ((crc << 1) ^ POLY) & 0xFF
            else:
                crc = (crc << 1) & 0xFF
    
    return crc

def write_config(config_id: int, data: bytes) -> bool:
    """Write a configuration value to Gateway (insecure configs only)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2.0)
    
    crc = calculate_crc8(config_id, data)
    
    # Build write packet
    length = 3 + 1 + len(data)  # cmd + id + crc + data
    packet = struct.pack('<H', length)  # Length
    packet += bytes([0x02])             # Command = WRITE
    packet += struct.pack('>H', config_id)  # Config ID (BE)
    packet += bytes([crc])              # CRC-8
    packet += data                      # Data
    
    sock.sendto(packet, (GATEWAY_IP, GATEWAY_PORT))
    response, _ = sock.recvfrom(1024)
    
    status = response[2] if len(response) > 2 else 0xFF
    return status == 0x00
```

---

## Config Unlock (Magic Bytes)

Some sources indicate a "config unlock" command exists:

### Unlock Command

```
Hex: 18 BA BB A0 AD
```

### Usage

```bash
echo "18babba0ad" | xxd -r -p | socat - udp:192.168.90.102:3500
```

**Expected Response:** Echo of sent payload indicates success.

**Note:** This may be required before writing certain configs. Status: ⚠️ UNVERIFIED

---

## Common Operations

### Read VIN

```python
vin = read_config(0x0000)
print(f"VIN: {vin.decode('ascii')}")
# Output: VIN: 7SAYGDEEXPA052466
```

### Read Map Region

```python
region = read_config(0x0014)
print(f"Region: {region[0]}")
# 0 = US, 1 = EU, 3 = CN, etc.
```

### Change Map Region

```python
# Set to EU (requires insecure config access)
success = write_config(0x0014, bytes([0x01]))
print(f"Write success: {success}")
```

### Read Firmware Hash

```python
hash1 = read_config(0x0025)
print(f"Hash 1: {hash1.hex()}")
```

---

## Using gateway_database_query.py

### Read Command

```bash
python3 scripts/gateway_database_query.py read 0x0000
# Output: 7SAYGDEEXPA052466
```

### Write Command

```bash
python3 scripts/gateway_database_query.py write 0x0014 01
# Sets map region to EU
```

### Scan Range

```bash
python3 scripts/gateway_database_query.py scan 0x0000 0x00A1
# Reads all configs in range
```

---

## Security Considerations

### Accessible Without Authentication

- Any device on 192.168.90.0/24 can read ALL configs
- Any device can write INSECURE configs (map region, units, etc.)
- No encryption, no authentication on UDP protocol

### Protected Against

- Writing SECURE configs (VIN, country, supercharger) - returns PERMISSION_DENIED
- Invalid CRC values - returns CRC_ERROR

### Attack Surface

```
Modem (192.168.90.60) → Can read/write insecure Gateway configs
Tuner (192.168.90.30) → Can read/write insecure Gateway configs
Any compromised device → Full insecure config access
```

---

## Wireshark Filter

```
udp.port == 3500 && ip.addr == 192.168.90.102
```

---

## Cross-References

- [Config System](config-system.md) - Config ID reference
- [Security Model](security-model.md) - Secure vs insecure configs
- [CAN Flood Attack](../5-attacks/can-flood.md) - Alternative access via port 25956

---

**Status:** VERIFIED ✅  
**Evidence:** Protocol analysis, working scripts  
**Last Updated:** 2026-02-07
