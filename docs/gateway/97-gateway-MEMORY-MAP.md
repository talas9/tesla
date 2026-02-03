# Gateway Firmware Memory Map

**Binary:** ryzenfromtable.bin (6,029,152 bytes)

---

## Memory Layout

| Address Range | Size | Content | Notes |
|---------------|------|---------|-------|
| 0x00000000-0x000000FF | 256B | Boot vector table | Entry point, exception vectors |
| 0x00000100-0x003FFFFF | ~4MB | .text section | Executable code (PowerPC) |
| 0x00400000-0x00401150 | 4.3KB | Unknown data | Padding or reserved |
| 0x00401150-0x00401800 | 1.7KB | Config name strings | 84+ null-terminated ASCII names |
| 0x00401800-0x00402000 | 2KB | Unknown data | Padding |
| 0x00402000-0x00402400 | 1KB | FreeRTOS strings | Task names, function names |
| 0x00402400-0x00402590 | 400B | Config ID array | 200 config IDs (0x0125-0x02FB) |
| 0x00402590-0x00403000 | 2.6KB | Unknown data | Padding |
| 0x00403000-0x00410000 | 53KB | **CAN/Config metadata** | 6,647 structured entries |
| 0x00410000-0x005FFFFF | ~2MB | Mixed data | Additional data sections |
| 0x00600000-End | ~512KB | Padding/unused | 0xFF padding |

---

## Boot Vector Table (0x00-0xFF)

| Offset | Value | Description |
|--------|-------|-------------|
| 0x00 | 0x5a0002 | Initial SP? |
| 0x10 | 0xf9006c | Reset vector |
| 0x2C | 0xDEADBEEF | **REBOOT MAGIC** |
| 0x50 | 0x40000020 | Exception handler |

---

## Key Data Structures

### Config Name Strings (0x401150)
- **Count:** ~84 names
- **Format:** Null-terminated ASCII
- **Examples:** mapRegion, chassisType, deliveryStatus

### Config ID Array (0x402400)
- **Count:** 200 entries
- **Format:** 16-bit big-endian
- **Range:** 0x0125-0x02FB

### CAN/Config Metadata (0x403000)
- **Count:** 6,647 entries
- **Format:** [prefix:2][id:2][value:4] (8 bytes)
- **Types:** CAN mailboxes, config defaults, register addresses

