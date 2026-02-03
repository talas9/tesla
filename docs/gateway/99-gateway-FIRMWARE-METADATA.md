# Gateway Firmware Metadata

**File:** ryzenfromtable.bin
**Size:** 6,225,920 bytes (5.94 MB)

---

## File Statistics

- **Total bytes:** 6,225,920
- **Strings (ASCII):** 37,672
- **Strings (UTF-16):** 30
- **CAN/Config entries:** 6,647
- **Null bytes:** 0 (0.0%)
- **FF bytes (padding):** 0 (0.0%)

## Boot Information

- **Entry point:** 0xf9006c
- **Reboot magic:** 0xDEADBEEF at offset 0x2C
- **Boot vector size:** 256 bytes

## Processor Architecture

- **ISA:** PowerPC (big-endian)
- **CPU:** NXP MPC5748G (e200 core)
- **RTOS:** FreeRTOS (detected from strings)

## Network Configuration

- **MCU endpoint:** 192.168.90.100:20564
- **UDP API port:** 3500
- **TFTP port:** 69 (xferTask)

## Cryptographic Features

- **SHA-256:** Constants found at 0x36730
- **CRC-8:** Polynomial 0x2F (11,512 occurrences)
- **Config signature:** CRC-8 used for config validation

## Key Offsets

| Offset | Content |
|--------|----------|
| 0x2C | DEADBEEF magic (reboot) |
| 0x36730 | SHA-256 constants |
| 0x401150 | Config name strings |
| 0x402000 | FreeRTOS strings |
| 0x402400 | Config ID array |
| 0x403000 | CAN/Config metadata table |
