# Gateway Research Documentation

This section contains complete reverse engineering of Tesla's Gateway ECU.

## Core Gateway Documents

### Configuration & Database
- **77-gateway-config-database-REAL.md** - Complete config database (662 configs from real vehicle)
- **80-ryzen-gateway-flash-COMPLETE.md** - Gateway flash dump analysis
- **81-gateway-secure-configs-CRITICAL.md** - Security model (UDP/Hermes/GTW)
- **92-config-metadata-table-FOUND.md** - Config metadata structures

### Firmware Analysis
- **76-gateway-app-firmware-REAL.md** - Gateway firmware analysis
- **79-gateway-flash-dump-JTAG.md** - JTAG extraction methods
- **88-gateway-strings-analysis.md** - String table extraction
- **89-gateway-config-metadata-extraction.md** - Metadata parsing
- **91-gateway-powerpc-disassembly-summary.md** - PowerPC disassembly

### Security & Protocols
- **82-odin-routines-database-UNHASHED.md** - Odin service database
- **78-update-signature-extraction-TOOL.md** - Signature tools

## Organization Notes

**Config Data Split:**
- IDs 0x0000-0x01FF: Vehicle configuration data (VIN, country, features)
- IDs 0x4000-0x7FFF: CAN message data (multi-byte sensor values)

**Security Levels:**
1. **Insecure (UDP)** - Readable/writable via UDP:3500
2. **Secure (Hermes)** - Requires Tesla auth (VIN, country, features)
3. **Hardware-locked (GTW)** - Only writable with dev security level unlocked

See **81-gateway-secure-configs-CRITICAL.md** for complete security model.
