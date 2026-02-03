# KB Frontmatter Convention

Add this optional YAML frontmatter at the top of any markdown doc to make indexing reliable:

```yaml
---
title: "Gateway CAN flood → updater port 25956"
date: "2026-02-02"
vehicle:
  platform: "MCU2"      # MCU2 | ICE | APE | GTW | Modem | Unknown
  model: "S/X"          # S/X | 3/Y | Unknown
components: ["gateway", "updater", "can"]
ports:
  - { port: 25956, proto: "tcp", purpose: "CID updater shell" }
  - { port: 3500, proto: "udp", purpose: "Gateway UDPAPI" }
tags: ["exploit", "diagnostics", "handshake"]
confidence: 0.8
sources:
  - kind: "file"
    ref: "/root/tesla/scripts/openportlanpluscan.py"
  - kind: "firmware"
    ref: "/root/downloads/mcu2-extracted/..."
---
```

## Field meanings
- `title`: Human name for the entry.
- `vehicle.platform`: Where this applies.
- `components`: High-level area.
- `ports`: Structured list of ports mentioned.
- `tags`: Search labels.
- `confidence`: 0.0–1.0.
- `sources`: What backs the claim.
