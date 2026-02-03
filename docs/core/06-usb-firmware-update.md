# USB Firmware Update (Research Notes)

## Scope
This document summarizes **what the firmware indicates** about “offline / USB” update mechanisms (no step-by-step exploitation).

## Key artifacts observed
From `sx-updater` strings (MCU2 / S-X firmware):
- Mentions of **offline packages** and mounting:
  - `/dev/mapper/offline-package`
  - `/mnt/mmcblk0p1/offline-iasImage*`
  - `/mnt/mmcblk0p1/iasUpdate`
- Mentions of a **factory USB** concept:
  - `factory_usb`
  - `factory_usb_check`
- Package verification / staging concepts:
  - `verify_offline_and_stage`
  - `package_signature_invalid`
  - `verify_nacl_signature...`
  - `reported_offline_signature`
- Generic removable media mount points:
  - `/media/`

## Interpretation (from evidence)
- The updater appears to support an **“offline” package mode** (distinct from normal online update flows).
- There are explicit “factory USB” checks, suggesting an **intended manufacturing/service workflow** for loading packages when not using the normal online distribution pipeline.
- The presence of signature-verification strings implies that even in offline mode, packages are expected to be **cryptographically verified**.

## Next research steps
1. Locate the **run scripts** for updater services (runit) and identify the exact binaries involved:
   - `/etc/sv/sx-updater/run`
   - `/usr/bin/updaterctl` (if present)
   - `/usr/bin/updater-envoy` and its config
2. Search Odin bundle tasks for any explicit “offline update”, “USB update”, or “factory USB” tasks.
3. When we extract APE firmware, search for:
   - `factory_usb` / `offline-package` / `verify_offline_and_stage`
   - provisioning endpoints that might coordinate offline update.

## References
- Firmware extraction: `/firmware/mcu2-extracted`
- Related handshake notes (network install path): see `/research/02-gateway-can-flood-exploit.md`
