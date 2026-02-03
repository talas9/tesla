# Key Programming / VCSEC (Research Notes)

## Scope
This document summarizes **what we can confirm from artifacts** about key/keycard programming flows, without providing misuse-ready instructions.

## What we know
- Model 3/Y uses **VCSEC** (Vehicle Security Controller) for key management and whitelisting.
- Many key/security operations in ODJ definitions require **high security levels** (often level 5) and are designed for authorized service tooling.
- Firmware/UI side references indicate:
  - Dedicated service workflows for key pairing / provisioning.
  - Principal-/role-based permissions (service vs security operations).

## Confirmed related routines (from ODJ / tasks catalog)
Examples observed in the task catalog (Model X / BCCEN world, shown as evidence of tooling structure):
- `PROC_BCCEN_X_AUTO-PAIRING` (pair key fob)
- `PROC_BCCEN_X_GET-PAIRED-KEYFOBS`
- `PROC_BCCEN_X_UNPAIR-KEY`
- `PROC_BCCEN_X_PROVISIONING` (VIN learning / provisioning)

For Model 3/Y, the analogous workflows are expected under **VCSEC** routines in:
- `/firmware/tesla_odj/Model 3/VCSEC.odj.json`
- `/firmware/tesla_odj/Model Y/VCSEC.odj.json`

## Open questions (to resolve next)
1. Identify the **exact VCSEC routines** that correspond to:
   - “add keycard” (with existing keys)
   - “all keys lost” / emergency pairing
   - offline vs online enablement requirements
2. Determine if “engineering mode” changes:
   - accepted security level
   - availability of special routines (e.g., key add without prior key)
3. Map any UI entry points (service mode menus) to underlying Odin tasks.

## Next steps
- Extract a focused list of VCSEC routines by name/id and tag by security level.
- Cross-reference with Odin Python tasks for any key-related “service security operations” principal usage.

## References
- ODJ repository cloned: `/firmware/tesla_odj/`
- Prior doc: `/research/00-master-cross-reference.md`
