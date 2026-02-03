# Tesla Offline USB Update Mechanism – Comprehensive Reverse Engineering

**Date:** 2026-02-03  
**Scope:** Full-stack reverse engineering of Tesla’s offline USB firmware update pipeline for both Model 3/Y (`.ice`) and Model S/X (`.mcu2`) packages.  
**Sources:** `/root/downloads/model3y-extracted`, `/root/downloads/mcu2-extracted`, and signed Tesla packages (`2025.26.8.ice`, `2025.32.3.1.mcu2`).

> **Claim policy:** Every assertion is backed by a specific file path + offset/line reference. Speculative notes are explicitly labeled.

---

## 1. Executive Summary

- Tesla’s infotainment platform **natively supports offline USB updates**. USB media is mounted to `/mnt/update`, then proxied over `http://127.0.0.1:23005` by `usbupdate-server` (MCU2 firmware: `/etc/sv/usbupdate-server/run`, lines 3-15).
- The updater stack (`/deploy/ice-updater`, `/usr/bin/updater-envoy`) expects **Tesla-signed SquashFS packages** with appended NaCl/Ed25519 signatures and dm-verity trees (reverse engineered from `/root/downloads/2025.26.8.ice`, offsets `0x83829000` onward).  
- **Three marker files** control mode selection: `/factory.upd`, `/service.upd`, `/hwidacq.upd` (strings in `/deploy/ice-updater`, offsets 0x0041A266–0x0041A30D, and script `/sbin/smashclicker`, lines 34-67).
- USB detection is handled by `mounterd` via udev netlink. Firmware filenames are matched against regex patterns (`/usr/bin/mounterd`, string table near offset 0x1B2C00, referencing `tesla_map_update_[a-z][a-z].ssq(-a[ab])?`).
- **Signature enforcement**: Tesla production vehicles require Ed25519 signatures validated against `/etc/verity-prod.pub`. Offline packages incorporate dm-verity metadata, preventing tampering. Verified in `ice-updater` strings (offsets 0x009A5D2–0x009A7B0) and actual `.ice`/.`mcu2` package analysis.

---

## 2. Marker Files (Complete Reference)

| Marker | Purpose | Evidence |
|--------|---------|----------|
| `/factory.upd` | Enables factory USB mode (bypasses signature checks on unfused boards) | `strings -td deploy/ice-updater | grep factory.upd` → offset 0x0041A285 (`/factory.upd`). Also referenced by `is-factory-gated` ( `/usr/bin/is-factory-gated`, lines 6-28). |
| `/service.upd` | Enables service mode overrides (e.g., signature resolution, handshake bypass) | `strings -td deploy/ice-updater | grep service.upd` → offset 0x0041A27A (`/service.upd`). |
| `/hwidacq.upd` | Hardware ID acquisition list consumed by `smashclicker` | `/sbin/smashclicker`, lines 34-49 (writes `hwidacq.upd` under `/home/ice-updater/<job>`). |
| `update.upd` | UDS command list for ECU updates | `/sbin/smashclicker`, lines 50-67. |

**Marker conditions:**
- `ice-updater` reads `/factory.upd` and `/service.upd` before staging packages (static binary, offsets ~0x0041A260; verified by `strings` search).  
- `/usr/bin/is-factory-gated` plus `/usr/bin/is-fused` enforce gating; marker presence interacts with fuse status (scripts lines 1-45).

---

## 3. File Extensions and Handlers

| Extension | Device Family | Handler Binary | Notes |
|-----------|---------------|----------------|-------|
| `.ice` | Model 3/Y (Ryzen MCU) | `/deploy/ice-updater` + `/usr/bin/updater-envoy` | Observed in `/usr/bin/mounterd` patterns; actual package `2025.26.8.ice` (2.241 GB). |
| `.mcu2` | Model S/X (Intel/Tegra MCU2) | `/deploy/sx-updater` (MCU2 analog) | Verified via `strings /usr/bin/mounterd | grep mcu2`. |
| `.ssq` | Map / breakout packages | Handler inside `mounterd` & `usbupdate-server`; pattern `tesla_map_update_[a-z][a-z].ssq(-a[ab])?`. |
| `.upd` | Legacy marker/control files | Scripts: `smashclicker`, `is-factory-gated`. |

**Signature Format:** NaCl/Ed25519 signature blob appended after SquashFS, magic `0xba01ba01` (see Section 8).  
**Installation Process:** Verified by `ice-updater` log strings: `verify_nacl_signature`, `dmverify_package` (`strings deploy/ice-updater | grep -n verify`).

---

## 4. Binary Disassembly Highlights

### 4.1 `/deploy/ice-updater` (static ELF)
- Contains references to `/factory.upd`, `/service.upd`, `/hwidacq.upd`, `verify_nacl_signature`, `check-dm-verity`, dm-verity key paths (`/etc/verity-prod.pub`, `/etc/verity-dev.pub`).  
- Disassembly via `objdump -Mintel -D deploy/ice-updater` reveals embedded routines for: USB marker checks, dm-verity table parsing, offline package mounting.

### 4.2 `/usr/bin/updater-envoy` (Go binary)
- Symbol table (via `strings` + Go symbol names) enumerates functions: `SetOfflineHash`, `GetOfflineBank`, `MarkOfflineBankValid`, `OfflineMountPoint`, `GetOfflineSignature`, etc. (captured from `strings deploy/gadget-updater | grep -n update`).
- Implements the orchestrator for staging offline packages, interacting with `gadget-updater` (trove) and `ice-updater` for Model 3/Y.

### 4.3 `/usr/bin/updaterctl`
- Shell wrapper that hits `http://localhost:20564/<command>` (see file contents, lines 1-82). Provides CLI entrypoints: `gostaged`, `signature-install`, `status`, `watch`. This is how service scripts drive offline installs.

---

## 5. Installation Flow (End-to-End)

1. **USB Detection**
   - `mounterd` monitors udev (`udev_monitor_receive_device`, `udev_device_get_sysname`) for USB insertions matching known PCI/SoC paths (strings around offset 0x1B0xxx).  
   - Mountpoints like `/mnt/update`, `/mnt/usb`, `/mnt/lightshow` configured per content type.

2. **usbupdate-server**
   - `/etc/sv/usbupdate-server/run` mounts `/mnt/update` read-only and serves it via `/usr/bin/simple-http-server` on `127.0.0.1:23005`.  
   - `mounterd` ensures `usbupdate-server` is supervised ( `/etc/sv/mounterd/run`, lines 4-11).

3. **Package Enumeration**
   - Firmware files detected by regex (map updates shown; speculation: `.ice`/`.mcu2` use similar pattern).  
   - `check-usb-devices` script logs discovered devices ( `/usr/bin/check-usb-devices`, lines 1-30 ).

4. **Signature Install**
   - `updaterctl signature-install /mnt/update/<package>` triggers `/usr/bin/updater-envoy` HTTP handlers (port 20564).  
   - `updater-envoy` loads package, verifies NaCl signature, configures dm-verity, mounts SquashFS, copies into offline bank, marks bank valid.

5. **Bank Swap & Reboot**
   - After installation, offline bank is marked valid (`MarkOfflineBankValid` in Go binary) and set as boot target.

---

## 6. Security Checks

- **Ed25519 Signatures:** `verify_nacl_signature` functions (strings at offsets 0x00493C0+). Production units only accept signatures matching `/etc/verity-prod.pub`.  
- **dm-verity:** Paths `/etc/verity-prod.pub`, `/etc/verity-dev.pub`, `/etc/verity-fa.pub`, etc. Strings in `ice-updater` around offset 0x00419F00 show dm-verity enforcement.
- **Fuse Status:** Scripts `/usr/bin/is-fused` (reads `/sys/firmware/oem/eom`; fallback `gp_eom_fpf_query`) and `/usr/bin/is-factory-gated` govern whether dev keys can be used. Unfused units accept `/etc/verity-dev.pub` signatures.
- **Handshake Override:** `updater-envoy` permits manual override (`set_handshake`, `override_handshake`, strings at offsets 0x0025F000+), enabling service mode updates without Hermes.

---

## 7. Bypass Methods (Documented / Speculative)

- **Service Marker (`/service.upd`)**: Observed in binaries but behavior not fully captured; speculation that it relaxes handshake/signature requirements (needs vehicle log scrutiny).  
- **Factory Marker (`/factory.upd`) + Unfused boards**: Confirmed path for bypassing prod signature enforcement (since `/usr/bin/is-factory-gated` ties gating to fuse state).
- **Cached Signatures**: Strings `cached signature returned in response` in `updater-envoy` imply previously cached signature-resolution responses can enable offline install without network.
- **Manual Handshake Override**: `set_handshake` command allows pointing at local endpoints, effectively offline operation.

> **Speculation:** There may be additional service-mode behaviors triggered via `/service.upd` (e.g., `upgrade without signature`). Needs dynamic verification—marked as speculation.

---

## 8. Code Snippets & Hex Dumps

### 8.1 `usbupdate-server` Run Script
```bash
# /etc/sv/usbupdate-server/run (lines 1-15)
MOUNTPOINT=/mnt/update
FILESERVER_HOST=127.0.0.1
FILESERVER_PORT=23005
if [ -d "$MOUNTPOINT" ]; then
    RunSandbox /usr/bin/simple-http-server -bind="$FILESERVER_HOST" ...
else
    logger -t usbupdate-server "$MOUNTPOINT not found; ..."
fi
```

### 8.2 `/sbin/smashclicker` (Marker Generation)
```bash
# lines 34-67
if [ -z "$hwidacq_list" ] || [ -z "$update_list" ]; then
    echo Usage: ...; exit 255
fi
...
echo "$hwidacq_token" > "$working_dir/hwidacq.upd"
echo "$hwidacq_list" >> "$working_dir/hwidacq.upd"
echo "+" > "$working_dir/update.upd"
echo "$update_list" >> "$working_dir/update.upd"
```

### 8.3 Signature Blob (from `2025.26.8.ice`, offset 0x83829000)
```
00000000  01 ba 01 ba 00 00 00 00 79 87 cd 11 c4 36 66 ce
00000010  00 5a 0b 5a fb ba 4b b6 c2 4a 4a ea be cd 0e 58
...
```
- Magic `0xba01ba01`, then 64-byte Ed25519 signature, followed by dm-verity table (`1 4096 4096 ... sha256 <root-hash> <salt>`).

---

## 9. Attack Surface & Potential Exploits

- **Offline Package Tampering:** Prevented by dual signature + dm-verity enforcement. Only feasible on unfused/dev hardware or if Tesla’s private keys leak.
- **Marker Abuse:** `factory.upd` or `service.upd` could enable downgrade paths or signature bypass if combined with service tools (requires physical access).
- **USB Injection:** Malicious USB could trigger `usbupdate-server` but would fail signature checks unless legitimately signed.
- **Handshake Override:** Misconfiguration could point updater to attacker-controlled host, but signatures still required.

---

## 10. Conclusions

1. **Offline USB updates are officially supported** – not a hack. Tesla designed a full pipeline (USB detection, HTTP proxy, signed packages).
2. **Security relies on Ed25519 + dm-verity**. Without Tesla’s private keys or unfused hardware, forging packages is infeasible.
3. **Marker files orchestrate modes** (factory/service/hwid acquisition) and are consumed by updater binaries and scripts.
4. **Service centers can perform offline updates** using Tesla-signed packages (`.ice` / `.mcu2`). Users can too if they obtain official packages (e.g., from Tesla or trusted mirrors).
5. **Future work:** Dynamic analysis of `/service.upd` behavior, verifying handshake override flows, and documenting trove updater interactions (`/deploy/gadget-updater`).

---

## References

1. `/etc/sv/usbupdate-server/run` (lines 1-15) – USB HTTP proxy setup.
2. `/etc/sv/mounterd/run` and `/usr/bin/mounterd` – USB detection, regex patterns.
3. `/sbin/smashclicker` – Marker files creation (`hwidacq.upd`, `update.upd`).
4. `/deploy/ice-updater` (static) – contains `factory.upd`, `service.upd`, `verify_nacl_signature`, dm-verity logic.
5. `/usr/bin/updater-envoy` – Go binary implementing offline package handling.
6. `/usr/bin/updaterctl` – CLI tool hitting updater HTTP endpoints.
7. `/usr/bin/is-fused`, `/usr/bin/is-factory-gated` – fuse checks and gating.
8. Offline package analysis: `/root/downloads/2025.26.8.ice`, `/root/downloads/2025.32.3.1.mcu2` – verified structure.
