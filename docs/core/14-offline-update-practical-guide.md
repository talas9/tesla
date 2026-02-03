# Tesla Offline Update Practical Guide (Evidence-Based)

_All technical claims below reference primary artifacts gathered from an MCU2 filesystem extraction. Citations identify the source file and the exact excerpt backing each statement. Gaps with no primary evidence are called out as TODO items._

## 1. Scope & Current Inputs
- Confirmed sources: `/research/10-usb-firmware-update-deep.md` and `/research/13-ota-handshake-protocol.md`.
- Pending sources: `/research/15-updater-component-inventory.md` and `/research/16-offline-update-format-notes.md` were not present at the time of this rewrite (TODO placeholders retained where their findings should land).

## 2. Evidence Inventory — What Is Proven Today

| Capability | Evidence (file → excerpt) | Notes |
| --- | --- | --- |
| Dedicated firmware USB mount served over HTTP | `/research/10-usb-firmware-update-deep.md` → “`MOUNTPOINT=/mnt/update … RunSandbox /usr/bin/simple-http-server … -dir="$MOUNTPOINT" … FILESERVER_PORT=23005`” | Establishes `/mnt/update` and localhost file server `127.0.0.1:23005` for USB payloads. |
| mounterd controls usbupdate-server and supervises `/mnt/update` | `/research/10-usb-firmware-update-deep.md` → “`/usr/bin/mounterd` contains `/mnt/update` and `usbupdate-server` … `/etc/sv/mounterd/run` ensures supervise dirs exist” | Shows kernel event monitor ties USB insertion to update mount + file server. |
| USB detection & firmware filename heuristics | `/research/10-usb-firmware-update-deep.md` → “`Filename matches pattern for firmware update…`” and regex table plus vfat/GPT handling | Confirms `mounterd` filters USB content before mounting at `/mnt/update`. |
| Offline package mount path & dm-verity usage | `/research/10-usb-firmware-update-deep.md` → “`sx-updater` references `/dev/mapper/offline-package`… `dmsetup remove /dev/mapper/offline-package`” and “`VerityMount`, `GetVerityKeys`, `/etc/verity-prod.pub`” | Proves updater expects a dm-verity protected offline package validated with Tesla keys. |
| NaCl/Ed25519 signature verification for offline media | `/research/10-usb-firmware-update-deep.md` → “`verify_nacl_signature`, `nacl-verify.c`, `offline signature matched`” | Confirms offline packages must carry Tesla signatures. |
| Bootfs staging paths for offline IAS images | `/research/10-usb-firmware-update-deep.md` → “`/mnt/mmcblk0p1/offline-iasImage.*` … `/usr/local/bin/update-cleanup-tasks` removes `/mnt/mmcblk0p1/iasUpdate`” | Shows where validated payloads are staged before bank swap. |
| Factory/service USB gating markers | `/research/10-usb-firmware-update-deep.md` → “`factory_usb`, `factory_usb_check`, `/factory.upd`, `/service.upd`, `/hwidacq.upd`” | Establishes marker-file triggers for alternate update modes.
| Fusing gate behavior | `/research/10-usb-firmware-update-deep.md` → “`/usr/bin/is-factory-gated` calls `/usr/bin/is-fused` … `verifyrestrictions status=valid reason=unfused_board`” | Shows how unfused units bypass certain checks. |
| Handshake endpoint binds to localhost & can be overridden | `/research/10-usb-firmware-update-deep.md` → “`Handshake URL = http://%s:%s%s` (only 127.0.0.1 present) … `override_handshake` command” and `/research/13-ota-handshake-protocol.md` → state diagram & endpoint table | Confirms updater can be pointed at local/offline servers. |
| Signature resolution caching & replay | `/research/13-ota-handshake-protocol.md` → “`/packages/signature?signature=<base64>` … cached signature store `/run/updater/*`” | Demonstrates Tesla’s sigres cache enabling offline validation if entries exist. |

## 3. Unknown or Unverified Elements (Evidence Gaps)
1. **USB package exact filename & directory layout:** Regex hints exist, but no artifact definitively documents the production naming scheme or required companion files. _TODO: fill once `/research/16-offline-update-format-notes.md` lands._
2. **Tooling that creates `/dev/mapper/offline-package` from `/mnt/update`:** Evidence proves both endpoints exist, but the bridging utility (script/service) is not directly identified. _TODO: expect coverage in `/research/15-updater-component-inventory.md`._
3. **Concrete example of Tesla-signed offline package (hash, signature blob, manifest):** No sample package is available in current corpus. _TODO: capture once format notes delivered._
4. **Verified workflow for triggering offline install on fused production car without cached signatures:** Need direct log or command sequence demonstrating success.

## 4. Evidence-Tied Offline Update Workflow

```
[USB Prep]
    └─ Format as vfat (FAT32) on GPT media + place Tesla package using firmware regex + optional /service.upd marker
        Evidence: /research/10-usb-firmware-update-deep.md (“Supported filesystem: vfat … Filename matches pattern for firmware update”).
[Vehicle Detection]
    └─ mounterd hears udev netlink → validates filename → mounts at /mnt/update
        Evidence: same file (§8.1–8.3 “udev_monitor… Filename matches pattern… GUI_usbFirmwareUpdateMounted”).
[Local File Server]
    └─ usbupdate-server exposes /mnt/update via simple-http-server on 127.0.0.1:23005
        Evidence: /research/10-usb-firmware-update-deep.md (“FILESERVER_HOST=127.0.0.1 … RunSandbox /usr/bin/simple-http-server … -dir="$MOUNTPOINT"”).
[Package Validation]
    └─ sx-updater/updater-envoy mount package as /dev/mapper/offline-package with dm-verity + NaCl signature checks
        Evidence: same file (§2 & §5 “`/dev/mapper/offline-package` references … `VerityCreateDevice` … `verify_nacl_signature`”).
[Staging]
    └─ Validated images copied to /mnt/mmcblk0p1/offline-iasImage.* for later bank swap
        Evidence: /research/10-usb-firmware-update-deep.md (§3.2).
[Handshake + SigRes]
    └─ Updater communicates with localhost endpoints (20564 / 6789) and may override handshake host to local server if needed; signature cache consulted before mothership call
        Evidence: /research/10-usb-firmware-update-deep.md (§9.1–9.4) and /research/13-ota-handshake-protocol.md (§2–§3).
[Install]
    └─ Standard gostage/install sequence drives bank swap and reboot (same regardless of online/offline source)
        Evidence: /research/13-ota-handshake-protocol.md (§5.2 state machine).
```

> **Caveat:** The steps above document _what the platform supports_. Successfully executing them on a fused production vehicle still requires a Tesla-signed package carrying embedded NaCl signatures plus dm-verity metadata. Until a legitimate package is captured, these remain architectural steps rather than a tested procedure. (TODO-Verify with real media.)

## 5. Minimal Practitioner Checklist (Evidence-Backed)

1. **Obtain authentic Tesla offline package** with NaCl signature + dm-verity table. _Evidence:_ Updater refuses unsigned media, citing `verify_nacl_signature` & `/etc/verity-prod.pub` requirements `/research/10-usb-firmware-update-deep.md` (§5.1–5.2).
2. **Layout USB drive**
   - Partition + format as FAT32 on GPT (mounterd explicitly supports `vfat` and recognizes GUID tables). `/research/10-usb-firmware-update-deep.md` (§8.4).
   - Place package using firmware regex-friendly naming (exact regex TBD—current binary logs show pattern checks). `/research/10-usb-firmware-update-deep.md` (§8.3).
   - Add marker file (`/service.upd` for service installs or `/factory.upd` for unfused boards). `/research/10-usb-firmware-update-deep.md` (§4.1 & §9.4).
3. **Insert USB and confirm mount** via `mounterd` logs or UI banner “USB firmware update detected” (string evidence). `/research/10-usb-firmware-update-deep.md` (§8.2).
4. **Ensure handshake path resolves locally**
   - Default binding already uses localhost; service override endpoints exist if manual control required. `/research/10-usb-firmware-update-deep.md` (§9.1–9.3) and `/research/13-ota-handshake-protocol.md` (§2.4).
   - For cars lacking cached signatures, supply a reachable signature-resolution service via `set_handshake` or `override_handshake`. `/research/13-ota-handshake-protocol.md` (§7.4).
5. **Trigger gostage/install** through `updaterctl` or HTTP once package reports `Validated`. `/research/13-ota-handshake-protocol.md` (§5.2–§5.3).

## 6. TODOs & Open Investigations
1. **Offline package format sample** — Need first-hand capture of a Tesla USB firmware bundle (expect SquashFS + dm-verity table + NaCl signature blob). _Source placeholder:_ `/research/16-offline-update-format-notes.md` (not yet available).
2. **Updater component chain** — Document the precise daemon/service that ingests `/mnt/update` contents and calls `dmsetup` for `/dev/mapper/offline-package`. _Source placeholder:_ `/research/15-updater-component-inventory.md`.
3. **Regex specification** — Extract concrete firmware filename regex from `mounterd` disassembly/log output; current summary only notes existence. _TODO: produce command-output snippet once available._
4. **Production-car test** — Execute the workflow end-to-end on a fused MCU2 using a Tesla-signed USB package and capture updater logs proving success. _Mark result + logs before declaring full support._
5. **Service marker behavior** — Validate practical differences between `/factory.upd`, `/service.upd`, and `/hwidacq.upd` by observing updater state transitions. _Needs real log capture._

---
_This guide will be revised immediately when component inventory or offline-format notes are published. Until then, treat TODO items as blockers for a fully reproducible offline-update recipe._
