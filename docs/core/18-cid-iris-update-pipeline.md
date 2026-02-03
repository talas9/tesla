# MCU2 CID / Iris Update Pipeline (Evidence-Only)

## /usr/local/bin/iris-fw-upgrade.sh
- Initializes paths for CID packages by scanning `/home/cid-updater/iris-*.ssq` and fallback `/opt/games/usr/iris-*.ssq`, sets loader `/usr/local/bin/iris-fw-ssq-load.sh`, and uses `/deploy/iris` as package root, confirming it expects `iris-*.ssq` plus SKU-specific files under `/deploy/iris` (`${MODEM_SKU}.version`).【/firmware/mcu2-extracted/usr/local/bin/iris-fw-upgrade.sh†L5-L24】【/firmware/mcu2-extracted/usr/local/bin/iris-fw-upgrade.sh†L130-L159】
- Mounts SSQ via `iris-fw-ssq-load.sh --load <pkg>` and later unmounts, showing reliance on verity-protected SSQ packages; signature check compares `/deploy/iris-<SKU>.sig` tail data against the SSQ, meaning artifacts include `.ssq` and `.sig` pairs.【/firmware/mcu2-extracted/usr/local/bin/iris-fw-upgrade.sh†L97-L122】【/firmware/mcu2-extracted/usr/local/bin/iris-fw-upgrade.sh†L124-L166】
- Performs modem SKU detection, signature-domain matching, and triggers `/usr/bin/QFirehose -f /deploy/iris/<TARGET_FW>` attempts (with EDL fallback), demonstrating the binary payloads are QFirehose-compatible firmware directories under `/deploy/iris` keyed by version strings.【/firmware/mcu2-extracted/usr/local/bin/iris-fw-upgrade.sh†L167-L258】【/firmware/mcu2-extracted/usr/local/bin/iris-fw-upgrade.sh†L260-L333】
- Exposed via AppArmor escalator abstraction: `/usr/local/bin/iris-fw-upgrade.sh PUx` indicates escalation contexts can execute it.【/firmware/mcu2-extracted/etc/apparmor.d/abstractions/escalator/exec†L97】

**Invocation / Triggers**
- Not directly tied to a runit service; instead accessible to escalator and likely triggered by service-shell tasks or firmware update flows (given AppArmor profile). No dedicated service referencing it was found.

**Artifacts Expected**
- `/home/cid-updater/iris-*.ssq` (primary), `/opt/games/usr/iris-*.ssq` (backup), `/deploy/iris/<MODEM_SKU>.version`, `/deploy/iris-<MODEM_SKU>.sig`, plus QFirehose image directories under `/deploy/iris` (named by version string).

## /usr/local/bin/iris-fw-ssq-load.sh
- Provides `--load/--unload` around `ssq-util`, defaulting to `/home/cid-updater/iris-*.ssq`, Device Mapper target `iris-modem`, and keys `/etc/verity-modem-{prod,dev}.pub`; chooses dev key when unfused (`is-fused` returns 1).【/firmware/mcu2-extracted/usr/local/bin/iris-fw-ssq-load.sh†L3-L52】【/firmware/mcu2-extracted/usr/local/bin/iris-fw-ssq-load.sh†L89-L123】
- Enforces cleanup (loopback, dm, mount) before load, meaning it expects SSQ images with dm-verity metadata and matching pubkeys (i.e., `.ssq` packages signed against `/etc/verity-modem-*.pub`).【/firmware/mcu2-extracted/usr/local/bin/iris-fw-ssq-load.sh†L56-L117】

**Invocation / Triggers**
- Called by `iris-fw-upgrade.sh` for load/unload; no standalone service references located (only via upgrade script).

**Artifacts Expected**
- Same SSQ files as above, plus verity pubkeys installed at `/etc/verity-modem-{prod,dev}.pub`.

## /usr/bin/load-breakouts
- Determined boot bank by parsing `/proc/cmdline` and uses `/usr/bin/breakout-loader --spec-file /deploy/breakout-spec.json --install-dir /home/cid-updater --install-dir /opt/games/usr --load-dir /run/breakouts`, verifying breakout bundles land in `/home/cid-updater` (primary) and `/opt/games/usr` (secondary).【/firmware/mcu2-extracted/usr/bin/load-breakouts†L1-L28】
- Signed via `/etc/verity-breakout-prod.pub` with optional dev key (if `is-fused --no-fuse-sentinel` returns 1), showing `.ssq`-style breakout artifacts validated under `/deploy/breakout-spec.json` and staged into `/home/cid-updater` directories (likely `ape.ssq`, `ice.ssq`).【/firmware/mcu2-extracted/usr/bin/load-breakouts†L20-L28】

**Invocation / Triggers**
- /etc/runit/1 executes `run /usr/bin/load-breakouts` during early boot before userland services, ensuring breakout SSQs mount automatically.【/firmware/mcu2-extracted/etc/runit/1†L24-L34】
- /etc/runit/3 invokes `/usr/bin/unload-breakouts` during shutdown, mirroring load/unload lifecycle.【/firmware/mcu2-extracted/etc/runit/3†L12-L20】

**Artifacts Expected**
- `/deploy/breakout-spec.json` (manifest), breakout SSQ files under `/home/cid-updater` and `/opt/games/usr` (including `ape.ssq`, `ice.ssq` referenced elsewhere), plus `url-for-*` signature downloads that accompany them (see cleanups below).

## /deploy/common-post-install-fixups.sh
- Performs cleanup of CID updater staging: deletes `/home/cid-updater/ape.ssq`, `/home/cid-updater/ice.ssq`, and prunes `url-for-*` downloads if total >1GB, showing these artifacts accumulate in the updater home directory and may be removed post-install.【/firmware/mcu2-extracted/deploy/common-post-install-fixups.sh†L72-L85】
- Resets ownership (`chown -R 6887:6887 /home/cid-updater`), meaning services expect cid-updater user/group to own the SSQs/signatures afterwards.【/firmware/mcu2-extracted/deploy/common-post-install-fixups.sh†L76-L83】

**Invocation / Triggers**
- Part of `/deploy` scripts run after OTA installation (common fixups). Not directly tied to a runit service but executed by installer workflow.

**Artifacts Expected**
- `/home/cid-updater/{ape.ssq, ice.ssq}`, `url-for-*` signature files, general ssq downloads.

## /home/cid-updater References & Cleanup
- `update-cleanup-tasks` removes partial downloads in `/home/cid-updater/iris-cache.ssq.*`, `*.download*`, `.reconstituted`, `patch`, `staging/*.download*`, plus matching paths under `/opt/games/usr`, confirming repeated handshake/partial download artifacts accumulate there.【/firmware/mcu2-extracted/usr/local/bin/update-cleanup-tasks†L38-L64】
- AppArmor abstraction `service-shell-service-engineering` grants read to `/home/cid-updater/*` and `staging/*`, implying service-shell tasks (engineering tools) inspect those artifacts.【/firmware/mcu2-extracted/etc/apparmor.d/abstractions/service-shell-service-engineering†L445-L476】

## Abl IFWI Dispatch (/sbin/abl_update_dispatch)
- Binary uses `heci_ifwi_update_stage/clear` to stage Intel IFWI updates from `DEV:PART:FILE` arguments (DEV=2 eMMC, DEV=4 SD) or `clear`. Strings show CLI usage and error handling; it opens HECI (ME) to stage updates for boot firmware (ABL).【/firmware/mcu2-extracted/sbin/abl_update_dispatch†strings】
- No service references found; likely invoked from OTA installer or maintenance scripts when bootloader updates are present (not in runit). Accepts path triplets pointing to `iasUpdate`-style files as seen in `update-cleanup-tasks` (same script cleans `/mnt/mmcblk0p1/iasUpdate`).【/firmware/mcu2-extracted/usr/local/bin/update-cleanup-tasks†L65-L117】【/firmware/mcu2-extracted/sbin/abl_update_dispatch†strings】

**Artifacts Expected**
- IFWI blobs staged on removable/eMMC partitions (e.g., `/dev/mmcblk0p1` containing `iasUpdate`), along with HECI support libraries (`libheci.so`).

## Abl / Update Dispatch Under /sbin
- Only `/sbin/abl_update_dispatch` found; no other `*update_dispatch` binaries present under `/sbin` (search results limited to this file).【/firmware/mcu2-extracted/sbin†listing】【strings output above】

## Summary of Artifact Flow
1. **Breakout SSQs**: `load-breakouts` (boot) uses `/deploy/breakout-spec.json` to mount breakouts into `/home/cid-updater` and `/opt/games/usr`. `common-post-install-fixups` cleans `ape.ssq`, `ice.ssq`, and their `url-for-*` signatures afterward.
2. **Iris Modem Firmware**: `iris-fw-upgrade.sh` loads `/home/cid-updater/iris-*.ssq` via `iris-fw-ssq-load.sh`, verifies against `/deploy/iris-<sku>.sig`, extracts target firmware version files (`/deploy/iris/<sku>.version`), then flashes QFirehose packages from `/deploy/iris/<target_fw>`.
3. **Maintenance / Cleanup**: `update-cleanup-tasks` and AppArmor policies expect numerous temporary files under `/home/cid-updater` (`*.download*`, `.ssq`, `url-for-*`), ensuring only validated SSQs remain.
4. **Bootloader IFWI**: `abl_update_dispatch` stages/clears low-level FW updates using HECI, with supporting scripts cleaning `/mnt/mmcblk0p1/iasUpdate` (Intel bootfs) afterwards.

All findings are evidence-only, citing extracted firmware paths above.