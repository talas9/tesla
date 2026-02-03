# MCU2 USB / Offline Firmware Update – Deep Dive (evidence-based)

Scope: determine whether MCU2 firmware can be installed “offline/from USB” via an intended (non-exploit) mechanism, and document concrete evidence of: mount points, expected file naming, gating checks (factory/fusing), and offline signature verification.

All statements below are backed by strings or logic found in the extracted MCU2 filesystem under `/firmware/mcu2-extracted`.

---

## 1) USB-related mountpoint and an on-device file server

### 1.1 `/mnt/update` is a defined mountpoint used by a dedicated service

* `/etc/sv/usbupdate-server/run`:
  * sets `MOUNTPOINT=/mnt/update`
  * serves it with `simple-http-server` on `127.0.0.1:23005`
  * if the directory does not exist, it logs and exits.

Evidence (excerpt):

```sh
MOUNTPOINT=/mnt/update
FILESERVER_HOST=127.0.0.1
FILESERVER_PORT=23005

if [ -d "$MOUNTPOINT" ]; then
    RunSandbox /usr/bin/simple-http-server -bind="$FILESERVER_HOST" -port="$FILESERVER_PORT" -dir="$MOUNTPOINT" -split_file_support;
else
    logger -t usbupdate-server "$MOUNTPOINT not found; usbupdate-server shutting down";
fi
```

### 1.2 `mounterd` explicitly references `/mnt/update` and `usbupdate-server`

* `/usr/bin/mounterd` contains the literal strings:
  * `/mnt/update`
  * `usbupdate-server`
  * `sv %s usbupdate-server failed! ...`

This is evidence that `mounterd` is aware of `/mnt/update` and controls (or attempts to control) the `usbupdate-server` runit service via `sv`.

* `/etc/sv/mounterd/run` additionally enforces that the `usbupdate-server` service supervision directory exists and adjusts permissions so `mounterd` can control it:

```bash
[ -d /service/usbupdate-server/supervise ] || exit 1

chmod 755 /service/usbupdate-server/{,log/}supervise/
chown mounterd /service/usbupdate-server/{,log/}supervise/{ok,control,status}
```

### 1.3 What mounts/populates `/mnt/update` is not identified in the artifacts searched

* `/etc/fstab` does **not** define a static mount for `/mnt/update`.
* A text-search of the extracted tree only found `/mnt/update` in:
  * `usbupdate-server` service scripts
  * `usbupdate-server` minijail sandbox var file
  * `mounterd` binary strings

No scripts/configs in the extracted tree explicitly describe:

* which block device/partition is mounted to `/mnt/update`
* what directory layout inside `/mnt/update` is expected
* which updater component consumes the `127.0.0.1:23005` file server

This remains an open linkage gap.

---

## 2) Confirmed “offline package” mechanism on device

Even without proving that `/mnt/update` is the source, there is strong on-device support for an **offline update package** mounted via dm-verity and associated signature verification.

### 2.1 `/dev/mapper/offline-package` is referenced by the updater stack

* `sx-updater` binary contains the literal path: `/dev/mapper/offline-package`
* `/usr/local/bin/restart-updater` removes it on cleanup:

```sh
... 
dmsetup remove /dev/mapper/offline-package
```

### 2.2 Updater-envoy (Go binary) contains explicit offline/verity/signature APIs

`/usr/bin/updater-envoy` (Go) includes strings and symbols indicating:

* Offline bank management:
  * `OfflineBank`, `GetOfflineBank`, `ResetOfflineBank`, `MarkOfflineBankValid`, `SwapOnlineOfflineBank`
* Offline mounting:
  * `OfflineMountPoint`, `MountOfflineSquashFS`, `UnmountOfflineIfMounted`
* dm-verity support:
  * `VerityMount`, `VerityCreateDevice`, `ReadVerityTable`, `ReadVerityMetaData`, `CalculateVerityOffset`
  * `GetVerityKeys` and named key types `VerityDev/Prov/Prod` and `VerityDevKey/VerityProvKey/VerityProdKey`
* Signature retrieval:
  * `GetOfflineSignature`, `ReadOfflineSignature`, `signatureAlgorithm`, `signatureDataHash`
* Use of Ed25519 and NaCl:
  * `crypto/ed25519`
  * `tesla/vendor/github.com/kevinburke/nacl`
  * `*nacl.Key`

This is direct evidence that the updater stack supports an “offline package” whose integrity is protected using dm-verity and signatures.

---

## 3) Confirmed naming/layout on boot filesystem for ias artifacts

The updater ecosystem uses a dedicated internal partition mounted at `/mnt/mmcblk0p1`.

### 3.1 Bootfs mountpoint

* `/etc/fstab`:

```
/dev/mmcblk0p1      /mnt/mmcblk0p1          ext2  ... ro,noauto
```

### 3.2 `sx-updater` hardcodes ias staging filenames on `/mnt/mmcblk0p1`

`/firmware/mcu2-extracted/deploy/sx-updater` contains literal strings indicating it expects these items on `/mnt/mmcblk0p1`:

* ias images:
  * `/mnt/mmcblk0p1/iasImage`
  * `/mnt/mmcblk0p1/iasImage.31`
  * `/mnt/mmcblk0p1/iasImage.63`
  * `/mnt/mmcblk0p1/iasImage.127`
  * `/mnt/mmcblk0p1/iasImage.255`
* “banked” images:
  * `/mnt/mmcblk0p1/bank_a.iasImage`
  * `/mnt/mmcblk0p1/bank_b.iasImage`
* “offline” image variants:
  * `/mnt/mmcblk0p1/offline-iasImage`
  * `/mnt/mmcblk0p1/offline-iasImage.31`
  * `/mnt/mmcblk0p1/offline-iasImage.63`
  * `/mnt/mmcblk0p1/offline-iasImage.127`
  * `/mnt/mmcblk0p1/offline-iasImage.255`
* ias update staging:
  * `/mnt/mmcblk0p1/iasUpdate`

### 3.3 There is a cleanup task that removes `/mnt/mmcblk0p1/iasUpdate`

* `/usr/local/bin/update-cleanup-tasks` mounts `/dev/mmcblk0p1` at `/mnt/mmcblk0p1` and removes the staged `iasUpdate` path.

Evidence (excerpt):

```sh
mount -t ext2 -o ro /dev/mmcblk0p1 /mnt/mmcblk0p1
...
rm -rf /mnt/mmcblk0p1/iasUpdate
```

---

## 4) Factory/USB gating indicators (evidence)

### 4.1 `sx-updater` contains explicit `factory_usb` / `factory_usb_check` strings

The `sx-updater` binary includes the literal strings:

* `factory_usb`
* `factory_usb_check`
* `/factory.upd`

This is strong evidence that `sx-updater` contains logic paths specifically related to a “factory USB” mode and a marker file `/factory.upd`.

### 4.2 There is an explicit “factory-gating” helper tied to fusing status

* `/usr/bin/is-factory-gated` is a shell script.
* It calls `/usr/bin/is-fused` and returns success if fused.
* If not fused, it may create a sentinel `/var/etc/in-factory` (when invoked with `--factory-sentinel`) and then fails.

Evidence (excerpt):

```sh
FACTORY_SENTINEL=/var/etc/in-factory
...
/usr/bin/is-fused "$@" && exit 0
...
touch "$FACTORY_SENTINEL"
...
exit 1
```

* `/usr/bin/is-fused` reads fuse state (primary from `/sys/firmware/oem/eom`, fallback via `/usr/bin/gp_eom_fpf_query`) and returns 0 when fused.

This provides an evidence-based explanation for how “factory gating” can be enforced on the device.

---

## 5) Offline signature verification: NaCl/Ed25519 + dm-verity keys

### 5.1 `sx-updater` includes NaCl signature verification routines

The `sx-updater` binary contains literal strings (selected):

* `nacl-verify.c`
* `verify_nacl_signature`
* `verify_signature_in_chunks`
* `verifysig status=... key=prod` and `verifysig status=... key=dev`

This is evidence that signature verification can be done using NaCl signatures (and sometimes chunked verification).

### 5.2 `sx-updater` references dm-verity public keys on disk

`sx-updater` contains these literal paths:

* `/etc/verity-fa.pub`
* `/etc/verity-prov.pub`
* `/etc/verity-dev.pub`
* `/etc/verity-prod.pub`

It also contains strings indicating dm-verity checks and error paths:

* `check_verity`
* `Error reading verity metadata`
* `Invalid verity table`

This is evidence that offline packages can be mounted under dm-verity with key material stored in `/etc/verity-*.pub`.

### 5.3 `updater-envoy` includes `crypto/ed25519` and NaCl

As noted earlier, `updater-envoy` includes:

* `crypto/ed25519`
* `tesla/vendor/github.com/kevinburke/nacl`

This supports the conclusion that offline signature verification is implemented using Ed25519/NaCl primitives.

### 5.4 IAS image verification uses `ias_image_tool` with a production public key

* `/sbin/autofuser-ice.sh` verifies `/mnt/mmcblk0p1/iasImage` via:

```sh
/usr/bin/ias_image_tool verify --image "$BOOT_IMAGE" --pubkey /etc/oskernel_prod.pem
```

This is direct evidence that at least one IAS image verification path uses a public key at `/etc/oskernel_prod.pem`.

---

## 6) What’s still missing to claim an “intended USB firmware update” workflow

Evidence **does** show:

* A USB-facing mountpoint and a local file server (`/mnt/update` → `127.0.0.1:23005`).
* An updater stack that supports:
  * mounting an offline squashfs-like package
  * dm-verity verification
  * signature verification via NaCl/Ed25519
* Explicit `factory_usb` / `/factory.upd` indicators in `sx-updater`.

However, based on the extracted artifacts searched so far, we do **not** yet have evidence that:

1) `/mnt/update` is populated by a specific *firmware* USB update package format, nor
2) `sx-updater`/`updater-envoy` consumes `/mnt/update` or `127.0.0.1:23005` directly.

Bridging evidence needed (not found yet):

* a script, config, or binary string connecting `/mnt/update` (or port `23005`) to:
  * `/dev/mapper/offline-package` creation, or
  * staging into `/mnt/mmcblk0p1/iasUpdate` / `iasImage*`.

---

## 7) Quick index of key artifacts

* USB update server:
  * `/etc/sv/usbupdate-server/run`
  * `/etc/sandbox.d/vars/usbupdate-server.vars`
* Mount manager:
  * `/etc/sv/mounterd/run`
  * `/usr/bin/mounterd` (binary; contains `/mnt/update`, `usbupdate-server`)
* Updater core:
  * `/etc/sv/sx-updater/run`
  * `/deploy/sx-updater` (static binary)
  * `/usr/bin/updater-envoy` (Go binary)
  * `/usr/bin/updaterctl` (HTTP client to updater endpoints)
* Bootfs staging/cleanup:
  * `/etc/fstab` (defines `/mnt/mmcblk0p1`)
  * `/usr/local/bin/update-cleanup-tasks`
* Fusing/factory gating:
  * `/usr/bin/is-factory-gated`
  * `/usr/bin/is-fused`
* IAS verification:
  * `/sbin/autofuser-ice.sh` (uses `/usr/bin/ias_image_tool verify ... --pubkey /etc/oskernel_prod.pem`)

---

## 8) USB Detection & Firmware Update Filename Patterns (NEW FINDINGS)

### 8.1 `mounterd` USB detection logic

The `mounterd` binary uses udev to detect USB devices via netlink monitoring:

```
udev_monitor_new_from_netlink
udev_monitor_receive_device
udev_device_get_devpath
udev_device_get_sysname
```

It recognizes USB ports via regex patterns matching device paths:

```
^/devices/soc0/7d004000.usb/usb2/.*$          (Tegra/Model 3/Y front USB)
^/devices/pci0000:00/0000:00:15.0/usb1/.*$     (Intel MCU2 USB)
^/devices/pci0000:00/0000:00:15.0/usb2/.*$
^/devices/pci0000:00/0000:00:08.1/.*/usb1/.*$
^/devices/pci0000:00/0000:00:08.1/.*/usb2/.*$
```

### 8.2 USB Mountpoints and Purpose Detection

`mounterd` supports multiple specialized mount destinations based on USB content:

| Mountpoint | Purpose | String in mounterd |
|------------|---------|-------------------|
| `/mnt/usb` | Generic USB | `GUI_usbDevicesMounted` |
| `/mnt/usb/TeslaCam` | Dashcam recordings | `GUI_usbMediaMounted` |
| `/mnt/crypto/usb` | Encrypted USB | `GUI_usbEncryptionMounted` |
| `/mnt/update` | Firmware updates | `GUI_usbFirmwareUpdateMounted` |
| `/mnt/media/usb-*` | Media playback | `GUI_usbMediaMounted` |
| `/mnt/lightshow` | Lightshow files | `GUI_usbLightshowMounted` |

### 8.3 Firmware Update Filename Pattern Recognition

**Critical finding:** `mounterd` uses regex pattern matching to identify firmware updates:

```
Filename matches pattern for firmware update directory='%s'
Filename matches pattern for firmware update, mounting for filename='%s'
Filename does not match pattern for firmware update for filename='%s'
```

For map updates, the pattern is explicitly shown:

```regex
^tesla_map_update_[a-z][a-z].ssq(-a[ab])?$
```

This suggests firmware updates follow a similar naming convention (likely `tesla_firmware_*.ssq` or similar squashfs-based format).

### 8.4 USB Filesystem Requirements

* Supported filesystem: **vfat** (FAT32)
  * Evidence: `vfat` string in mounterd, `GUI_dashcamErrorDriveTooBigForVfatFsck`
* `mounterd` uses `libblkid` for partition detection (`blkid_probe_enable_partitions`)
* GUID Partition Table (GPT) is recognized: `Found GUID partition table on device='%s'`

---

## 9) Handshake Endpoint & Offline Update Flow (NEW FINDINGS)

### 9.1 Handshake Endpoint Binding Behavior

The handshake endpoint is **always bound to localhost** (`127.0.0.1`), regardless of Hermes connectivity:

**From sx-updater:**
```
set_handshake host=%s port=%s path=%s
Handshake URL = http://%s:%s%s
Handshake URL = http://%s:%s%s/%%s/handshake
0.0.0.0  (search for binding - not found as bind address)
127.0.0.1 (present - used for localhost binding)
localhost (present - used as hostname)
```

The handshake can be manually overridden:
```
Usage: set_handshake HOST PORT [PATH]
/set_handshake?host=%s&port=%s&path=%s
override_handshake
```

### 9.2 USB Update Server Integration

The USB update flow uses the local file server:
```
http://localhost:4070   (deploy server)
http://localhost:%d     (dynamic port allocation)
http://localhost:23005  (usbupdate-server, serves /mnt/update)
```

### 9.3 Offline Handshake Bypass Mechanism

**Key finding:** The handshake system can operate without mothership connectivity when:

1. **Offline package validation** - Signatures are embedded in the package:
   ```
   offline_firmware_signature:
   Offline Signature:
   GetOfflineSignature
   ReadOfflineSignature
   offline signature matched
   ```

2. **Local signature resolution** - The updater can use cached signatures:
   ```
   signature resolution response is stale
   missing signature resolution response in cache
   cached_signature
   cached signature returned in response
   ```

3. **Manual handshake override** - Can bypass mothership:
   ```
   override_handshake command received
   Manual Handshake Parameter Override
   override_handshake { "vehicle_job_status_url":"%s", "force_gostaged":"true", ... }
   ```

### 9.4 Factory/Service USB Mode Markers

Three distinct marker files trigger different update modes:

| Marker File | Purpose | Evidence |
|-------------|---------|----------|
| `/factory.upd` | Factory USB update mode | `factory_usb`, `factory_usb_check` |
| `/service.upd` | Service center update mode | Present in strings |
| `/hwidacq.upd` | Hardware ID acquisition | Present in strings |

### 9.5 Fusing & Factory Mode Flow

**From `/usr/bin/is-fused`:**
```sh
# Reads fuse state from:
# 1. /sys/firmware/oem/eom (primary)
# 2. /usr/bin/gp_eom_fpf_query (fallback)
# Returns 0 if fused, 1 if unfused

# Unfused boards bypass signature verification:
verifyversion status=valid reason=unfused_board
verifyrestrictions status=valid reason=unfused_board
auth status=success reason=not_fused_and_no_tokens
```

---

## 10) Offline Package Verification Flow (NEW FINDINGS)

### 10.1 Signature Verification Keys (Multi-tier)

The system supports multiple key types for verification:

| Key File | Purpose |
|----------|---------|
| `/etc/verity-dev.pub` | Development builds |
| `/etc/verity-prov.pub` | Provisioning/manufacturing |
| `/etc/verity-prod.pub` | Production releases |
| `/etc/verity-fa.pub` | Factory authentication |
| `/etc/oskernel_prod.pem` | IAS kernel image verification |

### 10.2 Verification Flow

```
1. Package mounted via dm-verity → /dev/mapper/offline-package
2. Signature read from package: GetOfflineSignature, ReadOfflineSignature
3. NaCl/Ed25519 signature verification: verify_nacl_signature
4. Hash comparison: offline_hash, unified_hash, confirm_hash
5. Bank marked valid: MarkOfflineBankValid
```

### 10.3 dm-verity Integration

```
VerityCreateDevice - Creates dm-verity mapped device
VerityRemoveDevice - Removes dm-verity device
ReadVerityTable - Reads verity metadata table
ReadVerityMetaData - Reads verity metadata
CalculateVerityOffset - Calculates hash table offset
GetVerityKeys - Retrieves verification keys
```

---

## 11) Step-by-Step Legitimate USB Update Procedure (SYNTHESIZED)

Based on all evidence, here is the reconstructed legitimate USB update flow:

### 11.1 USB Preparation

1. Format USB drive as **FAT32** (vfat)
2. Use **GPT** partition table (recognized by mounterd)
3. Place firmware package with correct naming pattern (likely `tesla_firmware_*.ssq`)
4. For factory mode: create `/factory.upd` marker file
5. For service mode: create `/service.upd` marker file

### 11.2 Vehicle-Side Detection

1. `mounterd` monitors udev for USB insertion via netlink
2. Device path matched against known USB port patterns
3. Filesystem probed with `libblkid`
4. Filename pattern matched against firmware regex
5. If match: mounted to `/mnt/update`
6. `usbupdate-server` starts serving on `127.0.0.1:23005`

### 11.3 Update Processing

1. `sx-updater` or `updater-envoy` connects to `http://localhost:23005`
2. Package downloaded/verified:
   - For factory mode: checks `/factory.upd` marker
   - For fused vehicles: requires NaCl signature verification
   - For unfused: bypasses signature checks
3. Package mounted via dm-verity as `/dev/mapper/offline-package`
4. Staging to `/mnt/mmcblk0p1/offline-iasImage*`
5. Gostaged command triggers installation

### 11.4 Offline Handshake Bypass

For cars without Hermes connectivity:

1. **Option A (Factory Mode):**
   - Car must be unfused (`/sys/firmware/oem/eom` = "0")
   - Or have factory sentinel: `/var/etc/in-factory`
   - Signature verification bypassed

2. **Option B (Cached Signature):**
   - Use previously cached signature resolution
   - Works if update was previously "staged" with connectivity

3. **Option C (Manual Override):**
   - Service mode uses: `/set_handshake?host=<ip>&port=<port>&path=<path>`
   - Or override_handshake JSON command

---

## 12) Differences: Factory vs Service vs User USB Updates

| Aspect | Factory Mode | Service Mode | User Mode |
|--------|--------------|--------------|-----------|
| Marker File | `/factory.upd` | `/service.upd` | None |
| Fusing Required | No (unfused) | Either | Yes (fused) |
| Signature Check | Bypassed | Required | Required |
| Key Used | dev/prov | prod | prod |
| Hermes Required | No | No | Typically Yes |
| UI Access | No | Yes (service menu) | Yes (software menu) |

---

## 13) Blocking Issues for Offline USB Updates on Production Cars

### 13.1 Primary Blocker: Signature Resolution

For fused production cars:
- Signature verification **requires** either:
  1. Mothership connection for signature resolution
  2. Cached signature from previous connectivity
  3. Embedded signature in package (offline packages have this)

### 13.2 Secondary Blocker: Handshake Endpoint

- Handshake defaults to mothership servers
- Offline cars can't reach: `firmware.vn.teslamotors.com:4567`
- Manual override possible but requires service access

### 13.3 Workaround Path (Legitimate)

For orphan cars stuck without Hermes:

1. **If signature was previously cached:**
   - Download a Tesla-signed USB package
   - Include all required files in correct layout
   - The cached signature should allow verification

2. **If no cached signature:**
   - Car needs brief connectivity to get signature resolution
   - Or service center can use service mode override
   - Tesla Mobile Service may use factory USB mode

---

## 14) Key URLs & Endpoints

```
http://localhost:23005          - USB update file server
http://localhost:4070           - Local deploy server
http://localhost:20564          - sx-updater command interface
http://localhost:28496          - gadget-updater (trove) interface
firmware.vn.teslamotors.com:4567 - Mothership firmware server
hermes-api.{env}.{region}.vn.cloud.tesla.com - Hermes WebSocket
```

---

## 15) Summary: Can USB Updates Work Offline?

**YES, but with conditions:**

1. **Factory/Service USB** - Works fully offline on unfused boards
2. **Production USB with embedded signature** - Works offline if package includes NaCl signature and dm-verity metadata
3. **Production USB without embedded signature** - Requires:
   - Cached signature from previous connectivity, OR
   - Service mode handshake override

**The Missing Link:**
The exact format of a Tesla-signed USB update package with embedded offline signatures remains undocumented. Tesla's internal USB update packages likely include:
- SquashFS firmware image
- dm-verity hash table
- NaCl/Ed25519 signature blob
- Manifest/metadata JSON

This format would allow fully offline installation on production vehicles.
