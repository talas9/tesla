# Tesla MCU2 Hardware Architecture (MCU2 + Gateway on one PCB)

**Document:** `48-hardware-architecture.md`  
**Date:** 2026-02-03  
**Scope:** Physical + logical architecture of a Tesla MCU2 system **as described by the user** and cross‑checked against the extracted MCU2 filesystem (`/firmware/mcu2-extracted`) and existing research docs in `/research/`.

> **Evidence vs inference:**
> - **Evidence** items are backed by paths/strings/scripts in the extracted filesystem or by prior docs in `/research/`.
> - **Inference** items are architectural hypotheses consistent with evidence but not directly proven.

---

## 0) Executive summary

This MCU2 generation appears to be a **two‑processor “main board”** that combines:

- **MCU2 (x86‑64)** running Linux (UI, update orchestration, networking services).
- **Gateway ECU** (separate MCU/SoC) on the same PCB (CAN aggregation, critical vehicle interfacing, SD card host).

Key architectural consequences:

1. **MCU↔Gateway is not a simple internal bus:** it is a **networked** relationship using **UDP** for Gateway control/config ("UDPAPI"), and other protocols/services for update/monitoring.
2. **SD card trust boundary:** the SD card is **physically on the Gateway**, not the MCU. This makes the Gateway a data diode / proxy for SD-backed artifacts and an important security boundary.
3. **APE is a separate physical board** connected via **100BASE‑T1** (single twisted pair automotive Ethernet) with IPs **192.168.90.103** (APE‑A) and **192.168.90.105** (APE‑B) on the vehicle LAN.
4. **Modem is on the main board** and has a dedicated update pipeline using dm‑verity keys **`/etc/verity-modem-{dev,prod}.pub`** and SSQ bundles.
5. **Debug connector is a network diagnostic port** (mini‑HDMI form factor) that can expose a limited updater/recovery terminal.

---

## 1) Physical architecture (boards, connectors, boundaries)

### 1.1 Board layout (physical)

**User-provided physical topology (primary truth source):**

- **Main board:**
  - MCU2 (x86‑64) running Linux.
  - Gateway ECU (separate processor on same PCB).
  - MCU↔Gateway linked via an internal network connection (Ethernet/UDP).
  - **SD card is connected to Gateway only**.
  - LTE modem is on this board.

- **Secondary board:**
  - APE (Autopilot) as a separate physical board.
  - Connected to main board via **100BASE‑T1**.

- **Debug connector:**
  - mini‑HDMI physical connector used as a network diagnostic port.

### 1.2 High-level physical diagram

```text
                 ┌───────────────────────────────────────────┐
                 │             MAIN BOARD (PCB)              │
                 │                                           │
                 │  ┌───────────────┐       ┌──────────────┐ │
Power domains ───┼─▶│ MCU2 (x86-64)  │<─────▶│ Gateway ECU   │ │
(ACC/AON/etc)    │  │ Linux          │  Eth/ │ (separate MCU)│ │
                 │  │ UI + updater   │  UDP  │ CAN + SD host │ │
                 │  └──────┬────────┘       └──────┬───────┘ │
                 │         │                        │         │
                 │         │                        │ SDIO/   │
                 │         │                        │ SD bus  │
                 │         │                        ▼         │
                 │   ┌─────┴─────┐            ┌───────────┐  │
                 │   │ LTE Modem  │            │ SD Card    │  │
                 │   │ Iris/Tillit│            │ (Gateway)  │  │
                 │   └─────┬─────┘            └───────────┘  │
                 │         │                                   │
                 │  Debug port (mini-HDMI form factor)         │
                 └───────┬────────────────────────────────────┘
                         │ (diag Ethernet / restricted)
                         ▼
                 ┌────────────────────┐
                 │ External diag host  │
                 └────────────────────┘

                 ┌───────────────────────────────────────────┐
                 │         SECONDARY BOARD (APE)              │
                 │  ┌─────────────────────────────────────┐  │
                 │  │ Autopilot ECU (APE-A / APE-B)        │  │
                 │  └─────────────────────────────────────┘  │
                 └───────────────▲───────────────────────────┘
                                 │ 100BASE-T1 (single pair)
                                 └──────────────────────────
```

### 1.3 Physical security boundaries

**Boundary A — Debug connector** (physical access):
- Provides privileged *network reachability* into internal services (not necessarily a full shell).
- In recovery/updater mode, exposes an updater terminal.

**Boundary B — Gateway SD card** (physical access):
- The SD card being on the Gateway means:
  - Attacks against SD require Gateway compromise or physical extraction.
  - MCU compromise alone may not yield raw SD block access (depends on Gateway proxy services).

**Boundary C — 100BASE‑T1 link** (physical access):
- Single twisted pair automotive Ethernet between main board and APE.
- Sniffing/injection requires access to the differential pair and proper PHY/tap.

---

## 2) Logical network & addressing (vehicle LAN)

### 2.1 Vehicle internal subnet (evidence-backed)

Existing research consistently uses **192.168.90.0/24** for the internal ECU LAN.

From `/research/00-master-cross-reference.md` and `/research/44-mcu-networking-deep-dive.md`:

| IP | Component | Notes |
|---:|-----------|------|
| `192.168.90.100` | MCU2 | Linux system, UI + update stack |
| `192.168.90.102` | Gateway ECU (GTW) | CAN gateway + UDPAPI, TFTP/update interactions |
| `192.168.90.103` | APE-A | Autopilot primary |
| `192.168.90.105` | APE-B | Autopilot secondary (dual setups) |
| `192.168.90.60` | Modem | Cellular subsystem (Iris) |
| `192.168.90.30` | Tuner | Harman radio/tuner |
| `192.168.90.104` | (often labeled AURIX/GPS in docs) | See note below |

**Note:** Some docs distinguish `192.168.90.104` (AURIX) from `192.168.90.102` (GTW). In the user’s physical description, “Gateway ECU” is a single separate processor on the main PCB. These can both be true if the main board hosts multiple auxiliary MCUs (Gateway + safety/infotainment support MCU). Treat `90.104` as **present in some builds** until physically confirmed.

### 2.2 Logical topology diagram

```text
                 Internal Vehicle LAN: 192.168.90.0/24

        ┌──────────────┐         ┌───────────────┐
        │   APE-A      │         │     APE-B     │
        │  .90.103     │         │   .90.105     │
        └──────┬───────┘         └──────┬────────┘
               │ 100BASE-T1 (PHY)       │
               └──────────┬─────────────┘
                          │
                    ┌─────▼─────┐
                    │   MCU2    │
                    │ .90.100   │
                    └─────┬─────┘
                          │ Ethernet (internal)
                    ┌─────▼─────┐
                    │  Gateway  │
                    │ .90.102   │
                    └─────┬─────┘
                          │
         ┌────────────────┼─────────────────┐
         │                │                 │
   ┌─────▼─────┐    ┌─────▼─────┐     ┌─────▼─────┐
   │  Modem    │    │  Tuner    │     │ Other ECUs │
   │ .90.60    │    │ .90.30    │     │ .90.101+   │
   └───────────┘    └───────────┘     └───────────┘
```

---

## 3) Communication paths (what talks to what)

This section maps the **primary communication channels** and their security properties.

### 3.1 MCU ↔ Gateway (Ethernet/UDP)

**Evidence:**
- Firewall rules explicitly allow MCU processes to send UDP to Gateway on **port 3500**:
  - `/firmware/mcu2-extracted/etc/firewall.d/hermes-livestream.iptables` includes `--dports 1666,1667,3500` to `192.168.90.102`.
  - `/firmware/mcu2-extracted/etc/firewall.d/qtcar-connman.iptables` allows UDP dports `3500,31415` to `192.168.90.102`.
- Multiple MCU scripts send UDP to `gw:3500` via `socat`:
  - `/firmware/mcu2-extracted/usr/local/bin/restart-updater`
  - `/firmware/mcu2-extracted/usr/local/bin/reboot-gateway`
  - `/firmware/mcu2-extracted/usr/local/bin/request-gateway-switch-dump`
  - `/firmware/mcu2-extracted/sbin/autofuser.sh`

**Interpretation:**
- `gw` is a hostname resolving to the Gateway ECU (likely `192.168.90.102`).
- The MCU uses this UDP channel for:
  - liveness checks,
  - reboot requests,
  - special service commands (e.g., “switch dump”),
  - keeping the Gateway/related features alive during fusing/maintenance.

**Security notes:**
- UDP is connectionless; unless the Gateway enforces authentication in payload, this interface is easy to spoof once on the LAN.
- Prior research documents a “magic unlock” used by the Gateway config API (see §4).

### 3.2 MCU ↔ APE (100BASE‑T1, IP)

**Evidence:**
- APE IPs: `192.168.90.103` and `192.168.90.105` appear across firewall and network analysis (`/research/44-mcu-networking-deep-dive.md`).
- Many firewall chains explicitly gate “APE_INPUT” traffic.
- `updaterctl` can target APE updater at `HOST=ape` port `28496` (evidence: `/firmware/mcu2-extracted/usr/bin/updaterctl`).

**Interpretation:**
- The logical interface on MCU is `eth0` for “APE network” in some docs; physically, that Ethernet is **100BASE‑T1** to the APE board.

**Security notes:**
- The firewall is a major boundary: many services are limited to APE IPs.
- If an attacker compromises APE, it becomes a strong pivot into MCU services permitted to APE.

### 3.3 Gateway ↔ SD card (direct connection)

**User-provided fact:** SD is physically connected to Gateway only.

**Evidence (indirect):**
- Gateway SD logs are a major artifact source (`/research/09-gateway-sdcard-log-analysis.md`).
- MCU software parses Gateway update logs (`parse_gateway_update_log` strings referenced in `/research/21-gateway-heartbeat-failsafe.md`).

**Interpretation (inference):**
- Gateway likely uses SD for:
  - logging,
  - update staging metadata,
  - crash/event artifacts.
- MCU likely accesses SD-backed *data* only through Gateway-provided services (network API, log extraction, update flows), not as a block device.

### 3.4 Modem ↔ MCU

**Evidence:**
- Modem update server port: `49503/tcp` (modem → MCU) discussed in `/research/04-network-ports-firewall.md`.
- Modem firmware update pipeline uses `/usr/local/bin/iris-fw-upgrade.sh` and SSQ loading via `/usr/local/bin/iris-fw-ssq-load.sh` (see `/research/18-cid-iris-update-pipeline.md`).
- dm‑verity pubkeys exist:
  - `/firmware/mcu2-extracted/etc/verity-modem-dev.pub`
  - `/firmware/mcu2-extracted/etc/verity-modem-prod.pub`
- `ofono` configuration exists at `/firmware/mcu2-extracted/etc/ofono/iris.conf`.

**Interpretation:**
- The modem has a dedicated update/flash toolchain (QFirehose), and the MCU enforces a signed/verity-verified SSQ bundle pipeline for modem artifacts.

### 3.5 Debug connector ↔ MCU (diagnostic port)

**User-provided fact:** The mini‑HDMI debug connector is a network diagnostic port; most ports blocked; recovery boots into updater with a limited terminal supporting at least: `gostaged`, `set_handshake`, `start_update`.

**Evidence (adjacent):**
- The updater stack provides an HTTP control plane on MCU (default `localhost:20564`) via `sx-updater` (`/research/15-updater-component-inventory.md`, `/research/16-offline-update-format-notes.md`).
- `updaterctl` exposes commands including `gostaged` and targets MCU/APE.

**Interpretation (inference):**
- Recovery/updater terminal likely acts as a constrained frontend to the same underlying update state machine ("gostaged", handshake configuration, start/install actions).

---

## 4) Gateway UDP configuration/control protocol (“UDPAPI”, port 3500)

### 4.1 What is confirmed (evidence)

**Destination & port:** Gateway UDPAPI listens on **UDP/3500**.

- Firewall allows UDP/3500 to `192.168.90.102` from multiple services.
- Multiple scripts directly send single‑byte and multi‑byte payloads to `udp:gw:3500`.

**Confirmed MCU-side clients (binaries/scripts):**

| Client | Path | What it does (from code) |
|---|---|---|
| `restart-updater` | `/usr/local/bin/restart-updater` | Sends `0x01` to `gw:3500` as a gateway responsiveness probe before restarting updater services. |
| `reboot-gateway` | `/usr/local/bin/reboot-gateway` | Sends `00 DE AD BE EF` to request a gateway reboot; expects reply bytes `00 01`. |
| `request-gateway-switch-dump` | `/usr/local/bin/request-gateway-switch-dump` | Sends a 1‑byte command (`0x2D` or `0x2E`) and expects echo + status byte (`01` success, `00` false). |
| `autofuser.sh` | `/sbin/autofuser.sh` | Sends `22 0A` to `gw:3500` as part of keep-alive/OTA power handling (context: fusing). |

### 4.2 Packet patterns and inferred command model

From the scripts, the UDPAPI behaves like a **command byte(s) + simple ACK** protocol.

#### (A) Liveness probe
- **Request:** `01`
- **Response:** not captured in the script (script just checks exit code), but implies some reply or at least no error.
- **Evidence:** `/usr/local/bin/restart-updater`.

#### (B) Gateway reboot request
- **Request:** `00 DE AD BE EF`
- **Response:** `00 01` indicates accepted.
- **Evidence:** `/usr/local/bin/reboot-gateway`.

#### (C) “Switch dump” request
- **Request:** `2D` (or `2E` on some variants)
- **Response:** `2D 01` = success; `2D 00` = returned false.
- **Evidence:** `/usr/local/bin/request-gateway-switch-dump`.

#### (D) Keep-alive / OTA power request (contextual)
- **Request:** `22 0A`
- **Response:** not checked; best interpreted as a command “poke”.
- **Evidence:** `/sbin/autofuser.sh`.

### 4.3 Config unlock and config write (research corpus)

**From `/research/02-gateway-can-flood-exploit.md` (research, not directly from MCU filesystem):**

- A “config unlock” magic payload is described:
  - `18 BA BB A0 AD` (hex)
- A “write config” framing is described by examples using a leading byte `0x0c` followed by config ID and payload.

This aligns with the idea that UDP/3500 hosts a broader command set beyond the few maintenance commands seen in MCU scripts.

### 4.4 Security analysis of UDPAPI

**Threat model:** attacker with access to the internal LAN (via debug connector, compromised ECU, physical Ethernet tap, etc.).

- **Authentication:**
  - Maintenance commands shown in scripts appear to have **no cryptographic authentication** at the MCU level.
  - The config API described in research appears to rely on a **magic unlock token**, which is a weak form of authorization if static.

- **Integrity/confidentiality:**
  - UDP payloads are not encrypted at the transport level.
  - Any confidentiality/integrity must come from application-level crypto (not evidenced here).

- **Security boundary impact:**
  - UDPAPI is one of the most important trust boundaries: it bridges from the infotainment compute domain into a safety/vehicle domain controller.

### 4.5 Next reverse-engineering steps (recommended)

To fully document UDPAPI:

1. Identify the **Gateway-side implementation** (firmware / image) and reverse it.
2. On the MCU filesystem, search for “gw:” hostname resolution and any libraries that encode UDPAPI messages.
3. Capture real traffic (pcap) on MCU `eth0` while invoking:
   - `reboot-gateway`, `request-gateway-switch-dump`, normal boot activity.

---

## 5) Recovery mode + debug port deep dive

### 5.1 User-observed behavior (primary)

- Debug connector is a network diagnostic port.
- Recovery mode boots into an updater environment.
- Updater terminal reachable over the debug port.
- Observed commands:
  - `gostaged`
  - `set_handshake`
  - `start_update`

### 5.2 Relationship to the normal updater stack (evidence-backed)

On the normal running MCU:

- `sx-updater` exposes an HTTP control surface on `localhost:20564`.
- `updaterctl` is a client that sends commands to:
  - **MCU:** `localhost:20564`
  - **APE:** `ape:28496` or `ape-b:28496`

Evidence: `/firmware/mcu2-extracted/usr/bin/updaterctl`.

**Interpretation (inference):** Recovery/updater terminal likely provides a restricted command interface to the same underlying state machine (staging, handshake selection, start/install actions).

### 5.3 Security properties

- **Physical access requirement:** High confidence. Debug port presence implies physical access is the primary gate.
- **Firewall restrictions:** User reports most ports blocked. This matches overall design: the internal firewall tightly gates services by source IP.
- **Remaining unknowns:**
  - Whether the recovery terminal requires authentication beyond physical presence.
  - Whether the recovery environment enforces signature/verity checks or offers factory/service bypasses.

---

## 6) 100BASE‑T1 (Automotive Ethernet) analysis

### 6.1 What 100BASE‑T1 is

100BASE‑T1 (IEEE 802.3bw) is **100 Mbps full‑duplex Ethernet over a single twisted pair**.

Key points:

- **2 wires (differential pair):** One twisted pair carries bidirectional traffic using echo cancellation and PAM modulation.
- **PHY requirement:** You need a 100BASE‑T1 PHY (or media converter) to interface; you can’t plug it into standard RJ45 Ethernet without conversion.
- **Use case:** weight/cost reduction and automotive EMC robustness vs 4‑pair 100BASE‑TX.

### 6.2 Speed/bandwidth implications

- Nominal **100 Mbps** link; enough for:
  - sensor/telemetry streams,
  - control plane RPCs,
  - time sync (PTP),
  - some video/metadata flows (depending on compression).

### 6.3 Security: sniffing/injection feasibility

- **Sniffing:** possible with physical access to the pair and an appropriate tap + PHY.
- **Injection:** also possible if you can attach as an active node on the link (requires maintaining link integrity and correct PHY).
- **Cryptographic protection:** depends on higher layers. The firewall shows many services are IP‑gated, but that is not crypto.

**Research implication:** If APE is compromised, it is already an on‑link node, so IP-layer restrictions are the relevant boundary.

---

## 7) SD card isolation (why it matters)

### 7.1 Why place SD on the Gateway (inference)

Plausible reasons Tesla attaches SD to the Gateway rather than the MCU:

1. **Safety boundary:** Gateway is closer to CAN/vehicle domain; storing critical logs/configs there reduces trust in infotainment.
2. **Availability:** Gateway may remain powered or more reliable across MCU crashes/reboots.
3. **Tamper resistance:** MCU compromise does not automatically grant raw SD access.

### 7.2 How the MCU likely accesses SD-backed data (inference)

Because the MCU lacks the physical SD interface, it likely consumes SD-backed artifacts via:

- Gateway-exported logs/events via network protocol,
- update logs parsed by MCU (`parse_gateway_update_log` string evidence from `/research/21-gateway-heartbeat-failsafe.md`),
- staged update artifacts delivered through the Gateway update pipeline (TFTP flows described in `/research/09-gateway-sdcard-log-analysis.md`).

### 7.3 Security implications

- **Good:** Compromising MCU doesn’t trivially yield SD block-level tampering.
- **Bad:** If UDPAPI/config channels are weak, an attacker might coerce the Gateway into acting on SD data or changing its config.

---

## 8) Modem (Iris/Tillit) subsystem

### 8.1 Firmware artifacts and verification (evidence)

From `/research/18-cid-iris-update-pipeline.md` and extracted filesystem:

- Modem SSQ loader uses dm‑verity keys:
  - `/etc/verity-modem-prod.pub`
  - `/etc/verity-modem-dev.pub`
- Loader script: `/usr/local/bin/iris-fw-ssq-load.sh`
- Upgrade script: `/usr/local/bin/iris-fw-upgrade.sh`
- Flash tooling: `/usr/bin/QFirehose` invoked to apply firmware in `/deploy/iris/<TARGET_FW>`.

**Important nuance:** Even if `/deploy/iris/` is “empty” on a running system at a particular moment, the update pipeline expects to populate it via staged SSQs and signatures.

### 8.2 Modem ↔ MCU network relationship

- Modem is an internal LAN node (`192.168.90.60`).
- Modem can reach MCU’s modem update server (`49503/tcp` in prior firewall analysis docs).

### 8.3 Security notes

- Modem is the **internet-facing** subsystem; compromise of modem is a high-value pivot into the vehicle LAN.
- Tesla mitigates via:
  - signature verification,
  - dm‑verity-verified SSQ packages,
  - firewall source restrictions.

---

## 9) Trust boundaries and attack surface map (hardware-centric)

### 9.1 Boundary map

```text
UNTRUSTED / EXTERNAL
  - Cellular network (attacker-controlled environment)
  - Physical access to debug connector (attacker if car accessible)

SEMI-TRUSTED (vehicle internal, but compromise plausible)
  - Modem (.90.60)
  - APE (.90.103/.90.105)
  - Other ECUs on 192.168.90.x

HIGH-TRUST / SAFETY-CRITICAL
  - Gateway ECU (.90.102) (CAN boundary, SD host)

HIGH-VALUE COMPUTE (large attack surface)
  - MCU2 (.90.100) (Linux + many services)
```

### 9.2 Critical cross-domain chokepoints

1. **UDPAPI (Gateway config/control) — UDP/3500**
   - Crosses from infotainment compute into gateway domain.

2. **Updater control plane**
   - `sx-updater` and related components drive firmware updates and can influence multiple components.

3. **Modem update server**
   - Modem-to-MCU update path is critical because modem sits on an external threat boundary.

---

## 10) Cross-references to existing research docs

These documents contain deeper detail that should be kept consistent with this hardware architecture view:

- Network & firewall: `04-network-ports-firewall.md`, `44-mcu-networking-deep-dive.md`
- Gateway SD/update evidence: `09-gateway-sdcard-log-analysis.md`
- Gateway heartbeat/failsafe: `21-gateway-heartbeat-failsafe.md`
- Gateway bootloader & primitives: `12-gateway-bootloader-analysis.md`
- Iris/modem pipeline: `18-cid-iris-update-pipeline.md`
- Master synthesis: `00-master-cross-reference.md`

---

## 11) Open questions / next steps (highest value)

1. **Confirm physical wiring:** MCU↔Gateway link type on PCB (internal Ethernet PHY? direct MAC-to-MAC?) and whether a second MCU (AURIX) exists on-board.
2. **Fully reverse UDPAPI:**
   - identify message format for reads/writes,
   - config ID namespace (beyond what is in logs),
   - authentication/authorization model (magic token vs crypto).
3. **Recovery terminal characterization:**
   - capture complete command list and any auth handshake,
   - map to underlying updater endpoints (20564/25956/etc).
4. **SD proxy mechanism:** determine how MCU retrieves SD logs (pull vs push; protocol and endpoints).
5. **100BASE‑T1 sniff/inject practicality:** identify PHY parts and whether link supports standard automotive security features.

---

## Appendix A — Evidence snippets (paths)

- UDP/3500 clients:
  - `/firmware/mcu2-extracted/usr/local/bin/restart-updater`
  - `/firmware/mcu2-extracted/usr/local/bin/reboot-gateway`
  - `/firmware/mcu2-extracted/usr/local/bin/request-gateway-switch-dump`
  - `/firmware/mcu2-extracted/sbin/autofuser.sh`

- Firewall allowance to Gateway UDP/3500:
  - `/firmware/mcu2-extracted/etc/firewall.d/hermes-livestream.iptables`
  - `/firmware/mcu2-extracted/etc/firewall.d/qtcar-connman.iptables`

- Modem verity keys:
  - `/firmware/mcu2-extracted/etc/verity-modem-prod.pub`
  - `/firmware/mcu2-extracted/etc/verity-modem-dev.pub`

- Iris updater scripts:
  - `/firmware/mcu2-extracted/usr/local/bin/iris-fw-upgrade.sh`
  - `/firmware/mcu2-extracted/usr/local/bin/iris-fw-ssq-load.sh`

- Updater client:
  - `/firmware/mcu2-extracted/usr/bin/updaterctl`

