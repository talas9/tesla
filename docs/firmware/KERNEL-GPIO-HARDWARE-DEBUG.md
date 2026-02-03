# Tesla Model 3/Y ICE Kernel: GPIO, Hardware Debug Interfaces, and Attack Surface

## 1. Kernel Overview & Methodology
- Firmware image: `/root/downloads/model3y-extracted/`
- Kernel version: `5.4.294-PLK`
- Artifacts used: kernel modules under `lib/modules/5.4.294-PLK/`, `etc/gpio_mapping.txt`, AppArmor profiles, and `deploy/iasImage-bank_a` (boot header).
- Tools: `strings`, `/sbin/modinfo`, `grep`, `python3` for tabulation.

### Kernel command line (from `iasImage-bank_a`)
```
console=null bootpart=kernel-a clocksource=tsc loglevel=7 panic=1 security=apparmor apparmor=1 
intel_xhci_usb_role_switch.default_role=1 snd_soc_skl.pci_binding=2 modprobe.blacklist=dwc3 
psstore.backend=ramoops memmap=0x400000$0x50000000 ramoops.mem_address=0x50000000 
ramoops.mem_size=0x400000 ramoops.record_size=0x40000 ramoops.console_size=0x200000 
ramoops.pmsg_size=0x80000 ramoops.dump_oops=1 isolcpus=1 intel_iommu=on,igfx_off,ipu_off 
rng_core.default_quality=1000
```

Implications:
- `security=apparmor` + `apparmor=1` enables mandatory access control.
- `intel_iommu=on,igfx_off,ipu_off` keeps VT-d enabled but disables graphics/IPU IOMMUs, likely for stability.
- `loglevel=7` and `panic=1` indicates verbose logging but immediate panic on oops.
- `psstore.backend=ramoops` etc. ensures persistent crash logging in RAM/flash.
- `modprobe.blacklist=dwc3` prevents the xHCI-based gadget controller, reducing USB attack surface.

## 2. GPIO-related Kernel Modules
| Module Path | Description / Notes | Interface | Debug / Params |
|-------------|--------------------|-----------|----------------|
| `kernel/drivers/gpio/gpio-generic.ko` | Generic memory-mapped GPIO controller framework | GPIO | Built-in (from `modules.builtin`)
| `kernel/drivers/gpio/gpio-ich.ko` | Intel ICH/LPSS GPIO controller | GPIO | Built-in
| `kernel/drivers/regulator/gpio-regulator.ko` | Regulator driver controlled by GPIO pins | Regulator/GPIO | Built-in
| `kernel/drivers/tty/serial/serial_mctrl_gpio.ko` | Serial modem-control lines via GPIO | GPIO/UART | Built-in
| `kernel/drivers/base/regmap/regmap-i2c.ko` | Generic I2C register map helper, widely used by GPIO expanders | I2C | `debug` param
| `kernel/drivers/base/regmap/regmap-spi.ko` | SPI register map helper | SPI | `debug` param
| `kernel/drivers/spi/spidev.ko` | Exposes SPI devices to user space (dangerous if misconfigured) | SPI | `bufsiz` param
| `kernel/drivers/spi/spi-pxa2xx-platform.ko` | Intel/LPSS SPI controller | SPI | Platform driver
| `extra/bcmdhd.ko` | Broadcom Wi-Fi, includes multiple GPIO hooks (`dhd_customer_gpio_wlan_ctrl`, `si_gpio*`) | WLAN/GPIO | Strings show direct GPIO manipulation
| `extra/nt_ts_51922.ko` | Novatek touch controller, requests reset/IRQ GPIOs | Touch GPIO | Inline diagnostic strings
| `kernel/drivers/input/touchscreen/cyttsp6.ko` | Cypress TrueTouch touchscreen, heavy GPIO usage for IRQ/RESET | Touch GPIO | Verbose error logging when GPIO fails
| `kernel/drivers/media/i2c/crlmodule/crlmodule.ko` | Camera aggregator, manages GPIO IRQs for sensors | Camera/I2C/GPIO | `unable to acquire custom gpio` strings

> Many modules embed GPIO handling even if they are not under `drivers/gpio/`. Strings confirmed request/free patterns.

## 3. GPIO Pin Mapping & Configuration (from `/etc/gpio_mapping.txt`)
Total pins mapped: **426** entries covering PCIe wake, storage, PMIC, display, wireless, debug, etc. Highlights below.

### 3.1 Storage / Boot Media
| Function | Pin | Notes |
|----------|-----|-------|
| `EMMC0_CLK`, `BMP-EMMC-CLK` | 271 | eMMC clock shared with board management processor
| `EMMC0_D0..D7` | 272-279 | eMMC data lines (duplicated names for board harness)
| `EMMC0_CMD` | 280 | Command
| `EMMC0_STROBE` / `EMMC-RCLK` | 296 | Replay/HS400 strobe
| `EMMC-nRST` | 442 | Reset
| `SDIO_CLK/D0-D3/CMD` | 281-286 | SDIO to WLAN/BT
| `SDCARD_*` pins | 287-295 | Removable SD/debug slot (includes write protect & detect)
| `SDIO_PWR_DOWN_B` | 297 | Allows complete power gating of SDIO devices

### 3.2 LPSS I2C Buses & Camera/Display Buses
| Bus | SDA Pin | SCL Pin | Notes |
|-----|---------|---------|------|
| LPSS_I2C0 | 310 | 311 | Onboard Intel i210 Ethernet (BMP-I210-I2C-*)
| LPSS_I2C1 | 312 | 313 | Peripheral I2C (service bus)
| LPSS_I2C2 | 314 | 315 | Display I2C (EDID, panel control)
| LPSS_I2C3 | 316 | 317 | APE camera bus
| LPSS_I2C4 | 318 | 319 | Audio config I2C
| LPSS_I2C5 | 320 | 321 | Temperature alert lines
| LPSS_I2C6 | 322 | 323 | A2B automotive audio bus + CAM GPIO
| LPSS_I2C7 | 324 | 325 | Camera GPIOs 5-6
| PMIC_I2C | 389 | 390 | Power management, mirrored as BMP-PMIC-SCL/SDA
| HV_DDI0/1_DDC | 357-360 | DisplayPort AUX/DDC lines
| DBI_SDA/SCL | 361/362 | Panel SPI-to-I2C bridge

### 3.3 SPI / SSP / Boot Flash
| Signal | Pin | Notes |
|--------|-----|------|
| `PMC_SPI_*` | 375-380 | PCH power management controller SPI (likely TPM/PMIC interface)
| `FST_SPI_*` / `BOOT-SPI-*` | 410-417 | Boot flash interface (QSPI) with dedicated chip selects and quad data pins
| `GP_SSP_0/1/2` CLK/FS/RX/TX | 418-433 | General SSP blocks used for audio (A2B IRQ) and diag (JTAG consent). Notably `GP_SSP_0_FS1 = JTAG-BOOT-nHALT` and `GP_SSP_2_TXD = JTAG-DEBUG-nCONSENT`, tying SSP lines to JTAG gating.

### 3.4 UART / Console / Modem
| Signal | Pin | Purpose |
|--------|-----|---------|
| `LPSS_UART0_*` (pins 472-475) | Bluetooth module UART (host handshake)
| `LPSS_UART1_*` (476-479) | Gateway/diagnostic UART channel
| `LPSS_UART2_RXD/TXD` (480/481) | Dedicated debug UART to board connectors (`BMP-DEBUG-UART-*`)
| `LPSS_UART2_RTS/CTS` (482/483) | Flow control for debug UART
| Additional `BMP-BT-UART-*`, `BMP-GTW-UART*` entries show board wiring.

### 3.5 JTAG / Intel DCI
| Signal | Pin | Notes |
|--------|-----|------|
| `JTAG-BOOT-nHALT` | 420 | Boot halt gating (GP_SSP_0_FS1)
| `JTAG-DEBUG-nCONSENT` | 433 | Consent line (GP_SSP_2_TXD)
| `TCK/TMS/TDI/TDO/TRST_B` | 496-504 | Standard JTAG pins accessible on board; mirrored as `BMP-JTAG-*`
| `CX_PMODE/PREQ_B/PRDY_B/JTAGX` | 500-503 | Intel Converged Security Engine/boot strap + DCI (Direct Connect Interface) handshake lines

### 3.6 Power / PMIC / System State
Pins 345-390 cover AC detect, battery low, reset, sleep states, wake lines, PMIC I2C, thermal trips, PROCHOT, etc., showing tight coupling between PMU, gateway and board management processor (BMP). Attackers with GPIO access could toggle `PMIC_RESET_B`, `PMU_PLTRST_B`, or `GTW-BMP-WAKE` to glitch the system.

### 3.7 Wireless & Peripheral Controls
- WLAN: `BMP-WLAN-REG-ON` (334), `BMP-WLAN-PCIE-EN` (439), `BMP-WLAN-PCIE-nPERST` (440), `nWLAN-PCI-PME` (441)
- Bluetooth: `BMP-BT-REG-ON` (332), `BMP-BT-DEV-WAKE` (333), `BMP-BT-PCM-*` (406-409)
- Cellular: `LTE/GSM` pins for power, crash indicators, EFUSE toggling (289-292, 398-399)
- Display power gating: `BMP-DISP-PWR-EN` (467), `DISP-REM-...` lines (452-461)

## 4. Hardware Debug Interfaces
### 4.1 UART Access
- **BT module UART (LPSS_UART0)** – accessible via board harness; risk if attacker can reflash BT firmware.
- **Gateway UART (LPSS_UART1)** – `BMP-GTW-UART1RX/TX` implies management console between gateway MCU and infotainment.
- **Dedicated Debug UART (LPSS_UART2)** – labeled `BMP-DEBUG-UART-RX/TX`; likely routed to service headers. Combined with `gpio` utility, software can expose console.

### 4.2 JTAG / DCI
- Pins for JTAG are fully listed. Combined with `opt/odin/.../VAPI_apeOTPJTAGLocked` references, Tesla enforces OTP fuses, but hardware pads exist.
- `JTAG-DEBUG-nCONSENT` suggests firmware-controlled gating; compromising GPIO driver or userland utility `/usr/sbin/gpio` could drop consent and enable JTAG in-field.
- Intel DCI lines (CX_PMODE/PRDY/PREQ) present, enabling USB-based debug if not fused off.

### 4.3 SPI / QSPI Headers
- Boot flash accessible via `BOOT-SPI-CLK`, etc. Attackers with board access can clip to flash for offline analysis or patching.
- `GP_SSP` blocks hint at additional high-speed serial debug (A2B IRQ, diag toggles).

### 4.4 I2C / Misc Interfaces
- Multiple LPSS I2C buses break out to cameras, displays, PMIC, sensors. `AppArmor` profile `/etc/apparmor.d/abstractions/tesla/gpio` includes `/usr/sbin/gpio`, `/sys/class/gpio/**`, etc., meaning Tesla expects software-level GPIO poking for diagnostics.
- `A2B` pins connect to Analog Devices automotive audio bus. Could be leveraged for audio injection if accessible.

## 5. Kernel Attack Surfaces
### 5.1 Exposed Modules / Interfaces
| Component | Risk | Evidence |
|-----------|------|----------|
| `spidev` | User-space SPI access can read/write arbitrary SPI slaves (flash, sensors) if device tree exposes nodes. `modules.alias` includes many OF aliases (menlo,m53cpld etc.), so if Tesla accidentally binds spidev to real buses, privilege escalation is possible.
| `cyttsp6`, `nt_ts_51922` | Touchscreen drivers rely on GPIO resets/IRQs. Fault injection by toggling GPIO could cause buffer overflows or fault conditions (strings show limited validation).
| `bcmdhd` | Contains numerous custom GPIO hooks and memory reallocation modules (`dhd_tesla_memprealloc.ko`). Historically high-risk due to vendor blobs.
| `usbcore` debug options (`dyndbg` via `/etc/modprobe.d/audio_debug.conf`) and `usbcore` parameters (autosuspend disabled) increase attack surface for rogue USB/peripheral devices.

### 5.2 Debug Features Enabled
- `/etc/modprobe.d/audio_debug.conf` enables `dyndbg=+p` for nearly every ALSA/SoC audio module – verbose logging that may leak kernel pointers.
- `usbcore` options (`old_scheme_first=1`, `use_both_schemes=1`) allow fallback enumeration paths, increasing chance of buggy states.
- `intel-ipu4 secure_mode_enable=1` indicates camera pipeline tries to stay in secure mode, but `csi2_port_optimized=0` might leave default open.
- AppArmor profile explicitly grants many services access to `/usr/sbin/gpio` and `/sys/class/gpio`, meaning userland daemons can reconfigure pins.

### 5.3 System Services
- Extensive `runit` service tree includes `service-shell`, `qtcar-monitor`, etc. If any daemon has access to `gpio` abstraction, it could toggle debug gating pins.

## 6. Secure Boot & Kernel Hardening Indicators
| Feature | Evidence | Notes |
|---------|----------|-------|
| AppArmor | `security=apparmor apparmor=1` kernel cmdline; `/etc/apparmor.d/` has Tesla-specific profiles | Enabled by default
| IOMMU | `intel_iommu=on` | Mitigates DMA, though `igfx_off,ipu_off` disables graphics/IPU IOMMUs
| Ramoops | `pstore.backend=ramoops` with explicit address/size | Preserves crash logs for forensic use
| Panic on oops | `panic=1` | Prevents continued execution after fatal error
| Secure camera pipeline | `options intel-ipu4 secure_mode_enable=1` | Suggests HW pipeline lock-down
| Unclear secure boot status | Need bootloader/TPM data; not visible in kernel tree. `opt/odin/...JTAGLocked` indicates OTP enforcement exists, but actual secure boot verification not confirmed here.

## 7. Example: Using `/usr/sbin/gpio` Utility
Tesla ships a shell-based GPIO helper. Usage string confirms ability to force values, set edge triggers, and map names to numbers.

```sh
# List pin number for debug UART TX
/usr/sbin/gpio -p BMP-DEBUG-UART-TX   # -> 481

# Pulse JTAG consent low (hypothetical)
/usr/sbin/gpio JTAG-DEBUG-nCONSENT 0
sleep 1
/usr/sbin/gpio JTAG-DEBUG-nCONSENT 1
```
> Because AppArmor grants many daemons access to this tool, hardening relies on userland integrity.

## 8. Attack Surface Summary
1. **Physical interfaces**: Well-documented GPIO map exposes eMMC, SD, SPI flash, UART, and JTAG pins. Combined with board access, attackers gain full hardware debug.
2. **Software-controlled debug gating**: Pins like `JTAG-DEBUG-nCONSENT` tied to SSP channels imply software can enable/disable hardware debug. Compromised kernel/userland could re-enable JTAG even if OTP fused to “locked but consented”.
3. **spidev + GPIO userland**: Presence of `spidev` module and generic GPIO tool increases risk if device tree nodes exist. Attackers with root shell can talk to flash/PMIC directly.
4. **Verbose debug logging**: ALSA dyndbg and other debug parameters may leak memory contents or degrade performance, providing side-channel info.
5. **Lack of device tree binaries**: DTBs absent from rootfs indicates they may reside in bootloader; without them, kernel may rely on ACPI tables. Attackers modifying ACPI via bootkits could redefine GPIO for malicious purposes.

## 9. Recommendations
- Audit `/usr/sbin/gpio` usage and restrict to service partitions; enforce AppArmor policies to limit which daemons can toggle sensitive pins (JTAG consent, PMU resets).
- Confirm `spidev` is not bound to critical buses in production; remove module if unused.
- Ensure OTP/Efuse truly disables JTAG even if consent pin is toggled via software.
- Consider reducing `loglevel` or removing `dyndbg` in production builds to avoid information leakage.
- Validate secure boot chain (e.g., TPM measurements, verified boot) to prevent ACPI/kernel tampering that could remap GPIO for malicious purposes.

---
*Generated by sub-agent task: Tesla ICE firmware GPIO & hardware-debug analysis.*
